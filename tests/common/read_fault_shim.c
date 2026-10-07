/*
 * read_fault_shim.c - deterministic fault injection for `roottrace root`'s
 * file read loop.
 *
 * It is an LD_PRELOAD interposer for read(2) and does nothing unless the
 * RT_SCRIPT environment variable is set. The script is a ';'-separated list
 * of actions consumed, in order, once per read whose requested size is
 * exactly 65536 - the fixed batch buffer `roottrace root` reads through
 * (see READ_BUF / merkle_root_of_file in src/main.rs). Reads of any other
 * size, actions past the last scripted one, and an empty or "." action all
 * pass straight through, so every other I/O and every later read is
 * untouched.
 *
 * Actions per batch-file read call:
 *   "."     pass this read through unchanged (placeholder used to reach a
 *           later call, e.g. the EOF read; empty tokens mean the same)
 *   "i"     fail the read with EINTR  -> Rust reports ErrorKind::Interrupted
 *   "e"     fail the read with EIO    -> a persistent, non-retryable error
 *   "rN"    clamp the read's requested byte count to N (1 <= N < 65536),
 *           so the kernel hands back a deliberately short read of exactly
 *           the first N remaining file bytes; the next scripted action then
 *           applies to the following read call. This places an interruption
 *           or an error at an exact file offset without changing any byte.
 *
 * A short read followed by "i" models a read() interrupted by a signal after
 * the buffer was partially filled in an earlier call; one followed by "e"
 * models the device returning some bytes and then failing unrecoverably. The
 * fault is a genuine error returned on the read syscall path (the shim only
 * fabricates its errno/result), so this exercises roottrace's actual
 * std::io::Read handling - EINTR retry, the fatal-error path and the bytes in
 * between - end to end through the built command.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RT_MAX_TOKENS 64

/* Token storage lives in the script copy itself; the pointers below point
 * into `storage`, where each token is NUL-terminated in place. */
static char storage[2048];
static char *g_tokens[RT_MAX_TOKENS];
static int g_ntokens;
static int g_next_call;
static ssize_t (*g_real_read)(int, void *, size_t);

__attribute__((constructor))
static void rt_parse_script(void) {
    const char *script = getenv("RT_SCRIPT");
    if (script == NULL || script[0] == '\0') {
        return;
    }

    size_t len = strlen(script);
    if (len >= sizeof(storage)) {
        len = sizeof(storage) - 1;
    }
    memcpy(storage, script, len);
    storage[len] = '\0';

    /* Manual split on ';': unlike strtok_r this keeps EMPTY tokens, so two
     * consecutive ';' genuinely advance one read call with no action. */
    char *start = storage;
    char *p = storage;
    while (1) {
        if (*p == ';' || *p == '\0') {
            char at = *p;
            *p = '\0';
            if (g_ntokens < RT_MAX_TOKENS) {
                g_tokens[g_ntokens++] = start;
            }
            start = p + 1;
            if (at == '\0') {
                break;
            }
        }
        p++;
    }
}

ssize_t read(int fd, void *buf, size_t count) {
    if (g_real_read == NULL) {
        g_real_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    }

    if (count == 65536 && g_next_call < g_ntokens) {
        const char *action = g_tokens[g_next_call++];
        if (action[0] == 'i') {
            errno = EINTR;
            return -1;
        }
        if (action[0] == 'e') {
            errno = EIO;
            return -1;
        }
        if (action[0] == 'r') {
            unsigned long limit = strtoul(action + 1, NULL, 10);
            if (limit > 0 && limit < count) {
                count = (size_t)limit;
            }
        }
        /* empty token or ".": no fault, fall through to the real read. */
    }

    return g_real_read(fd, buf, count);
}
