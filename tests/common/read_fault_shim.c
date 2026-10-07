/*
 * LD_PRELOAD read-fault injector for the roottrace `root` end-to-end
 * regressions (tests/read_fault_regression.rs).
 *
 * It is NOT linked into roottrace and is not used by the program in normal
 * operation; the tests build this file as a shared object and preload it only
 * for child processes running the already compiled roottrace binary. Every
 * fault is therefore seen by the command's real file-read loop on a real
 * regular file, instead of being simulated inside a copy of the code.
 *
 * Only read() attempts on one file descriptor are affected, identified on
 * every call by resolving /proc/self/fd/<fd> and matching it against
 * RT_FAULT_TARGET; reads on every other descriptor (the loader, libraries,
 * standard streams, ...) pass through unchanged.
 *
 * Environment (read on each call):
 *   RT_FAULT_TARGET  substring of the target file's /proc/self/fd resolution
 *   RT_READ_CAP      if a positive decimal, cap each target read() to that
 *                    many bytes, so the command sees many small reads whose
 *                    boundaries the tests can align to; unset/0 = no cap
 *   RT_FAULT_SCRIPT  comma-separated actions for successive read() ATTEMPTS
 *                    on the target descriptor (an EINTR attempt is an attempt
 *                    and consumes its own token):
 *                      ok    ordinary read (still capped)
 *                      intr  return -1 with errno=EINTR
 *                      eio   return -1 with errno=EIO
 *                      eof   return 0 (premature end of file)
 *                    past the last token, reads pass through normally.
 *
 * Linux + glibc/musl only (the regression that needs it skips elsewhere).
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef ssize_t (*read_fn_t)(int fd, void *buf, size_t count);

static read_fn_t real_read(void) {
    static read_fn_t cached = NULL;
    if (cached == NULL) {
        cached = (read_fn_t)dlsym(RTLD_NEXT, "read");
    }
    return cached;
}

static int fd_backed_by_target(int fd) {
    const char *target = getenv("RT_FAULT_TARGET");
    if (target == NULL || target[0] == '\0' || fd < 0) {
        return 0;
    }
    char proc[64];
    char link[4096];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, link, sizeof(link) - 1);
    if (n <= 0) {
        return 0;
    }
    link[n] = '\0';
    return strstr(link, target) != NULL;
}

/* Action token for read-attempt number `call`, or NULL when the script ends
 * before it (normal read). Parsed fresh per call; the script is short. */
static const char *scripted_action(unsigned long call) {
    const char *s = getenv("RT_FAULT_SCRIPT");
    if (s == NULL || s[0] == '\0') {
        return NULL;
    }
    char copy[2048];
    snprintf(copy, sizeof(copy), "%s", s);
    char *save = NULL;
    char *tok = strtok_r(copy, ",", &save);
    unsigned long i = 0;
    while (tok != NULL && i < call) {
        tok = strtok_r(NULL, ",", &save);
        i++;
    }
    return (tok != NULL && i == call) ? tok : NULL;
}

/* Per-descriptor counters of read attempts, indexed by descriptor number. */
static unsigned long attempt[4096];

ssize_t read(int fd, void *buf, size_t count) {
    if (fd >= 0 && fd < (int)(sizeof(attempt) / sizeof(attempt[0]))
        && fd_backed_by_target(fd)) {
        const char *cap_s = getenv("RT_READ_CAP");
        if (cap_s != NULL && cap_s[0] != '\0') {
            long cap = strtol(cap_s, NULL, 10);
            if (cap > 0 && count > (size_t)cap) {
                count = (size_t)cap;
            }
        }
        const char *a = scripted_action(attempt[fd]++);
        if (a != NULL) {
            if (strcmp(a, "intr") == 0) {
                errno = EINTR;
                return -1;
            }
            if (strcmp(a, "eio") == 0) {
                errno = EIO;
                return -1;
            }
            if (strcmp(a, "eof") == 0) {
                return 0;
            }
        }
    }
    return real_read()(fd, buf, count);
}
