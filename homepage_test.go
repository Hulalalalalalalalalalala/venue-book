package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 首页浏览器端到端回归：
//
// 服务端的精确整数校验与时段规则已由 HTTP 层测试覆盖；这里补上“用户在首页
// 表单填写 → 浏览器提交 → 服务端保存 → 首页列表显示”这一段的保障，覆盖容量
// 逐位准确提交/显示，以及每周开放时段的填写、保存、卡片排序展示（含跨午夜
// “次日”标注）、跨周重叠拒绝后保留填写内容、不完整行拦截与删除全部时段后
// 显示“暂未开放”。测试启动真实 HTTP 服务（httptest）与本机无头 Chrome，由
// testdata/homepage_browser_test.mjs 通过 Chrome DevTools Protocol 驱动真实
// 首页，逐字节检查请求/响应内容，并验证列表显示与失败时的表单保留行为。
//
// 脚本不依赖任何 npm 包（Node ≥22 的全局 WebSocket 即可），在缺少 node 或
// Chrome 的环境中跳过，保证其余测试照常运行。可用 CHROME_BIN 指定浏览器。

type browserCheckResult struct {
	HarnessError string `json:"harnessError"`
	Browser      string `json:"browser"`
	Checks       []struct {
		Scenario string `json:"scenario"`
		Name     string `json:"name"`
		Pass     bool   `json:"pass"`
		Detail   string `json:"detail"`
	} `json:"checks"`
}

func findExecutable(t *testing.T, names []string, candidates []string) string {
	t.Helper()
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
		}
	}
	return ""
}

func TestHomepageBrowserE2E(t *testing.T) {
	nodeBin := findExecutable(t, []string{"node"}, []string{
		"/opt/gsb-production/bin/node",
		"/usr/local/bin/node",
		"/usr/bin/node",
	})
	if nodeBin == "" {
		t.Skip("未找到 node，跳过首页浏览器端到端测试")
	}
	chromeBin := findExecutable(t,
		[]string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"},
		[]string{
			os.Getenv("CHROME_BIN"),
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/usr/local/bin/google-chrome",
		})
	if chromeBin == "" {
		t.Skip("未找到 Chrome/Chromium（可用 CHROME_BIN 指定），跳过首页浏览器端到端测试")
	}

	// 与线上相同的处理链：临时数据目录 + 真实 HTTP 服务。
	_, handler := newTestServer(t)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	harness := filepath.Join("testdata", "homepage_browser_test.mjs")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, nodeBin, harness, srv.URL, chromeBin)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("运行首页浏览器脚本失败: %v\nstderr:\n%s\nstdout:\n%s", err, stderr.String(), stdout.String())
	}

	// 脚本只在最后一行输出 JSON 结果。
	var result browserCheckResult
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var report string
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var probe browserCheckResult
		if err := json.Unmarshal([]byte(line), &probe); err == nil {
			result = probe
			report = line
			break
		}
	}
	if report == "" {
		t.Fatalf("浏览器脚本没有输出 JSON 结果\nstderr:\n%s\nstdout:\n%s", stderr.String(), stdout.String())
	}
	if result.HarnessError != "" {
		t.Fatalf("浏览器脚本基础设施故障: %s\nstderr:\n%s", result.HarnessError, stderr.String())
	}
	if len(result.Checks) == 0 {
		t.Fatalf("浏览器脚本没有产出任何检查项: %s", report)
	}
	t.Logf("浏览器：%s，共 %d 项页面行为检查", result.Browser, len(result.Checks))

	failures := 0
	for _, c := range result.Checks {
		if !c.Pass {
			failures++
		}
		c := c
		t.Run(subtestName(c.Scenario, c.Name), func(t *testing.T) {
			if !c.Pass {
				t.Errorf("%s / %s 未通过%s", c.Scenario, c.Name, detailSuffix(c.Detail))
			}
		})
	}
	if failures > 0 {
		t.Fatalf("首页浏览器端到端回归共有 %d 项失败", failures)
	}
}

// subtestName 把场景与检查名拼成稳定的子测试名（去掉会影响层级显示的斜杠）。
func subtestName(scenario, name string) string {
	safe := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			if r == '/' || r == '\\' {
				r = ' '
			}
			b.WriteRune(r)
		}
		return strings.TrimSpace(b.String())
	}
	return safe(scenario) + " · " + safe(name)
}

func detailSuffix(detail string) string {
	detail = strings.ReplaceAll(detail, "\n", " ")
	if len(detail) > 600 {
		detail = detail[:600] + "…"
	}
	if detail == "" {
		return ""
	}
	return "：" + detail
}
