package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 首页端到端回归：用真实的 headless Chrome 打开服务端返回的首页
// （newHandler 内嵌的 index.html），像真实用户一样在表单里填写、提交，
// 再从列表 DOM 和浏览器实际发出的 fetch 记录两个层面做断言。
//
// 这条链路是服务端单元测试覆盖不到的：
//   - 容量在 number 输入框 -> 页面拼 JSON -> POST 原文的逐位准确性；
//   - 列表 JSON 被页面解析后容量的完整十进制显示；
//   - 名称中的引号、反斜杠、"capacity":1 文本不被误当作字段；
//   - 容量被服务端拒绝后，表单填写内容与开放时段全部保留。
//
// Chrome/Node 不可用时整组首页测试跳过，不影响其余 Go 测试。

const (
	homeExactCapacity    = "9007199254740993"    // 2^53+1，float64 无法精确表示
	homeNeighborCapacity = "9007199254740992"    // 若被舍入，会变成这个相邻偶数
	homeOverRangeCap     = "9223372036854775808" // 2^63，超出 int64 支持范围
)

// ---- headless Chrome 驱动（testdata/browser/cdp.mjs）的 stdio JSON-RPC 客户端 ----

type driverEnvelope struct {
	ID     int             `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

type browserDriver struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	cancel  context.CancelFunc
	mu      sync.Mutex
	nextID  int64
	pending map[int]chan driverEnvelope
}

var (
	driverOnce sync.Once
	driverInst *browserDriver
	driverErr  error
)

func executableExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func chromeBinary() string {
	if p := os.Getenv("HB_CHROME_BIN"); p != "" {
		if executableExists(p) {
			return p
		}
		return ""
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// getHomepageDriver 惰性启动一个供全部首页测试复用的 Chrome 驱动进程。
// 本机没有 Node 或 Chrome 时跳过（而不是失败）：端到端测试依赖浏览器
// 运行环境，缺环境不应拖垮纯逻辑测试。
func getHomepageDriver(t *testing.T) *browserDriver {
	t.Helper()
	driverOnce.Do(func() {
		if _, err := exec.LookPath("node"); err != nil {
			driverErr = fmt.Errorf("node 不可用：%w", err)
			return
		}
		chrome := chromeBinary()
		if chrome == "" {
			driverErr = fmt.Errorf("找不到 Chrome/Chromium 可执行文件")
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, "node", filepath.Join("testdata", "browser", "cdp.mjs"))
		cmd.Env = append(os.Environ(), "HB_CHROME_BIN="+chrome)
		cmd.Stderr = os.Stderr

		stdin, err := cmd.StdinPipe()
		if err != nil {
			cancel()
			driverErr = err
			return
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			driverErr = err
			return
		}
		if err := cmd.Start(); err != nil {
			cancel()
			driverErr = fmt.Errorf("启动浏览器驱动失败：%w", err)
			return
		}
		d := &browserDriver{
			cmd:     cmd,
			stdin:   stdin,
			cancel:  cancel,
			pending: make(map[int]chan driverEnvelope),
		}
		go func() {
			scanner := bufio.NewScanner(stdout)
			scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
			for scanner.Scan() {
				var env driverEnvelope
				if err := json.Unmarshal(scanner.Bytes(), &env); err != nil {
					continue
				}
				d.mu.Lock()
				ch := d.pending[env.ID]
				d.mu.Unlock()
				if ch != nil {
					ch <- env
				}
			}
		}()
		// 给驱动一点启动时间，若立刻退出则环境不可用。
		time.Sleep(300 * time.Millisecond)
		if cmd.ProcessState != nil {
			driverErr = fmt.Errorf("浏览器驱动进程意外退出")
			return
		}
		driverInst = d
	})
	if driverErr != nil {
		t.Skipf("跳过首页浏览器回归：%v", driverErr)
	}
	return driverInst
}

func (d *browserDriver) close() {
	d.cancel()
	_ = d.stdin.Close()
	if d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
	}
}

func (d *browserDriver) call(t *testing.T, method string, params map[string]any) json.RawMessage {
	t.Helper()
	id := int(atomic.AddInt64(&d.nextID, 1))
	ch := make(chan driverEnvelope, 1)
	d.mu.Lock()
	d.pending[id] = ch
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.pending, id)
		d.mu.Unlock()
	}()

	req := map[string]any{"id": id, "method": method}
	for k, v := range params {
		req[k] = v
	}
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal driver request: %v", err)
	}
	line = append(line, '\n')
	if _, err := d.stdin.Write(line); err != nil {
		t.Fatalf("写入浏览器驱动失败：%v", err)
	}
	select {
	case reply := <-ch:
		if !reply.OK {
			t.Fatalf("浏览器驱动 %s 失败：%s", method, reply.Error)
		}
		return reply.Result
	case <-time.After(60 * time.Second):
		t.Fatalf("浏览器驱动 %s 超时", method)
		return nil
	}
}

// 全部测试结束后关闭复用的浏览器进程。
func TestMain(m *testing.M) {
	code := m.Run()
	if driverInst != nil {
		driverInst.close()
	}
	os.Exit(code)
}

// ---- 首页测试环境：独立数据目录的 HTTP 服务 + 一个浏览器标签页 ----

type homeEnv struct {
	t       *testing.T
	driver  *browserDriver
	session string
	server  *httptest.Server
}

var homeSessionSerial int64

func newHomeEnv(t *testing.T) *homeEnv {
	t.Helper()
	d := getHomepageDriver(t)

	store, err := newStore(t.TempDir())
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	server := httptest.NewServer(newHandler(store))
	t.Cleanup(server.Close)

	session := "home" + strconv.FormatInt(atomic.AddInt64(&homeSessionSerial, 1), 10)
	raw := d.call(t, "open", map[string]any{"name": session, "url": server.URL + "/"})
	var opened struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal(raw, &opened)

	env := &homeEnv{t: t, driver: d, session: session, server: server}
	// 等待首页初始列表加载完成（“正在加载…”消失），避免与提交后的等待混淆。
	env.mustEval(`async () => {
		await __hbWait(function () {
			return document.getElementById('venue-list').textContent.indexOf('正在加载') < 0;
		}, 6000);
	}`)
	return env
}

func (e *homeEnv) mustEval(fn string) json.RawMessage {
	e.t.Helper()
	return e.driver.call(e.t, "eval", map[string]any{"name": e.session, "fn": fn})
}

// fillSpec 是页面内 __hbFillForm 的入参。
type fillSpec struct {
	Name     string         `json:"name"`
	Capacity string         `json:"capacity"`
	Timezone string         `json:"timezone"`
	Hours    []fillHourSpec `json:"hours"`
}

type fillHourSpec struct {
	Weekday int    `json:"weekday"`
	Start   string `json:"start"`
	End     string `json:"end"`
}

func (e *homeEnv) fill(spec fillSpec) {
	e.t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		e.t.Fatal(err)
	}
	e.mustEval(fmt.Sprintf(`async () => { __hbFillForm(%s); }`, raw))
}

// submitAndWait 点击保存并等待浏览器内谓词成立。
func (e *homeEnv) submitAndWait(predicate string) {
	e.t.Helper()
	e.mustEval(`async () => {
		__hbSubmit();
		await __hbWait(` + predicate + `, 6000);
	}`)
}

func waitCards(n int) string {
	return fmt.Sprintf(`function () { return document.querySelectorAll('#venue-list .venue-card').length === %d; }`, n)
}

func waitInitialLoadDone() string {
	return `function () {
		return document.getElementById('venue-list').textContent.indexOf('正在加载') < 0;
	}`
}

// ---- 页面快照结构（与 cdp.mjs 的 __hbSnapshot 对齐） ----

type pageCard struct {
	Name  string   `json:"name"`
	Meta  []string `json:"meta"`
	Hours []string `json:"hours"`
	Text  string   `json:"text"`
}

type pageSnapshot struct {
	Form struct {
		Name     string `json:"name"`
		Capacity string `json:"capacity"`
		Timezone string `json:"timezone"`
		Hours    []struct {
			Weekday int    `json:"weekday"`
			Start   string `json:"start"`
			End     string `json:"end"`
		} `json:"hours"`
	} `json:"form"`
	Error struct {
		Shown bool   `json:"shown"`
		Text  string `json:"text"`
	} `json:"error"`
	Cards    []pageCard    `json:"cards"`
	ListText string        `json:"listText"`
	Requests []pageRequest `json:"requests"`
}

type pageRequest struct {
	URL          string `json:"url"`
	Method       string `json:"method"`
	RequestBody  string `json:"requestBody"`
	Status       int    `json:"status"`
	ResponseText string `json:"responseText"`
	Error        string `json:"error"`
}

func (e *homeEnv) snapshot() pageSnapshot {
	e.t.Helper()
	raw := e.mustEval(`async () => { return __hbSnapshot(); }`)
	var snap pageSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		e.t.Fatalf("decode snapshot: %v (%s)", err, raw)
	}
	return snap
}

func (e *homeEnv) reloadAndWait() {
	e.t.Helper()
	e.driver.call(e.t, "navigate", map[string]any{"name": e.session})
	e.mustEval(`async () => { await __hbWait(` + waitInitialLoadDone() + `, 6000); }`)
}

func venueRequests(snap pageSnapshot, method string) []pageRequest {
	var out []pageRequest
	for _, r := range snap.Requests {
		if r.Method == method && strings.HasSuffix(r.URL, "/api/venues") {
			out = append(out, r)
		}
	}
	return out
}

func cardByName(t *testing.T, snap pageSnapshot, name string) pageCard {
	t.Helper()
	for _, c := range snap.Cards {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("列表中找不到场地 %q，当前卡片：%+v", name, snap.Cards)
	return pageCard{}
}

func capacityMeta(t *testing.T, card pageCard) string {
	t.Helper()
	for _, m := range card.Meta {
		if strings.HasPrefix(m, "容量：") {
			return m
		}
	}
	t.Fatalf("卡片缺少容量行：%+v", card.Meta)
	return ""
}

// decodePostedBody 按 UseNumber 解析 POST 原文，保证容量以 json.Number
// （JSON 数字原文）呈现，而不是 float64 或被引号包起来的字符串。
func decodePostedBody(t *testing.T, body string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("POST 请求体不是合法 JSON：%v\n原文：%s", err, body)
	}
	return payload
}

func capacityNumberOf(t *testing.T, payload map[string]any) json.Number {
	t.Helper()
	value, ok := payload["capacity"]
	if !ok {
		t.Fatalf("POST 请求缺少 capacity 字段：%v", payload)
	}
	if s, isString := value.(string); isString {
		t.Fatalf("容量被改成了带引号的字符串 %q；必须以 JSON 数字提交", s)
	}
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("容量不是 JSON 数字原文（%T：%v）", value, value)
	}
	return number
}

var capacityFieldRE = regexp.MustCompile(`"capacity"\s*:\s*(-?[0-9eE.+-]+)`)

// capacityTokensIn 从 JSON 文本里取出每个 capacity 字段的数字原文，
// 用来检查响应中容量始终是数字、且逐位准确。
func capacityTokensIn(text string) []string {
	var out []string
	for _, m := range capacityFieldRE.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}

// ---- 回归用例 ----

// TestHomepageLargeCapacityExactRoundTrip 覆盖核心场景：用户在容量框填写
// 9007199254740993（2^53+1），从提交报文、保存响应、列表显示到重新读取
// 列表，容量必须逐位保持，既不能变成相邻的 9007199254740992，也不能
// 为保精度改成字符串，显示时也不能出现科学计数法或近似值。
func TestHomepageLargeCapacityExactRoundTrip(t *testing.T) {
	env := newHomeEnv(t)
	const name = "超大容量馆"

	env.fill(fillSpec{
		Name:     name,
		Capacity: homeExactCapacity,
		Timezone: "Asia/Shanghai",
	})
	env.submitAndWait(waitCards(1))

	snap := env.snapshot()

	// 1) 发给服务端的请求体：容量必须是 JSON 数字 9007199254740993。
	posts := venueRequests(snap, http.MethodPost)
	if len(posts) != 1 {
		t.Fatalf("应恰好发出 1 次 POST，实际 %d 条：%+v", len(posts), snap.Requests)
	}
	post := posts[0]
	if post.Status != http.StatusCreated {
		t.Fatalf("保存应成功 201，实际 %d，响应：%s", post.Status, post.ResponseText)
	}
	payload := decodePostedBody(t, post.RequestBody)
	if got := capacityNumberOf(t, payload).String(); got != homeExactCapacity {
		t.Fatalf("提交的容量 = %s，必须逐位等于 %s（不能被 float64 舍入）", got, homeExactCapacity)
	}
	if payload["name"] != name || payload["timezone"] != "Asia/Shanghai" {
		t.Fatalf("名称/时区在提交时被改变：%v", payload)
	}
	if strings.Contains(post.RequestBody, homeNeighborCapacity) {
		t.Fatalf("请求体中出现了相邻舍入值 %s：%s", homeNeighborCapacity, post.RequestBody)
	}
	if strings.Contains(post.RequestBody, `"capacity":"`) {
		t.Fatalf("容量不能以字符串形式提交：%s", post.RequestBody)
	}

	// 2) 保存响应中的容量同样逐位准确。
	if tokens := capacityTokensIn(post.ResponseText); len(tokens) != 1 || tokens[0] != homeExactCapacity {
		t.Fatalf("保存响应容量异常 %v：%s", tokens, post.ResponseText)
	}

	// 3) 列表卡片必须完整显示原数字，不用科学计数法或近似值。
	card := cardByName(t, snap, name)
	if got := capacityMeta(t, card); got != "容量："+homeExactCapacity+" 人" {
		t.Fatalf("列表容量显示 = %q，应为完整十进制 %s", got, homeExactCapacity)
	}
	if regexp.MustCompile(`\d\s*[eE]\s*\+?\d`).MatchString(card.Text) {
		t.Fatalf("列表显示出现科学计数法：%q", card.Text)
	}
	if strings.Contains(card.Text, homeNeighborCapacity) {
		t.Fatalf("列表把容量显示成了相邻舍入值 %s：%q", homeNeighborCapacity, card.Text)
	}

	// 4) 保存后那次列表 GET 的响应文本中，容量仍是逐位准确的数字。
	sawSavedGET := false
	for _, get := range venueRequests(snap, http.MethodGet) {
		if get.Status != http.StatusOK {
			continue
		}
		for _, token := range capacityTokensIn(get.ResponseText) {
			sawSavedGET = true
			if token != homeExactCapacity {
				t.Fatalf("列表接口容量 = %s，应为 %s；响应：%s", token, homeExactCapacity, get.ResponseText)
			}
		}
	}
	if !sawSavedGET {
		t.Fatalf("保存后未观察到带容量的列表读取：%+v", venueRequests(snap, http.MethodGet))
	}

	// 5) 再次打开首页（重新读取已有场地列表）时仍显示同一人数。
	env.reloadAndWait()
	env.mustEval(`async () => { await __hbWait(` + waitCards(1) + `, 6000); }`)
	reloaded := env.snapshot()
	if len(reloaded.Cards) != 1 {
		t.Fatalf("重新读取后应有 1 张卡片，实际 %+v", reloaded.Cards)
	}
	if got := capacityMeta(t, cardByName(t, reloaded, name)); got != "容量："+homeExactCapacity+" 人" {
		t.Fatalf("重新读取后容量显示 = %q，应为 %s", got, homeExactCapacity)
	}
	for _, get := range venueRequests(reloaded, http.MethodGet) {
		if tokens := capacityTokensIn(get.ResponseText); len(tokens) != 1 || tokens[0] != homeExactCapacity {
			t.Fatalf("重新读取的列表容量异常 %v：%s", tokens, get.ResponseText)
		}
	}
}

// TestHomepageNormalCapacity120 保证普通容量的提交与显示不被大整数处理改变。
func TestHomepageNormalCapacity120(t *testing.T) {
	env := newHomeEnv(t)
	const name = "普通馆"

	env.fill(fillSpec{
		Name:     name,
		Capacity: "120",
		Timezone: "Asia/Shanghai",
	})
	env.submitAndWait(waitCards(1))

	snap := env.snapshot()
	posts := venueRequests(snap, http.MethodPost)
	if len(posts) != 1 || posts[0].Status != http.StatusCreated {
		t.Fatalf("普通容量保存应成功：%+v", posts)
	}
	payload := decodePostedBody(t, posts[0].RequestBody)
	if got := capacityNumberOf(t, payload).String(); got != "120" {
		t.Fatalf("普通容量提交值 = %q，应为数字 120", got)
	}
	if got := capacityMeta(t, cardByName(t, snap, name)); got != "容量：120 人" {
		t.Fatalf("普通容量显示 = %q，应为 \"容量：120 人\"", got)
	}
}

// TestHomepageTrickyNameDoesNotAffectCapacity 名称里同时包含引号、反斜杠
// 和 "capacity":1 文字：列表必须按保存内容显示名称，这段文字不能被当成
// 另一个容量字段；真正的容量以服务端返回的完整十进制数字为准。
func TestHomepageTrickyNameDoesNotAffectCapacity(t *testing.T) {
	env := newHomeEnv(t)
	const trickyName = `A\B"C"  "capacity":1`

	env.fill(fillSpec{
		Name:     trickyName,
		Capacity: "120",
		Timezone: "UTC",
	})
	env.submitAndWait(waitCards(1))

	snap := env.snapshot()
	posts := venueRequests(snap, http.MethodPost)
	if len(posts) != 1 || posts[0].Status != http.StatusCreated {
		t.Fatalf("特殊名称保存应成功：%+v", posts)
	}
	payload := decodePostedBody(t, posts[0].RequestBody)
	if got, _ := payload["name"].(string); got != trickyName {
		t.Fatalf("提交的名称 = %q，应逐字等于 %q", got, trickyName)
	}
	if got := capacityNumberOf(t, payload).String(); got != "120" {
		t.Fatalf("真正的容量 = %s，应为 120，不能受名称中 \"capacity\":1 文本影响", got)
	}
	if got := capacityMeta(t, cardByName(t, snap, trickyName)); got != "容量：120 人" {
		t.Fatalf("特殊名称下容量显示被改写：%q", got)
	}

	// 重新读取：名称按保存内容显示，容量仍是 120；名称里的伪字段在传输
	// JSON 中是被转义的字符串内容，页面解析后绝不能把它当对象键。
	env.reloadAndWait()
	env.mustEval(`async () => { await __hbWait(` + waitCards(1) + `, 6000); }`)
	reloaded := env.snapshot()
	card := cardByName(t, reloaded, trickyName)
	if card.Name != trickyName {
		t.Fatalf("重新读取后名称显示 = %q，应为 %q", card.Name, trickyName)
	}
	if got := capacityMeta(t, card); got != "容量：120 人" {
		t.Fatalf("重新读取后容量显示 = %q，应为 120", got)
	}
	for _, get := range venueRequests(reloaded, http.MethodGet) {
		dec := json.NewDecoder(strings.NewReader(get.ResponseText))
		dec.UseNumber()
		var body struct {
			Venues []struct {
				Name     string      `json:"name"`
				Capacity json.Number `json:"capacity"`
			} `json:"venues"`
		}
		if err := dec.Decode(&body); err != nil {
			t.Fatalf("列表响应解析失败：%v：%s", err, get.ResponseText)
		}
		if len(body.Venues) != 1 {
			t.Fatalf("应只有 1 个场地，实际 %d：%s", len(body.Venues), get.ResponseText)
		}
		if body.Venues[0].Name != trickyName {
			t.Fatalf("接口返回名称 = %q，应为 %q", body.Venues[0].Name, trickyName)
		}
		if body.Venues[0].Capacity.String() != "120" {
			t.Fatalf("接口返回容量 = %s，应为 120；名称中的伪 capacity 文本不能改写真实字段",
				body.Venues[0].Capacity)
		}
	}
}

// TestHomepageRejectedCapacityKeepsForm 容量超出支持范围时：页面显示服务端
// 的超出范围原因、不新增场地卡片，名称/容量/时区/开放时段全部保留，
// 失败数值不能先被页面舍入成另一个整数提交；用户保留内容改正容量后可保存。
func TestHomepageRejectedCapacityKeepsForm(t *testing.T) {
	env := newHomeEnv(t)
	const name = "超限馆"

	env.fill(fillSpec{
		Name:     name,
		Capacity: homeOverRangeCap,
		Timezone: "Asia/Shanghai",
		Hours:    []fillHourSpec{{Weekday: 1, Start: "09:00", End: "18:00"}},
	})
	env.submitAndWait(`function () {
		var box = document.getElementById('form-error');
		return box.style.display !== 'none' && box.textContent.indexOf('超出支持范围') >= 0;
	}`)

	snap := env.snapshot()

	// 失败提示必须来自服务端说明，且明确指出超出支持范围。
	if !snap.Error.Shown || !strings.Contains(snap.Error.Text, "超出支持范围") {
		t.Fatalf("应显示服务端的超出范围原因，实际：%q", snap.Error.Text)
	}

	// 不能新增场地卡片。
	if len(snap.Cards) != 0 {
		t.Fatalf("被拒绝的提交不能生成场地卡片，实际有 %d 张：%+v", len(snap.Cards), snap.Cards)
	}

	// POST 必须是 400，且请求体中的容量是用户输入的精确值 9223372036854775808：
	// 页面不能先把它舍入成另一个“可提交”的整数。
	posts := venueRequests(snap, http.MethodPost)
	if len(posts) != 1 {
		t.Fatalf("应只发出 1 次 POST，实际 %+v", snap.Requests)
	}
	post := posts[0]
	if post.Status != http.StatusBadRequest {
		t.Fatalf("超范围容量应返回 400，实际 %d：%s", post.Status, post.ResponseText)
	}
	if !strings.Contains(post.ResponseText, "超出支持范围") {
		t.Fatalf("400 响应应说明超出支持范围：%s", post.ResponseText)
	}
	payload := decodePostedBody(t, post.RequestBody)
	if got := capacityNumberOf(t, payload).String(); got != homeOverRangeCap {
		t.Fatalf("失败请求提交的容量 = %s，必须是用户输入的精确值 %s，不能先舍入",
			got, homeOverRangeCap)
	}

	// 名称、容量、时区、已填写的开放时段全部保留。
	if snap.Form.Name != name {
		t.Fatalf("失败后名称被清空/改变：%q", snap.Form.Name)
	}
	if snap.Form.Capacity != homeOverRangeCap {
		t.Fatalf("失败后容量输入应保留 %s，实际 %q", homeOverRangeCap, snap.Form.Capacity)
	}
	if snap.Form.Timezone != "Asia/Shanghai" {
		t.Fatalf("失败后时区被清空/改变：%q", snap.Form.Timezone)
	}
	if len(snap.Form.Hours) != 1 {
		t.Fatalf("失败后开放时段应保留 1 条，实际 %d 条：%+v", len(snap.Form.Hours), snap.Form.Hours)
	} else {
		h := snap.Form.Hours[0]
		if h.Weekday != 1 || h.Start != "09:00" || h.End != "18:00" {
			t.Fatalf("失败后开放时段内容被改变：%+v", h)
		}
	}

	// 用户在保留其它内容的情况下纠正容量，应能保存成功，原有开放时段随之展示。
	env.fill(fillSpec{
		Name:     name,
		Capacity: "120",
		Timezone: "Asia/Shanghai",
		Hours:    []fillHourSpec{{Weekday: 1, Start: "09:00", End: "18:00"}},
	})
	env.submitAndWait(waitCards(1))
	fixed := env.snapshot()
	if fixed.Error.Shown {
		t.Fatalf("纠正容量后不应再有错误提示：%q", fixed.Error.Text)
	}
	fixedPosts := venueRequests(fixed, http.MethodPost)
	if len(fixedPosts) != 2 {
		t.Fatalf("纠正后应累计 2 次 POST，实际 %+v", fixedPosts)
	}
	if last := fixedPosts[1]; last.Status != http.StatusCreated {
		t.Fatalf("纠正容量后保存应成功，实际 %d：%s", last.Status, last.ResponseText)
	}
	card := cardByName(t, fixed, name)
	if got := capacityMeta(t, card); got != "容量：120 人" {
		t.Fatalf("纠正后容量显示 = %q，应为 120", got)
	}
	if len(card.Hours) != 1 || card.Hours[0] != "周一 09:00 – 18:00" {
		t.Fatalf("纠正后原有开放时段未保留：%+v", card.Hours)
	}

	// 重新读取仍只有纠正成功的这 1 个场地：失败请求确实没有落库。
	env.reloadAndWait()
	env.mustEval(`async () => { await __hbWait(` + waitCards(1) + `, 6000); }`)
	reloaded := env.snapshot()
	if len(reloaded.Cards) != 1 {
		t.Fatalf("被拒绝的容量不能落库；重新读取后应有且仅有 1 张卡片，实际 %+v", reloaded.Cards)
	}
	if got := capacityMeta(t, cardByName(t, reloaded, name)); got != "容量：120 人" {
		t.Fatalf("重新读取后容量 = %q，应为 120", got)
	}
}
