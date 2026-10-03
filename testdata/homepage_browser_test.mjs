// 首页容量准确性端到端回归脚本（由 main_test.go 通过 go test 调用，不单独运行）。
//
// 用法：node homepage_browser_test.mjs <baseURL> [chrome 可执行文件路径]
//
// 脚本用 Chrome DevTools Protocol 驱动本机无头 Chrome 打开真实首页，覆盖
// “用户填表 → 提交 → 查看已保存场地”的完整链路；stdout 最后一行输出 JSON
// 结果。除浏览器/脚本自身的基础设施故障（退出码非 0）外，页面行为层面的
// 断言失败都记录在 JSON 的 checks 中，由 Go 测试统一判定。
//
// 设计要点：
//   - 直接启动系统 Chrome 并以裸 WebSocket（Node 24 全局 WebSocket）连接
//     CDP，不依赖任何 npm 包，适配无外网/无 node_modules 的环境。
//   - 监听 Network 事件，保存发往 /api/venues 的请求体原文与响应体原文，
//     因此可以逐字节验证 capacity 是否仍是未加引号的十进制整数。
//   - 表单取值通过原型 value setter + input/change 事件注入，真实触发
//     页面已有的提交逻辑，而不是直接调用内部函数。

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const baseURL = process.argv[2];
const chromeArg = process.argv[3] || "";
if (!baseURL) {
  console.error("usage: node homepage_browser_test.mjs <baseURL> [chrome]");
  process.exit(2);
}

function failInfra(message) {
  process.stdout.write(JSON.stringify({ harnessError: String(message) }) + "\n");
  process.exit(1);
}

process.on("unhandledRejection", (err) => failInfra(err && err.stack || err));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findChrome() {
  if (chromeArg) return chromeArg;
  if (process.env.CHROME_BIN) return process.env.CHROME_BIN;
  const candidates = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/local/bin/google-chrome",
  ];
  for (const c of candidates) {
    try {
      fs.accessSync(c, fs.constants.X_OK);
      return c;
    } catch { /* keep looking */ }
  }
  return "google-chrome";
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
    srv.on("error", reject);
  });
}

async function launchChrome() {
  const binary = findChrome();
  const port = await freePort();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "tb-chrome-"));
  const args = [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-crash-reporter",
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${profile}`,
    "about:blank",
  ];
  const chrome = spawn(binary, args, {
    stdio: ["ignore", "ignore", "pipe"],
    detached: true,
  });
  let stderr = "";
  chrome.stderr.on("data", (d) => { stderr += d; });

  let info = null;
  for (let i = 0; i < 60; i++) {
    await sleep(100);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (res.ok) { info = await res.json(); break; }
    } catch { /* not ready */ }
  }
  if (!info) {
    try { process.kill(-chrome.pid, "SIGKILL"); } catch { /* ignore */ }
    failInfra(`Chrome 未在预期时间内开启 CDP（${binary}）：${stderr.slice(-400)}`);
  }
  const cleanup = () => {
    try { process.kill(-chrome.pid, "SIGKILL"); } catch { /* already gone */ }
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  return { port, browserInfo: info, cleanup };
}

// ---- 极简 CDP 客户端 ----

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.nextId = 0;
    this.pending = new Map();
    this.eventListeners = [];
  }
  async connect() {
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve, { once: true });
      this.ws.addEventListener("error", reject, { once: true });
    });
    this.ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message || JSON.stringify(msg.error)}`));
        else resolve(msg.result);
        return;
      }
      if (msg.method) {
        for (const fn of this.eventListeners) {
          try { fn(msg.method, msg.params); } catch { /* listener errors must not break the run */ }
        }
      }
    });
  }
  on(fn) { this.eventListeners.push(fn); }
  send(method, params = {}) {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  close() { try { this.ws.close(); } catch { /* ignore */ } }

  // 在页面里求值；表达式必须是返回可 JSON 序列化值的同步表达式。
  async eval(expression) {
    const res = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (res.exceptionDetails) {
      const exc = res.exceptionDetails.exception;
      throw new Error(`page exception: ${(exc && exc.description) || JSON.stringify(res.exceptionDetails)}`);
    }
    return res.result ? res.result.value : undefined;
  }
  async evalFn(fnSource, arg) {
    return this.eval(`(${fnSource})(${JSON.stringify(arg === undefined ? null : arg)})`);
  }
}

// ---- 网络记录 ----

function createNetworkLog(cdp) {
  // requests: requestId -> {method,url,postData,status,mimeType}
  const requests = new Map();
  cdp.on((method, params) => {
    if (method === "Network.requestWillBeSent") {
      const r = params.request;
      const rec = requests.get(params.requestId) || {};
      rec.method = r.method;
      rec.url = r.url;
      if (typeof r.postData === "string") rec.postData = r.postData;
      requests.set(params.requestId, rec);
    } else if (method === "Network.responseReceived") {
      const rec = requests.get(params.requestId) || {};
      rec.method = rec.method || params.request.method;
      rec.url = rec.url || params.request.url;
      rec.status = params.response.status;
      rec.mimeType = params.response.mimeType;
      requests.set(params.requestId, rec);
    }
  });
  const snapshot = () => Array.from(requests.values());
  return {
    snapshot,
    venuePosts(after = 0) {
      return snapshot()
        .filter((r) => r.method === "POST" && r.url.includes("/api/venues"))
        .slice(after);
    },
    venueGets() {
      return snapshot().filter((r) => r.method === "GET" && r.url.includes("/api/venues"));
    },
    async postDataOf(rec) {
      if (rec.postData !== undefined) return rec.postData;
      // requestWillBeSent 未携带 body 时按 requestId 补取。
      for (const [id, r] of requests) {
        if (r === rec) {
          try {
            const out = await cdp.send("Network.getRequestPostData", { requestId: id });
            return out.postData;
          } catch { return null; }
        }
      }
      return null;
    },
    async bodyOf(rec) {
      for (const [id, r] of requests) {
        if (r === rec) {
          const out = await cdp.send("Network.getResponseBody", { requestId: id });
          return out.base64Encoded ? Buffer.from(out.body, "base64").toString("utf8") : out.body;
        }
      }
      return null;
    },
  };
}

// ---- 注入页面的测试驱动 ----

// fill：按真实用户方式给字段赋 value（原型 setter + input/change），
// 并按需要点击“添加开放时段”生成行。字段值全部来自参数 JSON，不经任何
// Number 转换。
const PAGE_FILL = `function (data) {
  function setValue(el, value) {
    var proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    var setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, String(value));
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  setValue(document.getElementById("name"), data.name || "");
  setValue(document.getElementById("capacity"), data.capacity || "");
  setValue(document.getElementById("timezone"), data.timezone || "");
  document.querySelectorAll("#hours-rows .hour-row").forEach(function (row) { row.remove(); });
  (data.hours || []).forEach(function (h) {
    document.getElementById("add-hour").click();
    var rows = document.querySelectorAll("#hours-rows .hour-row");
    var row = rows[rows.length - 1];
    setValue(row.querySelector(".hour-weekday"), h.weekday);
    setValue(row.querySelector(".hour-start"), h.start);
    setValue(row.querySelector(".hour-end"), h.end);
  });
  return true;
}`;

const PAGE_SUBMIT = `function () {
  document.getElementById("venue-form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  return true;
}`;

// fillPartial：与 PAGE_FILL 相同的真实注入方式，但允许某行缺少开始或结束
// 时间（null 表示不填），用于覆盖“某行未填写完整”的前端拦截。
const PAGE_FILL_PARTIAL = `function (data) {
  function setValue(el, value) {
    var proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    var setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, String(value));
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  setValue(document.getElementById("name"), data.name || "");
  setValue(document.getElementById("capacity"), data.capacity || "");
  setValue(document.getElementById("timezone"), data.timezone || "");
  document.querySelectorAll("#hours-rows .hour-row").forEach(function (row) { row.remove(); });
  (data.hours || []).forEach(function (h) {
    document.getElementById("add-hour").click();
    var rows = document.querySelectorAll("#hours-rows .hour-row");
    var row = rows[rows.length - 1];
    setValue(row.querySelector(".hour-weekday"), h.weekday);
    if (h.start !== null && h.start !== undefined) setValue(row.querySelector(".hour-start"), h.start);
    if (h.end !== null && h.end !== undefined) setValue(row.querySelector(".hour-end"), h.end);
  });
  return true;
}`;

// removeAllHours：点击每行的“删除”按钮移除全部开放时段，模拟用户删空。
const PAGE_REMOVE_ALL_HOURS = `function () {
  var rows = document.querySelectorAll("#hours-rows .hour-row");
  rows.forEach(function (row) { row.querySelector("button.danger").click(); });
  return document.querySelectorAll("#hours-rows .hour-row").length;
}`;

// setField：只改名称/容量/时区中的某一个字段（真实 setter + input/change），
// 用于在保存请求在途期间做最小化编辑，而不是像 fill 那样重建整张表单。
const PAGE_SET_FIELD = `function (arg) {
  var el = document.getElementById(arg.id);
  var proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  var setter = Object.getOwnPropertyDescriptor(proto, "value").set;
  setter.call(el, String(arg.value));
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}`;

// addHour：点击一次“添加开放时段”，返回点击后页面上的时段行数。
const PAGE_ADD_HOUR = `function () {
  document.getElementById("add-hour").click();
  return document.querySelectorAll("#hours-rows .hour-row").length;
}`;

// setHour：修改第 index 行（0 起）给出的 weekday/start/end；未给出的字段
// 不动，null 表示把该字段清空，支持“只改开始时间”等最小编辑。
const PAGE_SET_HOUR = `function (arg) {
  var rows = document.querySelectorAll("#hours-rows .hour-row");
  var row = rows[arg.index];
  if (!row) return false;
  function setValue(el, value) {
    var proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    var setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, String(value));
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  if (Object.prototype.hasOwnProperty.call(arg, "weekday"))
    setValue(row.querySelector(".hour-weekday"), arg.weekday === null ? "" : arg.weekday);
  if (Object.prototype.hasOwnProperty.call(arg, "start"))
    setValue(row.querySelector(".hour-start"), arg.start === null ? "" : arg.start);
  if (Object.prototype.hasOwnProperty.call(arg, "end"))
    setValue(row.querySelector(".hour-end"), arg.end === null ? "" : arg.end);
  return true;
}`;

// removeHourAt：点击第 index 行自己的“删除”按钮，模拟在途期间删掉该行。
const PAGE_REMOVE_HOUR_AT = `function (index) {
  var rows = document.querySelectorAll("#hours-rows .hour-row");
  if (!rows[index]) return false;
  rows[index].querySelector("button.danger").click();
  return document.querySelectorAll("#hours-rows .hour-row").length;
}`;

// PAGE_FETCH_GATE_BOOTSTRAP 由 Page.addScriptToEvaluateOnNewDocument 在每个
// 文档的页面脚本运行前注入（导航后依然生效）：包住 window.fetch，不改变请求
// 的发送与服务端处理，只把 POST /api/venues 的 Response 交还给页面业务代码
// 的时机延后到测试放行——由此确定性地造出“点击保存后、服务端结果尚未返回”
// 的窗口：请求已真实发出（Network 记录里能看到请求体与状态码），而页面的成
// 功/失败回调尚未执行。GET（如成功后的列表刷新）不拦截，避免卡住既有加载流
// 程；放行后所有被挂起的响应按原顺序交还。默认透传，只有测试显式 hold 时才
// 挂起。全局 __venueTestGate 提供 hold/release/pending。
const PAGE_FETCH_GATE_BOOTSTRAP = `(function () {
  var realFetch = window.fetch.bind(window);
  var held = [];
  var holding = false;
  window.__venueTestGate = {
    hold: function () { holding = true; return held.length; },
    release: function () {
      var old = held;
      held = [];
      holding = false;
      old.forEach(function (go) { go(); });
      return old.length;
    },
    pending: function () { return held.length; }
  };
  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : ((input && input.url) || "");
    var isVenuePost = url.indexOf("/api/venues") >= 0 &&
      init && init.method && String(init.method).toUpperCase() === "POST";
    if (!isVenuePost) return realFetch(input, init);
    return realFetch(input, init).then(function (response) {
      if (!holding) return response;
      return new Promise(function (resolve) {
        held.push(function () { resolve(response); });
      });
    });
  };
})();`;

// changeLastHourStart：只修改最后一行的开始时间，用于在保留上一轮失败
// 表单内容的前提下做最小纠正。
const PAGE_CHANGE_LAST_START = `function (value) {
  var rows = document.querySelectorAll("#hours-rows .hour-row");
  var row = rows[rows.length - 1];
  var el = row.querySelector(".hour-start");
  var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  setter.call(el, String(value));
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}`;

// state：读取错误提示、表单当前值与场地卡片文本（textContent 即页面
// 实际展示内容）。
const PAGE_STATE = `function () {
  var errorBox = document.getElementById("form-error");
  var rows = Array.prototype.map.call(document.querySelectorAll("#hours-rows .hour-row"), function (row) {
    return {
      weekday: row.querySelector(".hour-weekday").value,
      start: row.querySelector(".hour-start").value,
      end: row.querySelector(".hour-end").value
    };
  });
  var cards = Array.prototype.map.call(document.querySelectorAll(".venue-card"), function (card) {
    var tzLine = "";
    var meta = card.querySelectorAll(".venue-meta");
    for (var mi = 0; mi < meta.length; mi++) {
      if (meta[mi].textContent.indexOf("时区：") === 0) { tzLine = meta[mi].textContent; break; }
    }
    var chips = Array.prototype.map.call(card.querySelectorAll(".hours li"), function (li) {
      // textContent 会把跨午夜结束时间的 <span class="next-day">次日 HH:mm</span>
      // 连同前缀一并读出，正好用于固定“次日”标注。
      return li.textContent.replace(/\s+/g, " ").trim();
    });
    var noHours = false;
    for (var mj = 0; mj < meta.length; mj++) {
      if (meta[mj].textContent.indexOf("暂未开放") >= 0) { noHours = true; break; }
    }
    return {
      name: card.querySelector("h3") ? card.querySelector("h3").textContent : "",
      tz: tzLine,
      chips: chips,
      noHours: noHours,
      text: card.textContent
    };
  });
  return {
    listText: document.getElementById("venue-list").textContent,
    error: errorBox.style.display === "none" ? null : errorBox.textContent,
    form: {
      name: document.getElementById("name").value,
      capacity: document.getElementById("capacity").value,
      timezone: document.getElementById("timezone").value,
      hours: rows
    },
    cards: cards
  };
}`;

// ---- 断言收集 ----

const checks = [];
function check(scenario, name, pass, detail) {
  checks.push({ scenario, name, pass: !!pass, detail: detail === undefined ? "" : String(detail) });
}
function ok(s, n, d) { check(s, n, true, d); }
function bad(s, n, d) { check(s, n, false, d); }

async function poll(fn, { timeout = 6000, interval = 80, label = "" } = {}) {
  const deadline = Date.now() + timeout;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) { lastErr = e; }
    await sleep(interval);
  }
  throw new Error(`等待页面状态超时${label ? "（" + label + "）" : ""}${lastErr ? ": " + lastErr.message : ""}`);
}

async function main() {
  const chrome = await launchChrome();
  /** @type {CDP} */
  let cdp;
  try {
    const list = await (await fetch(`http://127.0.0.1:${chrome.port}/json/list`)).json();
    const page = list.find((t) => t.type === "page") || list[0];
    cdp = new CDP(page.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Network.enable");

    // 在每个文档的页面脚本运行前装好保存响应闸门（导航后自动重装），默认
    // 透传，不影响页面自身与既有场景。
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", {
      source: PAGE_FETCH_GATE_BOOTSTRAP,
    });

    const pageErrors = [];
    cdp.on((method, params) => {
      if (method === "Runtime.exceptionThrown") {
        pageErrors.push(params.exceptionDetails.text +
          (params.exceptionDetails.exception ? " " + params.exceptionDetails.exception.description : ""));
      }
    });

    const net = createNetworkLog(cdp);

    const navigate = async () => {
      await cdp.send("Page.navigate", { url: baseURL + "/" });
      // 等待初始列表渲染完成（“正在加载…”消失）。
      await poll(async () => {
        const text = await cdp.eval(`document.getElementById("venue-list").textContent`);
        return text && text.indexOf("正在加载") === -1;
      }, { timeout: 8000, label: "初始列表加载" });
      await sleep(100);
    };
    await navigate();

    const state = () => cdp.eval(`(${PAGE_STATE})()`);
    const fill = (data) => cdp.evalFn(PAGE_FILL, data);
    const fillPartial = (data) => cdp.evalFn(PAGE_FILL_PARTIAL, data);
    const removeAllHours = () => cdp.eval(`(${PAGE_REMOVE_ALL_HOURS})()`);
    const changeLastHourStart = (value) => cdp.evalFn(PAGE_CHANGE_LAST_START, value);
    const submit = () => cdp.eval(`(${PAGE_SUBMIT})()`);

    // —— 在途编辑相关驱动 ——
    const gateHold = () => cdp.eval(`window.__venueTestGate.hold()`);
    const gateRelease = () => cdp.eval(`window.__venueTestGate.release()`);
    const gatePending = () => cdp.eval(`window.__venueTestGate.pending()`);
    const setField = (id, value) => cdp.evalFn(PAGE_SET_FIELD, { id, value });
    const addHour = () => cdp.eval(`(${PAGE_ADD_HOUR})()`);
    const setHour = (index, patch) => cdp.evalFn(PAGE_SET_HOUR, Object.assign({ index }, patch));
    const removeHourAt = (index) => cdp.evalFn(PAGE_REMOVE_HOUR_AT, index);

    // 放行挂起的 POST 响应，并等页面的成功/失败回调与列表刷新渲染完成。
    const releaseAndSettle = async () => {
      await gateRelease();
      await sleep(350);
    };

    // 开始挂起新响应、点击保存，等到“请求已发出、响应头已回到浏览器、但页面
    // 业务回调被 gate 按住”的确定性时刻。heldPosts(before, n) 支持一次挂起
    // 多个在途保存。
    const heldPosts = async (before, n) => {
      const posts = await poll(async () => {
        const got = net.venuePosts(before);
        return got.length === n && got.every((r) => r.status !== undefined) ? got : null;
      }, { timeout: 8000, label: `挂起中的 ${n} 个 POST 响应` });
      await poll(async () => (await gatePending()) === n,
        { timeout: 8000, label: "响应被 gate 挂起" });
      return posts;
    };
    const gatedSubmit = async () => {
      const before = net.venuePosts().length;
      await gateHold();
      await submit();
      return (await heldPosts(before, 1))[0];
    };
    const findCard = (cards, name) => cards.find((c) => c.name === name) || null;
    const capacityOnCard = (card) => {
      const m = card.text.match(/容量：(\S+)\s*人/);
      return m ? m[1] : null;
    };

    // 提交后等待一个新的 POST /api/venues 响应落地。
    const submitAndWaitPost = async () => {
      const before = net.snapshot().filter((r) => r.method === "POST").length;
      await submit();
      const posts = await poll(async () => {
        const got = net.venuePosts(before);
        return got.length ? got : null;
      }, { timeout: 8000, label: "POST /api/venues" });
      // 再等页面渲染（成功后还会触发一次列表 GET）。
      await sleep(250);
      return posts[0];
    };

    // 从 JSON 文本里取出 capacity 的原始写法（不解析成 Number）。
    const rawCapacityToken = (raw) => {
      const m = raw.match(/"capacity"\s*:\s*([^,}\s]+)/);
      return m ? m[1] : null;
    };

    // ---------- 场景 1：2^53+1 大整数完整往返 ----------
    {
      const S = "大整数容量 9007199254740993";
      const exact = "9007199254740993";
      const neighbor = "9007199254740992";
      try {
        await fill({ name: "超大容量馆", capacity: exact, timezone: "Asia/Shanghai", hours: [] });
        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);

        check(S, "请求已发出且为 JSON", !!raw && raw.trim().startsWith("{"), raw);
        const token = raw ? rawCapacityToken(raw) : null;
        check(S, "请求 capacity 逐位等于 9007199254740993", token === exact,
          `token=${token} body=${raw}`);
        check(S, "请求 capacity 是未加引号的 JSON 数字", token !== null && token[0] !== '"',
          `token=${token}`);
        check(S, "请求未被舍入成相邻整数 9007199254740992", raw.indexOf(neighbor) === -1, raw);
        check(S, "服务端返回 201", post.status === 201, `status=${post.status}`);

        let s0 = await state();
        check(S, "错误提示未出现", s0.error === null, s0.error);
        const card = findCard(s0.cards, "超大容量馆");
        check(S, "成功后列表出现场地卡片", !!card, JSON.stringify(s0.cards.map((c) => c.name)));
        if (card) {
          const shown = capacityOnCard(card);
          check(S, "卡片容量完整显示 9007199254740993", shown === exact, `shown=${shown} text=${card.text}`);
          check(S, "卡片不显示相邻整数", card.text.indexOf(neighbor) === -1, card.text);
          check(S, "卡片不使用科学计数法", !/e[+-]?\d/i.test(card.text), card.text);
        }

        // 重新加载页面，模拟“再次读取已有场地列表”。
        const getsBefore = net.venueGets().length;
        await navigate();
        const get = await poll(async () => {
          const got = net.venueGets().slice(getsBefore);
          return got.length ? got[got.length - 1] : null;
        }, { timeout: 8000, label: "重新读取列表" });
        const getBody = await net.bodyOf(get);
        check(S, "列表接口响应体逐位携带该整数", getBody.indexOf(exact) >= 0 && getBody.indexOf(neighbor) === -1,
          getBody);
        s0 = await state();
        const card2 = findCard(s0.cards, "超大容量馆");
        const shown2 = card2 ? capacityOnCard(card2) : null;
        check(S, "重新读取后卡片仍显示同一整数", card2 && shown2 === exact,
          `card=${card2 ? card2.text : null}`);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 2：普通容量 120 行为不变 ----------
    {
      const S = "普通容量 120";
      try {
        await fill({ name: "一百二十人厅", capacity: "120", timezone: "UTC", hours: [] });
        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);
        const token = raw ? rawCapacityToken(raw) : null;
        check(S, "请求 capacity 为数字 120", token === "120", `token=${token} body=${raw}`);
        check(S, "服务端返回 201", post.status === 201, `status=${post.status}`);
        const s0 = await state();
        const card = findCard(s0.cards, "一百二十人厅");
        check(S, "卡片容量显示 120", card && capacityOnCard(card) === "120", card ? card.text : null);

        await navigate();
        await poll(async () => {
          const s1 = await state();
          return findCard(s1.cards, "一百二十人厅");
        }, { timeout: 8000 });
        const s1 = await state();
        const card2 = findCard(s1.cards, "一百二十人厅");
        check(S, "重新读取后仍显示 120", card2 && capacityOnCard(card2) === "120", card2 ? card2.text : null);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 3：名称含引号、反斜杠与 "capacity":1 文本 ----------
    {
      const S = "名称含特殊字符";
      // 名称同时包含引号、反斜杠、单引号，以及两类疑似 capacity 字段的文本：
      // 纯展示型的 "capacity":1，和能骗过“不处理转义引号”的扫描器的注入型
      // 片段 ","capacity":999（序列化后误闭合字符串的扫描器会把后面的
      // "capacity" 误认为对象键）。
      const trickyName = '展厅"capacity":1，注入","capacity":999，反斜杠 \\，引号\'x';
      try {
        await fill({ name: trickyName, capacity: "77", timezone: "Asia/Shanghai", hours: [] });
        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);
        check(S, "服务端返回 201", post.status === 201, `status=${post.status} body=${raw}`);

        // 请求体可按标准 JSON 解析（容量 77 很小，不存在精度问题）：
        // 名称转义后必须能还原成原文，真正的 capacity 仍是数字 77。
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch (e) { bad(S, "请求体是合法 JSON: " + e.message, raw); }
        if (parsed) {
          check(S, "名称按保存内容提交（转义可还原）", parsed.name === trickyName,
            `got=${parsed.name}`);
          check(S, "名称中的文字未变成第二个 capacity 字段",
            parsed.capacity === 77 && Object.keys(parsed).filter((k) => k === "capacity").length === 1,
            `capacity=${parsed.capacity}`);
        }
        check(S, "传输报文中容量仍是数字而非字符串",
          /"capacity"\s*:\s*77(\s|,|})/.test(raw), raw);

        let s0 = await state();
        let card = findCard(s0.cards, trickyName);
        check(S, "卡片标题按保存内容显示特殊名称", !!card, JSON.stringify(s0.cards.map((c) => c.name)));
        if (card) {
          check(S, "卡片标题包含 \"capacity\":1 原文", card.name.indexOf('"capacity":1') >= 0, card.name);
          check(S, "真实容量仍显示 77", capacityOnCard(card) === "77", card.text);
        }

        // 重新读取：服务端 JSON 会把名称里的引号转义为 \"，页面的扫描
        // 解析必须跳过字符串内部的“键”，不把它当作容量字段改写。
        const getsBefore = net.venueGets().length;
        await navigate();
        await poll(async () => {
          const got = net.venueGets().slice(getsBefore);
          return got.length ? got[got.length - 1] : null;
        }, { timeout: 8000 });
        await poll(async () => {
          const s1 = await state();
          return findCard(s1.cards, trickyName);
        }, { timeout: 8000 });
        const s1 = await state();
        card = findCard(s1.cards, trickyName);
        check(S, "重新读取后名称仍按原文显示", card && card.name === trickyName,
          card ? card.name : null);
        check(S, "重新读取后真实容量仍显示 77（名称文字未被当作容量）",
          card && capacityOnCard(card) === "77", card ? card.text : null);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 4：超范围容量被拒绝，填写内容全部保留，可纠正 ----------
    {
      const S = "超范围容量被拒绝";
      const tooBig = "9223372036854775808"; // 2^63，超出服务端 int64 上限
      try {
        const before = await state();
        const beforeNames = before.cards.map((c) => c.name);
        await fill({
          name: "超限馆",
          capacity: tooBig,
          timezone: "Asia/Shanghai",
          hours: [{ weekday: 1, start: "09:00", end: "17:00" }],
        });
        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);
        const token = raw ? rawCapacityToken(raw) : null;

        check(S, "失败请求仍按未舍入的原文提交", token === tooBig, `token=${token} body=${raw}`);
        check(S, "失败请求容量仍是数字而非字符串", token !== null && token[0] !== '"', token);
        check(S, "服务端返回 400", post.status === 400, `status=${post.status}`);

        // 读取错误响应体，确认页面展示的是服务端“超出支持范围”的原因。
        const errBody = await net.bodyOf(post);
        let serverMsg = "";
        try { serverMsg = JSON.parse(errBody).error || ""; } catch { /* ignore */ }
        check(S, "服务端说明超出支持范围", serverMsg.indexOf("超出支持范围") >= 0, errBody);

        const after = await state();
        check(S, "页面展示服务端失败原因", after.error && after.error.indexOf("超出支持范围") >= 0,
          after.error);
        const afterNames = after.cards.map((c) => c.name);
        check(S, "失败后不新增场地卡片",
          afterNames.length === beforeNames.length &&
            afterNames.every((n) => beforeNames.indexOf(n) >= 0),
          JSON.stringify({ before: beforeNames, after: afterNames }));

        // 名称、容量、时区、开放时段全部保留；失败数值不能被页面舍入。
        check(S, "失败后名称保留", after.form.name === "超限馆", after.form.name);
        check(S, "失败后容量原文保留（未舍入/未用科学计数法）",
          after.form.capacity === tooBig, after.form.capacity);
        check(S, "失败后时区保留", after.form.timezone === "Asia/Shanghai", after.form.timezone);
        const h0 = after.form.hours[0];
        check(S, "失败后已填写的开放时段保留",
          after.form.hours.length === 1 && h0.weekday === "1" &&
            h0.start === "09:00" && h0.end === "17:00",
          JSON.stringify(after.form.hours));

        // 在保留其它内容的情况下把容量改对再保存。
        await fill({
          name: "超限馆",
          capacity: "88",
          timezone: "Asia/Shanghai",
          hours: [{ weekday: 1, start: "09:00", end: "17:00" }],
        });
        const post2 = await submitAndWaitPost();
        check(S, "纠正容量后服务端返回 201", post2.status === 201, `status=${post2.status}`);
        const fixed = await state();
        check(S, "纠正后错误提示消失", fixed.error === null, fixed.error);
        const card = findCard(fixed.cards, "超限馆");
        check(S, "纠正后新增卡片且容量为 88", card && capacityOnCard(card) === "88",
          card ? card.text : null);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 5：前端既有规则：非正整数在页面拦截，不发请求 ----------
    {
      const S = "前端容量规则保持";
      try {
        // 只挑选 number 输入框会原样保留的、可解析但不合法的值：
        // "abc" 这类无法解析的文本会被浏览器清空，不属于页面自身逻辑。
        for (const bad2 of ["12.5", "0", "-5"]) {
          await fill({ name: "本地拦截馆", capacity: bad2, timezone: "UTC", hours: [] });
          const before = net.snapshot().filter((r) => r.method === "POST").length;
          await submit();
          await sleep(350);
          const sent = net.snapshot().filter((r) => r.method === "POST").length;
          const s0 = await state();
          check(S, `填写 ${bad2} 不发送请求`, sent === before, `POST 数量 ${sent - before}`);
          check(S, `填写 ${bad2} 提示必须为正整数`,
            s0.error && s0.error.indexOf("正整数") >= 0, s0.error);
          check(S, `填写 ${bad2} 后内容保留`, s0.form.capacity === bad2, s0.form.capacity);
        }
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 6：跨午夜相接时段保存成功，卡片排序、次日标注与时区 ----------
    {
      const S = "开放时段跨午夜相接与卡片展示";
      const name = "夜训馆";
      const tz = "Asia/Shanghai";
      // 严格按题目给定顺序填写：周日 22:00-02:00、周一 09:00-12:00、周一 02:00-04:00。
      const hours = [
        { weekday: 7, start: "22:00", end: "02:00" },
        { weekday: 1, start: "09:00", end: "12:00" },
        { weekday: 1, start: "02:00", end: "04:00" },
      ];
      try {
        await fill({ name, capacity: "150", timezone: tz, hours });
        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);
        check(S, "周日跨午夜结束与周一 02:00 开始相接，服务端返回 201",
          post.status === 201, `status=${post.status} body=${raw}`);

        // 请求体中的 weeklyHours 必须按填写原文与顺序提交，时间不被换算。
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch (e) { bad(S, "请求体是合法 JSON: " + e.message, raw); }
        if (parsed) {
          const same = Array.isArray(parsed.weeklyHours) &&
            parsed.weeklyHours.length === 3 &&
            hours.every((w, i) => {
              const g = parsed.weeklyHours[i];
              return g.weekday === w.weekday && g.start === w.start && g.end === w.end;
            });
          check(S, "三个时段按星期/起止时间原文与填写顺序提交", same,
            JSON.stringify(parsed && parsed.weeklyHours));
          check(S, "请求携带填写的时区且不换算时间", parsed.timezone === tz, parsed.timezone);
        }

        const s0 = await state();
        check(S, "保存成功无错误提示", s0.error === null, s0.error);
        const card = findCard(s0.cards, name);
        check(S, "新增场地立即出现在列表中", !!card,
          JSON.stringify(s0.cards.map((c) => c.name)));
        if (card) {
          check(S, "卡片显示填写的时区", card.tz === "时区：" + tz, card.tz);
          check(S, "卡片展示三段开放时间", card.chips.length === 3, JSON.stringify(card.chips));
          // 按星期及开始时间排列：周一两段（02:00 早于 09:00）在前，周日在最后。
          check(S, "卡片排序为周一 02:00、周一 09:00、周日 22:00",
            card.chips.length === 3 &&
              card.chips[0].indexOf("周一 02:00") === 0 &&
              card.chips[1].indexOf("周一 09:00") === 0 &&
              card.chips[2].indexOf("周日 22:00") === 0,
            JSON.stringify(card.chips));
          // 跨午夜的结束时间必须明确标注“次日 02:00”，不能换算或改写。
          check(S, "周日跨午夜结束明确显示“次日 02:00”",
            /周日 22:00\s*[–-]\s*次日\s*02:00/.test(card.chips[2]),
            JSON.stringify(card.chips));
          check(S, "当天结束时段不标注次日且时间不换算",
            card.chips[1] === "周一 09:00 – 12:00", JSON.stringify(card.chips));
          check(S, "跨午夜时间不被改成当天结束（24:00/00:00）",
            card.chips[2].indexOf("24:00") === -1 && card.chips[2].indexOf("00:00") === -1,
            JSON.stringify(card.chips));
        }

        // 保存成功后表单清空，开放时段行移除。
        check(S, "成功后名称清空", s0.form.name === "", JSON.stringify(s0.form.name));
        check(S, "成功后容量清空", s0.form.capacity === "", JSON.stringify(s0.form.capacity));
        check(S, "成功后时区清空", s0.form.timezone === "", JSON.stringify(s0.form.timezone));
        check(S, "成功后开放时段行全部移除", s0.form.hours.length === 0,
          JSON.stringify(s0.form.hours));

        // 重新加载：排序、次日标注与时区均来自保存数据，保持一致。
        const getsBefore = net.venueGets().length;
        await navigate();
        await poll(async () => {
          const got = net.venueGets().slice(getsBefore);
          return got.length ? got[got.length - 1] : null;
        }, { timeout: 8000, label: "重新读取列表" });
        await poll(async () => findCard((await state()).cards, name),
          { timeout: 8000, label: "重新读取后卡片出现" });
        const card2 = findCard((await state()).cards, name);
        check(S, "重新读取后时区不变", !!card2 && card2.tz === "时区：" + tz,
          card2 ? card2.tz : null);
        check(S, "重新读取后仍为周一两段在前、周日在最后",
          !!card2 && card2.chips.length === 3 &&
            card2.chips[0].indexOf("周一 02:00") === 0 &&
            card2.chips[1].indexOf("周一 09:00") === 0 &&
            card2.chips[2].indexOf("周日 22:00") === 0,
          card2 ? JSON.stringify(card2.chips) : null);
        check(S, "重新读取后仍明确标注次日 02:00",
          !!card2 && /次日\s*02:00/.test(card2.chips[2]),
          card2 ? JSON.stringify(card2.chips) : null);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 7：跨周重叠返回 400，内容全部保留；改成 02:00 后成功 ----------
    {
      const S = "跨周重叠被拒绝并可纠正";
      const name = "周末连场";
      const tz = "UTC";
      try {
        const beforeNames = (await state()).cards.map((c) => c.name);
        await fill({
          name, capacity: "66", timezone: tz,
          hours: [
            { weekday: 7, start: "22:00", end: "02:00" },
            { weekday: 1, start: "01:00", end: "03:00" },
          ],
        });
        const post = await submitAndWaitPost();
        check(S, "周日延续到周一与周一时段重叠，服务端返回 400",
          post.status === 400, `status=${post.status}`);

        const errBody = await net.bodyOf(post);
        let serverMsg = "";
        try { serverMsg = JSON.parse(errBody).error || ""; } catch { /* ignore */ }
        check(S, "服务端错误说明时段相交/重叠",
          serverMsg.indexOf("重叠") >= 0 || serverMsg.indexOf("相交") >= 0, errBody);

        const after = await state();
        check(S, "页面展示重叠原因",
          !!after.error &&
            (after.error.indexOf("重叠") >= 0 || after.error.indexOf("相交") >= 0),
          after.error);
        const afterNames = after.cards.map((c) => c.name);
        check(S, "失败后列表不增加记录，已有场地不受影响",
          afterNames.length === beforeNames.length &&
            afterNames.every((n) => beforeNames.indexOf(n) >= 0),
          JSON.stringify({ before: beforeNames, after: afterNames }));

        // 名称、容量、时区以及每行星期、起止时间与填写顺序全部保留。
        check(S, "失败后名称保留", after.form.name === name, after.form.name);
        check(S, "失败后容量保留", after.form.capacity === "66", after.form.capacity);
        check(S, "失败后时区保留", after.form.timezone === tz, after.form.timezone);
        const h = after.form.hours;
        check(S, "失败后两行时段内容与顺序保留",
          h.length === 2 &&
            h[0].weekday === "7" && h[0].start === "22:00" && h[0].end === "02:00" &&
            h[1].weekday === "1" && h[1].start === "01:00" && h[1].end === "03:00",
          JSON.stringify(h));

        // 只把周一（最后一行）开始时间改成 02:00，其余一律不动，再次保存。
        await changeLastHourStart("02:00");
        const post2 = await submitAndWaitPost();
        check(S, "只改周一开始时间为 02:00 后服务端返回 201",
          post2.status === 201, `status=${post2.status}`);
        const raw2 = await net.postDataOf(post2);
        let parsed2 = null;
        try { parsed2 = raw2 && JSON.parse(raw2); } catch { /* ignore */ }
        check(S, "第二次请求保留上一轮内容，仅周一开始时间变为 02:00",
          !!parsed2 && parsed2.name === name && parsed2.capacity === 66 &&
            parsed2.timezone === tz && parsed2.weeklyHours.length === 2 &&
            parsed2.weeklyHours[0].weekday === 7 &&
            parsed2.weeklyHours[0].start === "22:00" && parsed2.weeklyHours[0].end === "02:00" &&
            parsed2.weeklyHours[1].weekday === 1 &&
            parsed2.weeklyHours[1].start === "02:00" && parsed2.weeklyHours[1].end === "03:00",
          raw2);

        const fixed = await state();
        check(S, "纠正成功后旧错误消失", fixed.error === null, fixed.error);
        const card = findCard(fixed.cards, name);
        check(S, "纠正后新增场地卡片", !!card,
          JSON.stringify(fixed.cards.map((c) => c.name)));
        if (card) {
          check(S, "纠正后卡片时区仍为填写值", card.tz === "时区：UTC", card.tz);
          check(S, "纠正后卡片周一在前、周日跨午夜标注次日",
            card.chips.length === 2 &&
              card.chips[0].indexOf("周一 02:00 – 03:00") === 0 &&
              /周日 22:00\s*[–-]\s*次日\s*02:00/.test(card.chips[1]),
            JSON.stringify(card.chips));
        }
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 8：某行缺少开始/结束时间：指出具体行、阻止保存、保留内容 ----------
    {
      const S = "开放时段行不完整";
      const cases = [
        {
          label: "首行缺结束时间",
          hours: [{ weekday: 7, start: "22:00", end: null }],
          expectMsg: "第 1 个开放时段未填写完整",
          expectRows: [{ weekday: "7", start: "22:00", end: "" }],
        },
        {
          label: "首行缺开始时间",
          hours: [{ weekday: 3, start: null, end: "18:00" }],
          expectMsg: "第 1 个开放时段未填写完整",
          expectRows: [{ weekday: "3", start: "", end: "18:00" }],
        },
        {
          label: "第二行缺结束时间",
          hours: [
            { weekday: 1, start: "09:00", end: "12:00" },
            { weekday: 2, start: "13:00", end: null },
          ],
          expectMsg: "第 2 个开放时段未填写完整",
          expectRows: [
            { weekday: "1", start: "09:00", end: "12:00" },
            { weekday: "2", start: "13:00", end: "" },
          ],
        },
      ];
      try {
        for (const c of cases) {
          await fillPartial({
            name: "未填完馆", capacity: "42", timezone: "Asia/Tokyo", hours: c.hours,
          });
          const postsBefore = net.snapshot().filter((r) => r.method === "POST").length;
          await submit();
          await sleep(350);
          const postsSent = net.snapshot().filter((r) => r.method === "POST").length -
            postsBefore;
          const s0 = await state();
          check(S, `[${c.label}] 阻止保存且不发送请求`, postsSent === 0,
            `POST 数量 ${postsSent}`);
          check(S, `[${c.label}] 指出该行未填写完整`,
            s0.error && s0.error.indexOf(c.expectMsg) >= 0, s0.error);
          check(S, `[${c.label}] 名称/容量/时区保留`,
            s0.form.name === "未填完馆" && s0.form.capacity === "42" &&
              s0.form.timezone === "Asia/Tokyo",
            JSON.stringify({
              name: s0.form.name, capacity: s0.form.capacity, timezone: s0.form.timezone,
            }));
          const rowsOk = s0.form.hours.length === c.expectRows.length &&
            c.expectRows.every((w, i) => {
              const g = s0.form.hours[i];
              return g.weekday === w.weekday && g.start === w.start && g.end === w.end;
            });
          check(S, `[${c.label}] 已填写的星期与时间保留`, rowsOk,
            JSON.stringify(s0.form.hours));
        }
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 9：删除全部开放时段后仍可保存，卡片显示“暂未开放” ----------
    {
      const S = "删除全部时段后可保存";
      const name = "暂未定档厅";
      try {
        const beforeNames = (await state()).cards.map((c) => c.name);
        // 先加两行再逐行点“删除”，覆盖删除交互以及空数组不等于错误。
        await fill({
          name, capacity: "30", timezone: "Europe/London",
          hours: [
            { weekday: 1, start: "09:00", end: "12:00" },
            { weekday: 7, start: "20:00", end: "23:00" },
          ],
        });
        const remaining = await removeAllHours();
        check(S, "点击删除后页面无开放时段行", remaining === 0, `remaining=${remaining}`);

        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);
        check(S, "无时段的合法场地服务端返回 201", post.status === 201,
          `status=${post.status} body=${raw}`);
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch { /* ignore */ }
        check(S, "请求 weeklyHours 是空数组而非缺省或 null",
          !!parsed && Array.isArray(parsed.weeklyHours) && parsed.weeklyHours.length === 0, raw);

        const s0 = await state();
        check(S, "无时段保存不出现错误提示", s0.error === null, s0.error);
        const afterNames = s0.cards.map((c) => c.name);
        check(S, "无时段场地立即出现在列表",
          afterNames.indexOf(name) >= 0 && afterNames.length === beforeNames.length + 1,
          JSON.stringify({ before: beforeNames, after: afterNames }));
        const card = findCard(s0.cards, name);
        if (card) {
          check(S, "卡片显示“开放时段：暂未开放”",
            card.noHours && card.text.indexOf("开放时段：暂未开放") >= 0, card.text);
          check(S, "空数组不渲染任何时段标签", card.chips.length === 0,
            JSON.stringify(card.chips));
          check(S, "卡片时区照常显示", card.tz === "时区：Europe/London", card.tz);
        }

        // 重新加载后仍为“暂未开放”。
        const getsBefore = net.venueGets().length;
        await navigate();
        await poll(async () => {
          const got = net.venueGets().slice(getsBefore);
          return got.length ? got[got.length - 1] : null;
        }, { timeout: 8000, label: "重新读取列表" });
        await poll(async () => findCard((await state()).cards, name),
          { timeout: 8000, label: "重新读取后卡片出现" });
        const card2 = findCard((await state()).cards, name);
        check(S, "重新读取后仍显示“暂未开放”且无时段标签",
          !!card2 && card2.noHours && card2.chips.length === 0,
          card2 ? card2.text : null);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 10：等待期间改名称与容量——列表只认已提交值，表单保留新值 ----------
    {
      const S = "等待期间修改名称与容量";
      try {
        await fill({
          name: "排练室", capacity: "120", timezone: "Asia/Shanghai",
          hours: [{ weekday: 1, start: "09:00", end: "12:00" }],
        });
        const post = await gatedSubmit();

        // 已发出的请求体以点击保存那一刻的快照为准。
        const raw = await net.postDataOf(post);
        let parsed = null;
        try { parsed = raw && JSON.parse(raw); } catch { /* ignore */ }
        check(S, "请求体是点击时的快照（排练室/120）",
          !!parsed && parsed.name === "排练室" && parsed.capacity === 120 &&
            parsed.timezone === "Asia/Shanghai" &&
            parsed.weeklyHours.length === 1 &&
            parsed.weeklyHours[0].weekday === 1 &&
            parsed.weeklyHours[0].start === "09:00" &&
            parsed.weeklyHours[0].end === "12:00",
          raw);

        // 响应在途：页面没有乐观新增，用户仍可编辑。
        const waiting = await state();
        check(S, "响应未返回前列表不抢先出现场地",
          !findCard(waiting.cards, "排练室") && !findCard(waiting.cards, "会议室"),
          JSON.stringify(waiting.cards.map((c) => c.name)));
        await setField("name", "会议室");
        await setField("capacity", "80");
        const editing = await state();
        check(S, "等待期间输入立即反映在表单上",
          editing.form.name === "会议室" && editing.form.capacity === "80",
          JSON.stringify(editing.form));

        await releaseAndSettle();
        check(S, "服务端对快照内容返回 201", post.status === 201, `status=${post.status}`);

        const after = await state();
        check(S, "成功后无错误提示", after.error === null, after.error);
        const savedCard = findCard(after.cards, "排练室");
        check(S, "新增的是已提交的“排练室”", !!savedCard,
          JSON.stringify(after.cards.map((c) => c.name)));
        if (savedCard) {
          check(S, "卡片容量是已提交的 120", capacityOnCard(savedCard) === "120",
            savedCard.text);
          check(S, "卡片时段是已提交的周一 09:00 – 12:00",
            savedCard.chips.length === 1 && savedCard.chips[0] === "周一 09:00 – 12:00",
            JSON.stringify(savedCard.chips));
        }
        check(S, "后来填写的“会议室”没有被当成已保存场地",
          !findCard(after.cards, "会议室"),
          JSON.stringify(after.cards.map((c) => c.name)));

        // 当前表单保留用户后来的整份内容：未改的时区、时段行不能被一并清掉。
        check(S, "表单名称保留为后来填写的“会议室”", after.form.name === "会议室",
          after.form.name);
        check(S, "表单容量保留为后来填写的 80", after.form.capacity === "80",
          after.form.capacity);
        check(S, "未改动的时区不被清空", after.form.timezone === "Asia/Shanghai",
          after.form.timezone);
        const h = after.form.hours;
        check(S, "未改动的时段行原样保留（不只保留变化字段）",
          h.length === 1 && h[0].weekday === "1" &&
            h[0].start === "09:00" && h[0].end === "12:00",
          JSON.stringify(h));
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 11：等待期间改时区、改星期/起止、加行、删行 ----------
    {
      const S = "等待期间编辑开放时段";
      try {
        await fill({
          name: "时段馆", capacity: "200", timezone: "UTC",
          hours: [
            { weekday: 1, start: "09:00", end: "17:00" },
            { weekday: 3, start: "10:00", end: "12:00" },
          ],
        });
        const post = await gatedSubmit();
        const raw = await net.postDataOf(post);
        let parsed = null;
        try { parsed = raw && JSON.parse(raw); } catch { /* ignore */ }
        check(S, "请求体快照含提交时的两行与 UTC",
          !!parsed && parsed.name === "时段馆" && parsed.capacity === 200 &&
            parsed.timezone === "UTC" &&
            parsed.weeklyHours.length === 2 &&
            parsed.weeklyHours[0].weekday === 1 &&
            parsed.weeklyHours[0].start === "09:00" &&
            parsed.weeklyHours[0].end === "17:00" &&
            parsed.weeklyHours[1].weekday === 3 &&
            parsed.weeklyHours[1].start === "10:00" &&
            parsed.weeklyHours[1].end === "12:00",
          raw);

        // 等待期间：时区改 Asia/Shanghai；首行周一改周二、结束改 16:00；
        // 第二行开始改 13:00；新增第三行周五 18:00-20:00；再删掉第二行。
        await setField("timezone", "Asia/Shanghai");
        await setHour(0, { weekday: 2, end: "16:00" });
        await setHour(1, { start: "13:00" });
        const rowCount = await addHour();
        check(S, "等待期间可以新增时段行", rowCount === 3, `rows=${rowCount}`);
        await setHour(2, { weekday: 5, start: "18:00", end: "20:00" });
        const afterDelete = await removeHourAt(1);
        check(S, "等待期间可以删除时段行", afterDelete === 2, `rows=${afterDelete}`);

        await releaseAndSettle();
        check(S, "服务端对快照内容返回 201", post.status === 201, `status=${post.status}`);

        const after = await state();
        check(S, "成功后无错误提示", after.error === null, after.error);
        const card = findCard(after.cards, "时段馆");
        check(S, "列表新增已提交的“时段馆”", !!card,
          JSON.stringify(after.cards.map((c) => c.name)));
        if (card) {
          check(S, "卡片时区是提交时的 UTC", card.tz === "时区：UTC", card.tz);
          // 卡片只渲染真正保存的两行（按既有规则排序），后续编辑不得混入。
          check(S, "卡片只显示已保存的两个时段",
            card.chips.length === 2 &&
              card.chips[0] === "周一 09:00 – 17:00" &&
              card.chips[1] === "周三 10:00 – 12:00",
            JSON.stringify(card.chips));
          check(S, "卡片不混入在途新增/修改的时段与时区",
            card.text.indexOf("13:00") === -1 &&
              card.text.indexOf("16:00") === -1 &&
              card.text.indexOf("18:00") === -1 &&
              card.text.indexOf("周二") === -1 &&
              card.text.indexOf("周五") === -1 &&
              card.text.indexOf("Asia/Shanghai") === -1,
            card.text);
        }

        // 表单保留当前剩余各行的内容与填写顺序，连同改动后的时区。
        const h = after.form.hours;
        check(S, "表单保留剩余两行及填写顺序",
          after.form.name === "时段馆" && after.form.capacity === "200" &&
            after.form.timezone === "Asia/Shanghai" &&
            h.length === 2 &&
            h[0].weekday === "2" && h[0].start === "09:00" && h[0].end === "16:00" &&
            h[1].weekday === "5" && h[1].start === "18:00" && h[1].end === "20:00",
          JSON.stringify(after.form));
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 12：在途改过又改回原值，成功后仍保留整份表单 ----------
    {
      const S = "在途编辑后改回原值";
      const form0 = {
        name: "改回原值馆", capacity: "50", timezone: "UTC",
        hours: [{ weekday: 4, start: "08:00", end: "10:00" }],
      };
      try {
        await fill(form0);
        const post = await gatedSubmit();
        // 先改乱再逐字改回提交时的样子。
        await setField("name", "临时名称");
        await setField("capacity", "60");
        await setHour(0, { start: "09:00" });
        await setField("name", form0.name);
        await setField("capacity", form0.capacity);
        await setHour(0, { start: "08:00" });

        await releaseAndSettle();
        check(S, "服务端返回 201", post.status === 201, `status=${post.status}`);
        const after = await state();
        const card = findCard(after.cards, form0.name);
        check(S, "已提交场地正常进入列表", !!card && capacityOnCard(card) === "50",
          card ? card.text : null);
        // 脏标记一旦置位不可被“改回去”撤销：整份表单必须保留，不能清空。
        check(S, "即使值与提交时相同，名称仍保留不清空",
          after.form.name === form0.name, JSON.stringify(after.form.name));
        check(S, "即使值与提交时相同，容量仍保留不清空",
          after.form.capacity === "50", after.form.capacity);
        check(S, "即使值与提交时相同，时区仍保留不清空",
          after.form.timezone === "UTC", after.form.timezone);
        const h = after.form.hours;
        check(S, "即使值与提交时相同，时段行仍保留不清空",
          h.length === 1 && h[0].weekday === "4" &&
            h[0].start === "08:00" && h[0].end === "10:00",
          JSON.stringify(h));
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 13：在途把表单改“坏”不影响已发出的合法保存，下次保存才校验 ----------
    {
      const S = "在途留下空名/非法容量/半行时段";
      try {
        await fill({
          name: "在途改坏馆", capacity: "30", timezone: "Asia/Shanghai",
          hours: [{ weekday: 2, start: "09:00", end: "12:00" }],
        });
        const post = await gatedSubmit();
        const raw = await net.postDataOf(post);
        const token = raw ? rawCapacityToken(raw) : null;
        check(S, "发出的仍是合法快照（容量 30）", token === "30", `token=${token} body=${raw}`);

        // 等待期间把名称清空、容量改成 0、时段结束时间删空。
        await setField("name", "");
        await setField("capacity", "0");
        await setHour(0, { end: null });

        await releaseAndSettle();
        check(S, "已发出的合法保存仍然成功（201）", post.status === 201,
          `status=${post.status}`);
        const after = await state();
        check(S, "成功不带来错误提示（坏内容留待下次保存校验）",
          after.error === null, after.error);
        const card = findCard(after.cards, "在途改坏馆");
        check(S, "卡片按快照显示在途改坏馆/30/周二 09:00-12:00",
          !!card && capacityOnCard(card) === "30" &&
            card.chips.length === 1 && card.chips[0] === "周二 09:00 – 12:00",
          card ? card.text : null);
        // 坏内容原样留下，不被恢复也不被清空。
        const h = after.form.hours;
        check(S, "空名称、容量 0、半行时段原样保留",
          after.form.name === "" && after.form.capacity === "0" &&
            after.form.timezone === "Asia/Shanghai" &&
            h.length === 1 && h[0].weekday === "2" &&
            h[0].start === "09:00" && h[0].end === "",
          JSON.stringify(after.form));

        // 下一次主动保存时才逐项接受前端校验，且拦截时不发请求。
        const blocked = async (expectMsg, label) => {
          const postsBefore = net.venuePosts().length;
          await submit();
          await sleep(350);
          const s = await state();
          const sent = net.venuePosts().length - postsBefore;
          check(S, `[${label}] 非法内容在页面拦截且不发请求`, sent === 0,
            `新增 POST 数 ${sent}`);
          check(S, `[${label}] 提示“${expectMsg}”`,
            !!s.error && s.error.indexOf(expectMsg) >= 0, s.error);
        };
        await blocked("名称不能为空", "空名称");
        await setField("name", "在途补全馆");
        await blocked("容量必须是正整数", "容量为 0");
        await setField("capacity", "31");
        await blocked("第 1 个开放时段未填写完整", "半行时段");

        // 补全后再保存：以当前整份表单提交并成功（这次等待期间无编辑，
        // 沿用既有清空行为）。
        await setHour(0, { end: "13:00" });
        const post2 = await submitAndWaitPost();
        const raw2 = await net.postDataOf(post2);
        let p2 = null;
        try { p2 = raw2 && JSON.parse(raw2); } catch { /* ignore */ }
        check(S, "补全后按当前表单提交且返回 201",
          post2.status === 201 && !!p2 && p2.name === "在途补全馆" &&
            p2.capacity === 31 && p2.weeklyHours.length === 1 &&
            p2.weeklyHours[0].weekday === 2 &&
            p2.weeklyHours[0].start === "09:00" &&
            p2.weeklyHours[0].end === "13:00",
          `status=${post2.status} body=${raw2}`);
        const cleared = await state();
        const card2 = findCard(cleared.cards, "在途补全馆");
        check(S, "补全保存的场地进入列表", !!card2 && capacityOnCard(card2) === "31",
          card2 ? card2.text : null);
        check(S, "本次无在途编辑，成功后整份表单清空",
          cleared.error === null && cleared.form.name === "" &&
            cleared.form.capacity === "" && cleared.form.timezone === "" &&
            cleared.form.hours.length === 0,
          JSON.stringify(cleared.form));
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 14：等待期间完全无编辑，成功后整份表单清空（既有行为兜底） ----------
    {
      const S = "等待期间无编辑仍清空";
      try {
        await fill({
          name: "无编辑馆", capacity: "10", timezone: "Europe/London",
          hours: [
            { weekday: 6, start: "10:00", end: "11:00" },
            { weekday: 7, start: "11:00", end: "12:00" },
          ],
        });
        const post = await gatedSubmit();
        check(S, "响应挂起期间已有 1 个保存被按住", await gatePending() === 1, null);
        const waiting = await state();
        check(S, "响应到达前不乐观新增卡片", !findCard(waiting.cards, "无编辑馆"),
          JSON.stringify(waiting.cards.map((c) => c.name)));

        await releaseAndSettle();
        check(S, "服务端返回 201", post.status === 201, `status=${post.status}`);
        const after = await state();
        const card = findCard(after.cards, "无编辑馆");
        check(S, "已保存场地出现在列表",
          !!card && capacityOnCard(card) === "10" && card.chips.length === 2,
          card ? card.text : null);
        check(S, "名称清空", after.form.name === "", JSON.stringify(after.form.name));
        check(S, "容量清空", after.form.capacity === "", JSON.stringify(after.form.capacity));
        check(S, "时区清空", after.form.timezone === "", JSON.stringify(after.form.timezone));
        check(S, "时段行全部移除", after.form.hours.length === 0,
          JSON.stringify(after.form.hours));
        check(S, "无错误提示", after.error === null, after.error);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 15：保存失败时保留响应到达时的当前填写、显示原因、不新增场地 ----------
    {
      const S = "等待期间编辑后保存失败";
      try {
        const beforeNames = (await state()).cards.map((c) => c.name);
        await fill({
          name: "在途失败馆", capacity: "40", timezone: "UTC",
          hours: [
            { weekday: 7, start: "22:00", end: "02:00" },
            { weekday: 1, start: "01:00", end: "03:00" },
          ],
        });
        const post = await gatedSubmit();
        const raw = await net.postDataOf(post);
        let parsed = null;
        try { parsed = raw && JSON.parse(raw); } catch { /* ignore */ }
        // 失败请求的请求体同样是点击时快照（周一 01:00 开始，造成跨周重叠）。
        check(S, "失败请求按提交快照发出",
          !!parsed && parsed.name === "在途失败馆" && parsed.capacity === 40 &&
            parsed.weeklyHours[1].start === "01:00",
          raw);

        // 等待期间继续编辑：名称、容量、时区都改，周一那行开始改 05:00。
        await setField("name", "在途失败改名");
        await setField("capacity", "45");
        await setField("timezone", "Asia/Tokyo");
        await setHour(1, { start: "05:00" });

        await releaseAndSettle();
        check(S, "服务端对快照返回 400", post.status === 400, `status=${post.status}`);
        const errBody = await net.bodyOf(post);
        let serverMsg = "";
        try { serverMsg = JSON.parse(errBody).error || ""; } catch { /* ignore */ }
        check(S, "失败原因为时段重叠/相交",
          serverMsg.indexOf("重叠") >= 0 || serverMsg.indexOf("相交") >= 0, errBody);

        const after = await state();
        check(S, "页面显示失败原因",
          !!after.error &&
            (after.error.indexOf("重叠") >= 0 || after.error.indexOf("相交") >= 0),
          after.error);
        const afterNames = after.cards.map((c) => c.name);
        check(S, "失败提交不显示为新场地（提交名与后来填写名都不出现）",
          afterNames.length === beforeNames.length &&
            afterNames.indexOf("在途失败馆") === -1 &&
            afterNames.indexOf("在途失败改名") === -1 &&
            afterNames.every((n) => beforeNames.indexOf(n) >= 0),
          JSON.stringify({ before: beforeNames, after: afterNames }));
        // 等待期间的编辑不被撤销，也不恢复成提交前的值。
        const h = after.form.hours;
        check(S, "失败后保留响应到达时的整份当前填写",
          after.form.name === "在途失败改名" &&
            after.form.capacity === "45" &&
            after.form.timezone === "Asia/Tokyo" &&
            h.length === 2 &&
            h[0].weekday === "7" && h[0].start === "22:00" && h[0].end === "02:00" &&
            h[1].weekday === "1" && h[1].start === "05:00" && h[1].end === "03:00",
          JSON.stringify(after.form));
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    check("浏览器", "交互过程无页面脚本异常", pageErrors.length === 0,
      pageErrors.join("\n"));

    process.stdout.write(JSON.stringify({
      harnessError: null,
      browser: chrome.browserInfo.Browser,
      checks,
    }) + "\n");
  } finally {
    if (cdp) cdp.close();
    chrome.cleanup();
  }
}

main().catch((err) => failInfra(err && err.stack || err));
