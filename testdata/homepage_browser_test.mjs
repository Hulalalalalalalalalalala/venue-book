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

// ---- POST 挂起闸门（Fetch 域拦截）----

// createPostGate 用 CDP 的 Fetch 域把发往 /api/venues 的 POST 暂停在“请求
// 已经发出、响应尚未返回”的阶段，真实复现“点击保存后、结果返回前继续编辑
// 表单”的等待窗口：pause() 之后遇到的下一个场地 POST 会被挂起，测试先在
// 页面里完成编辑，再决定放行到真实服务端（pass）或直接合成响应（fulfill，
// 例如 400），响应内容与到达时机完全由测试掌握。列表 GET 等其余请求一律
// 立即放行，不改变页面与服务端的既有行为。
function createPostGate(cdp) {
  // held: id -> { id, requestId, url, body, done }
  const held = new Map();
  let seq = 0;
  let paused = false;
  let waiters = [];

  cdp.on((method, params) => {
    if (method !== "Fetch.requestPaused") return;
    // 监听器内的异步失败（例如请求已失效）绝不能冒泡成 unhandledRejection，
    // 统一吞掉：挂起/放行失败只会让对应场景的断言失败。
    (async () => {
      const isVenuePost = params.request && params.request.method === "POST" &&
        params.request.url.includes("/api/venues");
      if (!paused || !isVenuePost) {
        try {
          await cdp.send("Fetch.continueRequest", { requestId: params.requestId });
        } catch { /* 请求可能已失效，忽略 */ }
        return;
      }
      // 挂起时立即取回请求体原文：此时尚未放行，内容必然是点击保存那一刻的
      // 快照，之后页面怎么改都影响不到它。
      let body = null;
      try {
        const out = await cdp.send("Fetch.getRequestBody", { requestId: params.requestId });
        body = out.base64Encoded ? Buffer.from(out.body, "base64").toString("utf8") : out.body;
      } catch {
        body = params.request.postData || null;
      }
      const id = ++seq;
      held.set(id, { id, requestId: params.requestId, url: params.request.url, body, done: false });
      const ws = waiters;
      waiters = [];
      for (const w of ws) w(id);
    })().catch(() => { /* 竞态失败交给场景断言处理 */ });
  });

  return {
    async enable() {
      await cdp.send("Fetch.enable", {
        patterns: [{ urlPattern: "*api/venues*", requestStage: "Request" }],
      });
    },
    pause() { paused = true; },
    resume() { paused = false; },
    nextHold(timeout = 8000) {
      for (const rec of held.values()) {
        if (!rec.done) return Promise.resolve(rec.id);
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("等待 POST /api/venues 被挂起超时")), timeout);
        waiters.push((id) => { clearTimeout(timer); resolve(id); });
      });
    },
    bodyOf(id) {
      const rec = held.get(id);
      return rec ? rec.body : null;
    },
    // pass 放行到真实服务端，由真实处理链给出 201/400。
    async pass(id) {
      const rec = held.get(id);
      if (!rec || rec.done) return;
      rec.done = true;
      await cdp.send("Fetch.continueRequest", { requestId: rec.requestId });
    },
    // fulfill 不接触真实服务端，直接合成一个响应，保证“失败提交”不可能在
    // 服务端落地。
    async fulfill(id, status, payload) {
      const rec = held.get(id);
      if (!rec || rec.done) return;
      rec.done = true;
      const raw = JSON.stringify(payload);
      await cdp.send("Fetch.fulfillRequest", {
        requestId: rec.requestId,
        responseCode: status,
        responseHeaders: [
          { name: "Content-Type", value: "application/json; charset=utf-8" },
          { name: "Content-Length", value: String(Buffer.byteLength(raw)) },
        ],
        body: Buffer.from(raw, "utf8").toString("base64"),
      });
    },
    // continueAll 放行所有仍挂着的请求：场景中断时自愈，避免遗留 fetch 永久
    // 挂起影响后续场景。
    async continueAll() {
      for (const rec of held.values()) {
        if (!rec.done) {
          rec.done = true;
          try {
            await cdp.send("Fetch.continueRequest", { requestId: rec.requestId });
          } catch { /* ignore */ }
        }
      }
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

// setFields：只修改给出的字段（name/capacity/timezone 任意子集），其余字段
// 原封不动，用于在保存请求在途期间做局部编辑。值按真实输入方式注入并派发
// input/change，确保页面的脏标记等监听真实触发。
const PAGE_SET_FIELDS = `function (data) {
  function setValue(el, value) {
    var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, String(value));
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  if (data.name !== undefined && data.name !== null) {
    setValue(document.getElementById("name"), data.name);
  }
  if (data.capacity !== undefined && data.capacity !== null) {
    setValue(document.getElementById("capacity"), data.capacity);
  }
  if (data.timezone !== undefined && data.timezone !== null) {
    setValue(document.getElementById("timezone"), data.timezone);
  }
  return true;
}`;

// hoursEdit：在不动其它行的前提下修改开放时段行集合：
//   {op:"setRow", index, weekday?, start?, end?}  修改指定行（null 表示清空该时间）
//   {op:"addRow", weekday, start, end}            点“添加开放时段”后填值
//   {op:"removeRow", index}                       点指定行的“删除”
// 与真实用户操作一致，新增/删除会触发页面在这些按钮上挂的脏标记。
const PAGE_HOURS_EDIT = `function (action) {
  function setValue(el, value) {
    var proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    var setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, String(value));
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  function rows() { return document.querySelectorAll("#hours-rows .hour-row"); }
  if (action.op === "removeRow") {
    var all = rows();
    if (!all[action.index]) return false;
    all[action.index].querySelector("button.danger").click();
    return true;
  }
  if (action.op === "addRow") {
    document.getElementById("add-hour").click();
    var added = rows()[rows().length - 1];
    if (action.weekday !== undefined && action.weekday !== null) {
      setValue(added.querySelector(".hour-weekday"), action.weekday);
    }
    if (action.start !== undefined && action.start !== null) {
      setValue(added.querySelector(".hour-start"), action.start);
    }
    if (action.end !== undefined && action.end !== null) {
      setValue(added.querySelector(".hour-end"), action.end);
    }
    return true;
  }
  if (action.op === "setRow") {
    var row = rows()[action.index];
    if (!row) return false;
    if (action.weekday !== undefined && action.weekday !== null) {
      setValue(row.querySelector(".hour-weekday"), action.weekday);
    }
    if (action.start !== undefined) {
      setValue(row.querySelector(".hour-start"), action.start === null ? "" : action.start);
    }
    if (action.end !== undefined) {
      setValue(row.querySelector(".hour-end"), action.end === null ? "" : action.end);
    }
    return true;
  }
  return false;
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

    const pageErrors = [];
    cdp.on((method, params) => {
      if (method === "Runtime.exceptionThrown") {
        pageErrors.push(params.exceptionDetails.text +
          (params.exceptionDetails.exception ? " " + params.exceptionDetails.exception.description : ""));
      }
    });

    const net = createNetworkLog(cdp);

    // POST 挂起闸门：默认不拦截（请求一律立即放行），仅在“等待期编辑”场景
    // 中临时 pause，把下一个场地 POST 挂在响应返回之前。
    const gate = createPostGate(cdp);
    await gate.enable();

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
    const setFields = (data) => cdp.evalFn(PAGE_SET_FIELDS, data);
    const hoursEdit = (action) => cdp.evalFn(PAGE_HOURS_EDIT, action);
    const removeAllHours = () => cdp.eval(`(${PAGE_REMOVE_ALL_HOURS})()`);
    const changeLastHourStart = (value) => cdp.evalFn(PAGE_CHANGE_LAST_START, value);
    const submit = () => cdp.eval(`(${PAGE_SUBMIT})()`);
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

    // ---- “等待期间继续编辑”场景共用辅助 ----

    const WEEKDAY_CN = { 1: "周一", 2: "周二", 3: "周三", 4: "周四", 5: "周五", 6: "周六", 7: "周日" };
    const toMin = (hhmm) => {
      const p = String(hhmm).split(":");
      return Number(p[0]) * 60 + Number(p[1]);
    };
    // expectedChips 按页面既有规则（先星期、再按开始时间）计算卡片时段标签，
    // 跨午夜（结束早于开始）标注“次日 HH:mm”。
    const expectedChips = (hours) => hours.slice()
      .sort((a, b) => (a.weekday - b.weekday) || (toMin(a.start) - toMin(b.start)))
      .map((h) => WEEKDAY_CN[h.weekday] + " " + h.start + " – " +
        (toMin(h.end) < toMin(h.start) ? "次日 " + h.end : h.end));

    // submitHeld：点击保存并让该 POST 停在“请求已发出、响应未返回”。拿到的
    // body 是点击那一刻的整份内容；调用方随后在页面里编辑，再决定 pass/
    // fulfill。gate 在挂住请求后立即恢复放行，后续请求（含成功后的列表
    // GET）不受影响，被挂住的这一个仍需显式放行。
    const submitHeld = async () => {
      gate.pause();
      await submit();
      const id = await gate.nextHold();
      gate.resume();
      const body = gate.bodyOf(id);
      let parsed = null;
      try { parsed = JSON.parse(body); } catch { /* 由场景断言 */ }
      return { id, body, parsed };
    };

    // waitLastPostStatus 等待最近一个 POST 的响应状态出现在 Network 记录里，
    // 再等一拍让页面完成表单处理与列表渲染，返回该条 POST 记录。
    const waitLastPostStatus = async (status) => {
      const rec = await poll(async () => {
        const posts = net.venuePosts();
        const last = posts[posts.length - 1];
        return last && last.status === status ? last : null;
      }, { timeout: 8000, label: "挂起 POST 响应 status=" + status });
      await sleep(350);
      return rec;
    };

    // formIs 逐字段比较当前表单（时段按 DOM 中的当前顺序）。
    const formIs = (form, want) =>
      form.name === want.name &&
      form.capacity === String(want.capacity) &&
      form.timezone === want.timezone &&
      form.hours.length === want.hours.length &&
      want.hours.every((h, i) => {
        const g = form.hours[i];
        return !!g && g.weekday === String(h.weekday) && g.start === h.start && g.end === h.end;
      });

    // assertRequestSnapshot 断言已发出的请求体就是点击保存那一刻的快照。
    const assertRequestSnapshot = (S, label, held, want) => {
      check(S, label + "请求体是合法 JSON", !!held.parsed, held.body);
      if (!held.parsed) return;
      check(S, label + "请求名称为点击时的值", held.parsed.name === want.name,
        `got=${held.parsed.name}`);
      check(S, label + "请求容量为点击时的值", held.parsed.capacity === Number(want.capacity),
        `got=${held.parsed.capacity}`);
      check(S, label + "请求时区为点击时的值", held.parsed.timezone === want.timezone,
        `got=${held.parsed.timezone}`);
      const sameRows = Array.isArray(held.parsed.weeklyHours) &&
        held.parsed.weeklyHours.length === want.hours.length &&
        want.hours.every((h, i) => {
          const g = held.parsed.weeklyHours[i];
          return !!g && g.weekday === h.weekday && g.start === h.start && g.end === h.end;
        });
      check(S, label + "请求各时段按点击时的内容与顺序", sameRows,
        JSON.stringify(held.parsed.weeklyHours));
    };

    // assertSavedCard 断言列表卡片严格等于服务端真正保存的快照：名称、容量、
    // 时区、排序后的时段标签一致，且不混入任何等待期里出现的未提交文本。
    const assertSavedCard = (S, label, cards, want, absentTexts) => {
      const card = findCard(cards, want.name);
      check(S, label + "列表新增的是已提交场地卡片", !!card,
        JSON.stringify(cards.map((c) => c.name)));
      if (!card) return;
      check(S, label + "卡片容量为已提交容量", capacityOnCard(card) === String(want.capacity),
        card.text);
      check(S, label + "卡片时区为已提交时区", card.tz === "时区：" + want.timezone, card.tz);
      const wantChips = expectedChips(want.hours);
      check(S, label + "卡片只显示已保存时段（排序/次日标注照旧）",
        card.chips.length === wantChips.length &&
          wantChips.every((t, i) => card.chips[i] === t),
        JSON.stringify({ got: card.chips, want: wantChips }));
      (absentTexts || []).forEach((txt) => {
        check(S, label + "卡片不混入未提交内容「" + txt + "」", card.text.indexOf(txt) === -1,
          card.text);
      });
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

    // ===== “点击保存后、结果返回前继续编辑”回归场景 =====
    //
    // 一次保存以点击那一刻的整份内容为准；等待期间用户可以继续修改名称、
    // 容量、时区与每周开放时间。成功返回时：列表新增的是“已提交”的那份
    // （绝不混入后来填写的内容），而当前表单必须完整保留用户正在填写的整
    // 份内容（不恢复旧值、不只留变化字段、不清空未提交内容）。

    // ---------- 场景 10：等待期改名称与容量，成功后两者互不串扰 ----------
    {
      const S = "等待期改名称容量";
      const submitted = { name: "排练室", capacity: "120", timezone: "Asia/Shanghai", hours: [] };
      const draft = { name: "会议室", capacity: "80", timezone: "Asia/Shanghai", hours: [] };
      try {
        const beforeNames = (await state()).cards.map((c) => c.name);
        await fill(submitted);
        const held = await submitHeld();
        // 响应未返回时修改名称与容量。
        await setFields({ name: draft.name, capacity: draft.capacity });

        check(S, "等待期间已发请求携带的仍是点击时快照（排练室/120）",
          !!held.parsed && held.parsed.name === "排练室" && held.parsed.capacity === 120,
          held.body);
        let pending = await state();
        check(S, "响应返回前表单已显示新填写内容（会议室/80）",
          pending.form.name === "会议室" && pending.form.capacity === "80",
          JSON.stringify(pending.form));
        check(S, "响应返回前列表尚未新增场地",
          pending.cards.map((c) => c.name).length === beforeNames.length,
          JSON.stringify(pending.cards.map((c) => c.name)));

        await gate.pass(held.id);
        const post = await waitLastPostStatus(201);
        check(S, "已提交的合法保存返回 201", !!post, "");
        const after = await state();
        check(S, "成功后无错误提示", after.error === null, after.error);
        assertSavedCard(S, "成功后", after.cards, submitted, ["会议室", "80"]);
        check(S, "列表只多出这一条已提交记录",
          after.cards.length === beforeNames.length + 1 &&
            after.cards.map((c) => c.name).indexOf("会议室") === -1,
          JSON.stringify(after.cards.map((c) => c.name)));
        check(S, "当前表单完整保留会议室/80（不恢复排练室/120、不清空）",
          formIs(after.form, draft), JSON.stringify(after.form));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 11：等待期改时区，卡片显示已提交时区、表单留新值 ----------
    {
      const S = "等待期改时区";
      const submitted = { name: "时区提交馆", capacity: "30", timezone: "UTC", hours: [] };
      const draft = { name: "时区提交馆", capacity: "30", timezone: "Asia/Tokyo", hours: [] };
      try {
        await fill(submitted);
        const held = await submitHeld();
        await setFields({ timezone: draft.timezone });
        assertRequestSnapshot(S, "", held, submitted);
        await gate.pass(held.id);
        await waitLastPostStatus(201);
        const after = await state();
        assertSavedCard(S, "", after.cards, submitted, ["Asia/Tokyo"]);
        check(S, "表单时区保留后来填的 Asia/Tokyo", after.form.timezone === "Asia/Tokyo",
          after.form.timezone);
        check(S, "未改动的名称/容量也原样保留（不只保留变化字段）",
          after.form.name === submitted.name && after.form.capacity === "30",
          JSON.stringify(after.form));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 12：等待期改某行星期/起止时间、加行、删行，顺序与内容保留 ----------
    {
      const S = "等待期增删改开放时段";
      const name = "时段编辑馆";
      const submitted = {
        name, capacity: "200", timezone: "Asia/Shanghai",
        hours: [
          { weekday: 2, start: "09:00", end: "12:00" },
          { weekday: 4, start: "14:00", end: "18:00" },
          { weekday: 6, start: "10:00", end: "11:00" },
        ],
      };
      try {
        await fill(submitted);
        const held = await submitHeld();
        assertRequestSnapshot(S, "", held, submitted);

        // 等待期间：改第一行星期与起止；删第二行；末尾新增一行。
        await hoursEdit({ op: "setRow", index: 0, weekday: 3, start: "08:30", end: "09:30" });
        await hoursEdit({ op: "removeRow", index: 1 });
        await hoursEdit({ op: "addRow", weekday: 5, start: "19:00", end: "21:00" });

        // 当前剩余各行（按 DOM 顺序）：改后的原首行、原第三行、新增行。
        const draft = {
          name, capacity: "200", timezone: "Asia/Shanghai",
          hours: [
            { weekday: 3, start: "08:30", end: "09:30" },
            { weekday: 6, start: "10:00", end: "11:00" },
            { weekday: 5, start: "19:00", end: "21:00" },
          ],
        };
        const mid = await state();
        check(S, "响应返回前时段行已是当前编辑结果与顺序", formIs(mid.form, draft),
          JSON.stringify(mid.form.hours));

        await gate.pass(held.id);
        await waitLastPostStatus(201);
        const after = await state();
        // 卡片只按已提交的三行显示（按星期/开始时间排序）：
        // 周二 09:00、周四 14:00、周六 10:00。
        assertSavedCard(S, "", after.cards, submitted,
          ["周三", "08:30", "19:00", "周五"]);
        const card = findCard(after.cards, name);
        check(S, "卡片时段排序为周二/周四/周六（已保存内容）",
          !!card && card.chips.length === 3 &&
            card.chips[0].indexOf("周二 09:00") === 0 &&
            card.chips[1].indexOf("周四 14:00") === 0 &&
            card.chips[2].indexOf("周六 10:00") === 0,
          card ? JSON.stringify(card.chips) : null);
        check(S, "成功后当前表单保留剩余各行的内容与填写顺序",
          formIs(after.form, draft), JSON.stringify(after.form.hours));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 12b：等待期只改已有行的星期与起止（不增不删） ----------
    // 与场景 12 分开：加行/删除按钮本身也会标记脏表单，这里专门保证“在已有
    // 行上改星期或时间”这一条监听链路独立有效——不能因为没点增删按钮就把
    // 成功响应当作无编辑而清空。
    {
      const S = "等待期只改已有时段行";
      const name = "行内编辑馆";
      const submitted = {
        name, capacity: "90", timezone: "UTC",
        hours: [
          { weekday: 1, start: "09:00", end: "12:00" },
          { weekday: 3, start: "13:00", end: "15:00" },
        ],
      };
      try {
        await fill(submitted);
        const held = await submitHeld();
        assertRequestSnapshot(S, "", held, submitted);
        // 只在两行原有控件上修改：第一行改星期，第二行改起止时间。
        await hoursEdit({ op: "setRow", index: 0, weekday: 2 });
        await hoursEdit({ op: "setRow", index: 1, start: "16:00", end: "17:30" });
        const draft = {
          name, capacity: "90", timezone: "UTC",
          hours: [
            { weekday: 2, start: "09:00", end: "12:00" },
            { weekday: 3, start: "16:00", end: "17:30" },
          ],
        };

        await gate.pass(held.id);
        await waitLastPostStatus(201);
        const after = await state();
        assertSavedCard(S, "", after.cards, submitted, ["周二", "16:00", "17:30"]);
        const card = findCard(after.cards, name);
        check(S, "卡片仍显示已保存的周一/周三两行",
          !!card && card.chips.length === 2 &&
            card.chips[0].indexOf("周一 09:00") === 0 &&
            card.chips[1].indexOf("周三 13:00") === 0,
          card ? JSON.stringify(card.chips) : null);
        check(S, "行内修改后表单两行当前值完整保留、行数不变",
          formIs(after.form, draft), JSON.stringify(after.form.hours));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 13：等待期先改再改回提交值，成功后仍保留整份表单 ----------
    {
      const S = "等待期改回原值仍保留";
      const submitted = {
        name: "改回原值馆", capacity: "45", timezone: "UTC",
        hours: [{ weekday: 1, start: "09:00", end: "17:00" }],
      };
      try {
        await fill(submitted);
        const held = await submitHeld();
        // 动过以后又改回与提交完全相同的值；按要求仍算“等待期间发生过编辑”。
        await setFields({ name: "临时新名字", capacity: "99" });
        await hoursEdit({ op: "setRow", index: 0, weekday: 7, start: "06:00", end: "08:00" });
        await setFields({ name: submitted.name, capacity: submitted.capacity });
        await hoursEdit({ op: "setRow", index: 0, weekday: 1, start: "09:00", end: "17:00" });

        await gate.pass(held.id);
        await waitLastPostStatus(201);
        const after = await state();
        assertSavedCard(S, "", after.cards, submitted, []);
        check(S, "即使值已改回提交时的样子，表单仍整份保留、不清空",
          formIs(after.form, submitted), JSON.stringify(after.form));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 14：等待期把内容改空/改非法/留半截时段，合法提交照成功、表单原样留 ----------
    {
      const S = "等待期改成非法内容";
      const submitted = {
        name: "合法已提交馆", capacity: "120", timezone: "Asia/Shanghai",
        hours: [
          { weekday: 1, start: "09:00", end: "12:00" },
          { weekday: 3, start: "13:00", end: "15:00" },
        ],
      };
      try {
        const beforeNames = (await state()).cards.map((c) => c.name);
        await fill(submitted);
        const held = await submitHeld();
        assertRequestSnapshot(S, "", held, submitted);

        // 名称清空、容量改成浏览器 number 输入仍会保留的非法文本 12.5、
        // 时区清空、第一行时段只留开始时间（半截）。
        await setFields({ name: "", capacity: "12.5", timezone: "" });
        await hoursEdit({ op: "setRow", index: 0, end: null });

        await gate.pass(held.id);
        await waitLastPostStatus(201);
        const after = await state();
        check(S, "已发出的合法保存仍然成功、无错误提示", after.error === null, after.error);
        assertSavedCard(S, "", after.cards, submitted, ["12.5"]);
        check(S, "列表只新增已提交的合法场地",
          after.cards.length === beforeNames.length + 1 &&
            after.cards.map((c) => c.name).indexOf(submitted.name) >= 0,
          JSON.stringify(after.cards.map((c) => c.name)));
        // 后来填成的空值/非法/半截内容原样留下，不借这次成功被校验或清掉。
        check(S, "表单名称保持清空", after.form.name === "", JSON.stringify(after.form.name));
        check(S, "表单容量保留非法值 12.5（下次保存才校验）",
          after.form.capacity === "12.5", after.form.capacity);
        check(S, "表单时区保持清空", after.form.timezone === "", after.form.timezone);
        const h = after.form.hours;
        check(S, "半截时段与另一行均原样保留",
          h.length === 2 &&
            h[0].weekday === "1" && h[0].start === "09:00" && h[0].end === "" &&
            h[1].weekday === "3" && h[1].start === "13:00" && h[1].end === "15:00",
          JSON.stringify(h));

        // 这些当前内容只有在用户“下一次主动保存”时才接受校验：再次点击保存
        // 应在前端被拦截（名称为空），不发请求，并把当前填写继续留在表单里。
        const postsBefore = net.snapshot().filter((r) => r.method === "POST").length;
        await submit();
        await sleep(350);
        const postsSent = net.snapshot().filter((r) => r.method === "POST").length - postsBefore;
        const retried = await state();
        check(S, "下一次主动保存被前端拦截、不发请求", postsSent === 0, `POST 数量 ${postsSent}`);
        check(S, "拦截时提示名称不能为空",
          retried.error && retried.error.indexOf("名称不能为空") >= 0, retried.error);
        check(S, "被拦截后非法填写仍然保留",
          retried.form.name === "" && retried.form.capacity === "12.5" &&
            retried.form.hours.length === 2 && retried.form.hours[0].end === "",
          JSON.stringify(retried.form));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 15：等待期编辑后保存失败——显示原因、保留当前内容、不新增卡片 ----------
    {
      const S = "等待期编辑后保存失败";
      const submitted = {
        name: "失败提交馆", capacity: "50", timezone: "UTC",
        hours: [{ weekday: 2, start: "10:00", end: "12:00" }],
      };
      const draft = {
        name: "失败后正在填写", capacity: "70", timezone: "Asia/Shanghai",
        hours: [
          { weekday: 5, start: "18:00", end: "20:00" },
          { weekday: 7, start: "09:00", end: "10:30" },
        ],
      };
      try {
        const beforeNames = (await state()).cards.map((c) => c.name);
        await fill(submitted);
        const held = await submitHeld();
        assertRequestSnapshot(S, "", held, submitted);
        await setFields({ name: draft.name, capacity: draft.capacity, timezone: draft.timezone });
        await hoursEdit({ op: "setRow", index: 0, weekday: 5, start: "18:00", end: "20:00" });
        await hoursEdit({ op: "addRow", weekday: 7, start: "09:00", end: "10:30" });

        // 直接合成 400：该“保存”没有接触真实服务端，不可能落地成新场地。
        const reason = "模拟服务端拒绝：开放时段存在相交";
        await gate.fulfill(held.id, 400, { error: reason });
        await waitLastPostStatus(400);
        const after = await state();
        check(S, "失败时显示失败原因",
          !!after.error && after.error.indexOf(reason) >= 0, after.error);
        const afterNames = after.cards.map((c) => c.name);
        check(S, "失败提交不显示为新场地（已提交名与新填写名都不出现）",
          afterNames.length === beforeNames.length &&
            afterNames.every((n) => beforeNames.indexOf(n) >= 0) &&
            afterNames.indexOf(submitted.name) === -1,
          JSON.stringify({ before: beforeNames, after: afterNames }));
        check(S, "失败不撤销等待期间的编辑：整份当前表单保留",
          formIs(after.form, draft), JSON.stringify(after.form));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 16：等待期间完全没有编辑：成功后整份表单清空（既有行为） ----------
    {
      const S = "等待期无编辑则清空";
      const submitted = {
        name: "无编辑清空馆", capacity: "60", timezone: "Europe/Paris",
        hours: [
          { weekday: 1, start: "09:00", end: "12:00" },
          { weekday: 7, start: "22:00", end: "02:00" },
        ],
      };
      const empty = { name: "", capacity: "", timezone: "", hours: [] };
      try {
        await fill(submitted);
        const held = await submitHeld();
        assertRequestSnapshot(S, "", held, submitted);
        // 刻意不做任何编辑，直接放行。
        await gate.pass(held.id);
        await waitLastPostStatus(201);
        const after = await state();
        check(S, "成功后无错误提示", after.error === null, after.error);
        assertSavedCard(S, "", after.cards, submitted, []);
        const card = findCard(after.cards, submitted.name);
        check(S, "卡片仍按既有规则排序并标注跨午夜次日",
          !!card && card.chips.length === 2 &&
            card.chips[0].indexOf("周一 09:00") === 0 &&
            /周日 22:00\s*[–-]\s*次日\s*02:00/.test(card.chips[1]),
          card ? JSON.stringify(card.chips) : null);
        check(S, "名称/容量/时区全部清空",
          after.form.name === "" && after.form.capacity === "" && after.form.timezone === "",
          JSON.stringify(after.form));
        check(S, "时段行全部移除", after.form.hours.length === 0,
          JSON.stringify(after.form.hours));
        check(S, "空表单与空时段行集合一致", formIs(after.form, empty), JSON.stringify(after.form));
      } catch (e) {
        await gate.continueAll();
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
