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
  off(fn) {
    const i = this.eventListeners.indexOf(fn);
    if (i >= 0) this.eventListeners.splice(i, 1);
  }
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

// createFetchGate 用 CDP 的 Fetch 域把发往 /api/venues 的 POST/GET 暂停在
// “请求已经发出、响应尚未返回”的阶段，真实复现两类等待窗口：
//   - POST 挂起：点击保存后、结果返回前继续编辑表单（既有等待期编辑场景）；
//   - GET 挂起：首页初次列表读取尚未结束时保存，保存触发的较新读取与较旧
//     读取先后返回顺序由测试完全掌握（列表读取竞态回归场景）。
// pause(method) 之后遇到的下一个匹配 method 的场地请求会被挂起，测试先在
// 页面里完成操作，再决定放行到真实服务端（pass）、直接合成响应（fulfill /
// fulfillText，例如 400、无法解析的 JSON）或让请求连接失败（fail）；响应
// 内容与到达时机完全由测试掌握。不匹配的请求一律立即放行，不改变页面与
// 服务端的既有行为。
function createFetchGate(cdp) {
  // held: id -> { id, requestId, url, method, body, done }
  const held = new Map();
  let seq = 0;
  // pausedMethods: 哪些 method 处于“下一个请求挂起”状态（一次性）。
  const pausedMethods = new Set();
  let waiters = [];
  // methodWaiters: 等待“下一个指定 method 请求被挂起”的回调。
  const methodWaiters = new Map();

  cdp.on((method, params) => {
    if (method !== "Fetch.requestPaused") return;
    // 监听器内的异步失败（例如请求已失效）绝不能冒泡成 unhandledRejection，
    // 统一吞掉：挂起/放行失败只会让对应场景的断言失败。
    (async () => {
      const isVenueReq = params.request.url.includes("/api/venues");
      const reqMethod = params.request.method;
      if (!isVenueReq || !pausedMethods.has(reqMethod)) {
        try {
          await cdp.send("Fetch.continueRequest", { requestId: params.requestId });
        } catch { /* 请求可能已失效，忽略 */ }
        return;
      }
      // 挂起时立即取回请求体原文：POST 此时尚未放行，内容必然是点击保存
      // 那一刻的快照，之后页面怎么改都影响不到它。
      let body = null;
      if (reqMethod === "POST") {
        try {
          const out = await cdp.send("Fetch.getRequestBody", { requestId: params.requestId });
          body = out.base64Encoded ? Buffer.from(out.body, "base64").toString("utf8") : out.body;
        } catch {
          body = params.request.postData || null;
        }
      }
      // “下一个该 method 请求挂起”是一次性的：挂住后立即恢复对后续请求
      // 放行，避免把保存成功后触发的 GET 等后续请求也挂住。
      pausedMethods.delete(reqMethod);
      const id = ++seq;
      held.set(id, {
        id,
        requestId: params.requestId,
        // Fetch 域的 requestId（interception-job-*）与 Network 域的请求 id
        // 不同；requestPaused 额外给出 networkId，监听网络事件时要用它关联。
        networkId: params.networkId || params.requestId,
        url: params.request.url,
        method: reqMethod,
        body,
        done: false,
      });
      const ws = waiters;
      waiters = [];
      for (const w of ws) w(id);
      const mw = methodWaiters.get(reqMethod);
      if (mw) {
        methodWaiters.delete(reqMethod);
        for (const w of mw) w(id);
      }
    })().catch(() => { /* 竞态失败交给场景断言处理 */ });
  });

  return {
    async enable() {
      await cdp.send("Fetch.enable", {
        patterns: [{ urlPattern: "*api/venues*", requestStage: "Request" }],
      });
    },
    pause(method = "POST") { pausedMethods.add(method); },
    resume(method = "POST") { pausedMethods.delete(method); },
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
    // nextHoldMethod 等待下一个被挂起的指定 method 请求（GET 竞态场景使用）。
    // afterId 用于两次读取同时挂起时跳过更早被挂住的那一个。
    nextHoldMethod(reqMethod, opts = {}) {
      const afterId = opts.afterId || 0;
      const timeout = opts.timeout || 8000;
      for (const rec of held.values()) {
        if (!rec.done && rec.method === reqMethod && rec.id > afterId) return Promise.resolve(rec.id);
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`等待 ${reqMethod} /api/venues 被挂起超时`)), timeout);
        const list = methodWaiters.get(reqMethod) || [];
        list.push((id) => {
          if (id <= afterId) return; // 理论上不会发生（新 id 恒更大），保险起见忽略
          clearTimeout(timer);
          resolve(id);
        });
        methodWaiters.set(reqMethod, list);
      });
    },
    bodyOf(id) {
      const rec = held.get(id);
      return rec ? rec.body : null;
    },
    // pass 放行到真实服务端，由真实处理链给出响应。
    async pass(id) {
      const rec = held.get(id);
      if (!rec || rec.done) return;
      rec.done = true;
      await cdp.send("Fetch.continueRequest", { requestId: rec.requestId });
    },
    // fulfill 不接触真实服务端，直接合成一个 JSON 响应；对 POST 可合成
    // 400 保证“失败提交”不可能在服务端落地，对 GET 可合成 HTTP 错误。
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
    // fulfillText 合成任意文本响应（Content-Type 仍声明 JSON），用于让较新
    // 或较旧读取拿到“HTTP 200 但响应不是有效 JSON”的结果。
    async fulfillText(id, status, text) {
      const rec = held.get(id);
      if (!rec || rec.done) return;
      rec.done = true;
      const raw = String(text);
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
    // fail 让请求在网络层失败（连接失败）：不返回任何 HTTP 响应。
    async fail(id, reason = "Failed") {
      const rec = held.get(id);
      if (!rec || rec.done) return;
      rec.done = true;
      try {
        await cdp.send("Fetch.failRequest", { requestId: rec.requestId, errorReason: reason });
      } catch { /* 请求可能已失效，忽略 */ }
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
    // networkIdOf 返回闸门记录对应的 Network 域请求 id（Fetch 拦截 id 与
    // Network 事件 id 不同，需用 requestPaused.networkId 关联），供网络记录
    // 精确等待“这条被挂起的请求已真正交付/失败”。
    networkIdOf(id) {
      const rec = held.get(id);
      return rec ? rec.networkId : null;
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

    // Fetch 闸门：默认不拦截（请求一律立即放行）；POST 场景临时 pause() 挂住
    // 下一个场地 POST，列表读取竞态场景用 pause("GET") 挂住指定的列表 GET。
    const gate = createFetchGate(cdp);
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

    // ===== 列表读取先后返回（读取竞态）回归场景 =====
    //
    // 首页打开时会读取一次场地列表；新增场地保存成功后又会读取一次。页面按
    // 读取的“发起顺序”处理响应：只有最近发起的读取能更新列表，更早读取随后
    // 成功（含空数组）或失败（HTTP 错误、无法解析的 JSON、连接失败）都必须
    // 被丢弃。下列场景完全经由现有首页操作触发竞态——初次 GET 在页面加载
    // 时被挂起，用户在它返回前用现有表单填写合法场地并点击现有“保存”，
    // POST 与保存触发的较新 GET 由真实服务端处理，两次读取的返回内容与先后
    // 顺序由闸门精确控制，断言对象始终是页面最终可见的卡片、空提示或错误。

    // waitRequestSettled：等待“这一条被闸门挂起的请求”在浏览器侧真正收到
    // 响应（Network.responseReceived）或被判定网络失败
    // （Network.loadingFailed），再补一拍等页面渲染。fulfillRequest/
    // failRequest 返回只代表 Chrome 接受了指令，响应到达页面是异步事件，
    // 用固定 sleep 等待会在机器慢时产生“页面还没渲染就断言”的抖动；按
    // Network 域请求 id（Fetch.requestPaused 的 networkId）监听该请求的
    // 网络事件，能把交付时机确定下来。
    const waitRequestSettled = (gateId) => new Promise((resolve) => {
      const requestId = gate.networkIdOf(gateId);
      let done = false;
      let timer;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        cdp.off(onEvent);
        sleep(120).then(resolve);
      };
      const onEvent = (method, params) => {
        if (!params || params.requestId !== requestId) return;
        if (method === "Network.responseReceived" || method === "Network.loadingFailed") {
          finish();
        }
      };
      cdp.on(onEvent);
      // 兜底：极端情况下事件错过时不永久挂起，交给场景断言暴露问题。
      timer = setTimeout(finish, 4000);
    });

    // disposeAndWait：先登记“该请求已交付/失败”的监听，再执行处置
    // （pass/fulfill/fail），最后等浏览器真正收到结果，避免处置与监听之间
    // 的竞态漏掉网络事件。
    const disposeAndWait = async (gateId, action) => {
      const delivered = waitRequestSettled(gateId);
      await action(gateId);
      await delivered;
    };

    // expectCardsShow 断言列表区域当前是“场地卡片视图”：present 中每个场地
    // 都在场且容量/时区/时段内容来自对应那次读取，absentNames 中任何名字都
    // 不出现；同时不出现空提示/加载提示/读取失败提示。不要求卡片总数恰好
    // 等于 present 数量——较新读取走真实服务端时会携带此前各场景保存的场地，
    // 它们本来就该继续显示。
    const expectCardsShow = async (S, label, present, absentNames) => {
      const s = await state();
      check(S, label + "列表为场地卡片视图而非空/错误/加载提示",
        s.cards.length >= present.length &&
          s.listText.indexOf("还没有场地记录") === -1 &&
          s.listText.indexOf("正在加载") === -1,
        `list=${s.listText}`);
      present.forEach((v) => {
        const card = findCard(s.cards, v.name);
        check(S, label + "存在场地卡片「" + v.name + "」", !!card,
          JSON.stringify(s.cards.map((c) => c.name)));
        if (!card) return;
        check(S, label + "「" + v.name + "」卡片容量来自较新读取",
          capacityOnCard(card) === String(v.capacity), card.text);
        check(S, label + "「" + v.name + "」卡片时区来自较新读取",
          card.tz === "时区：" + v.timezone, card.tz);
        if (v.hours !== undefined) {
          const wantChips = expectedChips(v.hours);
          check(S, label + "「" + v.name + "」卡片开放时段来自较新读取",
            card.chips.length >= wantChips.length &&
              wantChips.every((t) => card.chips.indexOf(t) >= 0),
            JSON.stringify({ got: card.chips, want: wantChips }));
        }
      });
      (absentNames || []).forEach((n) => {
        check(S, label + "不显示仅存在于较旧响应中的「" + n + "」",
          !findCard(s.cards, n), JSON.stringify(s.cards.map((c) => c.name)));
      });
      return s;
    };

    // expectEmptyHint：当前有效读取成功返回空数组时应展示原有的无场地提示。
    const expectEmptyHint = async (S, label) => {
      const s = await state();
      check(S, label + "显示“还没有场地记录”空提示",
        s.cards.length === 0 && s.listText.indexOf("还没有场地记录") >= 0,
        `list=${s.listText}`);
      check(S, label + "不显示加载或读取失败提示",
        s.listText.indexOf("正在加载") === -1 &&
          s.listText.indexOf("读取场地列表失败") === -1,
        `list=${s.listText}`);
      return s;
    };

    // expectListError：列表区域展示读取失败原因。HTTP 错误/无效 JSON 的原因
    // 带“读取场地列表失败”前缀；连接失败时页面直接显示浏览器给出的原文
    // （如 Failed to fetch），因此这里统一按“无卡片、无空提示、无加载提示、
    // 文本非空”识别失败状态，再用 fragment 精确核对原因片段。
    const expectListError = async (S, label, fragment) => {
      const s = await state();
      const isErrorState = s.cards.length === 0 &&
        s.listText.indexOf("还没有场地记录") === -1 &&
        s.listText.indexOf("正在加载") === -1 &&
        s.listText.trim() !== "";
      check(S, label + "列表显示读取失败提示（无卡片/空提示/加载提示）",
        isErrorState, `list=${s.listText}`);
      if (fragment) {
        check(S, label + "失败原因包含：" + fragment,
          s.listText.indexOf(fragment) >= 0, `list=${s.listText}`);
      }
      return s;
    };

    // expectListTextStable：连续两次读取列表文本完全一致，用来证明迟到响应
    // 没有在任何一个微任务时点改写界面。
    const expectListTextStable = async (S, label) => {
      const a = (await state()).listText;
      await sleep(150);
      const b = (await state()).listText;
      check(S, label, a === b && a.indexOf("正在加载") === -1, `a=${a} b=${b}`);
      return a;
    };

    // startFreshWithHeldInitialGet：重新加载首页并让初次列表读取挂起，在它
    // 返回前用现有表单填写 venue 并点击现有“保存”。POST 与保存成功触发的
    // 较新 GET 都由真实服务端处理并正常返回（较新 GET 立即完成，因此页面
    // 先显示真实保存结果），初次 GET 仍挂起等待场景控制。返回两个读取的
    // 闸门 id 与真实 POST 记录。
    const startFreshWithHeldInitialGet = async (venue) => {
      const getsAtStart = net.venueGets().length;
      gate.pause("GET");
      await cdp.send("Page.navigate", { url: baseURL + "/" });
      const olderId = await gate.nextHoldMethod("GET");
      // 初次读取未返回：页面仍是“正在加载…”。
      await poll(async () => {
        const t = await cdp.eval(`document.getElementById("venue-list").textContent`);
        return t && t.indexOf("正在加载") >= 0;
      }, { timeout: 4000, label: "初次读取挂起中的加载提示" });
      await fill(venue);
      const postsBefore = net.venuePosts().length;
      await submit();
      const post = await poll(async () => {
        const got = net.venuePosts(postsBefore);
        return got.length ? got[got.length - 1] : null;
      }, { timeout: 8000, label: "保存 POST 发出" });
      // POST 由真实服务端处理，等待 201；其成功后触发的较新 GET 不被拦截
      // （一次性 pause 已被初次 GET 消费），正常返回包含新场地的列表。
      await poll(async () => post.status === 201 ? post : null,
        { timeout: 8000, label: "保存 POST 返回 201" });
      // 等待较新 GET 发出（真实服务端，立即返回）：它是本次导航之后的第二
      // 个列表读取（不能用累计总数判断，网络记录保留了此前各场景的请求）。
      const newerGet = await poll(async () => {
        const got = net.venueGets().slice(getsAtStart);
        return got.length >= 2 ? got[got.length - 1] : null;
      }, { timeout: 8000, label: "保存触发较新读取" });
      // 等待较新读取真实渲染出本次保存的卡片（而不是固定睡眠），避免机器
      // 较慢时在页面渲染前就断言。
      await poll(async () => findCard((await state()).cards, venue.name) ? true : null,
        { timeout: 8000, label: "较新读取渲染新场地卡片" });
      return { olderId, newerGet, post };
    };

    // venuesJSON：构造列表接口风格的响应文本。
    const venuesJSON = (venues) => JSON.stringify({ venues });

    // ---------- 场景 17：无交错读取时，正常返回的列表照常显示 ----------
    {
      const S = "读取竞态·无交错正常显示";
      try {
        // 此刻服务端已有前面场景保存的多个场地；重新加载让唯一一次读取
        // 正常走真实服务端，列表应照常显示已保存场地且无错误。
        const beforeNames = (await state()).cards.map((c) => c.name);
        await navigate();
        const s = await state();
        check(S, "无交错读取后显示已有场地卡片",
          s.cards.length === beforeNames.length &&
            beforeNames.every((n) => s.cards.some((c) => c.name === n)),
          JSON.stringify({ before: beforeNames, after: s.cards.map((c) => c.name) }));
        check(S, "无交错读取不显示空/错误/加载提示",
          s.listText.indexOf("还没有场地记录") === -1 &&
            s.listText.indexOf("读取场地列表失败") === -1 &&
            s.listText.indexOf("正在加载") === -1,
          `list=${s.listText}`);
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 18：当前有效读取返回空数组，仍显示原有无场地提示 ----------
    // 经由首页现有表单保存引发列表刷新：初次读取挂起时保存第一个合法场地，
    // 保存触发的较新读取真实返回并显示卡片；随后再用现有表单保存第二个合法
    // 场地，把这次保存引发的“当前有效读取”（最近发起）挂起并让它成功返回
    // 空数组——页面必须显示原有的“还没有场地记录”。最后放行仍在途的初次
    // 读取，空提示也不能被更旧结果覆盖。
    {
      const S = "读取竞态·当前有效读取为空";
      const first = { name: "空结果前先保存馆", capacity: "35", timezone: "Asia/Shanghai", hours: [] };
      const second = { name: "空结果触发器", capacity: "9", timezone: "UTC", hours: [] };
      try {
        const { olderId } = await startFreshWithHeldInitialGet(first);
        let s = await state();
        check(S, "第一次保存后较新读取已显示其卡片",
          !!findCard(s.cards, first.name), JSON.stringify(s.cards.map((c) => c.name)));

        // 第二次保存：挂住它触发的列表刷新（此时初次读取仍挂着）。
        await fill(second);
        gate.pause("GET");
        const postsBefore = net.venuePosts().length;
        await submit();
        await poll(async () => net.venuePosts(postsBefore).length ? true : null,
          { timeout: 8000, label: "第二次保存 POST 发出" });
        const emptyGetId = await gate.nextHoldMethod("GET", { afterId: olderId });
        await poll(async () => {
          const posts = net.venuePosts();
          const last = posts[posts.length - 1];
          return last && last.status === 201 ? last : null;
        }, { timeout: 8000, label: "第二次保存返回 201" });
        // 当前有效读取成功返回空数组：显示原有的无场地提示。
        await disposeAndWait(emptyGetId, (id) => gate.fulfillText(id, 200, venuesJSON([])));
        await expectEmptyHint(S, "当前有效读取返回空数组后");

        // 仍在途的初次（更旧）读取随后成功返回含场地的保存前列表，也不能
        // 追加卡片或替换空提示。
        const staleVenues = [{
          id: "stale-before-empty", name: "空提示后旧读里的旧馆", capacity: 11,
          timezone: "UTC", weeklyHours: [],
        }];
        await disposeAndWait(olderId, (id) => gate.fulfillText(id, 200, venuesJSON(staleVenues)));
        await expectEmptyHint(S, "更旧读取迟到返回旧列表后");
        s = await state();
        check(S, "不把更旧响应里的场地追加进列表",
          !findCard(s.cards, "空提示后旧读里的旧馆"),
          JSON.stringify(s.cards.map((c) => c.name)));
        await expectListTextStable(S, "空提示在更旧读取迟到后保持稳定");
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 19：较新读取先显示新场地，旧读取随后成功返回保存前列表 ----------
    {
      const S = "读取竞态·旧读迟到返回旧列表";
      const venue = {
        name: "竞态旧列表馆", capacity: "128", timezone: "Asia/Tokyo",
        hours: [{ weekday: 2, start: "10:00", end: "12:30" }],
      };
      try {
        const { olderId, newerGet } = await startFreshWithHeldInitialGet(venue);
        const newerBody = await net.bodyOf(newerGet);
        let newerVenues = null;
        try { newerVenues = JSON.parse(newerBody).venues; } catch { /* ignore */ }
        await expectCardsShow(S, "较新读取先返回后", [
          { name: venue.name, capacity: venue.capacity, timezone: venue.timezone, hours: venue.hours },
        ]);
        check(S, "较新读取的完整列表确实包含新场地",
          Array.isArray(newerVenues) && newerVenues.some((v) => v.name === venue.name),
          newerBody);

        // 初次（较旧）读取随后返回“保存之前”的列表：放行到真实服务端拿到
        // 的可能已含新场地，无法保证是“保存前列表”，因此合成一份保存前列
        // 表：包含一条较新结果里不存在的旧场地、且不含新场地，专门验证旧
        // 记录不会被追加进来、页面以较新读取的完整列表为准。
        const staleName = "仅旧读取里的旧馆";
        const staleVenues = [{
          id: "stale-old-only", name: staleName, capacity: 11,
          timezone: "UTC", weeklyHours: [],
        }];
        await disposeAndWait(olderId, (id) => gate.fulfillText(id, 200, venuesJSON(staleVenues)));
        const s = await expectCardsShow(S, "旧读取迟到返回旧列表后", [
          { name: venue.name, capacity: venue.capacity, timezone: venue.timezone, hours: venue.hours },
        ], [staleName]);
        check(S, "新场地不消失、不变成空提示",
          !!findCard(s.cards, venue.name), s.listText);
        await expectListTextStable(S, "旧读取迟到后显示不再变化");
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 20：较新读取先显示新场地，旧读取随后返回空数组 ----------
    {
      const S = "读取竞态·旧读迟到返回空数组";
      const venue = {
        name: "竞态旧空馆", capacity: "72", timezone: "Europe/Paris",
        hours: [{ weekday: 1, start: "22:00", end: "02:00" }],
      };
      try {
        const { olderId } = await startFreshWithHeldInitialGet(venue);
        await expectCardsShow(S, "较新读取先返回后", [
          { name: venue.name, capacity: venue.capacity, timezone: venue.timezone, hours: venue.hours },
        ]);
        // 较旧读取随后返回空数组：绝不能清掉卡片、改成“还没有场地记录”。
        await disposeAndWait(olderId, (id) => gate.fulfillText(id, 200, venuesJSON([])));
        const s = await state();
        check(S, "旧读取空数组后新场地卡片仍在",
          s.cards.length >= 1 && !!findCard(s.cards, venue.name),
          `list=${s.listText}`);
        check(S, "旧读取空数组后不显示“还没有场地记录”",
          s.listText.indexOf("还没有场地记录") === -1, `list=${s.listText}`);
        check(S, "卡片仍显示较新读取的容量/时区/时段",
          (() => {
            const c = findCard(s.cards, venue.name);
            if (!c) return false;
            const wantChips = expectedChips(venue.hours);
            return capacityOnCard(c) === venue.capacity &&
              c.tz === "时区：" + venue.timezone &&
              c.chips.length === wantChips.length &&
              wantChips.every((t, i) => c.chips[i] === t);
          })(),
          JSON.stringify(findCard(s.cards, venue.name)));
        await expectListTextStable(S, "旧读取空数组后显示不再变化");
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 21：较新读取先显示新场地，旧读取随后以三种方式失败 ----------
    for (const failure of [
      { kind: "HTTP 错误", apply: (id) => gate.fulfillText(id, 500, JSON.stringify({ error: "boom" })), fragment: "HTTP 500" },
      { kind: "无法解析的 JSON", apply: (id) => gate.fulfillText(id, 200, "这不是JSON{,"), fragment: "不是有效的 JSON" },
      { kind: "连接失败", apply: (id) => gate.fail(id, "Failed"), fragment: null },
    ]) {
      const S = "读取竞态·旧读迟到失败（" + failure.kind + "）";
      const venue = { name: "旧读失败馆·" + failure.kind, capacity: "46", timezone: "UTC", hours: [] };
      try {
        const { olderId } = await startFreshWithHeldInitialGet(venue);
        await expectCardsShow(S, "较新读取先返回后", [
          { name: venue.name, capacity: venue.capacity, timezone: venue.timezone, hours: [] },
        ]);
        await disposeAndWait(olderId, (id) => failure.apply(id));
        const s = await state();
        check(S, "旧读取" + failure.kind + "后卡片不被换成失败提示",
          !!findCard(s.cards, venue.name) &&
            s.listText.indexOf("读取场地列表失败") === -1,
          `list=${s.listText}`);
        check(S, "旧读取" + failure.kind + "后不出现空提示",
          s.listText.indexOf("还没有场地记录") === -1, `list=${s.listText}`);
        await expectListTextStable(S, "旧读取" + failure.kind + "后显示不再变化");
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 22：较新读取失败并已显示原因，旧读取随后成功/失败都不能遮错 ----------
    // 流程：挂住初次（旧）读取；填表保存；把保存触发的较新读取也挂住（两次
    // 读取同时在途）；先让较新读取以指定方式失败并确认页面显示其原因；再让
    // 较旧读取成功返回非空列表、成功返回空数组，或以自己的方式失败，断言
    // 列表始终只显示较新读取的原因、且原因文本不被替换。
    const runNewerFailsScenario = async (newerFailure, olderOutcome, label) => {
      const S = "读取竞态·新读失败后旧读" + label;
      const venue = {
        name: "新读失败馆·" + newerFailure.kind + "·" + label,
        capacity: "53", timezone: "Asia/Shanghai",
        hours: [{ weekday: 3, start: "09:00", end: "18:00" }],
      };
      try {
        gate.pause("GET");
        await cdp.send("Page.navigate", { url: baseURL + "/" });
        const olderId = await gate.nextHoldMethod("GET");
        await fill(venue);
        // 保存 POST 走真实服务端；保存成功会立刻发起较新读取，把它也挂住：
        // 在点击保存前再次 pause("GET")（第一次 pause 已被初次读取消费）。
        gate.pause("GET");
        const postsBefore = net.venuePosts().length;
        await submit();
        await poll(async () => net.venuePosts(postsBefore).length ? true : null,
          { timeout: 8000, label: "保存 POST 发出" });
        await poll(async () => {
          const posts = net.venuePosts();
          const last = posts[posts.length - 1];
          return last && last.status === 201 ? last : null;
        }, { timeout: 8000, label: "保存 POST 返回 201" });
        const newerId = await gate.nextHoldMethod("GET", { afterId: olderId });
        check(S, "两次读取同时在途且为不同请求", newerId > olderId,
          `older=${olderId} newer=${newerId}`);

        // 较新读取先失败，页面显示它的原因。
        await disposeAndWait(newerId, (id) => newerFailure.apply(id));
        const errState = await expectListError(S, "较新读取失败后", newerFailure.fragment);
        const newerErrorText = errState.listText;

        // 较旧读取随后返回。
        let olderAction;
        if (olderOutcome.type === "list") {
          const staleVenues = [{
            id: "stale-after-newer-error", name: "错误后旧读里的旧馆", capacity: 8,
            timezone: "UTC", weeklyHours: [],
          }];
          olderAction = (id) => gate.fulfillText(id, 200, venuesJSON(staleVenues));
        } else if (olderOutcome.type === "empty") {
          olderAction = (id) => gate.fulfillText(id, 200, venuesJSON([]));
        } else {
          olderAction = (id) => olderOutcome.apply(id);
        }
        await disposeAndWait(olderId, olderAction);
        const s = await state();
        // 较新失败是连接失败时，页面显示的是浏览器原文（如 Failed to
        // fetch）而不带“读取场地列表失败”前缀，因此这里只严格比较文本与
        // 较新失败时完全一致，并核对无卡片/空提示。
        check(S, "旧读取" + label + "后仍只显示较新读取的失败原因",
          s.cards.length === 0 &&
            s.listText.trim() !== "" &&
            s.listText === newerErrorText,
          `now=${s.listText} newerWas=${newerErrorText}`);
        check(S, "旧读取" + label + "后不出现场地卡片或空提示",
          s.listText.indexOf("还没有场地记录") === -1 &&
            s.listText.indexOf("错误后旧读里的旧馆") === -1,
          `list=${s.listText}`);
        await expectListTextStable(S, "旧读取" + label + "后错误保持稳定");

        // 保存成功后的表单清空规则不受列表读取失败影响：无等待期编辑时
        // 表单应已清空。
        check(S, "保存本身成功，表单按既有规则清空",
          s.form.name === "" && s.form.capacity === "" && s.form.timezone === "" &&
            s.form.hours.length === 0,
          JSON.stringify(s.form));
      } catch (e) {
        await gate.continueAll();
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    };

    const newerFailures = [
      { kind: "HTTP错误", apply: (id) => gate.fulfillText(id, 503, JSON.stringify({ error: "x" })), fragment: "HTTP 503" },
      { kind: "无效JSON", apply: (id) => gate.fulfillText(id, 200, "<<<not json>>>"), fragment: "不是有效的 JSON" },
      { kind: "连接失败", apply: (id) => gate.fail(id, "Failed"), fragment: null },
    ];
    // 对每一种较新失败，覆盖较旧读取随后：成功返回列表、成功返回空数组、
    // 以另一种 HTTP 错误失败（502，原因文本与较新失败不同，专门检测较旧
    // 失败不能用自己的原因替换较新失败已显示的原因）。
    for (const nf of newerFailures) {
      await runNewerFailsScenario(nf, { type: "list" }, "成功返回列表");
      await runNewerFailsScenario(nf, { type: "empty" }, "成功返回空数组");
      await runNewerFailsScenario(nf,
        { type: "fail", apply: (id) => gate.fulfillText(id, 502, JSON.stringify({ error: "y" })) },
        "也失败（原因不同）");
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
