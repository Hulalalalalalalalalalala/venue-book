// 首页浏览器端到端回归脚本（由 homepage_test.go 通过 go test 调用，不单独运行）。
//
// 用法：node homepage_browser_test.mjs <baseURL> [chrome 可执行文件路径]
//
// 脚本用 Chrome DevTools Protocol 驱动本机无头 Chrome 打开真实首页，覆盖
// “用户填表 → 提交 → 查看已保存场地”的完整链路：容量逐位准确提交/显示，
// 以及每周开放时段的填写、保存、卡片展示、跨周重叠拒绝与表单内容保留。
// stdout 最后一行输出 JSON 结果。除浏览器/脚本自身的基础设施故障（退出码
// 非 0）外，页面行为层面的断言失败都记录在 JSON 的 checks 中，由 Go 测试
// 统一判定。
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
    return {
      name: card.querySelector("h3") ? card.querySelector("h3").textContent : "",
      text: card.textContent,
      // 卡片上每个开放时段条目的展示文本，按页面实际渲染顺序排列。
      hours: Array.prototype.map.call(card.querySelectorAll(".hours li"), function (li) {
        return li.textContent;
      })
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

// setHourField：只修改某一行的某一个字段（星期/开始/结束），其余已填写
// 内容一概不动，模拟用户纠正单个输入。data = {index, selector, value}。
const PAGE_SET_HOUR_FIELD = `function (data) {
  var rows = document.querySelectorAll("#hours-rows .hour-row");
  var row = rows[data.index];
  if (!row) return false;
  var el = row.querySelector(data.selector);
  if (!el) return false;
  var proto = el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  var setter = Object.getOwnPropertyDescriptor(proto, "value").set;
  setter.call(el, String(data.value));
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}`;

// removeAllHours：逐一点击每行的“删除”按钮，返回删除后剩余的行数。
const PAGE_REMOVE_ALL_HOURS = `function () {
  document.querySelectorAll("#hours-rows .hour-row .danger").forEach(function (btn) { btn.click(); });
  return document.querySelectorAll("#hours-rows .hour-row").length;
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

    // ---------- 场景 6：开放时段填写、保存与卡片展示 ----------
    {
      // 按 周日22:00–02:00、周一09:00–12:00、周一02:00–04:00 的顺序填写。
      // 周日的结束时间是次日凌晨，与周一 02:00 开始的时段只是相接，应保存成功。
      const S = "开放时段保存与展示";
      const hours = [
        { weekday: 7, start: "22:00", end: "02:00" },
        { weekday: 1, start: "09:00", end: "12:00" },
        { weekday: 1, start: "02:00", end: "04:00" },
      ];
      const compact = (s) => String(s).replace(/\s+/g, "");
      try {
        await fill({ name: "周末音乐厅", capacity: "200", timezone: "Asia/Shanghai", hours });
        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);
        check(S, "跨午夜相接的时段保存成功（201）", post.status === 201,
          `status=${post.status} body=${raw}`);

        // 请求体按填写顺序携带三段时段，时间原样提交、未被换算。
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch (e) { bad(S, "请求体是合法 JSON: " + e.message, raw); }
        if (parsed) {
          const wh = parsed.weeklyHours;
          check(S, "请求按填写顺序携带三段时段", Array.isArray(wh) && wh.length === 3 &&
            wh[0].weekday === 7 && wh[0].start === "22:00" && wh[0].end === "02:00" &&
            wh[1].weekday === 1 && wh[1].start === "09:00" && wh[1].end === "12:00" &&
            wh[2].weekday === 1 && wh[2].start === "02:00" && wh[2].end === "04:00", raw);
          check(S, "请求时区按填写提交", parsed.timezone === "Asia/Shanghai", raw);
        }

        // 保存成功后表单清空，开放时段行移除。
        let s0 = await state();
        check(S, "保存成功后错误提示未出现", s0.error === null, s0.error);
        check(S, "保存成功后名称清空", s0.form.name === "", s0.form.name);
        check(S, "保存成功后容量清空", s0.form.capacity === "", s0.form.capacity);
        check(S, "保存成功后时区清空", s0.form.timezone === "", s0.form.timezone);
        check(S, "保存成功后开放时段行移除", s0.form.hours.length === 0,
          JSON.stringify(s0.form.hours));

        // 新场地立即出现在列表中；卡片按星期及开始时间排列：周一两段在前、
        // 周日时段在后；跨午夜的结束时间明确显示“次日02:00”。
        const card = findCard(s0.cards, "周末音乐厅");
        check(S, "新场地立即出现在列表中", !!card, JSON.stringify(s0.cards.map((c) => c.name)));
        if (card) {
          check(S, "卡片显示填写的时区", card.text.indexOf("时区：Asia/Shanghai") >= 0, card.text);
          check(S, "卡片按星期及开始时间排列三段时段", card.hours.length === 3 &&
            card.hours[0].indexOf("周一") === 0 && card.hours[0].indexOf("02:00") >= 0 &&
              card.hours[0].indexOf("04:00") >= 0 &&
            card.hours[1].indexOf("周一") === 0 && card.hours[1].indexOf("09:00") >= 0 &&
              card.hours[1].indexOf("12:00") >= 0 &&
            card.hours[2].indexOf("周日") === 0 && card.hours[2].indexOf("22:00") >= 0,
            JSON.stringify(card.hours));
          check(S, "跨午夜结束时间明确显示次日02:00",
            card.hours.length === 3 && compact(card.hours[2]).indexOf("次日02:00") >= 0,
            card.hours[2]);
          check(S, "当天结束的时段不标注次日",
            card.hours.length === 3 &&
            card.hours[0].indexOf("次日") === -1 && card.hours[1].indexOf("次日") === -1,
            JSON.stringify(card.hours));
          check(S, "时间未被换算或改成当天结束",
            card.text.indexOf("22:00") >= 0 && card.text.indexOf("02:00") >= 0 &&
            card.text.indexOf("23:59") === -1 && card.text.indexOf("24:00") === -1,
            card.text);
        }

        // 重新加载页面：服务端原样保存，重新读取后展示不变。
        const getsBefore = net.venueGets().length;
        await navigate();
        const get = await poll(async () => {
          const got = net.venueGets().slice(getsBefore);
          return got.length ? got[got.length - 1] : null;
        }, { timeout: 8000, label: "重新读取列表" });
        const getBody = await net.bodyOf(get);
        let listed = null;
        try {
          listed = JSON.parse(getBody).venues.find((v) => v.name === "周末音乐厅");
        } catch (e) { bad(S, "列表响应是合法 JSON: " + e.message, getBody); }
        check(S, "重新读取后时段与时区原样保存", listed &&
          listed.timezone === "Asia/Shanghai" &&
          Array.isArray(listed.weeklyHours) && listed.weeklyHours.length === 3 &&
          listed.weeklyHours[0].weekday === 7 && listed.weeklyHours[0].start === "22:00" &&
            listed.weeklyHours[0].end === "02:00" &&
          listed.weeklyHours[1].weekday === 1 && listed.weeklyHours[1].start === "09:00" &&
            listed.weeklyHours[1].end === "12:00" &&
          listed.weeklyHours[2].weekday === 1 && listed.weeklyHours[2].start === "02:00" &&
            listed.weeklyHours[2].end === "04:00",
          getBody);
        s0 = await state();
        const card2 = findCard(s0.cards, "周末音乐厅");
        check(S, "重新读取后卡片仍按相同顺序展示", card2 && card2.hours.length === 3 &&
          card2.hours[0].indexOf("周一") === 0 && card2.hours[1].indexOf("周一") === 0 &&
          card2.hours[2].indexOf("周日") === 0 &&
          compact(card2.hours[2]).indexOf("次日02:00") >= 0,
          card2 ? JSON.stringify(card2.hours) : null);
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 7：跨周重叠被拒绝，内容保留并可纠正 ----------
    {
      // 周日22:00–02:00 跨午夜延续到周一凌晨，与周一01:00–03:00 相交 → 400。
      const S = "跨周重叠被拒绝";
      try {
        const before = await state();
        const beforeNames = before.cards.map((c) => c.name);
        await fill({
          name: "跨周重叠馆",
          capacity: "60",
          timezone: "Asia/Tokyo",
          hours: [
            { weekday: 7, start: "22:00", end: "02:00" },
            { weekday: 1, start: "01:00", end: "03:00" },
          ],
        });
        const post = await submitAndWaitPost();
        check(S, "服务端因跨周重叠返回 400", post.status === 400, `status=${post.status}`);

        const errBody = await net.bodyOf(post);
        let serverMsg = "";
        try { serverMsg = JSON.parse(errBody).error || ""; } catch { /* ignore */ }
        check(S, "服务端说明时段相交", serverMsg.indexOf("相交") >= 0, errBody);

        const after = await state();
        check(S, "页面展示重叠原因",
          after.error !== null && after.error.indexOf("相交") >= 0, after.error);
        const afterNames = after.cards.map((c) => c.name);
        check(S, "失败后列表不增加记录",
          afterNames.length === beforeNames.length &&
            beforeNames.every((n) => afterNames.indexOf(n) >= 0),
          JSON.stringify({ before: beforeNames, after: afterNames }));
        check(S, "已存在的场地不受影响", !!findCard(after.cards, "周末音乐厅"),
          JSON.stringify(afterNames));

        // 名称、容量、时区以及每行的星期、起止时间和填写顺序全部保留。
        check(S, "失败后名称保留", after.form.name === "跨周重叠馆", after.form.name);
        check(S, "失败后容量保留", after.form.capacity === "60", after.form.capacity);
        check(S, "失败时时区保留", after.form.timezone === "Asia/Tokyo", after.form.timezone);
        check(S, "失败后两行时段按填写顺序保留",
          after.form.hours.length === 2 &&
          after.form.hours[0].weekday === "7" && after.form.hours[0].start === "22:00" &&
            after.form.hours[0].end === "02:00" &&
          after.form.hours[1].weekday === "1" && after.form.hours[1].start === "01:00" &&
            after.form.hours[1].end === "03:00",
          JSON.stringify(after.form.hours));

        // 用户只把周一开始时间改成 02:00 再保存：不重填其它任何内容。
        await cdp.evalFn(PAGE_SET_HOUR_FIELD, { index: 1, selector: ".hour-start", value: "02:00" });
        const post2 = await submitAndWaitPost();
        check(S, "纠正后服务端返回 201", post2.status === 201, `status=${post2.status}`);
        const raw2 = await net.postDataOf(post2);
        let p2 = null;
        try { p2 = JSON.parse(raw2); } catch (e) { bad(S, "纠正后请求体是合法 JSON: " + e.message, raw2); }
        if (p2) {
          check(S, "保留的内容未被上一轮失败清空或替换",
            p2.name === "跨周重叠馆" && p2.capacity === 60 && p2.timezone === "Asia/Tokyo",
            raw2);
          check(S, "纠正后请求携带改正后的两段时段",
            Array.isArray(p2.weeklyHours) && p2.weeklyHours.length === 2 &&
            p2.weeklyHours[0].weekday === 7 && p2.weeklyHours[0].start === "22:00" &&
              p2.weeklyHours[0].end === "02:00" &&
            p2.weeklyHours[1].weekday === 1 && p2.weeklyHours[1].start === "02:00" &&
              p2.weeklyHours[1].end === "03:00",
            raw2);
        }
        const fixed = await state();
        check(S, "纠正后旧错误消失", fixed.error === null, fixed.error);
        const card = findCard(fixed.cards, "跨周重叠馆");
        check(S, "纠正后新场地出现在列表中", !!card,
          JSON.stringify(fixed.cards.map((c) => c.name)));
        if (card) {
          check(S, "卡片按星期及开始时间展示改正后的时段",
            card.hours.length === 2 &&
            card.hours[0].indexOf("周一") === 0 && card.hours[0].indexOf("02:00") >= 0 &&
              card.hours[0].indexOf("03:00") >= 0 &&
            card.hours[1].indexOf("周日") === 0 &&
              String(card.hours[1]).replace(/\s+/g, "").indexOf("次日02:00") >= 0,
            JSON.stringify(card.hours));
        }
      } catch (e) {
        bad(S, "场景执行中断: " + e.message, e.stack);
      }
    }

    // ---------- 场景 8：时段未填写完整 vs 删除全部时段 ----------
    {
      const S = "时段不完整与全部删除";
      try {
        // 某行缺少结束时间：页面指出该行未填写完整，阻止保存，不发请求。
        await fill({
          name: "未完成馆",
          capacity: "30",
          timezone: "UTC",
          hours: [{ weekday: 2, start: "10:00", end: "" }],
        });
        const postsBefore = net.snapshot().filter((r) => r.method === "POST").length;
        await submit();
        await sleep(350);
        const postsSent = net.snapshot().filter((r) => r.method === "POST").length;
        check(S, "缺少结束时间时不发送请求", postsSent === postsBefore,
          `POST 数量 ${postsSent - postsBefore}`);
        let s0 = await state();
        check(S, "页面指出该行未填写完整",
          s0.error !== null && s0.error.indexOf("未填写完整") >= 0, s0.error);
        check(S, "其它填写内容保留",
          s0.form.name === "未完成馆" && s0.form.capacity === "30" &&
            s0.form.timezone === "UTC",
          JSON.stringify(s0.form));
        check(S, "不完整行的已填内容保留",
          s0.form.hours.length === 1 && s0.form.hours[0].weekday === "2" &&
            s0.form.hours[0].start === "10:00" && s0.form.hours[0].end === "",
          JSON.stringify(s0.form.hours));

        // 用户删除所有开放时段：合法场地仍可保存，空数组不是错误。
        const remaining = await cdp.eval(`(${PAGE_REMOVE_ALL_HOURS})()`);
        check(S, "每行的删除按钮移除全部时段行", remaining === 0, `剩余 ${remaining} 行`);
        const post = await submitAndWaitPost();
        const raw = await net.postDataOf(post);
        check(S, "没有时段的合法场地保存成功（201）", post.status === 201,
          `status=${post.status} body=${raw}`);
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch (e) { bad(S, "请求体是合法 JSON: " + e.message, raw); }
        if (parsed) {
          check(S, "请求携带空时段数组而非报错",
            Array.isArray(parsed.weeklyHours) && parsed.weeklyHours.length === 0, raw);
        }
        s0 = await state();
        check(S, "空时段不当作错误", s0.error === null, s0.error);
        const card = findCard(s0.cards, "未完成馆");
        check(S, "卡片显示暂未开放",
          card !== null && card.text.indexOf("暂未开放") >= 0 && card.hours.length === 0,
          card ? card.text : null);
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
