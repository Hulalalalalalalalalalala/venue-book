// cdp.mjs 是首页端到端回归测试使用的 Chrome DevTools Protocol 驱动。
//
// 不依赖任何 npm 包，只用 Node 内置的 fetch / WebSocket。由 Go 测试
// （homepage_test.go）通过 stdio 上的单行 JSON-RPC 驱动：
//
//	{"id":1,"method":"open","name":"home","url":"http://127.0.0.1:PORT/"}
//	  -> {"id":1,"ok":true}
//	{"id":2,"method":"eval","name":"home","fn":"async () => { ...; return {...}; }"}
//	  -> {"id":2,"ok":true,"result":<可 JSON 序列化的值>}
//	{"id":3,"method":"navigate","name":"home"}           // 重新打开上次 URL
//	  -> {"id":3,"ok":true}
//	{"id":4,"method":"close"}
//
// 每次打开/导航都会在页面脚本之前注入 fetch 记录器，页面内还会安装一组
// __hb* 助手函数；Go 侧只与这些助手和 __hbSnapshot 的结构打交道。

import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

let devtoolsBase;

async function fetchJson(urlPath, options) {
  const res = await fetch(devtoolsBase + urlPath, options);
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${urlPath}`);
  return res.json();
}

// connectBrowser 建立浏览器级 WebSocket，并用 flatten 方式复用同一连接向
// 各 target session 发消息：响应按 (sessionId, id) 配对。
function connectBrowser(wsUrl) {
  const ws = new WebSocket(wsUrl);
  const ready = new Promise((resolve, reject) => {
    ws.addEventListener('open', () => resolve(), { once: true });
    ws.addEventListener('error', () => reject(new Error('cannot connect to browser websocket')), { once: true });
  });

  let nextId = 1;
  const waits = new Map();

  ws.addEventListener('message', event => {
    const msg = JSON.parse(event.data);
    if (msg.id == null) return;
    const key = `${msg.sessionId ?? ''}:${msg.id}`;
    const entry = waits.get(key);
    if (!entry) return;
    waits.delete(key);
    if (msg.error) {
      entry.reject(new Error(msg.error.data || msg.error.message || JSON.stringify(msg.error)));
    } else {
      entry.resolve(msg.result);
    }
  });

  function send(method, params = {}, sessionId) {
    const id = nextId++;
    const key = `${sessionId ?? ''}:${id}`;
    return new Promise((resolve, reject) => {
      waits.set(key, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }

  let closed = false;
  ws.addEventListener('close', () => {
    closed = true;
    const err = new Error('browser websocket closed');
    for (const { reject } of waits.values()) reject(err);
  });

  return {
    ready,
    send,
    isClosed: () => closed,
    close: () => ws.close(),
  };
}

// FETCH_HOOK 在页面任何脚本之前运行，记录每次 fetch 的方法、请求体原文、
// 状态码与响应文本。请求体用 String(body) 取出：页面发送的是手写 JSON 文本，
// 这里必须保留逐字原文，不能再解析成 JS 数字（否则大整数会被舍入）。
const FETCH_HOOK = `
window.__hbRequests = [];
(function () {
  var originalFetch = window.fetch;
  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : ((input && input.url) || String(input));
    var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    var hasBody = init && Object.prototype.hasOwnProperty.call(init, 'body');
    var record = {
      url: String(url),
      method: method,
      requestBody: hasBody && init.body != null ? String(init.body) : null,
      status: null,
      responseText: null,
      error: null
    };
    window.__hbRequests.push(record);
    return originalFetch.apply(this, arguments).then(function (res) {
      record.status = res.status;
      res.clone().text().then(
        function (text) { record.responseText = text; },
        function () { record.responseText = ''; }
      );
      return res;
    }, function (err) {
      record.error = String(err && err.message || err);
      throw err;
    });
  };
})();
`;

// PAGE_HELPERS 安装测试用的页面内 DSL：填表、提交、等待与快照。
const PAGE_HELPERS = `
function __hbSetValue(selector, value) {
  var el = document.querySelector(selector);
  if (!el) throw new Error('element not found: ' + selector);
  var proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype
    : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
    : HTMLInputElement.prototype;
  var setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
  setter.call(el, String(value));
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return el.value;
}

// __hbFillForm 按用户真实输入的方式填表单：容量也走 number 输入框，赋什么
// 字符就读回什么字符，绝不经过 Number/parseInt——是否合法由页面与服务端判断。
function __hbFillForm(spec) {
  __hbSetValue('#name', spec.name);
  __hbSetValue('#capacity', spec.capacity);
  __hbSetValue('#timezone', spec.timezone);
  var box = document.getElementById('hours-rows');
  box.innerHTML = '';
  var addButton = document.getElementById('add-hour');
  (spec.hours || []).forEach(function (h) {
    addButton.click();
    var row = box.lastElementChild;
    row.querySelector('.hour-weekday').value = String(h.weekday);
    __hbSetValue('#hours-rows .hour-row:last-child .hour-start', h.start);
    __hbSetValue('#hours-rows .hour-row:last-child .hour-end', h.end);
    row.querySelector('.hour-weekday').dispatchEvent(new Event('change', { bubbles: true }));
  });
}

function __hbSubmit() {
  // 点击提交按钮等价于用户提交，由页面自身的 submit 处理器 preventDefault。
  document.querySelector('#venue-form button[type="submit"]').click();
}

function __hbWait(predicate, timeoutMs) {
  return new Promise(function (resolve, reject) {
    var deadline = Date.now() + (timeoutMs || 5000);
    (function tick() {
      var value;
      try { value = predicate(); } catch (err) { reject(err); return; }
      if (value) { resolve(value); return; }
      if (Date.now() > deadline) { reject(new Error('__hbWait timeout')); return; }
      setTimeout(tick, 40);
    })();
  });
}

// __hbSnapshot 抓取测试要断言的全部页面状态：表单当前内容、错误提示、
// 场地卡片文本以及 fetch 记录（含请求体原文）。
function __hbSnapshot() {
  var errorBox = document.getElementById('form-error');
  var errorShown = errorBox.style.display !== 'none' && errorBox.textContent !== '';
  var cards = Array.prototype.map.call(
    document.querySelectorAll('#venue-list .venue-card'),
    function (article) {
      return {
        name: article.querySelector('h3') ? article.querySelector('h3').textContent : null,
        meta: Array.prototype.map.call(article.querySelectorAll('.venue-meta'), function (p) {
          return p.textContent;
        }),
        hours: Array.prototype.map.call(article.querySelectorAll('.hours li'), function (li) {
          return li.textContent;
        }),
        text: article.textContent
      };
    }
  );
  return {
    form: {
      name: document.getElementById('name').value,
      capacity: document.getElementById('capacity').value,
      timezone: document.getElementById('timezone').value,
      hours: Array.prototype.map.call(
        document.querySelectorAll('#hours-rows .hour-row'),
        function (row) {
          return {
            weekday: parseInt(row.querySelector('.hour-weekday').value, 10),
            start: row.querySelector('.hour-start').value,
            end: row.querySelector('.hour-end').value
          };
        }
      )
    },
    error: { shown: errorShown, text: errorBox.textContent },
    cards: cards,
    listText: document.getElementById('venue-list').textContent,
    requests: window.__hbRequests.map(function (r) {
      return {
        url: r.url, method: r.method, requestBody: r.requestBody,
        status: r.status, responseText: r.responseText, error: r.error
      };
    })
  };
}
`;

class PageSession {
  constructor(browser, targetId) {
    this.browser = browser;
    this.targetId = targetId;
    this.sessionId = null;
    this.url = null;
  }

  async open(url) {
    this.url = url;
    this.sessionId = await this.browser.send('Target.attachToTarget', {
      targetId: this.targetId,
      flatten: true,
    }).then(r => r.sessionId);
    await this.send('Page.enable');
    await this.send('Runtime.enable');
    // 必须在导航前注册：保证 fetch 包装先于页面自身脚本执行。
    await this.send('Page.addScriptToEvaluateOnNewDocument', { source: FETCH_HOOK });
    await this.navigate(url);
  }

  async navigate(url) {
    if (url) this.url = url;
    await this.send('Page.navigate', { url: this.url });
    // 轮询 readyState，不依赖 loadEventFired 事件编排。
    for (let i = 0; i < 100; i++) {
      const ready = await this.evaluateRaw('document.readyState');
      if (ready === 'complete') break;
      await sleep(30);
    }
    await sleep(100);
    await this.evaluateRaw(PAGE_HELPERS);
  }

  send(method, params) {
    return this.browser.send(method, params, this.sessionId);
  }

  async evaluateRaw(expression) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    });
    if (result.exceptionDetails) {
      const exc = result.exceptionDetails.exception;
      throw new Error(exc && exc.description ? exc.description : JSON.stringify(result.exceptionDetails));
    }
    return result.result.value;
  }

  async call(fnSource) {
    return this.evaluateRaw(`(${fnSource})()`);
  }
}

// ---- stdio JSON-RPC ----

const lineQueue = [];
let lineWaiter = null;
let stdinBuffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  stdinBuffer += chunk;
  let nl;
  while ((nl = stdinBuffer.indexOf('\n')) >= 0) {
    const line = stdinBuffer.slice(0, nl).trim();
    stdinBuffer = stdinBuffer.slice(nl + 1);
    if (!line) continue;
    if (lineWaiter) {
      const w = lineWaiter;
      lineWaiter = null;
      w(line);
    } else {
      lineQueue.push(line);
    }
  }
});

function nextLine() {
  if (lineQueue.length) return Promise.resolve(lineQueue.shift());
  return new Promise(resolve => { lineWaiter = resolve; });
}

function write(response) {
  process.stdout.write(JSON.stringify(response) + '\n');
}

let chrome;
let browser;
const sessions = new Map();
let shuttingDown = false;

async function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { browser && browser.close(); } catch { /* 忽略 */ }
  if (chrome) {
    chrome.kill('SIGKILL');
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  process.exit(code);
}

async function handle(req) {
  switch (req.method) {
    case 'open': {
      if (!req.url) throw new Error('open requires url');
      const target = await fetchJson(`/json/new?${encodeURIComponent(req.url)}`, { method: 'PUT' });
      const session = new PageSession(browser, target.id);
      await session.open(req.url);
      const name = req.name || target.id;
      sessions.set(name, session);
      return { session: name };
    }
    case 'eval': {
      const session = sessions.get(req.name);
      if (!session) throw new Error(`unknown session: ${req.name}`);
      if (!req.fn) throw new Error('eval requires fn');
      return await session.call(req.fn);
    }
    case 'navigate': {
      const session = sessions.get(req.name);
      if (!session) throw new Error(`unknown session: ${req.name}`);
      await session.navigate(req.url);
      return null;
    }
    case 'close':
      // 先让调用方收到响应，再退出进程。
      setTimeout(() => shutdown(0), 50);
      return null;
    default:
      throw new Error(`unknown method: ${req.method}`);
  }
}

async function main() {
  const chromePath = process.env.HB_CHROME_BIN || 'google-chrome';
  const userDir = mkdtempSync(path.join(tmpdir(), 'hb-chrome-'));
  chrome = spawn(chromePath, [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--disable-extensions',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--remote-debugging-port=0',
    `--user-data-dir=${userDir}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'ignore'] });
  chrome.on('exit', () => {
    if (!shuttingDown) {
      write({ id: null, ok: false, error: 'chrome exited unexpectedly' });
      process.exit(2);
    }
  });

  const portFile = path.join(userDir, 'DevToolsActivePort');
  let port = '';
  for (let i = 0; i < 100; i++) {
    try {
      port = readFileSync(portFile, 'utf8').split('\n')[0].trim();
      if (port) break;
    } catch { /* 端口文件尚未写出 */ }
    await sleep(100);
  }
  if (!port) throw new Error('Chrome did not open a DevTools port');
  devtoolsBase = `http://127.0.0.1:${port}`;

  let version = null;
  for (let i = 0; i < 50; i++) {
    try {
      version = await fetchJson('/json/version');
      break;
    } catch {
      await sleep(100);
    }
  }
  if (!version) throw new Error('Chrome DevTools endpoint unreachable');

  browser = connectBrowser(version.webSocketDebuggerUrl);
  await browser.ready;

  for (;;) {
    const line = await nextLine();
    let req;
    try {
      req = JSON.parse(line);
    } catch (err) {
      write({ id: null, ok: false, error: `bad request json: ${err.message}` });
      continue;
    }
    handle(req)
      .then(result => write({ id: req.id, ok: true, result: result === undefined ? null : result }))
      .catch(err => write({ id: req.id, ok: false, error: err.message }));
  }
}

main().catch(async err => {
  process.stderr.write(`cdp.mjs fatal: ${err.stack || err.message}\n`);
  await shutdown(1);
});
