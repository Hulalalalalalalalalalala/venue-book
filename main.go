package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"
)

const product = "VenueBook"
const resourceName = "venues"
const page = `<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VenueBook · 场地预约与活动报名</title>
<style>
body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.7;color:#222}
a{color:#175b9c}
h2{margin-top:2rem}
form{border:1px solid #ddd;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0}
label{display:block;margin:.6rem 0 .2rem;font-weight:600}
input,select{padding:.4rem;font-size:1rem;border:1px solid #bbb;border-radius:4px;box-sizing:border-box}
input[type=text],input[type=number]{width:100%;max-width:24rem}
.row{display:flex;gap:.5rem;align-items:center;margin:.35rem 0;flex-wrap:wrap}
.row select,.row input{width:auto}
button{padding:.45rem .9rem;font-size:1rem;border:1px solid #175b9c;background:#175b9c;color:#fff;border-radius:4px;cursor:pointer}
button.secondary{background:#fff;color:#175b9c}
button.danger{background:#fff;color:#b00020;border-color:#b00020}
.venue{border:1px solid #e0e0e0;border-radius:8px;padding:.75rem 1rem;margin:.75rem 0}
.venue h3{margin:.25rem 0}
.muted{color:#777}
.error{color:#b00020;font-weight:600}
.hint{color:#777;font-size:.85rem;margin:.25rem 0}
ul.hours{margin:.25rem 0;padding-left:1.25rem}
</style>
<main>
<h1>VenueBook</h1>
<p>场地预约与活动报名</p>
<h2>新增场地</h2>
<form id="venue-form" novalidate>
  <label for="name">名称</label>
  <input id="name" name="name" type="text" required placeholder="例如：主楼报告厅">
  <label for="capacity">容量</label>
  <input id="capacity" name="capacity" type="number" min="1" step="1" required placeholder="正整数，例如 200">
  <label for="timezone">时区（IANA 时区名称，如 Asia/Shanghai）</label>
  <input id="timezone" name="timezone" type="text" list="tz-list" required placeholder="Asia/Shanghai">
  <datalist id="tz-list">
    <option value="Asia/Shanghai">
    <option value="Asia/Tokyo">
    <option value="Asia/Singapore">
    <option value="Asia/Hong_Kong">
    <option value="Asia/Seoul">
    <option value="Europe/London">
    <option value="Europe/Paris">
    <option value="America/New_York">
    <option value="America/Los_Angeles">
    <option value="UTC">
  </datalist>
  <label>每周开放时间</label>
  <div id="hours-rows"></div>
  <button type="button" class="secondary" id="add-row">添加时段</button>
  <p class="hint">结束时间早于开始时间表示次日结束（跨午夜），两者相同属于无效时段。</p>
  <p class="error" id="form-error" role="alert"></p>
  <button type="submit">保存场地</button>
</form>
<h2>场地列表</h2>
<div id="venue-list"><p class="muted">加载中…</p></div>
<p><a href="/api/venues">查看场地列表接口</a> · <a href="/health">服务状态</a></p>
</main>
<script>
var WEEKDAYS = ['周一','周二','周三','周四','周五','周六','周日'];
function esc(s){
  return String(s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function addRow(weekday, start, end){
  var rows = document.getElementById('hours-rows');
  var div = document.createElement('div');
  div.className = 'row';
  var opts = '';
  for (var i = 1; i <= 7; i++){
    opts += '<option value="' + i + '"' + (i === weekday ? ' selected' : '') + '>' + WEEKDAYS[i-1] + '</option>';
  }
  div.innerHTML = '<select name="weekday">' + opts + '</select>' +
    '<input name="start" type="time" value="' + (start || '') + '">' +
    '<span>至</span>' +
    '<input name="end" type="time" value="' + (end || '') + '">' +
    '<button type="button" class="danger" onclick="this.parentNode.remove()">删除</button>';
  rows.appendChild(div);
}
function render(venues){
  var list = document.getElementById('venue-list');
  if (!venues.length){
    list.innerHTML = '<p>还没有场地记录。</p>';
    return;
  }
  list.innerHTML = venues.map(function(v){
    var hoursHtml;
    if (!v.weeklyHours || !v.weeklyHours.length){
      hoursHtml = '<p class="muted">暂未开放</p>';
    } else {
      var sorted = v.weeklyHours.slice().sort(function(a, b){
        return a.weekday - b.weekday || a.start.localeCompare(b.start);
      });
      hoursHtml = '<ul class="hours">' + sorted.map(function(h){
        var cross = h.end <= h.start;
        return '<li>' + WEEKDAYS[h.weekday-1] + ' ' + esc(h.start) + ' – ' +
          (cross ? '次日 ' : '') + esc(h.end) + '</li>';
      }).join('') + '</ul>';
    }
    return '<div class="venue"><h3>' + esc(v.name) + '</h3>' +
      '<p>容量：' + esc(v.capacity) + ' · 时区：' + esc(v.timezone) + '</p>' + hoursHtml + '</div>';
  }).join('');
}
function load(){
  fetch('/api/venues').then(function(r){ return r.json(); }).then(function(data){
    render(data.venues || []);
  }).catch(function(){
    document.getElementById('venue-list').innerHTML = '<p class="error">加载场地列表失败。</p>';
  });
}
document.getElementById('add-row').addEventListener('click', function(){ addRow(1, '', ''); });
document.getElementById('venue-form').addEventListener('submit', function(e){
  e.preventDefault();
  var errEl = document.getElementById('form-error');
  errEl.textContent = '';
  var name = document.getElementById('name').value;
  var capacityRaw = document.getElementById('capacity').value;
  var timezone = document.getElementById('timezone').value;
  var weeklyHours = [];
  document.querySelectorAll('#hours-rows .row').forEach(function(row){
    var wd = row.querySelector('[name=weekday]').value;
    var st = row.querySelector('[name=start]').value;
    var en = row.querySelector('[name=end]').value;
    if (wd && st && en){
      weeklyHours.push({weekday: Number(wd), start: st, end: en});
    }
  });
  var capacity = capacityRaw === '' ? null : Number(capacityRaw);
  fetch('/api/venues', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name: name, capacity: capacity, timezone: timezone, weeklyHours: weeklyHours})
  }).then(function(r){
    return r.json().then(function(data){ return {status: r.status, data: data}; });
  }).then(function(res){
    if (res.status === 201){
      document.getElementById('venue-form').reset();
      document.getElementById('hours-rows').innerHTML = '';
      load();
    } else {
      errEl.textContent = (res.data && res.data.error) ? res.data.error : '保存失败，请检查填写内容。';
    }
  }).catch(function(){
    errEl.textContent = '保存失败，请稍后重试。';
  });
});
load();
</script>
</main>
</html>`

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type weeklyHours struct {
	Weekday int    `json:"weekday"`
	Start   string `json:"start"`
	End     string `json:"end"`
}

type venue struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Capacity    int64         `json:"capacity"`
	Timezone    string        `json:"timezone"`
	WeeklyHours []weeklyHours `json:"weeklyHours"`
}

type createVenueRequest struct {
	Name        *string          `json:"name"`
	Capacity    *json.RawMessage `json:"capacity"`
	Timezone    *string          `json:"timezone"`
	WeeklyHours *[]weeklyHours   `json:"weeklyHours"`
}

var hhmmPattern = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func parseHHMM(value string) (int, bool) {
	if !hhmmPattern.MatchString(value) {
		return 0, false
	}
	hour, _ := strconv.Atoi(value[:2])
	minute, _ := strconv.Atoi(value[3:])
	return hour*60 + minute, true
}

type minuteInterval struct {
	start int
	end   int
}

// pieces 将跨午夜（可能延续到下一周）的时段展开为 [0, weekMinutes) 内的至多两段。
func pieces(iv minuteInterval, weekMinutes int) [][2]int {
	if iv.end <= weekMinutes {
		return [][2]int{{iv.start, iv.end}}
	}
	return [][2]int{{iv.start, weekMinutes}, {0, iv.end - weekMinutes}}
}

func intervalsOverlap(a, b minuteInterval, weekMinutes int) bool {
	for _, x := range pieces(a, weekMinutes) {
		for _, y := range pieces(b, weekMinutes) {
			if x[0] < y[1] && y[0] < x[1] {
				return true
			}
		}
	}
	return false
}

func validateVenue(req createVenueRequest) (venue, error) {
	if req.Name == nil {
		return venue{}, errors.New("缺少 name 字段")
	}
	name := strings.TrimSpace(*req.Name)
	if name == "" {
		return venue{}, errors.New("名称去除首尾空白后不能为空")
	}
	if req.Capacity == nil {
		return venue{}, errors.New("缺少 capacity 字段")
	}
	capRaw := bytes.TrimSpace(*req.Capacity)
	if len(capRaw) == 0 || (capRaw[0] != '-' && (capRaw[0] < '0' || capRaw[0] > '9')) {
		return venue{}, errors.New("容量必须是正整数")
	}
	capacity, err := strconv.ParseInt(string(capRaw), 10, 64)
	if err != nil || capacity <= 0 {
		return venue{}, errors.New("容量必须是正整数")
	}
	if req.Timezone == nil {
		return venue{}, errors.New("缺少 timezone 字段")
	}
	tz := strings.TrimSpace(*req.Timezone)
	if tz == "" {
		return venue{}, errors.New("时区不能为空")
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return venue{}, errors.New("时区必须是有效的 IANA 时区名称，例如 Asia/Shanghai")
	}
	if req.WeeklyHours == nil {
		return venue{}, errors.New("缺少 weeklyHours 字段")
	}
	hours := *req.WeeklyHours
	if hours == nil {
		hours = []weeklyHours{}
	}
	weekMinutes := 7 * 24 * 60
	intervals := make([]minuteInterval, 0, len(hours))
	for i, wh := range hours {
		if wh.Weekday < 1 || wh.Weekday > 7 {
			return venue{}, fmt.Errorf("weeklyHours[%d].weekday 必须为 1 到 7（周一至周日）", i)
		}
		start, ok := parseHHMM(wh.Start)
		if !ok {
			return venue{}, fmt.Errorf("weeklyHours[%d].start 必须为 00:00 至 23:59 的 HH:mm 格式", i)
		}
		end, ok := parseHHMM(wh.End)
		if !ok {
			return venue{}, fmt.Errorf("weeklyHours[%d].end 必须为 00:00 至 23:59 的 HH:mm 格式", i)
		}
		if start == end {
			return venue{}, fmt.Errorf("weeklyHours[%d].start 与 end 不能相同", i)
		}
		base := (wh.Weekday - 1) * 24 * 60
		s := base + start
		e := base + end
		if end < start {
			e += 24 * 60 // 结束时间早于开始时间，表示次日结束
		}
		intervals = append(intervals, minuteInterval{start: s, end: e})
	}
	for i := 0; i < len(intervals); i++ {
		for j := i + 1; j < len(intervals); j++ {
			if intervalsOverlap(intervals[i], intervals[j], weekMinutes) {
				return venue{}, errors.New("各段开放时间不能相交或互相包含（前一段结束时下一段开始可以保存）")
			}
		}
	}
	return venue{
		Name:        name,
		Capacity:    capacity,
		Timezone:    tz,
		WeeklyHours: hours,
	}, nil
}

func newVenueID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "v_" + hex.EncodeToString(b[:]), nil
}

type store struct {
	mu   sync.Mutex
	path string
}

func newStore(path string) *store {
	return &store{path: path}
}

func (s *store) load() ([]venue, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var venues []venue
	if err := json.Unmarshal(raw, &venues); err != nil {
		return nil, err
	}
	if venues == nil {
		venues = []venue{}
	}
	return venues, nil
}

func (s *store) save(venues []venue) error {
	data, err := json.MarshalIndent(venues, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".venues-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *store) handleList(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	venues, err := s.load()
	if err != nil {
		respond(w, http.StatusInternalServerError, map[string]string{"error": "无法读取场地数据"})
		return
	}
	respond(w, http.StatusOK, map[string]any{resourceName: venues})
}

func (s *store) handleCreate(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(body)
	var req createVenueRequest
	if err := dec.Decode(&req); err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "请求体不是有效的 JSON 对象"})
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		respond(w, http.StatusBadRequest, map[string]string{"error": "请求体必须是单个 JSON 对象"})
		return
	}
	v, err := validateVenue(req)
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	venues, err := s.load()
	if err != nil {
		respond(w, http.StatusInternalServerError, map[string]string{"error": "无法读取场地数据，未保存任何记录"})
		return
	}
	id, err := newVenueID()
	if err != nil {
		respond(w, http.StatusInternalServerError, map[string]string{"error": "无法生成场地标识"})
		return
	}
	v.ID = id
	venues = append(venues, v)
	if err := s.save(venues); err != nil {
		respond(w, http.StatusInternalServerError, map[string]string{"error": "保存场地失败，未写入任何记录"})
		return
	}
	respond(w, http.StatusCreated, map[string]any{"venue": v})
}

func run() error {
	if len(os.Args) < 2 {
		printHelp()
		return errors.New("expected serve or --help")
	}
	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		printHelp()
		return nil
	}
	if os.Args[1] != "serve" {
		return errors.New("expected serve or --help")
	}
	args := flag.NewFlagSet("venue-book serve", flag.ContinueOnError)
	args.SetOutput(os.Stdout)
	host := args.String("host", "127.0.0.1", "address to bind")
	port := args.Int("port", 8080, "port to bind; 0 selects an available port")
	data := args.String("data-dir", "data", "directory for local records")
	if err := args.Parse(os.Args[2:]); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if args.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	if *port < 0 || *port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	if err := os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	dataFile := filepath.Join(*data, "venues.json")
	file, err := os.OpenFile(dataFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, writeErr := file.WriteString("[]\n")
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	st := newStore(dataFile)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				respond(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, page)
		case "/health":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				respond(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			respond(w, http.StatusOK, map[string]string{"status": "ok", "product": product})
		case "/api/venues":
			switch r.Method {
			case http.MethodGet:
				st.handleList(w, r)
			case http.MethodPost:
				st.handleCreate(w, r)
			default:
				w.Header().Set("Allow", "GET, POST")
				respond(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			}
		default:
			respond(w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	listener, err := net.Listen("tcp", net.JoinHostPort(*host, fmt.Sprint(*port)))
	if err != nil {
		return err
	}
	fmt.Printf("%s listening on http://%s\n", product, listener.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, 1)
	go func() { failures <- server.Serve(listener) }()
	select {
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
	}
	return nil
}

func printHelp() {
	fmt.Println("VenueBook - 场地预约与活动报名")
	fmt.Println("Usage: go run . serve [--host ADDRESS] [--port PORT] [--data-dir DIRECTORY]")
	fmt.Println("       go run . --help")
	fmt.Println("Defaults: --host 127.0.0.1 --port 8080 --data-dir data")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
