package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validPayload() map[string]any {
	return map[string]any{
		"name":        "  音乐厅  ",
		"capacity":    120.0,
		"timezone":    "Asia/Shanghai",
		"weeklyHours": []any{},
	}
}

func TestBuildVenueValid(t *testing.T) {
	venue, err := buildVenue(validPayload())
	if err != nil {
		t.Fatalf("expected valid venue, got %v", err)
	}
	if venue.Name != "音乐厅" {
		t.Errorf("name should be trimmed, got %q", venue.Name)
	}
	if venue.Capacity != 120 || venue.Timezone != "Asia/Shanghai" {
		t.Errorf("unexpected venue fields: %+v", venue)
	}
	if len(venue.WeeklyHours) != 0 {
		t.Errorf("weeklyHours should be empty, got %+v", venue.WeeklyHours)
	}
}

func TestBuildVenueInvalid(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing name", func(p map[string]any) { delete(p, "name") }},
		{"blank name", func(p map[string]any) { p["name"] = "   " }},
		{"name wrong type", func(p map[string]any) { p["name"] = 42 }},
		{"missing capacity", func(p map[string]any) { delete(p, "capacity") }},
		{"zero capacity", func(p map[string]any) { p["capacity"] = 0.0 }},
		{"negative capacity", func(p map[string]any) { p["capacity"] = -3.0 }},
		{"fractional capacity", func(p map[string]any) { p["capacity"] = 12.5 }},
		{"capacity wrong type", func(p map[string]any) { p["capacity"] = "100" }},
		{"missing timezone", func(p map[string]any) { delete(p, "timezone") }},
		{"bad timezone", func(p map[string]any) { p["timezone"] = "Asia/NoSuchCity" }},
		{"local timezone", func(p map[string]any) { p["timezone"] = "Local" }},
		{"empty timezone", func(p map[string]any) { p["timezone"] = "" }},
		{"timezone wrong type", func(p map[string]any) { p["timezone"] = 8 }},
		{"missing weeklyHours", func(p map[string]any) { delete(p, "weeklyHours") }},
		{"weeklyHours wrong type", func(p map[string]any) { p["weeklyHours"] = "none" }},
		{"hour item wrong type", func(p map[string]any) { p["weeklyHours"] = []any{"x"} }},
		{"weekday out of range", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 8.0, "start": "10:00", "end": "12:00"}}
		}},
		{"weekday zero", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 0.0, "start": "10:00", "end": "12:00"}}
		}},
		{"weekday fractional", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 1.5, "start": "10:00", "end": "12:00"}}
		}},
		{"bad start format", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 1.0, "start": "9:00", "end": "12:00"}}
		}},
		{"hour 24", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 1.0, "start": "24:00", "end": "25:00"}}
		}},
		{"minute 60", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 1.0, "start": "10:60", "end": "12:00"}}
		}},
		{"non-numeric time", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 1.0, "start": "ab:cd", "end": "12:00"}}
		}},
		{"missing end", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 1.0, "start": "10:00"}}
		}},
		{"equal start and end", func(p map[string]any) {
			p["weeklyHours"] = []any{map[string]any{"weekday": 1.0, "start": "10:00", "end": "10:00"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := validPayload()
			tc.mutate(payload)
			if _, err := buildVenue(payload); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func hours(weekday int, start, end string) []WeeklyHour {
	return []WeeklyHour{{Weekday: weekday, Start: start, End: end}}
}

func TestValidateHoursOverlap(t *testing.T) {
	cases := []struct {
		name    string
		hours   []WeeklyHour
		wantErr bool
	}{
		{"adjacent same day", []WeeklyHour{
			{1, "10:00", "12:00"}, {1, "12:00", "14:00"},
		}, false},
		{"overlap same day", []WeeklyHour{
			{1, "10:00", "12:00"}, {1, "11:00", "13:00"},
		}, true},
		{"containment", []WeeklyHour{
			{1, "09:00", "18:00"}, {1, "10:00", "11:00"},
		}, true},
		{"different days no overlap", []WeeklyHour{
			{1, "22:00", "02:00"}, {3, "01:00", "03:00"},
		}, false},
		// 需求示例：周一 22:00-02:00 与周二 01:00-03:00 必须拒绝。
		{"cross midnight into next day", []WeeklyHour{
			{1, "22:00", "02:00"}, {2, "01:00", "03:00"},
		}, true},
		// 跨午夜在次日整点结束，与下一天 02:00 开始的时段相邻，允许。
		{"cross midnight adjacent to next day", []WeeklyHour{
			{1, "22:00", "02:00"}, {2, "02:00", "04:00"},
		}, false},
		// 周日 22:00-02:00 延续到周一，与周一 01:00 冲突。
		{"sunday spills into monday", []WeeklyHour{
			{7, "22:00", "02:00"}, {1, "01:00", "03:00"},
		}, true},
		// 周日跨午夜在周一 00:00 结束，与周一时段相邻，允许。
		{"sunday ends exactly monday midnight", []WeeklyHour{
			{7, "22:00", "00:00"}, {1, "00:00", "02:00"},
		}, false},
		// 同一起点的两个时段也属于相交。
		{"same start", []WeeklyHour{
			{3, "08:00", "09:00"}, {3, "08:00", "10:00"},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHours(tc.hours)
			if tc.wantErr && err == nil {
				t.Fatalf("expected overlap error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidHHMM(t *testing.T) {
	valid := []string{"00:00", "23:59", "12:30", "01:05"}
	invalid := []string{"", "0:00", "24:00", "23:60", "123:00", "12:3", "ab:12", "12：00", "12-00"}
	for _, v := range valid {
		if !validHHMM(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	for _, v := range invalid {
		if validHHMM(v) {
			t.Errorf("%q should be invalid", v)
		}
	}
}

// ---- HTTP 层测试 ----

func newTestServer(t *testing.T) (*store, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	s, err := newStore(dir)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	return s, newHandler(s)
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON object: %q (%v)", rec.Body.String(), err)
	}
	return out
}

func TestGetEmptyVenues(t *testing.T) {
	_, h := newTestServer(t)
	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	venues, ok := body["venues"].([]any)
	if !ok || len(venues) != 0 {
		t.Fatalf("expected empty venues array, got %v", body)
	}
}

func TestCreateVenue(t *testing.T) {
	_, h := newTestServer(t)
	rec := doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	venue, ok := body["venue"].(map[string]any)
	if !ok {
		t.Fatalf("expected venue object, got %v", body)
	}
	id, _ := venue["id"].(string)
	if id == "" {
		t.Fatalf("id must be non-empty, got %v", venue["id"])
	}
	if venue["name"] != "音乐厅" || venue["capacity"].(float64) != 120 ||
		venue["timezone"] != "Asia/Shanghai" {
		t.Fatalf("saved fields mismatch: %v", venue)
	}
	hours, ok := venue["weeklyHours"].([]any)
	if !ok || len(hours) != 0 {
		t.Fatalf("weeklyHours should be an empty array: %v", venue)
	}

	// 列表中应包含新记录。
	listRec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	listBody := decodeBody(t, listRec)
	venues := listBody["venues"].([]any)
	if len(venues) != 1 || venues[0].(map[string]any)["id"] != id {
		t.Fatalf("list should contain created venue, got %v", venues)
	}
}

func TestCreateVenueUniqueIDs(t *testing.T) {
	_, h := newTestServer(t)
	ids := map[string]bool{}
	for i := 0; i < 5; i++ {
		rec := doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		id := decodeBody(t, rec)["venue"].(map[string]any)["id"].(string)
		if ids[id] {
			t.Fatalf("duplicate id %s", id)
		}
		ids[id] = true
	}
}

func TestCreateVenueBadRequests(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"invalid json", `{not json`},
		{"json array", `[1,2,3]`},
		{"json null", `null`},
		{"missing name", `{"capacity":10,"timezone":"UTC","weeklyHours":[]}`},
		{"capacity string", `{"name":"x","capacity":"10","timezone":"UTC","weeklyHours":[]}`},
		{"bad timezone", `{"name":"x","capacity":10,"timezone":"Mars/Olympus","weeklyHours":[]}`},
		{"bad time", `{"name":"x","capacity":10,"timezone":"UTC","weeklyHours":[{"weekday":1,"start":"25:00","end":"26:00"}]}`},
		{"overlap", `{"name":"x","capacity":10,"timezone":"UTC","weeklyHours":[{"weekday":1,"start":"22:00","end":"02:00"},{"weekday":2,"start":"01:00","end":"03:00"}]}`},
		{"equal times", `{"name":"x","capacity":10,"timezone":"UTC","weeklyHours":[{"weekday":1,"start":"10:00","end":"10:00"}]}`},
		{"trailing value", `{"name":"x","capacity":10,"timezone":"UTC","weeklyHours":[]}{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, h := newTestServer(t)
			req := httptest.NewRequest(http.MethodPost, "/api/venues", strings.NewReader(tc.raw))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if msg, _ := body["error"].(string); msg == "" {
				t.Fatalf("error field must explain the reason, got %v", body)
			}
			// 列表不能增加未保存的记录。
			listRec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
			venues := decodeBody(t, listRec)["venues"].([]any)
			if len(venues) != 0 {
				t.Fatalf("failed request must not create a record, got %v", venues)
			}
		})
	}
}

func TestRoutingStatusAndAllow(t *testing.T) {
	_, h := newTestServer(t)
	cases := []struct {
		method    string
		path      string
		wantCode  int
		wantAllow string
	}{
		{http.MethodGet, "/api/venues", http.StatusOK, ""},
		{http.MethodPost, "/api/venues", http.StatusCreated, ""},
		{http.MethodDelete, "/api/venues", http.StatusMethodNotAllowed, "GET, POST"},
		{http.MethodPut, "/api/venues", http.StatusMethodNotAllowed, "GET, POST"},
		{http.MethodGet, "/health", http.StatusOK, ""},
		{http.MethodPost, "/health", http.StatusMethodNotAllowed, "GET"},
		{http.MethodDelete, "/health", http.StatusMethodNotAllowed, "GET"},
		{http.MethodGet, "/", http.StatusOK, ""},
		{http.MethodPost, "/", http.StatusMethodNotAllowed, "GET"},
		{http.MethodGet, "/api/nope", http.StatusNotFound, ""},
		{http.MethodPost, "/api/nope", http.StatusNotFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var body string
			if tc.method == http.MethodPost && tc.path == "/api/venues" {
				raw, _ := json.Marshal(validPayload())
				body = string(raw)
			}
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if tc.wantAllow != "" && rec.Header().Get("Allow") != tc.wantAllow {
				t.Fatalf("Allow = %q, want %q", rec.Header().Get("Allow"), tc.wantAllow)
			}
		})
	}
}

func TestHealth(t *testing.T) {
	_, h := newTestServer(t)
	rec := doJSON(t, h, http.MethodGet, "/health", nil)
	body := decodeBody(t, rec)
	if body["status"] != "ok" || body["product"] != product {
		t.Fatalf("unexpected health body: %v", body)
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s1, err := newStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	venue, err := s1.create(validPayload())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// 使用同一数据目录“重启”：记录及标识不变。
	s2, err := newStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s2.list()
	if err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 record, got %d", len(loaded))
	}
	if loaded[0].ID != venue.ID {
		t.Fatalf("id changed: %q vs %q", loaded[0].ID, venue.ID)
	}
	if loaded[0].Name != "音乐厅" || loaded[0].Capacity != 120 ||
		loaded[0].Timezone != "Asia/Shanghai" || len(loaded[0].WeeklyHours) != 0 {
		t.Fatalf("record changed across restart: %+v", loaded[0])
	}
}

func TestCorruptedDataReturns500AndKeepsFile(t *testing.T) {
	s, h := newTestServer(t)
	if err := os.WriteFile(s.path, []byte("{broken json"), 0600); err != nil {
		t.Fatal(err)
	}

	// GET 损坏数据 → 500。
	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET corrupted file: status = %d, want 500", rec.Code)
	}

	// POST 也必须 500，且不能覆盖损坏文件。
	rec = doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST with corrupted file: status = %d, want 500", rec.Code)
	}
	after, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "{broken json" {
		t.Fatalf("corrupted file must not be overwritten, got %q", string(after))
	}
}

func TestUnreadableDataReturns500(t *testing.T) {
	dir := t.TempDir()
	// venues.json 是目录时读取必然失败。
	if err := os.MkdirAll(filepath.Join(dir, "venues.json"), 0700); err != nil {
		t.Fatal(err)
	}
	s := &store{path: filepath.Join(dir, "venues.json")}
	h := newHandler(s)
	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	rec = doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST status = %d, want 500", rec.Code)
	}
}

func TestEmptyDataDirStillInitializes(t *testing.T) {
	dir := t.TempDir()
	s, err := newStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	venues, err := s.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(venues) != 0 {
		t.Fatalf("fresh dir should be empty, got %d", len(venues))
	}
}

// writeVenuesFile 直接写入原始记录，绕过新增时的校验，用于模拟已损坏的存量数据。
func writeVenuesFile(t *testing.T, s *store, venues any) string {
	t.Helper()
	raw, err := json.Marshal(venues)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(s.path, raw, 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return string(raw)
}

// TestInvalidSavedHoursTreatedAsCorruption 验证需求中的核心场景：
// 已有场地周日开放到次日凌晨两点、同时周一凌晨一点开放（两段重叠）。
func TestInvalidSavedHoursTreatedAsCorruption(t *testing.T) {
	cases := []struct {
		name   string
		venues []Venue
	}{
		{
			"sunday spills into monday",
			[]Venue{{
				ID: "v-sunday", Name: "屋顶球场", Capacity: 50, Timezone: "Asia/Shanghai",
				WeeklyHours: []WeeklyHour{
					{Weekday: 7, Start: "22:00", End: "02:00"},
					{Weekday: 1, Start: "01:00", End: "03:00"},
				},
			}},
		},
		{"equal start and end", []Venue{{
			ID: "v-equal", Name: "展厅", Capacity: 10, Timezone: "UTC",
			WeeklyHours: []WeeklyHour{{Weekday: 2, Start: "10:00", End: "10:00"}},
		}}},
		{"duplicate slot", []Venue{{
			ID: "v-dup", Name: "排练室", Capacity: 4, Timezone: "UTC",
			WeeklyHours: []WeeklyHour{
				{Weekday: 3, Start: "09:00", End: "11:00"},
				{Weekday: 3, Start: "09:00", End: "11:00"},
			},
		}}},
		{"containment", []Venue{{
			ID: "v-contain", Name: "礼堂", Capacity: 300, Timezone: "UTC",
			WeeklyHours: []WeeklyHour{
				{Weekday: 4, Start: "08:00", End: "20:00"},
				{Weekday: 4, Start: "09:00", End: "10:00"},
			},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, h := newTestServer(t)
			original := writeVenuesFile(t, s, tc.venues)

			// GET 必须 500：带非空 error，不返回场地列表，也不只显示正常场地。
			rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("GET invalid hours: status = %d, want 500, body = %s", rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if msg, _ := body["error"].(string); msg == "" {
				t.Fatalf("500 response must carry non-empty error, got %v", body)
			}
			if _, present := body["venues"]; present {
				t.Fatalf("corrupted store must not return a venues list, got %v", body)
			}

			// 提交内容合法的新场地同样 500，不新增、不追加、不改写异常时段。
			rec = doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("POST with corrupted store: status = %d, want 500, body = %s", rec.Code, rec.Body.String())
			}
			postBody := decodeBody(t, rec)
			if msg, _ := postBody["error"].(string); msg == "" {
				t.Fatalf("POST 500 must carry non-empty error, got %v", postBody)
			}
			after, err := os.ReadFile(s.path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != original {
				t.Fatalf("corrupted records must be preserved untouched:\nbefore=%s\nafter =%s", original, string(after))
			}

			// 损坏未修复前读取仍应持续失败。
			rec = doJSON(t, h, http.MethodGet, "/api/venues", nil)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("second GET should still be 500, got %d", rec.Code)
			}
		})
	}
}

// TestCorruptVenueAlongsideValidOneRejectsWholeList 异常场地与正常场地并存时，
// 不能跳过异常场地只返回剩余记录。
func TestCorruptVenueAlongsideValidOneRejectsWholeList(t *testing.T) {
	s, h := newTestServer(t)
	writeVenuesFile(t, s, []Venue{
		{
			ID: "v-ok", Name: "正常场地", Capacity: 20, Timezone: "UTC",
			WeeklyHours: []WeeklyHour{{Weekday: 1, Start: "09:00", End: "12:00"}},
		},
		{
			ID: "v-bad", Name: "异常场地", Capacity: 20, Timezone: "UTC",
			WeeklyHours: []WeeklyHour{
				{Weekday: 7, Start: "22:00", End: "02:00"},
				{Weekday: 1, Start: "01:00", End: "03:00"},
			},
		},
	})
	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body = %s", rec.Code, rec.Body.String())
	}
	if _, present := decodeBody(t, rec)["venues"]; present {
		t.Fatalf("must not return a partial list of the valid venue")
	}
}

// TestStoredHoursStructuralProblemsAreCorruption 存量记录中星期越界或时间格式
// 非法（新增请求本会拒绝的结构问题）同样按数据损坏处理。
func TestStoredHoursStructuralProblemsAreCorruption(t *testing.T) {
	s, h := newTestServer(t)
	writeVenuesFile(t, s, []Venue{{
		ID: "v-weird", Name: "问题场地", Capacity: 8, Timezone: "UTC",
		WeeklyHours: []WeeklyHour{{Weekday: 9, Start: "10:00", End: "11:00"}},
	}})
	if rec := doJSON(t, h, http.MethodGet, "/api/venues", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("bad weekday in store: status = %d, want 500", rec.Code)
	}

	writeVenuesFile(t, s, []Venue{{
		ID: "v-weird2", Name: "问题场地", Capacity: 8, Timezone: "UTC",
		WeeklyHours: []WeeklyHour{{Weekday: 1, Start: "25:00", End: "11:00"}},
	}})
	if rec := doJSON(t, h, http.MethodGet, "/api/venues", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("bad time in store: status = %d, want 500", rec.Code)
	}
}

// TestLegacyNullWeeklyHoursReadAsEmpty 兼容旧数据：weeklyHours 为 null 或
// 缺省时按空数组读取，且这种数据之上仍可继续新增合法场地。
func TestLegacyNullWeeklyHoursReadAsEmpty(t *testing.T) {
	s, h := newTestServer(t)
	writeVenuesFile(t, s, []map[string]any{
		{"id": "v-null", "name": "旧场地甲", "capacity": 10, "timezone": "UTC", "weeklyHours": nil},
		{"id": "v-missing", "name": "旧场地乙", "capacity": 12, "timezone": "UTC"},
	})

	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy null/missing hours should still load: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	venues := decodeBody(t, rec)["venues"].([]any)
	if len(venues) != 2 {
		t.Fatalf("expected both legacy venues, got %v", venues)
	}
	for i, item := range venues {
		hours, ok := item.(map[string]any)["weeklyHours"].([]any)
		if !ok || len(hours) != 0 {
			t.Fatalf("venue %d weeklyHours should be [], got %v", i, item)
		}
	}

	// 兼容读取不放宽新增要求：缺 weeklyHours 的请求仍是 400。
	rec = doJSON(t, h, http.MethodPost, "/api/venues", map[string]any{
		"name": "新场地", "capacity": 5, "timezone": "UTC",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST without weeklyHours: status = %d, want 400", rec.Code)
	}

	// 合法新增仍应成功，并保留既有记录、标识与顺序。
	rec = doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid POST on legacy data: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodGet, "/api/venues", nil)
	venues = decodeBody(t, rec)["venues"].([]any)
	if len(venues) != 3 {
		t.Fatalf("expected 3 venues, got %d", len(venues))
	}
	ids := []string{
		venues[0].(map[string]any)["id"].(string),
		venues[1].(map[string]any)["id"].(string),
		venues[2].(map[string]any)["id"].(string),
	}
	if ids[0] != "v-null" || ids[1] != "v-missing" || ids[2] == "" {
		t.Fatalf("legacy ids/order changed or new id empty: %v", ids)
	}
}

// TestValidSavedHoursUnchanged 合法存量记录的读取行为与字段保持原样。
func TestValidSavedHoursUnchanged(t *testing.T) {
	s, h := newTestServer(t)
	want := []Venue{{
		ID: "v-keep", Name: "游泳馆", Capacity: 80, Timezone: "Asia/Shanghai",
		WeeklyHours: []WeeklyHour{
			{Weekday: 1, Start: "22:00", End: "02:00"},
			{Weekday: 2, Start: "02:00", End: "04:00"}, // 与跨午夜段相邻，合法
			{Weekday: 7, Start: "10:00", End: "12:00"},
		},
	}}
	writeVenuesFile(t, s, want)

	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid hours: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	venues := decodeBody(t, rec)["venues"].([]any)
	if len(venues) != 1 {
		t.Fatalf("expected 1 venue, got %v", venues)
	}
	got := venues[0].(map[string]any)
	if got["id"] != "v-keep" || got["name"] != "游泳馆" ||
		got["capacity"].(float64) != 80 || got["timezone"] != "Asia/Shanghai" {
		t.Fatalf("stored fields changed: %v", got)
	}
	hours := got["weeklyHours"].([]any)
	if len(hours) != 3 {
		t.Fatalf("stored hours changed: %v", hours)
	}
	// 合法时段顺序与内容不应被重排或改写。
	first := hours[0].(map[string]any)
	if int(first["weekday"].(float64)) != 1 || first["start"] != "22:00" || first["end"] != "02:00" {
		t.Fatalf("first hours slot changed: %v", first)
	}
}
