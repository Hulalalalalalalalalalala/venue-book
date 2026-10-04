package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// writeRawVenues 直接写入原始 JSON 文本，用于精确模拟存量数据中的 null、
// 缺失字段、错误类型和超大整数（绕过 Go 结构体在编解码时的零值填充）。
func writeRawVenues(t *testing.T, s *store, raw string) string {
	t.Helper()
	if err := os.WriteFile(s.path, []byte(raw), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return raw
}

func validStoredVenueMap() map[string]any {
	return map[string]any{
		"id":          "v-ok",
		"name":        "正常场地",
		"capacity":    20,
		"timezone":    "UTC",
		"weeklyHours": []any{},
	}
}

// TestStoredBasicFieldProblemsAreCorruption 覆盖需求列出的全部基础信息异常：
// 名称缺失/null/去空白为空，容量缺失/null/零/负数，时区缺失/null/空/Local/
// 非 IANA，以及各字段类型错误。读取必须 500，且带非空 error，不返回列表。
func TestStoredBasicFieldProblemsAreCorruption(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"name missing", `[{"id":"v","capacity":10,"timezone":"UTC","weeklyHours":[]}]`},
		{"name null", `[{"id":"v","name":null,"capacity":10,"timezone":"UTC","weeklyHours":[]}]`},
		{"name empty", `[{"id":"v","name":"","capacity":10,"timezone":"UTC","weeklyHours":[]}]`},
		{"name blank", `[{"id":"v","name":"   ","capacity":10,"timezone":"UTC","weeklyHours":[]}]`},
		{"name wrong type", `[{"id":"v","name":42,"capacity":10,"timezone":"UTC","weeklyHours":[]}]`},
		{"name boolean", `[{"id":"v","name":true,"capacity":10,"timezone":"UTC","weeklyHours":[]}]`},

		{"capacity missing", `[{"id":"v","name":"x","timezone":"UTC","weeklyHours":[]}]`},
		{"capacity null", `[{"id":"v","name":"x","capacity":null,"timezone":"UTC","weeklyHours":[]}]`},
		{"capacity zero", `[{"id":"v","name":"x","capacity":0,"timezone":"UTC","weeklyHours":[]}]`},
		{"capacity negative", `[{"id":"v","name":"x","capacity":-3,"timezone":"UTC","weeklyHours":[]}]`},
		{"capacity fractional", `[{"id":"v","name":"x","capacity":12.5,"timezone":"UTC","weeklyHours":[]}]`},
		{"capacity string", `[{"id":"v","name":"x","capacity":"10","timezone":"UTC","weeklyHours":[]}]`},
		{"capacity boolean", `[{"id":"v","name":"x","capacity":true,"timezone":"UTC","weeklyHours":[]}]`},
		{"capacity beyond supported range", `[{"id":"v","name":"x","capacity":9223372036854775808,"timezone":"UTC","weeklyHours":[]}]`},

		{"timezone missing", `[{"id":"v","name":"x","capacity":10,"weeklyHours":[]}]`},
		{"timezone null", `[{"id":"v","name":"x","capacity":10,"timezone":null,"weeklyHours":[]}]`},
		{"timezone empty", `[{"id":"v","name":"x","capacity":10,"timezone":"","weeklyHours":[]}]`},
		{"timezone Local", `[{"id":"v","name":"x","capacity":10,"timezone":"Local","weeklyHours":[]}]`},
		{"timezone bad IANA", `[{"id":"v","name":"x","capacity":10,"timezone":"Mars/Olympus","weeklyHours":[]}]`},
		{"timezone wrong type", `[{"id":"v","name":"x","capacity":10,"timezone":8,"weeklyHours":[]}]`},

		{"null entry in array", `[null]`},
		{"null entry after valid one", `[{"id":"v","name":"x","capacity":10,"timezone":"UTC","weeklyHours":[]},null]`},
		{"non-object entry", `[42]`},

		{"weekly hours wrong type", `[{"id":"v","name":"x","capacity":10,"timezone":"UTC","weeklyHours":"none"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, h := newTestServer(t)
			writeRawVenues(t, s, tc.raw)

			rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("GET: status = %d, want 500, body = %s", rec.Code, rec.Body.String())
			}
			body := decodeBody(t, rec)
			if msg, _ := body["error"].(string); msg == "" {
				t.Fatalf("500 must carry non-empty error, got %v", body)
			}
			if _, present := body["venues"]; present {
				t.Fatalf("must not return a venues list, got %v", body)
			}
		})
	}
}

// TestCorruptRecordAroundValidOnesFailsWholeRead 异常记录无论出现在正常记录
// 之前还是之后，整次读取都必须失败，不能只返回正常场地。
func TestCorruptRecordAroundValidOnesFailsWholeRead(t *testing.T) {
	good := validStoredVenueMap()
	badBlankName := map[string]any{
		"id": "v-bad", "name": "  ", "capacity": 5, "timezone": "UTC", "weeklyHours": []any{},
	}
	for _, tc := range []struct {
		name   string
		venues []any
	}{
		{"bad before good", []any{badBlankName, good}},
		{"bad after good", []any{good, badBlankName}},
		{"bad between good", []any{good, badBlankName, good}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, h := newTestServer(t)
			writeVenuesFile(t, s, tc.venues)
			rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500, body = %s", rec.Code, rec.Body.String())
			}
			if _, present := decodeBody(t, rec)["venues"]; present {
				t.Fatalf("must not return a partial list")
			}
		})
	}
}

// TestValidCreateWhileStoreCorruptReturns500AndKeepsFile 异常未修正时，提交
// 完全合法的新场地也必须 500：不增加记录、不改写/补齐/删除异常记录，文件
// 逐字节不变；错误说明的是存量数据不可用，而非本次填写有误。
func TestValidCreateWhileStoreCorruptReturns500AndKeepsFile(t *testing.T) {
	cases := map[string]string{
		"blank name":    `[{"id":"v","name":"   ","capacity":10,"timezone":"UTC","weeklyHours":[]}]`,
		"zero capacity": `[{"id":"v","name":"旧馆","capacity":0,"timezone":"UTC","weeklyHours":[]}]`,
		"bad timezone":  `[{"id":"v","name":"旧馆","capacity":10,"timezone":"Local","weeklyHours":[]}]`,
		"null entry":    `[{"id":"v","name":"旧馆","capacity":10,"timezone":"UTC","weeklyHours":[]},null]`,
		"broken json":   `{broken`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			s, h := newTestServer(t)
			writeRawVenues(t, s, raw)

			rec := doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("POST: status = %d, want 500, body = %s", rec.Code, rec.Body.String())
			}
			postBody := decodeBody(t, rec)
			msg, _ := postBody["error"].(string)
			if msg == "" {
				t.Fatalf("500 must carry non-empty error, got %v", postBody)
			}
			// 不能把存量数据问题说成这次请求填写有误（400 类措辞）。
			if strings.Contains(msg, "去除首尾空白") || strings.Contains(msg, "正整数") ||
				strings.Contains(msg, "IANA") {
				t.Fatalf("error must blame stored data, not the submitted payload: %q", msg)
			}

			after, err := os.ReadFile(s.path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != raw {
				t.Fatalf("stored data must remain byte-for-byte unchanged:\nbefore=%s\nafter =%s", raw, string(after))
			}

			// 再次读取仍应持续失败。
			if rec := doJSON(t, h, http.MethodGet, "/api/venues", nil); rec.Code != http.StatusInternalServerError {
				t.Fatalf("follow-up GET: status = %d, want 500", rec.Code)
			}
		})
	}
}

// TestStoredValidVenuesReturnedVerbatim 合法记录按创建顺序返回，标识、名称
// 原文、容量、时区保持不变；带首尾空白的名称合法性按去空白判断，但读取不
// 裁剪它；超过 JS 安全整数范围、仍在服务端范围内的容量逐位保留。
func TestStoredValidVenuesReturnedVerbatim(t *testing.T) {
	s, h := newTestServer(t)
	writeVenuesFile(t, s, []map[string]any{
		{
			"id": "v-a", "name": "  带空白名称  ", "capacity": json.Number("9007199254740993"),
			"timezone": "Asia/Shanghai", "weeklyHours": []any{},
		},
		{
			"id": "v-b", "name": "普通馆", "capacity": json.Number("120"),
			"timezone": "UTC",
			"weeklyHours": []any{
				map[string]any{"weekday": 1, "start": "09:00", "end": "12:00"},
			},
		},
	})

	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// 响应文本必须逐位携带大整数与名称原文。
	body := rec.Body.String()
	if !strings.Contains(body, "9007199254740993") || strings.Contains(body, "9007199254740992") {
		t.Fatalf("big capacity must be preserved exactly: %s", body)
	}
	if !strings.Contains(body, "  带空白名称  ") {
		t.Fatalf("name must be returned verbatim without trimming: %s", body)
	}

	var decoded struct {
		Venues []struct {
			ID       string      `json:"id"`
			Name     string      `json:"name"`
			Capacity json.Number `json:"capacity"`
			Timezone string      `json:"timezone"`
		} `json:"venues"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Venues) != 2 {
		t.Fatalf("expected 2 venues in order, got %d", len(decoded.Venues))
	}
	first := decoded.Venues[0]
	if first.ID != "v-a" || first.Name != "  带空白名称  " ||
		first.Capacity.String() != "9007199254740993" || first.Timezone != "Asia/Shanghai" {
		t.Fatalf("first venue changed: %+v", first)
	}
	second := decoded.Venues[1]
	if second.ID != "v-b" || second.Name != "普通馆" ||
		second.Capacity.String() != "120" || second.Timezone != "UTC" {
		t.Fatalf("second venue changed: %+v", second)
	}

	// 合法旧记录上仍能新增合法场地，顺序保持。
	createRec := doJSON(t, h, http.MethodPost, "/api/venues", validPayload())
	if createRec.Code != http.StatusCreated {
		t.Fatalf("valid create on valid store: status = %d, body = %s",
			createRec.Code, createRec.Body.String())
	}
	listRec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	var listed struct {
		Venues []struct {
			ID string `json:"id"`
		} `json:"venues"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Venues) != 3 || listed.Venues[0].ID != "v-a" || listed.Venues[1].ID != "v-b" {
		t.Fatalf("order/ids changed after create: %+v", listed.Venues)
	}
	if listed.Venues[2].ID == "" {
		t.Fatalf("new venue must have an id")
	}
}

// TestLegacyNullHoursStillLoadsButBasicFieldsNotRelaxed 验证 weeklyHours 的
// 缺省/null 兼容仍然保留（按空数组），但这个兼容绝不扩展到名称、容量、时区。
func TestLegacyNullHoursStillLoadsButBasicFieldsNotRelaxed(t *testing.T) {
	s, h := newTestServer(t)
	// 名称/容量/时区合法、weeklyHours 缺失或为 null：照常读取为 []。
	writeVenuesFile(t, s, []map[string]any{
		{"id": "v-null", "name": "旧场地甲", "capacity": 10, "timezone": "UTC", "weeklyHours": nil},
		{"id": "v-missing", "name": "旧场地乙", "capacity": 12, "timezone": "UTC"},
	})
	rec := doJSON(t, h, http.MethodGet, "/api/venues", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy null/missing hours should load: status = %d, body = %s",
			rec.Code, rec.Body.String())
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

	// 同样的“缺省/null”若发生在基础字段上，则必须判损坏，不享受兼容。
	for _, raw := range []string{
		`[{"id":"v","capacity":10,"timezone":"UTC","weeklyHours":[]}]`, // 缺 name
		`[{"id":"v","name":"x","timezone":"UTC","weeklyHours":[]}]`,    // 缺 capacity
		`[{"id":"v","name":"x","capacity":10,"weeklyHours":[]}]`,       // 缺 timezone
	} {
		writeRawVenues(t, s, raw)
		if rec := doJSON(t, h, http.MethodGet, "/api/venues", nil); rec.Code != http.StatusInternalServerError {
			t.Fatalf("missing basic field must be 500, got %d for %s", rec.Code, raw)
		}
	}
}
