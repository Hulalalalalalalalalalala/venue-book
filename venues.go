package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	// 内嵌时区数据库，保证在没有 /usr/share/zoneinfo 的环境中也能校验 IANA 时区。
	_ "time/tzdata"
)

// maxVenueCapacity 是容量字段支持的整数上限。容量表示人数，必须能在
// 请求、保存和响应中逐位准确表示，因此范围限定在本机 int 可容纳的区间内
// （64 位平台上即 int64 上限）。
const maxVenueCapacity = int64(^uint(0) >> 1)

// WeeklyHour 表示每周固定的一段开放时间。
// Weekday 用 1 到 7 表示周一至周日；Start/End 为 HH:mm。
// End 晚于 Start 表示当天结束，早于 Start 表示次日结束。
type WeeklyHour struct {
	Weekday int    `json:"weekday"`
	Start   string `json:"start"`
	End     string `json:"end"`
}

// Venue 是一条场地记录。
type Venue struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Capacity    int          `json:"capacity"`
	Timezone    string       `json:"timezone"`
	WeeklyHours []WeeklyHour `json:"weeklyHours"`
}

// apiError 是返回给客户端的校验错误（HTTP 400）。
type apiError struct{ msg string }

func (e *apiError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &apiError{msg: fmt.Sprintf(format, args...)}
}

// store 负责场地记录的持久化，所有访问都通过互斥锁串行化。
type store struct {
	mu   sync.Mutex
	path string
}

func newStore(dataDir string) (*store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "venues.json")
	// 全新数据目录时初始化为空数组，保持原有行为。
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		if _, err := file.WriteString("[]\n"); err != nil {
			_ = file.Close()
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return &store{path: path}, nil
}

// load 读取并解析全部记录。读不到、JSON 损坏、结构异常，或任一场地的名称、
// 容量、时区、开放时段不满足新增功能已经公开的有效性规则，都返回错误，调用
// 方必须按 500 处理。绝不能把错误数据当作空列表覆盖，也不能跳过异常场地只
// 返回剩余记录；异常记录前后即使都有正常场地，整次读取也必须失败。
func (s *store) load() ([]Venue, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	// 用 UseNumber 做通用解码，让 capacity 等数字保留原始十进制文本
	// （json.Number），与新增入口一致：既不会把带小数的值静默舍入成整数，
	// 也能逐位识别超过 JavaScript 安全整数范围、但仍在服务端支持范围内的
	// 容量。直接解码到具体结构体会把缺失/null 的名称、容量、时区填成零值，
	// 从而漏掉存量数据里的异常，因此这里先解码成 map 再逐字段严格校验。
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var records []map[string]any
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("venues data is corrupted: %w", err)
	}
	// 拒绝数组之后的多余 JSON 内容（等价于此前 json.Unmarshal 的单值约束）。
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("venues data is corrupted: unexpected content after venue array")
	}

	venues := make([]Venue, 0, len(records))
	for i, rec := range records {
		// 数组中的 null（解码为 nil map）或任何非对象条目都是数据异常，
		// 不能变成名称为空、容量为零的场地。非对象条目在解码阶段已报错，
		// 这里拦的是 null。
		if rec == nil {
			return nil, fmt.Errorf("venues data is corrupted at venue index %d: entry is null", i)
		}
		venue, err := decodeStoredVenue(rec)
		if err != nil {
			return nil, fmt.Errorf("venues data is corrupted at venue index %d: %w", i, err)
		}
		venues = append(venues, venue)
	}
	return venues, nil
}

// decodeStoredVenue 对一条已保存记录逐字段做严格校验，规则与 buildVenue 在
// 新增请求上公开的规则完全一致。任何不满足都返回错误（由 load 按数据损坏、
// HTTP 500 处理），绝不把错误类型或缺失值转换成合法零值。
func decodeStoredVenue(rec map[string]any) (Venue, error) {
	// 标识不是本次校验重点，但类型错误仍属于结构异常：缺失/null 与历史行为
	// 一样按空串读取，其它非字符串类型直接判损坏。
	id, err := optionalStringField(rec, "id")
	if err != nil {
		return Venue{}, err
	}

	name, err := storedName(rec)
	if err != nil {
		return Venue{}, err
	}

	capacity, err := storedCapacity(rec)
	if err != nil {
		return Venue{}, err
	}

	timezone, err := storedTimezone(rec)
	if err != nil {
		return Venue{}, err
	}

	// 唯一保留的兼容规则：weeklyHours 缺省或为 null 仍按空数组（暂未开放）
	// 读取。该兼容不扩展到名称、容量、时区；字段存在但类型不对同样判损坏。
	rawHours, hasHours := rec["weeklyHours"]
	var hours []WeeklyHour
	if !hasHours || rawHours == nil {
		hours = []WeeklyHour{}
	} else {
		hours, err = parseWeeklyHours(rawHours)
		if err != nil {
			// parseWeeklyHours 的错误来自新增校验路径，类型是 *apiError
			//（400）。这里是存量数据读取，必须按数据损坏（500）处理，因此
			// 只保留错误文案、剥掉 apiError 类型，避免上层 errors.As 误判为
			// 这次请求填写有误。
			return Venue{}, errors.New(err.Error())
		}
		// 已保存数据同样必须满足新增时的全部时段业务规则。
		if err := validateHours(hours); err != nil {
			return Venue{}, err
		}
	}

	return Venue{
		ID:          id,
		Name:        name,
		Capacity:    capacity,
		Timezone:    timezone,
		WeeklyHours: hours,
	}, nil
}

// optionalStringField 读取一个可缺省的字符串字段：缺失或 null 返回空串，
// 其它非字符串类型视为数据异常。
func optionalStringField(rec map[string]any, field string) (string, error) {
	value, ok := rec[field]
	if !ok || value == nil {
		return "", nil
	}
	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s 类型错误：应为字符串", field)
	}
	return str, nil
}

// storedName 校验已保存记录的名称：必须存在、非 null、是字符串，且去掉首尾
// 空白后非空。合法性按去空白结果判断，但返回的是名称原文——读取绝不顺便
// 改写或裁剪名称。
func storedName(rec map[string]any) (string, error) {
	value, ok := rec["name"]
	if !ok || value == nil {
		return "", errors.New("name 缺失或为 null")
	}
	name, ok := value.(string)
	if !ok {
		return "", errors.New("name 类型错误：应为字符串")
	}
	if strings.TrimSpace(name) == "" {
		return "", errors.New("name 去除首尾空白后不能为空")
	}
	return name, nil
}

// storedCapacity 校验已保存记录的容量：必须存在、非 null，按 JSON 数字原文
// 精确判断为 1 到 maxVenueCapacity 的正整数。缺失、null、零、负数、带小数、
// 类型错误或超出服务端支持范围都属于数据异常，绝不截断或舍入成相邻整数。
func storedCapacity(rec map[string]any) (int, error) {
	value, ok := rec["capacity"]
	if !ok || value == nil {
		return 0, errors.New("capacity 缺失或为 null")
	}
	z, sign, isInt, inRange := parseJSONInteger(value)
	if !isInt || sign <= 0 {
		return 0, errors.New("capacity 必须是正整数")
	}
	if !inRange || z.Int64() > maxVenueCapacity {
		return 0, errors.New("capacity 超出服务端支持的整数范围")
	}
	return int(z.Int64()), nil
}

// storedTimezone 校验已保存记录的时区：必须存在、非 null、是非空字符串、不
// 能是 "Local"，且必须是有效的 IANA 时区名称。
func storedTimezone(rec map[string]any) (string, error) {
	value, ok := rec["timezone"]
	if !ok || value == nil {
		return "", errors.New("timezone 缺失或为 null")
	}
	timezone, ok := value.(string)
	if !ok {
		return "", errors.New("timezone 类型错误：应为字符串")
	}
	if timezone == "" || timezone == "Local" {
		return "", errors.New("timezone 必须是有效的 IANA 时区名称")
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return "", errors.New("timezone 必须是有效的 IANA 时区名称")
	}
	return timezone, nil
}

// save 通过同目录临时文件 + 重命名原子写入，避免半写状态损坏数据。
func (s *store) save(venues []Venue) error {
	encoded, err := json.MarshalIndent(venues, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".venues-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// list 返回当前全部场地（按首次创建顺序保留）。
func (s *store) list() ([]Venue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// create 校验请求内容，通过后写入新记录并返回保存后的场地。
// 校验失败时返回 apiError（400），不会写入任何内容。
func (s *store) create(payload map[string]any) (Venue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	venues, err := s.load()
	if err != nil {
		return Venue{}, err
	}

	venue, err := buildVenue(payload)
	if err != nil {
		return Venue{}, err
	}

	venue.ID = newID()
	for idTaken(venues, venue.ID) {
		// 极小概率的随机碰撞：重新生成直到唯一。
		venue.ID = newID()
	}
	venues = append(venues, venue)
	if err := s.save(venues); err != nil {
		return Venue{}, err
	}
	return venue, nil
}

// buildVenue 对请求对象做逐字段严格校验。
func buildVenue(payload map[string]any) (Venue, error) {
	name, err := requireString(payload, "name")
	if err != nil {
		return Venue{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Venue{}, badRequest("name 去除首尾空白后不能为空")
	}

	capacity, err := requirePositiveInt(payload, "capacity")
	if err != nil {
		return Venue{}, err
	}

	timezone, err := requireString(payload, "timezone")
	if err != nil {
		return Venue{}, err
	}
	if timezone == "" || timezone == "Local" {
		return Venue{}, badRequest("timezone 必须是有效的 IANA 时区名称，例如 Asia/Shanghai")
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return Venue{}, badRequest("timezone 必须是有效的 IANA 时区名称，例如 Asia/Shanghai")
	}

	rawHours, ok := payload["weeklyHours"]
	if !ok {
		return Venue{}, badRequest("缺少 weeklyHours 字段")
	}
	hours, err := parseWeeklyHours(rawHours)
	if err != nil {
		return Venue{}, err
	}
	if err := validateHours(hours); err != nil {
		// 读取已保存数据时 validateHours 的错误按数据损坏（500）处理；
		// 这里是新增请求，包装成面向客户端的 400 校验错误。
		return Venue{}, badRequest("%s", err.Error())
	}

	return Venue{
		Name:        name,
		Capacity:    capacity,
		Timezone:    timezone,
		WeeklyHours: hours,
	}, nil
}

func missingOrWrong(field, kind string) error {
	return badRequest("%s 类型错误：应为%s", field, kind)
}

func requireString(payload map[string]any, field string) (string, error) {
	value, ok := payload[field]
	if !ok || value == nil {
		return "", missingOrWrong(field, "字符串")
	}
	str, ok := value.(string)
	if !ok {
		return "", missingOrWrong(field, "字符串")
	}
	return str, nil
}

// parseJSONInteger 按 JSON 数字的准确十进制文本判断它是否为整数，并返回其
// 精确值。value 必须来自开启了 UseNumber 的 JSON 解码（即 json.Number），
// 这样即使是 9007199254740993 这样超过 float64 安全整数范围、或
// 120.00000000000000001 这样带极小小数的数字，也不会在转换中被悄悄舍入。
//
// 返回值含义：
//   - isInt=false：不是 JSON 整数（根本不是数字，或带有非零小数部分）；
//   - isInt=true、inRange=true：z 是精确的整数值，且能放进 int64；
//   - isInt=true、inRange=false：确实是整数，但超出 int64 可表示范围，
//     此时 z 为 nil，sign 仍标明它是正数还是负数。
//
// 120、120.0、1.2e2 都得到整数 120；120.00000000000000001 和 1e-1 则带
// 小数部分，判定为非整数。
func parseJSONInteger(value any) (z *big.Int, sign int, isInt bool, inRange bool) {
	switch number := value.(type) {
	case json.Number:
		return parseIntegerText(string(number))
	case float64:
		// 兼容直接在进程内构造 map（如测试）的调用方。HTTP 入口已启用
		// UseNumber，不会走到这里；此处能看到的只有调用方手中的 float64，
		// 按其当前值做精确的整数判断即可。
		if math.IsNaN(number) || math.IsInf(number, 0) || number != math.Trunc(number) {
			return nil, 0, false, false
		}
		sig := 1
		switch {
		case number < 0:
			sig = -1
		case number == 0:
			sig = 0
		}
		// 用严格的 2^63 边界比较，避免 float64(math.MaxInt64) 进位到 2^63
		// 后再转 int64 发生溢出回绕。
		if number < -9223372036854775808.0 || number >= 9223372036854775808.0 {
			return nil, sig, true, false
		}
		n := int64(number)
		return big.NewInt(n), sig, true, true
	default:
		return nil, 0, false, false
	}
}

// parseIntegerText 按 JSON 数字的原始十进制文本做精确解析，逻辑见
// parseJSONInteger 的说明。
func parseIntegerText(text string) (z *big.Int, sign int, isInt bool, inRange bool) {
	mant, exp, ok := decimalNumber(text)
	if !ok {
		return nil, 0, false, false
	}
	if mant.Sign() == 0 {
		// 0、0.0、0e10 等都精确等于整数 0。
		return big.NewInt(0), 0, true, true
	}
	// 极大/极小指数下无需真的构造巨大整数：非零尾数乘 10^exp 必然超出
	// int64；非零数除以足够大的 10 的幂必然留下小数部分。
	switch {
	case exp > 100000:
		return nil, mant.Sign(), true, false
	case exp < -100000:
		return nil, mant.Sign(), false, false
	}
	z = new(big.Int).Set(mant)
	if exp >= 0 {
		z.Mul(z, new(big.Int).Exp(big.NewInt(10), big.NewInt(exp), nil))
	} else {
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(-exp), nil)
		abs := new(big.Int).Set(z)
		if abs.Sign() < 0 {
			abs.Neg(abs)
		}
		// 不能被 10^(-exp) 整除，说明小数点后存在非零数字，不是整数。
		if new(big.Int).Mod(abs, divisor).Sign() != 0 {
			return nil, mant.Sign(), false, false
		}
		z.Quo(z, divisor)
	}
	if !z.IsInt64() {
		return nil, z.Sign(), true, false
	}
	return z, z.Sign(), true, true
}

// decimalNumber 把 JSON 数字文本拆成带符号的整数尾数 m 与十进制指数 e，
// 使 原值 == m * 10^e。输入来自合法 JSON 解码，不接受 Infinity/NaN。
func decimalNumber(text string) (m *big.Int, e int64, ok bool) {
	s := text
	neg := false
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return nil, 0, false
	}
	rest, expText, hasExp := s, "", false
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		rest, expText, hasExp = s[:i], s[i+1:], true
	}
	body := rest
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		whole, frac := rest[:i], rest[i+1:]
		if frac == "" {
			return nil, 0, false // 如 "1."，不是合法 JSON 数字
		}
		body = whole + frac
		e = -int64(len(frac))
	}
	if body == "" || !isDigits(body) {
		return nil, 0, false
	}
	if hasExp {
		exp, err := strconv.ParseInt(expText, 10, 64)
		if err != nil {
			return nil, 0, false
		}
		e += exp
	}
	m, ok = new(big.Int).SetString(body, 10)
	if !ok {
		return nil, 0, false
	}
	if neg {
		m.Neg(m)
	}
	return m, e, true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// requirePositiveInt 校验表示人数的容量字段：必须是 JSON 数字、按准确数值
// 判断为正整数，且落在支持的整数范围内。任何非正整数（零、负数以及带小数
// 部分的数字）都返回“必须是正整数”；是整数但超出范围则返回“超出支持范围”，
// 绝不截断或舍入成相邻整数保存。
func requirePositiveInt(payload map[string]any, field string) (int, error) {
	value, ok := payload[field]
	if !ok || value == nil {
		return 0, missingOrWrong(field, "正整数")
	}
	z, sign, isInt, inRange := parseJSONInteger(value)
	if !isInt || sign <= 0 {
		return 0, missingOrWrong(field, "正整数")
	}
	if !inRange || z.Int64() > maxVenueCapacity {
		return 0, badRequest("%s 超出支持范围：容量必须是 1 到 %d 的整数", field, maxVenueCapacity)
	}
	return int(z.Int64()), nil
}

// requireWeekday 用与容量相同的精确文本解析星期字段，保证只接受 1 到 7 的
// 整数（1.5 这类带小数的值不会被舍入后接受）。
func requireWeekday(value any, i int) (int, error) {
	z, _, isInt, inRange := parseJSONInteger(value)
	if !isInt {
		return 0, badRequest("weeklyHours[%d].weekday 类型错误：应为 1 到 7 的整数", i)
	}
	if !inRange || z.Int64() < 1 || z.Int64() > 7 {
		return 0, badRequest("weeklyHours[%d].weekday 必须为 1 到 7（周一至周日）", i)
	}
	return int(z.Int64()), nil
}

func parseWeeklyHours(raw any) ([]WeeklyHour, error) {
	if raw == nil {
		return nil, badRequest("weeklyHours 类型错误：应为数组")
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, badRequest("weeklyHours 类型错误：应为数组")
	}
	hours := make([]WeeklyHour, 0, len(items))
	for i, item := range items {
		obj, ok := item.(map[string]any)
		if !ok || obj == nil {
			return nil, badRequest("weeklyHours[%d] 类型错误：应为对象", i)
		}
		rawWeekday, ok := obj["weekday"]
		if !ok || rawWeekday == nil {
			return nil, badRequest("weeklyHours[%d].weekday 类型错误：应为 1 到 7 的整数", i)
		}
		weekday, err := requireWeekday(rawWeekday, i)
		if err != nil {
			return nil, err
		}
		start, err := hourField(obj, i, "start")
		if err != nil {
			return nil, err
		}
		end, err := hourField(obj, i, "end")
		if err != nil {
			return nil, err
		}
		hours = append(hours, WeeklyHour{Weekday: weekday, Start: start, End: end})
	}
	return hours, nil
}

func hourField(obj map[string]any, i int, field string) (string, error) {
	value, ok := obj[field]
	if !ok || value == nil {
		return "", badRequest("weeklyHours[%d].%s 类型错误：应为 HH:mm 时间", i, field)
	}
	str, ok := value.(string)
	if !ok || !validHHMM(str) {
		return "", badRequest("weeklyHours[%d].%s 时间无效，必须为 00:00 至 23:59 的 HH:mm 格式", i, field)
	}
	return str, nil
}

// validHHMM 严格校验 HH:mm：两位小时、冒号、两位分钟，范围 00:00–23:59。
func validHHMM(value string) bool {
	if len(value) != 5 || value[2] != ':' {
		return false
	}
	for i, c := range value {
		if i == 2 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	hour := int(value[0]-'0')*10 + int(value[1]-'0')
	minute := int(value[3]-'0')*10 + int(value[4]-'0')
	return hour <= 23 && minute <= 59
}

func minutes(value string) int {
	return int(value[0]-'0')*600 + int(value[1]-'0')*60 +
		int(value[3]-'0')*10 + int(value[4]-'0')
}

// interval 是展开到周时间轴上的一段开放时间，单位为分钟。
// 周一 00:00 为起点 0。
type interval struct {
	start int
	end   int
	label string
}

// validateHours 按开放时段的业务规则检查一段已解析的时段数据。
// 规则同时用于新增请求（400 校验）和已保存数据（损坏时按 500 处理）：
// 星期为 1–7（周一至周日），时间为严格 HH:mm（00:00–23:59），
// 起止时间不能相同；结束早于开始表示次日结束。重叠判断覆盖跨午夜
// 延续到次日的部分，也包含周日延续到下周一的部分；部分重叠、完全
// 包含和重复时段都不合法，下一段恰好在前一段结束时开始合法。
// 时段的填写顺序不影响结果。
//
// 返回的是普通错误而非 apiError：读取已保存数据命中时按数据损坏（500）
// 处理；新增流程由 buildVenue 包装成面向客户端的 400 错误。
func validateHours(hours []WeeklyHour) error {
	intervals := make([]interval, 0, len(hours)*2)
	for _, h := range hours {
		if h.Weekday < 1 || h.Weekday > 7 {
			return fmt.Errorf("开放时段无效：星期 %d 不在 1 到 7（周一至周日）范围内", h.Weekday)
		}
		if !validHHMM(h.Start) || !validHHMM(h.End) {
			return fmt.Errorf("开放时段无效：%s 的时间 %s-%s 不是合法的 HH:mm", weekdayName(h.Weekday), h.Start, h.End)
		}
		startMin := minutes(h.Start)
		endMin := minutes(h.End)
		label := fmt.Sprintf("%s %s-%s", weekdayName(h.Weekday), h.Start, h.End)
		if startMin == endMin {
			return fmt.Errorf("开放时段无效：%s 的结束时间与开始时间相同", label)
		}
		start := (h.Weekday-1)*1440 + startMin
		end := (h.Weekday-1)*1440 + endMin
		if endMin < startMin {
			end += 1440 // 跨午夜，次日结束
		}
		intervals = append(intervals, interval{start: start, end: end, label: label})
	}
	// 复制到下一周，用于检测周日跨午夜与下周一时段相交。
	base := make([]interval, len(intervals))
	copy(base, intervals)
	for _, iv := range base {
		intervals = append(intervals, interval{
			start: iv.start + 7*1440,
			end:   iv.end + 7*1440,
			label: iv.label,
		})
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start != intervals[j].start {
			return intervals[i].start < intervals[j].start
		}
		return intervals[i].end < intervals[j].end
	})
	for i := 1; i < len(intervals); i++ {
		if intervals[i].start < intervals[i-1].end {
			return fmt.Errorf("开放时段存在相交：%s 与其他时段重叠", intervals[i].label)
		}
	}
	return nil
}

func weekdayName(weekday int) string {
	return [...]string{"", "周一", "周二", "周三", "周四", "周五", "周六", "周日"}[weekday]
}

// newID 生成非空、概率上唯一的记录标识。
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败极不寻常；退化为纳秒时间戳，仍保证非空且基本唯一。
		return fmt.Sprintf("v-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func idTaken(venues []Venue, id string) bool {
	for _, v := range venues {
		if v.ID == id {
			return true
		}
	}
	return false
}
