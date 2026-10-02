package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	// 内嵌时区数据库，保证在没有 /usr/share/zoneinfo 的环境中也能校验 IANA 时区。
	_ "time/tzdata"
)

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

// load 读取并解析全部记录。读不到、JSON 损坏或结构异常都返回错误，
// 调用方必须按 500 处理，绝不能把错误数据当作空列表覆盖。
func (s *store) load() ([]Venue, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var venues []Venue
	if err := json.Unmarshal(raw, &venues); err != nil {
		return nil, fmt.Errorf("venues data is corrupted: %w", err)
	}
	if venues == nil {
		venues = []Venue{}
	}
	for i := range venues {
		if venues[i].WeeklyHours == nil {
			venues[i].WeeklyHours = []WeeklyHour{}
		}
	}
	return venues, nil
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
		return Venue{}, err
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

// jsonInt 取出一个 JSON 数字并要求它是整数；正数范围由调用方决定。
func jsonInt(value any) (int, bool) {
	number, ok := value.(float64)
	if !ok {
		return 0, false
	}
	if number != float64(int64(number)) {
		return 0, false
	}
	return int(number), true
}

func requirePositiveInt(payload map[string]any, field string) (int, error) {
	value, ok := payload[field]
	if !ok || value == nil {
		return 0, missingOrWrong(field, "正整数")
	}
	number, ok := jsonInt(value)
	if !ok || number <= 0 {
		return 0, missingOrWrong(field, "正整数")
	}
	return number, nil
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
		weekday, ok := jsonInt(rawWeekday)
		if !ok {
			return nil, badRequest("weeklyHours[%d].weekday 类型错误：应为 1 到 7 的整数", i)
		}
		if weekday < 1 || weekday > 7 {
			return nil, badRequest("weeklyHours[%d].weekday 必须为 1 到 7（周一至周日）", i)
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

// validateHours 检查所有时段是否相交或互相包含。
// 时段按“开始星期 × 开始时间”展开；跨午夜时段延伸到次日。
// 为检查周日延续到周一的情况，所有时段再复制一份到下一周坐标系。
// 前一段结束与下一段开始相同时允许保存。
func validateHours(hours []WeeklyHour) error {
	intervals := make([]interval, 0, len(hours)*2)
	for _, h := range hours {
		startMin := minutes(h.Start)
		endMin := minutes(h.End)
		label := fmt.Sprintf("%s %s-%s", weekdayName(h.Weekday), h.Start, h.End)
		if startMin == endMin {
			return badRequest("开放时段无效：%s 的结束时间与开始时间相同", label)
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
			return badRequest("开放时段存在相交：%s 与其他时段重叠", intervals[i].label)
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
