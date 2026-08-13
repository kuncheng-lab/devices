package atlas_pf6000

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPort           = 4545
	DefaultTimeoutMs      = 3000
	openProtocolHeaderLen = 20
)

type OpenProtocolProbeRequest struct {
	Host         string
	Port         int
	MID          int
	Revision     int
	NoAck        bool
	Station      int
	Spindle      int
	Data         string
	TimeoutMs    int
	StrictHeader bool
}

type OpenProtocolProbeResult struct {
	TX      string
	RX      string
	MID     string
	Summary string
}

type OpenProtocolMessage struct {
	Length   int
	MID      string
	Revision string
	NoAck    string
	Station  string
	Spindle  string
	Reserved string
	Data     string
}

type PsetProgram struct {
	ID           string
	Name         string
	Direction    string
	BatchSize    string
	TorqueMin    string
	TorqueTarget string
	TorqueMax    string
	AngleMin     string
	AngleTarget  string
	AngleMax     string
	Raw          string
	UpdatedAt    string
}

func ProbeOpenProtocol(req OpenProtocolProbeRequest) (OpenProtocolProbeResult, error) {
	normalizeProbeRequest(&req)
	frame, err := BuildOpenProtocolFrame(req)
	if err != nil {
		return OpenProtocolProbeResult{}, err
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(req.Host, strconv.Itoa(req.Port)), time.Duration(req.TimeoutMs)*time.Millisecond)
	if err != nil {
		return OpenProtocolProbeResult{TX: FrameText(frame)}, err
	}
	defer conn.Close()

	deadline := time.Now().Add(time.Duration(req.TimeoutMs) * time.Millisecond)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(frame); err != nil {
		return OpenProtocolProbeResult{TX: FrameText(frame)}, err
	}

	rx, err := bufio.NewReader(conn).ReadString(0)
	if err != nil {
		return OpenProtocolProbeResult{TX: FrameText(frame)}, err
	}

	raw := strings.TrimRight(rx, "\x00")
	msg, parseErr := ParseOpenProtocolMessage(raw)
	result := OpenProtocolProbeResult{
		TX: FrameText(frame),
		RX: VisibleFrame(raw),
	}
	if parseErr != nil {
		result.Summary = fmt.Sprintf("收到响应，但解析失败: %v", parseErr)
		return result, nil
	}
	result.MID = msg.MID
	result.Summary = SummarizeOpenProtocolResponse(msg)
	return result, nil
}

func BuildOpenProtocolFrame(req OpenProtocolProbeRequest) ([]byte, error) {
	normalizeProbeRequest(&req)
	if req.MID < 0 || req.MID > 9999 {
		return nil, fmt.Errorf("MID 必须在 0-9999 之间")
	}
	if req.Revision < 0 || req.Revision > 999 {
		return nil, fmt.Errorf("Revision 必须在 0-999 之间")
	}
	if req.Station < 0 || req.Station > 99 {
		return nil, fmt.Errorf("Station 必须在 0-99 之间")
	}
	if req.Spindle < 0 || req.Spindle > 99 {
		return nil, fmt.Errorf("Spindle 必须在 0-99 之间")
	}

	noAck := '0'
	if req.NoAck {
		noAck = '1'
	}
	data := SanitizeOpenProtocolData(req.Data)
	if req.StrictHeader {
		text := fmt.Sprintf("%04d%04d%03d%c%02d%02d0000%s",
			openProtocolHeaderLen+len(data),
			req.MID,
			req.Revision,
			noAck,
			req.Station,
			req.Spindle,
			data,
		)
		return append([]byte(text), 0), nil
	}
	station := "  "
	if req.Station > 0 {
		station = fmt.Sprintf("%2d", req.Station)
	}
	spindle := "  "
	if req.Spindle > 0 {
		spindle = fmt.Sprintf("%2d", req.Spindle)
	}
	text := fmt.Sprintf("%04d%04d%03d%c%s%s00  %s",
		openProtocolHeaderLen+len(data),
		req.MID,
		req.Revision,
		noAck,
		station,
		spindle,
		data,
	)
	return append([]byte(text), 0), nil
}

func ParseOpenProtocolMessage(raw string) (OpenProtocolMessage, error) {
	raw = strings.TrimRight(raw, "\x00")
	if len(raw) < openProtocolHeaderLen {
		return OpenProtocolMessage{}, fmt.Errorf("消息长度不足: %d", len(raw))
	}
	length, err := strconv.Atoi(raw[0:4])
	if err != nil {
		return OpenProtocolMessage{}, fmt.Errorf("长度字段无效 %q", raw[0:4])
	}
	msg := OpenProtocolMessage{
		Length:   length,
		MID:      raw[4:8],
		Revision: raw[8:11],
		NoAck:    raw[11:12],
		Station:  raw[12:14],
		Spindle:  raw[14:16],
		Reserved: raw[16:20],
		Data:     raw[20:],
	}
	return msg, nil
}

func SummarizeOpenProtocolResponse(msg OpenProtocolMessage) string {
	switch msg.MID {
	case "0002":
		return "通信启动成功，PF6000 接受握手"
	case "0004":
		failedMID := FieldOrUnknown(msg.Data, 0, 4)
		code := FieldOrUnknown(msg.Data, 4, 6)
		if failedMID == "0060" && code == "09" {
			return "订阅已存在: MID 0060, 控制器认为 Last tightening result 已有订阅"
		}
		return fmt.Sprintf("命令被拒绝: MID %s, 错误码 %s (%s)", failedMID, code, OpenProtocolErrorText(code))
	case "0005":
		acceptedMID := FieldOrUnknown(msg.Data, 0, 4)
		return fmt.Sprintf("命令已接受: MID %s", acceptedMID)
	case "0011":
		return summarizePsetList(msg.Data)
	case "0013":
		return summarizePsetDetail(msg.Data)
	case "2601":
		return summarizeModeList(msg.Data)
	case "2603":
		return summarizeModeDetail(msg.Data)
	case "0061":
		return summarizeTighteningResult(msg)
	case "0101":
		return summarizeMultiSpindleResult(msg)
	case "9999":
		return "收到心跳响应"
	default:
		return fmt.Sprintf("收到 MID %s，数据长度 %d", msg.MID, len(msg.Data))
	}
}

func ParsePsetProgram(msg OpenProtocolMessage) (PsetProgram, bool) {
	if msg.MID != "0013" {
		return PsetProgram{}, false
	}
	detail := parsePsetDetail(msg.Data)
	if detail.ID == "" {
		return PsetProgram{}, false
	}
	return PsetProgram{
		ID:           detail.ID,
		Name:         detail.Name,
		Direction:    detail.Direction,
		BatchSize:    detail.BatchSize,
		TorqueMin:    detail.TorqueMin,
		TorqueTarget: detail.TorqueTarget,
		TorqueMax:    detail.TorqueMax,
		AngleMin:     detail.AngleMin,
		AngleTarget:  detail.AngleTarget,
		AngleMax:     detail.AngleMax,
		Raw:          msg.Data,
	}, true
}

func ParseSelectedPset(msg OpenProtocolMessage) (string, bool) {
	if msg.MID != "0015" {
		return "", false
	}
	data := msg.Data
	if msg.Revision == "002" {
		if FieldOrUnknown(data, 0, 2) != "01" {
			return "", false
		}
		data = FieldOrUnknown(data, 2, 5)
	} else {
		data = FieldOrUnknown(data, 0, 3)
	}
	psetID := strings.TrimSpace(data)
	value, err := strconv.Atoi(psetID)
	if err != nil || value < 0 || value > 999 {
		return "", false
	}
	return fmt.Sprintf("%03d", value), true
}

type modeListEntry struct {
	ID   string
	Name string
}

type modeBolt struct {
	PsetID     string
	ToolNumber string
	BoltNumber string
	Name       string
}

type modeDetail struct {
	ID    string
	Name  string
	Bolts []modeBolt
}

func summarizeModeList(data string) string {
	entries, ok := parseModeList(data)
	if !ok {
		return fmt.Sprintf("收到 Mode 列表响应，但未能解析。数据长度 %d，Raw=%q", len(data), trimForLog(data))
	}
	lines := []string{fmt.Sprintf("收到 Mode 列表: 共 %d 个", len(entries))}
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			name = "--"
		}
		lines = append(lines, fmt.Sprintf("  Mode %s: %s", entry.ID, name))
	}
	return strings.Join(lines, "\n")
}

func parseModeList(data string) ([]modeListEntry, bool) {
	if len(data) < 3 {
		return nil, false
	}
	count, err := strconv.Atoi(data[:3])
	if err != nil || count < 0 {
		return nil, false
	}
	cursor := 3
	entries := make([]modeListEntry, 0, count)
	for i := 0; i < count; i++ {
		if cursor+6 > len(data) {
			return nil, false
		}
		id := data[cursor : cursor+4]
		cursor += 4
		nameSize, err := strconv.Atoi(data[cursor : cursor+2])
		cursor += 2
		if err != nil || nameSize < 0 || cursor+nameSize > len(data) {
			return nil, false
		}
		entries = append(entries, modeListEntry{ID: id, Name: data[cursor : cursor+nameSize]})
		cursor += nameSize
	}
	return entries, true
}

func summarizeModeDetail(data string) string {
	detail, ok := parseModeDetail(data)
	if !ok {
		return fmt.Sprintf("收到 Mode 详情响应，但未能解析。数据长度 %d，Raw=%q", len(data), trimForLog(data))
	}
	name := strings.TrimSpace(detail.Name)
	if name == "" {
		name = "--"
	}
	lines := []string{
		"收到 Mode 详情:",
		fmt.Sprintf("  Mode ID: %s", detail.ID),
		fmt.Sprintf("  名称: %s", name),
		fmt.Sprintf("  Bolt 数量: %d", len(detail.Bolts)),
	}
	for _, bolt := range detail.Bolts {
		boltName := strings.TrimSpace(bolt.Name)
		if boltName == "" {
			boltName = "--"
		}
		lines = append(lines, fmt.Sprintf("  Bolt %s: Pset %s，Tool %s，%s", bolt.BoltNumber, bolt.PsetID, bolt.ToolNumber, boltName))
	}
	return strings.Join(lines, "\n")
}

func parseModeDetail(data string) (modeDetail, bool) {
	if len(data) < 9 {
		return modeDetail{}, false
	}
	detail := modeDetail{ID: data[:4]}
	cursor := 4
	nameSize, err := strconv.Atoi(data[cursor : cursor+2])
	cursor += 2
	if err != nil || nameSize < 0 || cursor+nameSize+3 > len(data) {
		return modeDetail{}, false
	}
	detail.Name = data[cursor : cursor+nameSize]
	cursor += nameSize
	boltCount, err := strconv.Atoi(data[cursor : cursor+3])
	cursor += 3
	if err != nil || boltCount < 0 {
		return modeDetail{}, false
	}
	detail.Bolts = make([]modeBolt, 0, boltCount)
	for i := 0; i < boltCount; i++ {
		if cursor+12 > len(data) {
			return modeDetail{}, false
		}
		bolt := modeBolt{
			PsetID:     data[cursor : cursor+3],
			ToolNumber: data[cursor+3 : cursor+6],
			BoltNumber: data[cursor+6 : cursor+10],
		}
		cursor += 10
		boltNameSize, err := strconv.Atoi(data[cursor : cursor+2])
		cursor += 2
		if err != nil || boltNameSize < 0 || cursor+boltNameSize > len(data) {
			return modeDetail{}, false
		}
		bolt.Name = data[cursor : cursor+boltNameSize]
		cursor += boltNameSize
		detail.Bolts = append(detail.Bolts, bolt)
	}
	return detail, true
}

func summarizePsetList(data string) string {
	result := parsePsetList(data)
	if !result.Parsed {
		return fmt.Sprintf("收到 Pset 列表响应，但未能解析。数据长度 %d，Raw=%q", len(data), trimForLog(data))
	}
	ids := make([]string, 0, len(result.Items))
	for _, item := range result.Items {
		ids = append(ids, item.ID)
	}

	idText := "--"
	if len(ids) > 0 {
		idText = strings.Join(ids, ", ")
	}
	lines := []string{
		fmt.Sprintf("收到 Pset 列表: 共 %d 个，IDs: %s", result.Count, idText),
		fmt.Sprintf("  Raw Data: %q，长度=%d，Count字段=%q", trimForLog(data), len(data), result.CountField),
	}
	if result.HasDetails() {
		lines = append(lines, "  明细:")
		for _, item := range result.Items {
			parts := []string{item.ID}
			if item.StageCount != "" {
				parts = append(parts, "步骤数="+item.StageCount)
			}
			if item.ProgramType != "" {
				parts = append(parts, "类型="+item.ProgramType)
			}
			if item.ModifiedAt != "" {
				parts = append(parts, "修改时间="+item.ModifiedAt)
			}
			lines = append(lines, "  "+strings.Join(parts, " | "))
		}
	}
	if result.Extra != "" {
		lines = append(lines, fmt.Sprintf("  未解析额外数据: %q", trimForLog(result.Extra)))
	}
	if len(result.Warnings) > 0 {
		lines = append(lines, "  解析提示: "+strings.Join(result.Warnings, "; "))
	}
	return strings.Join(lines, "\n")
}

type psetListParse struct {
	Parsed     bool
	Count      int
	CountField string
	Items      []psetListItem
	Extra      string
	Warnings   []string
}

func (p psetListParse) HasDetails() bool {
	for _, item := range p.Items {
		if item.StageCount != "" || item.ProgramType != "" || item.ModifiedAt != "" {
			return true
		}
	}
	return false
}

type psetListItem struct {
	ID          string
	StageCount  string
	ProgramType string
	ModifiedAt  string
}

func parsePsetList(data string) psetListParse {
	data = strings.TrimSpace(data)
	for _, countWidth := range []int{3, 2} {
		if result := parsePsetListWithCountWidth(data, countWidth); result.Parsed {
			return result
		}
	}
	return psetListParse{}
}

func parsePsetListWithCountWidth(data string, countWidth int) psetListParse {
	if len(data) < countWidth {
		return psetListParse{}
	}
	count, err := strconv.Atoi(data[:countWidth])
	if err != nil || count < 0 {
		return psetListParse{}
	}
	rest := data[countWidth:]
	if len(rest) < count*3 {
		return psetListParse{}
	}
	items := make([]psetListItem, 0, count)
	for i := 0; i < count; i++ {
		pset := rest[i*3 : i*3+3]
		if _, err := strconv.Atoi(pset); err != nil {
			return psetListParse{}
		}
		items = append(items, psetListItem{ID: pset})
	}
	result := psetListParse{
		Parsed:     true,
		Count:      count,
		CountField: data[:countWidth],
		Items:      items,
	}
	extra := rest[count*3:]
	result.parseRevisionExtras(extra)
	return result
}

func (p *psetListParse) parseRevisionExtras(extra string) {
	if p.Count == 0 {
		p.Extra = strings.TrimSpace(extra)
		return
	}

	stageCounts, rest, ok := consumeFixedFields(extra, p.Count, 2, allDigits)
	if !ok {
		p.Extra = strings.TrimSpace(extra)
		return
	}
	for i, value := range stageCounts {
		p.Items[i].StageCount = value
	}

	programTypes, rest, ok := consumeFixedFields(rest, p.Count, 4, nil)
	if !ok {
		p.Extra = strings.TrimSpace(rest)
		return
	}
	for i, value := range programTypes {
		p.Items[i].ProgramType = strings.TrimSpace(value)
	}

	modifiedAts, rest, ok := consumeFixedFields(rest, p.Count, 19, looksLikeOpenProtocolTimestamp)
	if !ok {
		p.Extra = strings.TrimSpace(rest)
		return
	}
	for i, value := range modifiedAts {
		p.Items[i].ModifiedAt = strings.TrimSpace(value)
	}
	p.Extra = strings.TrimSpace(rest)
}

func consumeFixedFields(data string, count, width int, valid func(string) bool) ([]string, string, bool) {
	if count <= 0 || width <= 0 {
		return nil, data, false
	}
	if len(data) < count*width {
		return nil, data, false
	}
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		value := data[i*width : i*width+width]
		if valid != nil && !valid(value) {
			return nil, data, false
		}
		values = append(values, value)
	}
	return values, data[count*width:], true
}

type psetDetailParse struct {
	ID                string
	Name              string
	Direction         string
	BatchSize         string
	TorqueMin         string
	TorqueMax         string
	TorqueTarget      string
	AngleMin          string
	AngleMax          string
	AngleTarget       string
	TorqueFirstTarget string
	StartFinalAngle   string
	ModifiedAt        string
	Warnings          []string
}

func summarizePsetDetail(data string) string {
	detail := parsePsetDetail(data)
	if detail.ID == "" && detail.Name == "" {
		return fmt.Sprintf("收到 Pset 详情响应，但未能解析。数据长度 %d，Raw=%q", len(data), trimForLog(data))
	}

	lines := []string{
		"收到 Pset 详情:",
		fmt.Sprintf("  Pset ID: %s", emptyText(detail.ID)),
		fmt.Sprintf("  名称: %s", emptyText(detail.Name)),
		fmt.Sprintf("  旋转方向: %s", emptyText(detail.Direction)),
		fmt.Sprintf("  批次大小: %s", emptyText(detail.BatchSize)),
		fmt.Sprintf("  扭矩: 下限 %s / 目标 %s / 上限 %s", emptyText(detail.TorqueMin), emptyText(detail.TorqueTarget), emptyText(detail.TorqueMax)),
		fmt.Sprintf("  角度: 下限 %s / 目标 %s / 上限 %s", emptyText(detail.AngleMin), emptyText(detail.AngleTarget), emptyText(detail.AngleMax)),
	}
	extras := make([]string, 0, 3)
	if detail.TorqueFirstTarget != "" {
		extras = append(extras, "第一目标扭矩 "+detail.TorqueFirstTarget)
	}
	if detail.StartFinalAngle != "" {
		extras = append(extras, "起始最终角度 "+detail.StartFinalAngle)
	}
	if detail.ModifiedAt != "" {
		extras = append(extras, "修改时间 "+detail.ModifiedAt)
	}
	if len(extras) > 0 {
		lines = append(lines, "  补充字段: "+strings.Join(extras, " / "))
	}
	if len(detail.Warnings) > 0 {
		lines = append(lines, "  解析提示: "+strings.Join(detail.Warnings, "; "))
	}
	return strings.Join(lines, "\n")
}

func parsePsetDetail(data string) psetDetailParse {
	var detail psetDetailParse
	cursor := 0
	detail.ID = readPsetDetailField(data, &cursor, "01", 3, &detail.Warnings)
	detail.Name = strings.TrimSpace(readPsetDetailField(data, &cursor, "02", 25, &detail.Warnings))
	detail.Direction = directionText(readPsetDetailField(data, &cursor, "03", 1, &detail.Warnings))
	detail.BatchSize = readPsetDetailField(data, &cursor, "04", 2, &detail.Warnings)
	detail.TorqueMin = torqueText(readPsetDetailField(data, &cursor, "05", 6, &detail.Warnings))
	detail.TorqueMax = torqueText(readPsetDetailField(data, &cursor, "06", 6, &detail.Warnings))
	detail.TorqueTarget = torqueText(readPsetDetailField(data, &cursor, "07", 6, &detail.Warnings))
	detail.AngleMin = angleText(readPsetDetailField(data, &cursor, "08", 5, &detail.Warnings))
	detail.AngleMax = angleText(readPsetDetailField(data, &cursor, "09", 5, &detail.Warnings))
	detail.AngleTarget = angleText(readPsetDetailField(data, &cursor, "10", 5, &detail.Warnings))
	if value, ok := readOptionalPsetDetailField(data, &cursor, "11", 6, &detail.Warnings); ok {
		detail.TorqueFirstTarget = torqueText(value)
	}
	if value, ok := readOptionalPsetDetailField(data, &cursor, "12", 6, &detail.Warnings); ok {
		detail.StartFinalAngle = scaledNumberText(value, 100, "deg")
	}
	if value, ok := readOptionalPsetDetailField(data, &cursor, "13", 19, &detail.Warnings); ok {
		detail.ModifiedAt = value
	}
	if cursor < len(data) {
		extra := strings.TrimSpace(data[cursor:])
		if extra != "" {
			detail.Warnings = append(detail.Warnings, fmt.Sprintf("剩余未解析数据 %d 字节: %q", len(extra), trimForLog(extra)))
		}
	}
	return detail
}

type TighteningResult struct {
	HeaderStation    string
	HeaderSpindle    string
	CellID           string
	ChannelID        string
	ControllerName   string
	VIN              string
	JobID            string
	PsetID           string
	BatchSize        string
	BatchCounter     string
	TighteningStatus string
	TorqueStatus     string
	AngleStatus      string
	TorqueMin        string
	TorqueMax        string
	TorqueTarget     string
	TorqueActual     string
	AngleMin         string
	AngleMax         string
	AngleTarget      string
	AngleActual      string
	TightenedAt      string
	PsetUpdatedAt    string
	BatchStatus      string
	TighteningID     string
	Raw              string
	Warnings         []string
}

func (r TighteningResult) OK() bool {
	return strings.TrimSpace(r.TighteningStatus) == "1"
}

func ParseTighteningResult(msg OpenProtocolMessage) (TighteningResult, bool) {
	if msg.MID != "0061" {
		return TighteningResult{}, false
	}
	result := parseTighteningResultData(msg.Data)
	result.HeaderStation = strings.TrimSpace(msg.Station)
	result.HeaderSpindle = strings.TrimSpace(msg.Spindle)
	result.Raw = msg.Data
	if result.PsetID == "" && result.TorqueActual == "" && result.AngleActual == "" {
		return result, false
	}
	return result, true
}

func ParseMultiSpindleResult(msg OpenProtocolMessage) ([]TighteningResult, bool) {
	if msg.MID != "0101" {
		return nil, false
	}
	results := parseMultiSpindleResultData(msg)
	if len(results) == 0 {
		return nil, false
	}
	return results, true
}

func summarizeMultiSpindleResult(msg OpenProtocolMessage) string {
	results, ok := ParseMultiSpindleResult(msg)
	if !ok {
		return fmt.Sprintf("收到多轴拧紧结果 MID 0101，但未能解析。数据长度 %d，Raw=%q", len(msg.Data), trimForLog(msg.Data))
	}
	lines := []string{
		fmt.Sprintf("收到多轴拧紧结果: %d 个枪位", len(results)),
	}
	for _, result := range results {
		lines = append(lines, fmt.Sprintf("  Spindle %s / Channel %s: %s，Pset %s，扭矩 %s，角度 %s，ID %s",
			emptyText(result.HeaderSpindle),
			emptyText(result.ChannelID),
			emptyText(tighteningStatusText(result.TighteningStatus)),
			emptyText(result.PsetID),
			emptyText(result.TorqueActual),
			emptyText(result.AngleActual),
			emptyText(result.TighteningID),
		))
	}
	return strings.Join(lines, "\n")
}

func parseMultiSpindleResultData(msg OpenProtocolMessage) []TighteningResult {
	data := msg.Data
	cursor := 0
	var warnings []string
	spindleCountText := readTighteningField(data, &cursor, "01", 2, &warnings)
	vin := strings.TrimSpace(readTighteningField(data, &cursor, "02", 25, &warnings))
	jobID := readTighteningField(data, &cursor, "03", 2, &warnings)
	psetID := readTighteningField(data, &cursor, "04", 3, &warnings)
	batchSize := readTighteningField(data, &cursor, "05", 4, &warnings)
	batchCounter := readTighteningField(data, &cursor, "06", 4, &warnings)
	batchStatus := readTighteningField(data, &cursor, "07", 1, &warnings)
	torqueMin := torqueText(readTighteningField(data, &cursor, "08", 6, &warnings))
	torqueMax := torqueText(readTighteningField(data, &cursor, "09", 6, &warnings))
	torqueTarget := torqueText(readTighteningField(data, &cursor, "10", 6, &warnings))
	angleMin := angleText(readTighteningField(data, &cursor, "11", 5, &warnings))
	angleMax := angleText(readTighteningField(data, &cursor, "12", 5, &warnings))
	angleTarget := angleText(readTighteningField(data, &cursor, "13", 5, &warnings))
	psetUpdatedAt := readTighteningField(data, &cursor, "14", 19, &warnings)
	tightenedAt := readTighteningField(data, &cursor, "15", 19, &warnings)
	tighteningID := readTighteningField(data, &cursor, "16", 5, &warnings)
	_ = readTighteningField(data, &cursor, "17", 1, &warnings)
	if cursor+2 > len(data) || data[cursor:cursor+2] != "18" {
		warnings = append(warnings, "字段 18 标记缺失")
		return nil
	}
	cursor += 2
	spindleCount, _ := strconv.Atoi(strings.TrimSpace(spindleCountText))
	results := make([]TighteningResult, 0, spindleCount)
	for i := 0; i < spindleCount && cursor+18 <= len(data); i++ {
		spindle := strings.Trim(data[cursor:cursor+2], " \x00")
		cursor += 2
		channel := strings.Trim(data[cursor:cursor+2], " \x00")
		cursor += 2
		spindleStatus := strings.Trim(data[cursor:cursor+1], " \x00")
		cursor++
		torqueStatus := strings.Trim(data[cursor:cursor+1], " \x00")
		cursor++
		torqueActual := torqueText(strings.Trim(data[cursor:cursor+6], " \x00"))
		cursor += 6
		angleStatus := strings.Trim(data[cursor:cursor+1], " \x00")
		cursor++
		angleActual := angleText(strings.Trim(data[cursor:cursor+5], " \x00"))
		cursor += 5
		result := TighteningResult{
			HeaderStation:    strings.TrimSpace(msg.Station),
			HeaderSpindle:    spindle,
			ChannelID:        channel,
			VIN:              vin,
			JobID:            jobID,
			PsetID:           psetID,
			BatchSize:        batchSize,
			BatchCounter:     batchCounter,
			TighteningStatus: spindleStatus,
			TorqueStatus:     torqueStatus,
			AngleStatus:      angleStatus,
			TorqueMin:        torqueMin,
			TorqueMax:        torqueMax,
			TorqueTarget:     torqueTarget,
			TorqueActual:     torqueActual,
			AngleMin:         angleMin,
			AngleMax:         angleMax,
			AngleTarget:      angleTarget,
			AngleActual:      angleActual,
			TightenedAt:      tightenedAt,
			PsetUpdatedAt:    psetUpdatedAt,
			BatchStatus:      batchStatus,
			TighteningID:     tighteningID + "-" + spindle,
			Raw:              data,
			Warnings:         append([]string(nil), warnings...),
		}
		results = append(results, result)
	}
	if cursor < len(data) {
		extra := strings.TrimSpace(data[cursor:])
		if extra != "" {
			for i := range results {
				results[i].Warnings = append(results[i].Warnings, fmt.Sprintf("剩余未解析数据 %d 字节: %q", len(extra), trimForLog(extra)))
			}
		}
	}
	return results
}

func summarizeTighteningResult(msg OpenProtocolMessage) string {
	result, ok := ParseTighteningResult(msg)
	if !ok {
		return fmt.Sprintf("收到拧紧结果响应，但未能解析。数据长度 %d，Raw=%q", len(msg.Data), trimForLog(msg.Data))
	}

	channel := emptyText(result.ChannelID)
	headerSpindle := strings.TrimSpace(msg.Spindle)
	if headerSpindle != "" {
		channel += " / Header Spindle " + headerSpindle
	}

	lines := []string{
		"收到拧紧结果:",
		fmt.Sprintf("  Channel: %s", channel),
		fmt.Sprintf("  Pset ID: %s", emptyText(result.PsetID)),
		fmt.Sprintf("  VIN: %s", emptyText(result.VIN)),
		fmt.Sprintf("  结果: %s", emptyText(tighteningStatusText(result.TighteningStatus))),
		fmt.Sprintf("  扭矩: 实际 %s / 下限 %s / 目标 %s / 上限 %s / 状态 %s",
			emptyText(result.TorqueActual),
			emptyText(result.TorqueMin),
			emptyText(result.TorqueTarget),
			emptyText(result.TorqueMax),
			emptyText(limitStatusText(result.TorqueStatus)),
		),
		fmt.Sprintf("  角度: 实际 %s / 下限 %s / 目标 %s / 上限 %s / 状态 %s",
			emptyText(result.AngleActual),
			emptyText(result.AngleMin),
			emptyText(result.AngleTarget),
			emptyText(result.AngleMax),
			emptyText(limitStatusText(result.AngleStatus)),
		),
		fmt.Sprintf("  批次: %s/%s，批次状态 %s",
			emptyText(result.BatchCounter),
			emptyText(result.BatchSize),
			emptyText(result.BatchStatus),
		),
		fmt.Sprintf("  时间: %s", emptyText(result.TightenedAt)),
		fmt.Sprintf("  Tightening ID: %s", emptyText(result.TighteningID)),
		fmt.Sprintf("  Raw Data: %q，长度=%d", trimForLog(msg.Data), len(msg.Data)),
	}
	if result.ControllerName != "" || result.CellID != "" || result.JobID != "" {
		lines = append(lines, fmt.Sprintf("  控制器: %s，Cell %s，Job %s", emptyText(result.ControllerName), emptyText(result.CellID), emptyText(result.JobID)))
	}
	if result.PsetUpdatedAt != "" {
		lines = append(lines, "  Pset 修改时间: "+result.PsetUpdatedAt)
	}
	if len(result.Warnings) > 0 {
		lines = append(lines, "  解析提示: "+strings.Join(result.Warnings, "; "))
	}
	return strings.Join(lines, "\n")
}

func parseTighteningResultData(data string) TighteningResult {
	var result TighteningResult
	cursor := 0
	result.CellID = readTighteningField(data, &cursor, "01", 4, &result.Warnings)
	result.ChannelID = readTighteningField(data, &cursor, "02", 2, &result.Warnings)
	result.ControllerName = strings.TrimSpace(readTighteningField(data, &cursor, "03", 25, &result.Warnings))
	result.VIN = strings.TrimSpace(readTighteningField(data, &cursor, "04", 25, &result.Warnings))
	result.JobID = readTighteningField(data, &cursor, "05", 2, &result.Warnings)
	result.PsetID = readTighteningField(data, &cursor, "06", 3, &result.Warnings)
	result.BatchSize = readTighteningField(data, &cursor, "07", 4, &result.Warnings)
	result.BatchCounter = readTighteningField(data, &cursor, "08", 4, &result.Warnings)
	result.TighteningStatus = readTighteningField(data, &cursor, "09", 1, &result.Warnings)
	result.TorqueStatus = readTighteningField(data, &cursor, "10", 1, &result.Warnings)
	result.AngleStatus = readTighteningField(data, &cursor, "11", 1, &result.Warnings)
	result.TorqueMin = torqueText(readTighteningField(data, &cursor, "12", 6, &result.Warnings))
	result.TorqueMax = torqueText(readTighteningField(data, &cursor, "13", 6, &result.Warnings))
	result.TorqueTarget = torqueText(readTighteningField(data, &cursor, "14", 6, &result.Warnings))
	result.TorqueActual = torqueText(readTighteningField(data, &cursor, "15", 6, &result.Warnings))
	result.AngleMin = angleText(readTighteningField(data, &cursor, "16", 5, &result.Warnings))
	result.AngleMax = angleText(readTighteningField(data, &cursor, "17", 5, &result.Warnings))
	result.AngleTarget = angleText(readTighteningField(data, &cursor, "18", 5, &result.Warnings))
	result.AngleActual = angleText(readTighteningField(data, &cursor, "19", 5, &result.Warnings))
	result.TightenedAt = readTighteningField(data, &cursor, "20", 19, &result.Warnings)
	result.PsetUpdatedAt = readTighteningField(data, &cursor, "21", 19, &result.Warnings)
	result.BatchStatus = readTighteningField(data, &cursor, "22", 1, &result.Warnings)
	result.TighteningID = readTighteningField(data, &cursor, "23", 10, &result.Warnings)
	if cursor < len(data) {
		extra := strings.TrimSpace(data[cursor:])
		if extra != "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("剩余未解析数据 %d 字节: %q", len(extra), trimForLog(extra)))
		}
	}
	return result
}

func readTighteningField(data string, cursor *int, tag string, width int, warnings *[]string) string {
	start := *cursor
	valueStart := start + 2
	valueEnd := valueStart + width
	if len(data) < valueEnd {
		*warnings = append(*warnings, fmt.Sprintf("字段 %s 长度不足", tag))
		*cursor = len(data)
		return ""
	}
	if got := data[start:valueStart]; got != tag {
		*warnings = append(*warnings, fmt.Sprintf("字段 %s 标记异常，实际为 %q", tag, got))
	}
	*cursor = valueEnd
	return strings.Trim(data[valueStart:valueEnd], " \x00")
}

func tighteningStatusText(value string) string {
	switch strings.TrimSpace(value) {
	case "1":
		return "OK"
	case "0":
		return "NOK"
	case "":
		return ""
	default:
		return "未知(" + value + ")"
	}
}

func limitStatusText(value string) string {
	switch strings.TrimSpace(value) {
	case "0":
		return "Low"
	case "1":
		return "OK"
	case "2":
		return "High"
	case "":
		return ""
	default:
		return "未知(" + value + ")"
	}
}

func readPsetDetailField(data string, cursor *int, tag string, width int, warnings *[]string) string {
	start := *cursor
	valueStart := start + 2
	valueEnd := valueStart + width
	if len(data) < valueEnd {
		*warnings = append(*warnings, fmt.Sprintf("字段 %s 长度不足", tag))
		*cursor = len(data)
		return ""
	}
	if got := data[start:valueStart]; got != tag {
		*warnings = append(*warnings, fmt.Sprintf("字段 %s 标记异常，实际为 %q", tag, got))
	}
	*cursor = valueEnd
	return strings.Trim(data[valueStart:valueEnd], " \x00")
}

func readOptionalPsetDetailField(data string, cursor *int, tag string, width int, warnings *[]string) (string, bool) {
	if *cursor+2 > len(data) || data[*cursor:*cursor+2] != tag {
		return "", false
	}
	return readPsetDetailField(data, cursor, tag, width, warnings), true
}

func directionText(value string) string {
	switch strings.TrimSpace(value) {
	case "1":
		return "CW"
	case "2":
		return "CCW"
	case "":
		return ""
	default:
		return "未知(" + value + ")"
	}
}

func torqueText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return value
	}
	return fmt.Sprintf("%.2f Nm", float64(n)/100)
}

func angleText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return value
	}
	return fmt.Sprintf("%d deg", n)
}

func scaledNumberText(value string, scale int, unit string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	n, err := strconv.Atoi(value)
	if err != nil || scale <= 0 {
		return value
	}
	return fmt.Sprintf("%.2f %s", float64(n)/float64(scale), unit)
}

func emptyText(value string) string {
	if strings.TrimSpace(value) == "" {
		return "--"
	}
	return value
}

func trimForLog(value string) string {
	value = strings.TrimRight(value, "\x00")
	if len(value) <= 120 {
		return value
	}
	return value[:120] + "..."
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksLikeOpenProtocolTimestamp(value string) bool {
	if len(value) != 19 {
		return false
	}
	for i, r := range value {
		switch i {
		case 4, 7:
			if r != '-' {
				return false
			}
		case 10:
			if r != ':' && r != ' ' {
				return false
			}
		case 13, 16:
			if r != ':' {
				return false
			}
		default:
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func normalizeProbeRequest(req *OpenProtocolProbeRequest) {
	req.Host = strings.TrimSpace(req.Host)
	if req.Port <= 0 {
		req.Port = DefaultPort
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = DefaultTimeoutMs
	}
	req.Data = SanitizeOpenProtocolData(req.Data)
}

func SanitizeOpenProtocolData(data string) string {
	data = strings.TrimSuffix(data, `\0`)
	return strings.TrimRight(data, "\x00")
}

func FrameText(frame []byte) string {
	return VisibleFrame(strings.TrimRight(string(frame), "\x00"))
}

func VisibleFrame(text string) string {
	return text + `\0`
}

func FieldOrUnknown(text string, start, end int) string {
	if len(text) < end {
		return "????"
	}
	return text[start:end]
}

func OpenProtocolErrorText(code string) string {
	switch code {
	case "00":
		return "No error"
	case "01":
		return "Invalid data"
	case "02":
		return "Parameter set ID not present"
	case "03":
		return "Parameter set can not be set"
	case "04":
		return "Parameter set not running"
	case "09":
		return "Subscription already exists"
	case "10":
		return "Last tightening result subscription does not exist"
	case "13":
		return "Parameter set selection subscription already exists"
	case "14":
		return "Parameter set selection subscription does not exist"
	case "20":
		return "Job can not be set"
	case "27":
		return "Tool is inaccessible"
	case "28":
		return "Job abortion is in progress"
	case "29":
		return "Tool does not exist"
	case "30":
		return "Controller is not a sync Master/station controller"
	case "31":
		return "Multi-spindle status subscription already exists"
	case "32":
		return "Multi-spindle status subscription does not exist"
	case "33":
		return "Multi-spindle result subscription already exists"
	case "34":
		return "Multi-spindle result subscription does not exist"
	case "35":
		return "Other master client already connected"
	case "36":
		return "Lock type not supported"
	case "96":
		return "Client already connected"
	case "97":
		return "MID revision unsupported"
	case "99":
		return "Unknown MID"
	default:
		return "未知错误码"
	}
}
