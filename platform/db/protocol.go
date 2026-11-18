package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// ProtocolCase is one protocol reverse-engineering engagement. The Python
// toolchain writes findings.json; the normalized rows below are a queryable
// mirror for the UI, while Findings keeps the raw file verbatim.
type ProtocolCase struct {
	ID            int64           `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	InstallRoot   string          `json:"install_root"`
	DeviceIP      string          `json:"device_ip"`
	Authorization string          `json:"authorization"`
	Status        string          `json:"status"`
	Mode          string          `json:"mode"`
	Workdir       string          `json:"workdir"`
	Config        json.RawMessage `json:"config"`
	Findings      json.RawMessage `json:"findings,omitempty"`
	Error         string          `json:"error,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	StartedAt     *time.Time      `json:"started_at,omitempty"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
}

type ProtocolPhase struct {
	CaseID     int64           `json:"case_id"`
	Phase      string          `json:"phase"`
	Gate       string          `json:"gate"`
	Status     string          `json:"status"`
	Detail     string          `json:"detail"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type ProtocolAsset struct {
	ID          int64           `json:"id"`
	CaseID      int64           `json:"case_id"`
	Path        string          `json:"path"`
	Name        string          `json:"name"`
	Ext         string          `json:"ext"`
	Score       int             `json:"score"`
	CommExports int             `json:"comm_exports"`
	Machine     string          `json:"machine"`
	MD5         string          `json:"md5"`
	ConfigIPs   json.RawMessage `json:"config_ips,omitempty"`
	Grade       string          `json:"grade"`
	Evidence    json.RawMessage `json:"evidence,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

type ProtocolStream struct {
	ID       int64           `json:"id"`
	CaseID   int64           `json:"case_id"`
	Pcap     string          `json:"pcap"`
	Stream   int             `json:"stream"`
	Src      string          `json:"src"`
	Dst      string          `json:"dst"`
	Sport    int             `json:"sport"`
	Dport    int             `json:"dport"`
	Protocol string          `json:"protocol"`
	Bytes    int64           `json:"bytes"`
	Frames   int64           `json:"frames"`
	Grade    string          `json:"grade"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

type ProtocolFrame struct {
	ID               int64           `json:"id"`
	CaseID           int64           `json:"case_id"`
	FrameKey         string          `json:"frame_key"`
	Protocol         string          `json:"protocol"`
	Stream           int             `json:"stream"`
	Magic            string          `json:"magic"`
	AltMagic         string          `json:"alt_magic"`
	HeaderSize       int             `json:"header_size"`
	LenOffset        int             `json:"len_offset"`
	LenSize          int             `json:"len_size"`
	Endian           string          `json:"endian"`
	LenBias          int             `json:"len_bias"`
	Frames           int64           `json:"frames"`
	Bytes            int64           `json:"bytes"`
	Carrier          string          `json:"carrier"`
	InnerLayout      string          `json:"inner_layout"`
	Channels         string          `json:"channels"`
	CommandsObserved int             `json:"commands_observed"`
	Grade            string          `json:"grade"`
	Detail           json.RawMessage `json:"detail,omitempty"`
}

type ProtocolFieldMap struct {
	ID          int64           `json:"id"`
	CaseID      int64           `json:"case_id"`
	MapKey      string          `json:"map_key"`
	Direction   string          `json:"direction"`
	Samples     int             `json:"samples"`
	FrameLenMin int             `json:"frame_len_min"`
	FrameLenMax int             `json:"frame_len_max"`
	Grade       string          `json:"grade"`
	Fields      json.RawMessage `json:"fields"`
	Tail        json.RawMessage `json:"tail,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

type ProtocolFunctionCode struct {
	ID       int64           `json:"id"`
	CaseID   int64           `json:"case_id"`
	Layer    string          `json:"layer"`
	Code     int             `json:"code"`
	CodeKey  string          `json:"code_key"`
	Label    string          `json:"label"`
	Grade    string          `json:"grade"`
	Evidence string          `json:"evidence"`
	Source   string          `json:"source"`
	Verified bool            `json:"verified"`
	Semantic bool            `json:"semantic"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

type ProtocolProbe struct {
	ID        int64           `json:"id"`
	CaseID    int64           `json:"case_id"`
	ProbeKey  string          `json:"probe_key,omitempty"`
	Kind      string          `json:"kind"`
	Spec      string          `json:"spec"`
	Host      string          `json:"host"`
	Port      int             `json:"port"`
	Action    string          `json:"action"`
	Request   string          `json:"request"`
	Response  string          `json:"response"`
	Status    string          `json:"status"`
	Grade     string          `json:"grade"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type ProtocolNote struct {
	ID        int64           `json:"id"`
	CaseID    int64           `json:"case_id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type ProtocolReport struct {
	CaseID          int64      `json:"case_id"`
	DocType         string     `json:"doc_type"`
	Title           string     `json:"title"`
	Content         string     `json:"content"`
	Version         int        `json:"version"`
	ApprovedBy      string     `json:"approved_by"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty"`
	ApprovedVersion int        `json:"approved_version"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type ProtocolReportVersion struct {
	ID        int64     `json:"id"`
	CaseID    int64     `json:"case_id"`
	DocType   string    `json:"doc_type"`
	Version   int       `json:"version"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type ProtocolKnowledge struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	Vendor       string          `json:"vendor"`
	Model        string          `json:"model"`
	Protocol     string          `json:"protocol"`
	Ports        string          `json:"ports"`
	Magic        string          `json:"magic"`
	FrameSummary string          `json:"frame_summary"`
	CodeSummary  string          `json:"code_summary"`
	StateSummary string          `json:"state_summary"`
	Fingerprint  json.RawMessage `json:"fingerprint,omitempty"`
	SourceCaseID int64           `json:"source_case_id"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type ProtocolArtifact struct {
	ID        int64     `json:"id"`
	CaseID    int64     `json:"case_id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

type ProtocolSubagentRun struct {
	ID         int64           `json:"id"`
	CaseID     int64           `json:"case_id"`
	Phase      string          `json:"phase"`
	AgentKey   string          `json:"agent_key"`
	SessionID  string          `json:"session_id"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	Artifacts  json.RawMessage `json:"artifacts,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

func (d *DB) CreateProtocolSubagentRun(caseID int64, phase, agentKey, sessionID string) (*ProtocolSubagentRun, error) {
	row := d.QueryRow(`INSERT INTO protocol_subagent_runs(case_id,phase,agent_key,session_id)
VALUES ($1,$2,$3,$4)
RETURNING id,case_id,phase,agent_key,session_id,status,summary,evidence,artifacts,created_at,finished_at`,
		caseID, phase, agentKey, sessionID)
	var r ProtocolSubagentRun
	if err := row.Scan(&r.ID, &r.CaseID, &r.Phase, &r.AgentKey, &r.SessionID, &r.Status, &r.Summary, &r.Evidence, &r.Artifacts, &r.CreatedAt, &r.FinishedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *DB) FinishProtocolSubagentRun(id int64, status, summary string, evidence, artifacts json.RawMessage) error {
	if evidence == nil {
		evidence = json.RawMessage(`{}`)
	}
	if artifacts == nil {
		artifacts = json.RawMessage(`[]`)
	}
	switch status {
	case "pass", "partial", "fail", "error":
	default:
		status = "partial"
	}
	_, err := d.Exec(`UPDATE protocol_subagent_runs
SET status=$2, summary=$3, evidence=$4, artifacts=$5, finished_at=now()
WHERE id=$1`, id, status, summary, string(evidence), string(artifacts))
	return err
}

func (d *DB) GetProtocolSubagentRun(id int64) (*ProtocolSubagentRun, error) {
	row := d.QueryRow(`SELECT id,case_id,phase,agent_key,session_id,status,summary,evidence,artifacts,created_at,finished_at
FROM protocol_subagent_runs WHERE id=$1`, id)
	var r ProtocolSubagentRun
	if err := row.Scan(&r.ID, &r.CaseID, &r.Phase, &r.AgentKey, &r.SessionID, &r.Status, &r.Summary, &r.Evidence, &r.Artifacts, &r.CreatedAt, &r.FinishedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *DB) ListProtocolSubagentRuns(caseID int64, limit int) ([]*ProtocolSubagentRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.Query(`SELECT id,case_id,phase,agent_key,session_id,status,summary,evidence,artifacts,created_at,finished_at
FROM protocol_subagent_runs WHERE case_id=$1 ORDER BY id DESC LIMIT $2`, caseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProtocolSubagentRun
	for rows.Next() {
		var r ProtocolSubagentRun
		if err := rows.Scan(&r.ID, &r.CaseID, &r.Phase, &r.AgentKey, &r.SessionID, &r.Status, &r.Summary, &r.Evidence, &r.Artifacts, &r.CreatedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

type ProtocolEvent struct {
	ID        int64           `json:"id"`
	CaseID    int64           `json:"case_id"`
	Phase     string          `json:"phase"`
	Kind      string          `json:"kind"`
	Message   string          `json:"message"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// ProtocolFindings is the normalized view of one case's findings.json.
type ProtocolFindings struct {
	CaseID  int64                   `json:"case_id"`
	Raw     json.RawMessage         `json:"raw,omitempty"`
	Assets  []*ProtocolAsset        `json:"comm_assets"`
	Streams []*ProtocolStream       `json:"streams"`
	Frames  []*ProtocolFrame        `json:"frame_formats"`
	Fields  []*ProtocolFieldMap     `json:"field_maps"`
	Codes   []*ProtocolFunctionCode `json:"function_codes"`
	Probes  []*ProtocolProbe        `json:"probes"`
	Notes   []*ProtocolNote         `json:"notes"`
}

type ProtocolCaseInput struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	InstallRoot   string          `json:"install_root"`
	DeviceIP      string          `json:"device_ip"`
	Authorization string          `json:"authorization"`
	Mode          string          `json:"mode"`
	Workdir       string          `json:"workdir"`
	Config        json.RawMessage `json:"config"`
}

const protocolCaseColumns = `id,name,description,install_root,device_ip,auth_level,status,mode,workdir,config,findings,error,created_at,updated_at,started_at,finished_at`

func scanProtocolCase(row interface{ Scan(...any) error }) (*ProtocolCase, error) {
	var c ProtocolCase
	var cfg, findings []byte
	err := row.Scan(&c.ID, &c.Name, &c.Description, &c.InstallRoot, &c.DeviceIP, &c.Authorization,
		&c.Status, &c.Mode, &c.Workdir, &cfg, &findings, &c.Error, &c.CreatedAt, &c.UpdatedAt,
		&c.StartedAt, &c.FinishedAt)
	if err != nil {
		return nil, err
	}
	c.Config = cfg
	c.Findings = findings
	if len(c.Config) == 0 {
		c.Config = json.RawMessage(`{}`)
	}
	if len(c.Findings) == 0 {
		c.Findings = json.RawMessage(`{}`)
	}
	return &c, nil
}

func (d *DB) CreateProtocolCase(in ProtocolCaseInput) (*ProtocolCase, error) {
	if strings.TrimSpace(in.Name) == "" {
		in.Name = "未命名协议案例"
	}
	if in.Authorization == "" {
		in.Authorization = "read-only"
	}
	if in.Mode == "" {
		if strings.TrimSpace(in.DeviceIP) != "" {
			in.Mode = "live"
		} else {
			in.Mode = "static"
		}
	}
	if in.Config == nil {
		in.Config = json.RawMessage(`{}`)
	}
	row := d.QueryRow(`INSERT INTO protocol_cases(name,description,install_root,device_ip,auth_level,mode,workdir,config)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+protocolCaseColumns,
		in.Name, in.Description, in.InstallRoot, in.DeviceIP, in.Authorization, in.Mode, in.Workdir, string(in.Config))
	c, err := scanProtocolCase(row)
	if err != nil {
		return nil, err
	}
	// Seed the fixed six-phase state machine so the UI always renders the full
	// pipeline even before the first run.
	for _, p := range []struct{ phase, gate string }{
		{"P1", "A"}, {"P2", "B"}, {"P3", "C"}, {"P4", "D"}, {"P5", "E"}, {"P6", "F"},
	} {
		if _, err := d.Exec(`INSERT INTO protocol_phases(case_id,phase,gate,status) VALUES ($1,$2,$3,'pending')
ON CONFLICT (case_id,phase) DO NOTHING`, c.ID, p.phase, p.gate); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (d *DB) ListProtocolCases(status, q string, limit, offset int) ([]*ProtocolCase, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := []string{"1=1"}
	args := []any{}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	if strings.TrimSpace(q) != "" {
		args = append(args, "%"+strings.TrimSpace(q)+"%")
		where = append(where, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d OR install_root ILIKE $%d OR device_ip ILIKE $%d)", len(args), len(args), len(args), len(args)))
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM protocol_cases WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := d.Query(`SELECT `+protocolCaseColumns+` FROM protocol_cases WHERE `+cond+` ORDER BY created_at DESC, id DESC LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*ProtocolCase
	for rows.Next() {
		c, err := scanProtocolCase(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (d *DB) GetProtocolCase(id int64) (*ProtocolCase, error) {
	c, err := scanProtocolCase(d.QueryRow(`SELECT `+protocolCaseColumns+` FROM protocol_cases WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (d *DB) UpdateProtocolCase(id int64, in ProtocolCaseInput) (*ProtocolCase, error) {
	if in.Config == nil {
		in.Config = json.RawMessage(`{}`)
	}
	row := d.QueryRow(`UPDATE protocol_cases SET
name=CASE WHEN $2<>'' THEN $2 ELSE name END,
description=$3,
install_root=$4,
device_ip=$5,
auth_level=CASE WHEN $6<>'' THEN $6 ELSE auth_level END,
mode=CASE WHEN $7<>'' THEN $7 ELSE mode END,
workdir=CASE WHEN $8<>'' THEN $8 ELSE workdir END,
config=$9,
updated_at=now()
WHERE id=$1 RETURNING `+protocolCaseColumns,
		id, in.Name, in.Description, in.InstallRoot, in.DeviceIP, in.Authorization, in.Mode, in.Workdir, string(in.Config))
	c, err := scanProtocolCase(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (d *DB) UpdateProtocolCaseStatus(id int64, status, mode, errText string) error {
	_, err := d.Exec(`UPDATE protocol_cases SET status=$2, mode=CASE WHEN $3<>'' THEN $3 ELSE mode END,
error=$4, updated_at=now(),
started_at=CASE WHEN $2='running' AND started_at IS NULL THEN now() ELSE started_at END,
finished_at=CASE WHEN $2 IN ('done','failed') THEN now() ELSE finished_at END
WHERE id=$1`, id, status, mode, errText)
	return err
}

// RecoverInterruptedProtocolRuns closes rows left "running" by a previous
// process. Agent turns cannot survive a restart, so the case is paused and the
// operator can inspect the conversation or restart it.
func (d *DB) RecoverInterruptedProtocolRuns() error {
	if _, err := d.Exec(`UPDATE protocol_cases
SET status='paused', error='服务重启，Agent 分析中断', updated_at=now()
WHERE status='running'`); err != nil {
		return err
	}
	if _, err := d.Exec(`UPDATE protocol_phases
SET status='fail', detail=CASE WHEN detail='' THEN '服务重启，阶段中断' ELSE detail END, updated_at=now()
WHERE status='running'`); err != nil {
		return err
	}
	if _, err := d.Exec(`UPDATE protocol_phase_jobs
SET status='cancelled', error='服务重启，阶段任务中断', finished_at=now()
WHERE status='running'`); err != nil {
		return err
	}
	_, err := d.Exec(`UPDATE protocol_subagent_runs
SET status='error', summary='服务重启，子 Agent 中断', finished_at=now()
WHERE status='running'`)
	return err
}

func (d *DB) UpdateProtocolCaseConfig(id int64, cfg json.RawMessage) error {
	if cfg == nil {
		cfg = json.RawMessage(`{}`)
	}
	_, err := d.Exec(`UPDATE protocol_cases SET config=$2, updated_at=now() WHERE id=$1`, id, string(cfg))
	return err
}

func (d *DB) DeleteProtocolCase(id int64) error {
	_, err := d.Exec(`DELETE FROM protocol_cases WHERE id=$1`, id)
	return err
}

func (d *DB) UpsertProtocolPhase(caseID int64, phase, gate, status, detail string, evidence json.RawMessage) error {
	if evidence == nil {
		evidence = json.RawMessage(`{}`)
	}
	_, err := d.Exec(`INSERT INTO protocol_phases(case_id,phase,gate,status,detail,evidence,started_at,finished_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,
        CASE WHEN $4='running' THEN now() ELSE NULL END,
        CASE WHEN $4 IN ('pass','fail','skip') THEN now() ELSE NULL END,
        now())
ON CONFLICT (case_id,phase) DO UPDATE SET
  gate=EXCLUDED.gate,
  status=EXCLUDED.status,
  detail=EXCLUDED.detail,
  evidence=EXCLUDED.evidence,
  started_at=CASE WHEN EXCLUDED.status='running' THEN COALESCE(protocol_phases.started_at, now()) ELSE protocol_phases.started_at END,
  finished_at=CASE WHEN EXCLUDED.status IN ('pass','fail','skip') THEN now() ELSE protocol_phases.finished_at END,
  updated_at=now()`, caseID, phase, gate, status, detail, string(evidence))
	return err
}

func (d *DB) ListProtocolPhases(caseID int64) ([]*ProtocolPhase, error) {
	rows, err := d.Query(`SELECT case_id,phase,gate,status,detail,evidence,started_at,finished_at,updated_at
FROM protocol_phases WHERE case_id=$1 ORDER BY phase`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProtocolPhase
	for rows.Next() {
		var p ProtocolPhase
		var ev []byte
		if err := rows.Scan(&p.CaseID, &p.Phase, &p.Gate, &p.Status, &p.Detail, &ev, &p.StartedAt, &p.FinishedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Evidence = ev
		if len(p.Evidence) == 0 {
			p.Evidence = json.RawMessage(`{}`)
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// ResetProtocolPhases returns every phase to pending at the start of a full
// pipeline run, so an old pass cannot make "all phases passed" true early.
func (d *DB) ResetProtocolPhases(caseID int64) error {
	_, err := d.Exec(`UPDATE protocol_phases
SET status='pending', detail='', evidence='{}', started_at=NULL, finished_at=NULL, updated_at=now()
WHERE case_id=$1`, caseID)
	return err
}

func (d *DB) SetProtocolCaseFindings(caseID int64, raw json.RawMessage) error {
	if raw == nil {
		raw = json.RawMessage(`{}`)
	}
	_, err := d.Exec(`UPDATE protocol_cases SET findings=$2, updated_at=now() WHERE id=$1`, caseID, string(raw))
	return err
}

// ResetProtocolFindings clears the normalized mirror and reports for a fresh
// full pipeline run. Uploaded pcaps and the work directory are preserved.
func (d *DB) ResetProtocolFindings(caseID int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"protocol_assets", "protocol_streams", "protocol_frames", "protocol_field_maps", "protocol_probes", "protocol_notes", "protocol_reports"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE case_id=$1`, caseID); err != nil {
			return err
		}
	}
	// Preserve labels that a human/LLM assigned; only raw P4 codes are rebuilt.
	if _, err := tx.Exec(`DELETE FROM protocol_function_codes WHERE case_id=$1 AND semantic=false`, caseID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE protocol_cases SET findings='{}', updated_at=now() WHERE id=$1`, caseID); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceProtocolFindings mirrors findings.json into the normalized tables inside
// one transaction. The Python file remains the source of truth for the current
// run: rows are upserted by their natural key and only rows that disappeared are
// deleted. Keeping the same row IDs across syncs matters because delivered
// documents reference evidence as [asset|code|frame|field|probe:<id>] — a full
// DELETE+INSERT would renumber every row and invalidate those references.
func (d *DB) ReplaceProtocolFindings(caseID int64, raw json.RawMessage) error {
	if raw == nil || len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("parse findings: %w", err)
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, table := range []string{"protocol_notes"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE case_id=$1`, caseID); err != nil {
			return err
		}
	}
	insertAssets := func(items []map[string]any) error {
		for _, m := range items {
			bytes, _ := json.Marshal(m)
			path := strAny(m["path"])
			if path == "" {
				continue
			}
			_, err := tx.Exec(`INSERT INTO protocol_assets(case_id,path,name,ext,score,comm_exports,machine,md5,config_ips,grade,evidence)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (case_id,path) DO UPDATE SET
name=EXCLUDED.name, ext=EXCLUDED.ext, score=EXCLUDED.score, comm_exports=EXCLUDED.comm_exports,
machine=EXCLUDED.machine, md5=EXCLUDED.md5, config_ips=EXCLUDED.config_ips,
grade=EXCLUDED.grade, evidence=EXCLUDED.evidence`,
				caseID, path, strAny(m["name"]), strAny(m["ext"]), intAny(m["score"]), intAny(m["comm_exports"]),
				strAny(m["machine"]), strAny(m["md5"]), jsonAny(m["config_ips"]), gradeAny(m["grade"], "static"), string(bytes))
			if err != nil {
				return err
			}
		}
		return nil
	}
	insertFrames := func(items []map[string]any) error {
		for _, m := range items {
			bytes, _ := json.Marshal(m)
			key := frameKeyFor(m)
			_, err := tx.Exec(`INSERT INTO protocol_frames(case_id,frame_key,protocol,stream,magic,alt_magic,header_size,len_offset,len_size,endian,len_bias,frames,bytes,carrier,inner_layout,channels,commands_observed,grade,detail)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
ON CONFLICT (case_id,frame_key) DO UPDATE SET protocol=EXCLUDED.protocol,stream=EXCLUDED.stream,magic=EXCLUDED.magic,
alt_magic=EXCLUDED.alt_magic,header_size=EXCLUDED.header_size,len_offset=EXCLUDED.len_offset,len_size=EXCLUDED.len_size,
endian=EXCLUDED.endian,len_bias=EXCLUDED.len_bias,frames=EXCLUDED.frames,bytes=EXCLUDED.bytes,carrier=EXCLUDED.carrier,
inner_layout=EXCLUDED.inner_layout,channels=EXCLUDED.channels,commands_observed=EXCLUDED.commands_observed,grade=EXCLUDED.grade,detail=EXCLUDED.detail`,
				caseID, key, strAny(m["protocol"]), intAny(m["stream"]), strAny(m["magic"]), strAny(m["alt_magic"]),
				intAny(m["header_size"]), intAny(m["len_offset"]), intAny(m["len_size"]), strAny(m["endian"]),
				intAny(m["len_bias"]), int64Any(m["frames"]), int64Any(m["bytes"]), strAny(m["carrier"]),
				strAny(m["inner_layout"]), strAny(m["channels"]), intAny(m["commands_observed"]), gradeAny(m["grade"], "traffic"), string(bytes))
			if err != nil {
				return err
			}
		}
		return nil
	}
	insertFields := func(items []map[string]any) error {
		for _, m := range items {
			bytes, _ := json.Marshal(m)
			key := strAny(m["key"])
			if key == "" {
				key = strAny(m["map_key"])
			}
			min, max := 0, 0
			if arr, ok := m["frame_len"].([]any); ok && len(arr) >= 2 {
				min, max = intFromAny(arr[0]), intFromAny(arr[1])
			}
			if key == "" {
				key = fmt.Sprintf("%s-%d-%d", strAny(m["direction"]), min, max)
			}
			_, err := tx.Exec(`INSERT INTO protocol_field_maps(case_id,map_key,direction,samples,frame_len_min,frame_len_max,grade,fields,tail,payload)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (case_id,map_key) DO UPDATE SET direction=EXCLUDED.direction,samples=EXCLUDED.samples,
frame_len_min=EXCLUDED.frame_len_min,frame_len_max=EXCLUDED.frame_len_max,grade=EXCLUDED.grade,
fields=EXCLUDED.fields,tail=EXCLUDED.tail,payload=EXCLUDED.payload`,
				caseID, key, strAny(m["direction"]), intAny(m["samples"]), min, max, gradeAny(m["grade"], "traffic"),
				jsonAny(m["fields"]), jsonAny(m["tail"]), string(bytes))
			if err != nil {
				return err
			}
		}
		return nil
	}
	insertCodes := func(items []map[string]any) error {
		for _, m := range items {
			bytes, _ := json.Marshal(m)
			rawCode := strAny(m["code"])
			code := intAny(m["code"])
			codeKey := codeKeyFor(rawCode, code)
			label := strAny(m["label"])
			layer := strAny(m["layer"])
			if layer == "" {
				layer = "static-extract"
			}
			grade := gradeAny(m["grade"], "static")
			// "verified" means live-verified. Static/inferred/traffic evidence
			// must never present itself as a confirmed live result.
			verified := boolAny(m["verified"]) && grade == "live"
			_, err := tx.Exec(`INSERT INTO protocol_function_codes(case_id,layer,code,code_key,label,grade,evidence,source,verified,payload)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (case_id,layer,code_key) DO UPDATE SET
code=EXCLUDED.code,label=EXCLUDED.label,grade=EXCLUDED.grade,evidence=EXCLUDED.evidence,
source=EXCLUDED.source,verified=EXCLUDED.verified,payload=EXCLUDED.payload
WHERE protocol_function_codes.semantic = false`,
				caseID, layer, code, codeKey, label, grade, strAny(m["evidence"]), strAny(m["source"]),
				verified, string(bytes))
			if err != nil {
				return err
			}
		}
		return nil
	}
	insertProbes := func(items []map[string]any) error {
		for _, m := range items {
			bytes, _ := json.Marshal(m)
			_, err := tx.Exec(`INSERT INTO protocol_probes(case_id,probe_key,kind,spec,host,port,action,request,response,status,grade,payload)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (case_id,probe_key) WHERE probe_key <> '' DO UPDATE SET
kind=EXCLUDED.kind, spec=EXCLUDED.spec, host=EXCLUDED.host, port=EXCLUDED.port,
action=EXCLUDED.action, request=EXCLUDED.request, response=EXCLUDED.response,
status=EXCLUDED.status, grade=EXCLUDED.grade, payload=EXCLUDED.payload`,
				caseID, probeKeyFor(m), strAny(m["kind"]), strAny(m["spec"]), strAny(m["host"]), intAny(m["port"]), strAny(m["action"]),
				strAny(m["request"]), strAny(m["response"]), strAny(m["status"]), gradeAny(m["grade"], "live"), string(bytes))
			if err != nil {
				return err
			}
		}
		return nil
	}
	insertNotes := func(items []map[string]any) error {
		for _, m := range items {
			bytes, _ := json.Marshal(m)
			_, err := tx.Exec(`INSERT INTO protocol_notes(case_id,kind,payload) VALUES ($1,$2,$3)`, caseID, strAny(m["kind"]), string(bytes))
			if err != nil {
				return err
			}
		}
		return nil
	}
	insertStreams := func(items []map[string]any) error {
		for _, m := range items {
			bytes, _ := json.Marshal(m)
			_, err := tx.Exec(`INSERT INTO protocol_streams(case_id,pcap,stream,src,dst,sport,dport,protocol,bytes,frames,grade,evidence)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (case_id,pcap,stream) DO UPDATE SET src=EXCLUDED.src,dst=EXCLUDED.dst,sport=EXCLUDED.sport,
dport=EXCLUDED.dport,protocol=EXCLUDED.protocol,bytes=EXCLUDED.bytes,frames=EXCLUDED.frames,
grade=EXCLUDED.grade,evidence=EXCLUDED.evidence`,
				caseID, strAny(m["pcap"]), intAny(m["stream"]), strAny(m["src"]), strAny(m["dst"]),
				intAny(m["sport"]), intAny(m["dport"]), strAny(m["protocol"]), int64Any(m["bytes"]),
				int64Any(m["frames"]), gradeAny(m["grade"], "traffic"), string(bytes))
			if err != nil {
				return err
			}
		}
		return nil
	}

	type section struct {
		name  string
		apply func([]map[string]any) error
	}
	parsed := map[string][]map[string]any{}
	for _, s := range []section{
		{"comm_assets", insertAssets},
		{"streams", insertStreams},
		{"frame_formats", insertFrames},
		{"field_maps", insertFields},
		{"function_codes", insertCodes},
		{"probes", insertProbes},
		{"notes", insertNotes},
	} {
		items, err := decodeObjectList(obj[s.name])
		if err != nil {
			return fmt.Errorf("parse %s: %w", s.name, err)
		}
		parsed[s.name] = items
		if err := s.apply(items); err != nil {
			return err
		}
	}
	if err := deleteStaleProtocolFindings(tx, caseID, parsed); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE protocol_cases SET findings=$2, updated_at=now() WHERE id=$1`, caseID, string(raw)); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteStaleProtocolFindings removes rows whose natural key no longer appears in
// the incoming findings. Upserted rows keep their primary keys, so evidence IDs
// in already-written reports stay valid across syncs.
func deleteStaleProtocolFindings(tx *sql.Tx, caseID int64, items map[string][]map[string]any) error {
	assetKeys := make([]string, 0, len(items["comm_assets"]))
	for _, m := range items["comm_assets"] {
		if p := strAny(m["path"]); p != "" {
			assetKeys = append(assetKeys, p)
		}
	}
	streamKeys := make([]string, 0, len(items["streams"]))
	for _, m := range items["streams"] {
		streamKeys = append(streamKeys, fmt.Sprintf("%s#%d", strAny(m["pcap"]), intAny(m["stream"])))
	}
	frameKeys := make([]string, 0, len(items["frame_formats"]))
	for _, m := range items["frame_formats"] {
		frameKeys = append(frameKeys, frameKeyFor(m))
	}
	fieldKeys := make([]string, 0, len(items["field_maps"]))
	for _, m := range items["field_maps"] {
		key := strAny(m["key"])
		if key == "" {
			key = strAny(m["map_key"])
		}
		if key == "" {
			min, max := 0, 0
			if arr, ok := m["frame_len"].([]any); ok && len(arr) >= 2 {
				min, max = intFromAny(arr[0]), intFromAny(arr[1])
			}
			key = fmt.Sprintf("%s-%d-%d", strAny(m["direction"]), min, max)
		}
		fieldKeys = append(fieldKeys, key)
	}
	codeKeys := make([]string, 0, len(items["function_codes"]))
	for _, m := range items["function_codes"] {
		layer := strAny(m["layer"])
		if layer == "" {
			layer = "static-extract"
		}
		codeKeys = append(codeKeys, layer+"#"+codeKeyFor(strAny(m["code"]), intAny(m["code"])))
	}
	probeKeys := make([]string, 0, len(items["probes"]))
	for _, m := range items["probes"] {
		probeKeys = append(probeKeys, probeKeyFor(m))
	}

	deletes := []struct {
		query string
		keys  []string
	}{
		{`DELETE FROM protocol_assets WHERE case_id=$1 AND NOT (path = ANY($2::text[]))`, assetKeys},
		{`DELETE FROM protocol_streams WHERE case_id=$1 AND NOT ((pcap || '#' || stream::text) = ANY($2::text[]))`, streamKeys},
		{`DELETE FROM protocol_frames WHERE case_id=$1 AND NOT (frame_key = ANY($2::text[]))`, frameKeys},
		{`DELETE FROM protocol_field_maps WHERE case_id=$1 AND NOT (map_key = ANY($2::text[]))`, fieldKeys},
		{`DELETE FROM protocol_function_codes WHERE case_id=$1 AND semantic=false AND NOT ((layer || '#' || code_key) = ANY($2::text[]))`, codeKeys},
		{`DELETE FROM protocol_probes WHERE case_id=$1 AND NOT (probe_key = ANY($2::text[]))`, probeKeys},
	}
	for _, d := range deletes {
		if _, err := tx.Exec(d.query, caseID, d.keys); err != nil {
			return err
		}
	}
	return nil
}

// frameKeyFor derives the stable frame identity used by both the DB projection
// and the P5 normalizer. Keeping one helper prevents findings refs from using a
// different key than the gate's evidence index.
func frameKeyFor(m map[string]any) string {
	if key := strAny(m["key"]); key != "" {
		return key
	}
	if key := strAny(m["frame_key"]); key != "" {
		return key
	}
	return fmt.Sprintf("stream-%d-%s-%s-%d-%d-%d-%s",
		intAny(m["stream"]), strAny(m["magic"]), strAny(m["alt_magic"]),
		intAny(m["header_size"]), intAny(m["len_offset"]), intAny(m["len_size"]), strAny(m["endian"]))
}

// ProbeKeyFor exposes the probe identity generator to the P5 normalizer so it
// can write the same stable key into findings for [probe:<key>] references.
func ProbeKeyFor(m map[string]any) string { return probeKeyFor(m) }

// FrameKeyFor exposes the frame identity generator to the P5 normalizer.
func FrameKeyFor(m map[string]any) string { return frameKeyFor(m) }

// probeKeyFor derives a stable probe identity from what was probed (target,
// action, request), not from the outcome, so re-syncing the same findings keeps
// probe row IDs stable for [probe:<id>] references.
func probeKeyFor(m map[string]any) string {
	parts := []string{
		strAny(m["kind"]), strAny(m["spec"]), strAny(m["host"]),
		fmt.Sprint(intAny(m["port"])), strAny(m["action"]), strAny(m["code"]),
		strAny(m["request"]), strAny(m["response"]),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:16])
}

func (d *DB) GetProtocolFindings(caseID int64) (*ProtocolFindings, error) {
	out := &ProtocolFindings{CaseID: caseID}
	var raw []byte
	_ = d.QueryRow(`SELECT findings FROM protocol_cases WHERE id=$1`, caseID).Scan(&raw)
	if len(raw) > 0 {
		out.Raw = raw
	}
	rows, err := d.Query(`SELECT id,case_id,path,name,ext,score,comm_exports,machine,md5,config_ips,grade,evidence,created_at
FROM protocol_assets WHERE case_id=$1 ORDER BY score DESC, path`, caseID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a ProtocolAsset
		if err := rows.Scan(&a.ID, &a.CaseID, &a.Path, &a.Name, &a.Ext, &a.Score, &a.CommExports, &a.Machine, &a.MD5, &a.ConfigIPs, &a.Grade, &a.Evidence, &a.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Assets = append(out.Assets, &a)
	}
	rows.Close()

	rows, err = d.Query(`SELECT id,case_id,pcap,stream,src,dst,sport,dport,protocol,bytes,frames,grade,evidence
FROM protocol_streams WHERE case_id=$1 ORDER BY stream`, caseID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s ProtocolStream
		if err := rows.Scan(&s.ID, &s.CaseID, &s.Pcap, &s.Stream, &s.Src, &s.Dst, &s.Sport, &s.Dport, &s.Protocol, &s.Bytes, &s.Frames, &s.Grade, &s.Evidence); err != nil {
			rows.Close()
			return nil, err
		}
		out.Streams = append(out.Streams, &s)
	}
	rows.Close()

	rows, err = d.Query(`SELECT id,case_id,frame_key,protocol,stream,magic,alt_magic,header_size,len_offset,len_size,endian,len_bias,frames,bytes,carrier,inner_layout,channels,commands_observed,grade,detail
FROM protocol_frames WHERE case_id=$1 ORDER BY stream, frame_key`, caseID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f ProtocolFrame
		if err := rows.Scan(&f.ID, &f.CaseID, &f.FrameKey, &f.Protocol, &f.Stream, &f.Magic, &f.AltMagic, &f.HeaderSize, &f.LenOffset, &f.LenSize, &f.Endian, &f.LenBias, &f.Frames, &f.Bytes, &f.Carrier, &f.InnerLayout, &f.Channels, &f.CommandsObserved, &f.Grade, &f.Detail); err != nil {
			rows.Close()
			return nil, err
		}
		out.Frames = append(out.Frames, &f)
	}
	rows.Close()

	rows, err = d.Query(`SELECT id,case_id,map_key,direction,samples,frame_len_min,frame_len_max,grade,fields,tail,payload
FROM protocol_field_maps WHERE case_id=$1 ORDER BY map_key`, caseID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m ProtocolFieldMap
		if err := rows.Scan(&m.ID, &m.CaseID, &m.MapKey, &m.Direction, &m.Samples, &m.FrameLenMin, &m.FrameLenMax, &m.Grade, &m.Fields, &m.Tail, &m.Payload); err != nil {
			rows.Close()
			return nil, err
		}
		out.Fields = append(out.Fields, &m)
	}
	rows.Close()

	rows, err = d.Query(`SELECT id,case_id,layer,code,code_key,label,grade,evidence,source,verified,semantic,payload
FROM protocol_function_codes WHERE case_id=$1 ORDER BY layer, code, code_key, label`, caseID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c ProtocolFunctionCode
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Layer, &c.Code, &c.CodeKey, &c.Label, &c.Grade, &c.Evidence, &c.Source, &c.Verified, &c.Semantic, &c.Payload); err != nil {
			rows.Close()
			return nil, err
		}
		out.Codes = append(out.Codes, &c)
	}
	rows.Close()

	rows, err = d.Query(`SELECT id,case_id,probe_key,kind,spec,host,port,action,request,response,status,grade,payload,created_at
FROM protocol_probes WHERE case_id=$1 ORDER BY created_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p ProtocolProbe
		if err := rows.Scan(&p.ID, &p.CaseID, &p.ProbeKey, &p.Kind, &p.Spec, &p.Host, &p.Port, &p.Action, &p.Request, &p.Response, &p.Status, &p.Grade, &p.Payload, &p.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Probes = append(out.Probes, &p)
	}
	rows.Close()

	rows, err = d.Query(`SELECT id,case_id,kind,payload,created_at FROM protocol_notes WHERE case_id=$1 ORDER BY created_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n ProtocolNote
		if err := rows.Scan(&n.ID, &n.CaseID, &n.Kind, &n.Payload, &n.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.Notes = append(out.Notes, &n)
	}
	rows.Close()
	return out, nil
}

func (d *DB) UpsertProtocolReport(caseID int64, docType, title, content string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	err = tx.QueryRow(`INSERT INTO protocol_reports(case_id,doc_type,title,content,version,updated_at)
VALUES ($1,$2,$3,$4,1,now())
ON CONFLICT (case_id,doc_type) DO UPDATE SET title=EXCLUDED.title,content=EXCLUDED.content,
version=protocol_reports.version+1,updated_at=now() RETURNING version`, caseID, docType, title, content).Scan(&version)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO protocol_report_versions(case_id,doc_type,version,title,content)
VALUES ($1,$2,$3,$4,$5) ON CONFLICT (case_id,doc_type,version) DO NOTHING`, caseID, docType, version, title, content); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) ListProtocolReportVersions(caseID int64, docType string) ([]*ProtocolReportVersion, error) {
	rows, err := d.Query(`SELECT id,case_id,doc_type,version,title,content,created_at
FROM protocol_report_versions WHERE case_id=$1 AND doc_type=$2 ORDER BY version DESC`, caseID, docType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProtocolReportVersion{}
	for rows.Next() {
		var v ProtocolReportVersion
		if err := rows.Scan(&v.ID, &v.CaseID, &v.DocType, &v.Version, &v.Title, &v.Content, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

func (d *DB) ApproveProtocolReport(caseID int64, docType, approvedBy string) (*ProtocolReport, error) {
	_, err := d.Exec(`UPDATE protocol_reports SET approved_by=$3, approved_at=now(), approved_version=version
WHERE case_id=$1 AND doc_type=$2`, caseID, docType, approvedBy)
	if err != nil {
		return nil, err
	}
	reports, err := d.ListProtocolReports(caseID)
	if err != nil {
		return nil, err
	}
	for _, r := range reports {
		if r.DocType == docType {
			return r, nil
		}
	}
	return nil, ErrProtocolReportNotFound
}

var ErrProtocolReportNotFound = errors.New("报告不存在")

func (d *DB) ListProtocolReports(caseID int64) ([]*ProtocolReport, error) {
	rows, err := d.Query(`SELECT case_id,doc_type,title,content,version,COALESCE(approved_by,''),approved_at,approved_version,updated_at FROM protocol_reports WHERE case_id=$1 ORDER BY doc_type`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProtocolReport
	for rows.Next() {
		var r ProtocolReport
		var approvedAt sql.NullTime
		if err := rows.Scan(&r.CaseID, &r.DocType, &r.Title, &r.Content, &r.Version, &r.ApprovedBy, &approvedAt, &r.ApprovedVersion, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if approvedAt.Valid {
			t := approvedAt.Time
			r.ApprovedAt = &t
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (d *DB) UpsertProtocolArtifact(caseID int64, kind, name, path string, size int64, sha string) error {
	_, err := d.Exec(`INSERT INTO protocol_artifacts(case_id,kind,name,path,size,sha256) VALUES ($1,$2,$3,$4,$5,$6)`,
		caseID, kind, name, path, size, sha)
	return err
}

func (d *DB) ListProtocolArtifacts(caseID int64) ([]*ProtocolArtifact, error) {
	rows, err := d.Query(`SELECT id,case_id,kind,name,path,size,sha256,created_at FROM protocol_artifacts WHERE case_id=$1 ORDER BY created_at DESC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProtocolArtifact
	for rows.Next() {
		var a ProtocolArtifact
		if err := rows.Scan(&a.ID, &a.CaseID, &a.Kind, &a.Name, &a.Path, &a.Size, &a.SHA256, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (d *DB) AppendProtocolEvent(caseID int64, phase, kind, message string, payload json.RawMessage) (*ProtocolEvent, error) {
	if payload == nil {
		payload = json.RawMessage(`{}`)
	}
	if kind == "" {
		kind = "log"
	}
	// Keep the CHECK constraint happy for arbitrary callers.
	switch kind {
	case "log", "stdout", "stderr", "phase", "gate", "status", "artifact", "error":
	default:
		kind = "log"
	}
	row := d.QueryRow(`INSERT INTO protocol_events(case_id,phase,kind,message,payload) VALUES ($1,$2,$3,$4,$5)
RETURNING id,case_id,phase,kind,message,payload,created_at`, caseID, phase, kind, message, string(payload))
	var e ProtocolEvent
	if err := row.Scan(&e.ID, &e.CaseID, &e.Phase, &e.Kind, &e.Message, &e.Payload, &e.CreatedAt); err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) ListProtocolEvents(caseID, afterID int64, limit int) ([]*ProtocolEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := d.Query(`SELECT id,case_id,phase,kind,message,payload,created_at
FROM protocol_events WHERE case_id=$1 AND id>$2 ORDER BY id LIMIT $3`, caseID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProtocolEvent
	for rows.Next() {
		var e ProtocolEvent
		if err := rows.Scan(&e.ID, &e.CaseID, &e.Phase, &e.Kind, &e.Message, &e.Payload, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// UpdateProtocolCodeSemantics updates the human/LLM-assigned label and evidence
// grade of one function code. The original P4 evidence/source is preserved.
func (d *DB) UpdateProtocolCodeSemantics(caseID, codeID int64, label, grade string) (*ProtocolFunctionCode, error) {
	if grade == "" {
		grade = "static"
	}
	row := d.QueryRow(`UPDATE protocol_function_codes SET label=$3, grade=$4, semantic=true,
verified = CASE WHEN $4 = 'live' THEN verified ELSE false END
WHERE case_id=$1 AND id=$2
RETURNING id,case_id,layer,code,code_key,label,grade,evidence,source,verified,semantic,payload`, caseID, codeID, label, grade)
	var c ProtocolFunctionCode
	if err := row.Scan(&c.ID, &c.CaseID, &c.Layer, &c.Code, &c.CodeKey, &c.Label, &c.Grade, &c.Evidence, &c.Source, &c.Verified, &c.Semantic, &c.Payload); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}

// ProtocolCodeView joins a function code with its case name for the cross-case
// findings page.
type ProtocolCodeView struct {
	ProtocolFunctionCode
	CaseName string `json:"case_name"`
}

func (d *DB) ListProtocolFunctionCodesAll(q, grade, layer string, limit int) ([]*ProtocolCodeView, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	where := []string{"1=1"}
	args := []any{}
	if strings.TrimSpace(q) != "" {
		args = append(args, "%"+strings.TrimSpace(q)+"%")
		n := len(args)
		where = append(where, fmt.Sprintf("(c.label ILIKE $%d OR c.evidence ILIKE $%d OR c.layer ILIKE $%d OR p.name ILIKE $%d)", n, n, n, n))
	}
	if g := strings.TrimSpace(grade); g != "" {
		args = append(args, g)
		where = append(where, fmt.Sprintf("c.grade=$%d", len(args)))
	}
	if l := strings.TrimSpace(layer); l != "" {
		args = append(args, l)
		where = append(where, fmt.Sprintf("c.layer=$%d", len(args)))
	}
	args = append(args, limit)
	rows, err := d.Query(`SELECT c.id,c.case_id,c.layer,c.code,c.code_key,c.label,c.grade,c.evidence,c.source,c.verified,c.semantic,c.payload,p.name
FROM protocol_function_codes c JOIN protocol_cases p ON p.id=c.case_id
WHERE `+strings.Join(where, " AND ")+` ORDER BY c.created_at DESC, c.id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProtocolCodeView
	for rows.Next() {
		var v ProtocolCodeView
		if err := rows.Scan(&v.ID, &v.CaseID, &v.Layer, &v.Code, &v.CodeKey, &v.Label, &v.Grade, &v.Evidence, &v.Source, &v.Verified, &v.Semantic, &v.Payload, &v.CaseName); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

type ProtocolStats struct {
	Cases       int            `json:"cases"`
	Running     int            `json:"running"`
	Done        int            `json:"done"`
	Failed      int            `json:"failed"`
	Assets      int            `json:"assets"`
	Frames      int            `json:"frames"`
	FieldMaps   int            `json:"field_maps"`
	Codes       int            `json:"codes"`
	Verified    int            `json:"verified_codes"`
	ByGrade     map[string]int `json:"codes_by_grade"`
	PhaseCounts map[string]int `json:"phase_counts"`
}

func (d *DB) ProtocolStats() (*ProtocolStats, error) {
	s := &ProtocolStats{ByGrade: map[string]int{}, PhaseCounts: map[string]int{}}
	_ = d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE status='running'), count(*) FILTER (WHERE status='done'), count(*) FILTER (WHERE status='failed') FROM protocol_cases`).Scan(&s.Cases, &s.Running, &s.Done, &s.Failed)
	_ = d.QueryRow(`SELECT count(*) FROM protocol_assets`).Scan(&s.Assets)
	_ = d.QueryRow(`SELECT count(*) FROM protocol_frames`).Scan(&s.Frames)
	_ = d.QueryRow(`SELECT count(*) FROM protocol_field_maps`).Scan(&s.FieldMaps)
	_ = d.QueryRow(`SELECT count(*), count(*) FILTER (WHERE verified AND grade='live') FROM protocol_function_codes`).Scan(&s.Codes, &s.Verified)
	if rows, err := d.Query(`SELECT grade, count(*) FROM protocol_function_codes GROUP BY grade`); err == nil {
		for rows.Next() {
			var g string
			var n int
			if rows.Scan(&g, &n) == nil {
				s.ByGrade[g] = n
			}
		}
		rows.Close()
	}
	if rows, err := d.Query(`SELECT status, count(*) FROM protocol_phases GROUP BY status`); err == nil {
		for rows.Next() {
			var st string
			var n int
			if rows.Scan(&st, &n) == nil {
				s.PhaseCounts[st] = n
			}
		}
		rows.Close()
	}
	return s, nil
}

func decodeObjectList(raw json.RawMessage) ([]map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func strAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%g", x)
	case json.Number:
		return x.String()
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		var n int
		_, _ = fmt.Sscan(x, &n)
		return n
	}
	return 0
}

func intAny(v any) int { return intFromAny(v) }

// codeKeyFor builds a stable identity for a function code. P4/P6 use composite
// strings such as "0x58/0x39" for diagnostic sub-codes; keying only by the parsed
// integer collapses the whole family to 0x58. Numeric spellings are canonicalised
// to lowercase hex so "88" and "0x58" identify the same code.
// CodeKeyFor exposes the stable function-code key normalization so report
// evidence references ([code:<code_key>]) validate the same way rows do.
func CodeKeyFor(raw string, code int) string { return codeKeyFor(raw, code) }

func codeKeyFor(raw string, code int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Sprintf("0x%x", code)
	}
	parts := strings.Split(raw, "/")
	for i, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if n, err := strconv.ParseInt(part, 0, 64); err == nil {
			parts[i] = fmt.Sprintf("0x%x", n)
		} else {
			parts[i] = part
		}
	}
	return strings.Join(parts, "/")
}

func int64Any(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case json.Number:
		n, _ := x.Int64()
		return n
	}
	return 0
}

func boolAny(v any) bool {
	b, _ := v.(bool)
	return b
}

func gradeAny(v any, def string) string {
	s := strings.TrimSpace(strAny(v))
	switch s {
	case "traffic", "live", "static", "inferred":
		return s
	}
	return def
}

func jsonAny(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

// ---------- Phase job persistence ----------

type ProtocolPhaseJob struct {
	ID         int64           `json:"id"`
	JobID      string          `json:"job_id"`
	CaseID     int64           `json:"case_id"`
	Phase      string          `json:"phase"`
	AgentKey   string          `json:"agent_key"`
	Status     string          `json:"status"`
	Task       string          `json:"task"`
	Expected   string          `json:"expected"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

func (d *DB) CreateProtocolPhaseJob(caseID int64, jobID, phase, agentKey, task, expected string) (*ProtocolPhaseJob, error) {
	var j ProtocolPhaseJob
	err := d.QueryRow(`INSERT INTO protocol_phase_jobs(job_id,case_id,phase,agent_key,status,task,expected)
VALUES($1,$2,$3,$4,'running',$5,$6)
RETURNING id,job_id,case_id,phase,agent_key,status,task,expected,result,error,started_at,finished_at`,
		jobID, caseID, phase, agentKey, task, expected).Scan(
		&j.ID, &j.JobID, &j.CaseID, &j.Phase, &j.AgentKey, &j.Status, &j.Task, &j.Expected,
		&j.Result, &j.Error, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (d *DB) FinishProtocolPhaseJob(jobID, status string, result json.RawMessage, errText string) error {
	if result == nil {
		result = json.RawMessage(`{}`)
	}
	_, err := d.Exec(`UPDATE protocol_phase_jobs SET status=$2,result=$3,error=$4,finished_at=now()
WHERE job_id=$1`, jobID, status, string(result), errText)
	return err
}

func (d *DB) ListLatestProtocolPhaseJobs(caseID int64, phases []string) ([]*ProtocolPhaseJob, error) {
	q := `SELECT DISTINCT ON (phase) id,job_id,case_id,phase,agent_key,status,task,expected,result,error,started_at,finished_at
FROM protocol_phase_jobs WHERE case_id=$1`
	args := []any{caseID}
	if len(phases) > 0 {
		q += ` AND phase=ANY($2::text[])`
		args = append(args, phases)
	}
	q += ` ORDER BY phase,id DESC`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProtocolPhaseJob{}
	for rows.Next() {
		var j ProtocolPhaseJob
		if err := rows.Scan(&j.ID, &j.JobID, &j.CaseID, &j.Phase, &j.AgentKey, &j.Status, &j.Task, &j.Expected,
			&j.Result, &j.Error, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

// ---------- Run metrics ----------

type ProtocolPhaseMetric struct {
	Phase         string  `json:"phase"`
	Status        string  `json:"status"`
	Runs          int     `json:"runs"`
	AvgDurationMs float64 `json:"avg_duration_ms"`
}

type ProtocolAgentUsage struct {
	Agent        string `json:"agent"`
	Calls        int    `json:"calls"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	CacheRead    int    `json:"cache_read"`
	CacheWrite   int    `json:"cache_write"`
}

func (d *DB) ProtocolPhaseMetrics(caseID int64) ([]*ProtocolPhaseMetric, error) {
	rows, err := d.Query(`SELECT phase,status,count(*),
COALESCE(avg(EXTRACT(EPOCH FROM (finished_at-started_at))),0)*1000
FROM protocol_phase_jobs WHERE case_id=$1 GROUP BY phase,status ORDER BY phase,status`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProtocolPhaseMetric{}
	for rows.Next() {
		var m ProtocolPhaseMetric
		if err := rows.Scan(&m.Phase, &m.Status, &m.Runs, &m.AvgDurationMs); err != nil {
			return nil, err
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

func (d *DB) ProtocolAgentUsage(caseID int64) ([]*ProtocolAgentUsage, error) {
	rows, err := d.Query(`SELECT COALESCE(worker,''),count(*),
COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),
COALESCE(SUM(cache_read),0),COALESCE(SUM(cache_write),0)
FROM llm_usage WHERE session_id LIKE $1 GROUP BY worker ORDER BY count(*) DESC`,
		fmt.Sprintf("proto-%d-%%", caseID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProtocolAgentUsage{}
	for rows.Next() {
		var u ProtocolAgentUsage
		if err := rows.Scan(&u.Agent, &u.Calls, &u.InputTokens, &u.OutputTokens, &u.CacheRead, &u.CacheWrite); err != nil {
			return nil, err
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

// UpsertProtocolKnowledge stores or refreshes one cross-case fingerprint.
func (d *DB) UpsertProtocolKnowledge(k *ProtocolKnowledge) error {
	if k == nil || strings.TrimSpace(k.Name) == "" {
		return nil
	}
	if len(k.Fingerprint) == 0 {
		k.Fingerprint = json.RawMessage(`{}`)
	}
	_, err := d.Exec(`INSERT INTO protocol_knowledge(name,vendor,model,protocol,ports,magic,frame_summary,code_summary,state_summary,fingerprint,source_case_id,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,0),now())
ON CONFLICT (name) DO UPDATE SET vendor=EXCLUDED.vendor,model=EXCLUDED.model,protocol=EXCLUDED.protocol,
ports=EXCLUDED.ports,magic=EXCLUDED.magic,frame_summary=EXCLUDED.frame_summary,
code_summary=EXCLUDED.code_summary,state_summary=EXCLUDED.state_summary,
fingerprint=EXCLUDED.fingerprint,source_case_id=EXCLUDED.source_case_id,updated_at=now()`,
		k.Name, k.Vendor, k.Model, k.Protocol, k.Ports, k.Magic, k.FrameSummary,
		k.CodeSummary, k.StateSummary, string(k.Fingerprint), k.SourceCaseID)
	return err
}

// ListProtocolKnowledge searches by name/vendor/model/protocol/ports/magic or
// fingerprint text. Empty q returns the most recently updated entries.
func (d *DB) ListProtocolKnowledge(q string, limit int) ([]*ProtocolKnowledge, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	args := []any{}
	where := "1=1"
	if strings.TrimSpace(q) != "" {
		args = append(args, "%"+strings.TrimSpace(q)+"%")
		where = `(name ILIKE $1 OR vendor ILIKE $1 OR model ILIKE $1 OR protocol ILIKE $1
OR ports ILIKE $1 OR magic ILIKE $1 OR fingerprint::text ILIKE $1)`
	}
	args = append(args, limit)
	rows, err := d.Query(`SELECT id,name,vendor,model,protocol,ports,magic,frame_summary,code_summary,state_summary,fingerprint,COALESCE(source_case_id,0),created_at,updated_at
FROM protocol_knowledge WHERE `+where+` ORDER BY updated_at DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ProtocolKnowledge{}
	for rows.Next() {
		var k ProtocolKnowledge
		if err := rows.Scan(&k.ID, &k.Name, &k.Vendor, &k.Model, &k.Protocol, &k.Ports, &k.Magic,
			&k.FrameSummary, &k.CodeSummary, &k.StateSummary, &k.Fingerprint, &k.SourceCaseID,
			&k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// V2: destructive-campaign approvals (protocol_approvals). campaign_runner
// refuses destructive campaigns unless the referenced approval is approved.
// ---------------------------------------------------------------------------

type ProtocolApproval struct {
	ID          int64           `json:"id"`
	CaseID      int64           `json:"case_id"`
	Kind        string          `json:"kind"`
	Payload     json.RawMessage `json:"payload"`
	Risk        string          `json:"risk"`
	Status      string          `json:"status"`
	RequestedBy string          `json:"requested_by"`
	DecidedBy   string          `json:"decided_by,omitempty"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	Note        string          `json:"note,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

func scanProtocolApproval(row interface{ Scan(...any) error }) (*ProtocolApproval, error) {
	var a ProtocolApproval
	if err := row.Scan(&a.ID, &a.CaseID, &a.Kind, &a.Payload, &a.Risk, &a.Status,
		&a.RequestedBy, &a.DecidedBy, &a.DecidedAt, &a.Note, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func (d *DB) CreateProtocolApproval(caseID int64, kind string, payload json.RawMessage, risk, requestedBy string) (*ProtocolApproval, error) {
	row := d.QueryRow(`
INSERT INTO protocol_approvals(case_id, kind, payload, risk, status, requested_by)
VALUES ($1, $2, $3, $4, 'pending', $5)
RETURNING id, case_id, kind, payload, risk, status, requested_by, COALESCE(decided_by,''), decided_at, COALESCE(note,''), created_at`,
		caseID, kind, payload, risk, requestedBy)
	return scanProtocolApproval(row)
}

func (d *DB) GetProtocolApproval(id int64) (*ProtocolApproval, error) {
	row := d.QueryRow(`
SELECT id, case_id, kind, payload, risk, status, requested_by, COALESCE(decided_by,''), decided_at, COALESCE(note,''), created_at
FROM protocol_approvals WHERE id = $1`, id)
	a, err := scanProtocolApproval(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (d *DB) ListProtocolApprovals(caseID int64) ([]*ProtocolApproval, error) {
	rows, err := d.Query(`
SELECT id, case_id, kind, payload, risk, status, requested_by, COALESCE(decided_by,''), decided_at, COALESCE(note,''), created_at
FROM protocol_approvals WHERE case_id = $1 ORDER BY id DESC LIMIT 200`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProtocolApproval
	for rows.Next() {
		a, err := scanProtocolApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) DecideProtocolApproval(id int64, status, decidedBy, note string) (*ProtocolApproval, error) {
	row := d.QueryRow(`
UPDATE protocol_approvals
SET status = $2, decided_by = $3, decided_at = now(), note = NULLIF($4, '')
WHERE id = $1 AND status = 'pending'
RETURNING id, case_id, kind, payload, risk, status, requested_by, COALESCE(decided_by,''), decided_at, COALESCE(note,''), created_at`,
		id, status, decidedBy, note)
	a, err := scanProtocolApproval(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// ---------------------------------------------------------------------------
// V2 dashboard aggregation
// ---------------------------------------------------------------------------

// VulnDashboardCase is one row of the per-case vulnerability posture table.
type VulnDashboardCase struct {
	CaseID      int64  `json:"case_id"`
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Status      string `json:"status"`
	VulnEnabled bool   `json:"vuln_enabled"`
	P7          string `json:"p7"`
	P8          string `json:"p8"`
	P9          string `json:"p9"`
	Confirmed   int    `json:"confirmed"`
	Hypotheses  int    `json:"hypotheses"`
	Exploits    int    `json:"exploits"`
}

// VulnDashboardApproval is a recent approval queue entry.
type VulnDashboardApproval struct {
	ID          int64      `json:"id"`
	CaseID      int64      `json:"case_id"`
	Kind        string     `json:"kind"`
	Risk        string     `json:"risk"`
	Status      string     `json:"status"`
	Hypothesis  string     `json:"hypothesis"`
	RequestedBy string     `json:"requested_by"`
	CreatedAt   time.Time  `json:"created_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

// VulnDashboardEvent is a recent pipeline event.
type VulnDashboardEvent struct {
	ID        int64     `json:"id"`
	CaseID    int64     `json:"case_id"`
	Phase     string    `json:"phase"`
	Kind      string    `json:"kind"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// VulnDashboard aggregates the cross-case vulnerability posture for the
// dashboard page: counts from findings JSONB, the approval queue, the
// knowledge base and the event feed.
type VulnDashboard struct {
	Cases struct {
		Total       int `json:"total"`
		Running     int `json:"running"`
		Done        int `json:"done"`
		VulnEnabled int `json:"vuln_enabled"`
	} `json:"cases"`
	Hypotheses struct {
		Total        int            `json:"total"`
		ByState      map[string]int `json:"by_state"`
		ByVclass     map[string]int `json:"by_vclass"`
		ConfirmedRsk map[string]int `json:"confirmed_by_risk"`
	} `json:"hypotheses"`
	Exploits struct {
		Total   int            `json:"total"`
		ByTier  map[string]int `json:"by_tier"`
	} `json:"exploits"`
	Campaigns struct {
		Total  int            `json:"total"`
		ByMode map[string]int `json:"by_mode"`
	} `json:"campaigns"`
	Approvals struct {
		Pending int                     `json:"pending"`
		Recent  []*VulnDashboardApproval `json:"recent"`
	} `json:"approvals"`
	Knowledge struct {
		Rows     int `json:"rows"`
		CVEs     int `json:"cves"`
		Covered  int `json:"vclass_covered"`
	} `json:"knowledge"`
	Events   []*VulnDashboardEvent  `json:"events"`
	CaseRows []*VulnDashboardCase   `json:"case_rows"`
}

func (d *DB) VulnDashboard() (*VulnDashboard, error) {
	out := &VulnDashboard{}
	out.Hypotheses.ByState = map[string]int{}
	out.Hypotheses.ByVclass = map[string]int{}
	out.Hypotheses.ConfirmedRsk = map[string]int{}
	out.Exploits.ByTier = map[string]int{}
	out.Campaigns.ByMode = map[string]int{}

	_ = d.QueryRow(`SELECT count(*),
		count(*) FILTER (WHERE status='running'),
		count(*) FILTER (WHERE status='done'),
		count(*) FILTER (WHERE config->'vuln_enabled' = 'true'::jsonb)
		FROM protocol_cases`).
		Scan(&out.Cases.Total, &out.Cases.Running, &out.Cases.Done, &out.Cases.VulnEnabled)

	// Hypotheses / exploits / campaigns live inside each case's findings JSONB.
	// Three separate passes: a lateral join between the three arrays would
	// multiply rows (hyps × exploits × campaigns) and skew every count.
	// jsonb_array_of guards against JSON null literals and non-array garbage
	// (P7 writes "vuln_hypotheses": null until the section is populated) —
	// COALESCE alone does not, and one bad row aborts the whole aggregation.
	jsonbArray := func(col string) string {
		return fmt.Sprintf(`CASE WHEN jsonb_typeof(%s)='array' THEN %s ELSE '[]'::jsonb END`, col, col)
	}
	if rows, err := d.Query(fmt.Sprintf(`SELECT h->>'state', h->>'vclass', h->>'risk'
	FROM protocol_cases pc, jsonb_array_elements(%s) h`, jsonbArray("pc.findings->'vuln_hypotheses'"))); err == nil {
		for rows.Next() {
			var state, vclass, risk sql.NullString
			if rows.Scan(&state, &vclass, &risk) != nil {
				continue
			}
			out.Hypotheses.Total++
			out.Hypotheses.ByState[state.String]++
			if vclass.Valid && vclass.String != "" {
				out.Hypotheses.ByVclass[vclass.String]++
			}
			if state.String == "confirmed" && risk.Valid {
				out.Hypotheses.ConfirmedRsk[risk.String]++
			}
		}
		rows.Close()
	}
	if rows, err := d.Query(fmt.Sprintf(`SELECT e->>'tier'
	FROM protocol_cases pc, jsonb_array_elements(%s) e`, jsonbArray("pc.findings->'exploit_assets'"))); err == nil {
		for rows.Next() {
			var tier sql.NullString
			if rows.Scan(&tier) == nil {
				out.Exploits.Total++
				out.Exploits.ByTier[tier.String]++
			}
		}
		rows.Close()
	}
	if rows, err := d.Query(fmt.Sprintf(`SELECT c->>'mode'
	FROM protocol_cases pc, jsonb_array_elements(%s) c`, jsonbArray("pc.findings->'campaigns'"))); err == nil {
		for rows.Next() {
			var mode sql.NullString
			if rows.Scan(&mode) == nil {
				out.Campaigns.Total++
				out.Campaigns.ByMode[mode.String]++
			}
		}
		rows.Close()
	}

	_ = d.QueryRow(`SELECT count(*) FILTER (WHERE status='pending') FROM protocol_approvals`).Scan(&out.Approvals.Pending)

	if rows, err := d.Query(`SELECT a.id, a.case_id, a.kind, a.risk, a.status,
		COALESCE(a.payload->>'hypothesis',''), COALESCE(a.requested_by,''), a.created_at, a.decided_at
	FROM protocol_approvals a ORDER BY a.id DESC LIMIT 6`); err == nil {
		for rows.Next() {
			var it VulnDashboardApproval
			if rows.Scan(&it.ID, &it.CaseID, &it.Kind, &it.Risk, &it.Status,
				&it.Hypothesis, &it.RequestedBy, &it.CreatedAt, &it.DecidedAt) == nil {
				out.Approvals.Recent = append(out.Approvals.Recent, &it)
			}
		}
		rows.Close()
	}

	_ = d.QueryRow(`SELECT count(*), count(DISTINCT cve_id), count(vclass) FROM vuln_knowledge`).
		Scan(&out.Knowledge.Rows, &out.Knowledge.CVEs, &out.Knowledge.Covered)

	if rows, err := d.Query(`SELECT e.id, e.case_id, COALESCE(e.phase,''), e.kind, e.message, e.created_at
	FROM protocol_events e
	WHERE e.kind IN ('phase','gate','status','error','artifact')
	ORDER BY e.id DESC LIMIT 10`); err == nil {
		for rows.Next() {
			var it VulnDashboardEvent
			if rows.Scan(&it.ID, &it.CaseID, &it.Phase, &it.Kind, &it.Message, &it.CreatedAt) == nil {
				out.Events = append(out.Events, &it)
			}
		}
		rows.Close()
	}

	// Per-case posture: P7-P9 statuses plus findings counts. The jsonb_typeof
	// guards matter here too — jsonb_array_length(json 'null') aborts the query.
	if rows, err := d.Query(`SELECT pc.id, pc.name, pc.mode, pc.status,
		COALESCE(pc.config->'vuln_enabled' = 'true'::jsonb, false),
		COALESCE(p7.status,'not_started'), COALESCE(p8.status,'not_started'), COALESCE(p9.status,'not_started'),
		(SELECT count(*) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(pc.findings->'vuln_hypotheses')='array' THEN pc.findings->'vuln_hypotheses' ELSE '[]'::jsonb END) h WHERE h->>'state'='confirmed'),
		CASE WHEN jsonb_typeof(pc.findings->'vuln_hypotheses')='array' THEN jsonb_array_length(pc.findings->'vuln_hypotheses') ELSE 0 END,
		CASE WHEN jsonb_typeof(pc.findings->'exploit_assets')='array' THEN jsonb_array_length(pc.findings->'exploit_assets') ELSE 0 END
	FROM protocol_cases pc
	LEFT JOIN protocol_phases p7 ON p7.case_id=pc.id AND p7.phase='P7'
	LEFT JOIN protocol_phases p8 ON p8.case_id=pc.id AND p8.phase='P8'
	LEFT JOIN protocol_phases p9 ON p9.case_id=pc.id AND p9.phase='P9'
	ORDER BY pc.id DESC`); err == nil {
		for rows.Next() {
			var it VulnDashboardCase
			if err := rows.Scan(&it.CaseID, &it.Name, &it.Mode, &it.Status, &it.VulnEnabled,
				&it.P7, &it.P8, &it.P9, &it.Confirmed, &it.Hypotheses, &it.Exploits); err != nil {
				log.Printf("[dashboard] case posture scan: %v", err)
				continue
			}
			out.CaseRows = append(out.CaseRows, &it)
		}
		if err := rows.Err(); err != nil {
			log.Printf("[dashboard] case posture query: %v", err)
		}
		rows.Close()
	}
	return out, nil
}
