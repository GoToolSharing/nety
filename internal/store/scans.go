package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

const scanCols = `id, mission_id, network_id, kind, status, options, phase, progress,
	stats, error, created_by, created_at, started_at, paused_at, finished_at`

func scanScan(sc interface{ Scan(...any) error }) (model.Scan, error) {
	var (
		s                         model.Scan
		options, stats            string
		created                   int64
		started, paused, finished sql.NullInt64
	)
	err := sc.Scan(&s.ID, &s.MissionID, &s.NetworkID, &s.Kind, &s.Status, &options,
		&s.Phase, &s.Progress, &stats, &s.Error, &s.CreatedBy, &created,
		&started, &paused, &finished)
	if err != nil {
		return model.Scan{}, err
	}
	jsonDec(options, &s.Options)
	jsonDec(stats, &s.Stats)
	s.CreatedAt = toTime(created)
	s.StartedAt, s.PausedAt, s.FinishedAt = toTimePtr(started), toTimePtr(paused), toTimePtr(finished)
	return s, nil
}

// CreateScan inserts a scan in the queued state.
func (s *Store) CreateScan(ctx context.Context, sc model.Scan) (model.Scan, error) {
	if sc.Status == "" {
		sc.Status = model.ScanQueued
	}
	sc.CreatedAt = time.Now().UTC()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO scans (mission_id, network_id, kind, status, options, phase,
			                   progress, stats, error, created_by, created_at)
			VALUES (?, ?, ?, ?, ?, '', 0, '{}', '', ?, ?)`,
			sc.MissionID, sc.NetworkID, string(sc.Kind), string(sc.Status),
			jsonEnc(sc.Options), sc.CreatedBy, ms(sc.CreatedAt))
		if err != nil {
			return err
		}
		sc.ID, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: create scan: %w", err)
	}
	return sc, nil
}

// Scan loads a scan with its per-phase progress filled in.
func (s *Store) Scan(ctx context.Context, id int64) (model.Scan, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scans WHERE id = ?`, id)
	sc, err := scanScan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: scan: %w", err)
	}
	if sc.Phases, err = s.PhaseProgress(ctx, id); err != nil {
		return model.Scan{}, err
	}
	sc.Resumable = resumable(sc)
	return sc, nil
}

func resumable(sc model.Scan) bool {
	switch sc.Status {
	case model.ScanPaused, model.ScanFailed, model.ScanCancelled, model.ScanQueued:
	case model.ScanCompleted:
		// A scan normally stays finished. The exception is one that finished
		// with an unfinished plan: a process killed while the phases were
		// being written leaves a scan that ran whatever had made it to disk
		// and then reported success. Every kind of scan plans either host
		// discovery or segmentation, so a completed scan with neither did not
		// do what it was asked, and planning it again fills in the gap.
		return !hasPhase(sc, model.PhaseDiscovery) && !hasPhase(sc, model.PhaseSegment)
	default:
		return false
	}
	for _, p := range sc.Phases {
		if p.Total > p.Done+p.Failed {
			return true
		}
	}
	return sc.Status == model.ScanQueued
}

func hasPhase(sc model.Scan, phase model.WorkPhase) bool {
	for _, p := range sc.Phases {
		if p.Phase == phase {
			return true
		}
	}
	return false
}

// ListScans returns the scans of a mission, newest first.
func (s *Store) ListScans(ctx context.Context, missionID int64, limit int) ([]model.Scan, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.r.QueryContext(ctx,
		`SELECT `+scanCols+` FROM scans WHERE mission_id = ? ORDER BY id DESC LIMIT ?`,
		missionID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list scans: %w", err)
	}
	defer rows.Close()
	var out []model.Scan
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list scans: %w", err)
		}
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Phases, err = s.PhaseProgress(ctx, out[i].ID); err != nil {
			return nil, err
		}
		out[i].Resumable = resumable(out[i])
	}
	return out, nil
}

// ScansByStatus lists scans in one of the given states across all missions.
func (s *Store) ScansByStatus(ctx context.Context, statuses ...model.ScanStatus) ([]model.Scan, error) {
	if len(statuses) == 0 {
		return nil, nil
	}
	q := `SELECT ` + scanCols + ` FROM scans WHERE status IN (?` +
		repeatComma(len(statuses)-1) + `) ORDER BY id`
	args := make([]any, len(statuses))
	for i, st := range statuses {
		args[i] = string(st)
	}
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: scans by status: %w", err)
	}
	defer rows.Close()
	var out []model.Scan
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func repeatComma(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, n*2)
	for range n {
		b = append(b, ',', '?')
	}
	return string(b)
}

// SetScanStatus moves a scan to a new state, stamping the matching timestamp.
func (s *Store) SetScanStatus(ctx context.Context, id int64, status model.ScanStatus, scanErr string) error {
	now := time.Now().UnixMilli()
	return s.tx(ctx, func(tx *sql.Tx) error {
		var q string
		args := []any{string(status), scanErr}
		switch status {
		case model.ScanRunning:
			q = `UPDATE scans SET status = ?, error = ?, started_at = COALESCE(started_at, ?),
			     paused_at = NULL, finished_at = NULL WHERE id = ?`
			args = append(args, now, id)
		case model.ScanPaused:
			q = `UPDATE scans SET status = ?, error = ?, paused_at = ? WHERE id = ?`
			args = append(args, now, id)
		case model.ScanCompleted, model.ScanFailed, model.ScanCancelled:
			q = `UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ?`
			args = append(args, now, id)
		default:
			q = `UPDATE scans SET status = ?, error = ? WHERE id = ?`
			args = append(args, id)
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("store: set scan status: %w", err)
		}
		return affected(res)
	})
}

// UpdateScanProgress stores the live phase/progress/stats triple.
func (s *Store) UpdateScanProgress(ctx context.Context, id int64, phase string, progress float64, stats model.ScanStats) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE scans SET phase = ?, progress = ?, stats = ? WHERE id = ?`,
			phase, progress, jsonEnc(stats), id)
		return err
	})
}

// DeleteScan removes a scan and its work units and logs.
func (s *Store) DeleteScan(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("store: delete scan: %w", err)
		}
		return affected(res)
	})
}

// ---------------------------------------------------------------------------
// Work units - the backbone of pause / resume / crash recovery
// ---------------------------------------------------------------------------

// AddWork appends work units for a phase. seq numbering continues from the
// highest existing seq of that (scan, phase), and the unique index makes the
// call idempotent, so re-generating units after a resume is harmless.
func (s *Store) AddWork(ctx context.Context, scanID int64, phase model.WorkPhase, payloads []json.RawMessage) (int, error) {
	if len(payloads) == 0 {
		return 0, nil
	}
	var inserted int
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var maxSeq sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT MAX(seq) FROM scan_work WHERE scan_id = ? AND phase = ?`,
			scanID, string(phase)).Scan(&maxSeq); err != nil {
			return err
		}
		next := maxSeq.Int64 + 1
		stmt, err := tx.PrepareContext(ctx, `
			INSERT OR IGNORE INTO scan_work (scan_id, phase, seq, payload, status)
			VALUES (?, ?, ?, ?, 'pending')`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for i, p := range payloads {
			res, err := stmt.ExecContext(ctx, scanID, string(phase), next+int64(i), string(p))
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				inserted++
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: add work: %w", err)
	}
	return inserted, nil
}

// ClaimWork atomically leases up to n pending units of a scan, optionally
// restricted to one phase, and marks them running.
func (s *Store) ClaimWork(ctx context.Context, scanID int64, phase model.WorkPhase, n int) ([]model.WorkUnit, error) {
	if n <= 0 {
		n = 1
	}
	var out []model.WorkUnit
	err := s.tx(ctx, func(tx *sql.Tx) error {
		q := `SELECT id, scan_id, phase, seq, payload, status, attempts, error
		      FROM scan_work WHERE scan_id = ? AND status = 'pending'`
		args := []any{scanID}
		if phase != "" {
			q += ` AND phase = ?`
			args = append(args, string(phase))
		}
		q += ` ORDER BY seq LIMIT ?`
		args = append(args, n)

		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		var units []model.WorkUnit
		for rows.Next() {
			var (
				u   model.WorkUnit
				pay string
			)
			if err := rows.Scan(&u.ID, &u.ScanID, &u.Phase, &u.Seq, &pay,
				&u.Status, &u.Attempts, &u.Error); err != nil {
				rows.Close()
				return err
			}
			u.Payload = json.RawMessage(pay)
			units = append(units, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(units) == 0 {
			return nil
		}
		now := time.Now().UnixMilli()
		stmt, err := tx.PrepareContext(ctx,
			`UPDATE scan_work SET status = 'running', attempts = attempts + 1, leased_at = ?
			 WHERE id = ? AND status = 'pending'`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for i := range units {
			res, err := stmt.ExecContext(ctx, now, units[i].ID)
			if err != nil {
				return err
			}
			if k, _ := res.RowsAffected(); k == 0 {
				continue // raced with another claimer
			}
			units[i].Status = model.WorkRunning
			units[i].Attempts++
			t := time.UnixMilli(now).UTC()
			units[i].LeasedAt = &t
			out = append(out, units[i])
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: claim work: %w", err)
	}
	return out, nil
}

// CompleteWork marks a unit done.
func (s *Store) CompleteWork(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE scan_work SET status = 'done', error = '', done_at = ? WHERE id = ?`,
			time.Now().UnixMilli(), id)
		return err
	})
}

// FailWork marks a unit failed (it will not be retried automatically) or, when
// requeue is true, puts it back in the pending queue for another attempt.
func (s *Store) FailWork(ctx context.Context, id int64, cause string, requeue bool) error {
	status := "failed"
	if requeue {
		status = "pending"
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE scan_work SET status = ?, error = ?, done_at = ? WHERE id = ?`,
			status, truncate(cause, 2000), time.Now().UnixMilli(), id)
		return err
	})
}

// ReleaseRunningWork puts every leased unit of a scan back in the pending
// queue. Called when a scan is paused, and at startup for scans that were
// running when the process died - nothing is lost, nothing is redone twice.
//
// The attempt counter is rolled back too: being interrupted is not a failed
// attempt, and counting it as one would burn the unit's retry budget after a
// few pauses, failing it permanently on the first transient error.
func (s *Store) ReleaseRunningWork(ctx context.Context, scanID int64) (int64, error) {
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE scan_work
			 SET status = 'pending', leased_at = NULL,
			     attempts = CASE WHEN attempts > 0 THEN attempts - 1 ELSE 0 END
			 WHERE scan_id = ? AND status = 'running'`, scanID)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: release work: %w", err)
	}
	return n, nil
}

// RetryFailedWork requeues the failed units of a scan.
func (s *Store) RetryFailedWork(ctx context.Context, scanID int64) (int64, error) {
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE scan_work SET status = 'pending', error = '', leased_at = NULL
			 WHERE scan_id = ? AND status = 'failed'`, scanID)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: retry work: %w", err)
	}
	return n, nil
}

// PendingWorkCount reports how many units of a scan are still to be executed.
func (s *Store) PendingWorkCount(ctx context.Context, scanID int64) (int64, error) {
	var n int64
	err := s.r.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scan_work WHERE scan_id = ? AND status IN ('pending','running')`,
		scanID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: pending work: %w", err)
	}
	return n, nil
}

// PhaseProgress aggregates the work units of a scan per phase, in canonical
// phase order. Only phases that have units are returned.
func (s *Store) PhaseProgress(ctx context.Context, scanID int64) ([]model.PhaseProgress, error) {
	rows, err := s.r.QueryContext(ctx, `
		SELECT phase,
		       COUNT(*),
		       SUM(CASE WHEN status = 'done'    THEN 1 ELSE 0 END),
		       SUM(CASE WHEN status = 'failed'  THEN 1 ELSE 0 END),
		       SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END)
		FROM scan_work WHERE scan_id = ? GROUP BY phase`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: phase progress: %w", err)
	}
	defer rows.Close()

	byPhase := map[model.WorkPhase]model.PhaseProgress{}
	for rows.Next() {
		var (
			p                           model.PhaseProgress
			phase                       string
			total, done, failed, active sql.NullInt64
		)
		if err := rows.Scan(&phase, &total, &done, &failed, &active); err != nil {
			return nil, err
		}
		p.Phase = model.WorkPhase(phase)
		p.Total, p.Done, p.Failed, p.Active = total.Int64, done.Int64, failed.Int64, active.Int64
		p.Started = p.Done+p.Failed+p.Active > 0
		byPhase[p.Phase] = p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]model.PhaseProgress, 0, len(byPhase))
	for _, ph := range model.AllPhases {
		if p, ok := byPhase[ph]; ok {
			out = append(out, p)
			delete(byPhase, ph)
		}
	}
	for _, p := range byPhase { // unknown phases, keep them visible
		out = append(out, p)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Scan logs
// ---------------------------------------------------------------------------

// AppendScanLog stores one log line of a scan (also streamed to the UI live).
func (s *Store) AppendScanLog(ctx context.Context, scanID int64, level, message string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO scan_logs (scan_id, ts, level, message) VALUES (?, ?, ?, ?)`,
			scanID, time.Now().UnixMilli(), level, truncate(message, 4000))
		return err
	})
}

// ScanLog is one stored log line.
type ScanLog struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

// ScanLogs returns log lines of a scan with id greater than afterID.
func (s *Store) ScanLogs(ctx context.Context, scanID, afterID int64, limit int) ([]ScanLog, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.r.QueryContext(ctx,
		`SELECT id, ts, level, message FROM scan_logs
		 WHERE scan_id = ? AND id > ? ORDER BY id LIMIT ?`, scanID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: scan logs: %w", err)
	}
	defer rows.Close()
	var out []ScanLog
	for rows.Next() {
		var (
			l  ScanLog
			ts int64
		)
		if err := rows.Scan(&l.ID, &ts, &l.Level, &l.Message); err != nil {
			return nil, err
		}
		l.Time = toTime(ts)
		out = append(out, l)
	}
	return out, rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
