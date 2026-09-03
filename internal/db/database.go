package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	db   *sql.DB
	once sync.Once
	mu   sync.RWMutex
)

type Config struct {
	Path string
}

func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Path: filepath.Join(home, ".fang", "data", "fang.db"),
	}
}

func Open(cfg *Config) (*sql.DB, error) {
	var err error
	once.Do(func() {
		dir := filepath.Dir(cfg.Path)
		if errDir := os.MkdirAll(dir, 0700); errDir != nil {
			err = fmt.Errorf("create db dir: %w", errDir)
			return
		}
		db, err = sql.Open("sqlite", cfg.Path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
		if err != nil {
			err = fmt.Errorf("open db: %w", err)
			return
		}
		if err = migrate(db); err != nil {
			err = fmt.Errorf("migrate: %w", err)
			return
		}
	})
	return db, err
}

func DB() *sql.DB {
	mu.RLock()
	defer mu.RUnlock()
	return db
}

func Close() error {
	mu.Lock()
	defer mu.Unlock()
	if db != nil {
		return db.Close()
	}
	return nil
}

func BeginTx() (*sql.Tx, error) {
	d := DB()
	if d == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return d.Begin()
}

func migrate(d *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			api_key TEXT UNIQUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS targets (
			id TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			domain TEXT,
			name TEXT,
			tags TEXT,
			created_by TEXT REFERENCES users(id),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			target_id TEXT REFERENCES targets(id),
			status TEXT NOT NULL DEFAULT 'pending',
			modules TEXT,
			threads INTEGER DEFAULT 20,
			timeout INTEGER DEFAULT 10,
			proxy TEXT,
			started_at DATETIME,
			finished_at DATETIME,
			duration_ms INTEGER,
			error TEXT,
			triggered_by TEXT,
			schedule_id TEXT REFERENCES schedules(id),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
			target_id TEXT REFERENCES targets(id),
			module_id TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			cwe_id TEXT,
			owasp_category TEXT,
			cvss REAL,
			url TEXT,
			parameter TEXT,
			payload TEXT,
			evidence TEXT,
			description TEXT,
			remediation TEXT,
			request TEXT,
			response TEXT,
			extra TEXT,
			is_false_positive BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS schedules (
			id TEXT PRIMARY KEY,
			target_id TEXT REFERENCES targets(id),
			name TEXT,
			cron_expr TEXT NOT NULL,
			modules TEXT,
			enabled BOOLEAN DEFAULT 1,
			notify_on TEXT DEFAULT 'critical',
			webhook_url TEXT,
			created_by TEXT REFERENCES users(id),
			last_run_at DATETIME,
			next_run_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS notifications (
			id TEXT PRIMARY KEY,
			user_id TEXT REFERENCES users(id),
			scan_id TEXT REFERENCES scans(id),
			type TEXT NOT NULL,
			title TEXT NOT NULL,
			message TEXT,
			read BOOLEAN DEFAULT 0,
			channel TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_module_id ON findings(module_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id)`,
		`CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)`,
		`CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			domain TEXT,
			created_by TEXT REFERENCES users(id),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS organization_members (
			id TEXT PRIMARY KEY,
			org_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
			user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
			role TEXT NOT NULL DEFAULT 'member',
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			user_id TEXT REFERENCES users(id),
			org_id TEXT REFERENCES organizations(id),
			action TEXT NOT NULL,
			resource TEXT,
			details TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`ALTER TABLE targets ADD COLUMN org_id TEXT REFERENCES organizations(id)`,
		`ALTER TABLE users ADD COLUMN team_id TEXT`,
		`ALTER TABLE users ADD COLUMN org_id TEXT REFERENCES organizations(id)`,
		`CREATE INDEX IF NOT EXISTS idx_org_members_org_id ON organization_members(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON organization_members(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_org_id ON audit_log(org_id)`,
	}

	// Best-effort: re-opens hit expected duplicate-column errors from the
	// plain ALTER entries, so each statement proceeds independently.
	for _, m := range migrations {
		_, _ = d.Exec(m)
	}

	if err := ensureColumn(d, "findings", "occurrences", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	if err := ensureColumn(d, "findings", "check_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// Nullable on purpose: legacy rows keep NULL so the unique index below
	// never sees duplicate empty keys and never conflicts on their behalf.
	if err := ensureColumn(d, "findings", "fingerprint", "TEXT"); err != nil {
		return err
	}
	if err := ensureColumn(d, "findings", "first_seen", "DATETIME"); err != nil {
		return err
	}
	if err := ensureColumn(d, "findings", "last_seen", "DATETIME"); err != nil {
		return err
	}
	if err := ensureColumn(d, "findings", "status", "TEXT NOT NULL DEFAULT 'open'"); err != nil {
		return err
	}
	_, err := d.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)")
	if err != nil {
		return fmt.Errorf("index findings.fingerprint: %w", err)
	}
	return nil
}

// ensureColumn is idempotent, unlike the plain ALTER entries above.
func ensureColumn(d *sql.DB, table, column, definition string) error {
	rows, err := d.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("inspect %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return fmt.Errorf("inspect %s: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := d.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}
