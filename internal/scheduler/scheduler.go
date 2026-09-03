package scheduler

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/engine"
	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	cron    *cron.Cron
	entries map[string]cron.EntryID
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	running bool

	rootCtx  context.Context // parent for s.ctx; set via SetRootContext before Start
	activeMu sync.Mutex
	active   map[string]bool // per-job overlap guard: scheduleID -> executing
	wg       sync.WaitGroup  // tracks in-flight scheduled scans for graceful drain
}

func New() *Scheduler {
	return &Scheduler{
		entries: make(map[string]cron.EntryID),
		active:  make(map[string]bool),
	}
}

// SetRootContext pins the parent context for all job execution. Every scan
// derives its run context from it, so cancelling the root (e.g. on SIGINT in
// serve mode) aborts in-flight scans. Must be called before Start.
func (s *Scheduler) SetRootContext(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rootCtx = ctx
}

func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	base := s.rootCtx
	if base == nil {
		base = context.Background()
	}
	s.ctx, s.cancel = context.WithCancel(base)
	s.cron = cron.New(cron.WithSeconds())

	schedules, err := db.ListSchedules()
	if err != nil {
		return fmt.Errorf("list schedules: %w", err)
	}

	for _, sc := range schedules {
		if err := s.addJob(sc.ID, sc.CronExpr); err != nil {
			log.Printf("scheduler: failed to add job %s: %v", sc.ID, err)
		}
	}

	s.cron.Start()
	s.running = true
	return nil
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.cancel()
	ctx := s.cron.Stop()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		s.activeMu.Lock()
		n := len(s.active)
		s.activeMu.Unlock()
		log.Printf("scheduler: shutdown grace elapsed, %d scan(s) still in flight", n)
	}
	s.running = false
}

func (s *Scheduler) Add(scheduleID, cronExpr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	return s.addJob(scheduleID, cronExpr)
}

func (s *Scheduler) Remove(scheduleID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	if entryID, ok := s.entries[scheduleID]; ok {
		s.cron.Remove(entryID)
		delete(s.entries, scheduleID)
	}
}

func (s *Scheduler) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	for id, entryID := range s.entries {
		s.cron.Remove(entryID)
		delete(s.entries, id)
	}

	schedules, err := db.ListSchedules()
	if err != nil {
		return fmt.Errorf("list schedules: %w", err)
	}

	for _, sc := range schedules {
		if err := s.addJob(sc.ID, sc.CronExpr); err != nil {
			log.Printf("scheduler: failed to add job %s: %v", sc.ID, err)
		}
	}

	return nil
}

func (s *Scheduler) addJob(scheduleID, cronExpr string) error {
	entryID, err := s.cron.AddFunc(cronExpr, func() {
		s.executeJob(scheduleID)
	})
	if err != nil {
		return fmt.Errorf("add cron job: %w", err)
	}

	s.entries[scheduleID] = entryID
	return nil
}

func (s *Scheduler) executeJob(scheduleID string) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	schedules, err := db.ListSchedules()
	if err != nil {
		log.Printf("scheduler: list schedules: %v", err)
		return
	}

	var sc *db.ScheduleRow
	for i := range schedules {
		if schedules[i].ID == scheduleID {
			sc = &schedules[i]
			break
		}
	}
	if sc == nil {
		return
	}

	if !s.acquire(scheduleID) {
		log.Printf("scheduler: job %s (%s) skipped: still running", scheduleID, sc.Name)
		_, _ = db.CreateNotification("", "", "schedule_skipped", "Scheduled Scan Skipped",
			fmt.Sprintf("schedule %q skipped: still running", sc.Name), "in_app")
		return
	}

	target, err := db.GetTarget(sc.TargetID)
	if err != nil {
		s.release(scheduleID)
		log.Printf("scheduler: get target %s: %v", sc.TargetID, err)
		return
	}

	scanID, err := db.CreateScan(sc.TargetID, nil, 20, 10, "", "schedule", scheduleID)
	if err != nil {
		s.release(scheduleID)
		log.Printf("scheduler: create scan: %v", err)
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.release(scheduleID)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("scheduler: panic in scheduled scan %s: %v\n%s", scanID, r, debug.Stack())
				_ = db.UpdateScanStatus(scanID, "failed", fmt.Sprintf("panic recovered: %v", r))
			}
		}()
		_ = db.UpdateScanStatus(scanID, "running", "")
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
		defer cancel()

		cfg := engine.NewConfig(
			engine.WithThreads(20),
			engine.WithTimeout(10*time.Second),
		)
		eng := engine.New(cfg)
		result, err := eng.Run(ctx, target.URL)

		if err != nil {
			_ = db.UpdateScanStatus(scanID, "failed", err.Error())
			db.CreateNotification("", scanID, "scan_error", "Scheduled Scan Failed", err.Error(), "in_app")
			return
		}

		if len(result.Findings) > 0 {
			tx, txErr := db.BeginTx()
			if txErr == nil {
				if insErr := db.InsertFindings(tx, scanID, sc.TargetID, result.Findings); insErr != nil {
					tx.Rollback()
					log.Printf("scheduler scan %s: insert findings: %v", scanID, insErr)
				} else if cmtErr := tx.Commit(); cmtErr != nil {
					log.Printf("scheduler scan %s: commit findings: %v", scanID, cmtErr)
				}
			} else {
				log.Printf("scheduler scan %s: begin tx: %v", scanID, txErr)
			}
		}

		_ = db.UpdateScanStatus(scanID, "completed", "")
		db.CreateNotification("", scanID, "scan_complete", "Scheduled Scan Completed",
			fmt.Sprintf("Found %d findings on %s", len(result.Findings), target.URL), "in_app")

		s.dispatchNotifications(ctx, sc, target.URL, len(result.Findings))
	}()

	log.Printf("scheduler: triggered scan %s for target %s", scanID, target.URL)
}

func (s *Scheduler) acquire(scheduleID string) bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[scheduleID] {
		return false
	}
	s.active[scheduleID] = true
	return true
}

func (s *Scheduler) release(scheduleID string) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	delete(s.active, scheduleID)
}

func (s *Scheduler) Running() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
