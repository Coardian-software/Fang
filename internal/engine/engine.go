package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/detect"
	"github.com/aydocs/fang/internal/plugin"
	"github.com/aydocs/fang/pkg/models"
)

type Engine struct {
	registry      *Registry
	config        *Config
	logger        *Logger
	pluginManager *plugin.Manager
	mu            sync.Mutex
	stopped       bool
}

func New(cfg *Config) *Engine {
	eng := &Engine{
		registry: GetRegistry(),
		config:   cfg,
		logger:   NewLogger(cfg.Verbose),
	}
	eng.initPlugins()
	return eng
}

func (e *Engine) Run(ctx context.Context, target string) (*models.ScanResult, error) {
	startTime := time.Now()

	t, err := e.createTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	if !e.config.AllowPrivate && isPrivateTarget(t.Domain) {
		e.logger.Info("private target skipped (use --allow-private)")
		return &models.ScanResult{
			Target:    target,
			StartTime: startTime,
			EndTime:   time.Now(),
			Duration:  time.Since(startTime).String(),
		}, nil
	}

	client := e.config.BuildHTTPClient()
	defer client.Close()
	e.config.Client = client

	result := &models.ScanResult{
		Target:    target,
		StartTime: startTime,
	}

	agg := detect.NewAggregator()
	// absorb is the single enrichment point: every finding from every stage
	// (crawl, modules, plugins) passes through here exactly once, upstream
	// of both detect dedup and persistence.
	absorb := func(findings []*models.Finding) {
		for _, f := range findings {
			if f == nil {
				continue
			}
			models.EnrichFinding(f)
			e.persist(agg.Absorb(f, detect.Options{Ctx: ctx, Client: client}))
		}
	}

	absorb(e.runCrawlStage(ctx, t))
	targets := e.expandTargets(t)

	for _, mr := range e.runActiveStage(ctx, targets) {
		if mr.Error != nil {
			e.logger.Error("module %s failed: %v", mr.ModuleID, mr.Error)
			continue
		}
		absorb(mr.Findings)
	}
	absorb(e.runPlugins(ctx, t))

	result.Findings = agg.Findings()
	result.EndTime = time.Now()
	result.Duration = time.Since(startTime).String()

	summary := models.Summary{}
	for _, f := range result.Findings {
		summary.Add(f)
	}
	result.Summary = summary

	return result, nil
}

// persist upserts an absorption immediately keyed by fingerprint; failures
// are logged, never fatal.
func (e *Engine) persist(abs detect.Absorption) {
	if e.config.ScanID == "" || e.config.TargetID == "" {
		return
	}
	abs.Finding.ScanID = e.config.ScanID
	if err := db.UpsertFinding(e.config.ScanID, e.config.TargetID, abs.Finding); err != nil {
		e.logger.Error("persist finding: %v", err)
	}
}

func (e *Engine) initPlugins() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	pluginDir := filepath.Join(homeDir, ".fang", "plugins")
	e.pluginManager = plugin.NewManager(pluginDir)
	_ = e.pluginManager.LoadAll()
}

func (e *Engine) runPlugins(ctx context.Context, target *models.Target) []*models.Finding {
	if e.pluginManager == nil {
		return nil
	}

	plugins := e.pluginManager.List()
	if len(plugins) == 0 {
		return nil
	}

	e.logger.Info("running %d plugin(s)", len(plugins))

	var allFindings []*models.Finding
	for _, p := range plugins {
		select {
		case <-ctx.Done():
			return allFindings
		default:
		}
		if p.Module == nil {
			continue
		}

		e.logger.ModuleStart(p.Manifest.Name)
		start := time.Now()
		findings, err := p.Module.Scan(ctx, target)
		dur := time.Since(start)
		if err != nil {
			e.logger.Error("plugin %s error: %v", p.Manifest.Name, err)
			continue
		}
		e.logger.ModuleComplete(p.Manifest.Name, len(findings), dur)
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

func (e *Engine) runActiveStage(ctx context.Context, targets []*models.Target) []*models.ModuleResult {
	modules := e.filterModules(e.registry.List())
	if len(modules) == 0 {
		return nil
	}

	pool := NewWorkerPool(ctx, e.config.Threads, e.logger, e.config)
	pool.Start()

	jobs := 0
	for _, m := range modules {
		for _, t := range targets {
			select {
			case <-ctx.Done():
				pool.Stop()
				return nil
			default:
			}
			pool.Submit(Job{Module: m, Target: t})
			jobs++
		}
	}

	var results []*models.ModuleResult
	for i := 0; i < jobs; i++ {
		select {
		case <-ctx.Done():
			pool.Stop()
			return results
		case result := <-pool.Results():
			if result != nil {
				for _, f := range result.Findings {
					if f != nil && f.ModuleID == "" {
						f.ModuleID = result.ModuleID
					}
				}
			}
			results = append(results, result)
		}
	}

	pool.Stop()
	return results
}

func (e *Engine) filterModules(modules []Module) []Module {
	var filtered []Module
	for _, m := range modules {
		id := m.ID()
		if id == crawlerModuleID {
			continue
		}
		if len(e.config.Modules) > 0 {
			include := false
			for _, allowed := range e.config.Modules {
				if id == allowed {
					include = true
					break
				}
			}
			if !include {
				continue
			}
		}
		if len(e.config.ExcludeModules) > 0 {
			exclude := false
			for _, denied := range e.config.ExcludeModules {
				if id == denied {
					exclude = true
					break
				}
			}
			if exclude {
				continue
			}
		}
		if e.config.Quick && m.Severity() == models.Info {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}

func (e *Engine) RunModule(ctx context.Context, id string, target string) (*models.ModuleResult, error) {
	m, ok := e.registry.Get(id)
	if !ok {
		return nil, fmt.Errorf("module %s not found", id)
	}

	t, err := e.createTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	if err := m.Init(ctx, e.config); err != nil {
		return nil, fmt.Errorf("module %s init failed: %w", id, err)
	}

	start := time.Now()
	findings, err := m.Scan(ctx, t)
	dur := time.Since(start)

	return &models.ModuleResult{
		ModuleID:   m.ID(),
		ModuleName: m.Name(),
		Findings:   findings,
		Error:      err,
		Duration:   dur,
	}, nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
}
