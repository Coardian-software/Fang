package engine

import (
	"context"
	"net/url"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

const crawlerModuleID = "crawler"

// runCrawlStage drives the crawler synchronously before the module pool
// dispatches. The crawler registers itself through the shared registry
// (blank-imported by modules/register.go), so the engine only sees the
// Module interface and never imports the crawler package directly.
func (e *Engine) runCrawlStage(ctx context.Context, t *models.Target) []*models.Finding {
	if !e.config.CrawlEnabled {
		return nil
	}
	m, ok := e.registry.Get(crawlerModuleID)
	if !ok {
		e.logger.Info("crawl stage skipped: crawler module not registered")
		return nil
	}
	if err := m.Init(ctx, e.config); err != nil {
		e.logger.Error("crawler init failed: %v", err)
		return nil
	}
	e.logger.ModuleStart(m.Name())
	start := time.Now()
	findings, err := m.Scan(ctx, t)
	dur := time.Since(start)
	if err != nil {
		e.logger.Error("module %s error: %v", m.Name(), err)
		return nil
	}
	e.logger.ModuleComplete(m.Name(), len(findings), dur)
	for _, f := range findings {
		if f != nil {
			if f.ModuleID == "" {
				f.ModuleID = m.ID()
			}
			models.EnrichFinding(f)
		}
	}
	return findings
}

// expandTargets clones every discovered URL into its own *models.Target so
// pool workers never share a target pointer. The primary target keeps its
// CrawlResult; shallow copies inherit it read-only.
func (e *Engine) expandTargets(primary *models.Target) []*models.Target {
	targets := []*models.Target{primary}
	if !e.config.CrawlEnabled || primary.CrawlResult == nil {
		return targets
	}
	seen := map[string]bool{primary.URL: true}
	for _, u := range primary.CrawlResult.URLs {
		if len(targets) >= e.config.MaxPages || u == "" || seen[u] {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		seen[u] = true
		clone := *primary
		clone.URL = u
		clone.Domain = parsed.Hostname()
		targets = append(targets, &clone)
	}
	return targets
}
