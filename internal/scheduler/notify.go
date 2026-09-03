package scheduler

// Glue between scheduled scans and the salvaged notification actions in
// notify_salvage.go. After a scheduled scan completes, every enabled workflow
// in ~/.fang/config/workflows.json whose trigger fires post-scan gets its
// actions dispatched. Notification failures are logged, never fatal.

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aydocs/fang/internal/db"
	"github.com/aydocs/fang/internal/workflow"
)

const (
	actionWebhook     = "webhook"
	actionSlackNotify = "slack_notify"
	actionJiraIssue   = "jira_issue"
	actionGitHubIssue = "github_issue"

	triggerScanComplete = "scan_complete"
	triggerSeverityMet  = "severity_met"
)

func workflowStorePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".fang", "config", "workflows.json")
}

func (s *Scheduler) dispatchNotifications(ctx context.Context, sc *db.ScheduleRow, targetURL string, findings int) {
	data := map[string]interface{}{
		"schedule_id": sc.ID,
		"schedule":    sc.Name,
		"target":      targetURL,
		"findings":    findings,
		"notify_on":   sc.NotifyOn,
	}

	workflows, err := workflow.LoadWorkflows(workflowStorePath())
	if err != nil {
		log.Printf("scheduler: load workflows for notifications: %v", err)
	}
	for _, wf := range workflows {
		if wf == nil || !wf.Enabled || !firesPostScan(wf.Trigger, sc) {
			continue
		}
		for _, act := range wf.Actions {
			if err := runAction(ctx, string(act.Type), act.Config, data); err != nil {
				log.Printf("scheduler: notify action %q (workflow %s): %v", act.Type, wf.ID, err)
			}
		}
	}

	if sc.WebhookURL != "" {
		if err := runWebhook(ctx, map[string]string{"url": sc.WebhookURL}, data); err != nil {
			log.Printf("scheduler: schedule webhook (%s): %v", sc.ID, err)
		}
	}
}

func runAction(ctx context.Context, actionType string, cfg map[string]string, data map[string]interface{}) error {
	switch actionType {
	case actionWebhook:
		return runWebhook(ctx, cfg, data)
	case actionSlackNotify:
		msg := fmt.Sprintf("Fang scan %q on %s finished: %d findings", data["schedule"], data["target"], data["findings"])
		return runSlackNotify(ctx, withDefault(cfg, "message", msg), data)
	case actionJiraIssue:
		return runJiraIssue(ctx, withDefault(cfg, "summary", fmt.Sprintf("Fang findings on %s", data["target"])), data)
	case actionGitHubIssue:
		return runGitHubIssue(ctx, withDefault(cfg, "title", fmt.Sprintf("Fang findings on %s", data["target"])), data)
	default:
		return fmt.Errorf("action %q has no wired runner, skipping", actionType)
	}
}

func firesPostScan(t workflow.TriggerConfig, sc *db.ScheduleRow) bool {
	switch string(t.Type) {
	case triggerScanComplete:
		return true
	case triggerSeverityMet:
		want := t.Conditions["severity"]
		return want == "" || strings.EqualFold(want, sc.NotifyOn)
	default:
		return false
	}
}

func withDefault(cfg map[string]string, key, val string) map[string]string {
	out := make(map[string]string, len(cfg)+1)
	for k, v := range cfg {
		out[k] = v
	}
	if out[key] == "" {
		out[key] = val
	}
	return out
}
