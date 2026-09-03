package cmd

import (
	"os"

	"github.com/aydocs/fang/internal/pigment"
	"github.com/aydocs/fang/pkg/models"
)

var flagNoColor bool

// uiSetup applies the explicit --no-color override on top of pigment's own
// environment detection (NO_COLOR, TERM=dumb, TTY probing).
func uiSetup() {
	if flagNoColor {
		pigment.SetEnabled(false)
	}
}

func paintSeverity(s models.Severity) string {
	switch s {
	case models.Critical:
		return pigment.New().Fg("#ff5555").Bold().Sprint(s.String())
	case models.High:
		return pigment.New().Fg("#ff9f43").Sprint(s.String())
	case models.Medium:
		return pigment.New().Fg("#f1fa8c").Sprint(s.String())
	case models.Low:
		return pigment.New().Fg("#6272a4").Sprint(s.String())
	default:
		return pigment.New().Fg("#8be9fd").Sprint(s.String())
	}
}

func uiError(format string, a ...any) {
	pigment.New().Fg("#ff5555").Fprintf(os.Stderr, format+"\n", a...)
}

func paintStatus(status string) string {
	switch status {
	case "completed", "done":
		return pigment.GreenString("%s", status)
	case "running":
		return pigment.CyanString("%s", status)
	case "failed", "error":
		return pigment.RedString("%s", status)
	default:
		return pigment.HiBlackString("%s", status)
	}
}
