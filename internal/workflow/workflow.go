package workflow

import "time"

type Workflow struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Trigger   TriggerConfig  `json:"trigger"`
	Actions   []ActionConfig `json:"actions"`
	CreatedAt time.Time      `json:"created_at"`
}

type TriggerConfig struct {
	Type       TriggerType       `json:"type"`
	Conditions map[string]string `json:"conditions"`
}

type TriggerType string

type ActionConfig struct {
	Type   ActionType        `json:"type"`
	Config map[string]string `json:"config"`
}

type ActionType string
