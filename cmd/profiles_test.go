package cmd

import "testing"

func TestValidateProfile(t *testing.T) {
	for _, profile := range []string{"quick", "passive", "api", "infra", "full"} {
		if err := validateProfile(profile); err != nil {
			t.Errorf("validateProfile(%q) error = %v", profile, err)
		}
	}
	if err := validateProfile("not-a-profile"); err == nil {
		t.Fatal("validateProfile(invalid) error = nil")
	}
}
