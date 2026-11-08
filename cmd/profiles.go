package cmd

import "fmt"

func getProfileModules(profile string) []string {
	switch profile {
	case "full":
		return nil
	case "quick":
		return []string{"recon", "headers", "xss", "sqli", "cors"}
	case "passive":
		return []string{"recon", "headers", "cors"}
	case "api":
		return []string{"rest", "graphql", "ssrf", "nosqli", "inject"}
	case "infra":
		return []string{"recon", "k8s", "docker", "cloud"}
	default:
		return nil
	}
}

func validateProfile(profile string) error {
	if profile == "" {
		return nil
	}
	valid := map[string]bool{
		"quick": true, "passive": true, "api": true, "infra": true, "full": true,
	}
	if !valid[profile] {
		return fmt.Errorf("unknown profile %q (valid: quick, passive, api, infra, full)", profile)
	}
	return nil
}
