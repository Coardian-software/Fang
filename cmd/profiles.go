package cmd

func getProfileModules(profile string) []string {
	switch profile {
	case "full":
		return nil
	case "quick":
		return []string{"recon", "headers", "xss", "sqli", "cors"}
	case "passive":
		return []string{"recon", "headers", "cors"}
	case "api":
		return []string{"rest", "graphql", "ssrf", "nosqli", "injection"}
	case "infra":
		return []string{"recon", "k8s", "docker", "cloud", "smb"}
	default:
		return nil
	}
}
