package lint

import (
	"fmt"
	"sort"
	"strings"
)

// rule is a function that inspects one service and returns findings.
type rule func(name string, svc Service) []Finding

// allRules is the ordered list of checks applied to every service.
var allRules = []rule{
	checkLatestTag,
	checkPrivileged,
	checkCapabilities,
	checkHealthCheck,
	checkRestartPolicy,
	checkPorts,
	checkMemoryLimit,
	checkHostNetwork,
	checkNoRootUser,
	checkEnvSecrets,
	checkCPULimit,
	checkReadOnlyRootfs,
}

// checkLatestTag reports when an image has no tag or uses "latest".
func checkLatestTag(name string, svc Service) []Finding {
	if svc.Image == "" {
		return nil // build-only service
	}
	image := svc.Image
	// digest-pinned images are fine
	if strings.Contains(image, "@sha256:") {
		return nil
	}
	// extract tag: everything after the last ':' that contains no '/'
	// (a bare ':' in a registry address like registry:5000/img is followed by a '/')
	tag := ""
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		rest := image[idx+1:]
		if !strings.Contains(rest, "/") {
			tag = rest
		}
	}
	if tag == "" || tag == "latest" {
		return []Finding{{
			Service:  name,
			Severity: SeverityError,
			Rule:     "no-latest-tag",
			Message:  fmt.Sprintf("image %q uses %q – pin to a specific version or digest", image, "latest"),
		}}
	}
	return nil
}

// checkHealthCheck reports when a service has no healthcheck configured.
func checkHealthCheck(name string, svc Service) []Finding {
	if svc.HealthCheck == nil {
		return []Finding{{
			Service:  name,
			Severity: SeverityWarn,
			Rule:     "healthcheck",
			Message:  "no healthcheck defined",
		}}
	}
	if svc.HealthCheck.Disable {
		return []Finding{{
			Service:  name,
			Severity: SeverityInfo,
			Rule:     "healthcheck",
			Message:  "healthcheck is explicitly disabled",
		}}
	}
	return nil
}

// checkRestartPolicy reports when no restart policy is set.
func checkRestartPolicy(name string, svc Service) []Finding {
	if svc.Restart == "" {
		return []Finding{{
			Service:  name,
			Severity: SeverityWarn,
			Rule:     "restart-policy",
			Message:  `no restart policy defined – consider "unless-stopped" or "on-failure"`,
		}}
	}
	return nil
}

// checkPorts reports ports that are bound to all network interfaces.
func checkPorts(name string, svc Service) []Finding {
	var findings []Finding
	for _, p := range svc.Ports {
		if p.Short != "" {
			findings = append(findings, checkShortPort(name, p.Short)...)
		} else if p.HostIP == "" || p.HostIP == "0.0.0.0" {
			findings = append(findings, Finding{
				Service:  name,
				Severity: SeverityWarn,
				Rule:     "port-binding",
				Message:  fmt.Sprintf("port %d exposed on all interfaces – bind to 127.0.0.1 if external access is not needed", p.Target),
			})
		}
	}
	return findings
}

// checkShortPort evaluates a short-format port string such as "80:80" or "127.0.0.1:80:80".
func checkShortPort(name, portStr string) []Finding {
	bare := strings.SplitN(portStr, "/", 2)[0] // strip /tcp or /udp
	parts := strings.Split(bare, ":")
	switch len(parts) {
	case 1:
		// container-only port, exposed on a random host port – fine
		return nil
	case 2:
		// HOST_PORT:CONTAINER_PORT – binds to all interfaces
		return []Finding{{
			Service:  name,
			Severity: SeverityWarn,
			Rule:     "port-binding",
			Message:  fmt.Sprintf("port %q exposed on all interfaces – bind to 127.0.0.1 if external access is not needed", portStr),
		}}
	case 3:
		// HOST_IP:HOST_PORT:CONTAINER_PORT
		hostIP := parts[0]
		if hostIP == "" || hostIP == "0.0.0.0" {
			return []Finding{{
				Service:  name,
				Severity: SeverityWarn,
				Rule:     "port-binding",
				Message:  fmt.Sprintf("port %q exposed on all interfaces – bind to 127.0.0.1 if external access is not needed", portStr),
			}}
		}
	}
	return nil
}

// checkMemoryLimit reports when no memory limit is configured.
func checkMemoryLimit(name string, svc Service) []Finding {
	if svc.MemLimit != "" {
		return nil // Compose v2 mem_limit
	}
	if svc.Deploy != nil &&
		svc.Deploy.Resources != nil &&
		svc.Deploy.Resources.Limits != nil &&
		svc.Deploy.Resources.Limits.Memory != "" {
		return nil // Compose v3 deploy.resources.limits.memory
	}
	return []Finding{{
		Service:  name,
		Severity: SeverityWarn,
		Rule:     "memory-limit",
		Message:  "no memory limit set – service can consume all available memory",
	}}
}

// checkCPULimit reports when no CPU limit is configured.
func checkCPULimit(name string, svc Service) []Finding {
	if svc.CPUShares > 0 {
		return nil // Compose v2 cpu_shares
	}
	if svc.Deploy != nil &&
		svc.Deploy.Resources != nil &&
		svc.Deploy.Resources.Limits != nil &&
		svc.Deploy.Resources.Limits.CPUs != "" {
		return nil // Compose v3 deploy.resources.limits.cpus
	}
	return []Finding{{
		Service:  name,
		Severity: SeverityInfo,
		Rule:     "cpu-limit",
		Message:  "no CPU limit set – service can consume all available CPU",
	}}
}

// checkPrivileged reports containers running in privileged mode.
func checkPrivileged(name string, svc Service) []Finding {
	if !svc.Privileged {
		return nil
	}
	return []Finding{{
		Service:  name,
		Severity: SeverityError,
		Rule:     "privileged",
		Message:  "container runs in privileged mode – avoid unless absolutely necessary",
	}}
}

// dangerousCapabilities is the set of Linux capabilities that grant elevated kernel access.
var dangerousCapabilities = map[string]bool{
	"ALL":          true,
	"SYS_ADMIN":    true,
	"NET_ADMIN":    true,
	"SYS_PTRACE":   true,
	"SYS_MODULE":   true,
	"DAC_OVERRIDE": true,
	"SETUID":       true,
	"SETGID":       true,
}

// checkCapabilities reports dangerous Linux capabilities added to a service.
func checkCapabilities(name string, svc Service) []Finding {
	var findings []Finding
	for _, cap := range svc.CapAdd {
		if dangerousCapabilities[strings.ToUpper(cap)] {
			findings = append(findings, Finding{
				Service:  name,
				Severity: SeverityError,
				Rule:     "capabilities",
				Message:  fmt.Sprintf("dangerous capability %q added – grants elevated kernel access", cap),
			})
		}
	}
	return findings
}

// checkHostNetwork reports when a service uses host networking.
func checkHostNetwork(name string, svc Service) []Finding {
	if strings.EqualFold(svc.NetworkMode, "host") {
		return []Finding{{
			Service:  name,
			Severity: SeverityWarn,
			Rule:     "host-network",
			Message:  `network_mode "host" exposes the container on the host network stack – use a custom bridge network`,
		}}
	}
	return nil
}

// checkNoRootUser reports when a service is explicitly configured to run as root.
func checkNoRootUser(name string, svc Service) []Finding {
	u := strings.TrimSpace(svc.User)
	// Match "root", "0", "0:0", "0:<any_gid>"
	if u == "root" || u == "0" || strings.HasPrefix(u, "0:") {
		return []Finding{{
			Service:  name,
			Severity: SeverityWarn,
			Rule:     "no-root-user",
			Message:  fmt.Sprintf("service is configured to run as root (user: %q) – use a non-root UID", svc.User),
		}}
	}
	return nil
}

// secretKeywords are substrings in env var names that suggest sensitive values.
var secretKeywords = []string{
	"password", "passwd", "secret", "api_key", "private_key", "token", "credentials",
}

// checkEnvSecrets reports environment variables that appear to contain hardcoded credentials.
func checkEnvSecrets(name string, svc Service) []Finding {
	if len(svc.Environment) == 0 {
		return nil
	}
	keys := make([]string, 0, len(svc.Environment))
	for k := range svc.Environment {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []Finding
	for _, key := range keys {
		val := svc.Environment[key]
		// Skip empty values and env-var references like $VAR or ${VAR}
		if val == "" || strings.HasPrefix(val, "$") {
			continue
		}
		lower := strings.ToLower(key)
		for _, kw := range secretKeywords {
			if strings.Contains(lower, kw) {
				findings = append(findings, Finding{
					Service:  name,
					Severity: SeverityWarn,
					Rule:     "env-secrets",
					Message:  fmt.Sprintf("env var %q may contain a hardcoded secret – use Docker secrets or an env file", key),
				})
				break
			}
		}
	}
	return findings
}

// checkReadOnlyRootfs reports when the container root filesystem is not read-only.
func checkReadOnlyRootfs(name string, svc Service) []Finding {
	if svc.ReadOnly {
		return nil
	}
	return []Finding{{
		Service:  name,
		Severity: SeverityInfo,
		Rule:     "read-only-rootfs",
		Message:  "root filesystem is writable – consider read_only: true to reduce attack surface",
	}}
}
