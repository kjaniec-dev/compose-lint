package lint

import (
	"fmt"
	"strings"
)

// rule is a function that inspects one service and returns findings.
type rule func(name string, svc Service) []Finding

// allRules is the ordered list of checks applied to every service.
var allRules = []rule{
	checkLatestTag,
	checkHealthCheck,
	checkRestartPolicy,
	checkPorts,
	checkMemoryLimit,
	checkCPULimit,
	checkPrivileged,
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
