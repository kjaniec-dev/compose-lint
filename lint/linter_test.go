package lint

import (
	"strings"
	"testing"
)

// --- unit tests per rule ---

func TestCheckLatestTag(t *testing.T) {
	cases := []struct {
		image string
		want  bool // want a finding?
	}{
		{"nginx:latest", true},
		{"nginx", true},
		{"nginx:1.25", false},
		{"nginx@sha256:abc123def456", false},
		{"registry:5000/myimage", true},         // no tag → latest
		{"registry:5000/myimage:1.0", false},    // explicit tag
		{"registry:5000/myimage:latest", true},  // explicit latest
		{"gcr.io/myproject/app:v1.2.3", false},
		{"gcr.io/myproject/app", true},
	}
	for _, c := range cases {
		t.Run(c.image, func(t *testing.T) {
			got := checkLatestTag("svc", Service{Image: c.image})
			if c.want && len(got) == 0 {
				t.Errorf("image %q: expected finding, got none", c.image)
			}
			if !c.want && len(got) > 0 {
				t.Errorf("image %q: unexpected finding: %s", c.image, got[0].Message)
			}
		})
	}
}

func TestCheckLatestTag_BuildOnly(t *testing.T) {
	got := checkLatestTag("svc", Service{Build: "./myapp"})
	if len(got) != 0 {
		t.Error("build-only service should not trigger tag check")
	}
}

func TestCheckHealthCheck(t *testing.T) {
	t.Run("no healthcheck → warn", func(t *testing.T) {
		f := checkHealthCheck("svc", Service{})
		if len(f) == 0 || f[0].Severity != SeverityWarn {
			t.Error("expected warn for missing healthcheck")
		}
	})
	t.Run("healthcheck present → no finding", func(t *testing.T) {
		f := checkHealthCheck("svc", Service{HealthCheck: &HealthCheck{}})
		if len(f) != 0 {
			t.Error("expected no finding with healthcheck")
		}
	})
	t.Run("healthcheck disabled → info", func(t *testing.T) {
		f := checkHealthCheck("svc", Service{HealthCheck: &HealthCheck{Disable: true}})
		if len(f) == 0 || f[0].Severity != SeverityInfo {
			t.Error("expected info for disabled healthcheck")
		}
	})
}

func TestCheckRestartPolicy(t *testing.T) {
	t.Run("no restart → warn", func(t *testing.T) {
		f := checkRestartPolicy("svc", Service{})
		if len(f) == 0 {
			t.Error("expected warning for missing restart policy")
		}
	})
	t.Run("restart set → no finding", func(t *testing.T) {
		for _, policy := range []string{"always", "unless-stopped", "on-failure", "no"} {
			f := checkRestartPolicy("svc", Service{Restart: policy})
			if len(f) != 0 {
				t.Errorf("restart=%q: unexpected finding", policy)
			}
		}
	})
}

func TestCheckShortPort(t *testing.T) {
	cases := []struct {
		port string
		want bool
	}{
		{"80:80", true},
		{"0.0.0.0:80:80", true},
		{":80:80", true},     // empty host IP = all interfaces
		{"127.0.0.1:80:80", false},
		{"127.0.0.1:8080:80", false},
		{"80", false},        // container-only, no host binding
		{"80:80/tcp", true},  // with protocol suffix still bad
		{"127.0.0.1:80:80/udp", false},
	}
	for _, c := range cases {
		t.Run(c.port, func(t *testing.T) {
			got := checkShortPort("svc", c.port)
			if c.want && len(got) == 0 {
				t.Errorf("port %q: expected finding, got none", c.port)
			}
			if !c.want && len(got) > 0 {
				t.Errorf("port %q: unexpected finding: %s", c.port, got[0].Message)
			}
		})
	}
}

func TestCheckMemoryLimit(t *testing.T) {
	t.Run("no limit → warn", func(t *testing.T) {
		f := checkMemoryLimit("svc", Service{})
		if len(f) == 0 {
			t.Error("expected warning for missing memory limit")
		}
	})
	t.Run("v2 mem_limit → no finding", func(t *testing.T) {
		f := checkMemoryLimit("svc", Service{MemLimit: "512m"})
		if len(f) != 0 {
			t.Error("expected no finding with mem_limit")
		}
	})
	t.Run("v3 deploy limit → no finding", func(t *testing.T) {
		f := checkMemoryLimit("svc", Service{
			Deploy: &Deploy{Resources: &Resources{
				Limits: &ResourceSpec{Memory: "512M"},
			}},
		})
		if len(f) != 0 {
			t.Error("expected no finding with deploy memory limit")
		}
	})
}

func TestCheckCPULimit(t *testing.T) {
	t.Run("no limit → info", func(t *testing.T) {
		f := checkCPULimit("svc", Service{})
		if len(f) == 0 || f[0].Severity != SeverityInfo {
			t.Error("expected info for missing CPU limit")
		}
	})
	t.Run("v2 cpu_shares → no finding", func(t *testing.T) {
		f := checkCPULimit("svc", Service{CPUShares: 512})
		if len(f) != 0 {
			t.Error("expected no finding with cpu_shares")
		}
	})
	t.Run("v3 deploy limit → no finding", func(t *testing.T) {
		f := checkCPULimit("svc", Service{
			Deploy: &Deploy{Resources: &Resources{
				Limits: &ResourceSpec{CPUs: "0.5"},
			}},
		})
		if len(f) != 0 {
			t.Error("expected no finding with deploy CPU limit")
		}
	})
}

func TestCheckPrivileged(t *testing.T) {
	t.Run("not privileged → no finding", func(t *testing.T) {
		f := checkPrivileged("svc", Service{})
		if len(f) != 0 {
			t.Error("unexpected finding for non-privileged service")
		}
	})
	t.Run("privileged → error", func(t *testing.T) {
		f := checkPrivileged("svc", Service{Privileged: true})
		if len(f) == 0 || f[0].Severity != SeverityError {
			t.Error("expected error for privileged container")
		}
	})
}

// --- integration tests ---

var badYAML = []byte(`
version: "3.8"
services:
  api:
    image: myapp:latest
    ports:
      - "8080:8080"
      - "9090:9090"
  db:
    image: postgres
    privileged: true
    ports:
      - "0.0.0.0:5432:5432"
`)

var goodYAML = []byte(`
version: "3.8"
services:
  api:
    image: myapp:1.2.3
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
`)

func TestRun_BadCompose(t *testing.T) {
	findings, err := Run(badYAML)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !HasErrors(findings) {
		t.Error("expected errors in bad compose file")
	}
	rulesSeen := map[string]bool{}
	for _, f := range findings {
		rulesSeen[f.Rule] = true
	}
	for _, expected := range []string{"no-latest-tag", "healthcheck", "restart-policy", "port-binding", "memory-limit", "privileged"} {
		if !rulesSeen[expected] {
			t.Errorf("expected rule %q to fire, but it did not", expected)
		}
	}
}

func TestRun_GoodCompose(t *testing.T) {
	findings, err := Run(goodYAML)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	// Only the cpu-limit info is expected (not an error or warning)
	for _, f := range findings {
		if f.Severity >= SeverityWarn {
			t.Errorf("unexpected %s finding for good compose: [%s] %s", f.Severity, f.Rule, f.Message)
		}
	}
}

func TestRun_InvalidYAML(t *testing.T) {
	_, err := Run([]byte("{{invalid yaml"))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestPrint_NoFindings(t *testing.T) {
	var sb strings.Builder
	Print(nil, true, &sb)
	if !strings.Contains(sb.String(), "No issues found") {
		t.Error("expected 'No issues found' message")
	}
}

func TestPrint_WithFindings(t *testing.T) {
	findings := []Finding{
		{Service: "web", Severity: SeverityError, Rule: "no-latest-tag", Message: `image "nginx:latest" uses "latest"`},
		{Service: "web", Severity: SeverityWarn, Rule: "healthcheck", Message: "no healthcheck defined"},
	}
	var sb strings.Builder
	Print(findings, true, &sb)
	out := sb.String()
	if !strings.Contains(out, "ERROR") {
		t.Error("expected ERROR in output")
	}
	if !strings.Contains(out, "WARN") {
		t.Error("expected WARN in output")
	}
	if !strings.Contains(out, "1 error(s)") {
		t.Error("expected error count in summary")
	}
}

func TestLongFormatPort(t *testing.T) {
	yaml := []byte(`
version: "3.8"
services:
  web:
    image: nginx:1.25
    restart: always
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 128M
    ports:
      - target: 80
        published: 8080
`)
	findings, err := Run(yaml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Rule == "port-binding" {
			if f.Severity < SeverityWarn {
				t.Errorf("expected warning for long-format port without host_ip, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("expected port-binding finding for long-format port without host_ip")
}
