package lint

import "gopkg.in/yaml.v3"

// ComposeFile is the top-level docker-compose document.
type ComposeFile struct {
	Version  string             `yaml:"version"`
	Services map[string]Service `yaml:"services"`
}

// Service represents a single compose service.
type Service struct {
	Image       string       `yaml:"image"`
	Build       interface{}  `yaml:"build"`
	Ports       []Port       `yaml:"ports"`
	Restart     string       `yaml:"restart"`
	Privileged  bool         `yaml:"privileged"`
	ReadOnly    bool         `yaml:"read_only"`
	User        string       `yaml:"user"`
	SecurityOpt []string     `yaml:"security_opt"`
	HealthCheck *HealthCheck `yaml:"healthcheck"`
	Deploy      *Deploy      `yaml:"deploy"`
	MemLimit    string       `yaml:"mem_limit"`
	CPUShares   int64        `yaml:"cpu_shares"`
}

// Port handles the short ("HOST:CONTAINER") and long-form port entries.
type Port struct {
	Short  string // populated for short-format strings
	HostIP string `yaml:"host_ip"`
	Target int    `yaml:"target"`
}

func (p *Port) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		p.Short = node.Value
		return nil
	}
	type plain Port
	return node.Decode((*plain)(p))
}

// HealthCheck mirrors the compose healthcheck block.
type HealthCheck struct {
	Test     []string `yaml:"test"`
	Interval string   `yaml:"interval"`
	Timeout  string   `yaml:"timeout"`
	Retries  int      `yaml:"retries"`
	Disable  bool     `yaml:"disable"`
}

// Deploy mirrors the compose deploy block (Swarm / v3).
type Deploy struct {
	Resources *Resources `yaml:"resources"`
}

// Resources mirrors deploy.resources.
type Resources struct {
	Limits       *ResourceSpec `yaml:"limits"`
	Reservations *ResourceSpec `yaml:"reservations"`
}

// ResourceSpec holds CPU and memory values.
type ResourceSpec struct {
	CPUs   string `yaml:"cpus"`
	Memory string `yaml:"memory"`
}
