package lint

import (
	"strings"

	"gopkg.in/yaml.v3"
)

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
	NetworkMode string       `yaml:"network_mode"`
	CapAdd      []string     `yaml:"cap_add"`
	Environment EnvVars      `yaml:"environment"`
	DependsOn   DependsOn    `yaml:"depends_on"`
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

// EnvVars holds environment variables supporting both map and list YAML formats.
type EnvVars map[string]string

func (e *EnvVars) UnmarshalYAML(node *yaml.Node) error {
	*e = make(EnvVars)
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			(*e)[node.Content[i].Value] = node.Content[i+1].Value
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			kv := strings.SplitN(item.Value, "=", 2)
			if len(kv) == 2 {
				(*e)[kv[0]] = kv[1]
			} else {
				(*e)[kv[0]] = ""
			}
		}
	}
	return nil
}

// DependsOn is a list of service names this service depends on.
// Supports both list format (- svc) and map format (svc: {condition: ...}).
type DependsOn []string

func (d *DependsOn) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		for _, item := range node.Content {
			*d = append(*d, item.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			*d = append(*d, node.Content[i].Value)
		}
	}
	return nil
}
