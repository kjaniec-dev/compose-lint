# compose-lint

A fast, zero-dependency linter for `docker-compose.yml` files that catches common production pitfalls before they become incidents.

## Checks

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `no-latest-tag` | ERROR | Image with no tag or `:latest` – use a pinned version or digest |
| `privileged` | ERROR | Container running in privileged mode |
| `healthcheck` | WARN | Missing or disabled healthcheck |
| `restart-policy` | WARN | No restart policy defined |
| `port-binding` | WARN | Port exposed on all interfaces (`0.0.0.0`) instead of `127.0.0.1` |
| `memory-limit` | WARN | No memory limit (`mem_limit` or `deploy.resources.limits.memory`) |
| `cpu-limit` | INFO | No CPU limit (`cpu_shares` or `deploy.resources.limits.cpus`) |

## Installation

```bash
go install github.com/kjaniec-dev/compose-lint@latest
```

Or build from source:

```bash
git clone https://github.com/kjaniec-dev/compose-lint
cd compose-lint
go build -o compose-lint .
```

## Usage

```bash
# lint docker-compose.yml in the current directory
compose-lint

# lint a specific file
compose-lint path/to/docker-compose.yml

# lint multiple files
compose-lint docker-compose.yml docker-compose.prod.yml

# disable ANSI colors (useful for CI logs)
compose-lint --no-color docker-compose.yml
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No issues found (or only INFO findings) |
| `1` | At least one ERROR finding |
| `2` | File read or YAML parse error |

## Example output

```
[ERROR]  service "api": image "myapp:latest" uses "latest" – pin to a specific version or digest  (no-latest-tag)
[WARN ]  service "api": no healthcheck defined  (healthcheck)
[WARN ]  service "api": no restart policy defined – consider "unless-stopped" or "on-failure"  (restart-policy)
[WARN ]  service "api": port "8080:8080" exposed on all interfaces – bind to 127.0.0.1 if external access is not needed  (port-binding)
[WARN ]  service "api": no memory limit set – service can consume all available memory  (memory-limit)
[INFO ]  service "api": no CPU limit set – service can consume all available CPU  (cpu-limit)
[ERROR]  service "db": container runs in privileged mode – avoid unless absolutely necessary  (privileged)

Found 7 issue(s): 2 error(s), 4 warning(s), 1 info(s)
```

## Port binding note

Both short and long port formats are understood:

```yaml
ports:
  - "8080:8080"               # WARN – all interfaces
  - "127.0.0.1:8080:8080"    # OK   – localhost only
  - target: 80
    published: 80             # WARN – no host_ip → all interfaces
  - target: 80
    published: 80
    host_ip: "127.0.0.1"     # OK
```

## Resource limits

Both Compose v2 and v3 formats are recognised:

```yaml
# Compose v2
mem_limit: 512m
cpu_shares: 512

# Compose v3
deploy:
  resources:
    limits:
      cpus: "0.5"
      memory: 512M
```
