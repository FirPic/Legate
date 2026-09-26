# How-To: Hardened Deployment (systemd & Podman Quadlet)

This guide provides battle-tested production configurations for running **Legate** with strict sandboxing and security hardening, conforming to standards such as **ANSSI BP-028 v2.0 MIE**.

---

## Option 1: Native systemd Service (ANSSI BP-028 MIE Hardened)

This configuration runs the native compiled Go binary with extreme isolation: ephemeral unprivileged user, strict read-only root filesystem, restricted Linux namespaces, and empty capability bounding set.

### 1. Place Binary and Configuration File

Install the statically compiled binary to `/usr/local/bin/legate`:

```bash
sudo install -m 755 -o root -g root ./legate /usr/local/bin/legate
```

Create a configuration directory `/etc/legate` restricted to root:

```bash
sudo mkdir -p /etc/legate
sudo chmod 700 /etc/legate
```

Place your production YAML configuration at `/etc/legate/config.yaml`:

```yaml
server:
  port: "8080"
  bind_addr: "10.53.20.15"
  admin_port: "9090"
  admin_bind_addr: "127.0.0.1"
  rate_limit_per_minute: 60
  log_level: "info"

providers:
  cf-main:
    type: cloudflare
    api_token_file: "/etc/legate/secrets/cf_token"

domains:
  example.com:
    provider: cf-main

users:
  traefik_dmz:
    password_hash: "$argon2id$v=19$m=65536,t=3,p=2$ZHZ1bmtsZXZhbGlkc2FsdA$YnlF0zPsh8H3R3m5x/l5g8B4o2gC7f6Q9r8u1v2w3x4"
    allowed_subdomains: ["*.dmz.example.com", "dmz.example.com"]
```

> [!TIP]
> Generate the Argon2id hash for `password_hash` with:
> ```bash
> /usr/local/bin/legate hash-password "StrongRandomPassword123"
> ```

```bash
sudo chmod 600 /etc/legate/config.yaml
```

### 2. Create the systemd Unit File

Create `/etc/systemd/system/legate.service`:

```ini
[Unit]
Description=Legate ACME DNS-01 Challenge Gateway
Documentation=https://github.com/FirPic/legate
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/legate --config /etc/legate/config.yaml
Restart=always
RestartSec=5s

# -------------------------------------------------------------
# ANSSI BP-028 MIE Hardening Directives
# -------------------------------------------------------------

# Dynamic, ephemeral unprivileged execution
DynamicUser=yes
User=legate
Group=legate

# Filesystem protections
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
ReadOnlyPaths=/
TemporaryFileSystem=/tmp:ro

# Privilege elevation prevention
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=

# Network and IPC sandboxing
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
PrivateIPC=true

# System call filtering (allowlist standard network service calls)
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @mount
SystemCallArchitectures=native
LockPersonality=true
MemoryDenyWriteExecute=true

# Resource limits
LimitNOFILE=65535
LimitNPROC=512

[Install]
WantedBy=multi-user.target
```

### 3. Enable, Start, and Verify

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now legate.service
sudo systemctl status legate.service
```

Run security audit analysis:

```bash
systemd-analyze security legate.service
```

*Expected score:* `<= 1.0 / OK` (Extremely hardened, zero critical warnings).

---

## Option 2: Podman Rootless Quadlet Container

If you prefer running containerized workloads, Podman Quadlet allows rootless execution without a daemon:

Create `~/.config/containers/systemd/legate.container`:

```ini
[Unit]
Description=Legate ACME DNS Gateway Container
After=network-online.target

[Container]
Image=ghcr.io/firpic/legate:latest
ContainerName=legate
Volume=%h/.config/legate/config.yaml:/etc/legate/config.yaml:ro,z
Environment=CONFIG_FILE=/etc/legate/config.yaml
PublishPort=10.53.20.15:8080:8080
PublishPort=127.0.0.1:9090:9090

# Security constraints
User=65534:65534
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL

# Health check (queried on internal admin port 9090 via built-in healthcheck command)
HealthCmd=/usr/local/bin/legate healthcheck
HealthInterval=30s
HealthRetries=3

[Service]
Restart=always
TimeoutStartSec=60

[Install]
WantedBy=default.target
```

Reload systemd user daemon and start:

```bash
systemctl --user daemon-reload
systemctl --user enable --now legate.service
```
