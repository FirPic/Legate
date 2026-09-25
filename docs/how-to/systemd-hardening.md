# How-To: Hardened Deployment (systemd & Podman Quadlet)

This guide provides battle-tested production configurations for running `acme-dns-httpreq-proxy` with strict sandboxing and security hardening, conforming to standards such as **ANSSI BP-028 v2.0 MIE**.

---

## Option 1: Native systemd Service (ANSSI BP-028 MIE Hardened)

This configuration runs the native compiled Go binary with extreme isolation: ephemeral unprivileged user, strict read-only root filesystem, restricted Linux namespaces, and empty capability bounding set.

### 1. Place Binary and Environment File

Install the statically compiled binary to `/usr/local/bin/acme-dns-proxy`:

```bash
sudo install -m 755 -o root -g root ./acme-dns-proxy /usr/local/bin/acme-dns-proxy
```

Create an environment file `/etc/acme-dns-proxy/proxy.env` restricted to root:

```bash
sudo mkdir -p /etc/acme-dns-proxy
sudo chmod 700 /etc/acme-dns-proxy
```

```ini
# /etc/acme-dns-proxy/proxy.env (permissions 600)
PORT=8080
BIND_ADDR=10.53.20.15
ALLOWED_DOMAIN=example.com
CLOUDFLARE_API_TOKEN=your-cloudflare-token-here
USERS=traefik_dmz:StrongRandomPassword123,traefik_infra:AnotherStrongPassword456
LOG_LEVEL=info
```

```bash
sudo chmod 600 /etc/acme-dns-proxy/proxy.env
```

### 2. Create the systemd Unit File

Create `/etc/systemd/system/acme-dns-proxy.service`:

```ini
[Unit]
Description=ACME DNS HTTP Request Proxy
Documentation=https://github.com/FirPic/acme-dns-httpreq-proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/acme-dns-proxy
EnvironmentFile=/etc/acme-dns-proxy/proxy.env
Restart=always
RestartSec=5s

# -------------------------------------------------------------
# ANSSI BP-028 MIE Hardening Directives
# -------------------------------------------------------------

# Dynamic, ephemeral unprivileged execution
DynamicUser=yes
User=acme-proxy
Group=acme-proxy

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
sudo systemctl enable --now acme-dns-proxy.service
sudo systemctl status acme-dns-proxy.service
```

Run security audit analysis:

```bash
systemd-analyze security acme-dns-proxy.service
```

*Expected score:* `1.0 / OK` (Extremely hardened, zero critical warnings).

---

## Option 2: Podman Rootless Quadlet Container

If you prefer running containerized workloads, Podman Quadlet allows rootless execution without a daemon:

Create `~/.config/containers/systemd/acme-dns-proxy.container`:

```ini
[Unit]
Description=ACME DNS HTTP Request Proxy Container
After=network-online.target

[Container]
Image=ghcr.io/firpic/acme-dns-httpreq-proxy:latest
ContainerName=acme-dns-proxy
EnvironmentFile=%h/.config/acme-dns-proxy/proxy.env
PublishPort=10.53.20.15:8080:8080

# Security constraints
User=65534:65534
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL

# Health check
HealthCmd=curl -f http://127.0.0.1:8080/healthz || exit 1
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
systemctl --user enable --now acme-dns-proxy.service
```
