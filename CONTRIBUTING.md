# Contributing to Legate

Thank you for your interest in contributing! We appreciate bug reports, feature suggestions, documentation enhancements, and pull requests.

---

## Code of Conduct

We are committed to providing a friendly, safe, and welcoming environment for all contributors. Please treat everyone with respect and kindness.

---

## Development Environment

### Prerequisites

- **Go**: 1.24 or later.
- **Podman**: for building container images.
- **golangci-lint**: for static analysis.

### Cloning and Building

```bash
git clone https://github.com/FirPic/legate.git
cd legate

# Build binary
make build

# Run unit tests with race detection
make test

# Run linter
make lint
```

---

## Code Style & Architecture Guidelines

1. **Package by Capability / Domain**: Keep domain logic clean:
   - `internal/challenge`: Validation and request models.
   - `internal/provider`: DNS provider interfaces and implementations.
   - `internal/tracker`: Concurrency and lifecycle state tracking.
   - `internal/http`: HTTP handlers, middlewares, metrics.
   - `internal/config`: Fail-fast environment and YAML configuration.
2. **Minimal External Dependencies**: We avoid bloated SDKs and framework overhead. Favor standard library (`net/http`, `log/slog`, `crypto/subtle`, `sync`) whenever possible.
3. **Zero Data Races**: All code handling state must be thread-safe. `go test -race ./...` must pass with zero warnings.
4. **Security by Design**:
   - Always validate inputs strictly.
   - Never log secrets or API tokens.
   - Use constant-time comparisons for authentication.

---

## Submitting Pull Requests

1. **Create a Topic Branch**:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. **Write Unit Tests**: Every new feature or bugfix must include corresponding unit tests.
3. **Verify All Checks Pass**:
   ```bash
   make test
   make lint
   ```
4. **Commit Format**: Use [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add DuckDNS provider support`
   - `fix: handle edge case in FQDN label length validation`
   - `docs: update Traefik v3 integration guide`
5. **Open a PR**: Fill out the Pull Request template completely.
