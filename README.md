# 🔒 Docker Host Hardening — Hadolint + Trivy + Kyverno


## 🚀 Quick start

```bash
# 1. Clone project
git clone https://github.com/your-org/docker-hardening
cd docker-hardening

# 2. Install tools
chmod +x scripts/install-tools.sh
./scripts/install-tools.sh

# 3. Launch full validation
chmod +x scripts/validate.sh
./scripts/validate.sh

# 4. Validation with JSON report
./scripts/validate.sh --json

```

### Local pipeline launch (act)

```bash
# Launch pipeline locally
act push --job hadolint
act push --job trivy-scan
```

