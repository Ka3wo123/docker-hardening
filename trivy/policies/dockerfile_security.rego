package custom.dockerfile.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ============================================================
# Custom Trivy policies (Rego/OPA) for Dockerfile
# Command: trivy config --policy ./policies/ <Dockerfile>
# ============================================================

# --- Rule 1: Block installation commands without version pinning ---
deny contains msg if {
    some instruction in input.Stages[_].Commands
    instruction.Cmd == "run"
    some arg in instruction.Value
    
    regex.match(`apt-get install.*\s\w+\s`, arg)
    not regex.match(`apt-get install.*=`, arg)

    msg := sprintf(
        "SECURITY [DS-001]: Packages should be installed with version pinning. "+
        "Use: apt-get install package=version. Found: '%v'",
        [arg]
    )
}

# --- Rule 2: Detect plain-text secrets in ENV ---
deny contains msg if {
    some instruction in input.Stages[_].Commands
    instruction.Cmd == "env"
    some env_pair in instruction.Value

    secret_patterns := [
        "password", "passwd", "secret", "key", "token",
        "api_key", "apikey", "credentials", "cert", "private"
    ]

    some pattern in secret_patterns
    contains(lower(env_pair), pattern)
    
    not regex.match(`\$\{.*\}|\$[A-Z_]+`, env_pair)

    msg := sprintf(
        "CRITICAL [DS-002]: Possible secret in ENV: '%v'. "+
        "Use Docker secrets or time execution environment variables.",
        [env_pair]
    )
}

# --- Rule 3: Require non-root ---
deny contains msg if {
    user_instructions := [cmd |
        some cmd in input.Stages[_].Commands
        cmd.Cmd == "user"
    ]

    count(user_instructions) == 0

    msg := "HIGH [DS-003]: No USER instruction. Container will start as root. Add: USER nonroot"
}

deny contains msg if {
    some instruction in input.Stages[_].Commands
    instruction.Cmd == "user"
    some val in instruction.Value
    val in {"root", "0", "0:0", "root:root"}

    msg := sprintf(
        "HIGH [DS-003]: USER instruction sets user as root: '%v'. "+
        "Use user with UID >= 1000.",
        [val]
    )
}

# --- Rule 4: Require HEALTHCHECK ---
warn contains msg if {
    healthcheck_instructions := [cmd |
        some cmd in input.Stages[_].Commands
        cmd.Cmd == "healthcheck"
    ]

    count(healthcheck_instructions) == 0

    msg := "MEDIUM [DS-004]: No HEALTHCHECK. Add HEALTHCHECK instruction to monitor state of container."
}

# --- Rule 5: Block ADD instead of COPY for local files ---
deny contains msg if {
    some instruction in input.Stages[_].Commands
    instruction.Cmd == "add"
    some src in instruction.Value

    not regex.match(`^https?://`, src)
    not regex.match(`\.tar\.(gz|bz2|xz)$`, src)

    msg := sprintf(
        "LOW [DS-005]: Use COPY instead of ADD for local files: '%v'. "+
        "ADD could have unexpected behaviour. ADD is allowed only for URL and tar.",
        [src]
    )
}

# --- Rule 6: Verify FROM using specific tags ---
deny contains msg if {
    some stage in input.Stages
    image := stage.From.Image
    
    endswith(image, ":latest")

    msg := sprintf(
        "HIGH [DS-006]: Base image uses latest tag: '%v'. "+
        "Use specific version or sha256 digest for reproducible builds.",
        [image]
    )
}

# --- Rule 7: Require multi-stage builds for production applications ---
warn contains msg if {
    stage_count := count(input.Stages)
    stage_count == 1

    some instruction in input.Stages[_].Commands
    instruction.Cmd in {"copy", "run"}

    msg := "INFO [DS-007]: Consider multi-stage build to diminish image size and surface attack."
}

# --- Rule 8: Detect curl/wget without SSL ---
deny contains msg if {
    some instruction in input.Stages[_].Commands
    instruction.Cmd == "run"
    some arg in instruction.Value

    regex.match(`curl\s+(-k|--insecure)`, arg)

    msg := sprintf(
        "HIGH [DS-008]: curl without SSL (-k/--insecure): '%v'. "+
        "Delete flag -k and import appropiate CA certificate.",
        [arg]
    )
}

# --- Rule 9: Verify wget without SSL certificate ---
deny contains msg if {
    some instruction in input.Stages[_].Commands
    instruction.Cmd == "run"
    some arg in instruction.Value

    regex.match(`wget\s+--no-check-certificate`, arg)

    msg := sprintf(
        "HIGH [DS-009]: wget without certificate verification: '%v'.",
        [arg]
    )
}

# --- Rule 10: Require apt-get cache clean ---
deny contains msg if {
    some instruction in input.Stages[_].Commands
    instruction.Cmd == "run"
    some arg in instruction.Value

    regex.match(`apt-get (install|upgrade)`, arg)
    not regex.match(`(rm -rf /var/lib/apt|apt-get clean|apt-get autoremove)`, arg)

    msg := sprintf(
        "MEDIUM [DS-010]: apt-get install without cache clean: '%v'. "+
        "Add: && rm -rf /var/lib/apt/lists/* after installation.",
        [arg]
    )
}
