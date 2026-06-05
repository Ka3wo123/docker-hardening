#!/usr/bin/env bash
# Usage: ./validate.sh [--fix] [--json] [--dockerfile path] [--image name]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORTS_DIR/security-report-$TIMESTAMP.txt"
JSON_REPORT="$REPORTS_DIR/security-report-$TIMESTAMP.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARN_CHECKS=0

FLAG_JSON=false
FLAG_FIX=false
CUSTOM_DOCKERFILE=""
CUSTOM_IMAGE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --json) FLAG_JSON=true; shift ;;        
        --dockerfile) CUSTOM_DOCKERFILE="$2"; shift 2 ;;
        --image) CUSTOM_IMAGE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--json] [--dockerfile <path>] [--image <name>]"
            echo ""
            echo "Options:"            
            echo "  --json        Generate report in JSON format"
            echo "  --dockerfile  Path to Dockerfile"
            echo "  --image       Image name to scan"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done


print_header() {
    echo ""
    echo -e "${WHITE}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}       Docker Hardening - Validation            ${NC}"
    echo -e "${WHITE}       $(date +'%Y-%m-%d %H:%M:%S')             ${NC}"
    echo -e "${WHITE}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_result() {
    local name="$1"
    local status="$2"
    local details="${3:-}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case $status in
        pass)
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            echo -e "  ${GREEN}✓${NC} $name"
            ;;
        fail)
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            echo -e "  ${RED}✗${NC} $name"
            [[ -n "$details" ]] && echo -e "    ${RED}↳ $details${NC}"
            ;;
        warn)
            WARN_CHECKS=$((WARN_CHECKS + 1))
            echo -e "  ${YELLOW}⚠${NC} $name"
            [[ -n "$details" ]] && echo -e "    ${YELLOW}↳ $details${NC}"
            ;;
    esac
}

check_tool_installed() {
    local tool="$1"
    if command -v "$tool" &>/dev/null; then
        check_result "$tool installed: $(command -v "$tool")" "pass"
        return 0
    else
        check_result "$tool not installed" "fail" "Requires: $tool"
        return 1
    fi
}

check_prerequisites() {
    print_section "1. Checking required tools"

    local tools_ok=true

    check_tool_installed "hadolint" || tools_ok=false
    check_tool_installed "trivy" || tools_ok=false
    check_tool_installed "docker" || tools_ok=false
    check_tool_installed "jq" || tools_ok=false

    # Sprawdź wersje
    if command -v hadolint &>/dev/null; then
        local hadolint_ver
        hadolint_ver=$(hadolint --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "\t${BLUE}ℹ Hadolint: v$hadolint_ver${NC}"
    fi

    if command -v trivy &>/dev/null; then
        local trivy_ver
        trivy_ver=$(trivy --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "\t${BLUE}ℹ Trivy: v$trivy_ver${NC}"
    fi

    if command -v kyverno &>/dev/null; then
        local kyverno_ver
        kyverno_ver=$(kyverno version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "\t${BLUE}ℹ Kyverno CLI: v$kyverno_ver${NC}"
    fi

    if command -v docker &>/dev/null; then
        local docker_ver
        docker_ver=$(docker --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "\t${BLUE}ℹ Docker: v$docker_ver${NC}"
    fi

    if ! $tools_ok; then
        echo ""
        echo -e "${RED}ERROR. Required tools missing. Install them first.${NC}"
        echo -e "${YELLOW}Tip: Launch ./scripts/install-tools.sh${NC}"
        exit 1
    fi
}

run_hadolint() {
    print_section "2. Hadolint - Dockerfile analyze"

    local dockerfiles=()

    if [[ -n "$CUSTOM_DOCKERFILE" ]]; then
        dockerfiles+=("$CUSTOM_DOCKERFILE")
    else
        while IFS= read -r -d '' f; do
            dockerfiles+=("$f")
        done < <(find "$PROJECT_DIR/dockerfiles" -name "Dockerfile*" -print0 2>/dev/null)
    fi

    if [[ ${#dockerfiles[@]} -eq 0 ]]; then
        check_result "No Dockerfiles to scan" "warn"
        return 0
    fi

    local hadolint_config="$PROJECT_DIR/.hadolint.yaml"
    local overall_result="pass"

    for dockerfile in "${dockerfiles[@]}"; do
        local rel_path
        rel_path=$(realpath --relative-to="$PROJECT_DIR" "$dockerfile" 2>/dev/null || echo "$dockerfile")

        echo ""
        echo -e "  ${BLUE}Scanning: $rel_path${NC}"

        local output
        local exit_code=0

        output=$(hadolint --config "$hadolint_config" --format tty "$dockerfile" 2>&1) && exit_code=$? || exit_code=$?
        if [[ $exit_code -eq 0 ]]; then 
            check_result "$rel_path: no problems" "pass"
        else            
            overall_result="fail"

            local errors
            local warnings
            errors=$(echo "$output" | grep -c " error " | tr -d '[:space:]' || echo 0)
            warnings=$(echo "$output" | grep -c " warning " | tr -d '[:space:]' || echo 0)

            [[ -z "$errors" ]] && errors=0
            [[ -z "$warnings" ]] && warnings=0

            if [[ $errors -gt 0 ]]; then
                check_result "$rel_path: $errors errors, $warnings warnings" "fail"
            else
                check_result "$rel_path: $warnings warnings" "warn"
            fi

            echo ""
            echo "$output" | while IFS= read -r line; do
                if echo "$line" | grep -q " error "; then
                    echo -e "    ${RED}$line${NC}"
                elif echo "$line" | grep -q " warning "; then
                    echo -e "    ${YELLOW}$line${NC}"
                else
                    echo -e "    $line"
                fi
            done
            echo ""
        fi

        if $FLAG_JSON; then
            hadolint \
                --config "$hadolint_config" \
                --format json \
                "$dockerfile" >> "$JSON_REPORT" 2>/dev/null || true
        fi
    done

    if [[ "$overall_result" == "pass" ]]; then
        echo -e "\n  ${GREEN}✓ Hadolint: All Dockerfiles passed validation${NC}"
    else
        echo -e "\n  ${RED}✗ Hadolint: Problems found in Dockerfiles${NC}"
    fi
}

run_trivy_image() {
    print_section "3. Trivy - CVE scanning in images"

    local images=()

    if [[ -n "$CUSTOM_IMAGE" ]]; then
        images+=("$CUSTOM_IMAGE")
    else
        if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
            mapfile -t images < <(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | \
                grep -v "<none>" | head -5 || true)
        fi
    fi

    if [[ ${#images[@]} -eq 0 ]]; then
        check_result "No images to scan" "warn" \
            "Build image: docker build -t myapp:latest . or use --image flag"
        return 0
    fi

    local trivy_config="$PROJECT_DIR/trivy/trivy.yaml"

    for image in "${images[@]}"; do
        echo ""
        echo -e "  ${BLUE}Scanning image: $image${NC}"

        local output
        local exit_code=0

        if output=$(trivy image \
            --config "$trivy_config" \
            --severity CRITICAL,HIGH,MEDIUM \
            --exit-code 1 \
            --format table \
            "$image" 2>&1); then
            check_result "Image $image: no critical vulnerabilities" "pass"
        else
            exit_code=$?
            local critical_count
            local high_count
            critical_count=$(echo "$output" | grep -c "CRITICAL" || echo 0)
            high_count=$(echo "$output" | grep -c "HIGH" || echo 0)

            if [[ $critical_count -gt 0 ]]; then
                check_result "Image $image: $critical_count CRITICAL, $high_count HIGH" "fail"
            else
                check_result "Image $image: $high_count HIGH vulnerabilities" "warn"
            fi
            
            echo "$output" | grep -E "(CRITICAL|HIGH|MEDIUM)" | head -20
        fi
        
        echo -e "  ${BLUE}Checking secrets in image: $image${NC}"
        local secrets_output
        if secrets_output=$(trivy image \
            --scanners secret \
            --secret-config "$PROJECT_DIR/trivy/trivy-secret.yaml" \
            --exit-code 1 \
            "$image" 2>&1); then
            check_result "Image $image: no secrets found" "pass"
        else
            check_result "Image $image: found possible secrets!" "fail" \
                "Check: trivy image --scanners secret $image"
        fi
    done
}

run_trivy_config() {
    print_section "4. Trivy - Scanning configuration in Dockerfile"

    local scan_paths=()

    if [[ -n "$CUSTOM_DOCKERFILE" ]]; then
        scan_paths+=("$(dirname "$CUSTOM_DOCKERFILE")")
    else
        scan_paths+=("$PROJECT_DIR/dockerfiles")
    fi

    local trivy_policy_dir="$PROJECT_DIR/trivy/policies"

    for scan_path in "${scan_paths[@]}"; do
        echo ""
        echo -e "  ${BLUE}Scanning konfiguracji: $scan_path${NC}"

        local output
        local exit_code=0

        if output=$(trivy config \
            --exit-code 1 \
            --severity CRITICAL,HIGH,MEDIUM \
            --policy "$trivy_policy_dir" \
            --format table \
            "$scan_path" 2>&1); then
            check_result "Configuration $scan_path: compliant with policies" "pass"
        else
            exit_code=$?
            check_result "Configuration $scan_path: problems found" "fail"
            echo "$output" | head -40
        fi
    done
}

validate_daemon_json() {
    print_section "5. Docker daemon configuration file validation (daemon.json)"

    local daemon_file="$PROJECT_DIR/daemon/daemon.json"

    if [[ ! -f "$daemon_file" ]]; then
        check_result "daemon.json: not found" "fail" \
            "Expecting localization: $daemon_file"
        return 1
    fi
    
    if jq empty "$daemon_file" 2>/dev/null; then
        check_result "daemon.json: correct JSON format" "pass"
    else
        check_result "daemon.json: incorrect JSON format!" "fail"
        return 1
    fi
    
    echo ""
    echo -e "  ${BLUE}Checking security settings:${NC}"
    echo ""
    
    local icc
    icc=$(jq -r '.icc // "not set"' "$daemon_file")
    if [[ "$icc" == "false" ]]; then
        check_result "icc (Inter-Container Communication): disabled" "pass"
    else
        check_result "icc: should be false (current: $icc)" "fail" \
            "Set: \"icc\": false"
    fi
    
    local no_new_priv
    no_new_priv=$(jq -r '."no-new-privileges" // "not set"' "$daemon_file")
    if [[ "$no_new_priv" == "true" ]]; then
        check_result "no-new-privileges: enabled" "pass"
    else
        check_result "no-new-privileges: should be true (current: $no_new_priv)" "fail" \
            "Ustaw: \"no-new-privileges\": true"
    fi
    
    local userns
    userns=$(jq -r '."userns-remap" // "not set"' "$daemon_file")
    if [[ "$userns" != "not set" && "$userns" != "null" && -n "$userns" ]]; then
        check_result "userns-remap: configured ($userns)" "pass"
    else
        check_result "userns-remap: not configured" "warn" \
            "Recommended: \"userns-remap\": \"default\""
    fi
    
    local live_restore
    live_restore=$(jq -r '."live-restore" // "not set"' "$daemon_file")
    if [[ "$live_restore" == "true" ]]; then
        check_result "live-restore: enabled" "pass"
    else
        check_result "live-restore: should be true (current: $live_restore)" "warn"
    fi
    
    local tls
    tls=$(jq -r '.tls // "not set"' "$daemon_file")
    local tlsverify
    tlsverify=$(jq -r '.tlsverify // "not set"' "$daemon_file")
    if [[ "$tls" == "true" && "$tlsverify" == "true" ]]; then
        check_result "TLS + mTLS verification: enabled" "pass"
    else
        check_result "TLS/mTLS: not configured (tls=$tls, tlsverify=$tlsverify)" "warn" \
            "Required for production: tls: true, tlsverify: true"
    fi
    
    local log_driver
    log_driver=$(jq -r '."log-driver" // "not set"' "$daemon_file")
    if [[ "$log_driver" != "not set" && "$log_driver" != "none" ]]; then
        check_result "log-driver: skonfigurowany ($log_driver)" "pass"
    else
        check_result "log-driver: not configured or disabled" "warn" \
            "Recommended: \"log-driver\": \"json-file\" lub \"journald\""
    fi
    
    local seccomp
    seccomp=$(jq -r '."seccomp-profile" // "not set"' "$daemon_file")
    if [[ "$seccomp" != "not set" && "$seccomp" != "null" ]]; then
        check_result "seccomp-profile: configured ($seccomp)" "pass"
    else
        check_result "seccomp-profile: uses default profile" "warn" \
            "Consider own profile: $PROJECT_DIR/daemon/custom-seccomp.json"
    fi
    
    echo ""
    echo -e "  ${BLUE}Checking active Docker daemon socket:${NC}"
    echo ""

    if docker info &>/dev/null 2>&1; then
        check_result "Docker daemon: up and running" "pass"

        local live_icc
        live_icc=$(docker info --format '{{json .}}' 2>/dev/null | \
            jq -r '.SecurityOptions // []' | grep -c "no-new-privileges" || echo 0)

        if [[ "$live_icc" -gt 0 ]]; then
            check_result "Live: no-new-privileges active in Docker daemon" "pass"
        else
            check_result "Live: no-new-privileges could not be active in Docker daemon" "warn" \
                "Check: docker info | grep -i security"
        fi

        local docker_version
        docker_version=$(docker --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "    ${BLUE}ℹ Docker version: $docker_version${NC}"
    else
        check_result "Docker daemon: unavailable (check privileges)" "warn"
    fi
}


check_runtime_security() {
    print_section "6. Checking running containers security"

    if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
        check_result "Docker daemon unavailable - skipping runtime checks" "warn"
        return 0
    fi
    
    local containers
    mapfile -t containers < <(docker ps --format "{{.ID}}:{{.Names}}" 2>/dev/null || true)

    if [[ ${#containers[@]} -eq 0 ]]; then
        check_result "Nothing to check. No running containers" "warn"
        return 0
    fi

    echo -e "  ${BLUE}Checking ${#containers[@]} running containers:${NC}"
    echo ""

    for container_info in "${containers[@]}"; do
        local container_id
        local container_name
        container_id="${container_info%%:*}"
        container_name="${container_info##*:}"

        echo -e "  ${BLUE}Container: $container_name ($container_id)${NC}"
        
        local user
        user=$(docker inspect "$container_id" \
            --format '{{.Config.User}}' 2>/dev/null)

        if [[ -z "$user" || "$user" == "0" || "$user" == "root" ]]; then
            check_result "$container_name: running as root!" "fail" \
                "Add USER non-root in Dockerfile or --user flag"
        else
            check_result "$container_name: running as $user" "pass"
        fi
        
        local privileged
        privileged=$(docker inspect "$container_id" \
            --format '{{.HostConfig.Privileged}}' 2>/dev/null)

        if [[ "$privileged" == "true" ]]; then
            check_result "$container_name: Privileged container!" "fail" \
                "Critical: container has full access to host"
        else
            check_result "$container_name: non-root" "pass"
        fi
        
        local readonly_fs
        readonly_fs=$(docker inspect "$container_id" \
            --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null)

        if [[ "$readonly_fs" == "true" ]]; then
            check_result "$container_name: read-only filesystem" "pass"
        else
            check_result "$container_name: filesystem is not read-only" "warn" \
                "Recommended: --read-only flag"
        fi
        
        local cap_add
        cap_add=$(docker inspect "$container_id" \
            --format '{{.HostConfig.CapAdd}}' 2>/dev/null)

        if [[ "$cap_add" == "[]" || -z "$cap_add" ]]; then
            check_result "$container_name: no additional capabilities" "pass"
        else
            check_result "$container_name: additional capabilities: $cap_add" "warn"
        fi
        
        local mounts
        mounts=$(docker inspect "$container_id" \
            --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null)

        local sensitive_mounts=("/etc" "/var/run/docker.sock" "/proc" "/sys" "/dev" "/boot" "/lib/modules")
        for sensitive in "${sensitive_mounts[@]}"; do
            if echo "$mounts" | grep -q "$sensitive"; then
                check_result "$container_name: sensitive path mounted: $sensitive" "fail" \
                    "Check if mounting $sensitive is really necessary"
            fi
        done

        echo ""
    done
}

check_kyverno_policies() {
    print_section "7. Kyverno - Policies validation (syntax check)"

    local policies_dir="$PROJECT_DIR/policies/kyverno"

    if [[ ! -d "$policies_dir" ]]; then
        check_result "Kyverno policies directry not exists: $policies_dir" "fail"
        return 1
    fi
    
    local validate_tool=""
    if command -v kyverno &>/dev/null; then
        validate_tool="kyverno"
    elif command -v kubectl &>/dev/null; then
        validate_tool="kubectl"
    fi

    local policy_files=()
    while IFS= read -r -d '' f; do
        policy_files+=("$f")
    done < <(find "$policies_dir" -name "*.yaml" -print0 2>/dev/null)

    if [[ ${#policy_files[@]} -eq 0 ]]; then
        check_result "No policies files in $policies_dir" "warn"
        return 0
    fi

    echo -e "  ${BLUE}Found ${#policy_files[@]} Kyverno policies:${NC}"
    echo ""

    for policy_file in "${policy_files[@]}"; do
        local policy_name
        policy_name=$(basename "$policy_file")
        
        if command -v python3 &>/dev/null; then
            if python3 -c "
import yaml, sys
try:
    with open('$policy_file') as f:
        list(yaml.safe_load_all(f))
    sys.exit(0)
except Exception as e:
    print(str(e))
    sys.exit(1)
" 2>/dev/null; then
                check_result "Policy $policy_name: correct YAML" "pass"
            else
                check_result "Policy $policy_name: syntax error in YAML!" "fail"
                continue
            fi
        fi
        
        if command -v jq &>/dev/null; then            
            local policy_kind
            policy_kind=$(python3 -c "
import yaml, json, sys
with open('$policy_file') as f:
    docs = list(yaml.safe_load_all(f))
    for doc in docs:
        if doc:
            print(doc.get('kind', 'unknown'))
" 2>/dev/null | head -1)

            if [[ "$policy_kind" == "ClusterPolicy" || "$policy_kind" == "Policy" ]]; then
                check_result "Policy $policy_name: type $policy_kind" "pass"
            else
                check_result "Policy $policy_name: unknown type ($policy_kind)" "warn"
            fi
        fi
        
        if [[ "$validate_tool" == "kyverno" ]]; then
            if kyverno test "$policy_file" &>/dev/null 2>&1; then
                check_result "Policy $policy_name: passed test" "pass"
            else
                check_result "Policy $policy_name: kyverno test - check manually" "warn"
            fi
        fi
    done

    echo ""
    if [[ "$validate_tool" == "" ]]; then
        echo -e "  ${YELLOW}ℹ Install Kyverno CLI for full policies validation:${NC}"
        echo -e "  ${YELLOW}  curl -LO https://github.com/kyverno/kyverno/releases/download/v1.12.0/kyverno_1.12.0_linux_amd64.tar.gz${NC}"
    fi
}

run_kyverno_runtime_validation() {
    print_section "7b. Kyverno - Runtime validation"

    local policies_dir="$PROJECT_DIR/policies/kyverno"
    local test_file="$policies_dir/kyverno-test.yaml"

    if ! command -v kyverno &>/dev/null; then
        check_result "Kyverno CLI not installed - skipping" "warn"
        return 0
    fi

    if [[ ! -f "$test_file" ]]; then
        check_result "No test file for Kyverno ($test_file)" "warn" \
            "Create kyverno-test.yaml file to automate testing according to policies."
        return 0
    fi

    echo -e "  ${BLUE}Launching Kyverno simulation (Dry-run for cluster)...${NC}"
    echo ""

    local output
    local exit_code=0
    
    output=$(kyverno test "$policies_dir" 2>&1) && exit_code=$? || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        check_result "Kyverno simulation: All pods are compliant with security policies" "pass"
        echo -e "    ${GREEN}$output${NC}"
    else
        check_result "Kyverno simulation: Some pods behaved differently as not expected!" "fail"
        echo ""
        echo "$output" | while IFS= read -r line; do
            if echo "$line" | grep -q "Fail"; then
                echo -e "    ${RED}$line${NC}"
            elif echo "$line" | grep -q "Pass"; then
                echo -e "    ${GREEN}$line${NC}"
            else
                echo -e "    $line"
            fi
        done
        echo ""
    fi
}

generate_report() {
    print_section "8. Security report summary"

    local score=0
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        score=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
    fi

    echo ""
    echo -e "  Total checks:\t${WHITE}$TOTAL_CHECKS${NC}"
    echo -e "  Passed:\t${GREEN}$PASSED_CHECKS${NC}"
    echo -e "  Warnings:\t${YELLOW}$WARN_CHECKS${NC}"
    echo -e "  Failures:\t${RED}$FAILED_CHECKS${NC}"
    echo ""
    
    if [[ $score -ge 90 ]]; then
        echo -e "  Security score: ${GREEN}$score% - HIGH security level ✓${NC}"
    elif [[ $score -ge 70 ]]; then
        echo -e "  Security score: ${YELLOW}$score% - MEDIUM security level ⚠${NC}"
    else
        echo -e "  Security score: ${RED}$score% - LOW security level ✗${NC}"
    fi

    echo ""
    echo -e "  Report written in: $REPORT_FILE"

    mkdir -p "$REPORTS_DIR"
    {
        echo "Docker Security Hardening Report"
        echo "Generated: $(date)"
        echo "================================"
        echo "Total checks: $TOTAL_CHECKS"
        echo "Passed: $PASSED_CHECKS"
        echo "Warnings: $WARN_CHECKS"
        echo "Failures: $FAILED_CHECKS"
        echo "Score: $score%"
    } > "$REPORT_FILE"
    
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        echo ""
        echo -e "  ${RED}✗ Validation finished unsuccessfully ($FAILED_CHECKS errors)${NC}"
        return 1
    elif [[ $WARN_CHECKS -gt 0 ]]; then
        echo ""
        echo -e "  ${YELLOW}⚠ Validation finished with warnings ($WARN_CHECKS)${NC}"
        return 0
    else
        echo ""
        echo -e "  ${GREEN}✓ Validation finished successfully!!!${NC}"
        return 0
    fi
}

main() {
    print_header
    
    mkdir -p "$REPORTS_DIR"
    
    check_prerequisites
    run_hadolint
    run_trivy_config
    run_trivy_image
    validate_daemon_json
    check_runtime_security
    check_kyverno_policies
    run_kyverno_runtime_validation
    generate_report
}

main "$@"
