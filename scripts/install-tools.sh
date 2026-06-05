#!/usr/bin/env bash

set -euo pipefail

RED='\033[;31m'
GREEN='\033[;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

HADOLINT_VERSION="2.12.0"
TRIVY_VERSION="0.50.2"
KYVERNO_CLI_VERSION="1.12.0"

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/alpine-release ]]; then
        echo "alpine"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/arch-release ]]; then
        echo "archlinux"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
ARCH=$(uname -m)

echo ""
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Docker Security Installation Tools   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "OS: ${YELLOW}$OS${NC}, arch: $ARCH"
echo ""

install_hadolint() {
    echo -e "${BLUE}[1/3] Installing Hadolint...${NC}"

    if command -v hadolint &>/dev/null; then
        local installed_ver
        installed_ver=$(hadolint --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "  ${YELLOW}Hadolint currently installed: v$installed_ver${NC}"
        return 0
    fi

    case "$OS" in
        macos)
            brew install hadolint
            ;;
        archlinux)            
            sudo pacman -S --needed --noconfirm base-devel git
            
            local current_dir=$(pwd)
            
            cd /tmp
            rm -rf hadolint-bin
            git clone https://aur.archlinux.org/hadolint-bin.git
            cd hadolint-bin
        
            makepkg -si --noconfirm
            
            cd "$current_dir"
            rm -rf /tmp/hadolint-bin
            ;;
        debian|alpine|rhel)
            local arch_suffix="x86_64"
            [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && arch_suffix="arm64"

            curl -L \
                "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${arch_suffix}" \
                -o /usr/local/bin/hadolint

            chmod +x /usr/local/bin/hadolint
            ;;
        *)
            echo -e "${RED}Unknown system: $OS${NC}"
            echo "Manual instalation: https://github.com/hadolint/hadolint/releases"
            return 1
            ;;
    esac

    if command -v hadolint &>/dev/null; then
        echo -e "  ${GREEN}✓ Hadolint installed: $(hadolint --version)${NC}"
    fi
}

install_trivy() {
    echo -e "${BLUE}[2/3] Installing Trivy...${NC}"

    if command -v trivy &>/dev/null; then
        local installed_ver
        installed_ver=$(trivy --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "  ${YELLOW}Trivy currently installed: v$installed_ver${NC}"
        return 0
    fi

    case "$OS" in
        macos)
            brew install trivy
            ;;
        archlinux)
            sudo pacman -S --noconfirm trivy
            ;;
        debian)
            sudo apt-get install -y wget apt-transport-https gnupg lsb-release

            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
                gpg --dearmor | \
                sudo tee /usr/share/keyrings/trivy.gpg > /dev/null

            echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
                https://aquasecurity.github.io/trivy-repo/deb \
                $(lsb_release -sc) main" | \
                sudo tee /etc/apt/sources.list.d/trivy.list

            sudo apt-get update
            sudo apt-get install -y trivy
            ;;
        rhel)
            cat <<'EOF' | sudo tee /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
            sudo yum -y update
            sudo yum -y install trivy
            ;;
        alpine)
            local arch_suffix="Linux-64bit"
            [[ "$ARCH" == "aarch64" ]] && arch_suffix="Linux-ARM64"

            wget -qO- "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${arch_suffix}.tar.gz" | \
                tar xz -C /usr/local/bin trivy
            ;;
        *)
            echo -e "${RED}Unknown system: $OS${NC}"
            echo "Manual installation: https://github.com/aquasecurity/trivy/releases"
            return 1
            ;;
    esac

    if command -v trivy &>/dev/null; then
        echo -e "  ${GREEN}✓ Trivy installed: $(trivy --version | head -1)${NC}"

        echo -e "  ${BLUE}CVE database update...${NC}"
        trivy image --download-db-only 2>/dev/null || true
    fi
}

install_kyverno_cli() {
    echo -e "${BLUE}[3/3] Installing Kyverno CLI v$KYVERNO_CLI_VERSION...${NC}"

    if command -v kyverno &>/dev/null; then
        local installed_ver
        installed_ver=$(kyverno version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        echo -e "  ${YELLOW}Kyverno CLI currently installed: v$installed_ver${NC}"
        return 0
    fi

    case "$OS" in
        macos)
            brew install kyverno
            ;;
        archlinux)
            echo -e "  ${BLUE}Installing kyverno-cli from AUR...${NC}"
            
            if command -v yay &>/dev/null; then
                yay -S --noconfirm kyverno-cli-bin
            elif command -v paru &>/dev/null; then
                paru -S --noconfirm kyverno-cli-bin
            else
                echo -e "  ${YELLOW}No AUR helper found. Building manually via makepkg...${NC}"
                sudo pacman -S --needed --noconfirm base-devel git
                
                local current_dir=$(pwd)
                
                cd /tmp
                rm -rf kyverno-cli-bin
                git clone https://aur.archlinux.org/kyverno-cli-bin.git
                cd kyverno-cli-bin
                
                makepkg -si --noconfirm
                
                cd "$current_dir"
            fi
            ;;
        *)
            local arch_suffix="linux_amd64"
            [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && arch_suffix="linux_arm64"

            local download_url
            download_url="https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_CLI_VERSION}/kyverno-cli_${KYVERNO_CLI_VERSION}_${arch_suffix}.tar.gz"

            curl -L "$download_url" -o /tmp/kyverno.tar.gz
            tar xzf /tmp/kyverno.tar.gz -C /tmp kyverno 2>/dev/null || tar xzf /tmp/kyverno.tar.gz -C /tmp kyverno-cli
            chmod +x /tmp/kyverno*
            sudo mv /tmp/kyverno* /usr/local/bin/kyverno
            rm -f /tmp/kyverno.tar.gz
            ;;
    esac

    if command -v kyverno &>/dev/null; then
        echo -e "  ${GREEN}✓ Kyverno CLI installed: $(kyverno version 2>&1 | head -1)${NC}"
    fi
}

install_dependencies() {
    echo -e "${BLUE}[0/3] Installing dependencies...${NC}"

    if ! command -v jq &>/dev/null; then
        case "$OS" in
            macos) brew install jq ;;
            debian) sudo apt-get install -y jq ;;
            rhel) sudo yum install -y jq ;;
            alpine) apk add --no-cache jq ;;
            archlinux) sudo pacman -S --noconfirm jq ;;
        esac
        echo -e "  ${GREEN} ✓ jq installed${NC}"
    else
        echo -e "  ${GREEN} ✓ jq: $(jq --version)${NC}"
    fi

    if ! command -v python3 &>/dev/null; then
        case "$OS" in
            macos) brew install python3 ;;
            debian) sudo apt-get install -y python3 python3-yaml ;;
            rhel) sudo yum install -y python3 python3-pyyaml ;;
            alpine) apk add --no-cache python3 py3-yaml ;;
            archlinux) sudo pacman -S --noconfirm python python-pyyaml ;;
        esac
        echo -e "  ${GREEN}✓ python3 installed${NC}"
    else
        echo -e "  ${GREEN}✓ python3: $(python3 --version)${NC}"

        if ! python3 -c "import yaml" 2>/dev/null; then
            if [[ "$OS" == "archlinux" ]]; then
                sudo pacman -S --noconfirm python-pyyaml
            else
                pip3 install pyyaml 2>/dev/null || \
                    python3 -m pip install pyyaml 2>/dev/null || \
                    echo -e "  ${YELLOW}⚠ PyYAML unavailable - restricted YAML validation${NC}"
            fi
        fi
    fi
}

# Uruchom instalację
install_dependencies
echo ""
install_hadolint
echo ""
install_trivy
echo ""
install_kyverno_cli

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation finished!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "Run validation: ${BLUE}./scripts/validate.sh${NC}"
echo ""