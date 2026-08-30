#!/usr/bin/env bash
set -euo pipefail

# Bash 3.2 compatible (macOS safe) installer for Red Team Framework tools.
TIER=${1:-min}
PLATFORM=$(uname)

echo "==> Platform: $PLATFORM | Tier: $TIER"
echo "[*] Provisioning external toolchain mapped to framework TOOLS_REGISTRY..."

# Detect active virtualenv pip for --user-incompatible installs
_venv_pip=""
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV:-}/bin/pip" ]; then
    _venv_pip="${VIRTUAL_ENV:-}/bin/pip"
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV:-}/bin/pip3" ]; then
    _venv_pip="${VIRTUAL_ENV:-}/bin/pip3"
fi

do_install() {
    local tool="$1"
    local cmd="$2"
    echo "  [-] Installing $tool..."
    eval "$cmd" && echo "     [OK] $tool installed successfully." || echo "     [WARN] Failed to install $tool (manual setup may be required)."
}

if [[ "$PLATFORM" == "Darwin" ]]; then
    which pipx &>/dev/null || { 
        echo "[-] Installing pipx for safe Python tool management..."
        brew install pipx
        python3 -m ensurepip --default-pip 2>/dev/null
        python3 -m pip install --user pipx 2>/dev/null
        python3 -m pipx ensurepath 2>/dev/null
    }

    if [[ "$TIER" == "min" ]]; then
        do_install "subfinder"   "brew install subfinder"
        do_install "nmap"        "brew install nmap"
        do_install "nuclei"      "brew install nuclei"
        do_install "searchsploit" "brew install exploitdb"

    elif [[ "$TIER" == "plus" ]]; then
        # Recon
        do_install "subfinder"   "brew install subfinder"
        do_install "amass"       "brew install amass"
        do_install "dnsrecon"    "pipx install dnsrecon"
        
        # Discovery
        do_install "nmap"        "brew install nmap"
        do_install "httpx"       "brew install httpx"
        do_install "gobuster"    "brew install gobuster"
        
        # Exploitation
        do_install "nuclei"      "brew install nuclei"
        do_install "searchsploit" "brew install exploitdb"
        do_install "hydra"       "brew install hydra"
        
        # Post-Exploit & Lateral Movement
        do_install "netexec"     'pipx install "git+https://github.com/Pennyw0rth/NetExec" --python=/opt/homebrew/bin/python3.13'
        do_install "impacket"    "pipx install impacket"
        if [ -n "$_venv_pip" ]; then
            do_install "pypykatz"  "${_venv_pip} install pypykatz"
        else
            do_install "pypykatz"  "pipx install pypykatz --python=/opt/homebrew/bin/python3.13"
        fi
        do_install "sshpass"     "brew install sshpass"
        echo "  [-] Installing chisel..."
        _chisel_ver=$(curl -sL https://api.github.com/repos/jpillora/chisel/releases/latest | python3 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"][1:])')
        if curl -sL "https://github.com/jpillora/chisel/releases/latest/download/chisel_${_chisel_ver}_darwin_arm64.gz" -o /tmp/chisel.gz && gunzip -f /tmp/chisel.gz && sudo mv /tmp/chisel /usr/local/bin/; then
            echo "     [OK] chisel installed successfully."
        else
            echo "     [WARN] Failed to install chisel (manual setup may be required)."
        fi

    elif [[ "$TIER" == "full" ]]; then
        # Recon
        do_install "subfinder"   "brew install subfinder"
        do_install "amass"       "brew install amass"
        do_install "censys-cli"  "pipx install censys"
        do_install "shodan"      "brew install shodan"
        do_install "theharvester" 'pipx install "git+https://github.com/laramies/theHarvester"'
        do_install "dnsrecon"    "pipx install dnsrecon"
        echo "  [-] Installing waybackurls..."
        if go install github.com/tomnomnom/waybackurls@latest 2>/dev/null; then
            sudo cp "$(go env GOPATH)/bin/waybackurls" /usr/local/bin/ && echo "     [OK] waybackurls installed successfully." || echo "     [WARN] Failed to install waybackurls (manual setup may be required)."
        else
            echo "     [WARN] Failed to compile waybackurls from source."
        fi
        do_install "gau"         "brew install gau"
        
        # Discovery
        do_install "nmap"        "brew install nmap"
        do_install "masscan"     "brew install masscan"
        do_install "rustscan"    "brew install rustscan"
        do_install "httpx"       "brew install httpx"
        do_install "gobuster"    "brew install gobuster"

        # Exploitation
        do_install "nuclei"      "brew install nuclei"
        do_install "searchsploit" "brew install exploitdb"
        do_install "hydra"       "brew install hydra"
        do_install "medusa"      "brew install medusa"
        do_install "msfconsole"  "brew install metasploit"

        # Post-Exploit & Lateral Movement
        do_install "netexec"     'pipx install "git+https://github.com/Pennyw0rth/NetExec" --python=/opt/homebrew/bin/python3.13'
        do_install "impacket"    "pipx install impacket"
        if [ -n "$_venv_pip" ]; then
            do_install "pypykatz"  "${_venv_pip} install pypykatz"
        else
            do_install "pypykatz"  "pipx install pypykatz --python=/opt/homebrew/bin/python3.13"
        fi
        do_install "sshpass"     "brew install sshpass"
        do_install "evil-winrm"  'ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.rb)" args="--force" 2>/dev/null; /opt/homebrew/bin/gem install --user-install evil-winrm'
        echo "  [-] Installing chisel..."
        _chisel_ver=$(curl -sL https://api.github.com/repos/jpillora/chisel/releases/latest | python3 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"][1:])')
        if curl -sL "https://github.com/jpillora/chisel/releases/latest/download/chisel_${_chisel_ver}_darwin_arm64.gz" -o /tmp/chisel.gz && gunzip -f /tmp/chisel.gz && sudo mv /tmp/chisel /usr/local/bin/; then
            echo "     [OK] chisel installed successfully."
        else
            echo "     [WARN] Failed to install chisel (manual setup may be required)."
        fi
        
        # Exfiltration
        do_install "postgresql"  "brew install libpq"
        do_install "mysql"       "brew install mysql"
        do_install "mongodb"     "brew install mongodb/brew/mongodb-database-tools"

    else
        echo "[!] Usage: $0 [min|plus|full]"
        exit 1
    fi
else
    echo "[!] This installer is currently optimized for macOS (Darwin)."
    exit 1
fi

echo ""
echo "Toolchain provisioning complete. Verify with:"
echo "  python3 main.py --validate-config"
echo "  python3 main.py --dry-run"
