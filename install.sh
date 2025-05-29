#!/bin/bash
echo "CyberSage V2 Installer - Full Suite"
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})
CYBERSAGE_INSTALL_DIR="$USER_HOME/.cybersage_install_temp"
CYBERSAGE_V2_DATA_DIR="$USER_HOME/.cybersage_v2"
CYBERSAGE_PROJECT_DIR=$(pwd) 
mkdir -p "$CYBERSAGE_INSTALL_DIR" "$CYBERSAGE_V2_DATA_DIR" "$CYBERSAGE_V2_DATA_DIR/wordlists"
mkdir -p "$CYBERSAGE_PROJECT_DIR/static/reports"

command_exists() { command -v "$1" >/dev/null 2>&1; }

# --- System Dependencies ---
echo "[INFO] System dependencies (apt)..."
if command_exists apt-get; then
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-pip python3-venv git curl wget nmap \
                           libpcap-dev pkg-config libssl-dev build-essential \
                           ruby ruby-dev zlib1g-dev procps openssl perl
else echo "[WARNING] apt-get not found. Install manually."; fi

# --- Golang ---
GO_VERSION_NEEDED="1.19"
GO_INSTALLED_VERSION=""
if command_exists go; then GO_INSTALLED_VERSION=$(go version | awk '{print $3}' | sed 's/go//'); fi

if ! command_exists go || dpkg --compare-versions "$GO_INSTALLED_VERSION" "lt" "$GO_VERSION_NEEDED"; then
    echo "[INFO] Go not found or version too low. Installing Go..."
    LATEST_GO_VERSION=$(curl -sSL "https://golang.org/VERSION?m=text" | head -n 1 | sed 's/go//')
    echo "[INFO] Latest Go: $LATEST_GO_VERSION. Downloading..."
    wget -q "https://golang.org/dl/go${LATEST_GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz && \
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz && \
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/golang_path.sh && \
    export PATH=$PATH:/usr/local/go/bin && echo "[INFO] Go installed." || echo "[ERROR] Go install failed."
else echo "[INFO] Go $GO_INSTALLED_VERSION found."; fi

export GOPATH="$HOME/go"; export GOBIN="$GOPATH/bin"; export PATH="$PATH:$GOBIN" 
mkdir -p "$GOPATH/src" "$GOPATH/pkg" "$GOBIN"
# Add to user's .bashrc if not present (for persistence)
if ! grep -q "GOPATH/bin" "$HOME/.bashrc"; then echo -e '\n# GoLang User Path\nexport GOPATH="$HOME/go"\nexport PATH="$PATH:$GOPATH/bin"' >> "$HOME/.bashrc"; fi


# --- Install Go-based Tools ---
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/hahwul/dalfox/v2@latest"
)
echo "[INFO] Installing Go-based tools (to \$HOME/go/bin)..."
if command_exists go; then
    for tool_path in "${GO_TOOLS[@]}"; do
        tool_name=$(basename "$tool_path" | cut -d'@' -f1)
        echo "Installing $tool_name..."
        if go install -v "$tool_path"; then echo "[SUCCESS] $tool_name installed."; 
        else echo "[ERROR] Failed to install $tool_name. Check Go env and network. Try 'go install -v $tool_path' manually."; fi
    done
    if command_exists nuclei; then echo "Updating Nuclei templates..."; nuclei -update-templates -ud "$USER_HOME/nuclei-templates"; fi # Specify update dir
else echo "[ERROR] Go command not found. Skipping Go-based tools."; fi

# --- Install Other Tools ---
echo -e "\n[INFO] Installing other specified tools..."
# WhatWeb
if ! command_exists whatweb; then
    echo "Installing WhatWeb via RubyGems..."
    if command_exists gem; then sudo gem install whatweb --silent --no-document; if command_exists whatweb; then echo "[SUCCESS] WhatWeb installed via gem."; else echo "[ERROR] Failed via gem."; fi
    else echo "[ERROR] Ruby 'gem' not found."; fi
else echo "WhatWeb already installed."; fi

# testssl.sh
TESTSSL_DIR="/opt/testssl.sh" 
if [ ! -d "$TESTSSL_DIR" ]; then
    echo "Installing testssl.sh to $TESTSSL_DIR..."
    if sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$TESTSSL_DIR"; then
        echo "[SUCCESS] testssl.sh cloned to $TESTSSL_DIR."
        echo "       Make sure $TESTSSL_DIR/testssl.sh is executable."
        sudo chmod +x "$TESTSSL_DIR/testssl.sh"
    else echo "[ERROR] Failed to clone testssl.sh."; fi
else
    echo "testssl.sh directory already exists at $TESTSSL_DIR. Skipping clone."
    if [ -f "$TESTSSL_DIR/testssl.sh" ] && [ ! -x "$TESTSSL_DIR/testssl.sh" ]; then
        sudo chmod +x "$TESTSSL_DIR/testssl.sh"
    fi
fi

# Nikto
NIKTO_DIR="/opt/nikto"
if [ ! -d "$NIKTO_DIR/program" ]; then 
    echo "Installing Nikto to $NIKTO_DIR..."
    if sudo git clone https://github.com/sullo/nikto.git "$NIKTO_DIR"; then echo "[SUCCESS] Nikto cloned."; else echo "[ERROR] Nikto clone failed."; fi
else echo "Nikto dir $NIKTO_DIR exists."; fi

# Dirsearch
DIRSEARCH_DIR="/opt/dirsearch"
if [ ! -d "$DIRSEARCH_DIR" ]; then
    echo "Installing Dirsearch to $DIRSEARCH_DIR..."
    if sudo git clone https://github.com/maurosoria/dirsearch.git "$DIRSEARCH_DIR"; then echo "[SUCCESS] Dirsearch cloned."; else echo "[ERROR] Dirsearch clone failed."; fi
else echo "Dirsearch dir $DIRSEARCH_DIR exists."; fi

# SQLMap
SQLMAP_DIR="/opt/sqlmap"
if [ ! -d "$SQLMAP_DIR" ]; then
    echo "Installing SQLMap to $SQLMAP_DIR..."
    if sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$SQLMAP_DIR"; then echo "[SUCCESS] SQLMap cloned."; else echo "[ERROR] SQLMap clone failed."; fi
else echo "SQLMap directory $SQLMAP_DIR already exists."; fi


# --- Wordlist ---
CYBERSAGE_V2_WORDLIST_DIR="$USER_HOME/.cybersage_v2/wordlists"
mkdir -p "$CYBERSAGE_V2_WORDLIST_DIR"
WORDLIST_PATH_V2="$CYBERSAGE_V2_WORDLIST_DIR/common.txt" # Match config
if [ ! -f "$WORDLIST_PATH_V2" ]; then
    echo "[INFO] Downloading common wordlist to $WORDLIST_PATH_V2..."
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O "$WORDLIST_PATH_V2"
    if [ -f "$WORDLIST_PATH_V2" ]; then echo "[SUCCESS] Wordlist downloaded."; else echo "[ERROR] Failed to download wordlist to $WORDLIST_PATH_V2."; fi
else echo -e "\n[INFO] Wordlist $WORDLIST_PATH_V2 already exists."; fi


# --- Python Virtual Environment ---
echo "[INFO] Setting up Python virtual environment..."
if [ ! -d "$CYBERSAGE_PROJECT_DIR/venv" ]; then python3 -m venv "$CYBERSAGE_PROJECT_DIR/venv"; fi
# shellcheck source=/dev/null
source "$CYBERSAGE_PROJECT_DIR/venv/bin/activate"
echo "Installing Python dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r "$CYBERSAGE_PROJECT_DIR/requirements.txt"
pip install "httpx[cli,http2]" --upgrade
deactivate
echo "Python dependencies installed."

echo -e "\n-----------------------------------------------------"
echo "CyberSage V2 Installation Attempt Finished!"
echo "-----------------------------------------------------"
echo "IMPORTANT NEXT STEPS:"
echo "1. Add \$HOME/go/bin to your PATH if not already: source ~/.bashrc (or .zshrc, .profile)"
echo "   OR RESTART YOUR TERMINAL SESSION for PATH changes to take full effect."
echo "2. Verify tool paths in 'config/tools.yaml', especially for 'testssl_dir'."
echo "3. If HTTPX still gives CLI errors, manually run in venv: pip uninstall httpx -y && pip install \"httpx[cli,http2]\" --no-cache-dir --force-reinstall"
echo "4. To run: cd $CYBERSAGE_PROJECT_DIR && source venv/bin/activate && python3 app.py"
echo "-----------------------------------------------------"