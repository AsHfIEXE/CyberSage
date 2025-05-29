<p align="center">
  <img src="placeholder_logo.png" alt="CyberSage V2 Logo" width="150"/>
</p>

<h1 align="center">CyberSage V2</h1>

<p align="center">
  <strong>An Automated & Intelligent Web Security Assessment Suite</strong>
  <br />
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#toolset">Toolset</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#usage">Usage</a> •
  <a href="#troubleshooting">Troubleshooting</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <!-- Optional Badges: Replace with your actual links if you set them up -->
  <!-- <img src="https://img.shields.io/github/stars/yourusername/CyberSageV2?style=social" alt="GitHub Stars"> -->
  <!-- <img src="https://img.shields.io/github/forks/yourusername/CyberSageV2?style=social" alt="GitHub Forks"> -->
  <!-- <img src="https://img.shields.io/github/issues/yourusername/CyberSageV2" alt="GitHub Issues"> -->
  <!-- <img src="https://img.shields.io/github/license/yourusername/CyberSageV2" alt="License"> -->
</p>

---

**CyberSage V2** is a powerful, Flask-based web application meticulously engineered to automate and streamline the complex workflow of web security assessments and penetration testing. By orchestrating a suite of battle-tested open-source security tools, CyberSage V2 empowers security professionals, developers, and enthusiasts to efficiently uncover vulnerabilities, understand attack surfaces, and bolster web application defenses.

The platform offers a modern, intuitive web interface for initiating comprehensive scans, tracking their progress in real-time, and analyzing consolidated findings presented in an accessible and actionable format.

## ✨ Features

CyberSage V2 is packed with features designed to make web security assessments more effective and efficient:

*   🌐 **Intuitive Web UI:** A sleek and responsive user interface built with Tailwind CSS and Flowbite, providing a seamless experience for scan management and results visualization.
*   🛠️ **Modular & Extensible Tool Integration:** A flexible architecture allowing for easy addition and management of various security tools.
    *   *(List key tools here once reliably integrated, e.g., Subfinder, HTTPX, Nmap, Nuclei, Dalfox, etc.)*
*   📊 **Consolidated & Parsed Results:** Findings from multiple tools are aggregated, parsed, and stored centrally in an SQLite database, presented in a unified and digestible format.
*   📈 **Real-time Scan Monitoring:** Leverages Server-Sent Events (SSE) for live progress updates and tool status tracking directly within the browser.
*   📉 **Vulnerability Visualization:** Automatic generation of severity distribution charts (primarily from Nuclei) to quickly grasp the risk landscape.
*   🧠 **AI-Powered Insights (OpenRouter.ai Ready):**
    *   Framework to connect with various Large Language Models (LLMs) via OpenRouter.ai for generating human-readable summaries and insights from scan data.
    *   Requires an OpenRouter API key for full functionality; provides informative stubs otherwise.
*   ⚙️ **Configuration Driven:** Centralized `config/tools.yaml` for managing tool paths, API keys, and specific tool options, promoting maintainability and customization.
*   🚀 **Automated Workflow:** Orchestrates a logical flow of reconnaissance, crawling, scanning, and vulnerability assessment steps.
*   📄 **Structured Logging:** Detailed application and tool execution logs for effective debugging and audit trails.

*(placeholder for a screenshot of the dashboard or results page)*
`[Screenshot of CyberSageV2 UI]`

## 🏗️ Architecture Overview

CyberSage V2 follows a modular, multi-component architecture:

1.  **Flask Backend (`app.py`):**
    *   Serves the web interface and API endpoints.
    *   Orchestrates the scan workflow by calling individual tool modules.
    *   Manages database interactions (SQLite via `sqlite3`).
    *   Handles real-time progress updates via SSE.
2.  **Tool Modules (`tools/`):**
    *   Each Python file (e.g., `recon.py`, `scan.py`, `vuln_scan.py`) encapsulates logic for running specific categories of security tools.
    *   `common.py` provides shared utilities like command execution and configuration loading.
3.  **Configuration (`config/tools.yaml`):**
    *   Externalizes tool paths, API keys, and operational parameters, allowing for easy customization without code changes.
4.  **Frontend (HTML, CSS, JavaScript):**
    *   `templates/` contains Jinja2 HTML templates for the user interface.
    *   `static/` serves CSS (Tailwind via CDN) and client-side JavaScript for interactivity and SSE handling.
5.  **Database (SQLite):**
    *   Stores scan metadata, raw outputs (optional/links), parsed results from tools, and AI summaries.
6.  **External Security Tools:**
    *   The suite of open-source tools that perform the actual security assessment tasks. CyberSage V2 acts as an orchestrator and data aggregator for these tools.

## 🧰 Core Toolset

CyberSage V2 integrates the following open-source tools (ensure they are installed and correctly configured in `config/tools.yaml`):

*   **Reconnaissance:**
    *   `Subfinder`: Subdomain discovery.
    *   `HTTPX` (ProjectDiscovery): Fast HTTP/HTTPS probing and tech detection.
    *   `Katana`: Advanced crawling and spidering.
    *   `Dirsearch`: Directory and file brute-forcing.
*   **Scanning:**
    *   `Nmap`: Network exploration and port scanning.
    *   `testssl.sh`: Comprehensive SSL/TLS scanner.
    *   `WhatWeb`: Web technology identification.
    *   `Nikto`: Web server vulnerability scanning.
*   **Vulnerability Assessment:**
    *   `Nuclei`: Template-based vulnerability scanning.
    *   `Dalfox`: Parameter analysis and XSS scanning.
    *   `SQLMap`: SQL injection detection and exploitation (basic checks implemented).
*   **Exploit Information:**
    *   `SearchSploit`: Exploit database lookup (currently for reference).

## 🚀 Getting Started

Follow these steps to get CyberSage V2 up and running on your system (Debian/Ubuntu based Linux recommended):

### Prerequisites

*   Python 3.8+
*   `pip` and `venv`
*   Go 1.19+ (with `$GOPATH/bin` or `$HOME/go/bin` in your system `PATH`)
*   Git, Curl, Wget
*   Standard build tools (`build-essential`, `pkg-config`, etc.)

### Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/yourusername/CyberSageV2.git # Replace with your repo URL
    cd CyberSageV2
    ```

2.  **Run the Installation Script:**
    This script attempts to install system dependencies, Go tools, and clones Git-based tools.
    ```bash
    chmod +x install.sh
    ./install.sh
    ```
     внимательно review the output. Some tools might require manual path configuration or dependency resolution.
    **After running `install.sh`, RESTART YOUR TERMINAL or source your shell profile (e.g., `source ~/.bashrc`) for PATH changes to take effect.**

3.  **Verify Tool Paths & Configure API Keys:**
    *   Open `config/tools.yaml`.
    *   **Crucially, update `tool_paths` with the correct absolute paths** to your installed tools if they are not found via system `PATH`. This is especially important for Go binaries (e.g., `httpx`, `nuclei`) and tools cloned into specific directories (e.g., `/opt/testssl.sh/testssl.sh`).
    *   Add your OpenRouter.ai API key to `openai_api_key` to enable AI summarization features.

4.  **Set Up Python Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    # Ensure httpx CLI extras for Python's httpx library (if used by any dependency, though we aim for PD's httpx)
    # pip install "httpx[cli,http2]" --upgrade # Typically handled by requirements if specified
    ```

### Running CyberSage V2

1.  **Activate Virtual Environment:**
    ```bash
    source venv/bin/activate
    ```
2.  **Start the Flask Application:**
    ```bash
    python3 app.py
    ```
3.  **Access in Browser:**
    Open your web browser and navigate to `http://127.0.0.1:5000`.

## 📖 Usage Guide

1.  **Initiate a Scan:**
    *   On the main page (`/`), enter the target domain (e.g., `example.com`) or a full URL (e.g., `http://testphp.vulnweb.com`).
    *   Click "Start Scan".
2.  **Monitor Progress:**
    *   Scan progress will be displayed in real-time on the same page, showing updates from each tool stage.
    *   The scan ID will also be displayed.
3.  **View Results:**
    *   Once the scan completes, the "Start Scan" button will change to "View Results". Clicking it will take you to the detailed results page for that scan (`/results/<scan_id>`).
    *   The results page features:
        *   Overall scan summary and AI-generated insights.
        *   Vulnerability severity distribution chart.
        *   Tabbed sections for detailed findings from each tool category (Reconnaissance, Scanning, Web Server, SSL/TLS, Exploits, and a consolidated Vulnerabilities table).
        *   Interactive filtering for the main vulnerabilities table.
        *   Modal pop-ups for viewing full details of individual vulnerabilities.

*(placeholder for a GIF showing the scan process and results view)*
`[GIF of CyberSageV2 in action]`

## 🔧 Troubleshooting

*   **`Tool Not Found` / `command not found`:**
    *   Verify `install.sh` completed successfully for the specific tool.
    *   **Ensure the absolute path to the tool's executable is correctly specified in `config/tools.yaml` under `tool_paths`.**
    *   For Go tools, ensure `$HOME/go/bin` is in your `PATH` environment variable and that this `PATH` is active in the terminal session running `python3 app.py`.
*   **HTTPX Flag Errors (`No such option: -l / -list / -jsonl`):**
    *   This strongly indicates that the system is finding Python's `httpx` CLI wrapper instead of ProjectDiscovery's Go-based `httpx`.
    *   **Solution:** Ensure `tool_paths.httpx` in `config/tools.yaml` points to the *absolute path* of your ProjectDiscovery `httpx` binary (e.g., `/home/youruser/go/bin/httpx`). Reinstall it with `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` if unsure. Manually test the binary with `-list <file>` and `-jsonl` flags.
*   **Dirsearch/Nikto/SQLMap not found or errors:**
    *   Ensure they were cloned by `install.sh` to the directories specified in `config/tools.yaml` (`/opt/...`).
    *   Dirsearch might need its Python dependencies installed: `cd /opt/dirsearch && sudo python3 -m pip install -r requirements.txt`.
    *   Nikto requires Perl.
*   **Flask `BuildError` for `url_for('...')`:** A route for the specified endpoint is missing in `app.py`, or there's a typo in the `url_for` call within an HTML template. Check HTML comments too, as Jinja processes them.
*   **Python `NameError` or `AttributeError` in `.py` files:** Usually typos or scope issues. Check the traceback from the Flask console carefully.
*   **UI Data Not Displaying:**
    *   Check Flask console logs for errors during tool execution or data fetching in `app.py`'s `results_page`.
    *   Inspect the raw tool output files in `~/.cybersage_v2/tool_outputs_raw/`.
    *   Verify data is being correctly stored in `~/.cybersage_v2/cybersage_v2.db` (you can use an SQLite browser).
    *   Check browser console for JavaScript errors on the results page.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check [issues page](https://github.com/yourusername/CyberSageV2/issues).

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE.txt` for more information.
*(Create a LICENSE.txt file with the MIT License text if you choose this license).*

## ⚠️ Disclaimer

CyberSage V2 is a powerful tool intended for **educational purposes and authorized security testing only**. Misuse of this software for unauthorized activities against systems you do not own or have explicit permission to test is illegal and unethical. The authors and contributors are not responsible for any misuse or damage caused by this tool. **Use responsibly and ethically.**

---

<p align="center">
  Made with ❤️ by [Your Name/Team Name]
</p>