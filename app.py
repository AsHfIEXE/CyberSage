# CyberSageV2/app.py
import flask
from flask import (
    Flask, render_template, request, jsonify, Response, stream_with_context,
    g, redirect, url_for, flash
)
import sqlite3, os, uuid, threading, time, json, logging, yaml
from datetime import datetime
from urllib.parse import urlparse  # For URL parsing if needed

# Tool imports with more descriptive logging
try: from tools import scan as port_scan_module
except ImportError as e: port_scan_module = None; app_logger.warning(f"Could not import port_scan_module: {e}")
try: from tools import service_id
except ImportError as e: service_id = None; app_logger.warning(f"Could not import service_id: {e}")
try: from tools import dalfox_scan
except ImportError as e: dalfox_scan = None; app_logger.warning(f"Could not import dalfox_scan: {e}")
try: from tools import nikto_scan
except ImportError as e: nikto_scan = None; app_logger.warning(f"Could not import nikto_scan: {e}")
try: from tools import sqlmap_scan
except ImportError as e: sqlmap_scan = None; app_logger.warning(f"Could not import sqlmap_scan: {e}")
try: from tools import dirsearch_scan
except ImportError as e: dirsearch_scan = None; app_logger.warning(f"Could not import dirsearch_scan: {e}")
try: from tools import crawl
except ImportError as e: crawl = None; app_logger.warning(f"Could not import crawl: {e}")


from tools import recon, vuln_scan, exploit, parse, ai_assist # vuln_scan has Nuclei
from tools.common import TOOL_CONFIG, CYBERSAGE_BASE_DIR, load_config, logger as common_logger
from vuln_chart import generate_vuln_chart

app = Flask(__name__)
app.secret_key = os.urandom(24)
app_logger = common_logger; app_logger.name = "CyberSageApp"
log_file_path = os.path.join(CYBERSAGE_BASE_DIR, "cybersage_app.log")
file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s'))
if not any(isinstance(h, logging.FileHandler) and h.baseFilename == file_handler.baseFilename for h in app_logger.handlers):
    app_logger.addHandler(file_handler)
app_logger.setLevel(logging.DEBUG)

DATABASE_NAME = "cybersage_v2.db"; DATABASE_PATH = os.path.join(CYBERSAGE_BASE_DIR, DATABASE_NAME)
os.makedirs(CYBERSAGE_BASE_DIR, exist_ok=True)
STATIC_REPORTS_DIR = os.path.join(app.static_folder, 'reports'); os.makedirs(STATIC_REPORTS_DIR, exist_ok=True)

def get_db():
    db = getattr(g, '_database', None)
    if db is None: db = g._database = sqlite3.connect(DATABASE_PATH); db.row_factory = sqlite3.Row 
    return db
@app.teardown_appcontext
def close_connection(exception): ((db := getattr(g, '_database', None)) and db.close())
def init_db_schema():
    with app.app_context(): 
        db = get_db(); cursor = db.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, target TEXT, status TEXT, start_time DATETIME, end_time DATETIME, config_snapshot TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS tool_logs (log_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, tool_name TEXT, status TEXT, output TEXT, errors TEXT, target_info TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (scan_id) REFERENCES scans (scan_id))")
        cursor.execute("CREATE TABLE IF NOT EXISTS results (result_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, tool_name TEXT, result_type TEXT, data TEXT, target_info TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (scan_id) REFERENCES scans (scan_id))")
        cursor.execute("CREATE TABLE IF NOT EXISTS ai_summaries (summary_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, summary_text TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (scan_id) REFERENCES scans (scan_id))")
        db.commit(); app_logger.info("Database schema checked/initialized.")
with app.app_context(): init_db_schema()
scan_progress_messages = {} 

def send_progress(scan_id, tool_name, message, status="INFO", percent_complete=None):
    if scan_id not in scan_progress_messages: scan_progress_messages[scan_id] = []
    log_entry = {"timestamp": datetime.now().isoformat(), "tool": tool_name, "message": message, "status": status}
    if percent_complete is not None: log_entry["percent_complete"] = percent_complete
    scan_progress_messages[scan_id].append(log_entry)
    app_logger.debug(f"PROGRESS :: {scan_id} | {tool_name} | {status} | {message} | {percent_complete if percent_complete is not None else '--'}%")

def run_full_scan_orchestration(target_domain_or_url, scan_id):
    app_logger.info(f"Full scan starting: Target={target_domain_or_url}, ScanID={scan_id}")
    with app.app_context():
        db = get_db()
        tool_run_outcomes = { 
            "subfinder":0,"httpx":0,"katana":0,"dirsearch":0,"nmap":0,"testssl":0,"whatweb":0,
            "nuclei":0,"dalfox":0,"nikto":0,"sqlmap":0,
            "scan_flow_error_occurred": False 
        }
        def update_outcome(tool_key, items_found_count_or_error_flag):
            if items_found_count_or_error_flag == -1 : tool_run_outcomes[tool_key] = -1
            elif isinstance(items_found_count_or_error_flag, int) and items_found_count_or_error_flag > 0:
                tool_run_outcomes[tool_key] = items_found_count_or_error_flag
            elif isinstance(items_found_count_or_error_flag, bool) and items_found_count_or_error_flag:
                 tool_run_outcomes[tool_key] = 1 
        try:
            cursor = db.cursor(); cursor.execute("UPDATE scans SET status = 'running', start_time = CURRENT_TIMESTAMP WHERE scan_id = ?", (scan_id,)); db.commit()
            send_progress(scan_id, "Core", f"Scan started for target: {target_domain_or_url}", "STAGE_START", 5)
            primary_target_domain = target_domain_or_url.split("://")[-1].split("/")[0].split(":")[0] if "://" in target_domain_or_url else target_domain_or_url
            
            send_progress(scan_id, "Recon(Subfinder)", "Starting...", "INFO", 8)
            discovered_subdomains = recon.run_subdomain_discovery(primary_target_domain, scan_id, db)
            update_outcome("subfinder", len(discovered_subdomains))
            send_progress(scan_id, "Recon(Subfinder)", f"{len(discovered_subdomains)} subdomains found.", "SUCCESS" if discovered_subdomains else "INFO", 10)

            all_hosts_to_check_live = list(set([primary_target_domain] + discovered_subdomains))
            send_progress(scan_id, "Recon(HTTPX)", f"Probing {len(all_hosts_to_check_live)} hosts...", "INFO", 12)
            live_host_details_httpx = recon.run_live_host_identification(all_hosts_to_check_live, scan_id, db, primary_target_domain)
            update_outcome("httpx", len(live_host_details_httpx))
            live_web_urls_from_httpx = [h['url'] for h in live_host_details_httpx if h.get('url') and h.get('status_code',500) < 400 and ("http" in (h.get('scheme') or ''))]
            send_progress(scan_id, "Recon(HTTPX)", f"{len(live_web_urls_from_httpx)} live web URLs found.", "SUCCESS" if live_web_urls_from_httpx else "INFO", 15)
            
            all_discovered_endpoints = set(); urls_to_crawl = []
            if "http" in target_domain_or_url: urls_to_crawl.append(target_domain_or_url)
            urls_to_crawl.extend(u for u in live_web_urls_from_httpx if u not in urls_to_crawl)
            urls_to_crawl = list(set(urls_to_crawl))[:1] 
            
            if urls_to_crawl:
                for web_url in urls_to_crawl:
                    send_progress(scan_id, "Crawl(Katana)", f"Crawling {web_url}...", "INFO", 17)
                    endpoints = crawl.run_endpoint_discovery(web_url, scan_id, db)
                    if endpoints: all_discovered_endpoints.update(endpoints); update_outcome("katana", len(endpoints))
                    send_progress(scan_id, "Crawl(Katana)", f"{len(endpoints)} endpoints for {web_url}.", "SUCCESS" if endpoints else "INFO", 20)
            else: send_progress(scan_id, "Crawl(Katana)", "No URLs to crawl.", "INFO", 20)
            
            web_targets_for_scans = set(live_web_urls_from_httpx) | all_discovered_endpoints # Variable for accumulating web targets
            if "http" in target_domain_or_url: web_targets_for_scans.add(target_domain_or_url)

            if dirsearch_scan:
                dirsearch_base_targets = list(web_targets_for_scans)[:1] 
                if not dirsearch_base_targets and primary_target_domain: 
                    if not live_web_urls_from_httpx and not all_discovered_endpoints : 
                        dirsearch_base_targets.append(f"http://{primary_target_domain}") 
                for ds_target_url in dirsearch_base_targets:
                    send_progress(scan_id, "DirEnum(Dirsearch)", f"Starting for {ds_target_url}...", "INFO", 22)
                    dir_findings = dirsearch_scan.run_dirsearch(ds_target_url, scan_id, db)
                    if dir_findings: 
                        update_outcome("dirsearch", len(dir_findings))
                        for p in dir_findings: 
                            if p.get('path') and p.get('status_code',0) < 400: web_targets_for_scans.add(f"{ds_target_url.strip('/')}/{p['path'].strip('/')}")
                    send_progress(scan_id, "DirEnum(Dirsearch)", f"Completed. Found {len(dir_findings if dir_findings else [])} paths for {ds_target_url}.", "SUCCESS" if dir_findings else "INFO", 25)
            else: send_progress(scan_id, "DirEnum(Dirsearch)", "Skipped (module not loaded).", "INFO", 25)

            open_ports_with_service_glob = []
            if port_scan_module:
                nmap_hosts = list(set([primary_target_domain] + [url.split("://")[1].split("/")[0].split(":")[0] for url in live_web_urls_from_httpx if "://" in url]))
                if not nmap_hosts and primary_target_domain: nmap_hosts.append(primary_target_domain)
                
                for p_host in list(set(nmap_hosts))[:1]: 
                    send_progress(scan_id, "PortScan(Nmap)", f"Nmap on {p_host}...", "INFO", 30)
                    current_host_open_ports = port_scan_module.run_nmap_scan(p_host, scan_id, db)
                    if current_host_open_ports: update_outcome("nmap", len(current_host_open_ports)); open_ports_with_service_glob.extend(current_host_open_ports)
                    send_progress(scan_id, "PortScan(Nmap)", f"{len(current_host_open_ports)} open ports on {p_host}.", "SUCCESS" if current_host_open_ports else "INFO", 35)
                    
                    # Corrected AttributeError check here for SSL test logic
                    run_ssl = ("https" in target_domain_or_url.lower() and primary_target_domain.lower()==p_host.lower()) or \
                                   any(str(p.get('port')) in ['443','8443'] or 'ssl' in (p.get('tunnel','') or '').lower() or 'https' in (p.get('service','') or '').lower() for p in current_host_open_ports)
                    if run_ssl:
                        https_p = next((p.get('port') for p in current_host_open_ports if str(p.get('port')) in ['443','8443'] or 'ssl' in (p.get('tunnel','') or '').lower() or 'https' in (p.get('service','') or '').lower()), "443")
                        ssl_tgt = f"{p_host}:{https_p}"; send_progress(scan_id, "SSLTest", f"testssl.sh on {ssl_tgt}...", "INFO", 37)
                        ssl_res = port_scan_module.run_ssl_test(ssl_tgt, scan_id, db)
                        if ssl_res: update_outcome("testssl", 1 if ssl_res.get("key_issues") or ssl_res.get("overall_rating") not in ["N/A", "Likely Secure", "Likely Secure (No major issues)"] else 0)
                        send_progress(scan_id, "SSLTest", f"testssl.sh done for {ssl_tgt}.", "SUCCESS" if ssl_res else "INFO", 39)
                    
                    if service_id and current_host_open_ports:
                        for pd_item in current_host_open_ports: 
                            s_name_val=(pd_item.get('service')or'').lower(); p_num=str(pd_item.get('port')); p_tun=(pd_item.get('tunnel')or'').lower()
                            is_h=('http' in s_name_val) or p_num in ['80','443','3000','8000','8080','8443']; is_s=("https" in s_name_val) or p_num in ['443','8443'] or ('ssl' in p_tun)
                            if is_h:
                                proto="https" if is_s else "http"; tech_url=f"{proto}://{p_host}:{p_num}"
                                web_targets_for_scans.add(tech_url); # Add to the main set
                                send_progress(scan_id, "TechID(WhatWeb)", f"WhatWeb on {tech_url}...", "INFO", 42)
                                ww_r = service_id.run_tech_identification(tech_url, scan_id, db)
                                if ww_r: update_outcome("whatweb", tool_run_outcomes.get("whatweb",0)+1)
                                send_progress(scan_id, "TechID(WhatWeb)", f"WhatWeb done for {tech_url}.", "SUCCESS", 45)
            else: send_progress(scan_id, "Core", "Port/Service/SSL modules skipped.", "WARNING", 40)
            
            # Using corrected variable name `web_targets_for_scans`
            if not web_targets_for_scans and not ("http" in target_domain_or_url):
                send_progress(scan_id, "Core", f"No web targets. Assuming HTTP/S on {primary_target_domain}.", "WARNING")
                web_targets_for_scans.add(f"http://{primary_target_domain}"); web_targets_for_scans.add(f"https://{primary_target_domain}")

            unique_web_targets = list(set(u for u in web_targets_for_scans if isinstance(u, str) and u.startswith("http")))
            app_logger.info(f"Final Web Targets for Vuln Scans ({len(unique_web_targets)}): {unique_web_targets[:2]}...")

            # Define targets for tools using the corrected 'unique_web_targets'
            targets_nikto = unique_web_targets[:1]      # Corrected: was targets_for_nikto_final
            targets_nuclei = unique_web_targets[:1]     # Corrected: was targets_for_nuclei_final
            targets_dalfox = [t for t in unique_web_targets if "?" in t][:1]; 
            if not targets_dalfox and unique_web_targets: targets_dalfox = unique_web_targets[:1] # Corrected
            targets_sqlmap = targets_dalfox[:1]          # Corrected

            all_vuln_findings_for_ai = [] 

            if nikto_scan and targets_nikto: # CORRECTED
                for url in targets_nikto:    
                    send_progress(scan_id, "Scan(Nikto)", f"Nikto on {url}...", "INFO", 50)
                    nikto_res = nikto_scan.run_nikto(url, scan_id, db)
                    if nikto_res: update_outcome("nikto", len(nikto_res)); all_vuln_findings_for_ai.extend(nikto_res) 
                    send_progress(scan_id, "Scan(Nikto)", f"{len(nikto_res if nikto_res else [])} items for {url}.", "SUCCESS" if nikto_res is not None else "INFO", 55)
            else: send_progress(scan_id, "Scan(Nikto)", "Nikto skipped.", "INFO", 55)

            if targets_nuclei: # CORRECTED
                for url in targets_nuclei:
                    send_progress(scan_id, "VulnScan(Nuclei)", f"Nuclei on {url}...", "INFO", 60)
                    nuc_res = vuln_scan.run_nuclei_scan(url, scan_id, db)
                    if nuc_res: update_outcome("nuclei", tool_run_outcomes.get("nuclei",0) + len(nuc_res)); all_vuln_findings_for_ai.extend(nuc_res)
                    send_progress(scan_id, "VulnScan(Nuclei)", f"{len(nuc_res if nuc_res else [])} items for {url}.", "SUCCESS" if nuc_res is not None else "INFO", 65)
            else: send_progress(scan_id, "VulnScan(Nuclei)", "No targets for Nuclei.", "INFO", 65)

            if dalfox_scan and targets_dalfox: # CORRECTED
                for url in targets_dalfox:    
                    send_progress(scan_id, "XSS(Dalfox)", f"Dalfox on {url}...", "INFO", 70)
                    dalf_res = dalfox_scan.run_dalfox(url, scan_id, db)
                    if dalf_res: update_outcome("dalfox", len(dalf_res)); 
                    send_progress(scan_id, "XSS(Dalfox)", f"{len(dalf_res if dalf_res else [])} XSS for {url}.", "SUCCESS" if dalf_res is not None else "INFO", 75)
            else: send_progress(scan_id, "XSS(Dalfox)", "Dalfox skipped.", "INFO", 75)
            
            if sqlmap_scan and targets_sqlmap: # CORRECTED
                for url in targets_sqlmap:     
                    send_progress(scan_id, "SQLi(SQLMap)", f"SQLMap on {url} (basic)...", "INFO", 80)
                    sql_res = sqlmap_scan.run_sqlmap(url, scan_id, db)
                    if sql_res: update_outcome("sqlmap", len(sql_res)); 
                    send_progress(scan_id, "SQLi(SQLMap)", f"{len(sql_res if sql_res else [])} potential for {url}.", "SUCCESS" if sql_res is not None else "INFO", 85)
            else: send_progress(scan_id, "SQLi(SQLMap)", "SQLMap skipped.", "INFO", 85)
            
            send_progress(scan_id, "ExploitLookup", "SearchSploit...", "INFO", 88)
            exploit.run_exploit_checks(primary_target_domain, all_vuln_findings_for_ai, scan_id, db)
            send_progress(scan_id, "ExploitLookup", "Done.", "SUCCESS", 90)
            send_progress(scan_id, "Parse", "Parsing...", "INFO", 91); parse.parse_and_correlate_results(scan_id, db); send_progress(scan_id, "Parse", "Done.", "SUCCESS", 92)
            send_progress(scan_id, "AI Summary", "Generating...", "INFO", 94)
            
            normalized_ai_vulns = []
            all_db_vulns_for_ai_rows = db.execute("SELECT tool_name, result_type, data, target_info FROM results WHERE scan_id = ? AND result_type LIKE 'vulnerability_%'", (scan_id,)).fetchall()
            for r_item in all_db_vulns_for_ai_rows: 
                if r_item['data']:
                    try:
                        loaded_d = json.loads(r_item['data']); tool_n = r_item['tool_name']
                        if tool_n == "nuclei": normalized_ai_vulns.append(loaded_d) 
                        elif tool_n == "dalfox": normalized_ai_vulns.append({"info": {"name": f"Dalfox XSS: {loaded_d.get('param', loaded_d.get('type', 'Unknown'))}", "severity": "high", "description": loaded_d.get("poc","No PoC provided.")},"matched-at": loaded_d.get("url", r_item['target_info']), "tags": ["xss", "dalfox"]})
                        elif tool_n == "nikto": normalized_ai_vulns.append({"info": {"name": f"Nikto: {loaded_d.get('id', 'Finding')}", "severity": "medium", "description": loaded_d.get("msg")}, "matched-at": loaded_d.get("url", r_item['target_info']), "tags":["nikto"]})
                        elif tool_n == "sqlmap": normalized_ai_vulns.append({"info": {"name": f"SQLMap: {loaded_d.get('parameter', 'Injectable')}", "severity": "high", "description": loaded_d.get("notes")}, "matched-at": loaded_d.get("target_url", r_item['target_info']), "tags":["sqli", "sqlmap"]})
                    except json.JSONDecodeError: pass
            
            ai_summary_text = ai_assist.summarize_vulnerabilities_ai(normalized_ai_vulns, primary_target_domain)
            cursor.execute("INSERT INTO ai_summaries (scan_id, summary_text) VALUES (?, ?)", (scan_id, ai_summary_text)); db.commit()
            send_progress(scan_id, "AI Summary", "Generated.", "SUCCESS", 96)
            send_progress(scan_id, "ChartGen", "Generating Chart...", "INFO", 97)
            chart_path = os.path.join(STATIC_REPORTS_DIR, f'vuln_chart_{scan_id}.png')
            generate_vuln_chart(DATABASE_PATH, scan_id, chart_path)
            send_progress(scan_id, "ChartGen", "Chart done.", "SUCCESS",98)
            
            # Determine final status based on tool_run_outcomes (counts of findings)
            if tool_run_outcomes.get("scan_flow_error_occurred"): final_status = 'failed_exception'
            elif tool_run_outcomes.get("nuclei",0) > 0 or tool_run_outcomes.get("dalfox",0) > 0 or tool_run_outcomes.get("nikto",0) > 0 or tool_run_outcomes.get("sqlmap",0) > 0: final_status = 'completed_with_findings'
            elif tool_run_outcomes.get("httpx",0) > 0 and tool_run_outcomes.get("nmap",0) > 0 : final_status = 'completed_no_major_vulns'
            elif tool_run_outcomes.get("subfinder",0) > 0 : final_status = 'completed_recon_only'
            elif any(v == -1 for k,v in tool_run_outcomes.items() if k != "scan_flow_error_occurred"): final_status = 'completed_with_tool_errors'
            else: final_status = 'completed_no_significant_data'

            cursor.execute("UPDATE scans SET status = ?, end_time = CURRENT_TIMESTAMP WHERE scan_id = ?", (final_status, scan_id,)); db.commit()
            send_progress(scan_id, "Core", f"Scan {final_status.replace('_',' ').title()}.", "STAGE_END", 100)
            app_logger.info(f"Scan {scan_id} ({target_domain_or_url}) ended: {final_status}.")

        except Exception as e: # This is the main exception handler for the whole orchestration
            # Ensure tool_run_outcomes is defined before accessing, it's defined at the start of the outer try
            tool_run_outcomes["scan_flow_error_occurred"] = True 
            app_logger.error(f"CRITICAL SCAN EXCEPTION ScanID={scan_id}: {e}", exc_info=True)
            db_for_except = get_db() 
            try:
                cursor_except = db_for_except.cursor()
                cursor_except.execute("UPDATE scans SET status = 'failed_exception', end_time = CURRENT_TIMESTAMP WHERE scan_id = ?", (scan_id,))
                db_for_except.commit()
            except sqlite3.Error as db_err: app_logger.error(f"DB update to 'failed_exception' FAILED for {scan_id}: {db_err}")
            send_progress(scan_id, "Core", f"Scan CRITICALLY FAILED: {str(e)[:100]}...", "ERROR", 100)
        finally:
            if scan_id in scan_progress_messages: scan_progress_messages[scan_id].append({"tool":"Core", "message": "Scan ended.", "status":"INFO_FINAL"})
            app_logger.info(f"Scan orchestration thread finished: {scan_id}")

# --- Routes ---
@app.route('/', methods=['GET'])
def index(): return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan_route():
    target = request.form.get('target', '').strip()
    if not target: return jsonify({"error": "Target cannot be empty.", "success": False}), 400
    scan_id = str(uuid.uuid4()); app_logger.info(f"Scan request: {target}. ID: {scan_id}")
    current_config_snapshot = "{}"; 
    try: current_config_snapshot = json.dumps(load_config())
    except Exception as conf_e: app_logger.error(f"Error loading config for snapshot: {conf_e}")
    db = get_db()
    try:
        db.execute("INSERT INTO scans (scan_id, target, status, config_snapshot) VALUES (?, ?, ?, ?)", (scan_id, target, 'pending', current_config_snapshot)); db.commit()
    except sqlite3.Error as e: app_logger.error(f"DB error creating scan {scan_id}: {e}"); return jsonify({"error": f"DB error: {e}", "success": False}), 500
    threading.Thread(target=run_full_scan_orchestration, args=(target, scan_id), daemon=True).start()
    return jsonify({"success": True, "scan_id": scan_id, "message": "Scan initiated. Progress below."})

@app.route('/results/<scan_id>')
def results_page(scan_id):
    db = get_db(); scan_info_row = db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if not scan_info_row: flash(f"Scan ID '{scan_id}' not found.", "error"); return redirect(url_for('index'))

    scan_data = dict(scan_info_row)
    scan_data['start_time_str'] = datetime.fromisoformat(scan_data['start_time']).strftime('%Y-%m-%d %H:%M:%S') if scan_data.get('start_time') else 'N/A'
    scan_data['end_time_str'] = datetime.fromisoformat(scan_data['end_time']).strftime('%Y-%m-%d %H:%M:%S') if scan_data.get('end_time') else 'N/A'
    
    results_for_template = { 
        "summaries": {},"subdomains": [],"live_hosts_httpx": [], "crawled_endpoints": [], 
        "ports": [],"services": [], "tech_id": [], "ssl_tests": [], 
        "dirsearch_paths": [], "nikto_findings": [], "sqlmap_findings": [], 
        "vulnerabilities": [], "exploit_refs": []
    }

    def safe_json_load_list(rows, key_to_extract=None):
        data_list = []; 
        for r_idx, r in enumerate(rows):
            if r['data']:
                try: 
                    loaded = json.loads(r['data'])
                    if key_to_extract: data_list.append(loaded[key_to_extract]) if isinstance(loaded, dict) and key_to_extract in loaded else None
                    else: data_list.append(loaded)
                except (json.JSONDecodeError, KeyError, TypeError) as e: 
                    logger.warning(f"JSON/Key/Type error for scan {scan_id}, type {r['result_type'] if isinstance(r, sqlite3.Row) and 'result_type' in r.keys() else 'unknown'}, row {r_idx}: {str(r['data'])[:100]}. Error: {e}")
        return [item for item in data_list if item is not None]

    results_for_template['subdomains'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND result_type='subdomain_discovered'", (scan_id,)).fetchall(), 'subdomain')
    results_for_template['live_hosts_httpx'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND tool_name='httpx' AND result_type='live_host_detail_httpx'", (scan_id,)).fetchall())
    results_for_template['crawled_endpoints'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND tool_name='katana' AND result_type='endpoint_katana_detail'", (scan_id,)).fetchall())
    results_for_template['dirsearch_paths'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND tool_name='dirsearch' AND result_type='directory_listing'", (scan_id,)).fetchall())
    results_for_template['nikto_findings'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND tool_name='nikto' AND result_type='vulnerability_nikto'", (scan_id,)).fetchall())
    results_for_template['sqlmap_findings'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND tool_name='sqlmap' AND result_type='vulnerability_sqlmap'", (scan_id,)).fetchall())
    
    nmap_data = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND tool_name='nmap' AND result_type='open_port_service_detail'", (scan_id,)).fetchall())
    for item in nmap_data:
        results_for_template['ports'].append({"ip": item.get('host', scan_data.get('target','N/A')), "port": item.get('port'), "protocol": item.get('protocol','tcp'), "state": item.get('state','open')})
        results_for_template['services'].append({"host": item.get('host', scan_data.get('target','N/A')),"port": item.get('port'),"service": item.get('service'),"version": f"{item.get('product','')} {item.get('version','')} {item.get('extrainfo','')}".strip(), "scripts_summary": f"{len(item.get('scripts',[]))} scripts" if item.get('scripts') else "", "banner": (item.get('banner') or '')[:100]+"..."})
    
    whatweb_rows = db.execute("SELECT data, target_info, result_type FROM results WHERE scan_id=? AND tool_name='whatweb' AND result_type='technology_whatweb'", (scan_id,)).fetchall()
    for row in whatweb_rows: 
        if row['data']: results_for_template['tech_id'].append({"target_url": row["target_info"], "data": json.loads(row["data"])})
    
    results_for_template['ssl_tests'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id=? AND tool_name='testssl' AND result_type='ssl_test_summary'", (scan_id,)).fetchall())

    all_tool_vulns_for_table = []
    nuclei_db_vulns = safe_json_load_list(db.execute("SELECT data, target_info, result_type FROM results WHERE scan_id = ? AND tool_name = 'nuclei' AND result_type = 'vulnerability_nuclei'", (scan_id,)).fetchall())
    for vuln_data in nuclei_db_vulns: 
        info = vuln_data.get('info', {}); all_tool_vulns_for_table.append({"scan_tool": "Nuclei", "data": vuln_data, "affected_url": vuln_data.get('matched-at', vuln_data.get('host', 'N/A')), "severity": info.get('severity', 'unknown').capitalize(), "type": info.get('name',"Nuclei Finding"), "description": info.get('description','N/A')[:150]+"...", "tags":(", ".join(info.get('tags',[])) if info.get('tags') else "N/A")}) # Ensure tags is string
    dalfox_db_vulns = safe_json_load_list(db.execute("SELECT data, target_info, result_type FROM results WHERE scan_id = ? AND tool_name = 'dalfox' AND result_type = 'vulnerability_dalfox_xss'", (scan_id,)).fetchall())
    for vuln_data in dalfox_db_vulns:
        poc=vuln_data.get('PoC',vuln_data.get('poc',vuln_data.get('data',{}))); desc=str(poc)[:150]+"..." if poc else "Dalfox XSS"; param=vuln_data.get('paramKey',vuln_data.get('param','N/A')); 
        all_tool_vulns_for_table.append({"scan_tool": "Dalfox", "data": vuln_data, "affected_url": vuln_data.get('url', vuln_data.get('target_info', 'N/A')), "severity":"High", "type":f"XSS ({vuln_data.get('@type',vuln_data.get('type','Dalfox'))}) in {param}", "description":desc, "tags":f"Method: {vuln_data.get('method','N/A')}"})
    for item_data in results_for_template['nikto_findings']: 
        all_tool_vulns_for_table.append({"scan_tool":"Nikto", "data": item_data, "affected_url": item_data.get('url', item_data.get('target_url','N/A')), "severity": (item_data.get('severity') or "Medium").capitalize(), "type":item_data.get('id',"Nikto Finding"), "description":item_data.get('msg','')[:150]+"...", "tags": item_data.get('osvdbid','') or "N/A"})
    for item_data in results_for_template['sqlmap_findings']: 
        all_tool_vulns_for_table.append({"scan_tool":"SQLMap", "data": item_data, "affected_url": item_data.get('target_url','N/A'), "severity":(item_data.get('severity') or "High").capitalize(), "type":f"SQLi in {item_data.get('parameter')}", "description":item_data.get('notes','')[:150]+"...", "tags": "SQL Injection"})
        
    severity_order_map = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"unknown":5}
    all_tool_vulns_for_table.sort(key=lambda v: severity_order_map.get(v.get('severity','unknown').lower(), 99))
    results_for_template['vulnerabilities'] = all_tool_vulns_for_table

    results_for_template['exploit_refs'] = safe_json_load_list(db.execute("SELECT data, result_type FROM results WHERE scan_id = ? AND tool_name = 'searchsploit_lookup' AND result_type = 'exploit_reference'", (scan_id,)).fetchall())
    
    summary_row = db.execute("SELECT summary_text FROM ai_summaries WHERE scan_id=? ORDER BY timestamp DESC LIMIT 1", (scan_id,)).fetchone()
    results_for_template['summaries']['AI Analysis'] = summary_row['summary_text'] if summary_row and summary_row['summary_text'] else "AI summary processing or no applicable findings."
    
    overview_parts = []
    if results_for_template['subdomains']: overview_parts.append(f"{len(results_for_template['subdomains'])} subdomains")
    if results_for_template['ports']: overview_parts.append(f"{len(results_for_template['ports'])} open ports")
    if results_for_template['vulnerabilities']: overview_parts.append(f"{len(results_for_template['vulnerabilities'])} potential vulnerabilities") 
    results_for_template['summaries']['Scan Overview'] = "Scan Data: " + ", ".join(overview_parts) + "." if overview_parts else "Scan completed. No specific items (subdomains, ports, vulnerabilities) were found/logged from successful tool runs. Check individual tool logs or if critical tools failed."

    chart_file = f'reports/vuln_chart_{scan_id}.png'; scan_data['chart_path'] = url_for('static', filename=chart_file) if os.path.exists(os.path.join(app.static_folder, chart_file)) else None
    scan_data['timestamp_for_cache_bust'] = int(time.time())
    
    return render_template('result.html', scan=scan_data, **results_for_template)

@app.route('/progress/<scan_id>')
def progress_feed(scan_id): 
    def generate_feed():
        last_sent_index = 0 
        try:
            while True:
                current_messages = scan_progress_messages.get(scan_id, [])
                if last_sent_index < len(current_messages):
                    for msg_obj in current_messages[last_sent_index:]: yield f"data: {json.dumps(msg_obj)}\n\n"
                    last_sent_index = len(current_messages)
                if any(m.get("status") == "INFO_FINAL" for m in current_messages[last_sent_index:]):
                    yield f"data: {json.dumps({'tool':'Core', 'message': 'SSE_STREAM_END', 'status': 'END_OF_STREAM'})}\n\n"; break 
                time.sleep(0.2) 
        except GeneratorExit: app_logger.info(f"SSE client closed: {scan_id}")
        finally: app_logger.info(f"SSE Stream finished: {scan_id}.")
    return Response(stream_with_context(generate_feed()), mimetype='text/event-stream')

@app.route('/config_viewer')
def config_viewer():
    try:
        current_config = load_config() 
        config_display_string = yaml.dump(current_config, indent=2, sort_keys=False, allow_unicode=True, default_flow_style=False)
    except Exception as e:
        app_logger.error(f"Failed to load or dump config for viewer: {e}")
        config_display_string = f"Error loading configuration: {str(e)}"
    return render_template('config_viewer.html', config_data=config_display_string)

if __name__ == '__main__':
    app_logger.info("Starting CyberSage (Full Suite Integrated)...")
    app.run(debug=True, host='127.0.0.1', port=5000, threaded=True) 