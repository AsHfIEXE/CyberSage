# CyberSageV2/tools/sqlmap_scan.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger, CYBERSAGE_BASE_DIR
from .common import db_log_tool_run, db_store_structured_result
import os, re, json, glob

def run_sqlmap(target_url_with_params, scan_id, db_conn):
    tool_name = "sqlmap"; sqlmap_base_dir = get_tool_path("sqlmap_dir")
    sqlmap_script_name = TOOL_CONFIG.get("tool_paths",{}).get("sqlmap_script_name", "sqlmap.py")
    tool_status = "failed_to_start"; findings = []

    if not sqlmap_base_dir or not os.path.isdir(sqlmap_base_dir):
        logger.error(f"SQLMap dir '{sqlmap_base_dir}' missing."); db_log_tool_run(db_conn,scan_id,tool_name,"config_error_path","","",target_url_with_params); return findings
    tool_executable = os.path.join(sqlmap_base_dir, sqlmap_script_name)
    if not os.path.exists(tool_executable):
        logger.error(f"SQLMap script '{tool_executable}' missing."); db_log_tool_run(db_conn,scan_id,tool_name,"config_error_script","","",target_url_with_params); return findings

    level = TOOL_CONFIG.get("sqlmap_level", 1); risk = TOOL_CONFIG.get("sqlmap_risk", 1)
    sqlmap_opts_str = TOOL_CONFIG.get("sqlmap_options", "--batch --random-agent --smart --threads=3 --crawl=0") # Default config options
    
    sqlmap_output_dir = os.path.join(CYBERSAGE_BASE_DIR, "sqlmap_outputs", scan_id, "".join(c if c.isalnum() else '_' for c in target_url_with_params.split("://")[-1])[:50] )
    os.makedirs(sqlmap_output_dir, exist_ok=True)

    cmd = ["python3", tool_executable, "-u", target_url_with_params, "--level", str(level), "--risk", str(risk)]
    cmd.extend(sqlmap_opts_str.split()) 
    cmd.extend(["--output-dir", sqlmap_output_dir]) # Ensure output dir is always set

    logger.info(f"Running SQLMap on {target_url_with_params}. Command: {' '.join(cmd)}")
    raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, target_url_with_params, 3600, cwd=sqlmap_base_dir) # Increased timeout to 1 hour

    # Enhanced parsing - check session file for more reliable results
    log_file_path = os.path.join(sqlmap_output_dir, "log") # Main log file from sqlmap run
    target_session_file_path = None # Path to target-specific session file if created

    # SQLMap creates a directory structure like: output_dir/hostname/session.sqlite
    # We need to find the actual session file.
    if os.path.isdir(sqlmap_output_dir):
        host_specific_dirs = [d for d in os.listdir(sqlmap_output_dir) if os.path.isdir(os.path.join(sqlmap_output_dir, d))]
        if host_specific_dirs:
            # Assume the first directory found is the relevant one, or refine if multiple targets are handled by one sqlmap run
            target_session_file_path = os.path.join(sqlmap_output_dir, host_specific_dirs[0], "session.sqlite")
    
    parsed_from_session = False
    if target_session_file_path and os.path.exists(target_session_file_path):
        logger.info(f"SQLMap session file found: {target_session_file_path}. Attempting to parse.")
        try:
            # This requires python3-sqlite3. This parsing is COMPLEX because sqlmap stores results in various ways.
            # For a robust solution, you'd query specific tables within session.sqlite or parse JSON dumps if sqlmap was run with --dump and JSON output.
            # This is a simplified check for now.
            # A simple indicator: if the session file is non-empty, it likely found something or tried.
            # Actual parsing of session.sqlite is out of scope for quick implementation.
            # We'll look for keywords in the main 'log' file created by SQLMap.
            if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 500: # Arbitrary size to indicate activity
                 with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f_log:
                    log_content = f_log.read()
                    if "injectable" in log_content.lower() or "vulnerable" in log_content.lower():
                        params_found = re.findall(r"Parameter:\s*#?\d*\*?\s*([^ \n(]+)", log_content, re.IGNORECASE)
                        dbms_found = re.search(r"back-end DBMS:\s*(.*?)\n", log_content, re.IGNORECASE)
                        dbms_info = dbms_found.group(1) if dbms_found else "Unknown"
                        for param in set(params_found): # Unique parameters
                            finding = {"parameter": param, "dbms": dbms_info, "target_url": target_url_with_params, "notes": "SQLMap log indicates vulnerability."}
                            findings.append(finding)
                            db_store_structured_result(db_conn, scan_id, tool_name, "vulnerability_sqlmap", finding, target_url_with_params)
                        if findings: tool_status = "success_finding_from_log"; parsed_from_session = True
                        else: tool_status = "success_log_needs_review" # Log exists, keywords present, but no params parsed by this regex
            if not findings: logger.info("No specific vulnerabilities parsed from SQLMap session log.")
        except Exception as e:
            logger.error(f"Error reading SQLMap session/log files: {e}")

    if not parsed_from_session: # Fallback to stdout parsing if session log parsing didn't yield results
        if "Parameter:" in raw_stdout and "Type:" in raw_stdout and "Title:" in raw_stdout and "Payload:" in raw_stdout:
            tool_status = "success_potential_finding_stdout"
            injectable_params = re.findall(r"Parameter:\s*#?\d*\*?\s*([^ \n(]+)[\s\S]*?Type:.*?Payload: (.*?)\n", raw_stdout, re.IGNORECASE)
            for param_name, payload_example in injectable_params:
                finding_detail = {"parameter": param_name, "payload_example": payload_example.strip(), "target_url": target_url_with_params, "notes": "SQLMap reported parameter injectable (from stdout)."}
                findings.append(finding_detail)
                db_store_structured_result(db_conn, scan_id, tool_name, "vulnerability_sqlmap", finding_detail, target_url_with_params)
            if not findings: tool_status = "success_no_clear_finding_stdout"
        elif "all tested parameters do not appear to be injectable" in raw_stdout.lower(): tool_status = "success_no_vuln_found"
        elif return_code == 0 and raw_stdout: tool_status = "success_output_needs_review"
        elif "command not found" in raw_stderr.lower(): tool_status = "config_error_not_found"
        else: tool_status = "failed_execution"

    if findings: logger.info(f"SQLMap found {len(findings)} potential issues for {target_url_with_params}. Status: {tool_status}")
    else: logger.info(f"SQLMap scan for {target_url_with_params} completed. Status: {tool_status}")
           
    db_log_tool_run(db_conn, scan_id, tool_name, tool_status, raw_stdout[:2000], raw_stderr, target_url_with_params)
    return findings