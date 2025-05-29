# CyberSageV2/tools/dalfox_scan.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger, CYBERSAGE_BASE_DIR
from .common import db_log_tool_run, db_store_structured_result
import json, os

def run_dalfox(target_url_with_params, scan_id, db_conn):
    tool_name = "dalfox"; tool_executable = get_tool_path(tool_name)
    if not tool_executable: 
        logger.error(f"{tool_name} path not found. Check config: tool_paths.{tool_name}"); 
        db_log_tool_run(db_conn,scan_id,tool_name,"config_error_path","","",target_url_with_params); return []

    dalfox_output_dir = os.path.join(CYBERSAGE_BASE_DIR, "dalfox_reports", scan_id); os.makedirs(dalfox_output_dir, exist_ok=True)
    safe_target_name = "".join(c if c.isalnum() else '_' for c in target_url_with_params.split("://")[-1])[:100]
    # Make output filename unique per scan and target to avoid clashes if dalfox is run multiple times in a scan
    output_json_file = os.path.join(dalfox_output_dir, f"dalfox_{safe_target_name.replace(':','_')}_{scan_id}.json")


    dalfox_workers = TOOL_CONFIG.get("dalfox_concurrency_workers", 10) 
    dalfox_scan_timeout = TOOL_CONFIG.get("dalfox_timeout", 120) 

    # Dalfox v2 uses -w for workers (concurrency).
    cmd = [
        tool_executable, "url", target_url_with_params,
        "-o", output_json_file, # Output to JSON file
        "--silence",            
        "--skip-bav",           # Skip Basic Auth Bypass
        # "--skip-mining-dom",  # Can add for speed if DOM XSS not priority
        "--timeout", str(dalfox_scan_timeout), 
        "-w", str(dalfox_workers) # -w for workers
    ]
    
    logger.info(f"Running Dalfox on {target_url_with_params}. Command: {' '.join(cmd)}")
    raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, target_url_with_params, timeout_seconds=dalfox_scan_timeout + 60) # Wrapper timeout

    findings = []; tool_status = "failed_execution"
    if (return_code == 127 or ("command not found" in raw_stderr.lower() and "dalfox" in raw_stderr.lower())): tool_status = "config_error_not_found"
    elif "unknown flag" in raw_stderr.lower(): 
        tool_status = "config_error_cli_option"
        logger.error(f"Dalfox flag error. Your Dalfox version might be incompatible or command malformed. Stderr: {raw_stderr[:200]}")
    elif os.path.exists(output_json_file) and os.path.getsize(output_json_file) > 0:
        tool_status = "success_partial_output" if return_code !=0 else "success" 
        try:
            with open(output_json_file, 'r', encoding='utf-8') as f:
                dalfox_data_list = []
                content = f.read()
                # Dalfox output might be a list of JSON objects or JSON lines
                if content.strip().startswith('[') and content.strip().endswith(']'): # It's a JSON list
                    dalfox_data_list = json.loads(content)
                else: # Assume JSON lines
                    for line_content in content.splitlines():
                        if line_content.strip():
                            try: dalfox_data_list.append(json.loads(line_content))
                            except json.JSONDecodeError as je: logger.warning(f"Dalfox: Invalid JSON line in {output_json_file}: {line_content[:100]}... Error: {je}")
            
            if dalfox_data_list:
                for finding_data in dalfox_data_list:
                    if isinstance(finding_data, dict) and (finding_data.get("@type") == "gefunden" or finding_data.get("type") == "vulnerable" or "PoC" in finding_data or finding_data.get("result") == True):
                        findings.append(finding_data)
                        db_store_structured_result(db_conn, scan_id, tool_name, "vulnerability_dalfox_xss", finding_data, target_url_with_params)
                if findings: logger.info(f"Dalfox found {len(findings)} potential XSS for {target_url_with_params}.")
                else: tool_status = "success_no_vuln_parsed" if tool_status == "success" else tool_status; logger.info(f"Dalfox JSON processed, no specific XSS findings parsed as vulnerable.")
            else: tool_status = "success_empty_json" if tool_status == "success" else tool_status; logger.info(f"Dalfox JSON output file for {target_url_with_params} was empty or unparsable as list.")
        except Exception as e: logger.error(f"Dalfox: Error processing report {output_json_file}: {e}", exc_info=True); tool_status = "failed_report_processing"
    elif return_code == 0: tool_status = "success_no_report_file"; logger.warning(f"Dalfox (exit 0) - JSON report {output_json_file} missing or empty.")
    
    db_log_tool_run(db_conn, scan_id, tool_name, tool_status, raw_stdout, raw_stderr, target_url_with_params)
    return findings