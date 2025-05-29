# CyberSageV2/tools/vuln_scan.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger, CYBERSAGE_BASE_DIR
from .common import db_log_tool_run, db_store_structured_result
import json, os, tempfile # tempfile might not be used here, but good to have if needed by other funcs

def run_nuclei_scan(target_url_or_host, scan_id, db_conn):
    tool_name = "nuclei"; tool_executable = get_tool_path(tool_name)
    if not tool_executable:
        logger.error(f"{tool_name} path missing. Check config: tool_paths.{tool_name}"); 
        db_log_tool_run(db_conn,scan_id,tool_name,"config_error_path","","",target_url_or_host); return []

    vulnerabilities_found = []; raw_stdout = ""; raw_stderr = ""; return_code = -1; tool_status = "failed_to_start"
    nuclei_output_jsonl_file = None # Renamed for clarity
    try:
        safe_target_name = "".join(c if c.isalnum() else '_' for c in target_url_or_host.split("://")[-1])[:100]
        nuclei_output_dir = os.path.join(CYBERSAGE_BASE_DIR, "nuclei_scan_outputs"); os.makedirs(nuclei_output_dir, exist_ok=True)
        # Ensure unique filename per scan to avoid issues if multiple targets use same safe_target_name in one scan
        nuclei_output_jsonl_file = os.path.join(nuclei_output_dir, f"nuclei_results_{safe_target_name}_{scan_id}.jsonl")

        cmd = [
            tool_executable, 
            "-u", target_url_or_host, 
            "-jsonl", "-o", nuclei_output_jsonl_file, # Use -jsonl for line-delimited JSON
            "-silent", 
            "-stats", "-stats-interval", "60", # Show stats every 60s (can be noisy)
            "-bulk-size", "20", "-c", "15", 
            "-s", "critical,high,medium,low,info", 
            "-retries", "1", "-timeout", "15" # Increased timeout per template slightly
        ]
        if TOOL_CONFIG.get("nuclei_update_templates", True): cmd.insert(1, "-update-templates")
        
        nuclei_custom_templates_path = TOOL_CONFIG.get("nuclei_templates_path")
        if nuclei_custom_templates_path: 
            expanded_path = os.path.expanduser(nuclei_custom_templates_path)
            if os.path.exists(expanded_path):
                 cmd.extend(["-t", expanded_path])
            else:
                logger.warning(f"Nuclei custom templates path specified but not found: {expanded_path}")

        logger.info(f"Running Nuclei: {' '.join(cmd)}")
        raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, target_url_or_host, timeout_seconds=3600) # 1 hour overall timeout

        if (return_code == 127 or ("command not found" in raw_stderr.lower())): 
            tool_status = "config_error_not_found"; logger.error(f"Nuclei executable not found at '{tool_executable}'.")
        elif "No such option: -jsonl" in raw_stderr or "flag provided but not defined: -jsonl" in raw_stderr:
            tool_status = "config_error_cli_option_jsonl"
            logger.error(f"Nuclei flag -jsonl error. Your Nuclei ('{tool_executable}') version might be old or incompatible. Try just -json and adjust parsing. Stderr: {raw_stderr[:200]}")
        elif os.path.exists(nuclei_output_jsonl_file) and os.path.getsize(nuclei_output_jsonl_file) > 0:
            tool_status = "success_partial_output" if return_code !=0 and raw_stderr else "success"
            with open(nuclei_output_jsonl_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line) # This expects one JSON object per line
                            vulnerabilities_found.append(vuln_data)
                            # Store the raw vuln_data dict from Nuclei
                            db_store_structured_result(db_conn, scan_id, tool_name, "vulnerability_nuclei", vuln_data, vuln_data.get("matched-at", vuln_data.get("host", target_url_or_host)))
                        except json.JSONDecodeError as e: 
                            logger.warning(f"Nuclei: JSON parse error line {line_num+1} in {nuclei_output_jsonl_file}: '{line[:100]}...'. Error: {e}")
            if not vulnerabilities_found and tool_status == "success": 
                tool_status = "success_no_vulns_parsed_from_file"
                logger.info(f"Nuclei ran for {target_url_or_host}, output file exists but no vulnerabilities parsed.")
        elif return_code == 0: 
            tool_status = "success_empty_report_file"
            logger.info(f"Nuclei ran successfully for {target_url_or_host} but report file was empty or not created: {nuclei_output_jsonl_file}")
        else: 
            tool_status = "failed_execution"; logger.error(f"Nuclei scan failed for {target_url_or_host}. Code: {return_code}. Stderr: {raw_stderr[:200]}")
    except Exception as e: 
        logger.error(f"Unexpected exception during Nuclei scan for {target_url_or_host}: {e}", exc_info=True); tool_status = "error_internal"
    
    db_log_tool_run(db_conn, scan_id, tool_name, tool_status, raw_stdout, raw_stderr, target_url_or_host)
    logger.info(f"Nuclei scan for {target_url_or_host} found {len(vulnerabilities_found)} items. Final Status: {tool_status}")
    return vulnerabilities_found