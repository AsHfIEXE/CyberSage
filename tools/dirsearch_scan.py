# CyberSageV2/tools/dirsearch_scan.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger, DEFAULT_WORDLIST, CYBERSAGE_BASE_DIR 
from .common import db_log_tool_run, db_store_structured_result
import json, os, time # <--- IMPORTED time

def run_dirsearch(target_url, scan_id, db_conn):
    tool_name = "dirsearch"
    dirsearch_base_dir = get_tool_path("dirsearch_dir")
    dirsearch_script_name = TOOL_CONFIG.get("tool_paths",{}).get("dirsearch_script_name", "dirsearch.py")
    tool_status = "failed_to_start"; findings = []

    if not dirsearch_base_dir or not os.path.isdir(dirsearch_base_dir):
        logger.error(f"Dirsearch directory '{dirsearch_base_dir}' missing. Check config."); 
        db_log_tool_run(db_conn,scan_id,tool_name,"config_error_path","",f"Dirsearch dir: {dirsearch_base_dir}",target_url); return findings
    tool_executable = os.path.join(dirsearch_base_dir, dirsearch_script_name)
    if not os.path.exists(tool_executable):
        logger.error(f"Dirsearch script '{tool_executable}' missing."); 
        db_log_tool_run(db_conn,scan_id,tool_name,"config_error_script","",f"Script missing: {tool_executable}",target_url); return findings

    wordlist = os.path.expanduser(TOOL_CONFIG.get("dirsearch_wordlist", DEFAULT_WORDLIST)) # Use specific or default
    if not os.path.exists(wordlist):
        logger.error(f"Wordlist '{wordlist}' for Dirsearch missing."); 
        db_log_tool_run(db_conn,scan_id,tool_name,"config_error_wordlist","",f"Wordlist missing: {wordlist}",target_url); return findings

    extensions = TOOL_CONFIG.get("dirsearch_extensions", "php,html,txt,js")
    exclude_status = TOOL_CONFIG.get("dirsearch_exclude_status", "404,403")
    threads = TOOL_CONFIG.get("dirsearch_threads", 10)
    max_time_cfg = TOOL_CONFIG.get("dirsearch_max_time", 120) # Max scan time from config
    
    dirsearch_output_dir = os.path.join(CYBERSAGE_BASE_DIR, "dirsearch_reports", scan_id) 
    os.makedirs(dirsearch_output_dir, exist_ok=True)
    safe_target_name = target_url.replace("http://","").replace("https://","").replace("/","_").replace(":","_")[:100]
    output_json_file = os.path.join(dirsearch_output_dir, f"dirsearch_{safe_target_name}_{scan_id}.json")

    cmd = [ "python3", tool_executable, "-u", target_url, "-w", wordlist, "-e", extensions,
            "--exclude-statuses", exclude_status, "--json-report", output_json_file,
            "--plain-text-report=", "--simple-report=", # Suppress other file outputs
            "-t", str(threads), "--timeout", "7", "--max-time", str(max_time_cfg) ]
    
    logger.info(f"Running Dirsearch on {target_url}. Max time: {max_time_cfg}s. Output: {output_json_file}")
    # Dirsearch can be slow, give wrapper a bit more time than dirsearch's own max-time
    start_time = time.time() # For logging actual duration
    raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, target_url, max_time_cfg + 60)
    duration = time.time() - start_time
    logger.info(f"Dirsearch finished in {duration:.2f}s. Code: {return_code}.")


    if (return_code == 127 or ("command not found" in raw_stderr.lower() and "dirsearch.py" in raw_stderr.lower())): tool_status = "config_error_not_found"
    elif "Traceback" in raw_stderr and "installation.py" in raw_stderr : # Check for dirsearch's internal dependency errors
        tool_status = "dep_error_dirsearch"; logger.error(f"Dirsearch internal dependency error. Stderr: {raw_stderr[:300]}")
    elif os.path.exists(output_json_file) and os.path.getsize(output_json_file) > 0:
        tool_status = "success_partial_output" if return_code !=0 and raw_stderr else "success"
        try:
            with open(output_json_file, 'r', encoding='utf-8') as f: report_data = json.load(f)
            target_key_found = None
            # Dirsearch report is a dict where keys are target URLs. Find the one matching our input.
            # It might add/remove trailing slashes, so flexible match.
            processed_target_url = target_url.strip('/')
            for k_url_report in report_data.keys():
                if k_url_report.strip('/') == processed_target_url:
                    target_key_found = k_url_report
                    break
            if not target_key_found and report_data: # Fallback if exact match failed (e.g. due to redirect)
                target_key_found = list(report_data.keys())[0]


            if target_key_found and isinstance(report_data.get(target_key_found), list):
                for path_info in report_data[target_key_found]:
                    if isinstance(path_info, dict) and path_info.get("status") not in [404, 403, 400, 401]: 
                        finding_detail = { "path": path_info.get("path"), "status_code": path_info.get("status"), "content_length": path_info.get("content-length"), "redirect": path_info.get("redirect"), "target_base_url": target_key_found }
                        findings.append(finding_detail)
                        db_store_structured_result(db_conn, scan_id, tool_name, "directory_listing", finding_detail, target_url)
                if findings: logger.info(f"Dirsearch found {len(findings)} paths for {target_url}.")
                else: tool_status = "success_no_paths_parsed" if tool_status == "success" else tool_status
            else: tool_status = "failed_parsing_format"; logger.warning(f"Dirsearch JSON report for {target_url} not in expected format or key '{target_url}' not found.")
        except json.JSONDecodeError as e: logger.error(f"Dirsearch JSON parse error for {output_json_file}: {e}"); tool_status = "failed_parsing"
        except Exception as e: logger.error(f"Error processing Dirsearch report {output_json_file}: {e}", exc_info=True); tool_status = "failed_report_processing"
    elif return_code == 0: tool_status = "success_no_report_file"
    
    db_log_tool_run(db_conn, scan_id, tool_name, tool_status, raw_stdout, raw_stderr, target_url)
    return findings