# CyberSageV2/tools/recon.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger
from .common import db_log_tool_run, db_store_structured_result
import os, json, re, tempfile

def run_subdomain_discovery(target_domain, scan_id, db_conn):
    preferred_tool = TOOL_CONFIG.get("recon_tools", {}).get("subdomain_discovery", ["subfinder"])[0]
    tool_executable = get_tool_path(preferred_tool) 
    subdomains_found_set, raw_stdout, raw_stderr,return_code,tool_status = set(),"","",-1,"failed_to_start"

    if not tool_executable:
        logger.error(f"Subfinder path missing. Config: tool_paths.{preferred_tool}"); 
        db_log_tool_run(db_conn,scan_id,preferred_tool,"config_error_path","","",target_domain); return []

    cmd = [tool_executable, "-d", target_domain, "-silent", "-all", "-timeout", "300"]
    raw_stdout, raw_stderr, return_code = run_tool_command(cmd, "subfinder", target_domain, 360)
    
    if return_code == 127 or ("command not found" in raw_stderr.lower()): tool_status = "config_error_not_found"
    elif return_code == 0 and raw_stdout:
        parsed_subs = { line.strip().lower() for line in raw_stdout.splitlines() if line.strip() and '.' in line.strip() and not line.strip().lower().startswith(("[err]", "[ftl]", "warn", "fail", "unable", "info", "time=","took ", "could not resolve", "no results found for"))}
        subdomains_found_set.update(parsed_subs); tool_status = "success" if subdomains_found_set else "success_no_valid_subs_parsed"
    elif return_code == 0: tool_status = "success_empty_stdout"
    else: tool_status = "failed_execution"
    
    db_log_tool_run(db_conn, scan_id, preferred_tool, tool_status, raw_stdout, raw_stderr, target_domain)
    actual_subs_stored = 0
    if tool_status == "success" and subdomains_found_set:
        for sub in subdomains_found_set: db_store_structured_result(db_conn,scan_id,preferred_tool,"subdomain_discovered",{"subdomain": sub},target_domain); actual_subs_stored +=1
    logger.info(f"SubdomainDiscovery({preferred_tool}): target={target_domain}, potential={len(subdomains_found_set)}, stored={actual_subs_stored}, status={tool_status}")
    return list(subdomains_found_set)


def run_live_host_identification(hosts_to_check, scan_id, db_conn, original_target_domain):
    if not hosts_to_check:
        logger.info("HTTPX: No hosts provided."); return []
    tool_name = "httpx"; tool_executable = get_tool_path(tool_name) 
    if not tool_executable:
        logger.error(f"{tool_name} path missing."); db_log_tool_run(db_conn,scan_id,tool_name,"config_error_path","","",original_target_domain); return []
    
    live_hosts_details = []; parsed_items_count = 0; tool_status = "failed_to_start"
    # Create temp input file for httpx -list
    temp_input_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt", prefix=f"cs_httpx_in_{scan_id}_") as tmp_file:
            temp_input_file = tmp_file.name
            for host in hosts_to_check: tmp_file.write(f"{host.strip()}\n")

        # CRITICAL: Using -json for httpx as -jsonl failed. No -tech flag.
        cmd = [tool_executable, "-list", temp_input_file, "-json", "-silent", "-status-code", "-title", "-server", "-follow-redirects", "-threads", "20", "-timeout", "10", "-retries", "1", "-system-dns", "-random-agent", "-no-color"]

        logger.info(f"Running HTTPX: {' '.join(cmd)}")
        raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, f"list_for_{original_target_domain}", 300) # Reduced timeout
        
        # HTTPX output parsing:
        # - For single-target manual tests, you showed it outputs one JSON object.
        # - For -list with multiple potential targets, it *should* output a JSON array of result objects OR
        #   it might still output JSON lines (one object per resolved host) even with the -json flag.
        # The parsing logic needs to handle either of these.
        if (return_code == 127 or ("command not found" in raw_stderr.lower())): tool_status = "config_error_not_found"; logger.error(f"HTTPX executable '{tool_executable}' not found.")
        elif "No such option" in raw_stderr or "flag provided but not defined" in raw_stderr or "unknown flag" in raw_stderr.lower() : 
             tool_status = "config_error_cli_option"; logger.error(f"HTTPX flag error. '{tool_executable}'. Stderr: {raw_stderr[:200]}")
        elif raw_stdout:
            tool_status = "success_partial_output" if return_code !=0 and raw_stderr else "success"
            try:
                all_data_objects = json.loads(raw_stdout)
                if isinstance(all_data_objects, dict): # Single JSON Object (if httpx processed one target)
                    all_data_objects_list = [all_data_objects]
                elif isinstance(all_data_objects, list): # List of JSON objects (more likely with multiple targets)
                     all_data_objects_list = all_data_objects
                else:  # Unexpected format - fallback to line by line
                    logger.warning(f"HTTPX: -json output unexpected format: {type(all_data_objects)}. Trying line-by-line.")
                    all_data_objects_list = []  # Reset before trying line parse
                    for line_num, line in enumerate(raw_stdout.splitlines()):
                        if line.strip():
                            try:
                                parsed_data = json.loads(line)
                                all_data_objects_list.append(parsed_data)
                            except json.JSONDecodeError:
                                logger.warning(f"HTTPX: JSON parse error (line {line_num+1} of overall): '{line[:100]}...'")

                for data_item in all_data_objects_list:
                    if not isinstance(data_item, dict): continue
                    parsed_items_count += 1  # Track successful items parsed
                    if data_item.get("url") and data_item.get("status_code", 0) < 500 : 
                        mapped_data = {
                            "input": data_item.get("input"), "url": data_item.get("url"), "status_code": data_item.get("status_code"),
                            "title": data_item.get("title"), 
                            # Your httpx output already uses "technologies" and "webserver" in JSON
                            "technologies": data_item.get("technologies", []), 
                            "webserver": data_item.get("webserver", ''),
                            "host": data_item.get("host"), "port": data_item.get("port"), "scheme": data_item.get("scheme")
                        }
                        live_hosts_details.append(mapped_data)
                        db_store_structured_result(db_conn, scan_id, tool_name, "live_host_detail_httpx", mapped_data, data_item.get("input", original_target_domain))


            except json.JSONDecodeError as je: 
                 logger.warning(f"HTTPX: Failed to parse overall JSON output (tried with -json flag): '{raw_stdout[:300]}...'. Error: {je}")
                 tool_status = "failed_parsing_json"
        elif return_code == 0 and not raw_stderr: tool_status = "success_empty_stdout_raw"  # Successful, no output, no errors
        else: tool_status = "failed_execution"; logger.error(f"HTTPX failed: {original_target_domain}. Code: {return_code}. Stderr: {raw_stderr[:200]}")
            
        db_log_tool_run(db_conn, scan_id, tool_name, tool_status, raw_stdout, raw_stderr, original_target_domain)
    finally:
        if temp_input_file and os.path.exists(temp_input_file):
            try: os.remove(temp_input_file);
            except OSError as e: logger.warning(f"Could not remove temp httpx input file {temp_input_file}: {e}")

    logger.info(f"HTTPX: target={original_target_domain}, inputs={len(hosts_to_check)}, found_live={len(live_hosts_details)}, status={tool_status}")
    return live_hosts_details