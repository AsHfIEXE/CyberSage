# CyberSageV2/tools/recon.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger
from .common import db_log_tool_run, db_store_structured_result
import os, json, re, tempfile
import subprocess # Ensure this is imported

def run_subdomain_discovery(target_domain, scan_id, db_conn):
    # THIS BLOCK MUST BE INDENTED
    preferred_tool = TOOL_CONFIG.get("recon_tools", {}).get("subdomain_discovery", ["subfinder"])[0]
    tool_executable = get_tool_path(preferred_tool) 
    subdomains_found_set, raw_stdout, raw_stderr,return_code,tool_status = set(),"","",-1,"failed_to_start"

    if not tool_executable:
        logger.error(f"Subfinder path missing. Config: tool_paths.{preferred_tool}"); 
        db_log_tool_run(db_conn,scan_id,preferred_tool,"config_error_path","","",target_domain); return []

    # This 'if' block is part of run_subdomain_discovery, so it and its contents are indented
    if preferred_tool == "subfinder":
        cmd = [tool_executable, "-d", target_domain, "-silent", "-all", "-timeout", "300"]
        raw_stdout, raw_stderr, return_code = run_tool_command(cmd, "subfinder", target_domain, 360)
        
        if return_code == 127 or ("command not found" in raw_stderr.lower()): 
            tool_status = "config_error_not_found"; logger.error(f"Subfinder executable not found at '{tool_executable}'.")
        elif return_code == 0 and raw_stdout:
            parsed_subs = { ln.strip().lower() for ln in raw_stdout.splitlines() if ln.strip() and '.' in ln.strip() and not ln.strip().lower().startswith(("[err]", "[ftl]", "warn", "fail", "unable", "info", "time=","took ", "could not resolve", "no results found for"))}
            subdomains_found_set.update(parsed_subs)
            tool_status = "success" if subdomains_found_set else "success_no_valid_subs_parsed"
        elif return_code == 0: tool_status = "success_empty_stdout"
        else: tool_status = "failed_execution"
    # End of 'if preferred_tool == "subfinder":' block
    
    db_log_tool_run(db_conn, scan_id, preferred_tool, tool_status, raw_stdout, raw_stderr, target_domain)
    actual_subs_stored = 0
    if tool_status == "success" and subdomains_found_set:
        for sub in subdomains_found_set: 
            db_store_structured_result(db_conn,scan_id,preferred_tool,"subdomain_discovered",{"subdomain": sub},target_domain)
            actual_subs_stored +=1
    logger.info(f"SubdomainDiscovery({preferred_tool}): target={target_domain}, potential={len(subdomains_found_set)}, stored={actual_subs_stored}, status={tool_status}")
    return list(subdomains_found_set)
# End of run_subdomain_discovery function

def run_live_host_identification(hosts_to_check, scan_id, db_conn, original_target_domain):
    # THIS BLOCK MUST BE INDENTED
    if not hosts_to_check: logger.info("HTTPX: No hosts provided."); return []
    tool_name = "httpx"
    
    tool_executable = TOOL_CONFIG.get("tool_paths", {}).get(tool_name) # Try absolute path from config first
    path_source_log = f"config (tool_paths.{tool_name})"
    
    if not tool_executable or not (os.path.exists(tool_executable) and os.access(tool_executable, os.X_OK)):
        logger.warning(f"HTTPX path '{tool_executable}' from config not valid or not found. Trying PATH for 'httpx'.")
        tool_executable_from_path = get_tool_path(tool_name) # This returns "httpx" if not in config's tool_paths
        path_source_log = f"PATH (resolved to '{tool_executable_from_path}')"
        
        if command_exists(tool_executable_from_path): # Check if "httpx" (or path from get_tool_path) is actually in PATH
            tool_executable = tool_executable_from_path 
            logger.info(f"Using HTTPX from PATH: {tool_executable}")
        else:
             logger.error(f"HTTPX executable not found via config OR PATH. Check config/tools.yaml and ensure ProjectDiscovery's httpx is installed and in PATH.");
             db_log_tool_run(db_conn,scan_id,tool_name,"config_error_unresolvable_path","","",original_target_domain); return []
    else:
        logger.info(f"Using HTTPX from config: {tool_executable}")

    temp_input_file = None; live_hosts_details = []; tool_status = "failed_to_start"
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt", prefix=f"cs_httpx_in_{scan_id}_") as tmp_file:
            temp_input_file = tmp_file.name
            for host in hosts_to_check: tmp_file.write(f"{host.strip()}\n")
        
        json_output_flag_to_use = "-jsonl" 
        cmd_base_args = ["-silent", "-status-code", "-title", "-tech", "-server", "-follow-redirects", "-threads", "15", "-timeout", "7", "-retries", "0", "-random-agent", "-no-color" ]
        
        cmd = [ tool_executable, "-list", temp_input_file, json_output_flag_to_use] + cmd_base_args
        logger.info(f"Running HTTPX (1st try with {json_output_flag_to_use} using {path_source_log}): {' '.join(cmd)}")
        raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, f"list_for_{original_target_domain}", 240)

        if ("flag provided but not defined: -jsonl" in raw_stderr or "unknown flag: -jsonl" in raw_stderr.lower()) and return_code != 0 :
            logger.warning(f"HTTPX: -jsonl flag failed. Retrying with -json flag for '{tool_executable}'.")
            json_output_flag_to_use = "-json" 
            cmd = [ tool_executable, "-list", temp_input_file, json_output_flag_to_use] + cmd_base_args
            logger.info(f"Running HTTPX (2nd try with {json_output_flag_to_use}): {' '.join(cmd)}")
            raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, f"list_for_{original_target_domain}_try2", 240)
        
        parsed_lines_count = 0
        if (return_code == 127 or ("command not found" in raw_stderr.lower())): 
            tool_status = "config_error_not_found"; logger.error(f"HTTPX executable '{tool_executable}' not found by OS subprocess.")
        elif "No such option" in raw_stderr or "flag provided but not defined" in raw_stderr or "unknown flag" in raw_stderr.lower() : 
             tool_status = "config_error_cli_option"
             logger.error(f"HTTPX FLAG ERROR with '{tool_executable}'. Your binary may not be ProjectDiscovery's httpx or is an incompatible version. Stderr: {raw_stderr[:250]}")
        elif raw_stdout:
            tool_status = "success_partial_output" if return_code !=0 and raw_stderr else "success" 
            lines_to_parse = []
            if json_output_flag_to_use == "-json" and raw_stdout.strip().startswith("[") and raw_stdout.strip().endswith("]"):
                try: 
                    loaded_json = json.loads(raw_stdout)
                    lines_to_parse = loaded_json if isinstance(loaded_json, list) else [loaded_json]
                    parsed_lines_count = len(lines_to_parse)
                except json.JSONDecodeError: logger.warning(f"HTTPX (-json): Failed to parse overall JSON: '{raw_stdout[:200]}...'"); tool_status = "failed_parsing_json"
            else: lines_to_parse = raw_stdout.splitlines()

            for item_data in lines_to_parse:
                data_dict = None
                if isinstance(item_data, dict): data_dict = item_data
                elif isinstance(item_data, str) and item_data.strip():
                    if json_output_flag_to_use == "-jsonl": parsed_lines_count +=1 
                    try: data_dict = json.loads(item_data)
                    except json.JSONDecodeError: logger.warning(f"HTTPX: JSONL parse error line: '{item_data[:100]}...'"); continue 
                
                if data_dict and data_dict.get("url") and data_dict.get("status_code", 0) < 500 : 
                    mapped_data = { "input": data_dict.get("input"), "url": data_dict.get("url"), "status_code": data_dict.get("status_code"), "title": data_dict.get("title"), "technologies": data_dict.get("tech"), "webserver": data_dict.get("server"), "host": data_dict.get("host"), "port": data_dict.get("port"), "scheme": data_dict.get("scheme")}
                    live_hosts_details.append(mapped_data)
                    db_store_structured_result(db_conn, scan_id, tool_name, "live_host_detail_httpx", mapped_data, data_dict.get("input", original_target_domain))
            
            if live_hosts_details: tool_status = "success" 
            elif parsed_lines_count > 0: tool_status = "success_no_valid_live_hosts" 
            elif tool_status != "failed_parsing_json": tool_status = "success_empty_stdout" 
        elif return_code == 0: tool_status = "success_empty_stdout" 
        else: tool_status = "failed_execution"; logger.error(f"HTTPX failed: {original_target_domain}. Code: {return_code}. Stderr: {raw_stderr[:200]}")
            
        db_log_tool_run(db_conn, scan_id, tool_name, tool_status, raw_stdout, raw_stderr, original_target_domain)
    finally:
        if temp_input_file and os.path.exists(temp_input_file):
            try: os.remove(temp_input_file)
            except OSError as e: logger.warning(f"Could not remove temp httpx file {temp_input_file}: {e}")

    logger.info(f"HTTPX: target={original_target_domain}, inputs={len(hosts_to_check)}, found_live={len(live_hosts_details)}, status={tool_status}")
    return live_hosts_details

def command_exists(cmd): # Helper defined at the end or imported
    try:
        result = subprocess.run(['which', cmd], capture_output=True, text=True, check=False)
        return result.returncode == 0
    except FileNotFoundError: 
        logger.warning("'which' command not found, cannot reliably check if tool exists in PATH via 'which'.")
        # Fallback: try running the command with -h or --version if 'which' is missing
        try:
            result_tool = subprocess.run([cmd, '--version'], capture_output=True, text=True, check=False, timeout=2)
            return result_tool.returncode in [0,1,2] # Some tools exit non-zero for -h/--version
        except Exception:
            return False
    except Exception as e:
        logger.warning(f"Error running 'which {cmd}': {e}")
        return False
