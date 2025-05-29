# CyberSageV2/tools/nikto_scan.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger, CYBERSAGE_BASE_DIR
from .common import db_log_tool_run, db_store_structured_result
import json, os

def run_nikto(target_url, scan_id, db_conn):
    tool_name = "nikto"; nikto_base_dir = get_tool_path("nikto_dir")
    nikto_script_name = TOOL_CONFIG.get("tool_paths",{}).get("nikto_script_name", "program/nikto.pl")
    tool_status = "failed_to_start"; findings = []

    if not nikto_base_dir or not os.path.isdir(nikto_base_dir):
        logger.error(f"Nikto dir '{nikto_base_dir}' invalid."); db_log_tool_run(db_conn,scan_id,tool_name,"config_error_path","","",target_url); return findings
    tool_executable = os.path.join(nikto_base_dir, nikto_script_name)
    if not os.path.exists(tool_executable):
        logger.error(f"Nikto script '{tool_executable}' missing."); db_log_tool_run(db_conn,scan_id,tool_name,"config_error_script","","",target_url); return findings

    try:
        protocol, rest = target_url.split("://",1); host_port, _ = (rest.split("/",1)+[""])[:2]
        host, port_str = (host_port.split(":",1) if ":" in host_port else (host_port, "443" if protocol=="https" else "80"))
    except Exception as e: logger.error(f"Nikto URL parse error: {target_url} - {e}"); db_log_tool_run(db_conn,scan_id,tool_name,"param_error","","",target_url); return findings
    
    nikto_reports_dir = os.path.join(CYBERSAGE_BASE_DIR, "nikto_reports", scan_id); os.makedirs(nikto_reports_dir, exist_ok=True)
    safe_target_name = "".join(c if c.isalnum() else '_' for c in target_url.split("://")[-1])[:100]
    output_json_file = os.path.join(nikto_reports_dir, f"nikto_{safe_target_name}_{scan_id}.json")

    nikto_opts_str = TOOL_CONFIG.get("nikto_options", "-Tuning 123bde -maxtime 120s")
    cmd = ["perl", tool_executable, "-h", host, "-p", port_str, "-Format", "json", "-o", output_json_file, "-ask", "no"]
    cmd.extend(nikto_opts_str.split())
    if protocol == "https": cmd.append("-ssl")
    
    logger.info(f"Running Nikto: {' '.join(cmd)}. Output to: {output_json_file}")
    # Nikto might run from its own directory for plugins
    # cwd for Nikto should be nikto_base_dir/program/
    nikto_program_dir = os.path.dirname(tool_executable)
    raw_stdout, raw_stderr, return_code = run_tool_command(cmd, tool_name, target_url, 900, cwd=nikto_program_dir) 

    if "Can't locate Net/SSLeay.pm" in raw_stderr: tool_status="dep_error_ssleay"; logger.error("Nikto SSL error: Net::SSLeay missing.")
    elif "No such file or directory" in raw_stderr and "plugins" in raw_stderr: tool_status="dep_error_plugins"; logger.error("Nikto plugin error.")
    elif os.path.exists(output_json_file) and os.path.getsize(output_json_file) > 0:
        tool_status = "success_partial_output" if return_code !=0 and raw_stderr else "success"
        try:
            with open(output_json_file, 'r', encoding='utf-8') as f: nikto_data = json.load(f)
            if isinstance(nikto_data, dict) and "vulnerabilities" in nikto_data:
                for item in nikto_data["vulnerabilities"]:
                    finding_detail = { # Normalize key Nikto fields
                        "id": item.get("id"), "osvdbid": item.get("OSVDB"), "method": item.get("method"),
                        "url": item.get("url"), "msg": item.get("msg"), "namelink": item.get("namelink"),
                        "target_url": target_url, "raw_item": item # Store raw item for full details in modal
                    }
                    findings.append(finding_detail)
                    db_store_structured_result(db_conn, scan_id, tool_name, "vulnerability_nikto", finding_detail, target_url)
                if findings: logger.info(f"Nikto found and stored {len(findings)} items for {target_url}.")
                else: tool_status = "success_no_vulns_in_json"; logger.info(f"Nikto JSON parsed, no 'vulnerabilities' entries.")
            else: tool_status = "failed_parsing_format"; logger.warning("Nikto JSON missing 'vulnerabilities' key.")
        except json.JSONDecodeError: tool_status = "failed_parsing"; logger.warning(f"Nikto output file not valid JSON: {output_json_file}")
    elif return_code == 0: tool_status = "success_empty_report_file"
    else: tool_status = "failed_execution"; logger.error(f"Nikto failed. Code: {return_code}. Stderr: {raw_stderr[:200]}")
           
    db_log_tool_run(db_conn, scan_id, tool_name, tool_status, raw_stdout, raw_stderr, target_url)
    return findings