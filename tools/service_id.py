# CyberSageV2/tools/service_id.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger
from .common import db_log_tool_run, db_store_structured_result
import json
import os       # <--- ADD THIS IMPORT
import tempfile # <--- ADD THIS IMPORT

def run_tech_identification(target_url, scan_id, db_conn):
    """
    Identifies web technologies using WhatWeb.
    target_url should be a full URL like http://example.com:8080
    Returns the parsed WhatWeb JSON for the target, or None if errors/no data.
    """
    preferred_tool = TOOL_CONFIG.get("service_id_tools", {}).get("technology_identification", ["whatweb"])[0]
    tool_executable = get_tool_path(preferred_tool)
    tool_status = "failed_to_start"; tech_results_for_target = None; raw_stdout = ""; raw_stderr = ""

    if not tool_executable:
        logger.error(f"WhatWeb path missing. Check config: tool_paths.{preferred_tool}"); 
        db_log_tool_run(db_conn,scan_id,preferred_tool,"config_error_path","","",target_url); return None

    if preferred_tool == "whatweb":
        whatweb_json_output_file = None
        try:
            # Create a temporary file for WhatWeb's JSON output
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", prefix=f"cs_whatweb_{scan_id}_") as tmp_json_file:
                whatweb_json_output_file = tmp_json_file.name
            
            # WhatWeb command to log JSON to our specified file
            # Aggression level 1 is default, --max-threads can speed it up.
            cmd = [
                tool_executable, 
                target_url, 
                f"--log-json={whatweb_json_output_file}", 
                "--aggression=1", # Default, can be increased (1-4)
                "--max-threads=5" # Limit threads for stability
            ]
            
            logger.info(f"Running WhatWeb on {target_url}. Command: {' '.join(cmd)}")
            raw_stdout, raw_stderr, return_code = run_tool_command(cmd, "whatweb", target_url, timeout_seconds=180) # Reduced timeout

            # Check for common tool not found errors first
            if (return_code == 127 or ("command not found" in raw_stderr.lower() and "whatweb" in raw_stderr.lower())):
                tool_status = "config_error_not_found"
                logger.error(f"WhatWeb executable '{tool_executable}' not found.")
            elif return_code == 0 and os.path.exists(whatweb_json_output_file) and os.path.getsize(whatweb_json_output_file) > 0:
                try:
                    with open(whatweb_json_output_file, 'r', encoding='utf-8') as f_json:
                        # WhatWeb output is usually a list containing one dictionary for the target
                        json_output_list = json.load(f_json) 
                    
                    if isinstance(json_output_list, list) and len(json_output_list) > 0 and isinstance(json_output_list[0], dict):
                        tech_results_for_target = json_output_list[0] # Get the first (and usually only) element
                        db_store_structured_result(db_conn, scan_id, "whatweb", "technology_whatweb", tech_results_for_target, target_url)
                        tool_status = "success"
                        logger.info(f"WhatWeb successfully identified tech for {target_url}.")
                    else:
                        tool_status = "success_empty_or_malformed_json"
                        logger.warning(f"WhatWeb JSON for {target_url} was empty list or not a list of dicts.")
                except json.JSONDecodeError as e:
                    logger.error(f"WhatWeb JSON parsing error for {target_url} from file {whatweb_json_output_file}: {e}")
                    tool_status = "failed_parsing"
            elif return_code == 0: # Command succeeded but no output file created or file is empty
                tool_status = "success_no_report_file"
                logger.warning(f"WhatWeb ran successfully for {target_url} but report file {whatweb_json_output_file} is missing or empty.")
            else: # Command failed with non-zero exit code
                tool_status = "failed_execution"
                logger.error(f"WhatWeb execution failed for {target_url}. Code: {return_code}. Stderr: {raw_stderr[:200]}")
        except Exception as e:
            logger.error(f"Unexpected error during WhatWeb execution for {target_url}: {e}", exc_info=True)
            tool_status = "error_internal"
        finally:
            if whatweb_json_output_file and os.path.exists(whatweb_json_output_file):
                try: os.remove(whatweb_json_output_file)
                except OSError as e_os: logger.warning(f"Could not remove temp WhatWeb JSON file {whatweb_json_output_file}: {e_os}")

    db_log_tool_run(db_conn, scan_id, preferred_tool, tool_status, raw_stdout, raw_stderr, target_url)
    
    if tech_results_for_target:
        logger.info(f"WhatWeb successfully processed for {target_url}.")
    else:
        logger.info(f"WhatWeb processing for {target_url} did not yield results or failed. Status: {tool_status}")
        
    return tech_results_for_target


if __name__ == '__main__':
    # This __main__ block needs tools.common to be importable,
    # which means running it as part of the package, e.g., python -m tools.service_id
    # Or temporarily adjusting PYTHONPATH if run directly for testing.
    print("Testing service_id.py module (output will be logged, no actual DB writes here)...")
    # For direct testing, you might need to mock common.TOOL_CONFIG or ensure common.py can load config
    if 'TOOL_CONFIG' not in globals() or not TOOL_CONFIG:
        print("WARNING: TOOL_CONFIG not loaded. Standalone test might fail or use defaults.")
        # Provide minimal mock config for standalone test if needed
        TOOL_CONFIG = {
            "service_id_tools": {"technology_identification": ["whatweb"]},
            "tool_paths": {"whatweb": "whatweb"} # Assumes whatweb is in PATH
        }

    test_target = "http://testphp.vulnweb.com" 

    class DummyDBConn:
        def cursor(self): return DummyCursor()
        def commit(self): logger.debug("DummyDB: Commit called")
        def close(self): logger.debug("DummyDB: Close called")
    class DummyCursor:
        def execute(self, query, params=None): logger.debug(f"DummyDB: Execute: {query[:100]}... with params: {params}")
        def fetchone(self): return None; 
        def fetchall(self): return []
        def close(self): pass
    
    dummy_conn = DummyDBConn()
    test_scan_id = "serviceid_selftest_001"

    logger.info(f"\n--- Running Technology Identification for {test_target} ---")
    technologies = run_tech_identification(test_target, test_scan_id, dummy_conn)
    
    if technologies and isinstance(technologies, dict):
        logger.info(f"\n--- Identified Technologies for {test_target} (Sample) ---")
        # Log a few key pieces of info from the WhatWeb JSON
        target_info = technologies.get("target", "N/A")
        status_code = technologies.get("http_status", "N/A")
        logger.info(f"  Target URL: {target_info}, HTTP Status: {status_code}")
        
        plugins = technologies.get("plugins", {})
        if plugins:
            logger.info(f"  Detected Plugins ({len(plugins)}):")
            count = 0
            for plugin_name, plugin_data in plugins.items():
                # Try to get a representative string from the plugin data
                version_info = plugin_data.get("version", [])
                string_info = plugin_data.get("string", [])
                output_str = ""
                if version_info: output_str += f"Version(s): {', '.join(map(str, version_info))}"
                if string_info: output_str += f" String(s): {', '.join(map(str, string_info))}" if output_str else f"String(s): {', '.join(map(str, string_info))}"
                
                logger.info(f"    - {plugin_name}: {output_str[:100] if output_str else 'Details in raw JSON'}")
                count += 1
                if count >= 5: logger.info("      ... and potentially more plugins."); break
        else:
             logger.info(f"  Full WhatWeb JSON: {json.dumps(technologies, indent=2)}")
    else:
        logger.info(f"No specific technologies dictionary identified or returned for {test_target}.")