# CyberSageV2/tools/service_id.py
from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger
from .common import db_log_tool_run, db_store_structured_result
import json

def run_tech_identification(target_url, scan_id, db_conn):
    """
    Identifies web technologies using WhatWeb.
    target_url should be a full URL like http://example.com:8080
    Returns a list of identified technologies or None.
    """
    preferred_tool = TOOL_CONFIG.get("service_id_tools", {}).get("technology_identification", ["whatweb"])[0]
    tool_executable = get_tool_path(preferred_tool)

    if not tool_executable:
        logger.error(f"{preferred_tool} path not found. Skipping technology identification for {target_url}.")
        db_log_tool_run(db_conn, scan_id, preferred_tool, "config_error", "", f"{preferred_tool} not configured.", target_url)
        return None # Or an empty list

    tech_results = None
    raw_stdout, raw_stderr, return_code = "", "", -1
    tool_status = "failed"

    if preferred_tool == "whatweb":
        # WhatWeb command: whatweb <url> --log-json <output_file>
        # We'll parse JSON output directly from stdout if possible, or from a temp file.
        # Whatweb's direct JSON to stdout: `whatweb --no-errors --color=never --log-json-verbose - <url>`
        # However, `-` for stdout might not be universally supported or might mix with other output.
        # For safety, let's use a temporary file for JSON output, similar to Nmap.
        
        temp_whatweb_output_json = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json", prefix=f"cs_whatweb_{scan_id}_") as tmp_json:
                temp_whatweb_output_json = tmp_json.name

            # Aggression level 1 (stealthy) to 4 (heavy). Default usually 1.
            # Use --color=never and --no-errors for cleaner machine-readable output if not using JSON file.
            cmd = [tool_executable, target_url, f"--log-json={temp_whatweb_output_json}", "--aggression=1", "--max-threads=10"]
            
            # WhatWeb can sometimes be slow
            raw_stdout, raw_stderr, return_code = run_tool_command(cmd, "whatweb", target_url, timeout_seconds=300)

            # WhatWeb primary output is the JSON file. stdout might contain progress or errors.
            if return_code == 0 and os.path.exists(temp_whatweb_output_json) and os.path.getsize(temp_whatweb_output_json) > 0:
                try:
                    with open(temp_whatweb_output_json, 'r') as f:
                        # Whatweb outputs an array of JSON objects, one per target. We give one target.
                        json_data_list = json.load(f) 
                    if json_data_list and isinstance(json_data_list, list) and len(json_data_list) > 0:
                        tech_results = json_data_list[0] # We expect one result for one URL
                        db_store_structured_result(db_conn, scan_id, "whatweb", "technology_whatweb", tech_results, target_url)
                        tool_status = "success"
                    else:
                        logger.info(f"WhatWeb ran for {target_url}, but JSON output was empty or not as expected.")
                        tool_status = "success_no_results" # Ran but no parsable data
                except json.JSONDecodeError as e:
                    logger.error(f"WhatWeb JSON parsing error for {target_url}: {e}. File: {temp_whatweb_output_json}")
                    raw_stderr += f"\nWhatWeb JSON parsing error: {e}."
                    tool_status = "failed_parsing"
            elif return_code == 0: # Command success but no file or empty file
                logger.warning(f"WhatWeb command successful for {target_url} but no valid JSON output file found or file empty: {temp_whatweb_output_json}")
                tool_status = "success_no_json_file"
            else: # Command failed
                logger.error(f"WhatWeb command failed for {target_url}. Stderr: {raw_stderr[:500]}")
                tool_status = "failed_execution"

        finally:
            if temp_whatweb_output_json and os.path.exists(temp_whatweb_output_json):
                try:
                    os.remove(temp_whatweb_output_json)
                except OSError as e:
                    logger.warning(f"Could not remove temporary WhatWeb JSON file {temp_whatweb_output_json}: {e}")

    db_log_tool_run(db_conn, scan_id, preferred_tool, tool_status, raw_stdout, raw_stderr, target_url)

    if tech_results:
        logger.info(f"WhatWeb identified technologies for {target_url}.")
    else:
        logger.info(f"WhatWeb found no specific technology details for {target_url} or failed.")
        
    return tech_results


if __name__ == '__main__':
    print("Testing service_id.py module (output will be logged, no actual DB writes here)...")
    test_target = "http://testphp.vulnweb.com" 

    class DummyDBConn: # Mock DB connection
        def cursor(self): return DummyCursor()
        def commit(self): logger.debug("DummyDB: Commit called")
        def close(self): logger.debug("DummyDB: Close called")
    class DummyCursor:
        def execute(self, query, params=None): logger.debug(f"DummyDB: Execute: {query[:100]}... with params: {params}")
        def fetchone(self): return None
        def fetchall(self): return []
        def close(self): pass
    
    dummy_conn = DummyDBConn()
    test_scan_id = "serviceid_selftest_001"

    logger.info(f"\n--- Running Technology Identification for {test_target} ---")
    technologies = run_tech_identification(test_target, test_scan_id, dummy_conn)
    
    if technologies:
        logger.info(f"\n--- Identified Technologies for {test_target} (first 5 plugins if many) ---")
        # WhatWeb output is a dict, 'plugins' is often a key.
        # Example: technologies might be like {'plugins': {'WebServer': {'string': ['Apache/2.2.14 (Ubuntu)']}, ...}}
        # Or directly {'Country': ... , 'HTTPServer': ...}
        plugins = technologies.get("plugins")
        if plugins and isinstance(plugins, dict):
            count = 0
            for plugin_name, plugin_data in plugins.items():
                logger.info(f"  Plugin: {plugin_name}, Data: {str(plugin_data)[:100]}...") # Log a snippet
                count += 1
                if count >=5:
                    logger.info("  ... and potentially more.")
                    break
        else: # If no 'plugins' key, print the whole dict (or relevant parts)
             logger.info(json.dumps(technologies, indent=2, sort_keys=True))
    else:
        logger.info(f"No specific technologies identified for {test_target}.")