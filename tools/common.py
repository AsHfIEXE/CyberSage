# CyberSageV2/tools/common.py
import subprocess, os, yaml, shlex, logging, json
from datetime import datetime

logger = logging.getLogger("CyberSageToolRunner")
if not logger.hasHandlers():
    log_handler = logging.StreamHandler()
    log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s')
    log_handler.setFormatter(log_formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.DEBUG) # More verbose for debugging

def load_config():
    paths_to_try = [
        os.path.join(os.path.dirname(__file__), '..', 'config', 'tools.yaml'),
        os.path.join(os.getcwd(), 'config', 'tools.yaml'),
        os.path.join(os.getcwd(), '..', 'config', 'tools.yaml')
    ]
    for config_path in paths_to_try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f_config: return yaml.safe_load(f_config)
    raise FileNotFoundError(f"Config 'tools.yaml' not found. Tried: {', '.join(paths_to_try)}")

TOOL_CONFIG = load_config()
USER_HOME_DIR = os.path.expanduser("~")
CYBERSAGE_BASE_DIR = os.path.join(USER_HOME_DIR, ".cybersage_v2")
TOOL_RAW_OUTPUT_DIR = os.path.join(CYBERSAGE_BASE_DIR, "tool_outputs_raw")
DEFAULT_WORDLIST_PATH_CONFIG = TOOL_CONFIG.get("default_wordlist", "~/.cybersage_v2/wordlists/common.txt")
DEFAULT_WORDLIST = os.path.expanduser(DEFAULT_WORDLIST_PATH_CONFIG)
os.makedirs(CYBERSAGE_BASE_DIR, exist_ok=True)
os.makedirs(TOOL_RAW_OUTPUT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DEFAULT_WORDLIST), exist_ok=True) # Ensure wordlist dir exists

def get_tool_path(tool_name_key, tool_config_subgroup=None):
    paths_config = TOOL_CONFIG.get("tool_paths", {})
    if tool_name_key.endswith("_dir"): # For tools specified by directory (e.g., testssl_dir, nikto_dir)
        dir_path = paths_config.get(tool_name_key)
        if dir_path and os.path.isdir(os.path.expanduser(dir_path)): return os.path.expanduser(dir_path)
        elif dir_path: logger.warning(f"Path for {tool_name_key} ('{dir_path}') is not a valid directory."); return os.path.expanduser(dir_path)
        else: logger.warning(f"{tool_name_key} not configured in tool_paths."); return None
    configured_path = paths_config.get(tool_name_key) # For direct executables
    if configured_path and (os.path.isabs(configured_path) or "/" in configured_path or "\\" in configured_path): # If it looks like a path
        return os.path.expanduser(configured_path) # Return it if it's an absolute path or relative path provided
    return tool_name_key # Assume tool_name_key itself is the command in PATH

def run_tool_command(command_list_or_str, tool_name_logging, target_identifier_logging, timeout_seconds=600, cwd=None, shell=False, extra_env=None):
    command_parts = shlex.split(command_list_or_str) if not isinstance(command_list_or_str, list) else command_list_or_str
    safe_target_id = "".join(c if c.isalnum() or c in ('.','_','-') else '_' for c in str(target_identifier_logging))
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_out_file = os.path.join(TOOL_RAW_OUTPUT_DIR, f"{safe_target_id}_{tool_name_logging}_{ts_str}.txt")

    logger.info(f"RUNNING : {tool_name_logging} for '{target_identifier_logging}'")
    logger.debug(f"COMMAND : {' '.join(map(str, command_parts))}")
    logger.debug(f"CWD     : {cwd if cwd else os.getcwd()}")
    logger.debug(f"TIMEOUT : {timeout_seconds}s")
    
    full_stdout, full_stderr, ret_code = "", "", -1
    current_env = os.environ.copy(); 
    if extra_env: current_env.update(extra_env)
    try:
        cmd_str_list = [str(p) for p in command_parts]
        process = subprocess.Popen(cmd_str_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', cwd=cwd, shell=shell, env=current_env)
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout_seconds)
        full_stdout, full_stderr, ret_code = stdout_bytes, stderr_bytes, process.returncode
        if ret_code != 0: logger.warning(f"{tool_name_logging} ({target_identifier_logging}) exited code {ret_code}. Stderr: {full_stderr[:250]}")
        else: logger.info(f"{tool_name_logging} ({target_identifier_logging}) completed successfully (code 0).")
    except subprocess.TimeoutExpired:
        logger.error(f"{tool_name_logging} ({target_identifier_logging}) TIMED OUT after {timeout_seconds}s.")
        full_stderr += f"\nError: Command timed out after {timeout_seconds}s."
        if 'process' in locals() and process.poll() is None: process.kill(); outs, errs = process.communicate(); full_stdout += outs or ""; full_stderr += errs or ""
    except FileNotFoundError:
        err_msg = f"{tool_name_logging} NOT FOUND. Command: {' '.join(map(str,cmd_str_list))}. Check install/PATH/config."
        logger.error(err_msg); full_stderr += f"\nError: {err_msg}"
    except Exception as e:
        err_msg = f"EXCEPTION running {tool_name_logging} for '{target_identifier_logging}'. Cmd: {' '.join(map(str,cmd_str_list))}. Error: {e}"
        logger.error(err_msg, exc_info=False); full_stderr += f"\nException: {str(e)}" # Keep exc_info=False for cleaner logs unless debugging common.py itself
    
    try:
        with open(raw_out_file, 'w', encoding='utf-8') as f:
            f.write(f"--- CMD: {' '.join(map(str,command_parts))} ---\n--- CWD: {cwd} ---\n--- EXIT CODE: {ret_code} ---\n\n--- STDOUT ---\n{full_stdout}\n\n--- STDERR ---\n{full_stderr}")
        logger.info(f"Raw output for {tool_name_logging} saved to {raw_out_file}")
    except Exception as e: logger.error(f"Failed to write raw output for {tool_name_logging} to {raw_out_file}: {e}")
    return full_stdout.strip(), full_stderr.strip(), ret_code

def db_log_tool_run(db_conn, scan_id, tool_name, status, stdout, stderr, target_identifier):
    try:
        cursor = db_conn.cursor()
        cursor.execute("INSERT INTO tool_logs (scan_id,tool_name,status,output,errors,target_info,timestamp) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                       (scan_id,tool_name,status,stdout[:50000],stderr[:10000],str(target_identifier)))
        db_conn.commit()
    except Exception as e: logger.error(f"DB log_tool_run error ({tool_name}, {scan_id}): {e}")

def db_store_structured_result(db_conn, scan_id, source_tool_name, result_type, data_payload, target_identifier):
    try:
        cursor = db_conn.cursor()
        json_data = json.dumps(data_payload) if not isinstance(data_payload, str) else data_payload
        cursor.execute("INSERT INTO results (scan_id,tool_name,result_type,data,target_info,timestamp) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                       (scan_id,source_tool_name,result_type,json_data,str(target_identifier)))
        db_conn.commit()
    except Exception as e: logger.error(f"DB store_structured_result error ({source_tool_name}, {result_type}, {scan_id}): {e}")