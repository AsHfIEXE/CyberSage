from .common import TOOL_CONFIG, get_tool_path, run_tool_command, logger, CYBERSAGE_BASE_DIR
from .common import db_log_tool_run, db_store_structured_result
import json, os, tempfile, xml.etree.ElementTree as ET


def run_nmap_scan(target_host_or_ip, scan_id, db_conn):
    open_ports_detailed = []
    nmap_tool_name = "nmap"
    nmap_executable = get_tool_path(nmap_tool_name)
    if not nmap_executable:
        logger.error(f"{nmap_tool_name} path not found. Check config: tool_paths.{nmap_tool_name}")
        db_log_tool_run(db_conn, scan_id, nmap_tool_name, "config_error_path", "", "", target_host_or_ip)
        return open_ports_detailed

    nmap_timing = TOOL_CONFIG.get("nmap_timing_template", "-T4")
    nmap_scripts_arg = "-sC" if TOOL_CONFIG.get("nmap_default_scripts", True) else ""
    nmap_port_options_str = TOOL_CONFIG.get("nmap_port_scan_options", "--top-ports 2000 -sT -n")

    temp_nmap_output_xml = None
    nmap_final_status = "failed_to_start"
    nmap_stdout_full, nmap_stderr_full = "", ""

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".xml", prefix=f"cs_nmap_{scan_id}_") as tmp_xml:
            temp_nmap_output_xml = tmp_xml.name

        cmd_nmap_base = [nmap_executable, "-sV"]
        if nmap_scripts_arg:
            cmd_nmap_base.append(nmap_scripts_arg)
        cmd_nmap_base.extend(nmap_port_options_str.split())
        cmd_nmap_base.extend([target_host_or_ip, "-oX", temp_nmap_output_xml, nmap_timing, "-Pn"])
        cmd_nmap = [arg for arg in cmd_nmap_base if arg]

        logger.info(f"Starting Nmap scan on {target_host_or_ip}. Cmd: {' '.join(cmd_nmap)}")
        nmap_stdout_full, nmap_stderr_full, nmap_ret_code = run_tool_command(
            cmd_nmap, nmap_tool_name, target_host_or_ip, timeout_seconds=3600
        )

        if nmap_ret_code == 127 or ("command not found" in nmap_stderr_full.lower() and "nmap" in nmap_stderr_full.lower()):
            nmap_final_status = "config_error_not_found"
            logger.error(f"Nmap exec not found: '{nmap_executable}'.")
        elif nmap_ret_code == 0:
            if os.path.exists(temp_nmap_output_xml) and os.path.getsize(temp_nmap_output_xml) > 0:
                logger.debug(f"Nmap XML output: {temp_nmap_output_xml}")
                try:
                    tree = ET.parse(temp_nmap_output_xml)
                    root = tree.getroot()
                    for host_node in root.findall('host'):
                        host_ip_elem = host_node.find("./address[@addrtype='ipv4']") or host_node.find("./address[@addrtype='ipv6']")
                        host_ip = host_ip_elem.get('addr') if host_ip_elem is not None else target_host_or_ip
                        ports_node = host_node.find('ports')

                        if ports_node:
                            for port_node in ports_node.findall('port'):
                                p_id = port_node.get('portid')
                                protocol = port_node.get('protocol')
                                state_node = port_node.find('state')

                                if state_node is not None and state_node.get('state') == 'open':
                                    service_node = port_node.find('service')
                                    s_name = service_node.get('name') if service_node is not None else 'unknown'
                                    prod = service_node.get('product') if service_node is not None else ''
                                    ver = service_node.get('version') if service_node is not None else ''
                                    xtra = service_node.get('extrainfo') if service_node is not None else ''
                                    banner = service_node.get('servicefp') if service_node is not None else ''
                                    tunnel = service_node.get('tunnel') if service_node is not None else ''

                                    scripts_data = []
                                    for script_elem in port_node.findall('script'):
                                        sid, sout = script_elem.get("id"), script_elem.get("output")
                                        if sid and sout:
                                            scripts_data.append({"id": sid, "output": sout.strip()})

                                    port_info = {
                                        "port": p_id,
                                        "protocol": protocol,
                                        "state": "open",
                                        "service": s_name,
                                        "product": prod,
                                        "version": ver,
                                        "extrainfo": xtra,
                                        "scripts": scripts_data,
                                        "host": host_ip,
                                        "banner": banner,
                                        "tunnel": tunnel
                                    }

                                    open_ports_detailed.append(port_info)
                                    db_store_structured_result(db_conn, scan_id, nmap_tool_name, "open_port_service_detail", port_info, host_ip)

                    nmap_final_status = "success" if open_ports_detailed else "success_no_open_ports_parsed"
                except ET.ParseError as e:
                    logger.error(f"Nmap XML parse error: {e}")
                    nmap_stderr_full += f"\nXML parse error: {e}"
                    nmap_final_status = "failed_parsing"
                except Exception as e:
                    logger.exception(f"Error during Nmap XML processing: {e}")
                    nmap_final_status = "failed_processing"
            else:
                logger.warning(f"Nmap ran but output {temp_nmap_output_xml} missing/empty.")
                nmap_final_status = "success_no_xml_output"
        else:
            logger.error(f"Nmap failed. Code: {nmap_ret_code}. Stderr: {nmap_stderr_full[:500]}")
            nmap_final_status = "failed_execution"
    finally:
        if temp_nmap_output_xml and os.path.exists(temp_nmap_output_xml):
            try:
                os.remove(temp_nmap_output_xml)
            except OSError as e:
                logger.warning(f"Could not remove temp file: {e}")

    db_log_tool_run(db_conn, scan_id, nmap_tool_name, nmap_final_status, nmap_stdout_full, nmap_stderr_full, target_host_or_ip)
    logger.info(f"Nmap found details for {len(open_ports_detailed)} ports on {target_host_or_ip}.")
    return open_ports_detailed
