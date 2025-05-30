import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sqlite3
import json
import os
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from tools.common import logger

CHART_COLORS_NIKTO = {
    "Potentially Interesting": "#e76f51",  # Coral
    "Configuration Issue": "#f4a261",      # Sandy Brown
    "Informational": "#48cae4",           # Sky Blue
    "Generic Finding": "#adb5bd"           # Light Gray
}
CHART_COLORS_NUCLEI = {
    "critical": "#d00000",  # Dark Red
    "high": "#f48c06",      # Orange
    "medium": "#ffd60a",    # Yellow
    "low": "#38b000",       # Green
    "info": "#00b4d8",      # Cyan
    "unknown": "#6c757d"    # Gray
}
NIKTO_SEVERITY_ORDER = ["Potentially Interesting", "Configuration Issue", "Informational", "Generic Finding"]
NUCLEI_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

def validate_inputs(db_path: str, scan_id: str, output_image_path: str) -> bool:
    """Validate input parameters for chart generation."""
    if not os.path.isfile(db_path):
        logger.error(f"Database file does not exist: {db_path}")
        return False
    if not scan_id or not isinstance(scan_id, str):
        logger.error("Invalid scan_id provided")
        return False
    if not output_image_path.endswith('.png'):
        logger.error("Output image path must end with .png")
        return False
    output_dir = os.path.dirname(output_image_path)
    if output_dir and not os.path.isdir(output_dir):
        logger.error(f"Output directory does not exist: {output_dir}")
        return False
    return True

def categorize_nikto_finding(msg_text: str) -> str:
    """Categorize a Nikto finding based on its message text."""
    msg_lower = msg_text.lower()
    if any(keyword in msg_lower for keyword in ["might be interesting", "exposes", "directory indexing"]) or ("found" in msg_lower and "version" not in msg_lower):
        return "Potentially Interesting"
    if any(keyword in msg_lower for keyword in ["configuration", "misconfiguration"]) or ("header" in msg_lower and "missing" in msg_lower):
        return "Configuration Issue"
    if any(keyword in msg_lower for keyword in ["version", "allows", "server leaks"]):
        return "Informational"
    return "Generic Finding"

def fetch_vuln_data(cursor: sqlite3.Cursor, scan_id: str) -> Tuple[Optional[Dict], Optional[Dict], str]:
    """Fetch vulnerability data from the database for Nuclei or Nikto."""
    # Try Nuclei data first
    cursor.execute(
        "SELECT data FROM results WHERE scan_id = ? AND tool_name = 'nuclei' AND result_type = 'vulnerability_nuclei'",
        (scan_id,)
    )
    nuclei_rows = cursor.fetchall()
    severity_counts_nuclei = {s: 0 for s in NUCLEI_SEVERITY_ORDER}
    nuclei_findings_count = 0

    for row in nuclei_rows:
        try:
            data = json.loads(row[0])
            severity = data.get('info', {}).get('severity', 'unknown').lower()
            if severity in severity_counts_nuclei:
                severity_counts_nuclei[severity] += 1
            else:
                severity_counts_nuclei["unknown"] += 1
            nuclei_findings_count += 1
        except (json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Failed to parse Nuclei JSON data: {e}")

    if nuclei_findings_count > 0:
        return severity_counts_nuclei, None, "nuclei"

    # Fallback to Nikto data
    cursor.execute(
        "SELECT data FROM results WHERE scan_id = ? AND tool_name = 'nikto' AND result_type = 'vulnerability_nikto'",
        (scan_id,)
    )
    nikto_rows = cursor.fetchall()
    nikto_category_counts = {cat: 0 for cat in NIKTO_SEVERITY_ORDER}
    nikto_findings_count = 0

    for row in nikto_rows:
        try:
            finding = json.loads(row[0])
            msg = finding.get('msg', '')
            category = categorize_nikto_finding(msg)
            nikto_category_counts[category] += 1
            nikto_findings_count += 1
        except (json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Failed to parse Nikto JSON data: {e}")

    return None, nikto_category_counts, "nikto" if nikto_findings_count > 0 else None

def generate_summary_text(data: Dict, tool: str, scan_id: str, output_image_path: str) -> None:
    """Generate a text summary of vulnerability findings."""
    summary_path = output_image_path.replace('.png', '_summary.txt')
    total_findings = sum(data.values())
    summary_lines = [
        f"Vulnerability Scan Summary - Scan ID: {scan_id}",
        f"Tool: {tool.capitalize()}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Findings: {total_findings}",
        "\nBreakdown:"
    ]
    for category, count in data.items():
        if count > 0:
            summary_lines.append(f"  {category.capitalize()}: {count}")
    
    try:
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(summary_lines))
        logger.info(f"Generated summary file: {summary_path}")
    except OSError as e:
        logger.error(f"Failed to write summary file {summary_path}: {e}")

def generate_vuln_chart(db_path: str, scan_id: str, output_image_path: str) -> bool:
    """
    Generate a bar chart of vulnerability findings from Nuclei or Nikto data.

    Args:
        db_path (str): Path to the SQLite database.
        scan_id (str): Unique identifier for the scan.
        output_image_path (str): Path to save the generated chart (PNG).

    Returns:
        bool: True if chart generation succeeds, False otherwise.
    """
    if not validate_inputs(db_path, scan_id, output_image_path):
        return False

    logger.info(f"Generating vulnerability chart for scan_id: {scan_id} from DB: {db_path}")
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Fetch data
        nuclei_data, nikto_data, tool = fetch_vuln_data(cursor, scan_id)
        chart_generated = False
        labels = []
        counts = []
        colors = []
        chart_title = f"Vulnerability Data - Scan ID: {scan_id[:8]}\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        if tool == "nuclei" and nuclei_data:
            labels = [s.capitalize() for s in NUCLEI_SEVERITY_ORDER if nuclei_data[s] > 0]
            counts = [nuclei_data[s] for s in NUCLEI_SEVERITY_ORDER if nuclei_data[s] > 0]
            colors = [CHART_COLORS_NUCLEI.get(s.lower(), "#6c757d") for s in NUCLEI_SEVERITY_ORDER if nuclei_data[s] > 0]
            chart_title = f"Nuclei Vulnerability Severity\n{chart_title}"
            generate_summary_text(nuclei_data, tool, scan_id, output_image_path)
            chart_generated = True
            logger.info(f"Generating chart from Nuclei data ({sum(nuclei_data.values())} findings)")
        elif tool == "nikto" and nikto_data:
            labels = [cat for cat in NIKTO_SEVERITY_ORDER if nikto_data[cat] > 0]
            counts = [nikto_data[cat] for cat in NIKTO_SEVERITY_ORDER if nikto_data[cat] > 0]
            colors = [CHART_COLORS_NIKTO.get(cat, "#adb5bd") for cat in NIKTO_SEVERITY_ORDER if nikto_data[cat] > 0]
            chart_title = f"Nikto Finding Categories\n{chart_title}"
            generate_summary_text(nikto_data, tool, scan_id, output_image_path)
            chart_generated = True
            logger.info(f"Generating chart from Nikto data ({sum(nikto_data.values())} findings)")

        # Plotting
        plt.figure(figsize=(10, 7))
        if chart_generated and counts:
            bars = plt.bar(labels, counts, color=colors, edgecolor='black')
            plt.title(chart_title, fontsize=16, pad=20)
            plt.xlabel('Severity/Category', fontsize=14)
            plt.ylabel('Number of Findings', fontsize=14)
            plt.xticks(rotation=30, ha="right", fontsize=12)
            plt.yticks(fontsize=12)
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            plt.margins(y=0.2)  # Add padding for labels
            plt.legend(
                handles=[plt.Rectangle((0,0),1,1, color=colors[i]) for i in range(len(labels))],
                labels=labels,
                title="Severity/Category",
                loc="upper right",
                fontsize=10
            )
            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.05 * max(counts, default=1),
                         int(yval), ha='center', va='bottom', fontsize=10)
            plt.tight_layout()
        else:
            plt.text(0.5, 0.5, 'No chartable vulnerability data found\n(Nuclei/Nikto)', 
                     horizontalalignment='center', verticalalignment='center', fontsize=12, color='grey')
            plt.title(chart_title, fontsize=16)
            plt.axis('off')
            logger.info(f"No chartable data from Nuclei or Nikto for scan {scan_id}")

        plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
        plt.close()
        return True

    except sqlite3.Error as e:
        logger.error(f"Database error for scan {scan_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Failed to generate vuln chart for scan {scan_id}: {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()                                                                    
