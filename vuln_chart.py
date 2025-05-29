import matplotlib
matplotlib.use('Agg') # Use non-interactive backend, suitable for web servers
import matplotlib.pyplot as plt
import sqlite3
import json
import os
from tools.common import CYBERSAGE_BASE_DIR, TOOL_CONFIG, logger # Use common logger

# --- CHART CONFIG (can also be moved to tools.yaml if more complex) ---
CHART_COLORS = {
    "critical": "#FF0000", # Red
    "high": "#FFA500",     # Orange
    "medium": "#FFFF00",   # Yellow
    "low": "#008000",      # Green
    "info": "#ADD8E6",     # Light Blue
    "unknown": "#808080"   # Grey
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def generate_vuln_chart(db_path, scan_id, output_image_path):
    """
    Generates a bar chart of vulnerability severities from Nuclei results in the database.
    Saves the chart to output_image_path.
    """
    logger.info(f"Generating vulnerability chart for scan_id: {scan_id} from DB: {db_path}")
    severity_counts = {s: 0 for s in SEVERITY_ORDER}

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Query the 'results' table for Nuclei findings for the given scan_id
        # The 'data' column stores the full JSON output from Nuclei for each finding.
        cursor.execute("""
            SELECT data FROM results 
            WHERE scan_id = ? AND tool_name = 'nuclei' AND result_type = 'vulnerability_nuclei'
        """, (scan_id,))
        
        rows = cursor.fetchall()
        
        if not rows:
            logger.info(f"No Nuclei results found in DB for scan_id {scan_id} to generate chart.")
            # Create a blank chart or a "no data" placeholder image
            plt.figure(figsize=(8, 6))
            plt.text(0.5, 0.5, 'No vulnerability data found for this scan.', 
                     horizontalalignment='center', verticalalignment='center', 
                     fontsize=12, color='grey')
            plt.title(f'Vulnerability Severity Distribution\nScan ID: {scan_id}')
            plt.axis('off') # Turn off axis for text message
            plt.savefig(output_image_path)
            plt.close()
            return True


        for row in rows:
            try:
                # row[0] contains the JSON string from the 'data' column
                nuclei_finding_json = json.loads(row[0])
                # Extract severity from the 'info' block
                severity = nuclei_finding_json.get('info', {}).get('severity', 'unknown').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else: # If severity is not in predefined list, count as 'unknown'
                    severity_counts["unknown"] += 1
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON for a Nuclei result in scan {scan_id}: {e} - Data: {row[0][:100]}...")
            except Exception as e:
                logger.error(f"Unexpected error processing row for chart generation {scan_id}: {e} - Data: {row[0][:100]}...")


        # Prepare data for plotting
        labels = [s.capitalize() for s in SEVERITY_ORDER if severity_counts[s] > 0] # Only plot severities with counts
        counts = [severity_counts[s] for s in SEVERITY_ORDER if severity_counts[s] > 0]
        colors_to_use = [CHART_COLORS[s] for s in SEVERITY_ORDER if severity_counts[s] > 0]

        if not counts: # No valid severities counted, even if rows existed
            logger.info(f"No valid severities counted for scan_id {scan_id}, generating 'no data' chart.")
            # Similar "no data" placeholder as above
            plt.figure(figsize=(8, 6))
            plt.text(0.5, 0.5, 'No parsable vulnerability severity data.', 
                     horizontalalignment='center', verticalalignment='center', 
                     fontsize=12, color='grey')
            plt.title(f'Vulnerability Severity Distribution\nScan ID: {scan_id}')
            plt.axis('off')
            plt.savefig(output_image_path)
            plt.close()
            return True

        # Create the plot
        plt.figure(figsize=(10, 7)) # Adjusted size
        bars = plt.bar(labels, counts, color=colors_to_use)
        
        plt.title(f'Vulnerability Severity Distribution\nScan ID: {scan_id}', fontsize=16)
        plt.xlabel('Severity', fontsize=14)
        plt.ylabel('Number of Vulnerabilities', fontsize=14)
        plt.xticks(rotation=45, ha="right", fontsize=12)
        plt.yticks(fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout() # Adjust layout to prevent labels from overlapping

        # Add counts on top of bars
        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.05 * max(counts, default=1), # Adjust offset based on max count
                     int(yval), # Ensure integer display
                     ha='center', va='bottom', fontsize=10)

        plt.savefig(output_image_path)
        plt.close() # Close the plot to free memory
        logger.info(f"Vulnerability chart saved to {output_image_path}")
        return True

    except sqlite3.Error as e:
        logger.error(f"SQLite error while generating chart for scan {scan_id}: {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"Failed to generate vulnerability chart for scan {scan_id}: {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    print("Testing vuln_chart.py...")
    # --- Setup for standalone test ---
    # This requires a dummy database with some dummy Nuclei results.
    DUMMY_DB_NAME = "test_cybersage_chart.db"
    TEST_SCAN_ID = "chart_test_scan_001"
    
    # Base directory for CyberSage data (taken from common.py structure)
    cs_base_dir = os.path.join(os.path.expanduser("~"), ".cybersage_v2_chart_test")
    os.makedirs(cs_base_dir, exist_ok=True)
    
    dummy_db_path = os.path.join(cs_base_dir, DUMMY_DB_NAME)
    output_chart_path = os.path.join(cs_base_dir, "test_vuln_chart.png")

    # Create dummy DB and insert data
    conn_test = None
    try:
        if os.path.exists(dummy_db_path):
            os.remove(dummy_db_path) # Clean start
        conn_test = sqlite3.connect(dummy_db_path)
        cursor_test = conn_test.cursor()
        # Create tables (simplified version of app.py's schema for this test)
        cursor_test.execute("""
        CREATE TABLE IF NOT EXISTS results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            tool_name TEXT,
            result_type TEXT,
            data TEXT,
            target_info TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        conn_test.commit()

        # Dummy Nuclei results
        dummy_nuclei_findings = [
            {"info": {"severity": "critical"}, "matched-at": "target1"},
            {"info": {"severity": "critical"}, "matched-at": "target2"},
            {"info": {"severity": "high"}, "matched-at": "target1"},
            {"info": {"severity": "medium"}, "matched-at": "target3"},
            {"info": {"severity": "medium"}, "matched-at": "target1"},
            {"info": {"severity": "medium"}, "matched-at": "target2"},
            {"info": {"severity": "low"}, "matched-at": "target4"},
            {"info": {"severity": "info"}, "matched-at": "target1"},
            {"info": {"severity": "other"}, "matched-at": "target_unknown"} # Test 'unknown'
        ]
        for finding in dummy_nuclei_findings:
            cursor_test.execute(
                "INSERT INTO results (scan_id, tool_name, result_type, data, target_info) VALUES (?, ?, ?, ?, ?)",
                (TEST_SCAN_ID, "nuclei", "vulnerability_nuclei", json.dumps(finding), finding["matched-at"])
            )
        conn_test.commit()
        logger.info(f"Dummy data inserted into {dummy_db_path} for scan_id {TEST_SCAN_ID}")
        
        # Test with data
        success = generate_vuln_chart(dummy_db_path, TEST_SCAN_ID, output_chart_path)
        if success:
            logger.info(f"Test chart generated successfully: {output_chart_path}")
        else:
            logger.error("Test chart generation failed.")

        # Test with a scan_id that has no data
        TEST_SCAN_ID_NO_DATA = "chart_test_scan_no_data"
        output_chart_no_data_path = os.path.join(cs_base_dir, "test_vuln_chart_no_data.png")
        success_no_data = generate_vuln_chart(dummy_db_path, TEST_SCAN_ID_NO_DATA, output_chart_no_data_path)
        if success_no_data:
            logger.info(f"Test chart (no data) generated successfully: {output_chart_no_data_path}")
        else:
            logger.error("Test chart (no data) generation failed.")


    except Exception as e:
        logger.error(f"Error during vuln_chart.py standalone test: {e}", exc_info=True)
    finally:
        if conn_test:
            conn_test.close()
        # Clean up dummy db after test, or inspect it manually
        # if os.path.exists(dummy_db_path):
        #     os.remove(dummy_db_path)
        # if os.path.exists(output_chart_path):
        #     os.remove(output_chart_path)
        # if os.path.exists(output_chart_no_data_path):
        #      os.remove(output_chart_no_data_path)
        # Example: comment out cleanup to inspect files -> logger.info(f"Test files are in {cs_base_dir}")
    logger.info(f"Standalone test finished. Check logs and {cs_base_dir} for outputs.")