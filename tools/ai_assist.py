# CyberSageV2/tools/ai_assist.py
import yaml
import os
import json
from openai import OpenAI # OpenRouter uses OpenAI compatible SDK

# --- CONFIG LOAD ---
try:
    from .common import TOOL_CONFIG as COMMON_TOOL_CONFIG, logger as common_logger
    TOOL_CONFIG = COMMON_TOOL_CONFIG; logger = common_logger
except (ImportError, AttributeError):
    import logging; logger = logging.getLogger("AIServiceStandalone"); # Basic logger
    _cfg_path = os.path.join(os.path.dirname(__file__),'..','config','tools.yaml')
    if not os.path.exists(_cfg_path): _cfg_path = os.path.join(os.getcwd(),'config','tools.yaml')
    try:
        with open(_cfg_path, 'r') as f_cfg: TOOL_CONFIG = yaml.safe_load(f_cfg)
    except FileNotFoundError: logger.error("AI Config file tools.yaml not found."); TOOL_CONFIG = {}

OPENROUTER_API_KEY = TOOL_CONFIG.get('openai_api_key', '') # Use the same key name for simplicity
OPENROUTER_API_BASE = TOOL_CONFIG.get('openrouter_api_base', 'https://openrouter.ai/api/v1')
OPENROUTER_MODEL = TOOL_CONFIG.get('openrouter_model_preference', 'openai/gpt-3.5-turbo') # Default, user can override in config
# Example: openrouter_model_preference: "mistralai/mistral-7b-instruct"

# Site name for HTTP referrer, if required by OpenRouter (good practice)
# You can set this in config.yaml or leave it as a default.
HTTP_REFERRER = TOOL_CONFIG.get('openrouter_http_referrer', 'http://localhost:5000') 
# Your app name for OpenRouter to identify requests (optional but good)
APP_TITLE = TOOL_CONFIG.get('openrouter_app_title', 'CyberSageV2')


def get_openrouter_client():    
    if OPENROUTER_API_KEY and OPENROUTER_API_KEY != "sk-or-v1-YOUR_OPENROUTER_API_KEY_HERE": # Check it's not the placeholder
        try:
            client = OpenAI(
                base_url=OPENROUTER_API_BASE,
                api_key=OPENROUTER_API_KEY,
                default_headers={ # Optional, but good for OpenRouter
                    "HTTP-Referer": HTTP_REFERRER, 
                    "X-Title": APP_TITLE, 
                }
            )
            logger.info(f"OpenRouter client initialized. Preferred Model: {OPENROUTER_MODEL}")
            return client
        except Exception as e:
            logger.error(f"Failed to initialize OpenRouter client: {e}")
            return None
    logger.warning("OpenRouter API key not configured or is placeholder. AI summary will be generic placeholder.")
    return None

def summarize_vulnerabilities_ai(vulnerabilities_data_list, target_info=""):
    client = get_openrouter_client()
    
    if not vulnerabilities_data_list:
        return "No vulnerabilities were provided to the AI for summarization. Cannot generate AI-specific insights."

    # Prepare a concise and structured summary of findings for the prompt
    prompt_vuln_details = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}

    for i, vuln_item in enumerate(vulnerabilities_data_list):
        info = vuln_item.get('info', {})
        name = info.get('name', "N/A")
        severity = info.get('severity', 'unknown').lower()
        description = info.get('description', "No description.")[:150] # Limit description length
        matched_at = vuln_item.get('matched-at', vuln_item.get('host', 'N/A'))
        tags = ", ".join(info.get('tags', []))

        if severity in severity_counts: severity_counts[severity] += 1
        else: severity_counts["unknown"] += 1
        
        # Limit the number of detailed vulns in the prompt to manage token count/cost
        if i < 5 or (severity in ["critical", "high"] and i < 10): # Prioritize critical/high
            prompt_vuln_details.append(
                f"- Name: {name}\n  Severity: {severity.capitalize()}\n  Location: {matched_at}\n  Description Snippet: {description}...\n  Tags: {tags}"
            )
    
    findings_summary_for_prompt = "\n".join(prompt_vuln_details)
    if len(vulnerabilities_data_list) > len(prompt_vuln_details):
        findings_summary_for_prompt += f"\n\n(...and {len(vulnerabilities_data_list) - len(prompt_vuln_details)} more vulnerabilities of varying severities.)"

    total_vulns = len(vulnerabilities_data_list)
    counts_str = ", ".join([f"{count} {sev.capitalize()}" for sev, count in severity_counts.items() if count > 0])

    prompt = f"""
You are CyberSage AI, an expert cybersecurity analyst. Your task is to provide a concise, actionable summary of penetration testing findings for the target: '{target_info}'.

Total vulnerabilities identified: {total_vulns} ({counts_str}).

Key Findings Snippets:
{findings_summary_for_prompt}

Based *only* on the information provided above:
1. Briefly state the overall security posture (e.g., critical concerns, moderate risks, generally secure with minor issues).
2. Highlight the 2-3 most impactful *types* of vulnerabilities or attack vectors observed.
3. Suggest 2-3 high-level, actionable remediation themes or best practices relevant to these findings.
Be professional, clear, and avoid making up information not present in the snippets. Focus on impact and remediation.
Keep the entire summary to about 150-250 words.
"""

    if client: # Actual API call if client (and API key) is available
        logger.info(f"Sending prompt to OpenRouter (model: {OPENROUTER_MODEL}). Target: {target_info}. Prompt length (approx): {len(prompt)} chars.")
        try:
            chat_completion = client.chat.completions.create(
                model=OPENROUTER_MODEL, # Use the configured model
                messages=[
                    {"role": "system", "content": "You are CyberSage AI, a helpful and concise cybersecurity analyst."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300 # Limit response length to control cost
            )
            ai_summary = chat_completion.choices[0].message.content
            logger.info(f"Received AI summary from OpenRouter for {target_info}.")
            return f"**CyberSage AI Analysis (via OpenRouter - {OPENROUTER_MODEL}):**\n\n{ai_summary}"
        except Exception as e:
            logger.error(f"OpenRouter API call failed: {e}")
            return (
                f"**AI Summary Error (OpenRouter - {OPENROUTER_MODEL})**\n\n"
                f"An error occurred while communicating with the AI model: {str(e)[:100]}...\n"
                "Please check your OpenRouter API key, model selection in `config/tools.yaml`, and account status.\n\n"
                f"Based on raw data: {total_vulns} potential issues found ({counts_str}). Manual review recommended."
            )
    else: # Fallback to a more detailed STUB if API key is missing
        logger.warning("OpenRouter client not available (API key likely missing/invalid). Using detailed stub summary.")
        return (
            f"**AI Summary (Enhanced Stub - API Key Not Configured for '{target_info}')**\n\n"
            f"The scan reported {total_vulns} potential vulnerabilities: ({counts_str}).\n"
            "**Simulated Prioritization:**\n"
            f"- Critical ({severity_counts['critical']}) & High ({severity_counts['high']}): These typically require immediate investigation. Common examples include Remote Code Execution (RCE), SQL Injection, or severe misconfigurations.\n"
            f"- Medium ({severity_counts['medium']}): Should be addressed in a timely manner. Often represent exploitable flaws that might require specific conditions.\n"
            f"- Low ({severity_counts['low']}) & Info ({severity_counts['info']}): Review and fix as part of regular security hygiene.\n\n"
            "**Generic Remediation Themes (Simulated):**\n"
            "1. **Patch Management:** Update all software and dependencies.\n"
            "2. **Input Validation:** Sanitize all inputs to prevent injection attacks (XSS, SQLi).\n"
            "3. **Secure Configuration:** Remove default credentials, disable unused services, apply least privilege.\n\n"
            "*This is a simulated analysis. For a real AI-powered summary, configure your OpenRouter API key in `config/tools.yaml`.*"
        )

if __name__ == '__main__':
    logger.info("Testing ai_assist.py with OpenRouter integration...")
    # Dummy data
    dummy_vulns = [
        {"info": {"name": "SQL Injection", "severity": "critical", "description": "Login form vulnerable", "tags": ["owasp-a1", "sqli"]}, "matched-at": "http://test.com/login"},
        {"info": {"name": "Reflected XSS", "severity": "high", "description": "Search query reflected", "tags": ["owasp-a7", "xss"]}, "matched-at": "http://test.com/search?q=X"},
        {"info": {"name": "Outdated jQuery", "severity": "medium", "description": "jQuery v1.8.0 used", "tags": ["CVE-xxxx-xxxx"]}, "matched-at": "http://test.com/js/jquery.js"},
    ]
    summary = summarize_vulnerabilities_ai(dummy_vulns, "test.com")
    print("\n--- Test AI Summary (OpenRouter) ---")
    print(summary)

    # Test with empty vulns
    empty_summary = summarize_vulnerabilities_ai([], "no_vulns.com")
    print("\n--- Test AI Summary (No Vulns) ---")
    print(empty_summary)
