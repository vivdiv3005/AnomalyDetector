import requests
import json
import time
import os
from datetime import datetime
from collections import deque

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.1:8b"        # Switch to llama3.1:70b for production
LOG_FILE = "ot_simulation.log"
BATCH_SIZE = 10              # Lines per analysis window
POLL_INTERVAL = 5            # Seconds between checks
ALERT_LOG = "alerts.jsonl"   # Where alerts are saved

# The system prompt — this makes Llama an OT security analyst
SYSTEM_PROMPT = """You are a senior OT/ICS cybersecurity analyst specializing in 
industrial control system security. You analyze Modbus, DNP3, SCADA, and PLC logs 
for anomalies and cyber threats.

For each batch of logs you receive, you must respond ONLY with a valid JSON object 
in exactly this format — no other text:

{
  "anomalies_found": true or false,
  "risk_level": "LOW" or "MEDIUM" or "HIGH" or "CRITICAL",
  "incidents": [
    {
      "log_line": "the exact suspicious log line",
      "anomaly_type": "brief type label",
      "physical_impact": "what could happen to the physical process",
      "mitre_attack_ics": "ATT&CK for ICS technique name and ID",
      "iec_62443_control": "relevant IEC 62443 functional requirement",
      "recommended_action": "what the analyst should do immediately"
    }
  ],
  "summary": "one sentence summary of this log window"
}

If no anomalies are found, set anomalies_found to false and incidents to empty list."""


def analyze_logs_with_llm(log_batch: list[str]) -> dict:
    """Send a batch of log lines to local Llama for analysis."""
    log_text = "\n".join(log_batch)
    
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze these OT logs:\n\n{log_text}"}
        ],
        "stream": False,
        "options": {"temperature": 0.1}  # Low temp = consistent structured output
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        response.raise_for_status()
        content = response.json()["message"]["content"].strip()
        
        # Strip markdown fences if model adds them
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        
        return json.loads(content)
    
    except json.JSONDecodeError:
        return {"anomalies_found": False, "risk_level": "LOW",
                "incidents": [], "summary": "Parse error — model output not valid JSON"}
    except Exception as e:
        return {"anomalies_found": False, "risk_level": "LOW",
                "incidents": [], "summary": f"Analysis error: {str(e)}"}


def tail_log_file(filepath: str):
    """Watch a log file and yield new lines as they appear."""
    with open(filepath, "r") as f:
        f.seek(0, 2)  # Start at end of file
        buffer = deque(maxlen=BATCH_SIZE)
        
        while True:
            line = f.readline()
            if line:
                buffer.append(line.strip())
                if len(buffer) >= BATCH_SIZE:
                    yield list(buffer)
                    buffer.clear()
            else:
                if buffer:  # Flush partial batch every poll interval
                    yield list(buffer)
                    buffer.clear()
                time.sleep(POLL_INTERVAL)


def save_alert(result: dict, batch: list[str]):
    """Save alerts to JSONL file for dashboard to read."""
    if result.get("anomalies_found"):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "risk_level": result.get("risk_level", "UNKNOWN"),
            "incidents": result.get("incidents", []),
            "summary": result.get("summary", ""),
            "raw_logs": batch
        }
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")
        print(f"🚨 ALERT [{alert['risk_level']}]: {alert['summary']}")
    else:
        print(f"✓ Clean window — {result.get('summary', '')}")


def run_detector():
    print(f"OT Log Anomaly Detector started")
    print(f"Model: {MODEL} | Log: {LOG_FILE} | Batch: {BATCH_SIZE} lines")
    print("-" * 60)
    
    # Wait for log file to exist
    while not os.path.exists(LOG_FILE):
        print(f"Waiting for {LOG_FILE}...")
        time.sleep(2)
    
    for batch in tail_log_file(LOG_FILE):
        print(f"\nAnalyzing {len(batch)} log lines...")
        result = analyze_logs_with_llm(batch)
        save_alert(result, batch)


if __name__ == "__main__":
    run_detector()
