from engine import DetectionEngine
from rules import OfficeSpawnShellRule
from rules import SuspiciousEncodedCommandRule
from parser import load_events
import json
import argparse

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="HostLineage-Engine: Lightweight EDR/SIEM Process Tree & Detection Core")

    parser.add_argument(
        "-i",
        "--input",
        type=str,
        default="events.jsonl",
        help="Path to the input NDJSON telemetry file"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="alerts.json",
        help="Path to save detected alerts in NDJSON format"
    )
    

    args = parser.parse_args()


    engine = DetectionEngine()
    engine.register_rule(OfficeSpawnShellRule())
    engine.register_rule(SuspiciousEncodedCommandRule())

    alerts = []

    for process in load_events(args.input):
        alerts.extend(engine.process_event(process))

    for alert in alerts:
        chain = " -> ".join([f"{p.image_name} (PID: {p.pid})" for p in alert.lineage])
        print(f"[!] ALERT TRIGGERED: {alert.rule_name}")
        print(f"[-] Severity: {alert.severity} | MITRE: {alert.mitre_technique}")
        print(f"[-] Description: {alert.description}")
        print(f"[-] Target: {alert.process.image_name} (PID: {alert.process.pid}, User: {alert.process.user})")
        print(f"[-] Lineage: {chain}\n")

    with open(args.output, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert.to_dict()) + "\n")
