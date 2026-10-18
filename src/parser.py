from models import ProcessNode
from datetime import datetime
from collections.abc import Generator
import json

def parser(raw_event: dict) -> ProcessNode | None:
    try: 
        if raw_event.get("EventID") != 1:
            return None
        
        time = datetime.strptime(raw_event["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")


        process_event = ProcessNode(
            raw_event.get("ProcessGuid"), 
            int(raw_event.get("ProcessId")), 
            raw_event.get("Image"), 
            raw_event.get("CommandLine"), 
            time, 
            raw_event.get("User"), 
            raw_event.get("ParentProcessGuid"), 
            )   

        return process_event
    
    except (KeyError, ValueError, TypeError):
        return None

def load_events(file_path: str) -> Generator[ProcessNode, None, None]:

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw_event = json.loads(line)
                node = parser(raw_event)
                if node is not None:
                    yield node
            except json.JSONDecodeError:
                continue
            
    