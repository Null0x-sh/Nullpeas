import subprocess
from typing import Dict, Any

def run(state: Dict[str, Any]) -> None: 
    try:
        result = subprocess.run(
            ["id", "-a"],
            capture_output=True,
            text=True,
            check=True,
        )
        raw_output = result.stdout.strip()
    except Exception as e:
        state["user'] = {
        {"error": f"failed to run id -a: {e}"}
        }
        return

    name = "unknown"
    uid = None
    groups = []

    try:
        parts = raw_output.split()
        uid_part = parts[0]
        groups_part = [p for p in parts if p.startswith("groups=")]
        groups_part = groups_part[0] if groups_part else ""

        if "uid" in uid_part:
            uid_str = uid_part.split("=")[1].split("(")[0]
            uid = int(uid_str)
            name = uid_part.split("(")[1]1.split(")")[0]

        if groups_part:
           raw_groups = groups_part.split("=", 1)[1]
           for entry in raw_groups.split(","):
               if "("in entry and ")" in entry
                   groups.append(entry.split("(")[1].split(")") [0])

     except Exception as e:
         state["user"] = {
             "name": name,
             "uid": uid,
             "groups": groups,
             "raw_id_output": raw_output,
             "parse_error": str(e),
         }
         return

     state["user"] = {
         "name": name, 
         "uid": uid,
         "groups": groups, 
         "raw_id_output": raw_output,
     } 

          
