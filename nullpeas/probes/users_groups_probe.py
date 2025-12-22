import os
import pwd
import subprocess
from typing import Dict, Any

# 1) Run 'id -a' and capture raw output
def run(state: Dict[str, Any]) -> None: 
   """
   Collect current user info:
   - UID (via os.getuid())
   - Username (via pwd.getpwuid())
   - Groups (parsed from 'id -a' command output)
   """

   # Run 'id -a' command and capture raw output
   try:
      result = subprocess.run(
         ["id", "-a"],
         capture_output=True,
         text=True,
         check=True # Raises CalledProcessError on non-zero exit status
      )
      raw_output = result.stdout.strip()
   except Exception as e:
      state["user"] = {
         "error": f"Failed to run 'id -a': {str(e)}"
      }
      return
   
   # 2) Get UID and username from stdlib (this is more reliable)
   try:
      uid = os.getuid()
      name = pwd.getpwuid(uid).pw_name
   except Exception as e:
      uid = None
      name = "unknown"

   groups: list[str] = []
   
   try:
    parts = raw_output.split()
    groups_part = [p for p in parts if p.startswith("groups=")]
    groups_part = groups_part[0] if groups_part else ""
    if groups_part:
       raw_groups = groups_part.split("=", 1)[1]
       for entry in raw_groups.split(","):
          if "(" in entry and ")" in entry:
             groups.append(entry.split("(")[1].split(")")[0])
    
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

            
    
