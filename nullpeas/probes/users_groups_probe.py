import os
import pwd
import grp
from typing import Dict, Any, List


def run(state: dict):
    user_info: Dict[str, Any] = {
        "name": None,
        "uid": None,
        "gid": None,
        "home": None,
        "shell": None,
        "groups": [],
        "is_root": False,
        "in_sudo_group": False,
        "in_wheel_group": False,
        "in_docker_group": False,
        "in_lxd_group": False,
        "error": None,
    }

    try:
        uid = os.getuid()
        user_info["uid"] = uid

        pw = pwd.getpwuid(uid)
        user_info["name"] = pw.pw_name
        user_info["gid"] = pw.pw_gid
        user_info["home"] = pw.pw_dir
        user_info["shell"] = pw.pw_shell

        # Collect group memberships
        group_ids: List[int] = os.getgroups()
        groups: List[Dict[str, Any]] = []

        for gid in group_ids:
            try:
                gr = grp.getgrgid(gid)
                groups.append({
                    "name": gr.gr_name,
                    "gid": gr.gr_gid,
                })
            except KeyError:
                groups.append({
                    "name": None,
                    "gid": gid,
                })

        user_info["groups"] = groups

        # Convenience flags for triggers/modules
        user_info["is_root"] = (uid == 0)

        group_names = {g["name"] for g in groups if g["name"]}
        user_info["in_sudo_group"] = "sudo" in group_names
        user_info["in_wheel_group"] = "wheel" in group_names
        user_info["in_docker_group"] = "docker" in group_names
        user_info["in_lxd_group"] = "lxd" in group_names

    except Exception as e:
        user_info["error"] = str(e)

    state["user"] = user_info
