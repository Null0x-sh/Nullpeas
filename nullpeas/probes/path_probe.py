from typing import Dict, Any, List
import os
import stat
import pwd
import grp


def _split_path(raw: str) -> List[str]:
    """
    Split PATH into clean directory entries.

    - Empty segments are dropped
    - Deduplication is handled later if we need it
    """
    if not raw:
        return []
    segments = [p.strip() for p in raw.split(os.pathsep)]
    return [p for p in segments if p]


def _is_under_prefix(path: str, prefix: str) -> bool:
    if not path or not prefix:
        return False
    # Normalise to avoid trivial false negatives
    path = os.path.abspath(path)
    prefix = os.path.abspath(prefix)
    return path == prefix or path.startswith(prefix + os.sep)


def _safe_get_user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _safe_get_group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except Exception:
        return str(gid)


def run(state: Dict[str, Any]) -> None:
    """
    PATH probe.

    - Reads the current PATH
    - Inspects each directory
    - Records ownership, permissions, and basic context flags
    - Does not modify any filesystem state

    Output schema (high level):

      state["path"] = {
          "raw": "...",
          "entries": [
              {
                  "index": 0,
                  "dir": "/usr/local/sbin",
                  "exists": True,
                  "is_dir": True,
                  "is_symlink": False,
                  "mode": "0755",
                  "owner_uid": 0,
                  "owner_gid": 0,
                  "owner_name": "root",
                  "group_name": "root",
                  "owner_writable": True,
                  "group_writable": False,
                  "world_writable": False,
                  "in_home": False,
                  "in_tmpfs_like": False,
              },
              ...
          ],
          "summary": {
              "total_entries": 10,
              "existing_entries": 9,
              "world_writable_count": 1,
              "group_writable_count": 0,
              "user_writable_count": 2,
          },
      }
    """
    try:
        raw_path = os.environ.get("PATH") or ""
    except Exception:
        raw_path = ""

    entries: List[Dict[str, Any]] = []

    world_writable_count = 0
    group_writable_count = 0
    user_writable_count = 0

    home_dir = os.path.expanduser("~")
    tmpfs_prefixes = ["/tmp", "/var/tmp", "/dev/shm"]

    for idx, segment in enumerate(_split_path(raw_path)):
        entry: Dict[str, Any] = {
            "index": idx,
            "dir": segment,
        }

        # Basic symlink flag is cheap and useful for later reasoning
        entry["is_symlink"] = os.path.islink(segment)

        try:
            st = os.lstat(segment)
        except OSError as e:
            # Directory does not exist or is not reachable
            entry.update(
                {
                    "exists": False,
                    "is_dir": False,
                    "mode": None,
                    "owner_uid": None,
                    "owner_gid": None,
                    "owner_name": None,
                    "group_name": None,
                    "owner_writable": False,
                    "group_writable": False,
                    "world_writable": False,
                    "in_home": False,
                    "in_tmpfs_like": False,
                    "error": str(e),
                }
            )
            entries.append(entry)
            continue

        mode_bits = stat.S_IMODE(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)

        owner_uid = st.st_uid
        owner_gid = st.st_gid
        owner_name = _safe_get_user(owner_uid)
        group_name = _safe_get_group(owner_gid)

        owner_w = bool(mode_bits & stat.S_IWUSR)
        group_w = bool(mode_bits & stat.S_IWGRP)
        world_w = bool(mode_bits & stat.S_IWOTH)

        if owner_w:
            user_writable_count += 1
        if group_w:
            group_writable_count += 1
        if world_w:
            world_writable_count += 1

        in_home = _is_under_prefix(segment, home_dir)
        in_tmpfs_like = any(_is_under_prefix(segment, prefix) for prefix in tmpfs_prefixes)

        entry.update(
            {
                "exists": True,
                "is_dir": is_dir,
                "mode": f"{mode_bits:04o}",
                "owner_uid": owner_uid,
                "owner_gid": owner_gid,
                "owner_name": owner_name,
                "group_name": group_name,
                "owner_writable": owner_w,
                "group_writable": group_w,
                "world_writable": world_w,
                "in_home": in_home,
                "in_tmpfs_like": in_tmpfs_like,
            }
        )

        entries.append(entry)

    state["path"] = {
        "raw": raw_path,
        "entries": entries,
        "summary": {
            "total_entries": len(entries),
            "existing_entries": sum(1 for e in entries if e.get("exists")),
            "world_writable_count": world_writable_count,
            "group_writable_count": group_writable_count,
            "user_writable_count": user_writable_count,
        },
    }