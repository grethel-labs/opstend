"""Inspect a dedicated rootless account without adopting mismatched state."""

import argparse
import grp
import json
import os
import pwd
import stat
import sys
import tempfile
from pathlib import Path

RECORDS = Path("/var/lib/steward/application-identities")


def exact_directory(path, uid, gid, mode, *, create=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise
        path.mkdir(mode=mode)
        os.chown(path, uid, gid, follow_symlinks=False)
        info = path.lstat()
        changed = True
    else:
        changed = False
    if (
        not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (uid, gid)
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise ValueError(f"unexpected type, ownership or mode: {path}")
    return changed


def validate_ranges(filename, name, owner, allocated_ids):
    entries = []
    for line in Path(filename).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, start, count = line.split(":")
        start, count = int(start), int(count)
        if start < 1 or count < 1 or start + count > 2**32 - 1:
            raise ValueError(f"invalid subordinate range in {filename}")
        entries.append((key, start, start + count))
    matches = [entry for entry in entries if entry[0] in {name, str(owner)}]
    if len(matches) != 1 or matches[0][2] - matches[0][1] != 65536:
        raise ValueError(f"{name} requires one persistent 65536-wide range in {filename}")
    match = matches[0]
    if any(
        match[1] < end and start < match[2]
        for key, start, end in entries
        if key not in {name, str(owner)}
    ):
        raise ValueError(f"overlapping subordinate ranges for {name} in {filename}")
    if any(match[1] <= number < match[2] for number in allocated_ids):
        raise ValueError(f"subordinate range for {name} overlaps a local identity in {filename}")
    return [match[1], match[2] - match[1]]


def pin_identity(path, identity, *, create):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            return False
        fd, temp = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(identity, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            Path(temp).unlink(missing_ok=True)
        return True
    if (
        not stat.S_ISREG(info.st_mode)
        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o600)
        or info.st_nlink != 1
        or json.loads(path.read_text()) != identity
    ):
        raise ValueError(f"UID, GID or subordinate ranges changed for {path.name}")
    return False


def inspect_account(name, home, *, create_home=False):
    exact_directory(home.parent, 0, 0, 0o755)
    exact_directory(RECORDS.parent, 0, 0, 0o755)
    exact_directory(RECORDS, 0, 0, 0o700)
    record = RECORDS / name
    linger = Path("/var/lib/systemd/linger") / name
    if os.path.lexists(linger):
        raise ValueError(f"unexpected lingering enrollment: {name}")

    try:
        account = pwd.getpwnam(name)
    except KeyError:
        if create_home or os.path.lexists(home) or os.path.lexists(record):
            raise ValueError(f"missing account for {home}") from None
        try:
            grp.getgrnam(name)
        except KeyError:
            return {"exists": False}
        raise ValueError(f"unexpected group without corresponding account: {name}") from None

    group = grp.getgrnam(name)
    users, groups = pwd.getpwall(), grp.getgrall()
    shadow = [
        line.split(":")[1]
        for line in Path("/etc/shadow").read_text().splitlines()
        if line.startswith(name + ":")
    ]
    if (
        not 30000 <= account.pw_uid <= 39999
        or account.pw_dir != str(home)
        or account.pw_shell != "/usr/sbin/nologin"
        or account.pw_gid != group.gr_gid
        or len(shadow) != 1
        or not shadow[0].startswith("!")
        or set(os.getgrouplist(name, group.gr_gid)) != {group.gr_gid}
        or set(group.gr_mem) - {name}
        or any(user.pw_name != name and user.pw_uid == account.pw_uid for user in users)
        or any(user.pw_name != name and user.pw_gid == group.gr_gid for user in users)
        or any(other.gr_name != name and other.gr_gid == group.gr_gid for other in groups)
    ):
        raise ValueError(f"unexpected account or group attributes for {name}")

    subuid = validate_ranges("/etc/subuid", name, account.pw_uid, {user.pw_uid for user in users})
    # Both shadow-utils files identify an account by name or numeric login UID.
    subgid = validate_ranges(
        "/etc/subgid", name, account.pw_uid, {other.gr_gid for other in groups}
    )
    identity = {
        "uid": account.pw_uid,
        "gid": account.pw_gid,
        "subuid": subuid,
        "subgid": subgid,
    }
    # Check continuity before touching even the application's private home.
    pin_identity(record, identity, create=False)
    changed = False
    if create_home or os.path.lexists(home):
        changed = exact_directory(home, account.pw_uid, account.pw_gid, 0o700, create=create_home)
    for base, relative in (
        (home, ".config/systemd/user"),
        (home, ".config/systemd/user.control"),
        (home, ".local/share/systemd/user"),
        (home, ".config/systemd/user-generators"),
        (home, ".config/systemd/user-environment-generators"),
        (home, ".config/containers/systemd"),
        (home, ".config/containers/systemd-dev"),
        (Path(f"/run/user/{account.pw_uid}"), "systemd/user"),
        (Path(f"/run/user/{account.pw_uid}"), "systemd/user.control"),
        (Path(f"/run/user/{account.pw_uid}"), "containers/systemd"),
    ):
        if os.path.lexists(base / relative):
            raise ValueError(f"unexpected local systemd or Quadlet source: {base / relative}")
    pinned = pin_identity(record, identity, create=create_home)
    return {**identity, "exists": True, "changed": changed or pinned}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("home", type=Path)
    parser.add_argument("--create-home", action="store_true")
    args = parser.parse_args()
    if args.home != Path("/srv/steward/application-users") / args.name:
        parser.error("unexpected home path")
    os.umask(0o022)
    try:
        print(json.dumps(inspect_account(args.name, args.home, create_home=args.create_home)))
    except (OSError, KeyError, ValueError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
