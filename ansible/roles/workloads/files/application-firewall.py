"""Require the verified deployment's actual UID dispatch before rootless activation."""

import json
import subprocess
import sys


def inspect_dispatch(table):
    dispatches = []
    for item in table["nftables"]:
        rule = item.get("rule")
        if not rule or (rule["family"], rule["table"], rule["chain"]) != (
            "inet",
            "steward",
            "output",
        ):
            continue
        for expr in rule["expr"]:
            dispatch = expr.get("vmap")
            if dispatch and dispatch["key"] == {"meta": {"key": "skuid"}}:
                dispatches.append(dispatch["data"]["set"])
    if len(dispatches) != 1:
        raise ValueError("expected one socket UID verdict map in the steward output chain")
    verdicts = {}
    for uid, verdict in dispatches[0]:
        if type(uid) is not int or uid in verdicts:
            raise ValueError("expected unique numerical UID verdict keys")
        verdicts[uid] = verdict
    return verdicts


def require_verified_firewall(policy, expected_source, expected_dispatch, table):
    if (
        policy["state"] != "verified"
        or policy["source"] != expected_source
        or not policy["runtime"]
        or policy["runtime"] != policy["verified_runtime"]
    ):
        raise ValueError("live firewall is not the verified application policy")
    verdicts = inspect_dispatch(table)
    for uid, chain in expected_dispatch.items():
        if verdicts.get(int(uid)) != {"jump": {"target": chain}}:
            raise ValueError(f"live firewall has no expected verdict for UID {uid}")


def main():
    expected = json.load(sys.stdin)
    policy_command = ["/usr/bin/python3", "/etc/steward/nftables/firewall-policy.py", "inspect"]
    try:
        policy = json.loads(subprocess.check_output(policy_command, timeout=20))
        table = json.loads(
            subprocess.check_output(
                ["/usr/sbin/nft", "-j", "-s", "-n", "list", "table", "inet", "steward"], timeout=20
            )
        )
        require_verified_firewall(policy, expected["source"], expected["dispatch"], table)
        # Reject a drift between the inspection and the independent dispatch observation.
        if json.loads(subprocess.check_output(policy_command, timeout=20)) != policy:
            raise ValueError("verified firewall changed during inspection")
        print(json.dumps({"runtime": policy["verified_runtime"]}))
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
