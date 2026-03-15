from __future__ import annotations

import argparse
import sys
import time


ATTACK_SCRIPTS = {
    "nmap": [
        "Priming SYN stealth workflow for {target}",
        "Running simulated host discovery and port triage",
        "Identified services: 22/tcp ssh, 443/tcp https, 1514/tcp wazuh-remoted",
        "Pushing synthesized telemetry into the lab console",
        "Simulation complete for {target}",
    ],
    "ssh_bruteforce": [
        "Queueing credential spray simulation against {target}",
        "Testing staged username and password pairs in mock mode",
        "SOC alert threshold crossed: multiple failed authentication events observed",
        "Rate limiting engaged to preserve the lab state",
        "Simulation complete for {target}",
    ],
    "icmp_flood": [
        "Generating burst ICMP traffic profile for {target}",
        "Streaming packet-rate samples to the console",
        "Network telemetry indicates elevated inbound echo requests",
        "Safeguards applied before any disruptive threshold is reached",
        "Simulation complete for {target}",
    ],
}


def stream_lines(lines: list[str], delay: float) -> int:
    for line in lines:
        print(line, flush=True)
        time.sleep(delay)
    return 0


def run_attack(action: str, target: str) -> int:
    lines = ATTACK_SCRIPTS.get(action)
    if not lines:
        print(f"Unknown mock attack action: {action}", file=sys.stderr, flush=True)
        return 2
    return stream_lines([line.format(target=target) for line in lines], 0.7)


def run_ssh(host: str, username: str) -> int:
    lines = [
        f"Opening mock SSH transport to {host} as {username}",
        "Executing: systemctl status wazuh-manager --no-pager",
        "wazuh-manager.service - Wazuh manager",
        "Loaded: loaded (/usr/lib/systemd/system/wazuh-manager.service; enabled)",
        "Active: active (running) since Sat 2026-03-14 09:40:00 UTC",
        "Mock SSH session complete",
    ]
    return stream_lines(lines, 0.6)


def main() -> int:
    parser = argparse.ArgumentParser(description="Mock subprocess tasks for SIEM-Commander.")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    attack_parser = subparsers.add_parser("attack")
    attack_parser.add_argument("action", choices=sorted(ATTACK_SCRIPTS))
    attack_parser.add_argument("target")

    ssh_parser = subparsers.add_parser("ssh")
    ssh_parser.add_argument("host")
    ssh_parser.add_argument("username")

    args = parser.parse_args()

    if args.mode == "attack":
        return run_attack(args.action, args.target)
    if args.mode == "ssh":
        return run_ssh(args.host, args.username)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
