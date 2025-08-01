#!/usr/bin/env python3
import socket
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import argparse

def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Scan a single port and return results as a dict."""
    result = {
        "host": host,
        "port": port,
        "status": "closed",
        "service": "unknown"
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                result["status"] = "open"
                try:
                    result["service"] = socket.getservbyport(port, "tcp")
                except:
                    pass
    except Exception as e:
        result["error"] = str(e)
    return result

def port_scanner(host: str, start_port: int, end_port: int, max_threads: int = 100, timeout: float = 1.0) -> list:
    """Scan a range of ports using multithreading."""
    results = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, host, port, timeout) for port in range(start_port, end_port + 1)]
        for future in futures:
            results.append(future.result())
    return results

def export_to_json(data: list, filename: str = "port_scan_results.json") -> None:
    """Export scan results to JSON with timestamp."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "host": data[0]["host"] if data else "unknown",
        "scan_results": data
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Network Port Scanner with JSON Export")
    parser.add_argument("host", help="Target host (e.g., 127.0.0.1 or example.com)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=50, help="Max threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--output", help="JSON output filename")
    args = parser.parse_args()

    # Validate inputs
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        parser.error("Invalid port range. Ports must be between 1-65535 and start <= end.")
    if args.threads < 1 or args.threads > 1000:
        parser.error("Threads must be between 1 and 1000.")
    try:
        socket.gethostbyname(args.host)
    except socket.gaierror:
        parser.error(f"Cannot resolve host {args.host}")

    print(f"Scanning {args.host} (ports {args.start}-{args.end})...")
    results = port_scanner(args.host, args.start, args.end, args.threads, args.timeout)
    export_to_json(results, args.output or f"scan_{args.host}.json")

    # Print summary
    open_ports = [r["port"] for r in results if r["status"] == "open"]
    print(f"\nSummary: {len(open_ports)} open ports found: {open_ports}")
