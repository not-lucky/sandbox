#!/usr/bin/env python3
import asyncio
import re
import sys
import os
import shutil

# Configuration
CONCURRENCY_LIMIT = 50
TEST_DOMAINS = ["google.com", "cloudflare.com", "wikipedia.org"]
TIMEOUT_PER_QUERY = 1.5  # Seconds


async def check_resolver(sem, resolver_line):
    line = resolver_line.strip()
    if not line or line.startswith("#"):
        return None

    # Parse IP and Port (Handles IPv4, IPv6, and optional ports)
    ip = line
    port = "53"

    if line.startswith("["):
        # Format: [IPv6]:port or just [IPv6]
        match = re.match(r"^\[(.*)\]:(\d+)$", line)
        if match:
            ip = match.group(1)
            port = match.group(2)
        else:
            ip = line.strip("[]")
    elif line.count(":") == 1:
        # Format: IPv4:port
        parts = line.split(":")
        ip = parts[0]
        port = parts[1]

    latencies = []

    async with sem:
        # Test each domain sequentially for this specific resolver
        for domain in TEST_DOMAINS:
            proc = None
            try:
                # Spawn dig asynchronously
                proc = await asyncio.create_subprocess_exec(
                    "dig",
                    f"@{ip}",
                    "-p",
                    port,
                    domain,
                    f"+time=1",
                    "+tries=1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )

                # Enforce strict timeout to prevent hanging
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=TIMEOUT_PER_QUERY
                )
                stdout_str = stdout.decode("utf-8", errors="ignore")

                # Extract query time in milliseconds
                match = re.search(r"Query time:\s*(\d+)\s*msec", stdout_str)
                if match:
                    latencies.append(int(match.group(1)))
            except asyncio.TimeoutError:
                if proc and proc.returncode is None:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
            except Exception:
                pass

    if latencies:
        avg_latency = sum(latencies) // len(latencies)
        return (line, avg_latency)
    else:
        # Sort to the bottom if all domains failed/timed out
        return (line, float("inf"))


async def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <dns_list_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)

    if not shutil.which("dig"):
        print(
            "Error: 'dig' command-line utility is required but was not found.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(file_path, "r") as f:
        lines = f.readlines()

    # Filter out empty lines or comments
    valid_lines = [
        line for line in lines if line.strip() and not line.strip().startswith("#")
    ]

    print(f"Testing {len(valid_lines)} resolvers...")
    print(f"Domains used: {', '.join(TEST_DOMAINS)}")
    print(f"Concurrency limit: {CONCURRENCY_LIMIT} resolvers at a time.")
    print("-" * 65)

    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    tasks = [check_resolver(sem, line) for line in valid_lines]

    # Run all resolver checks in parallel
    results = await asyncio.gather(*tasks)

    # Filter and sort results by latency (lowest first)
    valid_results = [r for r in results if r is not None]
    valid_results.sort(key=lambda x: x[1])

    print("\nRanked Results (Fastest to Slowest):")
    print("-" * 65)
    print(f"{'Resolver':<35} {'Average Latency':<15}")
    print("-" * 65)

    for resolver, latency in valid_results:
        if latency == float("inf"):
            print(f"{resolver:<35} {'Failed/Timeout':<15}")
        else:
            print(f"{resolver:<35} {latency} ms")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
