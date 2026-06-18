#!/usr/bin/env python3

import argparse
import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

TRUE_VALUES = {"1", "true", "yes", "on"}


def first(mapping, *keys):
    """Return the first non-empty value from a dict or parse_qs dict."""
    for key in keys:
        if key not in mapping:
            continue

        value = mapping[key]

        if isinstance(value, list):
            if not value:
                continue
            value = value[0]

        if value is not None and value != "":
            return value

    return ""


def required(mapping, description, *keys):
    value = first(mapping, *keys)
    if value == "":
        raise ValueError(f"missing {description}")
    return value


def parse_bool(value):
    return str(value).strip().lower() in TRUE_VALUES


def parse_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {value!r}")

    if not 1 <= port <= 65535:
        raise ValueError(f"port outside valid range: {port}")

    return port


def decode_base64_text(value):
    value = unquote(value).strip()
    value += "=" * (-len(value) % 4)

    try:
        decoded = base64.b64decode(
            value.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        return decoded.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"invalid base64 data: {exc}") from exc


def fragment_label(link, fallback):
    if "#" not in link:
        return fallback

    label = unquote(link.split("#", 1)[1]).strip()
    return label or fallback


def parse_endpoint(address):
    try:
        parsed = urlsplit("//" + address)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid server address {address!r}: {exc}") from exc

    if not host:
        raise ValueError(f"missing server hostname in {address!r}")

    if port is None:
        raise ValueError(f"missing server port in {address!r}")

    return host, parse_port(port)


def build_tls(values, mode):
    mode = str(mode or "").strip().lower()

    if mode in {"", "none"}:
        return None

    if mode not in {"tls", "reality"}:
        raise ValueError(f"unsupported TLS/security mode: {mode!r}")

    tls = {
        "enabled": True,
    }

    server_name = first(values, "sni", "serverName", "server_name", "peer")
    if server_name:
        tls["server_name"] = str(server_name)

    insecure = first(values, "insecure", "allowInsecure", "allow_insecure")
    if insecure != "":
        tls["insecure"] = parse_bool(insecure)

    alpn = first(values, "alpn")
    if alpn:
        alpn_values = [item.strip() for item in str(alpn).split(",") if item.strip()]
        if alpn_values:
            tls["alpn"] = alpn_values

    fingerprint = first(values, "fp", "fingerprint")
    if fingerprint and str(fingerprint).lower() != "none":
        tls["utls"] = {
            "enabled": True,
            "fingerprint": str(fingerprint),
        }

    if mode == "reality":
        public_key = first(values, "pbk", "publicKey", "public_key")
        if not public_key:
            raise ValueError("Reality link is missing its public key")

        reality = {
            "enabled": True,
            "public_key": str(public_key),
        }

        short_id = first(values, "sid", "shortId", "short_id")
        if short_id:
            reality["short_id"] = str(short_id)

        tls["reality"] = reality

    return tls


def build_transport(kind, values, header_type=""):
    kind = str(kind or "tcp").strip().lower()
    header_type = str(header_type or "").strip().lower()

    if kind in {"", "tcp", "raw", "none"}:
        if header_type not in {"", "none"}:
            raise ValueError(
                f"TCP header type {header_type!r} is not supported by this generator"
            )
        return None

    host = str(first(values, "host") or "")
    path = str(first(values, "path") or "")

    if kind == "ws":
        transport = {
            "type": "ws",
        }

        if path:
            transport["path"] = path

        if host:
            transport["headers"] = {
                "Host": host,
            }

        return transport

    if kind in {"http", "h2"}:
        transport = {
            "type": "http",
        }

        if host:
            transport["host"] = [
                item.strip() for item in host.split(",") if item.strip()
            ]

        if path:
            transport["path"] = path

        return transport

    if kind == "grpc":
        service_name = first(
            values,
            "serviceName",
            "service_name",
            "service",
            "path",
        )

        transport = {
            "type": "grpc",
        }

        if service_name:
            transport["service_name"] = str(service_name).lstrip("/")

        return transport

    if kind in {"httpupgrade", "http-upgrade"}:
        transport = {
            "type": "httpupgrade",
        }

        if host:
            transport["host"] = host

        if path:
            transport["path"] = path

        return transport

    if kind == "quic":
        return {
            "type": "quic",
        }

    raise ValueError(f"unsupported transport type: {kind!r}")


def parse_vmess(link):
    payload = link[len("vmess://") :]
    decoded = decode_base64_text(payload)

    try:
        values = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid VMess JSON: {exc}") from exc

    if not isinstance(values, dict):
        raise ValueError("VMess payload is not a JSON object")

    server = str(required(values, "VMess server", "add", "server"))
    server_port = parse_port(required(values, "VMess port", "port"))
    uuid = str(required(values, "VMess UUID", "id", "uuid"))

    outbound = {
        "type": "vmess",
        "server": server,
        "server_port": server_port,
        "uuid": uuid,
        "security": str(first(values, "scy") or "auto"),
    }

    alter_id = first(values, "aid", "alterId", "alter_id")
    if alter_id != "":
        try:
            outbound["alter_id"] = int(alter_id)
        except ValueError as exc:
            raise ValueError(f"invalid VMess alter ID: {alter_id!r}") from exc

    tls = build_tls(values, first(values, "tls"))
    if tls:
        outbound["tls"] = tls

    transport = build_transport(
        first(values, "net", "network") or "tcp",
        values,
        first(values, "type", "headerType"),
    )
    if transport:
        outbound["transport"] = transport

    packet_encoding = first(values, "packetEncoding", "packet_encoding")
    if packet_encoding:
        outbound["packet_encoding"] = str(packet_encoding)

    label = str(first(values, "ps") or "VMess proxy")
    return outbound, label, "vmess"


def parse_vless(link):
    try:
        parsed = urlsplit(link)
        server = parsed.hostname
        server_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid VLESS URL: {exc}") from exc

    if not server:
        raise ValueError("VLESS link is missing its server")

    if server_port is None:
        raise ValueError("VLESS link is missing its server port")

    uuid = unquote(parsed.username or "")
    if not uuid:
        raise ValueError("VLESS link is missing its UUID")

    query = parse_qs(parsed.query, keep_blank_values=True)

    outbound = {
        "type": "vless",
        "server": server,
        "server_port": parse_port(server_port),
        "uuid": uuid,
    }

    flow = first(query, "flow")
    if flow:
        outbound["flow"] = str(flow)

    tls = build_tls(query, first(query, "security"))
    if tls:
        outbound["tls"] = tls

    transport = build_transport(
        first(query, "type") or "tcp",
        query,
        first(query, "headerType", "header_type"),
    )
    if transport:
        outbound["transport"] = transport

    packet_encoding = first(query, "packetEncoding", "packet_encoding")
    if packet_encoding:
        outbound["packet_encoding"] = str(packet_encoding)

    label = fragment_label(link, "VLESS proxy")
    return outbound, label, "vless"


def decode_ss_credentials(userinfo):
    candidate = unquote(userinfo)

    try:
        decoded = decode_base64_text(candidate)
        if ":" in decoded:
            return decoded.split(":", 1)
    except ValueError:
        pass

    if ":" in candidate:
        return candidate.split(":", 1)

    raise ValueError("invalid Shadowsocks credentials")


def parse_ss(link):
    without_fragment = link.split("#", 1)[0]
    body = without_fragment[len("ss://") :]

    if "?" in body:
        body, query_string = body.split("?", 1)
    else:
        query_string = ""

    if "@" in body:
        userinfo, address = body.rsplit("@", 1)
        method, password = decode_ss_credentials(userinfo)
    else:
        decoded = decode_base64_text(body)

        if "@" not in decoded:
            raise ValueError("legacy Shadowsocks link is missing server address")

        credentials, address = decoded.rsplit("@", 1)

        if ":" not in credentials:
            raise ValueError("invalid legacy Shadowsocks credentials")

        method, password = credentials.split(":", 1)

    server, server_port = parse_endpoint(address)

    outbound = {
        "type": "shadowsocks",
        "server": server,
        "server_port": server_port,
        "method": method,
        "password": password,
    }

    query = parse_qs(query_string, keep_blank_values=True)
    plugin = first(query, "plugin")

    if plugin:
        plugin_name, separator, plugin_options = str(plugin).partition(";")
        outbound["plugin"] = plugin_name

        if separator and plugin_options:
            outbound["plugin_opts"] = plugin_options

    label = fragment_label(link, "Shadowsocks proxy")
    return outbound, label, "shadowsocks"


def parse_proxy_link(link):
    lower = link.lower()

    if lower.startswith("vmess://"):
        return parse_vmess(link)

    if lower.startswith("vless://"):
        return parse_vless(link)

    if lower.startswith("ss://"):
        return parse_ss(link)

    raise ValueError("unsupported link type; expected vmess://, vless://, or ss://")


def main():
    parser = argparse.ArgumentParser(
        description="Convert proxy links into one SOCKS5 port per sing-box outbound."
    )

    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Input file containing one proxy link per line; default: stdin",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="config.json",
        help="Output sing-box config; default: config.json",
    )

    parser.add_argument(
        "--start-port",
        type=int,
        default=10808,
        help="First SOCKS port; default: 10808",
    )

    parser.add_argument(
        "--listen",
        default="127.0.0.1",
        help="SOCKS listen address; default: 127.0.0.1",
    )

    parser.add_argument(
        "--legacy-route",
        action="store_true",
        help="Generate legacy route rules for sing-box versions older than 1.11",
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Run 'sing-box check' after creating the config",
    )

    parser.add_argument(
        "--run",
        action="store_true",
        help="Check the generated config and then start sing-box",
    )

    parser.add_argument(
        "--sing-box",
        default="sing-box",
        help="Path to the sing-box executable; default: sing-box",
    )

    args = parser.parse_args()

    if not 1 <= args.start_port <= 65535:
        print("Start port must be between 1 and 65535.", file=sys.stderr)
        return 2

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text(encoding="utf-8-sig")

    parsed_proxies = []
    errors = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        link = raw_line.strip()

        if not link or link.startswith("#"):
            continue

        try:
            parsed_proxies.append(parse_proxy_link(link))
        except Exception as exc:
            errors.append(f"line {line_number}: {exc}")

    if errors:
        print("Could not create config:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 2

    if not parsed_proxies:
        print("No proxy links were found.", file=sys.stderr)
        return 2

    final_port = args.start_port + len(parsed_proxies) - 1
    if final_port > 65535:
        print(
            f"Too many links: final port would be {final_port}.",
            file=sys.stderr,
        )
        return 2

    inbounds = []
    outbounds = []
    route_rules = []
    mappings = []

    for index, (outbound, label, protocol) in enumerate(parsed_proxies):
        listen_port = args.start_port + index
        inbound_tag = f"socks-{index:03d}"
        outbound_tag = f"proxy-{index:03d}"

        inbounds.append(
            {
                "type": "socks",
                "tag": inbound_tag,
                "listen": args.listen,
                "listen_port": listen_port,
            }
        )

        outbound["tag"] = outbound_tag
        outbounds.append(outbound)

        if args.legacy_route:
            route_rules.append(
                {
                    "inbound": inbound_tag,
                    "outbound": outbound_tag,
                }
            )
        else:
            route_rules.append(
                {
                    "inbound": inbound_tag,
                    "action": "route",
                    "outbound": outbound_tag,
                }
            )

        clean_label = " ".join(str(label).split())
        mappings.append((listen_port, protocol, clean_label))

    config = {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": route_rules,
        },
    }

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Created {output_path} with {len(parsed_proxies)} SOCKS proxies.")

    for listen_port, protocol, label in mappings:
        print(
            f"  socks5://{args.listen}:{listen_port} -> {protocol}: {label}",
            file=sys.stderr,
        )

    if args.check or args.run:
        try:
            result = subprocess.run([args.sing_box, "check", "-c", str(output_path)])
        except FileNotFoundError:
            print(
                f"Could not find sing-box executable: {args.sing_box}",
                file=sys.stderr,
            )
            return 127

        if result.returncode != 0:
            return result.returncode

    if args.run:
        os.execvp(
            args.sing_box,
            [
                args.sing_box,
                "run",
                "-c",
                str(output_path),
            ],
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
