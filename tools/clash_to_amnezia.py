#!/usr/bin/env python3
"""
Convert a Mihomo/Clash config with a Hysteria2 proxy to an AmneziaVPN vpn:// link.

Usage:
    python3 clash_to_amnezia.py config.yaml
    python3 clash_to_amnezia.py config.yaml --proxy "⚡️ Hysteria2"
    python3 clash_to_amnezia.py config.yaml --dns1 77.88.8.8 --dns2 8.8.8.8

The output link can be pasted into the AmneziaVPN "Add key" field.
"""

import argparse
import base64
import json
import re
import struct
import sys
import zlib


def parse_clash_yaml(text: str) -> list[dict]:
    """
    Extract hysteria2 proxies from a Clash YAML without external deps.
    Parses the proxies list looking for type: hysteria2 entries.
    """
    proxies = []

    # Find the proxies block
    m = re.search(r'^proxies\s*:\s*\n((?:  .*\n?)*)', text, re.MULTILINE)
    if not m:
        return proxies

    block = m.group(1)

    # Split into individual proxy entries (each starts with "  - ")
    entries = re.split(r'(?=^  - )', block, flags=re.MULTILINE)

    for entry in entries:
        if not entry.strip():
            continue

        def get(key: str, default=None):
            pattern = rf'^\s+{re.escape(key)}\s*:\s*(.+)$'
            m2 = re.search(pattern, entry, re.MULTILINE)
            if not m2:
                return default
            val = m2.group(1).strip().strip('"').strip("'")
            return val

        if get('type') != 'hysteria2':
            continue

        proxy = {
            'name':             get('name', 'Hysteria2'),
            'server':           get('server', ''),
            'port':             int(get('port', '443')),
            'password':         get('password', ''),
            'sni':              get('sni', ''),
            'skip_cert_verify': get('skip-cert-verify', 'false').lower() == 'true',
            'up':               int(get('up', '0')),
            'down':             int(get('down', '0')),
            'obfs':             get('obfs', ''),
            'obfs_password':    get('obfs-password', ''),
        }
        proxies.append(proxy)

    return proxies


def build_amnezia_json(proxy: dict, dns1: str, dns2: str) -> dict:
    # last_config is embedded as a JSON string inside the "Hysteria2" container object.
    # Keys and types must match what setupHysteria2() in ios_controller.mm reads and
    # what Hysteria2Config.swift decodes (port=Int, up_mbps/down_mbps=Int, insecure=Bool).
    last_config = {
        "hostName":  proxy['server'],      # read by setupHysteria2 as "hostName" → Swift server
        "port":      proxy['port'],        # Int – Swift decodes as Int
        "password":  proxy['password'],
        "sni":       proxy['sni'] or proxy['server'],
        "insecure":  proxy['skip_cert_verify'],
        "up_mbps":   proxy['up'],          # Int
        "down_mbps": proxy['down'],        # Int
        "isThirdPartyConfig": True,
    }
    if proxy['obfs']:
        last_config['obfs'] = proxy['obfs']
    if proxy['obfs_password']:
        last_config['obfs_password'] = proxy['obfs_password']

    # Outer container config: "Hysteria2" key = protoToString(Proto::Hysteria2)
    # Must contain "last_config" (JSON string) so that isProtocolConfigExists() returns
    # true and the app skips the self-hosted SSH setup flow.
    hysteria2_container = {
        "isThirdPartyConfig": True,
        "port": str(proxy['port']),       # kept for desktop hysteria2protocol.cpp (reads as string)
        "last_config": json.dumps(last_config, ensure_ascii=False, separators=(',', ':')),
    }

    return {
        "hostName": proxy['server'],
        "dns1": dns1,
        "dns2": dns2,
        "containers": [
            {
                "container": "amnezia-hysteria2",
                "Hysteria2": hysteria2_container,
            }
        ],
        "defaultContainer": "amnezia-hysteria2",
    }


def to_vpn_link(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()
    # Qt qCompress format: 4-byte big-endian original size + zlib data
    compressed = struct.pack('>I', len(raw)) + zlib.compress(raw, 8)
    b64 = base64.urlsafe_b64encode(compressed).rstrip(b'=').decode()
    return 'vpn://' + b64


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('config', help='Clash/Mihomo YAML config file')
    ap.add_argument('--proxy', help='Proxy name to use (default: first hysteria2 proxy)')
    ap.add_argument('--dns1', default='1.1.1.1', help='Primary DNS (default: 1.1.1.1)')
    ap.add_argument('--dns2', default='8.8.8.8', help='Secondary DNS (default: 8.8.8.8)')
    args = ap.parse_args()

    with open(args.config, encoding='utf-8') as f:
        text = f.read()

    proxies = parse_clash_yaml(text)
    if not proxies:
        print('ERROR: no hysteria2 proxies found in config', file=sys.stderr)
        sys.exit(1)

    if args.proxy:
        matches = [p for p in proxies if p['name'] == args.proxy]
        if not matches:
            print(f'ERROR: proxy "{args.proxy}" not found', file=sys.stderr)
            print('Available:', ', '.join(p['name'] for p in proxies), file=sys.stderr)
            sys.exit(1)
        proxy = matches[0]
    else:
        proxy = proxies[0]

    print(f'Using proxy: {proxy["name"]} → {proxy["server"]}:{proxy["port"]}',
          file=sys.stderr)

    obj  = build_amnezia_json(proxy, args.dns1, args.dns2)
    link = to_vpn_link(obj)
    print(link)


if __name__ == '__main__':
    main()
