#!/usr/bin/env python3
"""Build AmneziaVPN client backup files (.backup) for iOS, Android and Windows.

The format follows the official AmneziaVPN client
(client/secureQSettings.cpp, client/core/controllers/settingsController.cpp).
See ../README.md for the full description.

Examples:
    # one backup from WireGuard / AmneziaWG .conf files
    python3 amnezia_backup.py build --platform iOS -o Ali.backup \
        "Server 1=s1.conf" "Server 2=s2.conf"

    # change the platform of an existing backup
    python3 amnezia_backup.py convert --platform Windows in.backup -o out.backup
"""

import argparse
import json
import re
import sys
import uuid

PLATFORMS = ("iOS", "Android", "Windows", "MacOS", "Linux")
AWG_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5")


def parse_conf(text):
    """Parse a WireGuard / AmneziaWG .conf into {section: {key: value}}."""
    sections, cur = {}, None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"\[(\w+)\]", line)
        if m:
            cur = sections.setdefault(m.group(1), {})
            continue
        if cur is not None and "=" in line:
            k, v = line.split("=", 1)
            cur[k.strip()] = v.strip()
    return sections


def server_from_conf(text, description, dns1="1.1.1.1", dns2="8.8.8.8"):
    """Turn one .conf into an Amnezia server entry (third-party config)."""
    c = parse_conf(text)
    iface, peer = c["Interface"], c["Peer"]
    host, port = peer["Endpoint"].rsplit(":", 1)
    awg = {k: iface[k] for k in AWG_KEYS if k in iface}
    # Classic AmneziaWG (H1..H4 random, S1/S2 set) -> amnezia-awg container.
    # WireGuard, or AWG 2.0 style (I1 set, H = 1..4) -> amnezia-wireguard with obfuscation.
    is_awg = bool(awg) and not ("I1" in awg and awg.get("H1") == "1")
    proto = "awg" if is_awg else "wireguard"
    container = "amnezia-awg" if is_awg else "amnezia-wireguard"

    last = dict(awg)
    last.update({
        "allowed_ips": [x.strip() for x in peer.get("AllowedIPs", "0.0.0.0/0, ::/0").split(",")],
        "client_ip": iface["Address"].split(",")[0].strip(),
        "client_priv_key": iface["PrivateKey"],
        "config": text if text.endswith("\n") else text + "\n",
        "hostName": host,
        "mtu": iface.get("MTU", "1420"),
        "persistent_keep_alive": peer.get("PersistentKeepalive", "25"),
        "port": int(port),
        "psk_key": peer.get("PresharedKey", ""),
        "server_pub_key": peer["PublicKey"],
    })
    if awg and not is_awg:
        last["isObfuscationEnabled"] = True

    return {
        "containers": [{
            "container": container,
            proto: {
                "isThirdPartyConfig": True,
                "last_config": json.dumps(last, indent=4, sort_keys=True) + "\n",
                "port": str(port),
                "transport_proto": "udp",
            },
        }],
        "defaultContainer": container,
        "description": description,
        "dns1": dns1,
        "dns2": dns2,
        "hostName": host,
        "storageServerId": str(uuid.uuid4()),
    }


def build_backup(servers, platform, default_index=0):
    """Wrap a list of server entries into a full backup dict for one platform."""
    if platform not in PLATFORMS:
        raise ValueError(f"platform must be one of {PLATFORMS}")
    cfg = {
        "AppPlatform": platform,
        "Conf/autoStart": False,
        "Conf/killSwitchEnabled": False,
        "Conf/strictKillSwitchEnabled": False,
        "Conf/useAmneziaDns": True,
        "Conf/routeMode": 0,
        "Servers/defaultServerId": servers[default_index]["storageServerId"],
        # Older clients read the index instead of the id.
        "Servers/defaultServerIndex": default_index,
        "Servers/serversList": json.dumps(servers, indent=4, ensure_ascii=False) + "\n",
    }
    if platform in ("Android", "Windows"):
        # Apps split tunneling only exists on these two.
        cfg["Conf/appsRouteMode"] = 0
    return cfg


def convert_backup(cfg, platform):
    """Re-target an existing backup to another platform."""
    cfg = dict(cfg)
    cfg["AppPlatform"] = platform
    if platform not in ("Android", "Windows"):
        cfg.pop("Conf/appsRouteMode", None)
        cfg.pop("Conf/appsSplitTunnelingEnabled", None)
    cfg.pop("Conf/installationUuid", None)
    return cfg


def dump(cfg):
    return json.dumps(cfg, indent=4, ensure_ascii=False, sort_keys=True) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="build a backup from .conf files")
    b.add_argument("--platform", required=True, choices=PLATFORMS)
    b.add_argument("-o", "--output", required=True)
    b.add_argument("--default", type=int, default=0, help="index of the default server")
    b.add_argument("items", nargs="+", help='"Server name=file.conf" (or just file.conf) ...')

    c = sub.add_parser("convert", help="change the platform of an existing backup")
    c.add_argument("--platform", required=True, choices=PLATFORMS)
    c.add_argument("input")
    c.add_argument("-o", "--output", required=True)

    args = ap.parse_args()
    if args.cmd == "build":
        servers = []
        for item in args.items:
            name, _, path = item.rpartition("=")
            with open(path, encoding="utf-8") as f:
                servers.append(server_from_conf(f.read(), name or f"Server {len(servers) + 1}"))
        cfg = build_backup(servers, args.platform, args.default)
    else:
        with open(args.input, encoding="utf-8") as f:
            cfg = convert_backup(json.load(f), args.platform)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(dump(cfg))
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
