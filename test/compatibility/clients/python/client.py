#!/usr/bin/env python3
"""Independent ldap3 client for T-115. Prints whoami and matching DNs only."""

from __future__ import annotations

import argparse
import ssl
import sys
from urllib.parse import urlparse


def tls_valid_names(url: str, server_name: str = "") -> list[str]:
    """Names ldap3 should accept for certificate matching.

    ldap3 compares valid_names to DNS SANs only. Connecting to an IP
    such as 127.0.0.1 therefore fails even when the certificate has an
    IP SAN for that address. Callers must pass --server-name matching a
    DNS SAN (typically "localhost") when the URL host is an IP.
    """
    host = (urlparse(url).hostname or "").strip()
    names: list[str] = []
    for name in (server_name.strip(), host):
        if name and name not in names:
            names.append(name)
    return names


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--starttls", action="store_true")
    p.add_argument("--ca-file", dest="ca_file", default="")
    p.add_argument("--bind-dn", dest="bind_dn", default="")
    p.add_argument("--password-file", dest="password_file", default="")
    p.add_argument("--base", default="")
    p.add_argument("--filter", default="(objectClass=*)")
    p.add_argument("--server-name", dest="server_name", default="")
    p.add_argument(
        "--print-valid-names",
        action="store_true",
        help="print TLS valid_names and exit (no ldap3, no network)",
    )
    args = p.parse_args()

    names = tls_valid_names(args.url, args.server_name)
    if args.print_valid_names:
        for name in names:
            print(name)
        return 0

    try:
        from ldap3 import NONE, Connection, Server, Tls
    except ImportError:
        print("ldap3-missing", file=sys.stderr)
        return 2

    password = ""
    if args.password_file:
        with open(args.password_file, encoding="utf-8") as fh:
            password = fh.read().rstrip("\n")

    tls = None
    if args.ca_file:
        tls_kwargs: dict[str, object] = {
            "ca_certs_file": args.ca_file,
            "validate": ssl.CERT_REQUIRED,
        }
        if names:
            tls_kwargs["valid_names"] = names
        tls = Tls(**tls_kwargs)
    use_ssl = args.url.startswith("ldaps://")
    # NONE: do not download schema. ldap3 SCHEMA/ALL rejects attributes the
    # engine does not advertise (389 extras such as entryDN, parity D6).
    server = Server(args.url, get_info=NONE, use_ssl=use_ssl, tls=tls)
    conn = Connection(server, user=args.bind_dn or None, password=password or None, auto_bind=False)
    if args.starttls:
        conn.open()
        if not conn.start_tls():
            print("starttls-failed", file=sys.stderr)
            return 1
        if args.bind_dn and not conn.bind():
            print("bind-failed", file=sys.stderr)
            return 1
    elif not conn.bind():
        print("bind-failed", file=sys.stderr)
        return 1

    who = conn.extend.standard.who_am_i()
    print("whoami", who or "")
    conn.search(args.base, args.filter, attributes=["uid"])
    for entry in conn.entries:
        print("dn", entry.entry_dn)
    conn.unbind()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
