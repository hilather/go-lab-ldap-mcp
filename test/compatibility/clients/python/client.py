#!/usr/bin/env python3
"""Independent ldap3 client for T-115. Prints whoami and matching DNs only."""

from __future__ import annotations

import argparse
import ssl
import sys


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--starttls", action="store_true")
    p.add_argument("--ca-file", dest="ca_file", default="")
    p.add_argument("--bind-dn", dest="bind_dn", default="")
    p.add_argument("--password-file", dest="password_file", default="")
    p.add_argument("--base", default="")
    p.add_argument("--filter", default="(objectClass=*)")
    args = p.parse_args()

    try:
        from ldap3 import ALL, Connection, Server, Tls
    except ImportError:
        print("ldap3-missing", file=sys.stderr)
        return 2

    password = ""
    if args.password_file:
        with open(args.password_file, encoding="utf-8") as fh:
            password = fh.read().rstrip("\n")

    tls = None
    if args.ca_file:
        tls = Tls(ca_certs_file=args.ca_file, validate=ssl.CERT_REQUIRED)
    use_ssl = args.url.startswith("ldaps://")
    server = Server(args.url, get_info=ALL, use_ssl=use_ssl, tls=tls)
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
    conn.search(args.base, args.filter, attributes=["entryDN"])
    for entry in conn.entries:
        print("dn", entry.entry_dn)
    conn.unbind()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
