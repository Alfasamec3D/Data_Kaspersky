"""Console instrument"""

import argparse
import sqlite3
import sys
from pathlib import Path

from versions import matching_ranges, parse_version, normalize, sort_versions

DEFAULT_DB = Path(__file__).with_name("vulns.db")


class UserError(Exception):
    pass


def connect(path):
    if not Path(path).exists():
        raise UserError(f"DB {path} not found. first execute: python load_data.py")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def resolve_product(conn, name, vendor=None):
    """finds product: exaxt overlap case-insensitive, otherwise substring"""
    base = (
        "SELECT p.id, p.name, v.name AS vendor FROM products p "
        "JOIN vendors v ON v.id = p.vendor_id WHERE "
    )
    vendor_sql, vendor_args = "", []
    if vendor:
        vendor_sql, vendor_args = " AND v.name = ? COLLATE NOCASE", [vendor]

    rows = conn.execute(
        base + "p.name = ? COLLATE NOCASE" + vendor_sql, [name, *vendor_args]
    ).fetchall()
    if not rows:
        like = "%" + name.replace("%", r"\%").replace("_", r"\_") + "%"
        rows = conn.execute(
            base + r"p.name LIKE ? ESCAPE '\'" + vendor_sql + " ORDER BY p.name",
            [like, *vendor_args],
        ).fetchall()
    if not rows:
        raise UserError(f"Product '{name}' not found.")
    if len(rows) > 1:
        lines = "\n".join(f"  - {r['name']} ({r['vendor']})" for r in rows)
        raise UserError(
            f"'{name}' matches several, specify name" f"(or point --vendor):\n{lines}"
        )
    return rows[0]


def load_ranges(conn, product_id):
    """{advisory_id: (kla, date, description, [(start, fixed), ...])}"""
    rows = conn.execute(
        "SELECT a.id, a.kla_id, a.publish_date, a.description, r.start_version, r.fixed_version "
        "FROM vulnerable_ranges r JOIN advisories a ON a.id = r.advisory_id "
        "WHERE r.product_id = ? ORDER BY a.publish_date, a.kla_id",
        (product_id,),
    ).fetchall()
    groups = {}
    for r in rows:
        g = groups.setdefault(
            r["id"], (r["kla_id"], r["publish_date"], r["description"], [])
        )
        g[3].append((r["start_version"], r["fixed_version"]))
    return groups


def vulnerabilities_of(version, groups):
    """list (kla, date, description, start, fixed) of vulnerabilities for verison"""
    found = []
    for kla, date, descr, ranges in groups.values():
        for start, fixed in matching_ranges(version, ranges):
            found.append((kla, date, descr, start, fixed))
    return found


def cmd_safe(conn, args):
    prod = resolve_product(conn, args.product, args.vendor)
    all_versions = [
        r["version"]
        for r in conn.execute(
            "SELECT version FROM versions WHERE product_id = ?", (prod["id"],)
        )
    ]
    if not all_versions:
        raise UserError(f"Для {prod['name']} no info about versions")
    groups = load_ranges(conn, prod["id"])
    safe = [v for v in sort_versions(all_versions) if not vulnerabilities_of(v, groups)]

    print(
        f"{prod['name']} ({prod['vendor']}): known versins {len(all_versions)}, "
        f"without vulnerabilities {len(safe)}"
    )
    if not safe:
        print("No versions without known vulnerabilities")
        return 1
    if args.latest:
        print(safe[-1])
    else:
        print("\n".join(safe))
    return 0


def cmd_info(conn, args):
    prod = resolve_product(conn, args.product, args.vendor)
    known = conn.execute(
        "SELECT 1 FROM versions WHERE product_id = ? AND version = ?",
        (prod["id"], args.version),
    ).fetchone()
    groups = load_ranges(conn, prod["id"])
    found = vulnerabilities_of(args.version, groups)

    print(f"{prod['name']} ({prod['vendor']}) {args.version}")
    if not known:
        print("Note: no such verision among known, check made by ranges")
    if not found:
        print("No vulnerabilities")
        return 0

    print(f"Found vulnerabilities: {len(found)}\n")
    for kla, date, descr, start, fixed in found:
        print(f"{kla}  [{date}]  {descr}")
        print(
            f"    vulnerable versions: from {start} to {fixed} (not including); fixed in {fixed}"
        )
    # recommend update within its branch, if there are fixes for it
    v = parse_version(args.version)
    fixes = [f[4] for f in found]
    same_branch = [f for f in fixes if parse_version(f)[:1] == v[:1]] or fixes
    best_fix = max(same_branch, key=lambda x: normalize(parse_version(x)))
    print(f"\nTo cover all found vulnerabilites, update at least to {best_fix}")
    return 1


def build_parser():
    ap = argparse.ArgumentParser(
        description="Search vulnerabilities by products and versions"
    )
    ap.add_argument("--db", default=str(DEFAULT_DB), help="path to DB SQLite")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("safe", help="product versions without vulnerabilities")
    p.add_argument("product")
    p.add_argument("--vendor")
    p.add_argument("--latest", action="store_true", help="only the latest safe version")
    p.set_defaults(func=cmd_safe)

    p = sub.add_parser("info", help="specific product version vulnerabilities")
    p.add_argument("product")
    p.add_argument("version")
    p.add_argument("--vendor")
    p.set_defaults(func=cmd_info)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        conn = connect(args.db)
        return args.func(conn, args)
    except UserError as e:
        print(e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
