#!/usr/bin/env python3
"""Creates DB SQLite and loads feeds"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from versions import version_key

SCHEMA = Path(__file__).with_name("schema.sql")


def get_or_create_vendor(cur, name):
    cur.execute("INSERT OR IGNORE INTO vendors(name) VALUES (?)", (name,))
    return cur.execute("SELECT id FROM vendors WHERE name = ?", (name,)).fetchone()[0]


def get_or_create_product(cur, vendor, product):
    vendor_id = get_or_create_vendor(cur, vendor)
    cur.execute(
        "INSERT OR IGNORE INTO products(vendor_id, name) VALUES (?, ?)",
        (vendor_id, product),
    )
    return cur.execute(
        "SELECT id FROM products WHERE vendor_id = ? AND name = ?", (vendor_id, product)
    ).fetchone()[0]


def load_versions(conn, rows):
    cur = conn.cursor()
    added = 0
    for r in rows:
        pid = get_or_create_product(cur, r["vendor"], r["product"])
        cur.execute(
            "INSERT OR IGNORE INTO versions(product_id, version, version_key) VALUES (?, ?, ?)",
            (pid, r["version"], version_key(r["version"])),
        )
        added += cur.rowcount
    return added


def load_vulnerabilities(conn, rows):
    cur = conn.cursor()
    added = 0
    for r in rows:
        pid = get_or_create_product(cur, r["vendor"], r["product"])
        cur.execute(
            "INSERT OR IGNORE INTO advisories(kla_id, description, publish_date) VALUES (?, ?, ?)",
            (r["KLA_id"], r["description"], r["publish_date"]),
        )
        adv_id, descr = cur.execute(
            "SELECT id, description FROM advisories WHERE kla_id = ?", (r["KLA_id"],)
        ).fetchone()
        if descr != r["description"]:
            print(
                f"warning: {r['KLA_id']}: описание отличается от ранее загруженного",
                file=sys.stderr,
            )
        cur.execute(
            "INSERT OR IGNORE INTO vulnerable_ranges"
            "(advisory_id, product_id, start_version, fixed_version) VALUES (?, ?, ?, ?)",
            (adv_id, pid, r["start_vuln_version"], r["fixed_version"]),
        )
        added += cur.rowcount
    return added


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--db", default="vulns.db")
    ap.add_argument("--vulnerabilities", default="vulnerabilities.json")
    ap.add_argument("--versions", default="versions.json")
    ap.add_argument("--rebuild", action="store_true", help="удалить существующую БД")
    args = ap.parse_args(argv)

    db = Path(args.db)
    if args.rebuild and db.exists():
        db.unlink()

    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    with conn:
        n_ver = load_versions(
            conn, json.loads(Path(args.versions).read_text(encoding="utf-8"))
        )
        n_vul = load_vulnerabilities(
            conn, json.loads(Path(args.vulnerabilities).read_text(encoding="utf-8"))
        )
    conn.close()
    print(f"Загружено: версий {n_ver}, диапазонов уязвимостей {n_vul} -> {db}")


if __name__ == "__main__":
    main()
