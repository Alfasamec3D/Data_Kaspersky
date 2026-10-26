PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vendors (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS products (
    id        INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id),
    name      TEXT NOT NULL,
    UNIQUE (vendor_id, name)
);

CREATE TABLE IF NOT EXISTS versions (
    id          INTEGER PRIMARY KEY,
    product_id  INTEGER NOT NULL REFERENCES products(id),
    version     TEXT NOT NULL,
    version_key TEXT NOT NULL,
    UNIQUE (product_id, version)
);

-- feed №1
-- one KLA_id may touch several products and version branches, therefore put seperately
CREATE TABLE IF NOT EXISTS advisories (
    id           INTEGER PRIMARY KEY,
    kla_id       TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL,
    publish_date TEXT NOT NULL            -- ISO-8601: YYYY-MM-DD
);

CREATE TABLE IF NOT EXISTS vulnerable_ranges (
    id            INTEGER PRIMARY KEY,
    advisory_id   INTEGER NOT NULL REFERENCES advisories(id),
    product_id    INTEGER NOT NULL REFERENCES products(id),
    start_version TEXT NOT NULL,          
    fixed_version TEXT NOT NULL,          
    UNIQUE (advisory_id, product_id, start_version, fixed_version)
);

CREATE INDEX IF NOT EXISTS idx_products_name ON products(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_versions_product ON versions(product_id);
CREATE INDEX IF NOT EXISTS idx_ranges_product ON vulnerable_ranges(product_id);
CREATE INDEX IF NOT EXISTS idx_ranges_advisory ON vulnerable_ranges(advisory_id);
