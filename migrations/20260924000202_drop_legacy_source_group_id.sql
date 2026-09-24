-- Group membership of list sources lives only in the *_source_groups pivots,
-- which cascade when a group is deleted. The pre-pivot `group_id` column was
-- write-only yet still carried a foreign key (RESTRICT for blocklists), so a
-- group that happened to be a source's first group could not be deleted.
-- The column is dropped by rebuilding each table. Migrations run inside a
-- transaction with foreign keys on, where dropping a parent table cascades
-- into its pivot, so the pivot rows are saved first and restored after.

CREATE TEMP TABLE saved_blocklist_source_groups AS
    SELECT source_id, group_id FROM blocklist_source_groups;
CREATE TEMP TABLE saved_whitelist_source_groups AS
    SELECT source_id, group_id FROM whitelist_source_groups;

CREATE TABLE blocklist_sources_new (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    url            TEXT,
    comment        TEXT,
    enabled        BOOLEAN NOT NULL DEFAULT 1,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at TEXT
);
INSERT INTO blocklist_sources_new
    (id, name, url, comment, enabled, created_at, updated_at, last_synced_at)
SELECT id, name, url, comment, enabled, created_at, updated_at, last_synced_at
FROM blocklist_sources;
DROP TABLE blocklist_sources;
ALTER TABLE blocklist_sources_new RENAME TO blocklist_sources;

CREATE TABLE whitelist_sources_new (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    url            TEXT,
    comment        TEXT,
    enabled        BOOLEAN NOT NULL DEFAULT 1,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at TEXT
);
INSERT INTO whitelist_sources_new
    (id, name, url, comment, enabled, created_at, updated_at, last_synced_at)
SELECT id, name, url, comment, enabled, created_at, updated_at, last_synced_at
FROM whitelist_sources;
DROP TABLE whitelist_sources;
ALTER TABLE whitelist_sources_new RENAME TO whitelist_sources;

INSERT OR IGNORE INTO blocklist_source_groups (source_id, group_id)
    SELECT source_id, group_id FROM saved_blocklist_source_groups;
INSERT OR IGNORE INTO whitelist_source_groups (source_id, group_id)
    SELECT source_id, group_id FROM saved_whitelist_source_groups;

DROP TABLE saved_blocklist_source_groups;
DROP TABLE saved_whitelist_source_groups;
