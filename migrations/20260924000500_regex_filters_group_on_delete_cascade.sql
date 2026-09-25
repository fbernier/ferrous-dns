-- Deleting a group deletes its regex filters, as it already does its managed
-- domains, safe-search configs and blocked services: the restricting foreign
-- key made any group that had a regex filter undeletable.
-- SQLite cannot alter a foreign key in place, so the table is rebuilt with
-- every column, the action CHECK, the UNIQUE name key, both indexes and the
-- AUTOINCREMENT high-water mark (so deleted ids are never handed out again);
-- regex_filters has no triggers, and nothing references it, so the drop
-- cascades nowhere. Filters whose group no longer exists are dropped, as
-- group_id is NOT NULL.
CREATE TABLE regex_filters_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    pattern    TEXT    NOT NULL,
    action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
    group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE CASCADE,
    comment    TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

INSERT INTO regex_filters_new
    (id, name, pattern, action, group_id, comment, enabled, created_at, updated_at)
SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
FROM regex_filters
WHERE group_id IN (SELECT id FROM groups);

DELETE FROM sqlite_sequence WHERE name = 'regex_filters_new';
INSERT INTO sqlite_sequence (name, seq)
SELECT 'regex_filters_new', seq FROM sqlite_sequence WHERE name = 'regex_filters';

DROP TABLE regex_filters;

ALTER TABLE regex_filters_new RENAME TO regex_filters;

CREATE INDEX idx_regex_filters_enabled  ON regex_filters(enabled);
CREATE INDEX idx_regex_filters_group_id ON regex_filters(group_id);
