-- Deleting a group deletes its managed domains, as it already does its blocked
-- services: the rules a blocked service generates live here, so a restricting
-- foreign key made any group that ever blocked a service undeletable.
-- SQLite cannot alter a foreign key in place, so the table is rebuilt with
-- every column, the UNIQUE (name, group_id) key, the three indexes and the
-- AUTOINCREMENT high-water mark (so deleted ids are never handed out again);
-- managed_domains has no triggers, and nothing references it, so the drop
-- cascades nowhere. Rules whose group no longer exists are dropped, as
-- group_id is NOT NULL.
CREATE TABLE managed_domains_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    domain     TEXT    NOT NULL,
    action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
    group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE CASCADE,
    comment    TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL,
    service_id TEXT,
    UNIQUE (name, group_id)
);

INSERT INTO managed_domains_new
    (id, name, domain, action, group_id, comment, enabled, created_at, updated_at, service_id)
SELECT id, name, domain, action, group_id, comment, enabled, created_at, updated_at, service_id
FROM managed_domains
WHERE group_id IN (SELECT id FROM groups);

DELETE FROM sqlite_sequence WHERE name = 'managed_domains_new';
INSERT INTO sqlite_sequence (name, seq)
SELECT 'managed_domains_new', seq FROM sqlite_sequence WHERE name = 'managed_domains';

DROP TABLE managed_domains;

ALTER TABLE managed_domains_new RENAME TO managed_domains;

CREATE INDEX idx_managed_domains_group_enabled
    ON managed_domains(group_id, enabled, action);
CREATE INDEX idx_managed_domains_service ON managed_domains(service_id);
CREATE INDEX idx_managed_domains_domain ON managed_domains(domain, enabled, action);
