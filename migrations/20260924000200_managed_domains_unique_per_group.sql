-- Rule names are unique per group, not globally: blocking a service names its
-- rules `[Service] domain`, and blocking the same service for a second group
-- must create that group's rows instead of colliding with the first group's.
-- SQLite cannot alter a constraint in place, so the table is rebuilt; nothing
-- references managed_domains, so the drop cascades nowhere.
CREATE TABLE managed_domains_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    domain     TEXT    NOT NULL,
    action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
    group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
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
FROM managed_domains;

DROP TABLE managed_domains;

ALTER TABLE managed_domains_new RENAME TO managed_domains;

CREATE INDEX idx_managed_domains_group_enabled
    ON managed_domains(group_id, enabled, action);
CREATE INDEX idx_managed_domains_service ON managed_domains(service_id);
CREATE INDEX idx_managed_domains_domain ON managed_domains(domain, enabled, action);
