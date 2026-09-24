-- Deleting a group keeps its logged queries and drops their attribution;
-- before, any group that had ever logged a query could not be deleted.
-- SQLite cannot alter a foreign key in place, so the table is rebuilt; nothing
-- references query_log, so the drop cascades nowhere.
CREATE TABLE query_log_new (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    domain            TEXT    NOT NULL,
    record_type       TEXT    NOT NULL,
    client_ip         TEXT    NOT NULL,
    blocked           INTEGER NOT NULL DEFAULT 0,
    response_time_ms  INTEGER,
    cache_hit         INTEGER NOT NULL DEFAULT 0,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    cache_refresh     INTEGER NOT NULL DEFAULT 0,
    dnssec_status     TEXT,
    upstream_server   TEXT,
    response_status   TEXT,
    query_source      TEXT    NOT NULL DEFAULT 'client',
    group_id          INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    block_source      TEXT,
    upstream_pool     TEXT,
    dns64_synthesized INTEGER NOT NULL DEFAULT 0,
    answers           TEXT,
    protocol          TEXT
);

INSERT INTO query_log_new
    (id, domain, record_type, client_ip, blocked, response_time_ms, cache_hit, created_at,
     cache_refresh, dnssec_status, upstream_server, response_status, query_source, group_id,
     block_source, upstream_pool, dns64_synthesized, answers, protocol)
SELECT id, domain, record_type, client_ip, blocked, response_time_ms, cache_hit, created_at,
       cache_refresh, dnssec_status, upstream_server, response_status, query_source, group_id,
       block_source, upstream_pool, dns64_synthesized, answers, protocol
FROM query_log;

DROP TABLE query_log;

ALTER TABLE query_log_new RENAME TO query_log;

CREATE INDEX idx_query_log_window ON query_log(query_source, created_at, blocked);
