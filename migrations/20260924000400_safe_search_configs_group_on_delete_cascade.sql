-- Deleting a group deletes its safe-search configs, as it already does its
-- managed domains and blocked services: the restricting foreign key made any
-- group that ever had safe search configured undeletable.
-- SQLite cannot alter a foreign key in place, so the table is rebuilt with
-- every column, both CHECK constraints, the UNIQUE (group_id, engine) key, the
-- group index (the engine index was dropped in 20260303000002) and the
-- AUTOINCREMENT high-water mark (so deleted ids are never handed out again);
-- safe_search_configs has no triggers, and nothing references it, so the drop
-- cascades nowhere. Configs whose group no longer exists are dropped, as
-- group_id is NOT NULL.
CREATE TABLE safe_search_configs_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id     INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE CASCADE,
    engine       TEXT    NOT NULL CHECK(engine IN ('google','bing','youtube','duckduckgo','yandex','brave','ecosia')),
    enabled      INTEGER NOT NULL DEFAULT 0,
    youtube_mode TEXT    NOT NULL DEFAULT 'strict' CHECK(youtube_mode IN ('strict','moderate')),
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    UNIQUE(group_id, engine)
);

INSERT INTO safe_search_configs_new
    (id, group_id, engine, enabled, youtube_mode, created_at, updated_at)
SELECT id, group_id, engine, enabled, youtube_mode, created_at, updated_at
FROM safe_search_configs
WHERE group_id IN (SELECT id FROM groups);

DELETE FROM sqlite_sequence WHERE name = 'safe_search_configs_new';
INSERT INTO sqlite_sequence (name, seq)
SELECT 'safe_search_configs_new', seq FROM sqlite_sequence WHERE name = 'safe_search_configs';

DROP TABLE safe_search_configs;

ALTER TABLE safe_search_configs_new RENAME TO safe_search_configs;

CREATE INDEX idx_safe_search_group  ON safe_search_configs(group_id);
