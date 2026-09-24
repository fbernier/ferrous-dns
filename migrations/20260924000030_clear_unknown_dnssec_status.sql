-- Cache hits on local records were logged with dnssec_status 'Unknown', which
-- is no DNSSEC determination at all: the query log now stores NULL for those,
-- and the rollups counted each one as validated without any outcome.
WITH unknown AS (
    SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 60) * 60 AS bucket,
           query_source,
           COUNT(*) AS n
    FROM query_log
    WHERE dnssec_status = 'Unknown' AND created_at IS NOT NULL
    GROUP BY 1, 2
)
UPDATE query_log_minute
SET dnssec_validated = MAX(dnssec_validated - unknown.n, 0)
FROM unknown
WHERE query_log_minute.bucket = unknown.bucket
  AND query_log_minute.query_source = unknown.query_source;

UPDATE query_log SET dnssec_status = NULL WHERE dnssec_status = 'Unknown';
