-- Bootstrap migration. Establishes the migration baseline only; no meeting
-- domain tables are created here. Managed by sql-migrate; MySQL is the only
-- supported datastore (no SQLite auto-create).

-- +migrate Up
CREATE TABLE IF NOT EXISTS bootstrap_marker (
    id          TINYINT      NOT NULL PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO bootstrap_marker (id, description)
VALUES (1, 'schema baseline established by bootstrap')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- +migrate Down
DROP TABLE IF EXISTS bootstrap_marker;
