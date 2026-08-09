-- Meeting domain schema. Bound to architecture SHA f0f482c0 (§8) and backend
-- appendix §6. All tables live in the service-owned MySQL database; there is no
-- SQLite auto-create. InnoDB / utf8mb4; business timestamps are UTC DATETIME(3),
-- bookkeeping timestamps default to CURRENT_TIMESTAMP(3). No column ever stores a
-- reversible password: only a non-reversible verifier and HMAC lookup hashes.
--
-- Creating new tables is online-safe. Apply order within this migration follows
-- the dependency chain: core -> participants -> notifications -> livekit -> audit.

-- +migrate Up

-- Core: meeting, credential, password verifier, idempotency key.
CREATE TABLE IF NOT EXISTS meeting (
    id                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    meeting_id            VARCHAR(64)  NOT NULL,
    space_id              VARCHAR(64)  NOT NULL,
    type                  ENUM('quick','scheduled') NOT NULL,
    topic                 VARCHAR(255) NULL,
    status                ENUM('scheduled','live','ended','cancelled') NOT NULL DEFAULT 'scheduled',
    creator_uid           VARCHAR(64)  NOT NULL,
    host_uid              VARCHAR(64)  NOT NULL,
    scheduled_start_at    DATETIME(3)  NULL,
    duration_minutes      INT          NULL,
    actual_start_at       DATETIME(3)  NULL,
    ended_at              DATETIME(3)  NULL,
    cancelled_at          DATETIME(3)  NULL,
    end_reason            ENUM('host_end','no_show','empty_timeout','system') NULL,
    empty_since           DATETIME(3)  NULL,
    locked                TINYINT(1)   NOT NULL DEFAULT 0,
    password_enabled      TINYINT(1)   NOT NULL DEFAULT 0,
    password_verifier_id  BIGINT UNSIGNED NULL,
    max_participants      INT          NOT NULL,
    share_holder_uid      VARCHAR(64)  NULL,
    share_segment_id      VARCHAR(64)  NULL,
    version               BIGINT       NOT NULL DEFAULT 1,
    created_at            TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at            TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at            DATETIME(3)  NULL,
    UNIQUE KEY uk_meeting_meeting_id (meeting_id),
    KEY idx_meeting_space_status_start (space_id, status, scheduled_start_at),
    KEY idx_meeting_creator_status_updated (creator_uid, status, updated_at),
    KEY idx_meeting_host_status (host_uid, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS meeting_credential (
    id                        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    meeting_id                VARCHAR(64)  NOT NULL,
    number_lookup_hash        VARBINARY(64) NOT NULL,
    number_display_ciphertext VARBINARY(512) NOT NULL,
    link_token_lookup_hash    VARBINARY(64) NOT NULL,
    link_token_ciphertext     VARBINARY(512) NOT NULL,
    status                    ENUM('active','revoked') NOT NULL DEFAULT 'active',
    expires_with_meeting_status TINYINT(1) NOT NULL DEFAULT 1,
    version                   BIGINT       NOT NULL DEFAULT 1,
    created_at                TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    revoked_at                DATETIME(3)  NULL,
    UNIQUE KEY uk_credential_number_hash (number_lookup_hash),
    UNIQUE KEY uk_credential_link_hash (link_token_lookup_hash),
    KEY idx_credential_meeting (meeting_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS meeting_password_verifier (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    meeting_id  VARCHAR(64)  NOT NULL,
    algorithm   VARCHAR(32)  NOT NULL,
    params_json JSON         NOT NULL,
    salt_id     VARCHAR(64)  NOT NULL,
    pepper_ref  VARCHAR(128) NOT NULL,
    verifier    VARBINARY(255) NOT NULL,
    status      ENUM('active','retired') NOT NULL DEFAULT 'active',
    created_by  VARCHAR(64)  NOT NULL,
    created_at  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    retired_at  DATETIME(3)  NULL,
    KEY idx_verifier_meeting_status (meeting_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS meeting_idempotency_key (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scope               VARCHAR(64)  NOT NULL,
    key_hash            VARBINARY(64) NOT NULL,
    payload_fingerprint VARBINARY(64) NOT NULL,
    result_ref          VARCHAR(64)  NOT NULL,
    created_at          TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at          DATETIME(3)  NOT NULL,
    UNIQUE KEY uk_idem_scope_key (scope, key_hash),
    KEY idx_idem_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Participants.
CREATE TABLE IF NOT EXISTS meeting_participant (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    meeting_id      VARCHAR(64)  NOT NULL,
    uid             VARCHAR(64)  NOT NULL,
    role            ENUM('H','C','M') NOT NULL DEFAULT 'M',
    aggregate_state ENUM('invited','joined','left','removed','superseded') NOT NULL DEFAULT 'invited',
    removed         TINYINT(1)   NOT NULL DEFAULT 0,
    removed_at      DATETIME(3)  NULL,
    removed_by      VARCHAR(64)  NULL,
    first_joined_at DATETIME(3)  NULL,
    last_left_at    DATETIME(3)  NULL,
    version         BIGINT       NOT NULL DEFAULT 1,
    created_at      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_participant_meeting_uid (meeting_id, uid),
    KEY idx_participant_uid_state (uid, aggregate_state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS meeting_participant_segment (
    id                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    segment_id               VARCHAR(64)  NOT NULL,
    meeting_id               VARCHAR(64)  NOT NULL,
    uid                      VARCHAR(64)  NOT NULL,
    device_id_hash           VARCHAR(128) NOT NULL,
    livekit_identity         VARCHAR(128) NOT NULL,
    join_at                  DATETIME(3)  NOT NULL,
    leave_at                 DATETIME(3)  NULL,
    end_reason               ENUM('left','removed','superseded','disconnected','ended') NULL,
    superseded_by_segment_id VARCHAR(64)  NULL,
    av_state_json            JSON         NULL,
    created_at               TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_segment_id (segment_id),
    KEY idx_segment_meeting_uid_join (meeting_id, uid, join_at),
    KEY idx_segment_active (meeting_id, leave_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Notifications: invite, reminder, outbox.
CREATE TABLE IF NOT EXISTS meeting_invite (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    meeting_id  VARCHAR(64)  NOT NULL,
    invitee_uid VARCHAR(64)  NOT NULL,
    status      ENUM('invited','cancelled') NOT NULL DEFAULT 'invited',
    invited_by  VARCHAR(64)  NOT NULL,
    version     BIGINT       NOT NULL DEFAULT 1,
    created_at  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_invite_meeting_uid (meeting_id, invitee_uid),
    KEY idx_invite_uid_status_updated (invitee_uid, status, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS meeting_reminder (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    meeting_id     VARCHAR(64)  NOT NULL,
    uid            VARCHAR(64)  NOT NULL,
    due_at         DATETIME(3)  NOT NULL,
    dedupe_key     VARCHAR(255) NOT NULL,
    status         ENUM('pending','leased','sent','failed','dead','cancelled') NOT NULL DEFAULT 'pending',
    lease_owner    VARCHAR(64)  NULL,
    lease_until    DATETIME(3)  NULL,
    attempt_count  INT          NOT NULL DEFAULT 0,
    last_error_code VARCHAR(64) NULL,
    created_at     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_reminder_dedupe (dedupe_key),
    KEY idx_reminder_status_due_lease (status, due_at, lease_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS meeting_outbox (
    id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_type           VARCHAR(64)  NOT NULL,
    meeting_id           VARCHAR(64)  NOT NULL,
    recipient_uid        VARCHAR(64)  NULL,
    dedupe_key           VARCHAR(255) NOT NULL,
    payload_redacted_json JSON        NOT NULL,
    status               ENUM('pending','leased','sent','failed','dead','cancelled') NOT NULL DEFAULT 'pending',
    lease_owner          VARCHAR(64)  NULL,
    lease_until          DATETIME(3)  NULL,
    attempt_count        INT          NOT NULL DEFAULT 0,
    next_attempt_at      DATETIME(3)  NULL,
    last_error_code      VARCHAR(64)  NULL,
    created_at           TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at           TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_outbox_dedupe (dedupe_key),
    KEY idx_outbox_status_next (status, next_attempt_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- LiveKit webhook dedupe/reconciliation ledger.
CREATE TABLE IF NOT EXISTS meeting_livekit_webhook_event (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id       VARCHAR(128) NOT NULL,
    room_name      VARCHAR(128) NOT NULL,
    event_type     VARCHAR(64)  NOT NULL,
    event_ts       DATETIME(3)  NOT NULL,
    received_at    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    processed_at   DATETIME(3)  NULL,
    status         ENUM('received','processed','skipped','failed') NOT NULL DEFAULT 'received',
    payload_hash   VARBINARY(64) NOT NULL,
    last_error_code VARCHAR(64) NULL,
    UNIQUE KEY uk_webhook_event_id (event_id),
    KEY idx_webhook_room_type_ts (room_name, event_type, event_ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Append-only audit.
CREATE TABLE IF NOT EXISTS meeting_audit_event (
    id                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id              VARCHAR(64)  NOT NULL,
    meeting_id            VARCHAR(64)  NOT NULL,
    actor_uid             VARCHAR(64)  NULL,
    target_uid            VARCHAR(64)  NULL,
    type                  VARCHAR(64)  NOT NULL,
    result                VARCHAR(32)  NOT NULL,
    error_code            VARCHAR(64)  NULL,
    request_id            VARCHAR(64)  NULL,
    redacted_metadata_json JSON        NULL,
    created_at            TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uk_audit_event_id (event_id),
    KEY idx_audit_meeting_created (meeting_id, created_at),
    KEY idx_audit_actor_created (actor_uid, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +migrate Down
DROP TABLE IF EXISTS meeting_audit_event;
DROP TABLE IF EXISTS meeting_livekit_webhook_event;
DROP TABLE IF EXISTS meeting_outbox;
DROP TABLE IF EXISTS meeting_reminder;
DROP TABLE IF EXISTS meeting_invite;
DROP TABLE IF EXISTS meeting_participant_segment;
DROP TABLE IF EXISTS meeting_participant;
DROP TABLE IF EXISTS meeting_idempotency_key;
DROP TABLE IF EXISTS meeting_password_verifier;
DROP TABLE IF EXISTS meeting_credential;
DROP TABLE IF EXISTS meeting;
