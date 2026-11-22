CREATE TABLE "polaris_audit_event" (
    "id" VARCHAR(36) NOT NULL,
    "name" VARCHAR(64) NOT NULL,
    "occurred_at" DATETIME NOT NULL,
    "actor_type" VARCHAR(16) NOT NULL,
    "actor_id" VARCHAR(64) NULL,
    "subject_id" VARCHAR(64) NULL,
    "organization_id" VARCHAR(64) NULL,
    "session_id" VARCHAR(64) NULL,
    "ip" VARCHAR(45) NULL,
    "user_agent" TEXT NULL,
    "data" TEXT NOT NULL,
    "request_id" VARCHAR(64) NULL,
    "prev_hash" VARCHAR(64) NULL,
    "hash" VARCHAR(64) NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_audit_event_name_index" ON "polaris_audit_event" ("name", "occurred_at");

CREATE INDEX "polaris_audit_event_occurred_index" ON "polaris_audit_event" ("occurred_at");

CREATE INDEX "polaris_audit_event_actor_index" ON "polaris_audit_event" ("actor_id", "occurred_at");

CREATE INDEX "polaris_audit_event_subject_index" ON "polaris_audit_event" ("subject_id", "occurred_at");

CREATE INDEX "polaris_audit_event_org_index" ON "polaris_audit_event" ("organization_id", "occurred_at");

CREATE TABLE "polaris_audit_drain" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "type" VARCHAR(16) NOT NULL,
    "endpoint" VARCHAR(2048) NOT NULL,
    "secret" TEXT NOT NULL,
    "filter" TEXT NOT NULL,
    "status" VARCHAR(16) NOT NULL,
    "last_delivery_at" DATETIME NULL,
    "last_error" TEXT NULL,
    "created_at" DATETIME NOT NULL,
    "created_by" VARCHAR(36) NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_audit_drain_org_index" ON "polaris_audit_drain" ("organization_id", "status");

CREATE TABLE "polaris_audit_activity" (
    "user_id" VARCHAR(36) NOT NULL,
    "last_active_at" DATETIME NOT NULL,
    PRIMARY KEY ("user_id")
);

CREATE TABLE "polaris_audit_chain" (
    "id" VARCHAR(16) NOT NULL,
    "last_id" VARCHAR(36) NOT NULL,
    "last_hash" VARCHAR(64) NOT NULL,
    "locked_by" VARCHAR(36) NOT NULL,
    PRIMARY KEY ("id")
);
