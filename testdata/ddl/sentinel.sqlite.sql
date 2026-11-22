CREATE TABLE "polaris_sentinel_decision" (
    "id" VARCHAR(36) NOT NULL,
    "kind" VARCHAR(32) NOT NULL,
    "email" VARCHAR(320) NULL,
    "ip" VARCHAR(45) NULL,
    "score" INTEGER NOT NULL,
    "action" VARCHAR(16) NOT NULL,
    "enforced" INTEGER NOT NULL,
    "signals" TEXT NOT NULL,
    "reasons" TEXT NOT NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_sentinel_decision_created_index" ON "polaris_sentinel_decision" ("created_at");

CREATE INDEX "polaris_sentinel_decision_email_index" ON "polaris_sentinel_decision" ("email");

CREATE INDEX "polaris_sentinel_decision_ip_index" ON "polaris_sentinel_decision" ("ip");

CREATE TABLE "polaris_sentinel_ip_rule" (
    "id" VARCHAR(36) NOT NULL,
    "cidr" VARCHAR(64) NOT NULL,
    "action" VARCHAR(16) NOT NULL,
    "note" VARCHAR(255) NULL,
    "created_by" VARCHAR(64) NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "polaris_sentinel_device" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "device_hash" VARCHAR(64) NOT NULL,
    "ip" VARCHAR(45) NULL,
    "latitude" VARCHAR(32) NULL,
    "longitude" VARCHAR(32) NULL,
    "last_seen_at" DATETIME NOT NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_sentinel_device_unique" ON "polaris_sentinel_device" ("user_id", "device_hash");
