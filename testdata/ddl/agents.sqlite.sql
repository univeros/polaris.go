CREATE TABLE "polaris_agent" (
    "id" VARCHAR(36) NOT NULL,
    "owner_type" VARCHAR(16) NOT NULL,
    "owner_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "name" VARCHAR(160) NOT NULL,
    "mode" VARCHAR(16) NOT NULL,
    "host_id" VARCHAR(36) NULL,
    "auth" VARCHAR(32) NOT NULL,
    "public_jwk" TEXT NULL,
    "status" VARCHAR(16) NOT NULL,
    "created_by" VARCHAR(36) NOT NULL,
    "sealed_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    "key_thumbprint" VARCHAR(64) NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_agent_host_key_thumbprint_unique" ON "polaris_agent" ("host_id", "key_thumbprint");

CREATE INDEX "polaris_agent_owner_index" ON "polaris_agent" ("owner_type", "owner_id");

CREATE INDEX "polaris_agent_org_index" ON "polaris_agent" ("organization_id");

CREATE TABLE "polaris_agent_host" (
    "id" VARCHAR(36) NOT NULL,
    "owner_type" VARCHAR(16) NOT NULL,
    "owner_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "name" VARCHAR(160) NOT NULL,
    "enrollment_token_hash" VARCHAR(128) NOT NULL,
    "default_capabilities" TEXT NOT NULL,
    "created_by" VARCHAR(36) NOT NULL,
    "revoked_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "public_jwk" TEXT NULL,
    "jwks_url" VARCHAR(500) NULL,
    "key_thumbprint" VARCHAR(64) NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_agent_host_token_unique" ON "polaris_agent_host" ("enrollment_token_hash");

CREATE UNIQUE INDEX "polaris_agent_host_key_unique" ON "polaris_agent_host" ("key_thumbprint");

CREATE UNIQUE INDEX "polaris_agent_host_jwks_unique" ON "polaris_agent_host" ("jwks_url");

CREATE INDEX "polaris_agent_host_owner_index" ON "polaris_agent_host" ("owner_type", "owner_id");

CREATE TABLE "polaris_agent_grant" (
    "id" VARCHAR(36) NOT NULL,
    "agent_id" VARCHAR(36) NOT NULL,
    "capability" VARCHAR(80) NOT NULL,
    "constraints" TEXT NOT NULL,
    "budget_total" INTEGER NULL,
    "budget_remaining" INTEGER NULL,
    "budget_kind" VARCHAR(8) NULL,
    "budget_field" VARCHAR(80) NULL,
    "status" VARCHAR(16) NOT NULL,
    "granted_by" VARCHAR(36) NULL,
    "approved_via" VARCHAR(32) NULL,
    "approval_id" VARCHAR(36) NULL,
    "expires_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_agent_grant_lookup_index" ON "polaris_agent_grant" ("agent_id", "capability", "status");

CREATE TABLE "polaris_agent_approval" (
    "id" VARCHAR(36) NOT NULL,
    "agent_id" VARCHAR(36) NOT NULL,
    "grant_ids" TEXT NOT NULL,
    "method" VARCHAR(32) NOT NULL,
    "strength" VARCHAR(16) NOT NULL,
    "user_code" VARCHAR(16) NOT NULL,
    "binding_message" VARCHAR(160) NULL,
    "status" VARCHAR(16) NOT NULL,
    "decided_by" VARCHAR(36) NULL,
    "expires_at" DATETIME NOT NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_agent_approval_code_index" ON "polaris_agent_approval" ("user_code", "status");

CREATE INDEX "polaris_agent_approval_agent_index" ON "polaris_agent_approval" ("agent_id", "status");

CREATE TABLE "polaris_agent_receipt" (
    "id" VARCHAR(36) NOT NULL,
    "agent_id" VARCHAR(36) NOT NULL,
    "seq" INTEGER NOT NULL,
    "grant_id" VARCHAR(36) NULL,
    "capability" VARCHAR(80) NULL,
    "input_hash" VARCHAR(64) NOT NULL,
    "outcome" VARCHAR(16) NOT NULL,
    "budget_before" INTEGER NULL,
    "budget_after" INTEGER NULL,
    "prev_hash" VARCHAR(64) NULL,
    "hash" VARCHAR(64) NOT NULL,
    "signature" TEXT NOT NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_agent_receipt_seq_unique" ON "polaris_agent_receipt" ("agent_id", "seq");

CREATE TABLE "polaris_agent_registration" (
    "id" VARCHAR(36) NOT NULL,
    "host_id" VARCHAR(36) NOT NULL,
    "host_thumbprint" VARCHAR(64) NOT NULL,
    "host_jwk" TEXT NOT NULL,
    "host_name" VARCHAR(160) NOT NULL,
    "agent_thumbprint" VARCHAR(64) NOT NULL,
    "agent_jwk" TEXT NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "mode" VARCHAR(16) NOT NULL,
    "reason" VARCHAR(500) NULL,
    "status" VARCHAR(16) NOT NULL,
    "expires_at" DATETIME NOT NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_agent_registration_keys_unique" ON "polaris_agent_registration" ("host_thumbprint", "agent_thumbprint");

CREATE INDEX "polaris_agent_registration_expiry_index" ON "polaris_agent_registration" ("expires_at");
