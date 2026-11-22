CREATE TABLE "polaris_scim_connection" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "sso_provider_id" VARCHAR(36) NULL,
    "name" VARCHAR(120) NOT NULL,
    "token_hash" VARCHAR(128) NOT NULL,
    "status" VARCHAR(16) NOT NULL,
    "settings" TEXT NOT NULL,
    "last_sync_at" DATETIME NULL,
    "decommissioned_at" DATETIME NULL,
    "created_by" VARCHAR(64) NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_scim_connection_org_index" ON "polaris_scim_connection" ("organization_id");

CREATE INDEX "polaris_scim_connection_token_index" ON "polaris_scim_connection" ("token_hash");

CREATE TABLE "polaris_scim_resource" (
    "id" VARCHAR(36) NOT NULL,
    "connection_id" VARCHAR(36) NOT NULL,
    "kind" VARCHAR(8) NOT NULL,
    "external_id" VARCHAR(255) NOT NULL,
    "local_id" VARCHAR(36) NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_scim_resource_unique" ON "polaris_scim_resource" ("connection_id", "kind", "local_id");

CREATE TABLE "polaris_scim_membership_provenance" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "connection_id" VARCHAR(36) NOT NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_scim_provenance_unique" ON "polaris_scim_membership_provenance" ("organization_id", "user_id");
