CREATE TABLE "polaris_api_key" (
    "id" VARCHAR(36) NOT NULL,
    "owner_type" VARCHAR(16) NOT NULL,
    "owner_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "created_by" VARCHAR(36) NOT NULL,
    "name" VARCHAR(80) NOT NULL,
    "environment" VARCHAR(8) NOT NULL,
    "hint" VARCHAR(8) NOT NULL,
    "key_hash" VARCHAR(128) NOT NULL,
    "permissions" JSONB NOT NULL,
    "rate_limit_window" INTEGER NULL,
    "rate_limit_max" INTEGER NULL,
    "metadata" JSONB NOT NULL,
    "rotated_from_id" VARCHAR(36) NULL,
    "grace_until" TIMESTAMP NULL,
    "expires_at" TIMESTAMP NULL,
    "last_used_at" TIMESTAMP NULL,
    "revoked_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_api_key_hash_unique" ON "polaris_api_key" ("key_hash");

CREATE INDEX "polaris_api_key_owner_index" ON "polaris_api_key" ("owner_type", "owner_id");

CREATE INDEX "polaris_api_key_creator_index" ON "polaris_api_key" ("created_by");
