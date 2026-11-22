CREATE TABLE "polaris_admin_grant" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "role" VARCHAR(16) NOT NULL,
    "scope" VARCHAR(36) NOT NULL,
    "granted_by" VARCHAR(36) NULL,
    "expires_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_admin_grant_user_unique" ON "polaris_admin_grant" ("user_id");

CREATE TABLE "polaris_admin_key" (
    "id" VARCHAR(36) NOT NULL,
    "name" VARCHAR(120) NOT NULL,
    "key_hash" VARCHAR(64) NOT NULL,
    "role" VARCHAR(16) NOT NULL,
    "scope" VARCHAR(36) NOT NULL,
    "ip_allowlist" JSONB NOT NULL,
    "expires_at" TIMESTAMP NULL,
    "last_used_at" TIMESTAMP NULL,
    "created_by" VARCHAR(64) NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_admin_key_hash_unique" ON "polaris_admin_key" ("key_hash");
