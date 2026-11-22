CREATE TABLE "polaris_oauth_client" (
    "id" VARCHAR(36) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "name" VARCHAR(160) NOT NULL,
    "type" VARCHAR(16) NOT NULL,
    "secret_hash" VARCHAR(128) NULL,
    "redirect_uris" TEXT NOT NULL,
    "grant_types" TEXT NOT NULL,
    "scopes" TEXT NOT NULL,
    "token_endpoint_auth_method" VARCHAR(32) NOT NULL,
    "jwks" TEXT NULL,
    "jwks_uri" VARCHAR(2048) NULL,
    "dpop_bound" INTEGER NOT NULL DEFAULT 0,
    "trusted" INTEGER NOT NULL DEFAULT 0,
    "logo_uri" VARCHAR(2048) NULL,
    "client_uri" VARCHAR(2048) NULL,
    "policy_uri" VARCHAR(2048) NULL,
    "tos_uri" VARCHAR(2048) NULL,
    "created_by" VARCHAR(36) NULL,
    "disabled_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_client_id_unique" ON "polaris_oauth_client" ("client_id");

CREATE INDEX "polaris_oauth_client_org_index" ON "polaris_oauth_client" ("organization_id");

CREATE TABLE "polaris_oauth_consent" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" TEXT NOT NULL,
    "granted_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_consent_org_unique" ON "polaris_oauth_consent" ("user_id", "client_id", "organization_id");

CREATE TABLE "polaris_oauth_code" (
    "id" VARCHAR(36) NOT NULL,
    "code_hash" VARCHAR(128) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" TEXT NOT NULL,
    "redirect_uri" VARCHAR(2048) NOT NULL,
    "code_challenge" VARCHAR(128) NOT NULL,
    "nonce" VARCHAR(255) NULL,
    "resource" VARCHAR(2048) NULL,
    "dpop_jkt" VARCHAR(128) NULL,
    "auth_time" INTEGER NULL,
    "expires_at" DATETIME NOT NULL,
    "used_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_code_hash_unique" ON "polaris_oauth_code" ("code_hash");

CREATE TABLE "polaris_oauth_token" (
    "id" VARCHAR(36) NOT NULL,
    "kind" VARCHAR(8) NOT NULL,
    "token_hash" VARCHAR(128) NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "user_id" VARCHAR(36) NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" TEXT NOT NULL,
    "family_id" VARCHAR(36) NULL,
    "resource" VARCHAR(2048) NULL,
    "dpop_jkt" VARCHAR(128) NULL,
    "actor" TEXT NULL,
    "auth_time" INTEGER NULL,
    "expires_at" DATETIME NOT NULL,
    "revoked_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_token_hash_unique" ON "polaris_oauth_token" ("token_hash");

CREATE INDEX "polaris_oauth_token_user_index" ON "polaris_oauth_token" ("user_id", "client_id");

CREATE INDEX "polaris_oauth_token_family_index" ON "polaris_oauth_token" ("family_id");

CREATE TABLE "polaris_oauth_device_code" (
    "id" VARCHAR(36) NOT NULL,
    "device_code_hash" VARCHAR(128) NOT NULL,
    "user_code" VARCHAR(16) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "scopes" TEXT NOT NULL,
    "resource" VARCHAR(2048) NULL,
    "status" VARCHAR(16) NOT NULL,
    "user_id" VARCHAR(36) NULL,
    "organization_id" VARCHAR(36) NULL,
    "auth_time" INTEGER NULL,
    "last_polled_at" DATETIME NULL,
    "expires_at" DATETIME NOT NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_device_code_hash_unique" ON "polaris_oauth_device_code" ("device_code_hash");

CREATE UNIQUE INDEX "polaris_oauth_device_user_code_unique" ON "polaris_oauth_device_code" ("user_code");

CREATE TABLE "polaris_oauth_ciba_request" (
    "id" VARCHAR(36) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" TEXT NOT NULL,
    "binding_message" VARCHAR(160) NULL,
    "resource" VARCHAR(2048) NULL,
    "status" VARCHAR(16) NOT NULL,
    "auth_time" INTEGER NULL,
    "last_polled_at" DATETIME NULL,
    "expires_at" DATETIME NOT NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_oauth_ciba_user_index" ON "polaris_oauth_ciba_request" ("user_id", "status");
