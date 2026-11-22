CREATE TABLE "polaris_passwordless_secret" (
    "id" VARCHAR(36) NOT NULL,
    "kind" VARCHAR(32) NOT NULL,
    "identifier_hash" VARCHAR(128) NOT NULL,
    "user_id" VARCHAR(36) NULL,
    "secret_hash" VARCHAR(128) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "data" JSONB NOT NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "used_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_passwordless_secret_identifier_index" ON "polaris_passwordless_secret" ("kind", "identifier_hash");

CREATE INDEX "polaris_passwordless_secret_hash_index" ON "polaris_passwordless_secret" ("secret_hash");

CREATE TABLE "polaris_passwordless_phone" (
    "user_id" VARCHAR(36) NOT NULL,
    "e164" VARCHAR(16) NOT NULL,
    "verified_at" TIMESTAMP NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("user_id")
);

CREATE UNIQUE INDEX "polaris_passwordless_phone_unique" ON "polaris_passwordless_phone" ("e164");
