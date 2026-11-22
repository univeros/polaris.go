CREATE TABLE "polaris_passkey" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "credential_id" VARCHAR(1024) NOT NULL,
    "public_key" TEXT NOT NULL,
    "counter" INTEGER NOT NULL DEFAULT 0,
    "aaguid" VARCHAR(36) NOT NULL,
    "transports" JSONB NOT NULL,
    "backup_eligible" BOOLEAN NOT NULL DEFAULT FALSE,
    "backed_up" BOOLEAN NOT NULL DEFAULT FALSE,
    "name" VARCHAR(80) NOT NULL,
    "factor_id" VARCHAR(36) NULL,
    "last_used_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_passkey_credential_unique" ON "polaris_passkey" ("credential_id");

CREATE INDEX "polaris_passkey_user_index" ON "polaris_passkey" ("user_id");

CREATE INDEX "polaris_passkey_factor_index" ON "polaris_passkey" ("factor_id");
