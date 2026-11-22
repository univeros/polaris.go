CREATE TABLE "polaris_passkey" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "credential_id" VARCHAR(1024) NOT NULL,
    "public_key" TEXT NOT NULL,
    "counter" INTEGER NOT NULL DEFAULT 0,
    "aaguid" VARCHAR(36) NOT NULL,
    "transports" TEXT NOT NULL,
    "backup_eligible" INTEGER NOT NULL DEFAULT 0,
    "backed_up" INTEGER NOT NULL DEFAULT 0,
    "name" VARCHAR(80) NOT NULL,
    "factor_id" VARCHAR(36) NULL,
    "last_used_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_passkey_credential_unique" ON "polaris_passkey" ("credential_id");

CREATE INDEX "polaris_passkey_user_index" ON "polaris_passkey" ("user_id");

CREATE INDEX "polaris_passkey_factor_index" ON "polaris_passkey" ("factor_id");
