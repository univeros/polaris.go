CREATE TABLE "polaris_social_account" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "provider" VARCHAR(40) NOT NULL,
    "provider_account_id" VARCHAR(255) NOT NULL,
    "email" VARCHAR(320) NULL,
    "email_verified" INTEGER NOT NULL DEFAULT 0,
    "scopes" TEXT NOT NULL,
    "profile" TEXT NOT NULL,
    "access_token_enc" TEXT NULL,
    "refresh_token_enc" TEXT NULL,
    "expires_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_social_account_unique" ON "polaris_social_account" ("provider", "provider_account_id");

CREATE UNIQUE INDEX "polaris_social_account_user_provider_unique" ON "polaris_social_account" ("user_id", "provider");
