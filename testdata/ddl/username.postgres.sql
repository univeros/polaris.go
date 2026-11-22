CREATE TABLE "polaris_username" (
    "user_id" VARCHAR(36) NOT NULL,
    "username" VARCHAR(64) NOT NULL,
    "display_username" VARCHAR(64) NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("user_id")
);

CREATE UNIQUE INDEX "polaris_username_unique" ON "polaris_username" ("username");
