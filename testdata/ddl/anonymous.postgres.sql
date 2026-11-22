CREATE TABLE "polaris_anonymous" (
    "user_id" VARCHAR(36) NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    "converted_at" TIMESTAMP NULL,
    "converted_user_id" VARCHAR(36) NULL,
    PRIMARY KEY ("user_id")
);

CREATE INDEX "polaris_anonymous_created_index" ON "polaris_anonymous" ("created_at");
