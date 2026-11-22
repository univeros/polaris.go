CREATE TABLE "polaris_anonymous" (
    "user_id" VARCHAR(36) NOT NULL,
    "created_at" DATETIME NOT NULL,
    "converted_at" DATETIME NULL,
    "converted_user_id" VARCHAR(36) NULL,
    PRIMARY KEY ("user_id")
);

CREATE INDEX "polaris_anonymous_created_index" ON "polaris_anonymous" ("created_at");
