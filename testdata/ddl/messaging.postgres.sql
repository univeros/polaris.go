CREATE TABLE "polaris_messaging_template" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "key" VARCHAR(64) NOT NULL,
    "locale" VARCHAR(8) NOT NULL,
    "subject" VARCHAR(255) NULL,
    "text" TEXT NOT NULL,
    "html" TEXT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_messaging_template_unique" ON "polaris_messaging_template" ("organization_id", "key", "locale");
