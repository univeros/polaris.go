CREATE TABLE "polaris_multi_session_device" (
    "id" VARCHAR(36) NOT NULL,
    "device_id" VARCHAR(64) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "session_id" VARCHAR(36) NOT NULL,
    "last_method" VARCHAR(32) NOT NULL,
    "sign_in_id" VARCHAR(36) NOT NULL,
    "signed_in_at" TIMESTAMP NOT NULL,
    "last_seen" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_multi_session_device_unique" ON "polaris_multi_session_device" ("device_id", "user_id");

CREATE INDEX "polaris_multi_session_device_session_index" ON "polaris_multi_session_device" ("session_id");
