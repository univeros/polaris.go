CREATE TABLE "auth_audit_log" (
    "id" VARCHAR(36) NOT NULL,
    "actor_user_id" VARCHAR(36) NULL,
    "organization_id" VARCHAR(36) NULL,
    "event" VARCHAR(80) NOT NULL,
    "ip" VARCHAR(45) NULL,
    "user_agent" VARCHAR(255) NULL,
    "metadata" TEXT NOT NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "auth_audit_log_actor_index" ON "auth_audit_log" ("actor_user_id", "created_at");

CREATE INDEX "auth_audit_log_org_index" ON "auth_audit_log" ("organization_id", "created_at");

CREATE INDEX "auth_audit_log_event_index" ON "auth_audit_log" ("event", "created_at");

CREATE TABLE "auth_email_verifications" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "expires_at" DATETIME NOT NULL,
    "consumed_at" DATETIME NULL,
    "ip" VARCHAR(45) NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_email_verifications_token_hash_unique" ON "auth_email_verifications" ("token_hash");

CREATE INDEX "auth_email_verifications_user_index" ON "auth_email_verifications" ("user_id");

CREATE INDEX "auth_email_verifications_expires_index" ON "auth_email_verifications" ("expires_at");

CREATE TABLE "auth_invitations" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "role_ids" TEXT NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "invited_by" VARCHAR(36) NOT NULL,
    "expires_at" DATETIME NOT NULL,
    "accepted_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_invitations_token_hash_unique" ON "auth_invitations" ("token_hash");

CREATE INDEX "auth_invitations_org_index" ON "auth_invitations" ("organization_id");

CREATE INDEX "auth_invitations_email_index" ON "auth_invitations" ("email");

CREATE TABLE "auth_memberships" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "status" VARCHAR(16) NOT NULL DEFAULT 'invited',
    "invited_by" VARCHAR(36) NULL,
    "joined_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_memberships_user_org_unique" ON "auth_memberships" ("user_id", "organization_id");

CREATE INDEX "auth_memberships_org_status_index" ON "auth_memberships" ("organization_id", "status");

CREATE TABLE "auth_mfa_factors" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "type" VARCHAR(16) NOT NULL,
    "label" VARCHAR(80) NULL,
    "secret_encrypted" TEXT NULL,
    "phone_e164" VARCHAR(20) NULL,
    "email" VARCHAR(320) NULL,
    "is_default" INTEGER NOT NULL DEFAULT 0,
    "confirmed_at" DATETIME NULL,
    "last_used_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "auth_mfa_factors_user_type_index" ON "auth_mfa_factors" ("user_id", "type");

CREATE INDEX "auth_mfa_factors_user_confirmed_index" ON "auth_mfa_factors" ("user_id", "confirmed_at");

CREATE TABLE "auth_organizations" (
    "id" VARCHAR(36) NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "slug" VARCHAR(160) NOT NULL,
    "status" VARCHAR(16) NOT NULL DEFAULT 'active',
    "created_by" VARCHAR(36) NOT NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_organizations_slug_unique" ON "auth_organizations" ("slug");

CREATE INDEX "auth_organizations_status_index" ON "auth_organizations" ("status");

CREATE TABLE "auth_otp_challenges" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "factor_id" VARCHAR(36) NULL,
    "purpose" VARCHAR(20) NOT NULL,
    "channel" VARCHAR(16) NOT NULL,
    "code_hash" VARCHAR(64) NULL,
    "destination" VARCHAR(320) NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 5,
    "expires_at" DATETIME NOT NULL,
    "consumed_at" DATETIME NULL,
    "ip" VARCHAR(45) NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "auth_otp_challenges_user_purpose_index" ON "auth_otp_challenges" ("user_id", "purpose", "consumed_at");

CREATE INDEX "auth_otp_challenges_expires_index" ON "auth_otp_challenges" ("expires_at");

CREATE TABLE "auth_password_resets" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "expires_at" DATETIME NOT NULL,
    "consumed_at" DATETIME NULL,
    "ip" VARCHAR(45) NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_password_resets_token_hash_unique" ON "auth_password_resets" ("token_hash");

CREATE INDEX "auth_password_resets_user_index" ON "auth_password_resets" ("user_id");

CREATE INDEX "auth_password_resets_expires_index" ON "auth_password_resets" ("expires_at");

CREATE TABLE "auth_permissions" (
    "id" VARCHAR(36) NOT NULL,
    "key" VARCHAR(120) NOT NULL,
    "description" VARCHAR(255) NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_permissions_key_unique" ON "auth_permissions" ("key");

CREATE TABLE "auth_recovery_codes" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "code_hash" VARCHAR(64) NOT NULL,
    "used_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "auth_recovery_codes_user_used_index" ON "auth_recovery_codes" ("user_id", "used_at");

CREATE TABLE "auth_refresh_tokens" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "family_id" VARCHAR(36) NOT NULL,
    "parent_id" VARCHAR(36) NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "user_agent" VARCHAR(255) NULL,
    "ip" VARCHAR(45) NULL,
    "mfa" INTEGER NOT NULL DEFAULT 0,
    "amr" VARCHAR(64) NULL,
    "auth_time" INTEGER NULL,
    "expires_at" DATETIME NOT NULL,
    "last_used_at" DATETIME NULL,
    "revoked_at" DATETIME NULL,
    "revoked_reason" VARCHAR(32) NULL,
    "created_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_refresh_tokens_token_hash_unique" ON "auth_refresh_tokens" ("token_hash");

CREATE INDEX "auth_refresh_tokens_user_index" ON "auth_refresh_tokens" ("user_id", "revoked_at");

CREATE INDEX "auth_refresh_tokens_family_index" ON "auth_refresh_tokens" ("family_id");

CREATE TABLE "auth_roles" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "name" VARCHAR(80) NOT NULL,
    "slug" VARCHAR(80) NOT NULL,
    "description" VARCHAR(255) NULL,
    "is_system" INTEGER NOT NULL DEFAULT 0,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_roles_org_slug_unique" ON "auth_roles" ("organization_id", "slug");

CREATE TABLE "auth_role_permissions" (
    "role_id" VARCHAR(36) NOT NULL,
    "permission_id" VARCHAR(36) NOT NULL,
    PRIMARY KEY ("role_id", "permission_id"),
    FOREIGN KEY ("role_id") REFERENCES "auth_roles" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY ("permission_id") REFERENCES "auth_permissions" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "auth_users" (
    "id" VARCHAR(36) NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "email_verified_at" DATETIME NULL,
    "password_hash" VARCHAR(255) NULL,
    "display_name" VARCHAR(120) NULL,
    "status" VARCHAR(16) NOT NULL DEFAULT 'active',
    "mfa_enforced" INTEGER NOT NULL DEFAULT 0,
    "failed_login_count" INTEGER NOT NULL DEFAULT 0,
    "failed_login_at" DATETIME NULL,
    "locked_until" DATETIME NULL,
    "last_login_at" DATETIME NULL,
    "created_at" DATETIME NOT NULL,
    "updated_at" DATETIME NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_users_email_unique" ON "auth_users" ("email");

CREATE INDEX "auth_users_status_index" ON "auth_users" ("status");

CREATE TABLE "auth_membership_roles" (
    "membership_id" VARCHAR(36) NOT NULL,
    "role_id" VARCHAR(36) NOT NULL,
    PRIMARY KEY ("membership_id", "role_id"),
    FOREIGN KEY ("membership_id") REFERENCES "auth_memberships" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY ("role_id") REFERENCES "auth_roles" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
