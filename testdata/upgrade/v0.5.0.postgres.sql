CREATE TABLE "auth_audit_log" (
    "id" VARCHAR(36) NOT NULL,
    "actor_user_id" VARCHAR(36) NULL,
    "organization_id" VARCHAR(36) NULL,
    "event" VARCHAR(80) NOT NULL,
    "ip" VARCHAR(45) NULL,
    "user_agent" VARCHAR(255) NULL,
    "metadata" JSONB NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
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
    "expires_at" TIMESTAMP NOT NULL,
    "consumed_at" TIMESTAMP NULL,
    "ip" VARCHAR(45) NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_email_verifications_token_hash_unique" ON "auth_email_verifications" ("token_hash");

CREATE INDEX "auth_email_verifications_user_index" ON "auth_email_verifications" ("user_id");

CREATE INDEX "auth_email_verifications_expires_index" ON "auth_email_verifications" ("expires_at");

CREATE TABLE "auth_invitations" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "role_ids" JSONB NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "invited_by" VARCHAR(36) NOT NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "accepted_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
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
    "joined_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
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
    "is_default" BOOLEAN NOT NULL DEFAULT FALSE,
    "confirmed_at" TIMESTAMP NULL,
    "last_used_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
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
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
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
    "expires_at" TIMESTAMP NOT NULL,
    "consumed_at" TIMESTAMP NULL,
    "ip" VARCHAR(45) NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "auth_otp_challenges_user_purpose_index" ON "auth_otp_challenges" ("user_id", "purpose", "consumed_at");

CREATE INDEX "auth_otp_challenges_expires_index" ON "auth_otp_challenges" ("expires_at");

CREATE TABLE "auth_password_resets" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "consumed_at" TIMESTAMP NULL,
    "ip" VARCHAR(45) NULL,
    "created_at" TIMESTAMP NOT NULL,
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
    "used_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
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
    "mfa" BOOLEAN NOT NULL DEFAULT FALSE,
    "amr" VARCHAR(64) NULL,
    "auth_time" INTEGER NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "last_used_at" TIMESTAMP NULL,
    "revoked_at" TIMESTAMP NULL,
    "revoked_reason" VARCHAR(32) NULL,
    "created_at" TIMESTAMP NOT NULL,
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
    "is_system" BOOLEAN NOT NULL DEFAULT FALSE,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
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
    "email_verified_at" TIMESTAMP NULL,
    "password_hash" VARCHAR(255) NULL,
    "display_name" VARCHAR(120) NULL,
    "status" VARCHAR(16) NOT NULL DEFAULT 'active',
    "mfa_enforced" BOOLEAN NOT NULL DEFAULT FALSE,
    "failed_login_count" INTEGER NOT NULL DEFAULT 0,
    "failed_login_at" TIMESTAMP NULL,
    "locked_until" TIMESTAMP NULL,
    "last_login_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "auth_users_email_unique" ON "auth_users" ("email");

CREATE INDEX "auth_users_status_index" ON "auth_users" ("status");

CREATE TABLE "polaris_audit_event" (
    "id" VARCHAR(36) NOT NULL,
    "name" VARCHAR(64) NOT NULL,
    "occurred_at" TIMESTAMP NOT NULL,
    "actor_type" VARCHAR(16) NOT NULL,
    "actor_id" VARCHAR(64) NULL,
    "subject_id" VARCHAR(64) NULL,
    "organization_id" VARCHAR(64) NULL,
    "session_id" VARCHAR(64) NULL,
    "ip" VARCHAR(45) NULL,
    "user_agent" TEXT NULL,
    "data" JSONB NOT NULL,
    "request_id" VARCHAR(64) NULL,
    "prev_hash" VARCHAR(64) NULL,
    "hash" VARCHAR(64) NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_audit_event_name_index" ON "polaris_audit_event" ("name", "occurred_at");

CREATE INDEX "polaris_audit_event_occurred_index" ON "polaris_audit_event" ("occurred_at");

CREATE INDEX "polaris_audit_event_actor_index" ON "polaris_audit_event" ("actor_id", "occurred_at");

CREATE INDEX "polaris_audit_event_subject_index" ON "polaris_audit_event" ("subject_id", "occurred_at");

CREATE INDEX "polaris_audit_event_org_index" ON "polaris_audit_event" ("organization_id", "occurred_at");

CREATE TABLE "polaris_audit_drain" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "type" VARCHAR(16) NOT NULL,
    "endpoint" VARCHAR(2048) NOT NULL,
    "secret" TEXT NOT NULL,
    "filter" JSONB NOT NULL,
    "status" VARCHAR(16) NOT NULL,
    "last_delivery_at" TIMESTAMP NULL,
    "last_error" TEXT NULL,
    "created_at" TIMESTAMP NOT NULL,
    "created_by" VARCHAR(36) NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_audit_drain_org_index" ON "polaris_audit_drain" ("organization_id", "status");

CREATE TABLE "polaris_audit_activity" (
    "user_id" VARCHAR(36) NOT NULL,
    "last_active_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("user_id")
);

CREATE TABLE "polaris_audit_chain" (
    "id" VARCHAR(16) NOT NULL,
    "last_id" VARCHAR(36) NOT NULL,
    "last_hash" VARCHAR(64) NOT NULL,
    "locked_by" VARCHAR(36) NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "polaris_admin_grant" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "role" VARCHAR(16) NOT NULL,
    "scope" VARCHAR(36) NOT NULL,
    "granted_by" VARCHAR(36) NULL,
    "expires_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_admin_grant_user_unique" ON "polaris_admin_grant" ("user_id");

CREATE TABLE "polaris_admin_key" (
    "id" VARCHAR(36) NOT NULL,
    "name" VARCHAR(120) NOT NULL,
    "key_hash" VARCHAR(64) NOT NULL,
    "role" VARCHAR(16) NOT NULL,
    "scope" VARCHAR(36) NOT NULL,
    "ip_allowlist" JSONB NOT NULL,
    "expires_at" TIMESTAMP NULL,
    "last_used_at" TIMESTAMP NULL,
    "created_by" VARCHAR(64) NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_admin_key_hash_unique" ON "polaris_admin_key" ("key_hash");

CREATE TABLE "polaris_api_key" (
    "id" VARCHAR(36) NOT NULL,
    "owner_type" VARCHAR(16) NOT NULL,
    "owner_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "created_by" VARCHAR(36) NOT NULL,
    "name" VARCHAR(80) NOT NULL,
    "environment" VARCHAR(8) NOT NULL,
    "hint" VARCHAR(8) NOT NULL,
    "key_hash" VARCHAR(128) NOT NULL,
    "permissions" JSONB NOT NULL,
    "rate_limit_window" INTEGER NULL,
    "rate_limit_max" INTEGER NULL,
    "metadata" JSONB NOT NULL,
    "rotated_from_id" VARCHAR(36) NULL,
    "grace_until" TIMESTAMP NULL,
    "expires_at" TIMESTAMP NULL,
    "last_used_at" TIMESTAMP NULL,
    "revoked_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_api_key_hash_unique" ON "polaris_api_key" ("key_hash");

CREATE INDEX "polaris_api_key_owner_index" ON "polaris_api_key" ("owner_type", "owner_id");

CREATE INDEX "polaris_api_key_creator_index" ON "polaris_api_key" ("created_by");

CREATE TABLE "polaris_oauth_client" (
    "id" VARCHAR(36) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "name" VARCHAR(160) NOT NULL,
    "type" VARCHAR(16) NOT NULL,
    "secret_hash" VARCHAR(128) NULL,
    "redirect_uris" JSONB NOT NULL,
    "grant_types" JSONB NOT NULL,
    "scopes" JSONB NOT NULL,
    "token_endpoint_auth_method" VARCHAR(32) NOT NULL,
    "jwks" JSONB NULL,
    "jwks_uri" VARCHAR(2048) NULL,
    "dpop_bound" BOOLEAN NOT NULL DEFAULT FALSE,
    "trusted" BOOLEAN NOT NULL DEFAULT FALSE,
    "logo_uri" VARCHAR(2048) NULL,
    "client_uri" VARCHAR(2048) NULL,
    "policy_uri" VARCHAR(2048) NULL,
    "tos_uri" VARCHAR(2048) NULL,
    "created_by" VARCHAR(36) NULL,
    "disabled_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_client_id_unique" ON "polaris_oauth_client" ("client_id");

CREATE INDEX "polaris_oauth_client_org_index" ON "polaris_oauth_client" ("organization_id");

CREATE TABLE "polaris_oauth_consent" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" JSONB NOT NULL,
    "granted_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_consent_unique" ON "polaris_oauth_consent" ("user_id", "client_id");

CREATE TABLE "polaris_oauth_code" (
    "id" VARCHAR(36) NOT NULL,
    "code_hash" VARCHAR(128) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" JSONB NOT NULL,
    "redirect_uri" VARCHAR(2048) NOT NULL,
    "code_challenge" VARCHAR(128) NOT NULL,
    "nonce" VARCHAR(255) NULL,
    "resource" VARCHAR(2048) NULL,
    "dpop_jkt" VARCHAR(128) NULL,
    "auth_time" INTEGER NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "used_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_code_hash_unique" ON "polaris_oauth_code" ("code_hash");

CREATE TABLE "polaris_oauth_token" (
    "id" VARCHAR(36) NOT NULL,
    "kind" VARCHAR(8) NOT NULL,
    "token_hash" VARCHAR(128) NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "user_id" VARCHAR(36) NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" JSONB NOT NULL,
    "family_id" VARCHAR(36) NULL,
    "resource" VARCHAR(2048) NULL,
    "dpop_jkt" VARCHAR(128) NULL,
    "actor" JSONB NULL,
    "auth_time" INTEGER NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "revoked_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_token_hash_unique" ON "polaris_oauth_token" ("token_hash");

CREATE INDEX "polaris_oauth_token_user_index" ON "polaris_oauth_token" ("user_id", "client_id");

CREATE INDEX "polaris_oauth_token_family_index" ON "polaris_oauth_token" ("family_id");

CREATE TABLE "polaris_oauth_device_code" (
    "id" VARCHAR(36) NOT NULL,
    "device_code_hash" VARCHAR(128) NOT NULL,
    "user_code" VARCHAR(16) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "scopes" JSONB NOT NULL,
    "resource" VARCHAR(2048) NULL,
    "status" VARCHAR(16) NOT NULL,
    "user_id" VARCHAR(36) NULL,
    "organization_id" VARCHAR(36) NULL,
    "auth_time" INTEGER NULL,
    "last_polled_at" TIMESTAMP NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_oauth_device_code_hash_unique" ON "polaris_oauth_device_code" ("device_code_hash");

CREATE UNIQUE INDEX "polaris_oauth_device_user_code_unique" ON "polaris_oauth_device_code" ("user_code");

CREATE TABLE "polaris_oauth_ciba_request" (
    "id" VARCHAR(36) NOT NULL,
    "client_id" VARCHAR(255) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "scopes" JSONB NOT NULL,
    "binding_message" VARCHAR(160) NULL,
    "resource" VARCHAR(2048) NULL,
    "status" VARCHAR(16) NOT NULL,
    "auth_time" INTEGER NULL,
    "last_polled_at" TIMESTAMP NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_oauth_ciba_user_index" ON "polaris_oauth_ciba_request" ("user_id", "status");

CREATE TABLE "polaris_agent" (
    "id" VARCHAR(36) NOT NULL,
    "owner_type" VARCHAR(16) NOT NULL,
    "owner_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "name" VARCHAR(160) NOT NULL,
    "mode" VARCHAR(16) NOT NULL,
    "host_id" VARCHAR(36) NULL,
    "auth" VARCHAR(32) NOT NULL,
    "public_jwk" JSONB NULL,
    "status" VARCHAR(16) NOT NULL,
    "created_by" VARCHAR(36) NOT NULL,
    "sealed_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_agent_owner_index" ON "polaris_agent" ("owner_type", "owner_id");

CREATE INDEX "polaris_agent_org_index" ON "polaris_agent" ("organization_id");

CREATE TABLE "polaris_agent_host" (
    "id" VARCHAR(36) NOT NULL,
    "owner_type" VARCHAR(16) NOT NULL,
    "owner_id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NULL,
    "name" VARCHAR(160) NOT NULL,
    "enrollment_token_hash" VARCHAR(128) NOT NULL,
    "default_capabilities" JSONB NOT NULL,
    "created_by" VARCHAR(36) NOT NULL,
    "revoked_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_agent_host_token_unique" ON "polaris_agent_host" ("enrollment_token_hash");

CREATE INDEX "polaris_agent_host_owner_index" ON "polaris_agent_host" ("owner_type", "owner_id");

CREATE TABLE "polaris_agent_grant" (
    "id" VARCHAR(36) NOT NULL,
    "agent_id" VARCHAR(36) NOT NULL,
    "capability" VARCHAR(80) NOT NULL,
    "constraints" JSONB NOT NULL,
    "budget_total" INTEGER NULL,
    "budget_remaining" INTEGER NULL,
    "budget_kind" VARCHAR(8) NULL,
    "budget_field" VARCHAR(80) NULL,
    "status" VARCHAR(16) NOT NULL,
    "granted_by" VARCHAR(36) NULL,
    "approved_via" VARCHAR(32) NULL,
    "approval_id" VARCHAR(36) NULL,
    "expires_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_agent_grant_lookup_index" ON "polaris_agent_grant" ("agent_id", "capability", "status");

CREATE TABLE "polaris_agent_approval" (
    "id" VARCHAR(36) NOT NULL,
    "agent_id" VARCHAR(36) NOT NULL,
    "grant_ids" JSONB NOT NULL,
    "method" VARCHAR(32) NOT NULL,
    "strength" VARCHAR(16) NOT NULL,
    "user_code" VARCHAR(16) NOT NULL,
    "binding_message" VARCHAR(160) NULL,
    "status" VARCHAR(16) NOT NULL,
    "decided_by" VARCHAR(36) NULL,
    "expires_at" TIMESTAMP NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_agent_approval_code_index" ON "polaris_agent_approval" ("user_code", "status");

CREATE INDEX "polaris_agent_approval_agent_index" ON "polaris_agent_approval" ("agent_id", "status");

CREATE TABLE "polaris_agent_receipt" (
    "id" VARCHAR(36) NOT NULL,
    "agent_id" VARCHAR(36) NOT NULL,
    "seq" INTEGER NOT NULL,
    "grant_id" VARCHAR(36) NULL,
    "capability" VARCHAR(80) NULL,
    "input_hash" VARCHAR(64) NOT NULL,
    "outcome" VARCHAR(16) NOT NULL,
    "budget_before" INTEGER NULL,
    "budget_after" INTEGER NULL,
    "prev_hash" VARCHAR(64) NULL,
    "hash" VARCHAR(64) NOT NULL,
    "signature" TEXT NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_agent_receipt_seq_unique" ON "polaris_agent_receipt" ("agent_id", "seq");

CREATE TABLE "polaris_anonymous" (
    "user_id" VARCHAR(36) NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    "converted_at" TIMESTAMP NULL,
    "converted_user_id" VARCHAR(36) NULL,
    PRIMARY KEY ("user_id")
);

CREATE INDEX "polaris_anonymous_created_index" ON "polaris_anonymous" ("created_at");

CREATE TABLE "polaris_username" (
    "user_id" VARCHAR(36) NOT NULL,
    "username" VARCHAR(64) NOT NULL,
    "display_username" VARCHAR(64) NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("user_id")
);

CREATE UNIQUE INDEX "polaris_username_unique" ON "polaris_username" ("username");

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

CREATE TABLE "polaris_sentinel_decision" (
    "id" VARCHAR(36) NOT NULL,
    "kind" VARCHAR(32) NOT NULL,
    "email" VARCHAR(320) NULL,
    "ip" VARCHAR(45) NULL,
    "score" INTEGER NOT NULL,
    "action" VARCHAR(16) NOT NULL,
    "enforced" BOOLEAN NOT NULL,
    "signals" JSONB NOT NULL,
    "reasons" JSONB NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_sentinel_decision_created_index" ON "polaris_sentinel_decision" ("created_at");

CREATE INDEX "polaris_sentinel_decision_email_index" ON "polaris_sentinel_decision" ("email");

CREATE INDEX "polaris_sentinel_decision_ip_index" ON "polaris_sentinel_decision" ("ip");

CREATE TABLE "polaris_sentinel_ip_rule" (
    "id" VARCHAR(36) NOT NULL,
    "cidr" VARCHAR(64) NOT NULL,
    "action" VARCHAR(16) NOT NULL,
    "note" VARCHAR(255) NULL,
    "created_by" VARCHAR(64) NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "polaris_sentinel_device" (
    "id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "device_hash" VARCHAR(64) NOT NULL,
    "ip" VARCHAR(45) NULL,
    "latitude" VARCHAR(32) NULL,
    "longitude" VARCHAR(32) NULL,
    "last_seen_at" TIMESTAMP NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_sentinel_device_unique" ON "polaris_sentinel_device" ("user_id", "device_hash");

CREATE TABLE "polaris_sso_provider" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "type" VARCHAR(8) NOT NULL,
    "name" VARCHAR(120) NOT NULL,
    "issuer" VARCHAR(512) NOT NULL,
    "config" JSONB NOT NULL,
    "attributes" JSONB NOT NULL,
    "jit" JSONB NOT NULL,
    "redirect_uris" JSONB NOT NULL,
    "enabled" BOOLEAN NOT NULL,
    "created_by" VARCHAR(64) NULL,
    "created_at" TIMESTAMP NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_sso_provider_org_index" ON "polaris_sso_provider" ("organization_id");

CREATE TABLE "polaris_sso_domain" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "provider_id" VARCHAR(36) NOT NULL,
    "domain" VARCHAR(253) NOT NULL,
    "token" VARCHAR(64) NOT NULL,
    "verified_at" TIMESTAMP NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_sso_domain_unique" ON "polaris_sso_domain" ("domain");

CREATE INDEX "polaris_sso_domain_org_index" ON "polaris_sso_domain" ("organization_id");

CREATE TABLE "polaris_scim_connection" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "sso_provider_id" VARCHAR(36) NULL,
    "name" VARCHAR(120) NOT NULL,
    "token_hash" VARCHAR(128) NOT NULL,
    "status" VARCHAR(16) NOT NULL,
    "settings" JSONB NOT NULL,
    "last_sync_at" TIMESTAMP NULL,
    "decommissioned_at" TIMESTAMP NULL,
    "created_by" VARCHAR(64) NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE INDEX "polaris_scim_connection_org_index" ON "polaris_scim_connection" ("organization_id");

CREATE INDEX "polaris_scim_connection_token_index" ON "polaris_scim_connection" ("token_hash");

CREATE TABLE "polaris_scim_resource" (
    "id" VARCHAR(36) NOT NULL,
    "connection_id" VARCHAR(36) NOT NULL,
    "kind" VARCHAR(8) NOT NULL,
    "external_id" VARCHAR(255) NOT NULL,
    "local_id" VARCHAR(36) NOT NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_scim_resource_unique" ON "polaris_scim_resource" ("connection_id", "kind", "local_id");

CREATE TABLE "polaris_scim_membership_provenance" (
    "id" VARCHAR(36) NOT NULL,
    "organization_id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "connection_id" VARCHAR(36) NOT NULL,
    "created_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_scim_provenance_unique" ON "polaris_scim_membership_provenance" ("organization_id", "user_id");

CREATE TABLE "polaris_scim_user_name" (
    "id" VARCHAR(36) NOT NULL,
    "connection_id" VARCHAR(36) NOT NULL,
    "user_id" VARCHAR(36) NOT NULL,
    "given_name" VARCHAR(120) NULL,
    "family_name" VARCHAR(120) NULL,
    "updated_at" TIMESTAMP NOT NULL,
    PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "polaris_scim_user_name_unique" ON "polaris_scim_user_name" ("connection_id", "user_id");

CREATE TABLE "auth_membership_roles" (
    "membership_id" VARCHAR(36) NOT NULL,
    "role_id" VARCHAR(36) NOT NULL,
    PRIMARY KEY ("membership_id", "role_id"),
    FOREIGN KEY ("membership_id") REFERENCES "auth_memberships" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY ("role_id") REFERENCES "auth_roles" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
