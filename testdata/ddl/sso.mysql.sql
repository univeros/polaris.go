CREATE TABLE `polaris_sso_provider` (
    `id` VARCHAR(36) NOT NULL,
    `organization_id` VARCHAR(36) NOT NULL,
    `type` VARCHAR(8) NOT NULL,
    `name` VARCHAR(120) NOT NULL,
    `issuer` VARCHAR(512) NOT NULL,
    `config` JSON NOT NULL,
    `attributes` JSON NOT NULL,
    `jit` JSON NOT NULL,
    `redirect_uris` JSON NOT NULL,
    `enabled` TINYINT(1) NOT NULL,
    `created_by` VARCHAR(64) NULL,
    `created_at` DATETIME NOT NULL,
    `updated_at` DATETIME NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE INDEX `polaris_sso_provider_org_index` ON `polaris_sso_provider` (`organization_id`);

CREATE TABLE `polaris_sso_domain` (
    `id` VARCHAR(36) NOT NULL,
    `organization_id` VARCHAR(36) NOT NULL,
    `provider_id` VARCHAR(36) NOT NULL,
    `domain` VARCHAR(253) NOT NULL,
    `token` VARCHAR(64) NOT NULL,
    `verified_at` DATETIME NULL,
    `created_at` DATETIME NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE UNIQUE INDEX `polaris_sso_domain_unique` ON `polaris_sso_domain` (`domain`);

CREATE INDEX `polaris_sso_domain_org_index` ON `polaris_sso_domain` (`organization_id`);
