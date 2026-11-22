CREATE TABLE `polaris_api_key` (
    `id` VARCHAR(36) NOT NULL,
    `owner_type` VARCHAR(16) NOT NULL,
    `owner_id` VARCHAR(36) NOT NULL,
    `organization_id` VARCHAR(36) NULL,
    `created_by` VARCHAR(36) NOT NULL,
    `name` VARCHAR(80) NOT NULL,
    `environment` VARCHAR(8) NOT NULL,
    `hint` VARCHAR(8) NOT NULL,
    `key_hash` VARCHAR(128) NOT NULL,
    `permissions` JSON NOT NULL,
    `rate_limit_window` INTEGER NULL,
    `rate_limit_max` INTEGER NULL,
    `metadata` JSON NOT NULL,
    `rotated_from_id` VARCHAR(36) NULL,
    `grace_until` DATETIME NULL,
    `expires_at` DATETIME NULL,
    `last_used_at` DATETIME NULL,
    `revoked_at` DATETIME NULL,
    `created_at` DATETIME NOT NULL,
    `updated_at` DATETIME NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE UNIQUE INDEX `polaris_api_key_hash_unique` ON `polaris_api_key` (`key_hash`);

CREATE INDEX `polaris_api_key_owner_index` ON `polaris_api_key` (`owner_type`, `owner_id`);

CREATE INDEX `polaris_api_key_creator_index` ON `polaris_api_key` (`created_by`);
