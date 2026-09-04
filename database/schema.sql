-- =========================================================
-- LEXINX PROTECT DATABASE SCHEMA
-- Version: 1.0
-- Description: Full database schema for LEXINX PROTECT
-- Supports: 24/7 operation, persistent storage
-- =========================================================

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS lexinx_protect
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE lexinx_protect;

-- =========================================================
-- 1. USERS TABLE
-- Stores: User accounts (register/login)
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    username_lower VARCHAR(32) NOT NULL UNIQUE COMMENT 'Lowercase username for lookups',
    password_hash VARCHAR(64) NOT NULL COMMENT 'SHA256 hash',
    created_at BIGINT NOT NULL COMMENT 'Unix timestamp in milliseconds',
    updated_at BIGINT NOT NULL COMMENT 'Unix timestamp in milliseconds',
    
    INDEX idx_username_lower (username_lower),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='User accounts';

-- =========================================================
-- 2. WEB SESSIONS TABLE
-- Stores: Web login sessions (7 days TTL)
-- =========================================================

CREATE TABLE IF NOT EXISTS web_sessions (
    session_id VARCHAR(64) PRIMARY KEY COMMENT 'Random 32 bytes hex',
    username_lower VARCHAR(32) NOT NULL COMMENT 'Reference to users',
    created_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    expires_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    last_accessed_at BIGINT NULL COMMENT 'For session tracking',
    
    INDEX idx_username (username_lower),
    INDEX idx_expires (expires_at),
    INDEX idx_last_accessed (last_accessed_at),
    
    FOREIGN KEY (username_lower) 
        REFERENCES users(username_lower)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Web sessions (7 days TTL)';

-- =========================================================
-- 3. SCRIPTS TABLE
-- Stores: User scripts with source code
-- =========================================================

CREATE TABLE IF NOT EXISTS scripts (
    id VARCHAR(24) PRIMARY KEY COMMENT 'Random 12 bytes hex',
    name VARCHAR(100) NOT NULL DEFAULT 'Untitled Script',
    source LONGTEXT NOT NULL COMMENT 'Lua script source code',
    owner_username VARCHAR(32) NOT NULL COMMENT 'Reference to users',
    created_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    updated_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    is_active TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Soft delete flag',
    
    INDEX idx_owner (owner_username),
    INDEX idx_created (created_at),
    INDEX idx_updated (updated_at),
    INDEX idx_active (is_active),
    
    FOREIGN KEY (owner_username) 
        REFERENCES users(username_lower)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='User scripts';

-- =========================================================
-- 4. LOADER SESSIONS TABLE
-- Stores: Loader execution sessions (60 seconds TTL)
-- =========================================================

CREATE TABLE IF NOT EXISTS loader_sessions (
    session_id VARCHAR(64) PRIMARY KEY COMMENT 'Random 32 bytes hex',
    script_id VARCHAR(24) NOT NULL COMMENT 'Reference to scripts',
    stage INT NOT NULL DEFAULT 0 COMMENT 'Execution stage: 0-3',
    created_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    expires_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    completed_at BIGINT NULL COMMENT 'When script was delivered',
    user_agent VARCHAR(255) NULL COMMENT 'Client user agent',
    ip_address VARCHAR(45) NULL COMMENT 'Client IP address',
    
    INDEX idx_script (script_id),
    INDEX idx_expires (expires_at),
    INDEX idx_stage (stage),
    INDEX idx_created (created_at),
    
    FOREIGN KEY (script_id) 
        REFERENCES scripts(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Loader sessions (60 seconds TTL)';

-- =========================================================
-- 5. LOADER TOKENS TABLE
-- Stores: One-time tokens for each stage
-- =========================================================

CREATE TABLE IF NOT EXISTS loader_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL COMMENT 'Reference to loader_sessions',
    token VARCHAR(64) NOT NULL UNIQUE COMMENT 'Random 32 bytes hex',
    stage INT NOT NULL COMMENT 'Stage this token belongs to',
    is_used TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Token consumed?',
    created_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    used_at BIGINT NULL COMMENT 'When token was consumed',
    
    INDEX idx_session (session_id),
    INDEX idx_token (token),
    INDEX idx_used (is_used),
    
    FOREIGN KEY (session_id) 
        REFERENCES loader_sessions(session_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Loader tokens for each stage';

-- =========================================================
-- 6. SCRIPT EXECUTION LOGS TABLE
-- Stores: Execution history and statistics
-- =========================================================

CREATE TABLE IF NOT EXISTS script_execution_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    script_id VARCHAR(24) NOT NULL COMMENT 'Reference to scripts',
    loader_session_id VARCHAR(64) NULL COMMENT 'Reference to loader_sessions',
    executed_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    success TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'Execution successful?',
    error_message TEXT NULL COMMENT 'Error details if failed',
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    execution_time_ms INT NULL COMMENT 'Time to complete execution',
    
    INDEX idx_script (script_id),
    INDEX idx_executed (executed_at),
    INDEX idx_success (success),
    
    FOREIGN KEY (script_id) 
        REFERENCES scripts(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
        
    FOREIGN KEY (loader_session_id) 
        REFERENCES loader_sessions(session_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Script execution logs';

-- =========================================================
-- 7. RATE LIMITING TABLE
-- Stores: API rate limiting data
-- =========================================================

CREATE TABLE IF NOT EXISTS rate_limits (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    request_count INT NOT NULL DEFAULT 0,
    window_start BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    last_request_at BIGINT NULL,
    
    INDEX idx_ip_endpoint (ip_address, endpoint),
    INDEX idx_window (window_start),
    
    UNIQUE KEY unique_ip_endpoint_window (ip_address, endpoint, window_start)
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Rate limiting data';

-- =========================================================
-- 8. AUDIT LOGS TABLE
-- Stores: Security and activity logs
-- =========================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username_lower VARCHAR(32) NULL COMMENT 'User involved (if any)',
    action VARCHAR(50) NOT NULL COMMENT 'Action type',
    details TEXT NULL COMMENT 'Additional details',
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    created_at BIGINT NOT NULL COMMENT 'Unix timestamp in ms',
    success TINYINT(1) NOT NULL DEFAULT 1,
    
    INDEX idx_username (username_lower),
    INDEX idx_action (action),
    INDEX idx_created (created_at)
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Security and activity logs';

-- =========================================================
-- 9. SCRIPT VERSIONS TABLE (Optional)
-- Stores: Version history for scripts
-- =========================================================

CREATE TABLE IF NOT EXISTS script_versions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    script_id VARCHAR(24) NOT NULL,
    version_number INT NOT NULL DEFAULT 1,
    name VARCHAR(100) NOT NULL,
    source LONGTEXT NOT NULL,
    created_at BIGINT NOT NULL,
    created_by VARCHAR(32) NOT NULL,
    
    INDEX idx_script (script_id),
    INDEX idx_version (version_number),
    
    UNIQUE KEY unique_script_version (script_id, version_number),
    
    FOREIGN KEY (script_id) 
        REFERENCES scripts(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Script version history';

-- =========================================================
-- 10. SETTINGS TABLE
-- Stores: System configuration
-- =========================================================

CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT NULL,
    updated_at BIGINT NULL,
    updated_by VARCHAR(32) NULL,
    
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB 
  DEFAULT CHARSET=utf8mb4 
  COLLATE=utf8mb4_unicode_ci
  COMMENT='System settings';

-- =========================================================
-- INSERT DEFAULT SETTINGS
-- =========================================================

INSERT INTO settings (setting_key, setting_value, updated_at) VALUES
    ('public_url', 'https://lexinx-protect-v230.vercel.app', UNIX_TIMESTAMP() * 1000),
    ('web_session_ttl', '604800000', UNIX_TIMESTAMP() * 1000), -- 7 days in ms
    ('loader_session_ttl', '60000', UNIX_TIMESTAMP() * 1000), -- 60 seconds in ms
    ('max_script_size', '1048576', UNIX_TIMESTAMP() * 1000), -- 1MB
    ('registration_enabled', 'true', UNIX_TIMESTAMP() * 1000)
ON DUPLICATE KEY UPDATE 
    setting_value = VALUES(setting_value),
    updated_at = VALUES(updated_at);

-- =========================================================
-- VIEWS FOR COMMON QUERIES
-- =========================================================

-- View: Active scripts with owner info
CREATE OR REPLACE VIEW v_active_scripts AS
SELECT 
    s.id,
    s.name,
    s.owner_username,
    u.username as owner_display_name,
    s.created_at,
    s.updated_at,
    (SELECT COUNT(*) FROM script_execution_logs sel 
     WHERE sel.script_id = s.id AND sel.success = 1) as execution_count,
    (SELECT MAX(sel.executed_at) FROM script_execution_logs sel 
     WHERE sel.script_id = s.id) as last_executed_at
FROM scripts s
JOIN users u ON s.owner_username = u.username_lower
WHERE s.is_active = 1;

-- View: Active web sessions with user info
CREATE OR REPLACE VIEW v_active_web_sessions AS
SELECT 
    ws.session_id,
    ws.username_lower,
    u.username,
    ws.created_at,
    ws.expires_at,
    (ws.expires_at - UNIX_TIMESTAMP() * 1000) / 1000 as seconds_remaining
FROM web_sessions ws
JOIN users u ON ws.username_lower = u.username_lower
WHERE ws.expires_at > UNIX_TIMESTAMP() * 1000;

-- View: Active loader sessions
CREATE OR REPLACE VIEW v_active_loader_sessions AS
SELECT 
    ls.session_id,
    ls.script_id,
    s.name as script_name,
    ls.stage,
    ls.created_at,
    ls.expires_at,
    (ls.expires_at - UNIX_TIMESTAMP() * 1000) / 1000 as seconds_remaining
FROM loader_sessions ls
JOIN scripts s ON ls.script_id = s.id
WHERE ls.expires_at > UNIX_TIMESTAMP() * 1000;

-- =========================================================
-- STORED PROCEDURES
-- =========================================================

-- Procedure: Clean expired sessions
DELIMITER $$

CREATE PROCEDURE IF NOT EXISTS sp_cleanup_expired_sessions()
BEGIN
    DECLARE current_time BIGINT;
    SET current_time = UNIX_TIMESTAMP() * 1000;
    
    -- Delete expired web sessions
    DELETE FROM web_sessions WHERE expires_at < current_time;
    
    -- Delete expired loader sessions and their tokens
    DELETE FROM loader_tokens WHERE session_id IN (
        SELECT session_id FROM loader_sessions WHERE expires_at < current_time
    );
    
    DELETE FROM loader_sessions WHERE expires_at < current_time;
    
    -- Delete old rate limits (1 hour)
    DELETE FROM rate_limits WHERE window_start < (current_time - 3600000);
    
    -- Delete old audit logs (30 days)
    DELETE FROM audit_logs WHERE created_at < (current_time - 2592000000);
    
    -- Delete old execution logs (90 days)
    DELETE FROM script_execution_logs WHERE executed_at < (current_time - 7776000000);
END$$

-- Procedure: Get user scripts
CREATE PROCEDURE IF NOT EXISTS sp_get_user_scripts(IN p_username VARCHAR(32))
BEGIN
    SELECT 
        id,
        name,
        created_at,
        updated_at
    FROM scripts
    WHERE owner_username = LOWER(p_username)
        AND is_active = 1
    ORDER BY created_at DESC;
END$$

-- Procedure: Create loader session with token
CREATE PROCEDURE IF NOT EXISTS sp_create_loader_session(
    IN p_script_id VARCHAR(24),
    IN p_session_id VARCHAR(64),
    IN p_token VARCHAR(64),
    IN p_stage INT,
    IN p_expires_at BIGINT
)
BEGIN
    INSERT INTO loader_sessions (session_id, script_id, stage, created_at, expires_at)
    VALUES (p_session_id, p_script_id, 0, UNIX_TIMESTAMP() * 1000, p_expires_at);
    
    INSERT INTO loader_tokens (session_id, token, stage, created_at)
    VALUES (p_session_id, p_token, p_stage, UNIX_TIMESTAMP() * 1000);
END$$

DELIMITER ;

-- =========================================================
-- EVENTS FOR AUTOMATIC CLEANUP
-- =========================================================

-- Event: Cleanup every 5 minutes
CREATE EVENT IF NOT EXISTS ev_cleanup_sessions
    ON SCHEDULE EVERY 5 MINUTE
    DO
    CALL sp_cleanup_expired_sessions();

-- Event: Update stats every hour
CREATE EVENT IF NOT EXISTS ev_update_stats
    ON SCHEDULE EVERY 1 HOUR
    DO
    BEGIN
        -- Update script statistics
        UPDATE scripts s
        SET s.updated_at = UNIX_TIMESTAMP() * 1000
        WHERE s.id IN (
            SELECT DISTINCT script_id 
            FROM script_execution_logs 
            WHERE executed_at > (UNIX_TIMESTAMP() * 1000 - 3600000)
        );
    END;

-- =========================================================
-- TRIGGERS
-- =========================================================

-- Trigger: Log user registration
DELIMITER $$

CREATE TRIGGER IF NOT EXISTS trg_user_register
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (username_lower, action, details, created_at, success)
    VALUES (NEW.username_lower, 'USER_REGISTER', 
            CONCAT('User registered: ', NEW.username), 
            UNIX_TIMESTAMP() * 1000, 1);
END$$

-- Trigger: Log script creation
CREATE TRIGGER IF NOT EXISTS trg_script_create
AFTER INSERT ON scripts
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (username_lower, action, details, created_at, success)
    VALUES (NEW.owner_username, 'SCRIPT_CREATE', 
            CONCAT('Script created: ', NEW.name, ' (ID: ', NEW.id, ')'), 
            UNIX_TIMESTAMP() * 1000, 1);
END$$

-- Trigger: Log script deletion
CREATE TRIGGER IF NOT EXISTS trg_script_delete
AFTER DELETE ON scripts
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (username_lower, action, details, created_at, success)
    VALUES (OLD.owner_username, 'SCRIPT_DELETE', 
            CONCAT('Script deleted: ', OLD.name, ' (ID: ', OLD.id, ')'), 
            UNIX_TIMESTAMP() * 1000, 1);
END$$

-- Trigger: Track token usage
CREATE TRIGGER IF NOT EXISTS trg_token_use
AFTER UPDATE ON loader_tokens
FOR EACH ROW
BEGIN
    IF NEW.is_used = 1 AND OLD.is_used = 0 THEN
        UPDATE loader_tokens 
        SET used_at = UNIX_TIMESTAMP() * 1000
        WHERE id = NEW.id;
    END IF;
END$$

DELIMITER ;

-- =========================================================
-- INITIAL INDEXES FOR PERFORMANCE
-- =========================================================

-- Composite indexes for common queries
CREATE INDEX idx_scripts_owner_created ON scripts(owner_username, created_at DESC);
CREATE INDEX idx_logs_script_time ON script_execution_logs(script_id, executed_at DESC);
CREATE INDEX idx_sessions_expires ON web_sessions(expires_at);
CREATE INDEX idx_loader_expires ON loader_sessions(expires_at);

-- Full-text search for script names (MySQL 5.7+)
ALTER TABLE scripts ADD FULLTEXT INDEX ft_script_name (name);
ALTER TABLE scripts ADD FULLTEXT INDEX ft_script_source (source);

-- =========================================================
-- DATABASE OPTIMIZATION
-- =========================================================

-- Set global variables for performance (run as root)
SET GLOBAL max_connections = 1000;
SET GLOBAL innodb_buffer_pool_size = 1073741824; -- 1GB
SET GLOBAL innodb_log_file_size = 268435456; -- 256MB
SET GLOBAL innodb_flush_log_at_trx_commit = 2;
SET GLOBAL query_cache_size = 67108864; -- 64MB
SET GLOBAL query_cache_type = 1;

-- =========================================================
-- BACKUP SCHEDULE (Run manually or via cron)
-- =========================================================
-- Backup command:
-- mysqldump -u root -p lexinx_protect > backup_$(date +%Y%m%d_%H%M%S).sql
-- 
-- Restore command:
-- mysql -u root -p lexinx_protect < backup_file.sql

-- =========================================================
-- END OF SCHEMA
-- =========================================================
