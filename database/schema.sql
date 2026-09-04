-- ============================================
-- LEXINX PROTECT DATABASE
-- PostgreSQL
-- FULL DATABASE SCHEMA
-- ============================================


-- ============================================
-- 1. USERS
-- ============================================

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,

    username VARCHAR(32) NOT NULL UNIQUE,

    password_hash TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- Case-insensitive username protection
-- Prevents User123 and user123 from both existing.

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower
ON users (LOWER(username));


-- ============================================
-- 2. SCRIPTS
-- ============================================

CREATE TABLE IF NOT EXISTS scripts (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    script_id VARCHAR(64) NOT NULL UNIQUE,

    name VARCHAR(100) NOT NULL DEFAULT 'My Script',

    source TEXT NOT NULL DEFAULT '',

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_scripts_user_id
ON scripts(user_id);


CREATE INDEX IF NOT EXISTS idx_scripts_script_id
ON scripts(script_id);


-- ============================================
-- 3. LOGIN SESSIONS
-- ============================================

CREATE TABLE IF NOT EXISTS login_sessions (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    session_token TEXT NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ,

    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_login_sessions_token
ON login_sessions(session_token);


CREATE INDEX IF NOT EXISTS idx_login_sessions_user_id
ON login_sessions(user_id);


CREATE INDEX IF NOT EXISTS idx_login_sessions_expires
ON login_sessions(expires_at);


-- ============================================
-- 4. SCRIPT ACCESS LOGS
-- ============================================

CREATE TABLE IF NOT EXISTS script_access_logs (
    id BIGSERIAL PRIMARY KEY,

    user_id BIGINT
        REFERENCES users(id)
        ON DELETE SET NULL,

    script_id VARCHAR(64),

    ip_address INET,

    success BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_access_logs_script
ON script_access_logs(script_id);


CREATE INDEX IF NOT EXISTS idx_access_logs_user
ON script_access_logs(user_id);


CREATE INDEX IF NOT EXISTS idx_access_logs_created
ON script_access_logs(created_at);


-- ============================================
-- 5. LOADER SESSIONS
-- ============================================
-- Used by the multi-stage LEXINX loader:
--
-- /api/loader/:id
--      ↓
-- /api/l3
--      ↓
-- /api/l4
--      ↓
-- /api/l5
--      ↓
-- /api/l5/final
--
-- This replaces the old in-memory loaderSessions Map.


CREATE TABLE IF NOT EXISTS loader_sessions (
    id BIGSERIAL PRIMARY KEY,

    session_token TEXT NOT NULL UNIQUE,

    script_id VARCHAR(64) NOT NULL
        REFERENCES scripts(script_id)
        ON DELETE CASCADE,

    stage INTEGER NOT NULL DEFAULT 0,

    tokens JSONB NOT NULL DEFAULT '[]'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT loader_sessions_stage_check
        CHECK (stage >= 0 AND stage <= 3)
);


CREATE INDEX IF NOT EXISTS idx_loader_sessions_token
ON loader_sessions(session_token);


CREATE INDEX IF NOT EXISTS idx_loader_sessions_script
ON loader_sessions(script_id);


CREATE INDEX IF NOT EXISTS idx_loader_sessions_expires
ON loader_sessions(expires_at);


-- ============================================
-- 6. CHECK DATABASE
-- ============================================

SELECT
    table_name
FROM information_schema.tables
WHERE table_schema = 'public'
AND table_name IN (
    'users',
    'scripts',
    'login_sessions',
    'script_access_logs',
    'loader_sessions'
)
ORDER BY table_name;


-- ============================================
-- 7. CHECK COLUMNS
-- ============================================

SELECT
    table_name,
    column_name,
    data_type
FROM information_schema.columns
WHERE table_schema = 'public'
AND table_name IN (
    'users',
    'scripts',
    'login_sessions',
    'script_access_logs',
    'loader_sessions'
)
ORDER BY
    table_name,
    ordinal_position;


-- ============================================
-- 8. CHECK DATABASE CONNECTION
-- ============================================

SELECT
    current_database() AS database_name,
    current_user AS database_user,
    NOW() AS server_time;


-- ============================================
-- 9. CHECK USERS TABLE
-- ============================================

SELECT
    id,
    username,
    created_at,
    updated_at
FROM users
ORDER BY id DESC
LIMIT 10;


-- ============================================
-- 10. CHECK SCRIPTS TABLE
-- ============================================

SELECT
    id,
    user_id,
    script_id,
    name,
    enabled,
    created_at,
    updated_at
FROM scripts
ORDER BY id DESC
LIMIT 10;


-- ============================================
-- 11. CHECK LOGIN SESSIONS
-- ============================================

SELECT
    id,
    user_id,
    session_token,
    created_at,
    expires_at,
    last_seen_at
FROM login_sessions
ORDER BY id DESC
LIMIT 10;


-- ============================================
-- 12. CHECK LOADER SESSIONS
-- ============================================

SELECT
    id,
    session_token,
    script_id,
    stage,
    tokens,
    created_at,
    expires_at,
    last_seen_at
FROM loader_sessions
ORDER BY id DESC
LIMIT 10;
