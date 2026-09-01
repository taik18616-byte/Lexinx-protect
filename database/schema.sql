-- ============================================
-- LEXINX PROTECT DATABASE
-- PostgreSQL
-- ============================================

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
-- OPTIONAL: LOGIN SESSIONS
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

-- ============================================
-- OPTIONAL: SCRIPT ACCESS LOG
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

-- ============================================
-- CHECK
-- ============================================

SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
