-- ============================================
-- LEXINX PROTECT DATABASE - COMPLETE
-- PostgreSQL
-- ============================================

-- ============================================
-- 1. USERS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 2. SCRIPTS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS scripts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    script_id VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL DEFAULT 'My Script',
    source TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 3. LOGIN SESSIONS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS login_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 4. LOADER SESSIONS TABLE (BẮT BUỘC)
-- ============================================
CREATE TABLE IF NOT EXISTS loader_sessions (
    id BIGSERIAL PRIMARY KEY,
    session_token TEXT NOT NULL UNIQUE,
    script_id VARCHAR(64) NOT NULL REFERENCES scripts(script_id) ON DELETE CASCADE,
    stage INTEGER NOT NULL DEFAULT 0,
    tokens JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- 5. SCRIPT ACCESS LOGS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS script_access_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    script_id VARCHAR(64),
    ip_address INET,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================
-- INDEXES
-- ============================================

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Scripts indexes
CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id);
CREATE INDEX IF NOT EXISTS idx_scripts_script_id ON scripts(script_id);
CREATE INDEX IF NOT EXISTS idx_scripts_enabled ON scripts(enabled);

-- Login sessions indexes
CREATE INDEX IF NOT EXISTS idx_login_sessions_token ON login_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_login_sessions_user_id ON login_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_login_sessions_expires ON login_sessions(expires_at);

-- Loader sessions indexes
CREATE INDEX IF NOT EXISTS idx_loader_sessions_token ON loader_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_loader_sessions_script ON loader_sessions(script_id);
CREATE INDEX IF NOT EXISTS idx_loader_sessions_expires ON loader_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_loader_sessions_stage ON loader_sessions(stage);

-- Script access logs indexes
CREATE INDEX IF NOT EXISTS idx_access_logs_script ON script_access_logs(script_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_user ON script_access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_created ON script_access_logs(created_at);

-- ============================================
-- TRIGGER: Tự động cập nhật updated_at cho users
-- ============================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- TRIGGER: Tự động cập nhật updated_at cho scripts
-- ============================================
DROP TRIGGER IF EXISTS update_scripts_updated_at ON scripts;
CREATE TRIGGER update_scripts_updated_at
    BEFORE UPDATE ON scripts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- CLEANUP FUNCTION: Xóa sessions hết hạn
-- ============================================
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    -- Xóa login sessions hết hạn
    DELETE FROM login_sessions 
    WHERE expires_at IS NOT NULL 
    AND expires_at <= NOW();
    
    -- Xóa loader sessions hết hạn
    DELETE FROM loader_sessions 
    WHERE expires_at <= NOW();
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- VIEW: Thống kê scripts theo user
-- ============================================
CREATE OR REPLACE VIEW v_user_script_stats AS
SELECT 
    u.id AS user_id,
    u.username,
    COUNT(s.id) AS total_scripts,
    COUNT(CASE WHEN s.enabled = TRUE THEN 1 END) AS enabled_scripts,
    COUNT(CASE WHEN s.enabled = FALSE THEN 1 END) AS disabled_scripts,
    MAX(s.created_at) AS last_script_created,
    MAX(s.updated_at) AS last_script_updated
FROM users u
LEFT JOIN scripts s ON s.user_id = u.id
GROUP BY u.id, u.username;

-- ============================================
-- VIEW: Thống kê access logs
-- ============================================
CREATE OR REPLACE VIEW v_script_access_stats AS
SELECT 
    s.script_id,
    s.name,
    s.user_id,
    u.username,
    COUNT(l.id) AS total_access,
    COUNT(CASE WHEN l.success = TRUE THEN 1 END) AS successful_access,
    COUNT(CASE WHEN l.success = FALSE THEN 1 END) AS failed_access,
    MAX(l.created_at) AS last_access
FROM scripts s
LEFT JOIN script_access_logs l ON l.script_id = s.script_id
LEFT JOIN users u ON u.id = s.user_id
GROUP BY s.script_id, s.name, s.user_id, u.username;

-- ============================================
-- GRANT PERMISSIONS (nếu cần)
-- ============================================
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO your_user;
-- GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO your_user;

-- ============================================
-- CHECK TABLES
-- ============================================
SELECT 
    table_name,
    table_type
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

-- ============================================
-- CHECK INDEXES
-- ============================================
SELECT 
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename, indexname;

-- ============================================
-- SAMPLE DATA (OPTIONAL - CÓ THỂ BỎ QUA)
-- ============================================
-- Thêm user mẫu
-- INSERT INTO users (username, password_hash) 
-- VALUES ('admin', 'hashed_password_here');

-- ============================================
-- MAINTENANCE QUERIES
-- ============================================

-- Xóa tất cả sessions hết hạn ngay lập tức
-- SELECT cleanup_expired_sessions();

-- Xem thống kê users
-- SELECT * FROM v_user_script_stats;

-- Xem thống kê access
-- SELECT * FROM v_script_access_stats;

-- Xóa toàn bộ dữ liệu (CẨN THẬN!)
-- TRUNCATE TABLE script_access_logs CASCADE;
-- TRUNCATE TABLE loader_sessions CASCADE;
-- TRUNCATE TABLE login_sessions CASCADE;
-- TRUNCATE TABLE scripts CASCADE;
-- TRUNCATE TABLE users CASCADE;
