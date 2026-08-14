const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const rateLimit = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN || "https://Lexinx-protect-2.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SCRIPTS_FILE = path.join(DATA_DIR, "scripts.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const BLACKLIST_FILE = path.join(DATA_DIR, "blacklist.json");
const ACCESS_LOG_FILE = path.join(DATA_DIR, "access_log.json");

const ONE_TIME_CODES = new Set([
    "LEXINX_6725YE7726d622",
    "LEXINX_8837yYe7726722"
]);

const PERMANENT_CODE = "LEXINX_King_2036";

// Danh sách User-Agent đáng ngờ
const SUSPICIOUS_UA = [
    "python",
    "curl",
    "wget",
    "postman",
    "node-fetch",
    "axios",
    "okhttp",
    "libwww",
    "scrapy",
    "bot",
    "spider",
    "crawler"
];

// Danh sách IP bị chặn vĩnh viễn
const BLOCKED_IPS = new Set();

// Cấu hình bảo mật nâng cao
const SECURITY_CONFIG = {
    maxRequestsPerMinute: 30, // Giới hạn request/phút
    maxFailedLogins: 5, // Số lần đăng nhập sai tối đa
    blockDuration: 30 * 60 * 1000, // Thời gian block (30 phút)
    sessionTimeout: 30 * 24 * 60 * 60 * 1000, // Session timeout (30 ngày)
    maxScriptSize: 10 * 1024 * 1024, // 10MB max script size
    honeypotEnabled: true, // Bật honeypot
    encryptionEnabled: true // Bật mã hóa source
};

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

function initFile(file) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, "{}", "utf8");
    }
}

initFile(USERS_FILE);
initFile(SCRIPTS_FILE);
initFile(SESSIONS_FILE);
initFile(BLACKLIST_FILE);
initFile(ACCESS_LOG_FILE);

// Rate limiting cho API
const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 phút
    max: SECURITY_CONFIG.maxRequestsPerMinute,
    message: {
        ok: false,
        error: "Too many requests, please try again later"
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Rate limiting cho delivery endpoint (chống bot tải source)
const deliveryLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10, // Chỉ cho phép 10 requests/phút cho delivery
    message: "Blocked by LEXINX",
    standardHeaders: false,
    legacyHeaders: false
});

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(express.static(PUBLIC_DIR));

function readDB(file) {
    try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
        return {};
    }
}

function writeDB(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

function randomID(bytes = 16) {
    return crypto.randomBytes(bytes).toString("hex");
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString("hex");
}

function checkPassword(password, salt, hash) {
    try {
        const a = Buffer.from(hashPassword(password, salt), "hex");
        const b = Buffer.from(hash, "hex");
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

// Mã hóa source code với AES-256-GCM
function encryptSource(source, key) {
    if (!SECURITY_CONFIG.encryptionEnabled) return source;
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(key, "hex"), iv);
    
    let encrypted = cipher.update(source, "utf8", "hex");
    encrypted += cipher.final("hex");
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
        iv: iv.toString("hex"),
        data: encrypted,
        tag: authTag.toString("hex"),
        algorithm: "aes-256-gcm"
    });
}

function decryptSource(encryptedData, key) {
    if (!SECURITY_CONFIG.encryptionEnabled) return encryptedData;
    
    try {
        const parsed = JSON.parse(encryptedData);
        const decipher = crypto.createDecipheriv(
            "aes-256-gcm",
            Buffer.from(key, "hex"),
            Buffer.from(parsed.iv, "hex")
        );
        
        decipher.setAuthTag(Buffer.from(parsed.tag, "hex"));
        
        let decrypted = decipher.update(parsed.data, "hex", "utf8");
        decrypted += decipher.final("utf8");
        
        return decrypted;
    } catch {
        return null;
    }
}

// Tạo key mã hóa từ user ID
function getEncryptionKey(userId) {
    return crypto.createHash("sha256").update(userId).digest("hex");
}

/* =========================================================
   COOKIE
========================================================= */

function cookies(req) {
    const result = {};
    for (const item of String(req.headers.cookie || "").split(";")) {
        const i = item.indexOf("=");
        if (i === -1) continue;
        result[item.slice(0, i).trim()] = decodeURIComponent(item.slice(i + 1).trim());
    }
    return result;
}

/* =========================================================
   SESSION MANAGEMENT NÂNG CAO
========================================================= */

function session(req) {
    const token = cookies(req).LEXINX_SESSION;
    if (!token) return null;

    const sessions = readDB(SESSIONS_FILE);
    const s = sessions[token];
    if (!s) return null;

    // Kiểm tra IP matching (chống session hijacking)
    const clientIP = getClientIP(req);
    if (s.ip !== clientIP) {
        delete sessions[token];
        writeDB(SESSIONS_FILE, sessions);
        return null;
    }

    // Kiểm tra user agent matching
    const userAgent = req.headers["user-agent"] || "";
    if (s.userAgent !== userAgent) {
        delete sessions[token];
        writeDB(SESSIONS_FILE, sessions);
        return null;
    }

    if (Date.now() - s.createdAt > SECURITY_CONFIG.sessionTimeout) {
        delete sessions[token];
        writeDB(SESSIONS_FILE, sessions);
        return null;
    }

    const users = readDB(USERS_FILE);
    if (!users[s.username]) return null;

    return {
        token,
        username: s.username,
        user: users[s.username]
    };
}

function auth(req, res, next) {
    const s = session(req);
    if (!s) {
        return res.status(401).json({ ok: false, error: "Unauthorized" });
    }
    req.auth = s;
    next();
}

/* =========================================================
   IP MANAGEMENT
========================================================= */

function getClientIP(req) {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) {
        return forwarded.split(",")[0].trim();
    }
    return req.connection.remoteAddress || req.socket.remoteAddress;
}

function isIPBlocked(ip) {
    if (BLOCKED_IPS.has(ip)) return true;
    
    const blacklist = readDB(BLACKLIST_FILE);
    const entry = blacklist[ip];
    
    if (entry && entry.expiresAt > Date.now()) {
        return true;
    }
    
    if (entry && entry.expiresAt <= Date.now()) {
        delete blacklist[ip];
        writeDB(BLACKLIST_FILE, blacklist);
    }
    
    return false;
}

function blockIP(ip, duration = SECURITY_CONFIG.blockDuration) {
    BLOCKED_IPS.add(ip);
    
    const blacklist = readDB(BLACKLIST_FILE);
    blacklist[ip] = {
        blockedAt: Date.now(),
        expiresAt: Date.now() + duration
    };
    writeDB(BLACKLIST_FILE, blacklist);
    
    setTimeout(() => {
        BLOCKED_IPS.delete(ip);
    }, duration);
}

/* =========================================================
   ACCESS LOGGING
========================================================= */

function logAccess(req, action, details = {}) {
    const accessLog = readDB(ACCESS_LOG_FILE);
    const today = new Date().toISOString().split("T")[0];
    
    if (!accessLog[today]) {
        accessLog[today] = [];
    }
    
    accessLog[today].push({
        timestamp: Date.now(),
        ip: getClientIP(req),
        userAgent: req.headers["user-agent"],
        action,
        details,
        path: req.path
    });
    
    // Giới hạn log size
    if (accessLog[today].length > 10000) {
        accessLog[today] = accessLog[today].slice(-10000);
    }
    
    writeDB(ACCESS_LOG_FILE, accessLog);
}

/* =========================================================
   BOT DETECTION NÂNG CAO
========================================================= */

function isBotRequest(req) {
    const ua = String(req.headers["user-agent"] || "").toLowerCase();
    const accept = String(req.headers["accept"] || "").toLowerCase();
    const clientIP = getClientIP(req);
    
    // 1. Kiểm tra IP bị block
    if (isIPBlocked(clientIP)) {
        return true;
    }
    
    // 2. Kiểm tra User-Agent đáng ngờ
    for (const suspiciousUA of SUSPICIOUS_UA) {
        if (ua.includes(suspiciousUA)) {
            logAccess(req, "blocked_suspicious_ua", { reason: suspiciousUA });
            return true;
        }
    }
    
    // 3. Kiểm tra browser fingerprint
    if (ua.includes("mozilla") && accept.includes("text/html")) {
        // Có vẻ là browser thật, nhưng kiểm tra thêm
        const secFetchSite = req.headers["sec-fetch-site"];
        const secFetchMode = req.headers["sec-fetch-mode"];
        
        if (!secFetchSite || !secFetchMode) {
            // Thiếu header bảo mật của browser hiện đại
            logAccess(req, "blocked_missing_headers");
            return true;
        }
        
        return false;
    }
    
    // 4. Roblox User-Agent thường không có Mozilla
    if (ua.includes("roblox") || ua.includes("RobloxStudio")) {
        return false;
    }
    
    // 5. Mặc định block các request không xác định
    logAccess(req, "blocked_unknown_ua");
    return true;
}

function browserRequest(req) {
    const ua = String(req.headers["user-agent"] || "").toLowerCase();
    const accept = String(req.headers["accept"] || "").toLowerCase();
    
    if (
        ua.includes("mozilla") &&
        (accept.includes("text/html") || accept.includes("application/xhtml"))
    ) {
        return true;
    }
    
    return false;
}

/* =========================================================
   HONEYPOT SYSTEM
========================================================= */

function setupHoneypot() {
    // Tạo endpoint giả để bẫy bot
    app.get("/api/scripts/:id/source", (req, res) => {
        logAccess(req, "honeypot_triggered", { honeypot: "fake_source_endpoint" });
        res.status(403).send("Blocked by LEXINX");
    });
    
    app.get("/scripts/:id", (req, res) => {
        logAccess(req, "honeypot_triggered", { honeypot: "fake_scripts_path" });
        res.status(403).send("Blocked by LEXINX");
    });
    
    app.post("/api/execute", (req, res) => {
        logAccess(req, "honeypot_triggered", { honeypot: "fake_execute_endpoint" });
        res.status(403).json({ ok: false, error: "Blocked by LEXINX" });
    });
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    if (isBotRequest(req)) {
        return res.status(403).send("Access Denied");
    }
    
    res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", apiLimiter, (req, res) => {
    const clientIP = getClientIP(req);
    
    if (isIPBlocked(clientIP)) {
        return res.status(403).json({ ok: false, error: "IP blocked" });
    }
    
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const code = String(req.body?.code || "").trim();
    
    // Honeypot field
    if (req.body?.website || req.body?.email_confirm) {
        logAccess(req, "honeypot_triggered", { honeypot: "register_form" });
        return res.status(403).json({ ok: false, error: "Bot detected" });
    }
    
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
        return res.status(400).json({ ok: false, error: "Invalid username" });
    }
    
    if (password.length < 8) {
        return res.status(400).json({
            ok: false,
            error: "Password must contain at least 8 characters"
        });
    }
    
    const users = readDB(USERS_FILE);
    
    if (users[username]) {
        return res.status(409).json({ ok: false, error: "Username already exists" });
    }
    
    let accessType;
    
    if (code === PERMANENT_CODE) {
        accessType = "permanent";
    } else if (ONE_TIME_CODES.has(code)) {
        accessType = "one-time";
    } else {
        return res.status(403).json({ ok: false, error: "Invalid access code" });
    }
    
    if (accessType === "one-time") {
        ONE_TIME_CODES.delete(code);
    }
    
    const salt = crypto.randomBytes(32).toString("hex");
    
    users[username] = {
        username,
        salt,
        passwordHash: hashPassword(password, salt),
        accessType,
        createdAt: Date.now(),
        scripts: [],
        failedLogins: 0
    };
    
    writeDB(USERS_FILE, users);
    
    const token = randomID(48);
    const sessions = readDB(SESSIONS_FILE);
    
    sessions[token] = {
        username,
        createdAt: Date.now(),
        ip: clientIP,
        userAgent: req.headers["user-agent"] || ""
    };
    
    writeDB(SESSIONS_FILE, sessions);
    
    logAccess(req, "register_success", { username });
    
    res.setHeader(
        "Set-Cookie",
        `LEXINX_SESSION=${token}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${SECURITY_CONFIG.sessionTimeout / 1000}`
    );
    
    res.json({ ok: true, username, accessType });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", apiLimiter, (req, res) => {
    const clientIP = getClientIP(req);
    
    if (isIPBlocked(clientIP)) {
        return res.status(403).json({ ok: false, error: "IP blocked" });
    }
    
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    
    const users = readDB(USERS_FILE);
    const user = users[username];
    
    if (!user || !checkPassword(password, user.salt, user.passwordHash)) {
        // Tăng counter failed login
        if (user) {
            user.failedLogins = (user.failedLogins || 0) + 1;
            users[username] = user;
            writeDB(USERS_FILE, users);
            
            if (user.failedLogins >= SECURITY_CONFIG.maxFailedLogins) {
                blockIP(clientIP);
                user.failedLogins = 0;
                users[username] = user;
                writeDB(USERS_FILE, users);
                
                logAccess(req, "ip_blocked", { reason: "too_many_failed_logins" });
                return res.status(403).json({ ok: false, error: "IP blocked due to too many failed attempts" });
            }
        }
        
        logAccess(req, "login_failed", { username });
        return res.status(401).json({ ok: false, error: "Invalid username or password" });
    }
    
    // Reset failed logins
    user.failedLogins = 0;
    users[username] = user;
    writeDB(USERS_FILE, users);
    
    const token = randomID(48);
    const sessions = readDB(SESSIONS_FILE);
    
    sessions[token] = {
        username,
        createdAt: Date.now(),
        ip: clientIP,
        userAgent: req.headers["user-agent"] || ""
    };
    
    writeDB(SESSIONS_FILE, sessions);
    
    logAccess(req, "login_success", { username });
    
    res.setHeader(
        "Set-Cookie",
        `LEXINX_SESSION=${token}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${SECURITY_CONFIG.sessionTimeout / 1000}`
    );
    
    res.json({ ok: true, username, accessType: user.accessType });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
    const token = cookies(req).LEXINX_SESSION;
    
    if (token) {
        const sessions = readDB(SESSIONS_FILE);
        delete sessions[token];
        writeDB(SESSIONS_FILE, sessions);
    }
    
    res.setHeader(
        "Set-Cookie",
        "LEXINX_SESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure"
    );
    
    res.json({ ok: true });
});

/* =========================================================
   ME
========================================================= */

app.get("/api/me", auth, (req, res) => {
    res.json({
        ok: true,
        username: req.auth.user.username,
        accessType: req.auth.user.accessType,
        scriptCount: req.auth.user.scripts.length
    });
});

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post("/api/create", auth, apiLimiter, (req, res) => {
    const source = typeof req.body?.source === "string" ? req.body.source : "";
    
    if (!source.trim()) {
        return res.status(400).json({ ok: false, error: "Script is empty" });
    }
    
    if (source.length > SECURITY_CONFIG.maxScriptSize) {
        return res.status(400).json({ ok: false, error: "Script too large" });
    }
    
    const name = cleanName(req.body?.name);
    const id = randomID(16);
    const token = randomID(32);
    
    // Mã hóa source
    const encryptionKey = getEncryptionKey(req.auth.username);
    const encryptedSource = encryptSource(source, encryptionKey);
    
    const scripts = readDB(SCRIPTS_FILE);
    
    scripts[id] = {
        id,
        token,
        name,
        source: encryptedSource,
        encrypted: true,
        owner: req.auth.username,
        createdAt: Date.now(),
        updatedAt: Date.now()
    };
    
    writeDB(SCRIPTS_FILE, scripts);
    
    const users = readDB(USERS_FILE);
    users[req.auth.username].scripts.push(id);
    writeDB(USERS_FILE, users);
    
    const endpoint = `${DOMAIN}/api/${id}/${token}`;
    
    logAccess(req, "script_created", { scriptId: id, scriptName: name });
    
    res.json({
        ok: true,
        id,
        name,
        endpoint,
        loader: `loadstring(game:HttpGet("${endpoint}"))()`
    });
});

/* =========================================================
   LIST SCRIPTS
========================================================= */

app.get("/api/scripts", auth, (req, res) => {
    const scripts = readDB(SCRIPTS_FILE);
    
    const list = req.auth.user.scripts
        .map(id => scripts[id])
        .filter(Boolean)
        .map(s => {
            const endpoint = `${DOMAIN}/api/${s.id}/${s.token}`;
            
            return {
                id: s.id,
                name: s.name,
                createdAt: s.createdAt,
                updatedAt: s.updatedAt,
                endpoint,
                loader: `loadstring(game:HttpGet("${endpoint}"))()`
            };
        })
        .reverse();
    
    res.json({ ok: true, scripts: list });
});

/* =========================================================
   GET SCRIPT FOR EDIT
========================================================= */

app.get("/api/scripts/:id", auth, (req, res) => {
    const scripts = readDB(SCRIPTS_FILE);
    const script = scripts[req.params.id];
    
    if (!script) {
        return res.status(404).json({ ok: false, error: "Script not found" });
    }
    
    if (script.owner !== req.auth.username) {
        return res.status(403).json({ ok: false, error: "Forbidden" });
    }
    
    // Giải mã source để edit
    let source = script.source;
    if (script.encrypted) {
        const encryptionKey = getEncryptionKey(req.auth.username);
        source = decryptSource(script.source, encryptionKey);
    }
    
    res.json({
        ok: true,
        script: {
            id: script.id,
            name: script.name,
            source: source,
            createdAt: script.createdAt,
            updatedAt: script.updatedAt
        }
    });
});

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put("/api/scripts/:id", auth, apiLimiter, (req, res) => {
    const scripts = readDB(SCRIPTS_FILE);
    const script = scripts[req.params.id];
    
    if (!script) {
        return res.status(404).json({ ok: false, error: "Script not found" });
    }
    
    if (script.owner !== req.auth.username) {
        return res.status(403).json({ ok: false, error: "Forbidden" });
    }
    
    const source = typeof req.body?.source === "string" ? req.body.source : "";
    
    if (!source.trim()) {
        return res.status(400).json({ ok: false, error: "Script is empty" });
    }
    
    if (source.length > SECURITY_CONFIG.maxScriptSize) {
        return res.status(400).json({ ok: false, error: "Script too large" });
    }
    
    script.name = cleanName(req.body?.name || script.name);
    
    // Mã hóa source mới
    const encryptionKey = getEncryptionKey(req.auth.username);
    script.source = encryptSource(source, encryptionKey);
    script.encrypted = true;
    script.updatedAt = Date.now();
    
    scripts[script.id] = script;
    writeDB(SCRIPTS_FILE, scripts);
    
    const endpoint = `${DOMAIN}/api/${script.id}/${script.token}`;
    
    logAccess(req, "script_updated", { scriptId: script.id });
    
    res.json({
        ok: true,
        id: script.id,
        name: script.name,
        endpoint,
        loader: `loadstring(game:HttpGet("${endpoint}"))()`
    });
});

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete("/api/scripts/:id", auth, (req, res) => {
    const scripts = readDB(SCRIPTS_FILE);
    const script = scripts[req.params.id];
    
    if (!script) {
        return res.status(404).json({ ok: false, error: "Script not found" });
    }
    
    if (script.owner !== req.auth.username) {
        return res.status(403).json({ ok: false, error: "Forbidden" });
    }
    
    delete scripts[req.params.id];
    writeDB(SCRIPTS_FILE, scripts);
    
    const users = readDB(USERS_FILE);
    users[req.auth.username].scripts = users[req.auth.username].scripts.filter(
        id => id !== req.params.id
    );
    writeDB(USERS_FILE, users);
    
    logAccess(req, "script_deleted", { scriptId: req.params.id });
    
    res.json({ ok: true });
});

/* =========================================================
   LUA DELIVERY - BẢO VỆ TỐI ĐA
========================================================= */

app.get("/api/:id/:token", deliveryLimiter, (req, res) => {
    const clientIP = getClientIP(req);
    
    // 1. Kiểm tra IP block
    if (isIPBlocked(clientIP)) {
        logAccess(req, "delivery_blocked", { reason: "ip_blocked" });
        return res.status(403).type("text/plain").send("Blocked by LEXINX");
    }
    
    // 2. Kiểm tra bot
    if (browserRequest(req)) {
        logAccess(req, "delivery_blocked", { reason: "browser_request" });
        return res.status(403).type("text/plain").send("BLOCKED BY LEXINX");
    }
    
    // 3. Kiểm tra User-Agent
    const ua = String(req.headers["user-agent"] || "").toLowerCase();
    if (!ua.includes("roblox") && !ua.includes("RobloxStudio")) {
        logAccess(req, "delivery_blocked", { reason: "invalid_ua", userAgent: ua });
        return res.status(403).type("text/plain").send("Blocked by LEXINX");
    }
    
    // 4. Kiểm tra script tồn tại
    const scripts = readDB(SCRIPTS_FILE);
    const script = scripts[req.params.id];
    
    if (!script) {
        logAccess(req, "delivery_blocked", { reason: "script_not_found" });
        return res.status(404).type("text/plain").send("Blocked by LEXINX v50 protection");
    }
    
    // 5. Kiểm tra token
    if (req.params.token !== script.token) {
        logAccess(req, "delivery_blocked", { reason: "invalid_token" });
        return res.status(403).type("text/plain").send("Blocked by LEXINX");
    }
    
    // 6. Giải mã source
    let source = script.source;
    if (script.encrypted) {
        const encryptionKey = getEncryptionKey(script.owner);
        source = decryptSource(script.source, encryptionKey);
        
        if (source === null) {
            logAccess(req, "delivery_blocked", { reason: "decryption_failed" });
            return res.status(500).type("text/plain").send("Blocked by LEXINX");
        }
    }
    
    // 7. Log access thành công
    logAccess(req, "delivery_success", { scriptId: script.id });
    
    // 8. Trả về source với security headers
    res.status(200)
        .type("text/plain")
        .set("Cache-Control", "no-store, no-cache, must-revalidate, private")
        .set("Pragma", "no-cache")
        .set("Expires", "0")
        .set("X-Content-Type-Options", "nosniff")
        .set("X-Frame-Options", "DENY")
        .set("X-XSS-Protection", "1; mode=block")
        .set("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        .set("Referrer-Policy", "no-referrer")
        .set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=(), vibrate=(), fullscreen=(), payment=()")
        .send(source);
});

/* =========================================================
   ADMIN ENDPOINTS (Bảo vệ source)
========================================================= */

app.get("/api/admin/stats", auth, (req, res) => {
    if (req.auth.user.accessType !== "permanent") {
        return res.status(403).json({ ok: false, error: "Forbidden" });
    }
    
    const accessLog = readDB(ACCESS_LOG_FILE);
    const today = new Date().toISOString().split("T")[0];
    const todayLog = accessLog[today] || [];
    
    const stats = {
        totalRequests: todayLog.length,
        blockedRequests: todayLog.filter(log => log.action.startsWith("blocked") || log.action === "honeypot_triggered").length,
        successfulDeliveries: todayLog.filter(log => log.action === "delivery_success").length,
        uniqueIPs: new Set(todayLog.map(log => log.ip)).size,
        blockedIPs: Object.keys(readDB(BLACKLIST_FILE)).length
    };
    
    res.json({ ok: true, stats });
});

/* =========================================================
   404 HANDLER
========================================================= */

app.use((req, res) => {
    const clientIP = getClientIP(req);
    
    if (isBotRequest(req)) {
        logAccess(req, "blocked_404", { path: req.path });
        return res.status(403).type("text/plain").send("Blocked by LEXINX");
    }
    
    res.status(404).type("text/plain").send("Blocked by LEXINX v50 protection");
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
    console.error("Error:", err);
    logAccess(req, "server_error", { error: err.message });
    
    res.status(500).json({ ok: false, error: "Internal server error" });
});

/* =========================================================
   INITIALIZE SECURITY
========================================================= */

// Setup honeypot system
if (SECURITY_CONFIG.honeypotEnabled) {
    setupHoneypot();
}

// Cleanup expired sessions mỗi 24 giờ
setInterval(() => {
    const sessions = readDB(SESSIONS_FILE);
    const now = Date.now();
    
    for (const token in sessions) {
        if (now - sessions[token].createdAt > SECURITY_CONFIG.sessionTimeout) {
            delete sessions[token];
        }
    }
    
    writeDB(SESSIONS_FILE, sessions);
}, 24 * 60 * 60 * 1000);

/* =========================================================
   START SERVER
========================================================= */

app.listen(PORT, "0.0.0.0", () => {
    console.log("=".repeat(50));
    console.log("🛡️  LEXINX PROTECT v50 - ULTIMATE SECURITY");
    console.log("=".repeat(50));
    console.log("✅ Server running on port:", PORT);
    console.log("🌐 Domain:", DOMAIN);
    console.log("🔒 Encryption:", SECURITY_CONFIG.encryptionEnabled ? "ENABLED" : "DISABLED");
    console.log("🕵️  Honeypot:", SECURITY_CONFIG.honeypotEnabled ? "ENABLED" : "DISABLED");
    console.log("⚡ Rate Limit:", SECURITY_CONFIG.maxRequestsPerMinute, "requests/min");
    console.log("=".repeat(50));
});
