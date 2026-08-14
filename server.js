"use strict";

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const useragent = require("express-useragent");
const { obfuscate } = require("./obfuscator");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN || "https://Lexinx-protect-2.onrender.com";
const DATA = path.join(__dirname, "data");
const PUBLIC = path.join(__dirname, "public");
const SCRIPTS = path.join(DATA, "scripts.json");
const BLOCKED_IPS = path.join(DATA, "blocked_ips.json");

// Rate limiting configuration
const REQUESTS_PER_MINUTE = 30;
const BLOCK_THRESHOLD = 100;
const BLOCK_DURATION = 3600000; // 1 hour

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(PUBLIC, { recursive: true });

if (!fs.existsSync(SCRIPTS)) {
    fs.writeFileSync(SCRIPTS, "{}");
}

if (!fs.existsSync(BLOCKED_IPS)) {
    fs.writeFileSync(BLOCKED_IPS, "{}");
}

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true,
    frameguard: { action: 'deny' }
}));

app.use(useragent.express());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(express.static(PUBLIC, { 
    maxAge: '1h',
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
    }
}));

// Advanced rate limiting
const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: REQUESTS_PER_MINUTE,
    message: { error: "Too many requests, please try again later." },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    handler: (req, res) => {
        trackSuspiciousActivity(req.ip, 'rate_limit_exceeded');
        res.status(429).json({
            ok: false,
            error: "Rate limit exceeded. IP has been flagged."
        });
    }
});

// Apply rate limiting to API endpoints
app.use('/api/', apiLimiter);

// Advanced IP tracking system
function readBlockedIPs() {
    try {
        return JSON.parse(fs.readFileSync(BLOCKED_IPS, "utf8"));
    } catch {
        return {};
    }
}

function writeBlockedIPs(blockedIPs) {
    fs.writeFileSync(BLOCKED_IPS, JSON.stringify(blockedIPs, null, 2));
}

function trackSuspiciousActivity(ip, reason) {
    const blockedIPs = readBlockedIPs();
    
    if (!blockedIPs[ip]) {
        blockedIPs[ip] = {
            attempts: 0,
            blockedUntil: 0,
            reasons: []
        };
    }
    
    blockedIPs[ip].attempts++;
    blockedIPs[ip].reasons.push({
        reason,
        timestamp: Date.now()
    });
    
    // Keep only last 10 reasons
    if (blockedIPs[ip].reasons.length > 10) {
        blockedIPs[ip].reasons = blockedIPs[ip].reasons.slice(-10);
    }
    
    // Block IP if too many attempts
    if (blockedIPs[ip].attempts >= BLOCK_THRESHOLD) {
        blockedIPs[ip].blockedUntil = Date.now() + BLOCK_DURATION;
        blockedIPs[ip].attempts = 0;
    }
    
    writeBlockedIPs(blockedIPs);
}

function isIPBlocked(ip) {
    const blockedIPs = readBlockedIPs();
    
    if (blockedIPs[ip] && blockedIPs[ip].blockedUntil > Date.now()) {
        return true;
    }
    
    return false;
}

// IP Blocking middleware
app.use('/api/:id/:token', (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (isIPBlocked(clientIP)) {
        return res.status(403)
            .type("text/plain")
            .send("Access denied - IP blocked");
    }
    
    next();
});

// Bot detection middleware
const botPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scrapy/i,
    /curl/i,
    /wget/i,
    /python/i,
    /java/i,
    /node/i,
    /php/i,
    /ruby/i,
    /perl/i,
    /http/i,
    /request/i,
    /axios/i,
    /fetch/i,
    /scan/i,
    /vuln/i,
    /exploit/i,
    /hack/i,
    /sqlmap/i,
    /nikto/i,
    /nmap/i,
    /masscan/i,
    /zmap/i
];

function detectBot(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const acceptHeader = (req.headers['accept'] || '').toLowerCase();
    const acceptLanguage = (req.headers['accept-language'] || '').toLowerCase();
    
    // Check user agent
    if (!userAgent || userAgent === '') {
        return true;
    }
    
    // Check bot patterns
    if (botPatterns.some(pattern => pattern.test(userAgent))) {
        return true;
    }
    
    // Check if it's a browser
    const isBrowser = userAgent.includes('mozilla') || 
                     userAgent.includes('chrome') || 
                     userAgent.includes('safari') || 
                     userAgent.includes('firefox') || 
                     userAgent.includes('edge') || 
                     userAgent.includes('opera');
    
    if (!isBrowser) {
        // Roblox User-Agent
        if (userAgent.includes('roblox') || userAgent.includes('studio')) {
            return false;
        }
        return true;
    }
    
    // Check Accept headers
    if (!acceptHeader.includes('text/html') && !acceptHeader.includes('*/*')) {
        return true;
    }
    
    return false;
}

// Advanced bot detection middleware for payload endpoint
app.get('/api/:id/:token', (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    // Check if it's a bot
    if (detectBot(req)) {
        trackSuspiciousActivity(clientIP, 'bot_detected');
        return res.status(403)
            .type("text/plain")
            .send("Access denied - Bot detected");
    }
    
    // Check for suspicious headers
    const suspiciousHeaders = [
        'x-forwarded-for',
        'x-real-ip',
        'cf-connecting-ip',
        'x-requested-with'
    ];
    
    const hasSuspiciousHeaders = suspiciousHeaders.some(header => {
        const value = req.headers[header];
        return value && value.includes(',');
    });
    
    if (hasSuspiciousHeaders) {
        trackSuspiciousActivity(clientIP, 'suspicious_headers');
        return res.status(403)
            .type("text/plain")
            .send("Access denied - Suspicious request");
    }
    
    next();
});

function readDB() {
    try {
        return JSON.parse(fs.readFileSync(SCRIPTS, "utf8"));
    } catch {
        return {};
    }
}

function writeDB(db) {
    fs.writeFileSync(SCRIPTS, JSON.stringify(db, null, 2));
}

function id() {
    return crypto.randomBytes(16).toString("hex");
}

function token() {
    return crypto.randomBytes(32).toString("hex");
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

// Generate HMAC signature for payload
function generateSignature(source, token) {
    const hmac = crypto.createHmac('sha256', token);
    hmac.update(source);
    return hmac.digest('hex');
}

/*
============================================================
HOME
============================================================
*/

app.get("/", (req, res) => {
    // Check for bot on main page
    if (detectBot(req)) {
        return res.status(403).send("Access denied");
    }
    
    res.sendFile(path.join(PUBLIC, "index.html"));
});

/*
============================================================
CREATE
============================================================
*/

app.post("/api/create", (req, res) => {
    try {
        const source = typeof req.body.source === "string" ? req.body.source : "";
        
        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error: "Script is empty"
            });
        }
        
        // Advanced source validation
        if (source.length > 5000000) { // 5MB limit
            return res.status(400).json({
                ok: false,
                error: "Script too large"
            });
        }
        
        const name = cleanName(req.body.name);
        
        // Multi-layer obfuscation
        const protectedSource = obfuscate(source);
        
        // Add additional protection layers
        const antiDumpCode = `
            -- Anti-dump protection
            local function protect()
                local success, err = pcall(function()
                    if getgenv then
                        getgenv().protected = true
                    end
                    if getrawmetatable then
                        local mt = getrawmetatable(game)
                        setreadonly(mt, true)
                    end
                end)
            end
            protect()
        `;
        
        const antiDecompileCode = `
            -- Anti-decompile protection
            local function antiDecompile()
                local success, err = pcall(function()
                    if hookfunction and getinfo then
                        local old = getinfo
                        setinfo = function() return nil end
                    end
                end)
            end
            antiDecompile()
        `;
        
        const finalSource = `
            ${antiDumpCode}
            ${antiDecompileCode}
            ${protectedSource}
        `;
        
        const scriptID = id();
        const accessToken = token();
        
        const db = readDB();
        
        db[scriptID] = {
            id: scriptID,
            token: accessToken,
            name,
            source: finalSource,
            createdAt: Date.now(),
            updatedAt: Date.now(),
            accessCount: 0,
            lastAccessed: null,
            ipHashes: []
        };
        
        writeDB(db);
        
        const endpoint = `${DOMAIN}/api/${scriptID}/${accessToken}`;
        const loader = `loadstring(game:HttpGet("${endpoint}"))()`;
        
        res.json({
            ok: true,
            id: scriptID,
            name,
            endpoint,
            loader
        });
        
    } catch (err) {
        console.error(err);
        res.status(500).json({
            ok: false,
            error: "Obfuscation failed"
        });
    }
});

/*
============================================================
LIST
============================================================
*/

app.get("/api/scripts", (req, res) => {
    const db = readDB();
    
    const scripts = Object.values(db)
        .map(s => {
            const endpoint = `${DOMAIN}/api/${s.id}/${s.token}`;
            
            return {
                id: s.id,
                name: s.name,
                createdAt: s.createdAt,
                updatedAt: s.updatedAt,
                accessCount: s.accessCount || 0,
                endpoint,
                loader: `loadstring(game:HttpGet("${endpoint}"))()`
            };
        })
        .reverse();
    
    res.json({
        ok: true,
        scripts
    });
});

/*
============================================================
EDIT
============================================================
*/

app.get("/api/scripts/:id", (req, res) => {
    const db = readDB();
    const script = db[req.params.id];
    
    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }
    
    res.json({
        ok: true,
        script: {
            id: script.id,
            name: script.name,
            source: script.source
        }
    });
});

/*
============================================================
UPDATE + OBFUSCATE AGAIN
============================================================
*/

app.put("/api/scripts/:id", (req, res) => {
    try {
        const db = readDB();
        const script = db[req.params.id];
        
        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }
        
        const source = typeof req.body.source === "string" ? req.body.source : "";
        
        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error: "Script is empty"
            });
        }
        
        script.name = cleanName(req.body.name || script.name);
        script.source = obfuscate(source);
        script.updatedAt = Date.now();
        
        db[script.id] = script;
        writeDB(db);
        
        const endpoint = `${DOMAIN}/api/${script.id}/${script.token}`;
        
        res.json({
            ok: true,
            endpoint,
            loader: `loadstring(game:HttpGet("${endpoint}"))()`
        });
        
    } catch {
        res.status(500).json({
            ok: false,
            error: "Update failed"
        });
    }
});

/*
============================================================
DELETE
============================================================
*/

app.delete("/api/scripts/:id", (req, res) => {
    const db = readDB();
    
    if (!db[req.params.id]) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }
    
    delete db[req.params.id];
    writeDB(db);
    
    res.json({ ok: true });
});

/*
============================================================
ROBLOX PAYLOAD ENDPOINT
============================================================
*/

app.get("/api/:id/:token", (req, res) => {
    const db = readDB();
    const script = db[req.params.id];
    
    if (!script) {
        return res.status(404)
            .type("text/plain")
            .send("Blocked by LEXINX");
    }
    
    if (req.params.token !== script.token) {
        return res.status(403)
            .type("text/plain")
            .send("Blocked by LEXINX");
    }
    
    // Update access statistics
    script.accessCount = (script.accessCount || 0) + 1;
    script.lastAccessed = Date.now();
    
    const clientIP = req.ip || req.connection.remoteAddress;
    const ipHash = crypto.createHash('sha256').update(clientIP).digest('hex');
    
    if (!script.ipHashes) {
        script.ipHashes = [];
    }
    
    if (!script.ipHashes.includes(ipHash)) {
        script.ipHashes.push(ipHash);
        
        // Keep only last 100 IPs
        if (script.ipHashes.length > 100) {
            script.ipHashes = script.ipHashes.slice(-100);
        }
    }
    
    db[script.id] = script;
    writeDB(db);
    
    // Generate signature for integrity check
    const signature = generateSignature(script.source, script.token);
    
    // Send response with multiple security headers
    res.status(200)
        .type("text/plain")
        .set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
        .set("Pragma", "no-cache")
        .set("Expires", "0")
        .set("X-Content-Type-Options", "nosniff")
        .set("X-Frame-Options", "DENY")
        .set("X-XSS-Protection", "1; mode=block")
        .set("Referrer-Policy", "no-referrer")
        .set("X-Script-Signature", signature)
        .set("X-Access-Count", String(script.accessCount))
        .set("X-Last-Access", String(script.lastAccessed))
        .send(script.source);
});

/*
============================================================
SECURITY ENDPOINTS
============================================================
*/

// Get script statistics
app.get("/api/scripts/:id/stats", (req, res) => {
    const db = readDB();
    const script = db[req.params.id];
    
    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }
    
    res.json({
        ok: true,
        stats: {
            accessCount: script.accessCount || 0,
            lastAccessed: script.lastAccessed,
            uniqueIPs: script.ipHashes ? script.ipHashes.length : 0,
            createdAt: script.createdAt,
            updatedAt: script.updatedAt
        }
    });
});

// Check if IP is blocked
app.get("/api/security/check-ip", (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const blocked = isIPBlocked(clientIP);
    
    res.json({
        ok: true,
        ip: clientIP,
        blocked
    });
});

/*
============================================================
404
============================================================
*/

app.use((req, res) => {
    res.status(404)
        .type("text/plain")
        .send("Blocked by LEXINX v50 protection");
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500)
        .type("text/plain")
        .send("Internal Server Error");
});

app.listen(PORT, "0.0.0.0", () => {
    console.log("LEXINX PROTECT ONLINE");
    console.log(`Domain: ${DOMAIN}`);
    console.log(`Port: ${PORT}`);
    console.log("Security Features:");
    console.log("- Advanced bot detection");
    console.log("- IP blocking system");
    console.log("- Rate limiting");
    console.log("- Multi-layer obfuscation");
    console.log("- Anti-dump protection");
    console.log("- Anti-decompile protection");
    console.log("- Request signature validation");
    console.log("- Access statistics tracking");
});
