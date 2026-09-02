// ============================================================
// LEXINX PROTECT V5
// server.js
// PostgreSQL + Auth + Script Storage + LXVM Binary
// ============================================================

"use strict";

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error("================================================");
    console.error("[LEXINX] ERROR: DATABASE_URL is missing");
    console.error("================================================");
}

// ============================================================
// EXPRESS
// ============================================================

app.disable("x-powered-by");

app.use(express.json({
    limit: "2mb"
}));

app.use(express.urlencoded({
    extended: false,
    limit: "2mb"
}));

// ============================================================
// POSTGRESQL
// ============================================================

const pool = new Pool({
    connectionString: DATABASE_URL,

    ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false,

    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

pool.on("error", (err) => {
    console.error("[POSTGRES ERROR]", err);
});

// ============================================================
// HELPERS
// ============================================================

function randomToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function sha256(data) {
    return crypto
        .createHash("sha256")
        .update(data)
        .digest();
}

function sha256Hex(data) {
    return crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");
}

function safeString(value, max = 100000) {
    if (typeof value !== "string") return "";
    return value.slice(0, max);
}

function parseCookies(req) {
    const result = {};

    const header = req.headers.cookie;
    if (!header) return result;

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) continue;

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        result[key] = decodeURIComponent(value);
    }

    return result;
}

function setSessionCookie(res, token) {
    const secure =
        process.env.NODE_ENV === "production"
            ? "; Secure"
            : "";

    res.setHeader(
        "Set-Cookie",
        `lexinx_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure}`
    );
}

function clearSessionCookie(res) {
    res.setHeader(
        "Set-Cookie",
        "lexinx_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}

// ============================================================
// PASSWORD
// ============================================================

function hashPassword(password) {
    const salt = crypto.randomBytes(16);

    const hash = crypto.scryptSync(
        password,
        salt,
        64
    );

    return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

function verifyPassword(password, stored) {
    try {
        const [saltHex, hashHex] = stored.split(":");

        if (!saltHex || !hashHex) {
            return false;
        }

        const salt = Buffer.from(saltHex, "hex");
        const expected = Buffer.from(hashHex, "hex");

        const actual = crypto.scryptSync(
            password,
            salt,
            expected.length
        );

        return (
            actual.length === expected.length &&
            crypto.timingSafeEqual(actual, expected)
        );
    } catch {
        return false;
    }
}

// ============================================================
// LXVM
// ============================================================

const OP = Object.freeze({
    NOP: 0x00,

    PUSH_STRING: 0x01,
    PUSH_NUMBER: 0x02,
    PUSH_BOOL: 0x03,
    PUSH_NIL: 0x04,

    GET_GLOBAL: 0x10,
    SET_GLOBAL: 0x11,

    ADD: 0x20,
    SUB: 0x21,
    MUL: 0x22,
    DIV: 0x23,

    CONCAT: 0x30,

    CALL_GLOBAL: 0x40,

    POP: 0x50,

    RETURN: 0xFF
});

function deriveVMKey(scriptId) {
    return sha256(
        Buffer.from(
            "LEXINX-V5-VM|" + scriptId,
            "utf8"
        )
    );
}

function xorBuffer(data, key) {
    const output = Buffer.alloc(data.length);

    for (let i = 0; i < data.length; i++) {
        output[i] =
            data[i] ^
            key[i % key.length];
    }

    return output;
}

// ============================================================
// TINY LUA -> CUSTOM BYTECODE
// ============================================================

function compileLua(source) {
    source = String(source || "").trim();

    const instructions = [];

    function pushString(value) {
        const data = Buffer.from(value, "utf8");

        const header = Buffer.alloc(3);

        header[0] = OP.PUSH_STRING;
        header.writeUInt16BE(data.length, 1);

        instructions.push(header);
        instructions.push(data);
    }

    function pushNumber(value) {
        const buffer = Buffer.alloc(9);

        buffer[0] = OP.PUSH_NUMBER;
        buffer.writeDoubleBE(value, 1);

        instructions.push(buffer);
    }

    function pushBool(value) {
        instructions.push(
            Buffer.from([
                OP.PUSH_BOOL,
                value ? 1 : 0
            ])
        );
    }

    function pushNil() {
        instructions.push(
            Buffer.from([
                OP.PUSH_NIL
            ])
        );
    }

    function callGlobal(name, argc) {
        const nameBuffer =
            Buffer.from(name, "utf8");

        const header = Buffer.alloc(4);

        header[0] = OP.CALL_GLOBAL;
        header[1] = argc;
        header.writeUInt16BE(
            nameBuffer.length,
            2
        );

        instructions.push(header);
        instructions.push(nameBuffer);
    }

    // --------------------------------------------------------
    // print("...")
    // --------------------------------------------------------

    let match = source.match(
        /^print\s*\(\s*"([\s\S]*)"\s*\)\s*;?$/
    );

    if (!match) {
        match = source.match(
            /^print\s*\(\s*'([\s\S]*)'\s*\)\s*;?$/
        );
    }

    if (match) {
        pushString(match[1]);
        callGlobal("print", 1);

        instructions.push(
            Buffer.from([OP.RETURN])
        );

        return Buffer.concat(instructions);
    }

    // --------------------------------------------------------
    // return string
    // --------------------------------------------------------

    match = source.match(
        /^return\s+"([\s\S]*)"\s*;?$/
    );

    if (!match) {
        match = source.match(
            /^return\s+'([\s\S]*)'\s*;?$/
        );
    }

    if (match) {
        pushString(match[1]);

        instructions.push(
            Buffer.from([OP.RETURN])
        );

        return Buffer.concat(instructions);
    }

    // --------------------------------------------------------
    // return number
    // --------------------------------------------------------

    match = source.match(
        /^return\s+(-?(?:\d+(?:\.\d*)?|\.\d+))\s*;?$/
    );

    if (match) {
        pushNumber(Number(match[1]));

        instructions.push(
            Buffer.from([OP.RETURN])
        );

        return Buffer.concat(instructions);
    }

    // --------------------------------------------------------
    // return boolean
    // --------------------------------------------------------

    match = source.match(
        /^return\s+(true|false)\s*;?$/
    );

    if (match) {
        pushBool(match[1] === "true");

        instructions.push(
            Buffer.from([OP.RETURN])
        );

        return Buffer.concat(instructions);
    }

    // --------------------------------------------------------
    // return nil
    // --------------------------------------------------------

    if (
        /^return\s+nil\s*;?$/.test(source)
    ) {
        pushNil();

        instructions.push(
            Buffer.from([OP.RETURN])
        );

        return Buffer.concat(instructions);
    }

    throw new Error(
        "Unsupported Lua syntax by LXVM compiler"
    );
}

// ============================================================
// LXVM PACKET
// ============================================================

function packLXVM(bytecode, scriptId) {
    const key = deriveVMKey(scriptId);

    const encrypted =
        xorBuffer(bytecode, key);

    const hash =
        sha256(bytecode);

    const header = Buffer.alloc(42);

    // MAGIC
    header.write("LXVM", 0, 4, "ascii");

    // VERSION
    header[4] = 1;

    // FLAGS
    header[5] = 1;

    // PAYLOAD LENGTH
    header.writeUInt32BE(
        encrypted.length,
        6
    );

    // SHA256
    hash.copy(header, 10);

    return Buffer.concat([
        header,
        encrypted
    ]);
}

function unpackLXVM(packet, scriptId) {
    if (!Buffer.isBuffer(packet)) {
        throw new Error("Invalid packet");
    }

    if (packet.length < 42) {
        throw new Error("Packet too small");
    }

    const magic =
        packet.toString(
            "ascii",
            0,
            4
        );

    if (magic !== "LXVM") {
        throw new Error("Invalid LXVM magic");
    }

    const version =
        packet[4];

    if (version !== 1) {
        throw new Error("Unsupported LXVM version");
    }

    const payloadLength =
        packet.readUInt32BE(6);

    if (
        payloadLength !==
        packet.length - 42
    ) {
        throw new Error(
            "Invalid payload length"
        );
    }

    const expectedHash =
        packet.subarray(10, 42);

    const encrypted =
        packet.subarray(42);

    const key =
        deriveVMKey(scriptId);

    const bytecode =
        xorBuffer(encrypted, key);

    const actualHash =
        sha256(bytecode);

    if (
        !crypto.timingSafeEqual(
            expectedHash,
            actualHash
        )
    ) {
        throw new Error(
            "LXVM integrity check failed"
        );
    }

    return bytecode;
}

// ============================================================
// BASE64 TRANSPORT
// ============================================================

function packForTransport(bytecode, scriptId) {
    return packLXVM(
        bytecode,
        scriptId
    ).toString("base64");
}

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function initDatabase() {
    if (!DATABASE_URL) {
        throw new Error(
            "DATABASE_URL environment variable is missing"
        );
    }

    console.log(
        "[LEXINX] Testing PostgreSQL connection..."
    );

    const client =
        await pool.connect();

    try {
        await client.query("SELECT 1");

        console.log(
            "[LEXINX] PostgreSQL connection OK"
        );

        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(32) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS scripts (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                script_id VARCHAR(64)
                    NOT NULL UNIQUE,

                name VARCHAR(100)
                    NOT NULL DEFAULT 'My Script',

                source TEXT
                    NOT NULL DEFAULT '',

                bytecode BYTEA,

                bytecode_version INTEGER
                    NOT NULL DEFAULT 1,

                vm_version INTEGER
                    NOT NULL DEFAULT 1,

                enabled BOOLEAN
                    NOT NULL DEFAULT TRUE,

                created_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW(),

                updated_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW()
            )
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS
            idx_scripts_user_id
            ON scripts(user_id)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS
            idx_scripts_script_id
            ON scripts(script_id)
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS login_sessions (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                session_token TEXT NOT NULL UNIQUE,

                created_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW(),

                expires_at TIMESTAMPTZ,

                last_seen_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW()
            )
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS
            idx_login_sessions_token
            ON login_sessions(session_token)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS
            idx_login_sessions_user_id
            ON login_sessions(user_id)
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS script_access_logs (
                id BIGSERIAL PRIMARY KEY,

                user_id BIGINT
                    REFERENCES users(id)
                    ON DELETE SET NULL,

                script_id VARCHAR(64),

                ip_address INET,

                success BOOLEAN
                    NOT NULL DEFAULT FALSE,

                created_at TIMESTAMPTZ
                    NOT NULL DEFAULT NOW()
            )
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS
            idx_access_logs_script
            ON script_access_logs(script_id)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS
            idx_access_logs_user
            ON script_access_logs(user_id)
        `);

        console.log(
            "[LEXINX] Database tables ready"
        );

    } finally {
        client.release();
    }
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

async function getSessionUser(req) {
    const cookies =
        parseCookies(req);

    const token =
        cookies.lexinx_session;

    if (!token) {
        return null;
    }

    const result =
        await pool.query(
            `
            SELECT
                u.id,
                u.username
            FROM login_sessions s
            JOIN users u
                ON u.id = s.user_id
            WHERE s.session_token = $1
              AND (
                    s.expires_at IS NULL
                    OR s.expires_at > NOW()
              )
            LIMIT 1
            `,
            [token]
        );

    if (!result.rows.length) {
        return null;
    }

    await pool.query(
        `
        UPDATE login_sessions
        SET last_seen_at = NOW()
        WHERE session_token = $1
        `,
        [token]
    );

    return result.rows[0];
}

async function requireAuth(req, res, next) {
    try {
        const user =
            await getSessionUser(req);

        if (!user) {
            return res.status(401).json({
                success: false,
                error: "Not authenticated"
            });
        }

        req.user = user;

        next();

    } catch (error) {
        console.error(
            "[AUTH ERROR]",
            error
        );

        res.status(500).json({
            success: false,
            error: "Authentication error"
        });
    }
}

// ============================================================
// HEALTH
// ============================================================

app.get("/health", async (req, res) => {
    let database = "OFFLINE";

    try {
        await pool.query("SELECT 1");
        database = "ONLINE";
    } catch (error) {
        console.error(
            "[HEALTH DB ERROR]",
            error.message
        );
    }

    res.json({
        success: true,
        service: "LEXINX PROTECT V5",
        status: "ONLINE",
        database,
        vm: "LXVM",
        version: "5.1.0",
        time: new Date().toISOString()
    });
});

// ============================================================
// REGISTER
// ============================================================

app.post("/api/register", async (req, res) => {
    try {
        const username =
            safeString(
                req.body?.username,
                32
            ).trim();

        const password =
            safeString(
                req.body?.password,
                200
            );

        console.log(
            `[REGISTER] username=${username || "<empty>"}`
        );

        if (!username) {
            return res.status(400).json({
                success: false,
                error: "Username is required"
            });
        }

        if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
            return res.status(400).json({
                success: false,
                error:
                    "Username must be 3-32 characters and contain only letters, numbers, underscore"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                error:
                    "Password must be at least 6 characters"
            });
        }

        if (!DATABASE_URL) {
            return res.status(500).json({
                success: false,
                error:
                    "DATABASE_URL is not configured on server"
            });
        }

        // ----------------------------------------------------
        // DB TEST
        // ----------------------------------------------------

        await pool.query("SELECT 1");

        // ----------------------------------------------------
        // TABLE TEST
        // ----------------------------------------------------

        await pool.query(
            "SELECT id FROM users LIMIT 1"
        );

        // ----------------------------------------------------
        // DUPLICATE CHECK
        // ----------------------------------------------------

        const exists =
            await pool.query(
                `
                SELECT id
                FROM users
                WHERE LOWER(username)
                    = LOWER($1)
                LIMIT 1
                `,
                [username]
            );

        if (exists.rows.length) {
            return res.status(409).json({
                success: false,
                error:
                    "Username already exists"
            });
        }

        // ----------------------------------------------------
        // HASH
        // ----------------------------------------------------

        const passwordHash =
            hashPassword(password);

        // ----------------------------------------------------
        // INSERT USER
        // ----------------------------------------------------

        const userResult =
            await pool.query(
                `
                INSERT INTO users
                    (username, password_hash)
                VALUES
                    ($1, $2)
                RETURNING id, username
                `,
                [
                    username,
                    passwordHash
                ]
            );

        const user =
            userResult.rows[0];

        // ----------------------------------------------------
        // SESSION
        // ----------------------------------------------------

        const sessionToken =
            randomToken(32);

        await pool.query(
            `
            INSERT INTO login_sessions
                (
                    user_id,
                    session_token,
                    expires_at
                )
            VALUES
                (
                    $1,
                    $2,
                    NOW() + INTERVAL '7 days'
                )
            `,
            [
                user.id,
                sessionToken
            ]
        );

        setSessionCookie(
            res,
            sessionToken
        );

        console.log(
            `[REGISTER] SUCCESS username=${username}`
        );

        return res.json({
            success: true,
            username: user.username,
            url:
                `/loader/user/${user.id}`
        });

    } catch (error) {
        console.error(
            "================================================"
        );

        console.error(
            "[REGISTER FAILED]"
        );

        console.error(
            "name:",
            error.name
        );

        console.error(
            "message:",
            error.message
        );

        console.error(
            "code:",
            error.code
        );

        console.error(
            "detail:",
            error.detail
        );

        console.error(
            "constraint:",
            error.constraint
        );

        console.error(
            "================================================"
        );

        // Temporary diagnostic response.
        // This makes the actual PostgreSQL problem
        // visible instead of only "Registration failed".

        return res.status(500).json({
            success: false,
            error:
                `Registration failed: ${error.message || "Unknown database error"}`,
            code:
                error.code || null
        });
    }
});

// ============================================================
// LOGIN
// ============================================================

app.post("/api/login", async (req, res) => {
    try {
        const username =
            safeString(
                req.body?.username,
                32
            ).trim();

        const password =
            safeString(
                req.body?.password,
                200
            );

        const result =
            await pool.query(
                `
                SELECT
                    id,
                    username,
                    password_hash
                FROM users
                WHERE LOWER(username)
                    = LOWER($1)
                LIMIT 1
                `,
                [username]
            );

        if (!result.rows.length) {
            return res.status(401).json({
                success: false,
                error:
                    "Invalid username or password"
            });
        }

        const user =
            result.rows[0];

        if (
            !verifyPassword(
                password,
                user.password_hash
            )
        ) {
            return res.status(401).json({
                success: false,
                error:
                    "Invalid username or password"
            });
        }

        const sessionToken =
            randomToken(32);

        await pool.query(
            `
            INSERT INTO login_sessions
                (
                    user_id,
                    session_token,
                    expires_at
                )
            VALUES
                (
                    $1,
                    $2,
                    NOW() + INTERVAL '7 days'
                )
            `,
            [
                user.id,
                sessionToken
            ]
        );

        setSessionCookie(
            res,
            sessionToken
        );

        res.json({
            success: true,
            username: user.username,
            url:
                `/loader/user/${user.id}`
        });

    } catch (error) {
        console.error(
            "[LOGIN ERROR]",
            error
        );

        res.status(500).json({
            success: false,
            error:
                `Login failed: ${error.message}`
        });
    }
});

// ============================================================
// ME
// ============================================================

app.get(
    "/api/me",
    requireAuth,
    async (req, res) => {
        res.json({
            success: true,
            username:
                req.user.username,
            url:
                `/loader/user/${req.user.id}`
        });
    }
);

// ============================================================
// LOGOUT
// ============================================================

app.post("/api/logout", async (req, res) => {
    try {
        const cookies =
            parseCookies(req);

        const token =
            cookies.lexinx_session;

        if (token) {
            await pool.query(
                `
                DELETE FROM login_sessions
                WHERE session_token = $1
                `,
                [token]
            );
        }

        clearSessionCookie(res);

        res.json({
            success: true
        });

    } catch (error) {
        console.error(
            "[LOGOUT ERROR]",
            error
        );

        clearSessionCookie(res);

        res.json({
            success: true
        });
    }
});

// ============================================================
// CREATE SCRIPT
// ============================================================

app.post(
    "/api/create",
    requireAuth,
    async (req, res) => {
        try {
            const name =
                safeString(
                    req.body?.name,
                    100
                ).trim() ||
                "My Script";

            const source =
                safeString(
                    req.body?.source,
                    1000000
                );

            if (!source.trim()) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Source cannot be empty"
                });
            }

            const scriptId =
                "LX-" +
                crypto
                    .randomBytes(12)
                    .toString("hex");

            const bytecode =
                compileLua(source);

            await pool.query(
                `
                INSERT INTO scripts
                    (
                        user_id,
                        script_id,
                        name,
                        source,
                        bytecode,
                        bytecode_version,
                        vm_version
                    )
                VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        1,
                        1
                    )
                `,
                [
                    req.user.id,
                    scriptId,
                    name,
                    source,
                    bytecode
                ]
            );

            const loader =
                `/loader/${encodeURIComponent(scriptId)}`;

            res.json({
                success: true,
                id: scriptId,
                loader
            });

        } catch (error) {
            console.error(
                "[CREATE SCRIPT ERROR]",
                error
            );

            res.status(400).json({
                success: false,
                error:
                    error.message ||
                    "Create script failed"
            });
        }
    }
);

// ============================================================
// LIST SCRIPTS
// ============================================================

app.get(
    "/api/scripts",
    requireAuth,
    async (req, res) => {
        try {
            const result =
                await pool.query(
                    `
                    SELECT
                        script_id AS id,
                        name,
                        enabled,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    `,
                    [req.user.id]
                );

            res.json({
                success: true,
                scripts:
                    result.rows.map(row => ({
                        id: row.id,
                        name: row.name,
                        loader:
                            `/loader/${encodeURIComponent(row.id)}`,
                        enabled:
                            row.enabled
                    }))
            });

        } catch (error) {
            console.error(
                "[LIST SCRIPT ERROR]",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Failed to load scripts"
            });
        }
    }
);

// ============================================================
// GET SCRIPT
// ============================================================

app.get(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {
        try {
            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        name,
                        source,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                      AND user_id = $2
                    LIMIT 1
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );

            if (!result.rows.length) {
                return res.status(404).json({
                    success: false,
                    error:
                        "Script not found"
                });
            }

            const row =
                result.rows[0];

            res.json({
                success: true,
                script: {
                    id:
                        row.script_id,
                    name:
                        row.name,
                    source:
                        row.source,
                    enabled:
                        row.enabled
                }
            });

        } catch (error) {
            console.error(
                "[GET SCRIPT ERROR]",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Failed to load script"
            });
        }
    }
);

// ============================================================
// UPDATE SCRIPT
// ============================================================

app.put(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {
        try {
            const name =
                safeString(
                    req.body?.name,
                    100
                ).trim() ||
                "My Script";

            const source =
                safeString(
                    req.body?.source,
                    1000000
                );

            if (!source.trim()) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Source cannot be empty"
                });
            }

            const bytecode =
                compileLua(source);

            const result =
                await pool.query(
                    `
                    UPDATE scripts
                    SET
                        name = $1,
                        source = $2,
                        bytecode = $3,
                        updated_at = NOW()
                    WHERE script_id = $4
                      AND user_id = $5
                    RETURNING script_id
                    `,
                    [
                        name,
                        source,
                        bytecode,
                        req.params.id,
                        req.user.id
                    ]
                );

            if (!result.rows.length) {
                return res.status(404).json({
                    success: false,
                    error:
                        "Script not found"
                });
            }

            res.json({
                success: true
            });

        } catch (error) {
            console.error(
                "[UPDATE SCRIPT ERROR]",
                error
            );

            res.status(400).json({
                success: false,
                error:
                    error.message ||
                    "Update failed"
            });
        }
    }
);

// ============================================================
// DELETE SCRIPT
// ============================================================

app.delete(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {
        try {
            const result =
                await pool.query(
                    `
                    DELETE FROM scripts
                    WHERE script_id = $1
                      AND user_id = $2
                    RETURNING script_id
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );

            if (!result.rows.length) {
                return res.status(404).json({
                    success: false,
                    error:
                        "Script not found"
                });
            }

            res.json({
                success: true
            });

        } catch (error) {
            console.error(
                "[DELETE SCRIPT ERROR]",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Delete failed"
            });
        }
    }
);

// ============================================================
// INTERNAL SCRIPT FETCH
// ============================================================

async function getScriptById(scriptId) {
    const result =
        await pool.query(
            `
            SELECT
                script_id,
                name,
                source,
                bytecode,
                enabled,
                bytecode_version,
                vm_version
            FROM scripts
            WHERE script_id = $1
            LIMIT 1
            `,
            [scriptId]
        );

    return result.rows[0] || null;
}

// ============================================================
// VM ENDPOINT
// ============================================================

app.get(
    "/api/vm/:scriptId",
    async (req, res) => {
        try {
            const script =
                await getScriptById(
                    req.params.scriptId
                );

            if (!script || !script.enabled) {
                return res.status(404).json({
                    success: false,
                    error:
                        "Script unavailable"
                });
            }

            const bytecode =
                script.bytecode;

            if (!bytecode) {
                return res.status(404).json({
                    success: false,
                    error:
                        "Bytecode unavailable"
                });
            }

            const packet =
                packLXVM(
                    bytecode,
                    script.script_id
                );

            res.setHeader(
                "Content-Type",
                "application/octet-stream"
            );

            res.setHeader(
                "Cache-Control",
                "no-store"
            );

            res.send(packet);

        } catch (error) {
            console.error(
                "[VM ERROR]",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "VM payload failed"
            });
        }
    }
);

// ============================================================
// L1
// ============================================================

app.get(
    "/api/l1/:scriptId",
    async (req, res) => {
        const id =
            encodeURIComponent(
                req.params.scriptId
            );

        res.type("text/plain");

        res.send(`
-- LEXINX PROTECT V5
-- L1

local SCRIPT_ID = "${id}"

local function nextLayer()
    return game:HttpGet(
        "https://" ..
        game:GetService("HttpService")
            :UrlEncode("") ..
        "/api/l2/" ..
        SCRIPT_ID
    )
end

return true
        `.trim());
    }
);

// ============================================================
// L2
// ============================================================

app.get(
    "/api/l2/:scriptId",
    async (req, res) => {
        const id =
            encodeURIComponent(
                req.params.scriptId
            );

        res.type("text/plain");

        res.send(`
-- LEXINX PROTECT V5
-- L2

local SCRIPT_ID = "${id}"

return {
    version = 2,
    script = SCRIPT_ID
}
        `.trim());
    }
);

// ============================================================
// L3
// ============================================================

app.get(
    "/api/l3/:scriptId",
    async (req, res) => {
        const id =
            encodeURIComponent(
                req.params.scriptId
            );

        res.type("text/plain");

        res.send(`
-- LEXINX PROTECT V5
-- L3

local SCRIPT_ID = "${id}"

return {
    stage = 3,
    id = SCRIPT_ID
}
        `.trim());
    }
);

// ============================================================
// L4
// ============================================================

app.get(
    "/api/l4/:scriptId",
    async (req, res) => {
        const id =
            encodeURIComponent(
                req.params.scriptId
            );

        res.type("text/plain");

        res.send(`
-- LEXINX PROTECT V5
-- L4

local SCRIPT_ID = "${id}"

return {
    stage = 4,
    vm = "LXVM",
    id = SCRIPT_ID
}
        `.trim());
    }
);

// ============================================================
// L5
// ============================================================

app.get(
    "/api/l5/:scriptId",
    async (req, res) => {
        try {
            const script =
                await getScriptById(
                    req.params.scriptId
                );

            if (!script || !script.enabled) {
                return res.status(404).send(
                    "-- LEXINX PROTECT V5\nreturn false"
                );
            }

            const binary =
                packForTransport(
                    script.bytecode,
                    script.script_id
                );

            res.type("text/plain");

            res.send(`
-- LEXINX PROTECT V5
-- L5 / LXVM

local B64 = [[
${binary}
]]

return {
    VM = "LXVM",
    VERSION = 1,
    PAYLOAD = B64
}
            `.trim());

        } catch (error) {
            console.error(
                "[L5 ERROR]",
                error
            );

            res.status(500).send(
                "-- LEXINX PROTECT V5\nreturn false"
            );
        }
    }
);

// ============================================================
// DYNAMIC LOADER
// ============================================================

app.get(
    "/loader/:scriptId",
    async (req, res) => {
        try {
            const scriptId =
                req.params.scriptId;

            const script =
                await getScriptById(
                    scriptId
                );

            if (!script || !script.enabled) {
                return res.status(404).type(
                    "text/plain"
                ).send(
                    "-- LEXINX PROTECT V5\n" +
                    "-- Script unavailable\n" +
                    "return false"
                );
            }

            const bytecode =
                script.bytecode;

            if (!bytecode) {
                return res.status(404).type(
                    "text/plain"
                ).send(
                    "-- LEXINX PROTECT V5\n" +
                    "-- Bytecode unavailable\n" +
                    "return false"
                );
            }

            const payload =
                packForTransport(
                    bytecode,
                    script.script_id
                );

            // ------------------------------------------------
            // Loader receives Base64 transport only.
            // The original Lua source is NOT sent here.
            // ------------------------------------------------

            const loader = `
-- ============================================================
-- LEXINX PROTECT V5
-- CUSTOM LXVM LOADER
-- SCRIPT: ${script.script_id}
-- ============================================================

local __LEXINX_PAYLOAD = [[
${payload}
]]

local __LEXINX_SCRIPT_ID =
    ${JSON.stringify(script.script_id)}

local function __b64decode(data)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    data = data:gsub("[^" .. alphabet .. "=]", "")

    local result = {}

    for i = 1, #data, 4 do

        local a =
            alphabet:find(
                data:sub(i, i),
                1,
                true
            )

        local b =
            alphabet:find(
                data:sub(i + 1, i + 1),
                1,
                true
            )

        local c =
            alphabet:find(
                data:sub(i + 2, i + 2),
                1,
                true
            )

        local d =
            alphabet:find(
                data:sub(i + 3, i + 3),
                1,
                true
            )

        a = (a or 1) - 1
        b = (b or 1) - 1
        c = (c or 1) - 1
        d = (d or 1) - 1

        local n =
            a * 262144 +
            b * 4096 +
            c * 64 +
            d

        local x =
            math.floor(n / 65536) % 256

        local y =
            math.floor(n / 256) % 256

        local z =
            n % 256

        result[#result + 1] =
            string.char(x)

        if data:sub(i + 2, i + 2) ~= "=" then
            result[#result + 1] =
                string.char(y)
        end

        if data:sub(i + 3, i + 3) ~= "=" then
            result[#result + 1] =
                string.char(z)
        end
    end

    return table.concat(result)
end

local function __readU32BE(s, p)

    local a, b, c, d =
        s:byte(p, p + 3)

    return
        a * 16777216 +
        b * 65536 +
        c * 256 +
        d
end

local function __readU16BE(s, p)

    local a, b =
        s:byte(p, p + 1)

    return
        a * 256 +
        b
end

local function __deriveKey(id)

    -- The real production implementation should
    -- derive this key in the same way as the VM.
    --
    -- This loader intentionally keeps the payload
    -- binary/VM based instead of returning Lua source.

    return id
end

local function __xor(data, key)

    local out = {}

    for i = 1, #data do

        local a =
            data:byte(i)

        local b =
            key:byte(
                ((i - 1) % #key) + 1
            )

        out[i] =
            string.char(
                bit32.bxor(a, b)
            )
    end

    return table.concat(out)
end

local function __loadLXVM(packet)

    assert(
        packet:sub(1, 4) == "LXVM",
        "LEXINX: invalid LXVM packet"
    )

    local version =
        packet:byte(5)

    assert(
        version == 1,
        "LEXINX: unsupported VM version"
    )

    local payloadLength =
        __readU32BE(packet, 7)

    local payload =
        packet:sub(43)

    assert(
        #payload == payloadLength,
        "LEXINX: invalid payload length"
    )

    local key =
        __deriveKey(
            __LEXINX_SCRIPT_ID
        )

    local bytecode =
        __xor(
            payload,
            key
        )

    return bytecode
end

local function __runVM(bytecode)

    local pc = 1
    local stack = {}

    local function push(v)
        stack[#stack + 1] = v
    end

    local function pop()
        local v = stack[#stack]
        stack[#stack] = nil
        return v
    end

    while pc <= #bytecode do

        local opcode =
            bytecode:byte(pc)

        pc = pc + 1

        if opcode == 0x00 then

            -- NOP

        elseif opcode == 0x01 then

            local len =
                __readU16BE(
                    bytecode,
                    pc
                )

            pc = pc + 2

            local value =
                bytecode:sub(
                    pc,
                    pc + len - 1
                )

            pc =
                pc + len

            push(value)

        elseif opcode == 0x03 then

            local value =
                bytecode:byte(pc)

            pc = pc + 1

            push(value ~= 0)

        elseif opcode == 0x04 then

            push(nil)

        elseif opcode == 0x40 then

            local argc =
                bytecode:byte(pc)

            pc = pc + 1

            local len =
                __readU16BE(
                    bytecode,
                    pc
                )

            pc = pc + 2

            local name =
                bytecode:sub(
                    pc,
                    pc + len - 1
                )

            pc =
                pc + len

            local args = {}

            for i = argc, 1, -1 do
                args[i] = pop()
            end

            if name == "print" then
                print(table.unpack(args))
            end

        elseif opcode == 0xFF then

            return pop()

        else

            error(
                "LEXINX VM: unknown opcode " ..
                tostring(opcode)
            )
        end
    end
end

local __packet =
    __b64decode(
        __LEXINX_PAYLOAD
    )

local __bytecode =
    __loadLXVM(
        __packet
    )

return __runVM(
    __bytecode
)
`;

            res.type("text/plain");

            res.setHeader(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            );

            res.send(loader);

        } catch (error) {
            console.error(
                "[LOADER ERROR]",
                error
            );

            res.status(500)
                .type("text/plain")
                .send(
                    "-- LEXINX PROTECT V5\n" +
                    "-- Loader generation failed\n" +
                    "return false"
                );
        }
    }
);

// ============================================================
// ROOT
// ============================================================

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

// ============================================================
// STATIC
// ============================================================

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);

// ============================================================
// 404
// ============================================================

app.use((req, res) => {
    if (
        req.path.startsWith("/api/")
    ) {
        return res.status(404).json({
            success: false,
            error: "API endpoint not found"
        });
    }

    res.status(404).type("text/plain").send(
        "LEXINX PROTECT V5 - 404"
    );
});

// ============================================================
// GLOBAL ERROR
// ============================================================

app.use((err, req, res, next) => {
    console.error(
        "[GLOBAL ERROR]",
        err
    );

    if (res.headersSent) {
        return next(err);
    }

    res.status(500).json({
        success: false,
        error: "Internal server error"
    });
});

// ============================================================
// START
// ============================================================

async function start() {
    try {
        await initDatabase();

        app.listen(
            PORT,
            "0.0.0.0",
            () => {
                console.log(
                    "================================================"
                );

                console.log(
                    " LEXINX PROTECT V5"
                );

                console.log(
                    " SERVER ONLINE"
                );

                console.log(
                    ` PORT: ${PORT}`
                );

                console.log(
                    " VM: LXVM"
                );

                console.log(
                    " DATABASE: ONLINE"
                );

                console.log(
                    "================================================"
                );
            }
        );

    } catch (error) {

        console.error(
            "================================================"
        );

        console.error(
            "[LEXINX] SERVER START FAILED"
        );

        console.error(
            "message:",
            error.message
        );

        console.error(
            "code:",
            error.code
        );

        console.error(
            "detail:",
            error.detail
        );

        console.error(
            "================================================"
        );

        process.exit(1);
    }
}

start();
