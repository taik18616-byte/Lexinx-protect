// ============================================================
// LEXINX PROTECT V5
// PostgreSQL + LXVM Custom Bytecode + L1 -> L5
// Existing public/index.html is served unchanged
// ============================================================

"use strict";

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;
const BASE_URL =
    process.env.BASE_URL ||
    "https://lexinx-protect.onrender.com";

// ============================================================
// EXPRESS
// ============================================================

app.use(express.json({
    limit: "2mb"
}));

app.use(express.urlencoded({
    extended: false
}));

// ============================================================
// POSTGRESQL
// ============================================================

if (!process.env.DATABASE_URL) {
    console.warn(
        "[LEXINX] DATABASE_URL is not configured."
    );
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl:
        process.env.NODE_ENV === "production"
            ? {
                rejectUnauthorized: false
            }
            : false
});

pool.on("error", (err) => {
    console.error(
        "[LEXINX] PostgreSQL pool error:",
        err
    );
});

// ============================================================
// STATIC EXISTING WEBSITE
// ============================================================

const publicDir =
    path.join(__dirname, "public");

app.use(
    express.static(publicDir)
);

// IMPORTANT:
// This serves YOUR existing public/index.html.
// No generated dashboard.
app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            publicDir,
            "index.html"
        )
    );
});

// ============================================================
// HELPERS
// ============================================================

function randomId(length = 24) {

    const alphabet =
        "ABCDEFGHJKLMNPQRSTUVWXYZ" +
        "abcdefghijkmnopqrstuvwxyz" +
        "23456789";

    const bytes =
        crypto.randomBytes(length);

    let out = "";

    for (let i = 0; i < length; i++) {
        out +=
            alphabet[
                bytes[i] % alphabet.length
            ];
    }

    return out;
}

function sha256Buffer(data) {

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

function xorBuffer(data, key) {

    const out =
        Buffer.alloc(data.length);

    for (
        let i = 0;
        i < data.length;
        i++
    ) {

        out[i] =
            data[i] ^
            key[i % key.length];
    }

    return out;
}

function deriveVMKey(scriptId) {

    return sha256Buffer(
        Buffer.from(
            "LEXINX-V5-VM|" +
            scriptId,
            "utf8"
        )
    );
}

async function uniqueScriptId() {

    for (let i = 0; i < 20; i++) {

        const id =
            randomId(24);

        const result =
            await pool.query(
                `
                SELECT 1
                FROM scripts
                WHERE script_id = $1
                LIMIT 1
                `,
                [id]
            );

        if (result.rowCount === 0) {
            return id;
        }
    }

    throw new Error(
        "Unable to generate unique script ID."
    );
}

function normalizeUsername(username) {

    return String(
        username || ""
    )
        .trim()
        .toLowerCase();
}

function validateUsername(username) {

    return /^[a-zA-Z0-9_]{3,32}$/
        .test(username);
}

// ============================================================
// PASSWORD HASHING
// ============================================================

function hashPassword(password) {

    return new Promise(
        (resolve, reject) => {

            const salt =
                crypto.randomBytes(16);

            crypto.scrypt(
                password,
                salt,
                64,
                {
                    N: 16384,
                    r: 8,
                    p: 1
                },
                (err, derivedKey) => {

                    if (err) {
                        reject(err);
                        return;
                    }

                    resolve(
                        [
                            "scrypt",
                            salt.toString("hex"),
                            derivedKey.toString("hex")
                        ].join("$")
                    );
                }
            );
        }
    );
}

function verifyPassword(
    password,
    stored
) {

    return new Promise(
        (resolve, reject) => {

            try {

                const parts =
                    String(stored)
                        .split("$");

                if (
                    parts.length !== 3 ||
                    parts[0] !== "scrypt"
                ) {
                    resolve(false);
                    return;
                }

                const salt =
                    Buffer.from(
                        parts[1],
                        "hex"
                    );

                const original =
                    Buffer.from(
                        parts[2],
                        "hex"
                    );

                crypto.scrypt(
                    password,
                    salt,
                    original.length,
                    {
                        N: 16384,
                        r: 8,
                        p: 1
                    },
                    (err, derived) => {

                        if (err) {
                            reject(err);
                            return;
                        }

                        resolve(
                            crypto.timingSafeEqual(
                                original,
                                derived
                            )
                        );
                    }
                );

            } catch {

                resolve(false);
            }
        }
    );
}

// ============================================================
// SESSION
// ============================================================

async function createSession(userId) {

    const token =
        crypto.randomBytes(32)
            .toString("hex");

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
            NOW() + INTERVAL '30 days'
        )
        `,
        [
            userId,
            token
        ]
    );

    return token;
}

function getSessionToken(req) {

    const cookie =
        req.headers.cookie || "";

    const match =
        cookie.match(
            /lexinx_session=([^;]+)/
        );

    if (match) {
        return match[1];
    }

    return null;
}

function setSessionCookie(
    res,
    token
) {

    res.setHeader(
        "Set-Cookie",
        [
            `lexinx_session=${token}`,
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=2592000"
        ].join("; ")
    );
}

function clearSessionCookie(res) {

    res.setHeader(
        "Set-Cookie",
        [
            "lexinx_session=",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=0"
        ].join("; ")
    );
}

async function getCurrentUser(req) {

    const token =
        getSessionToken(req);

    if (!token) {
        return null;
    }

    const result =
        await pool.query(
            `
            SELECT
                u.id,
                u.username,
                s.session_token
            FROM login_sessions s
            JOIN users u
                ON u.id = s.user_id
            WHERE
                s.session_token = $1
                AND
                (
                    s.expires_at IS NULL
                    OR
                    s.expires_at > NOW()
                )
            LIMIT 1
            `,
            [token]
        );

    if (result.rowCount === 0) {
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

async function requireAuth(
    req,
    res,
    next
) {

    try {

        const user =
            await getCurrentUser(req);

        if (!user) {

            return res
                .status(401)
                .json({
                    error:
                        "Authentication required."
                });
        }

        req.user = user;

        next();

    } catch (err) {

        console.error(err);

        res.status(500)
            .json({
                error:
                    "Authentication error."
            });
    }
}

// ============================================================
// LXVM OPCODES
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

// ============================================================
// CUSTOM BYTECODE COMPILER
//
// Supported prototype:
//
// print("hello")
// print('hello')
//
// return "hello"
// return 'hello'
//
// return 123
// return true
// return false
//
// Multiple supported statements are allowed.
// ============================================================

function compileLua(source) {

    if (
        typeof source !==
        "string"
    ) {
        throw new Error(
            "Source must be a string."
        );
    }

    const text =
        source
            .replace(/\r\n/g, "\n")
            .replace(/\r/g, "\n");

    const lines =
        text.split("\n");

    const chunks = [];

    function pushU8(value) {

        chunks.push(
            Buffer.from([
                value & 0xFF
            ])
        );
    }

    function pushU16(value) {

        const b =
            Buffer.alloc(2);

        b.writeUInt16LE(
            value,
            0
        );

        chunks.push(b);
    }

    function pushF64(value) {

        const b =
            Buffer.alloc(8);

        b.writeDoubleLE(
            value,
            0
        );

        chunks.push(b);
    }

    function pushString(value) {

        const b =
            Buffer.from(
                value,
                "utf8"
            );

        if (b.length > 65535) {

            throw new Error(
                "String literal too long."
            );
        }

        pushU16(
            b.length
        );

        chunks.push(b);
    }

    function emitString(value) {

        pushU8(
            OP.PUSH_STRING
        );

        pushString(value);
    }

    function emitNumber(value) {

        pushU8(
            OP.PUSH_NUMBER
        );

        pushF64(value);
    }

    function emitBool(value) {

        pushU8(
            OP.PUSH_BOOL
        );

        pushU8(
            value ? 1 : 0
        );
    }

    function emitNil() {

        pushU8(
            OP.PUSH_NIL
        );
    }

    function parseLiteral(value) {

        value =
            value.trim();

        if (
            value.length >= 2 &&
            (
                (
                    value[0] === '"' &&
                    value[value.length - 1] === '"'
                )
                ||
                (
                    value[0] === "'" &&
                    value[value.length - 1] === "'"
                )
            )
        ) {

            const quote =
                value[0];

            let content =
                value.slice(
                    1,
                    -1
                );

            // Basic Lua-style escapes.
            content =
                content
                    .replace(
                        new RegExp(
                            "\\\\" +
                            quote,
                            "g"
                        ),
                        quote
                    )
                    .replace(
                        /\\n/g,
                        "\n"
                    )
                    .replace(
                        /\\r/g,
                        "\r"
                    )
                    .replace(
                        /\\t/g,
                        "\t"
                    )
                    .replace(
                        /\\\\/g,
                        "\\"
                    );

            emitString(content);

            return true;
        }

        if (
            value === "true"
        ) {

            emitBool(true);

            return true;
        }

        if (
            value === "false"
        ) {

            emitBool(false);

            return true;
        }

        if (
            value === "nil"
        ) {

            emitNil();

            return true;
        }

        if (
            /^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?$/
                .test(value)
        ) {

            const number =
                Number(value);

            if (
                !Number.isFinite(number)
            ) {
                throw new Error(
                    "Invalid number."
                );
            }

            emitNumber(number);

            return true;
        }

        return false;
    }

    for (
        let lineNumber = 0;
        lineNumber < lines.length;
        lineNumber++
    ) {

        let line =
            lines[lineNumber]
                .trim();

        if (!line) {
            continue;
        }

        // Strip simple comments.
        if (
            line.startsWith("--")
        ) {
            continue;
        }

        line =
            line.replace(
                /--.*$/,
                ""
            ).trim();

        if (!line) {
            continue;
        }

        // ----------------------------------------------------
        // print(...)
        // ----------------------------------------------------

        const printMatch =
            line.match(
                /^print\s*\((.*)\)\s*;?$/
            );

        if (printMatch) {

            const argument =
                printMatch[1];

            if (
                !parseLiteral(argument)
            ) {

                throw new Error(
                    `Unsupported print() argument at line ${lineNumber + 1}.`
                );
            }

            pushU8(
                OP.CALL_GLOBAL
            );

            pushString("print");

            pushU8(1);

            continue;
        }

        // ----------------------------------------------------
        // return ...
        // ----------------------------------------------------

        const returnMatch =
            line.match(
                /^return(?:\s+(.+?))?\s*;?$/
            );

        if (returnMatch) {

            const expression =
                returnMatch[1];

            if (
                expression === undefined
            ) {

                emitNil();

            } else if (
                !parseLiteral(expression)
            ) {

                throw new Error(
                    `Unsupported return expression at line ${lineNumber + 1}.`
                );
            }

            pushU8(
                OP.RETURN
            );

            continue;
        }

        throw new Error(
            `Unsupported Lua syntax at line ${lineNumber + 1}: ${line}`
        );
    }

    // Always terminate bytecode.
    const compiled =
        Buffer.concat(chunks);

    if (
        compiled.length === 0 ||
        compiled[compiled.length - 1] !== OP.RETURN
    ) {

        pushU8(
            OP.PUSH_NIL
        );

        pushU8(
            OP.RETURN
        );
    }

    return Buffer.concat(chunks);
}

// ============================================================
// LXVM PACKET
//
// Header:
//
// 4 bytes  MAGIC = LXVM
// 1 byte   VERSION
// 1 byte   FLAGS
// 4 bytes  PAYLOAD LENGTH
// 32 bytes SHA256(payload)
//
// payload = XOR(bytecode, derived key)
// ============================================================

function packLXVM(
    bytecode,
    scriptId
) {

    const key =
        deriveVMKey(scriptId);

    const encrypted =
        xorBuffer(
            bytecode,
            key
        );

    const hash =
        sha256Buffer(
            bytecode
        );

    const header =
        Buffer.alloc(42);

    header.write(
        "LXVM",
        0,
        4,
        "ascii"
    );

    header.writeUInt8(
        1,
        4
    );

    header.writeUInt8(
        0,
        5
    );

    header.writeUInt32LE(
        encrypted.length,
        6
    );

    hash.copy(
        header,
        10
    );

    return Buffer.concat([
        header,
        encrypted
    ]);
}

// ============================================================
// AUTH API
// ============================================================

app.post(
    "/api/register",
    async (req, res) => {

        try {

            const username =
                normalizeUsername(
                    req.body.username
                );

            const password =
                String(
                    req.body.password || ""
                );

            if (
                !validateUsername(
                    username
                )
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Username must contain 3-32 letters, numbers or underscores."
                    });
            }

            if (
                password.length < 6
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Password must contain at least 6 characters."
                    });
            }

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE username = $1
                    LIMIT 1
                    `,
                    [username]
                );

            if (
                existing.rowCount > 0
            ) {

                return res
                    .status(409)
                    .json({
                        error:
                            "Username already exists."
                    });
            }

            const passwordHash =
                await hashPassword(
                    password
                );

            const inserted =
                await pool.query(
                    `
                    INSERT INTO users
                    (
                        username,
                        password_hash
                    )
                    VALUES
                    (
                        $1,
                        $2
                    )
                    RETURNING id, username
                    `,
                    [
                        username,
                        passwordHash
                    ]
                );

            const user =
                inserted.rows[0];

            const token =
                await createSession(
                    user.id
                );

            setSessionCookie(
                res,
                token
            );

            res.json({
                ok: true,
                username:
                    user.username,
                url:
                    `${BASE_URL}/`,
                userId:
                    user.id
            });

        } catch (err) {

            console.error(
                "[REGISTER]",
                err
            );

            res.status(500)
                .json({
                    error:
                        "Registration failed."
                });
        }
    }
);

// ============================================================

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const username =
                normalizeUsername(
                    req.body.username
                );

            const password =
                String(
                    req.body.password || ""
                );

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        password_hash
                    FROM users
                    WHERE username = $1
                    LIMIT 1
                    `,
                    [username]
                );

            if (
                result.rowCount === 0
            ) {

                return res
                    .status(401)
                    .json({
                        error:
                            "Invalid username or password."
                    });
            }

            const user =
                result.rows[0];

            const valid =
                await verifyPassword(
                    password,
                    user.password_hash
                );

            if (!valid) {

                return res
                    .status(401)
                    .json({
                        error:
                            "Invalid username or password."
                    });
            }

            const token =
                await createSession(
                    user.id
                );

            setSessionCookie(
                res,
                token
            );

            res.json({
                ok: true,
                username:
                    user.username,
                url:
                    `${BASE_URL}/`,
                userId:
                    user.id
            });

        } catch (err) {

            console.error(
                "[LOGIN]",
                err
            );

            res.status(500)
                .json({
                    error:
                        "Login failed."
                });
        }
    }
);

// ============================================================

app.get(
    "/api/me",
    async (req, res) => {

        try {

            const user =
                await getCurrentUser(req);

            if (!user) {

                return res
                    .status(401)
                    .json({
                        error:
                            "Not logged in."
                    });
            }

            res.json({
                ok: true,
                username:
                    user.username,
                url:
                    `${BASE_URL}/`,
                userId:
                    user.id
            });

        } catch (err) {

            console.error(
                "[ME]",
                err
            );

            res.status(500)
                .json({
                    error:
                        "Session check failed."
                });
        }
    }
);

// ============================================================

app.post(
    "/api/logout",
    async (req, res) => {

        try {

            const token =
                getSessionToken(req);

            if (token) {

                await pool.query(
                    `
                    DELETE FROM login_sessions
                    WHERE session_token = $1
                    `,
                    [token]
                );
            }

            clearSessionCookie(
                res
            );

            res.json({
                ok: true
            });

        } catch (err) {

            console.error(
                "[LOGOUT]",
                err
            );

            clearSessionCookie(
                res
            );

            res.json({
                ok: true
            });
        }
    }
);

// ============================================================
// CREATE SCRIPT
// ============================================================

app.post(
    "/api/create",
    requireAuth,
    async (req, res) => {

        try {

            const name =
                String(
                    req.body.name ||
                    "Untitled Script"
                )
                    .trim()
                    .slice(0, 100);

            const source =
                String(
                    req.body.source ||
                    ""
                );

            if (!source.trim()) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Script source cannot be empty."
                    });
            }

            const scriptId =
                await uniqueScriptId();

            // Compile Lua -> custom bytecode.
            const bytecode =
                compileLua(source);

            // Pack custom binary.
            const packet =
                packLXVM(
                    bytecode,
                    scriptId
                );

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
                    vm_version,
                    enabled
                )
                VALUES
                (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    1,
                    1,
                    TRUE
                )
                `,
                [
                    req.user.id,
                    scriptId,
                    name ||
                        "Untitled Script",
                    source,
                    packet
                ]
            );

            res.json({
                success: true,
                id:
                    scriptId,
                loader:
                    `${BASE_URL}/loader/${scriptId}`
            });

        } catch (err) {

            console.error(
                "[CREATE]",
                err
            );

            res.status(400)
                .json({
                    error:
                        err.message ||
                        "Failed to create script."
                });
        }
    }
);

// ============================================================
// LIST USER SCRIPTS
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
                        script_id,
                        name,
                        created_at,
                        updated_at,
                        enabled
                    FROM scripts
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    `,
                    [req.user.id]
                );

            const scripts =
                result.rows.map(
                    script => ({
                        id:
                            script.script_id,

                        name:
                            script.name,

                        loader:
                            `${BASE_URL}/loader/${script.script_id}`,

                        enabled:
                            script.enabled,

                        created_at:
                            script.created_at,

                        updated_at:
                            script.updated_at
                    })
                );

            res.json({
                ok: true,
                scripts
            });

        } catch (err) {

            console.error(
                "[SCRIPTS]",
                err
            );

            res.status(500)
                .json({
                    error:
                        "Failed to load scripts."
                });
        }
    }
);

// ============================================================
// GET ONE USER SCRIPT
// ============================================================

app.get(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const id =
                req.params.id;

            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        name,
                        source,
                        enabled,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE
                        script_id = $1
                        AND user_id = $2
                    LIMIT 1
                    `,
                    [
                        id,
                        req.user.id
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Script not found."
                    });
            }

            const script =
                result.rows[0];

            res.json({
                ok: true,

                script: {
                    id:
                        script.script_id,

                    name:
                        script.name,

                    source:
                        script.source,

                    enabled:
                        script.enabled,

                    created_at:
                        script.created_at,

                    updated_at:
                        script.updated_at
                }
            });

        } catch (err) {

            console.error(
                "[GET SCRIPT]",
                err
            );

            res.status(500)
                .json({
                    error:
                        "Failed to load script."
                });
        }
    }
);

// ============================================================
// EDIT SCRIPT
// ============================================================

app.put(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const id =
                req.params.id;

            const name =
                String(
                    req.body.name ||
                    "Untitled Script"
                )
                    .trim()
                    .slice(0, 100);

            const source =
                String(
                    req.body.source ||
                    ""
                );

            if (!source.trim()) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Script source cannot be empty."
                    });
            }

            // Compile first so invalid source
            // does not overwrite working bytecode.
            const bytecode =
                compileLua(source);

            const packet =
                packLXVM(
                    bytecode,
                    id
                );

            const result =
                await pool.query(
                    `
                    UPDATE scripts
                    SET
                        name = $1,
                        source = $2,
                        bytecode = $3,
                        updated_at = NOW()
                    WHERE
                        script_id = $4
                        AND user_id = $5
                    RETURNING
                        script_id,
                        name,
                        updated_at
                    `,
                    [
                        name,
                        source,
                        packet,
                        id,
                        req.user.id
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Script not found."
                    });
            }

            res.json({
                ok: true,
                script:
                    result.rows[0]
            });

        } catch (err) {

            console.error(
                "[EDIT]",
                err
            );

            res.status(400)
                .json({
                    error:
                        err.message ||
                        "Failed to update script."
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

            const id =
                req.params.id;

            const result =
                await pool.query(
                    `
                    DELETE FROM scripts
                    WHERE
                        script_id = $1
                        AND user_id = $2
                    RETURNING script_id
                    `,
                    [
                        id,
                        req.user.id
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Script not found."
                    });
            }

            res.json({
                ok: true
            });

        } catch (err) {

            console.error(
                "[DELETE]",
                err
            );

            res.status(500)
                .json({
                    error:
                        "Failed to delete script."
                });
        }
    }
);

// ============================================================
// INTERNAL SCRIPT LOOKUP
// ============================================================

async function getEnabledScript(
    scriptId
) {

    const result =
        await pool.query(
            `
            SELECT
                script_id,
                bytecode,
                bytecode_version,
                vm_version,
                enabled
            FROM scripts
            WHERE script_id = $1
            LIMIT 1
            `,
            [scriptId]
        );

    if (
        result.rowCount === 0
    ) {
        return null;
    }

    return result.rows[0];
}

// ============================================================
// VM BINARY ENDPOINT
// ============================================================

app.get(
    "/api/vm/:scriptId",
    async (req, res) => {

        const scriptId =
            req.params.scriptId;

        try {

            const script =
                await getEnabledScript(
                    scriptId
                );

            if (!script) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Script not found."
                    });
            }

            if (!script.enabled) {

                return res
                    .status(403)
                    .json({
                        error:
                            "Script disabled."
                    });
            }

            if (!script.bytecode) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Bytecode unavailable."
                    });
            }

            const ip =
                req.headers["x-forwarded-for"] ||
                req.socket.remoteAddress ||
                null;

            await pool.query(
                `
                INSERT INTO script_access_logs
                (
                    script_id,
                    ip_address,
                    success
                )
                VALUES
                (
                    $1,
                    $2,
                    TRUE
                )
                `,
                [
                    scriptId,
                    ip
                ]
            );

            res.setHeader(
                "Content-Type",
                "application/octet-stream"
            );

            res.setHeader(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            );

            res.setHeader(
                "Pragma",
                "no-cache"
            );

            res.send(
                script.bytecode
            );

        } catch (err) {

            console.error(
                "[VM]",
                err
            );

            res.status(500)
                .json({
                    error:
                        "VM payload error."
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
            req.params.scriptId;

        const code = `
-- LEXINX PROTECT V5
-- L1

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(id)}

local function fetchLayer(path)
    local ok, result = pcall(function()
        return game:HttpGet(
            BASE_URL .. path .. "/" .. SCRIPT_ID
        )
    end)

    if not ok then
        error(
            "LEXINX L1 HTTP ERROR: " ..
            tostring(result)
        )
    end

    return result
end

local source =
    fetchLayer("/api/l2")

local fn, err =
    loadstring(source)

if not fn then
    error(
        "LEXINX L1 LOAD ERROR: " ..
        tostring(err)
    )
end

return fn()
`;

        res.type(
            "text/plain"
        );

        res.send(code);
    }
);

// ============================================================
// L2
// ============================================================

app.get(
    "/api/l2/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const code = `
-- LEXINX PROTECT V5
-- L2

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(id)}

local function nextLayer()
    local ok, result = pcall(function()
        return game:HttpGet(
            BASE_URL ..
            "/api/l3/" ..
            SCRIPT_ID
        )
    end)

    if not ok then
        error(
            "LEXINX L2 HTTP ERROR: " ..
            tostring(result)
        )
    end

    return result
end

local source =
    nextLayer()

local fn, err =
    loadstring(source)

if not fn then
    error(
        "LEXINX L2 LOAD ERROR: " ..
        tostring(err)
    )
end

return fn()
`;

        res.type(
            "text/plain"
        );

        res.send(code);
    }
);

// ============================================================
// L3
// ============================================================

app.get(
    "/api/l3/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const code = `
-- LEXINX PROTECT V5
-- L3

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(id)}

local ok, source =
    pcall(function()
        return game:HttpGet(
            BASE_URL ..
            "/api/l4/" ..
            SCRIPT_ID
        )
    end)

if not ok then
    error(
        "LEXINX L3 HTTP ERROR: " ..
        tostring(source)
    )
end

local fn, err =
    loadstring(source)

if not fn then
    error(
        "LEXINX L3 LOAD ERROR: " ..
        tostring(err)
    )
end

return fn()
`;

        res.type(
            "text/plain"
        );

        res.send(code);
    }
);

// ============================================================
// L4
// ============================================================

app.get(
    "/api/l4/:scriptId",
    async (req, res) => {

        const id =
            req.params.id ||
            req.params.scriptId;

        const code = `
-- LEXINX PROTECT V5
-- L4

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(id)}

local ok, source =
    pcall(function()
        return game:HttpGet(
            BASE_URL ..
            "/api/l5/" ..
            SCRIPT_ID
        )
    end)

if not ok then
    error(
        "LEXINX L4 HTTP ERROR: " ..
        tostring(source)
    )
end

local fn, err =
    loadstring(source)

if not fn then
    error(
        "LEXINX L4 LOAD ERROR: " ..
        tostring(err)
    )
end

return fn()
`;

        res.type(
            "text/plain"
        );

        res.send(code);
    }
);

// ============================================================
// L5
//
// L5 receives the LXVM packet,
// decodes the header,
// derives the same key,
// XOR-decrypts,
// validates SHA256,
// then runs the custom VM.
//
// Transport is Base64 to avoid raw NUL-byte
// problems with some HTTP/executor environments.
// ============================================================

app.get(
    "/api/l5/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const code = `
-- ========================================================
-- LEXINX PROTECT V5
-- L5 CUSTOM VM
-- ========================================================

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(id)}

-- --------------------------------------------------------
-- SHA256 implementation
-- --------------------------------------------------------

local bit = bit32

if not bit then
    error("LEXINX L5: bit32 is required")
end

local function rrotate(x, n)
    return bit.rrotate(x, n)
end

local function sha256(message)

    local K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    }

    local H = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    }

    local bytes = {
        string.byte(
            message,
            1,
            #message
        )
    }

    local bitLen =
        #bytes * 8

    table.insert(
        bytes,
        0x80
    )

    while
        (#bytes + 8) % 64 ~= 0
    do
        table.insert(
            bytes,
            0
        )
    end

    for i = 7, 0, -1 do
        table.insert(
            bytes,
            math.floor(
                bitLen /
                (2 ^ (i * 8))
            ) % 256
        )
    end

    for offset = 1, #bytes, 64 do

        local W = {}

        for i = 0, 15 do

            local p =
                offset +
                i * 4

            W[i] =
                bit.bor(
                    bit.lshift(
                        bytes[p],
                        24
                    ),
                    bit.lshift(
                        bytes[p + 1],
                        16
                    ),
                    bit.lshift(
                        bytes[p + 2],
                        8
                    ),
                    bytes[p + 3]
                )
        end

        for i = 16, 63 do

            local x = W[i - 15]

            local s0 =
                bit.bxor(
                    rrotate(x, 7),
                    rrotate(x, 18),
                    bit.rshift(x, 3)
                )

            local y = W[i - 2]

            local s1 =
                bit.bxor(
                    rrotate(y, 17),
                    rrotate(y, 19),
                    bit.rshift(y, 10)
                )

            W[i] =
                (
                    W[i - 16] +
                    s0 +
                    W[i - 7] +
                    s1
                ) % 4294967296
        end

        local a,b,c,d,e,f,g,h =
            H[1],H[2],H[3],H[4],
            H[5],H[6],H[7],H[8]

        for i = 0, 63 do

            local S1 =
                bit.bxor(
                    rrotate(e, 6),
                    rrotate(e, 11),
                    rrotate(e, 25)
                )

            local ch =
                bit.bxor(
                    bit.band(e, f),
                    bit.band(
                        bit.bnot(e),
                        g
                    )
                )

            local temp1 =
                (
                    h +
                    S1 +
                    ch +
                    K[i + 1] +
                    W[i]
                ) % 4294967296

            local S0 =
                bit.bxor(
                    rrotate(a, 2),
                    rrotate(a, 13),
                    rrotate(a, 22)
                )

            local maj =
                bit.bxor(
                    bit.band(a,b),
                    bit.band(a,c),
                    bit.band(b,c)
                )

            local temp2 =
                (
                    S0 +
                    maj
                ) % 4294967296

            h = g
            g = f
            f = e

            e =
                (
                    d +
                    temp1
                ) % 4294967296

            d = c
            c = b
            b = a

            a =
                (
                    temp1 +
                    temp2
                ) % 4294967296
        end

        H[1] =
            (H[1] + a) % 4294967296

        H[2] =
            (H[2] + b) % 4294967296

        H[3] =
            (H[3] + c) % 4294967296

        H[4] =
            (H[4] + d) % 4294967296

        H[5] =
            (H[5] + e) % 4294967296

        H[6] =
            (H[6] + f) % 4294967296

        H[7] =
            (H[7] + g) % 4294967296

        H[8] =
            (H[8] + h) % 4294967296
    end

    local out = ""

    for i = 1, 8 do
        out =
            out ..
            string.format(
                "%08x",
                H[i]
            )
    end

    return out
end

-- --------------------------------------------------------
-- Base64 decoder
-- --------------------------------------------------------

local function base64decode(data)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ..
        "abcdefghijklmnopqrstuvwxyz" ..
        "0123456789+/"

    data =
        data:gsub(
            "[^" ..
            alphabet ..
            "=]",
            ""
        )

    local result = {}

    for i = 1, #data, 4 do

        local a =
            alphabet:find(
                data:sub(i,i),
                1,
                true
            )

        local b =
            alphabet:find(
                data:sub(i+1,i+1),
                1,
                true
            )

        local c =
            alphabet:find(
                data:sub(i+2,i+2),
                1,
                true
            )

        local d =
            alphabet:find(
                data:sub(i+3,i+3),
                1,
                true
            )

        a = a and a - 1 or 0
        b = b and b - 1 or 0
        c = c and c - 1 or 0
        d = d and d - 1 or 0

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

        table.insert(
            result,
            string.char(x)
        )

        if data:sub(i+2,i+2) ~= "=" then
            table.insert(
                result,
                string.char(y)
            )
        end

        if data:sub(i+3,i+3) ~= "=" then
            table.insert(
                result,
                string.char(z)
            )
        end
    end

    return table.concat(result)
end

-- --------------------------------------------------------
-- Number helpers
-- --------------------------------------------------------

local function u8(s, p)
    return string.byte(s, p)
end

local function u16(s, p)

    local a =
        string.byte(s, p)

    local b =
        string.byte(s, p + 1)

    return a + b * 256
end

local function u32(s, p)

    local a =
        string.byte(s, p)

    local b =
        string.byte(s, p + 1)

    local c =
        string.byte(s, p + 2)

    local d =
        string.byte(s, p + 3)

    return
        a +
        b * 256 +
        c * 65536 +
        d * 16777216
end

-- --------------------------------------------------------
-- VM key
-- --------------------------------------------------------

local function deriveKey(id)

    return sha256(
        "LEXINX-V5-VM|" ..
        id
    )
end

-- SHA256 hex -> raw bytes
local function hexToBytes(hex)

    local out = {}

    for i = 1, #hex, 2 do

        local n =
            tonumber(
                hex:sub(i,i+1),
                16
            )

        table.insert(
            out,
            string.char(n)
        )
    end

    return table.concat(out)
end

-- --------------------------------------------------------
-- Download payload
-- --------------------------------------------------------

local ok, response =
    pcall(function()

        return game:HttpGet(
            BASE_URL ..
            "/api/vm/" ..
            SCRIPT_ID
        )
    end)

if not ok then
    error(
        "LEXINX L5 HTTP ERROR: " ..
        tostring(response)
    )
end

local packet =
    response

-- --------------------------------------------------------
-- Header validation
-- --------------------------------------------------------

if #packet < 42 then
    error(
        "LEXINX L5: Invalid LXVM packet."
    )
end

if packet:sub(1,4) ~= "LXVM" then
    error(
        "LEXINX L5: Invalid LXVM magic."
    )
end

local version =
    u8(packet, 5)

if version ~= 1 then
    error(
        "LEXINX L5: Unsupported VM version."
    )
end

local payloadLength =
    u32(packet, 7)

local expectedHash =
    packet:sub(
        11,
        42
    )

local payloadStart =
    43

local payloadEnd =
    payloadStart +
    payloadLength -
    1

if payloadEnd > #packet then
    error(
        "LEXINX L5: Invalid payload length."
    )
end

local encrypted =
    packet:sub(
        payloadStart,
        payloadEnd
    )

-- --------------------------------------------------------
-- XOR decrypt
-- --------------------------------------------------------

local keyHex =
    deriveKey(
        SCRIPT_ID
    )

local key =
    hexToBytes(
        keyHex
    )

local decoded = {}

for i = 1, #encrypted do

    local a =
        string.byte(
            encrypted,
            i
        )

    local b =
        string.byte(
            key,
            ((i - 1) % #key) + 1
        )

    decoded[i] =
        string.char(
            bit.bxor(a,b)
        )
end

local bytecode =
    table.concat(decoded)

-- --------------------------------------------------------
-- Integrity verification
-- --------------------------------------------------------

local actualHashHex =
    sha256(
        bytecode
    )

local expectedHashHex = ""

for i = 1, #expectedHash do

    expectedHashHex =
        expectedHashHex ..
        string.format(
            "%02x",
            string.byte(
                expectedHash,
                i
            )
        )
end

if actualHashHex ~= expectedHashHex then
    error(
        "LEXINX L5: SHA256 verification failed."
    )
end

-- --------------------------------------------------------
-- Custom VM
-- --------------------------------------------------------

local VM = {}

function VM.run(code)

    local pc = 1
    local stack = {}
    local globals = {}

    local function push(v)
        stack[#stack + 1] = v
    end

    local function pop()

        local n =
            #stack

        if n == 0 then
            return nil
        end

        local v =
            stack[n]

        stack[n] = nil

        return v
    end

    while pc <= #code do

        local opcode =
            string.byte(
                code,
                pc
            )

        pc = pc + 1

        -- NOP
        if opcode == 0x00 then

        -- PUSH_STRING
        elseif opcode == 0x01 then

            local len =
                u16(
                    code,
                    pc
                )

            pc =
                pc + 2

            local value =
                code:sub(
                    pc,
                    pc + len - 1
                )

            pc =
                pc + len

            push(value)

        -- PUSH_NUMBER
        elseif opcode == 0x02 then

            -- IEEE754 little-endian f64 decoder
            local bytes = {}

            for i = 0, 7 do
                bytes[i + 1] =
                    string.byte(
                        code,
                        pc + i
                    )
            end

            pc =
                pc + 8

            local sign =
                bit.band(
                    bytes[8],
                    0x80
                ) ~= 0

            local exponent =
                bit.band(
                    bytes[8],
                    0x7F
                ) * 16 +
                bit.rshift(
                    bytes[7],
                    4
                )

            local mantissa = 0

            local multiplier = 1

            for i = 1, 6 do

                mantissa =
                    mantissa +
                    bytes[i] *
                    multiplier

                multiplier =
                    multiplier * 256
            end

            mantissa =
                mantissa +
                bit.band(
                    bytes[7],
                    0x0F
                ) *
                multiplier

            multiplier =
                multiplier * 16

            local value

            if exponent == 0 then

                value =
                    (
                        mantissa /
                        2^52
                    ) *
                    2^-1022

            elseif exponent == 2047 then

                if mantissa == 0 then
                    value =
                        sign
                        and -math.huge
                        or math.huge
                else
                    value =
                        0/0
                end

            else

                value =
                    (
                        1 +
                        mantissa /
                        2^52
                    ) *
                    2^(exponent - 1023)
            end

            if sign then
                value = -value
            end

            push(value)

        -- PUSH_BOOL
        elseif opcode == 0x03 then

            local value =
                string.byte(
                    code,
                    pc
                )

            pc =
                pc + 1

            push(
                value ~= 0
            )

        -- PUSH_NIL
        elseif opcode == 0x04 then

            push(nil)

        -- GET_GLOBAL
        elseif opcode == 0x10 then

            local len =
                u16(
                    code,
                    pc
                )

            pc =
                pc + 2

            local name =
                code:sub(
                    pc,
                    pc + len - 1
                )

            pc =
                pc + len

            push(
                globals[name]
            )

        -- SET_GLOBAL
        elseif opcode == 0x11 then

            local len =
                u16(
                    code,
                    pc
                )

            pc =
                pc + 2

            local name =
                code:sub(
                    pc,
                    pc + len - 1
                )

            pc =
                pc + len

            globals[name] =
                pop()

        -- ADD
        elseif opcode == 0x20 then

            local b =
                pop()

            local a =
                pop()

            push(
                a + b
            )

        -- SUB
        elseif opcode == 0x21 then

            local b =
                pop()

            local a =
                pop()

            push(
                a - b
            )

        -- MUL
        elseif opcode == 0x22 then

            local b =
                pop()

            local a =
                pop()

            push(
                a * b
            )

        -- DIV
        elseif opcode == 0x23 then

            local b =
                pop()

            local a =
                pop()

            push(
                a / b
            )

        -- CONCAT
        elseif opcode == 0x30 then

            local b =
                pop()

            local a =
                pop()

            push(
                tostring(a) ..
                tostring(b)
            )

        -- CALL_GLOBAL
        elseif opcode == 0x40 then

            local len =
                u16(
                    code,
                    pc
                )

            pc =
                pc + 2

            local name =
                code:sub(
                    pc,
                    pc + len - 1
                )

            pc =
                pc + len

            local argc =
                string.byte(
                    code,
                    pc
                )

            pc =
                pc + 1

            local args = {}

            for i = argc, 1, -1 do
                args[i] =
                    pop()
            end

            local fn =
                globals[name]

            if name == "print" then

                print(
                    table.unpack(args)
                )

            elseif
                type(fn) == "function"
            then

                local result =
                    fn(
                        table.unpack(args)
                    )

                push(result)

            else

                error(
                    "LEXINX VM: Unknown global call: " ..
                    tostring(name)
                )
            end

        -- POP
        elseif opcode == 0x50 then

            pop()

        -- RETURN
        elseif opcode == 0xFF then

            return pop()

        else

            error(
                "LEXINX VM: Unknown opcode 0x" ..
                string.format(
                    "%02X",
                    opcode
                )
            )
        end
    end

    return nil
end

-- Built-in VM globals.
local globals = {}

-- Execute.
return VM.run(bytecode)
`;

        res.type(
            "text/plain"
        );

        res.send(code);
    }
);

// ============================================================
// DYNAMIC LOADER
// ============================================================

app.get(
    "/loader/:scriptId",
    async (req, res) => {

        const scriptId =
            req.params.scriptId;

        try {

            const script =
                await getEnabledScript(
                    scriptId
                );

            if (!script) {

                return res
                    .status(404)
                    .type("text/plain")
                    .send(
                        "LEXINX: Script not found."
                    );
            }

            if (!script.enabled) {

                return res
                    .status(403)
                    .type("text/plain")
                    .send(
                        "LEXINX: Script disabled."
                    );
            }

            const loader = `
-- ========================================================
-- LEXINX PROTECT V5
-- Dynamic Loader
-- ========================================================

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local l1, err =
    pcall(function()
        return game:HttpGet(
            BASE_URL ..
            "/api/l1/" ..
            SCRIPT_ID
        )
    end)

if not l1 then
    error(
        "LEXINX LOADER HTTP ERROR: " ..
        tostring(err)
    )
end

local fn, loadErr =
    loadstring(err)

if not fn then
    error(
        "LEXINX LOADER ERROR: " ..
        tostring(loadErr)
    )
end

return fn()
`;

            res.type(
                "text/plain"
            );

            res.setHeader(
                "Cache-Control",
                "no-store"
            );

            res.send(
                loader
            );

        } catch (err) {

            console.error(
                "[LOADER]",
                err
            );

            res.status(500)
                .type("text/plain")
                .send(
                    "LEXINX: Loader error."
                );
        }
    }
);

// ============================================================
// HEALTH
// ============================================================

app.get(
    "/health",
    async (req, res) => {

        try {

            await pool.query(
                "SELECT 1"
            );

            res.json({
                ok: true,
                service:
                    "LEXINX PROTECT V5",
                status:
                    "online",
                database:
                    "connected",
                vm:
                    "LXVM V1"
            });

        } catch {

            res.status(503)
                .json({
                    ok: false,
                    service:
                        "LEXINX PROTECT V5",
                    status:
                        "online",
                    database:
                        "disconnected"
                });
        }
    }
);

// ============================================================
// 404
// ============================================================

app.use(
    (req, res) => {

        if (
            req.path.startsWith("/api/")
        ) {

            return res
                .status(404)
                .json({
                    error:
                        "API endpoint not found."
                });
        }

        res.status(404)
            .type("text/plain")
            .send(
                "LEXINX: Not Found"
            );
    }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "[LEXINX ERROR]",
            err
        );

        if (
            res.headersSent
        ) {
            return next(err);
        }

        res.status(500)
            .json({
                error:
                    "Internal server error."
            });
    }
);

// ============================================================
// START
// ============================================================

async function start() {

    try {

        if (process.env.DATABASE_URL) {

            await pool.query(
                "SELECT 1"
            );

            console.log(
                "[LEXINX] PostgreSQL connected."
            );
        }

        app.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    "========================================"
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
                    ` BASE: ${BASE_URL}`
                );

                console.log(
                    " VM: LXVM V1"
                );

                console.log(
                    "========================================"
                );
            }
        );

    } catch (err) {

        console.error(
            "[LEXINX] Startup error:",
            err
        );

        process.exit(1);
    }
}

start();
