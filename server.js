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

/* =========================================================
   EXPRESS
========================================================= */

app.use(express.json({ limit: "5mb" }));

app.use(express.static(
    path.join(__dirname, "public")
));

/* =========================================================
   DATABASE
========================================================= */

if (!process.env.DATABASE_URL) {
    console.warn(
        "[LEXINX] WARNING: DATABASE_URL is not configured."
    );
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl:
        process.env.NODE_ENV === "production"
            ? { rejectUnauthorized: false }
            : false
});

/* =========================================================
   DATABASE INIT
========================================================= */

async function initDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username VARCHAR(32) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS scripts (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id)
                ON DELETE CASCADE,

            script_id VARCHAR(64) NOT NULL UNIQUE,

            name VARCHAR(100)
                NOT NULL DEFAULT 'My Script',

            source TEXT NOT NULL DEFAULT '',

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
        );

        CREATE INDEX IF NOT EXISTS
        idx_scripts_user_id
        ON scripts(user_id);

        CREATE INDEX IF NOT EXISTS
        idx_scripts_script_id
        ON scripts(script_id);

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
        );

        CREATE INDEX IF NOT EXISTS
        idx_login_sessions_token
        ON login_sessions(session_token);

        CREATE INDEX IF NOT EXISTS
        idx_login_sessions_user_id
        ON login_sessions(user_id);

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
        );

        CREATE INDEX IF NOT EXISTS
        idx_access_logs_script
        ON script_access_logs(script_id);

        CREATE INDEX IF NOT EXISTS
        idx_access_logs_user
        ON script_access_logs(user_id);
    `);

    console.log(
        "[LEXINX] Database initialized."
    );
}

/* =========================================================
   PASSWORD HASH
========================================================= */

function hashPassword(password) {

    const salt =
        crypto.randomBytes(16);

    const hash =
        crypto.scryptSync(
            password,
            salt,
            64
        );

    return (
        "scrypt$" +
        salt.toString("hex") +
        "$" +
        hash.toString("hex")
    );
}

function verifyPassword(
    password,
    stored
) {

    try {

        const parts =
            stored.split("$");

        if (
            parts.length !== 3 ||
            parts[0] !== "scrypt"
        ) {
            return false;
        }

        const salt =
            Buffer.from(
                parts[1],
                "hex"
            );

        const expected =
            Buffer.from(
                parts[2],
                "hex"
            );

        const actual =
            crypto.scryptSync(
                password,
                salt,
                expected.length
            );

        return crypto.timingSafeEqual(
            actual,
            expected
        );

    } catch {

        return false;
    }
}

/* =========================================================
   SESSION
========================================================= */

function createSessionToken() {

    return crypto
        .randomBytes(48)
        .toString("hex");
}

async function createSession(
    userId
) {

    const token =
        createSessionToken();

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

    return match
        ? decodeURIComponent(match[1])
        : null;
}

function setSessionCookie(
    res,
    token
) {

    res.setHeader(
        "Set-Cookie",
        [
            `lexinx_session=${encodeURIComponent(token)}`,
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

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

async function requireAuth(
    req,
    res,
    next
) {

    try {

        const token =
            getSessionToken(req);

        if (!token) {

            return res
                .status(401)
                .json({
                    error:
                        "Not authenticated."
                });
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
                    AND (
                        s.expires_at IS NULL
                        OR s.expires_at > NOW()
                    )
                LIMIT 1
                `,
                [token]
            );

        if (
            result.rows.length === 0
        ) {

            return res
                .status(401)
                .json({
                    error:
                        "Session expired."
                });
        }

        req.user =
            result.rows[0];

        await pool.query(
            `
            UPDATE login_sessions
            SET last_seen_at = NOW()
            WHERE session_token = $1
            `,
            [token]
        );

        next();

    } catch (error) {

        console.error(
            "[AUTH]",
            error
        );

        res
            .status(500)
            .json({
                error:
                    "Authentication service error."
            });
    }
}

/* =========================================================
   SCRIPT ID
========================================================= */

function generateScriptId() {

    return crypto
        .randomBytes(18)
        .toString("base64url");
}

async function createUniqueScriptId() {

    for (let i = 0; i < 20; i++) {

        const id =
            generateScriptId();

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

        if (
            result.rows.length === 0
        ) {
            return id;
        }
    }

    throw new Error(
        "Unable to generate unique script ID."
    );
}

/* =========================================================
   LUA VM OPCODES
========================================================= */

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

/* =========================================================
   BYTECODE HELPERS
========================================================= */

function writeU32(value) {

    const b =
        Buffer.alloc(4);

    b.writeUInt32BE(
        value >>> 0,
        0
    );

    return b;
}

function writeF64(value) {

    const b =
        Buffer.alloc(8);

    b.writeDoubleBE(
        Number(value),
        0
    );

    return b;
}

function writeString(value) {

    const data =
        Buffer.from(
            String(value),
            "utf8"
        );

    return Buffer.concat([
        writeU32(data.length),
        data
    ]);
}

/* =========================================================
   SIMPLE LUA COMPILER
========================================================= */

function compileLua(source) {

    const instructions = [];

    const text =
        String(source)
        .replace(
            /--[^\r\n]*/g,
            ""
        )
        .trim();

    /*
        print("hello")
        print('hello')
    */

    const printRegex =
        /^print\s*\(\s*(['"])([\s\S]*?)\1\s*\)\s*$/;

    let match =
        text.match(printRegex);

    if (match) {

        const value =
            match[2];

        instructions.push(
            Buffer.from([
                OP.PUSH_STRING
            ])
        );

        instructions.push(
            writeString(value)
        );

        instructions.push(
            Buffer.from([
                OP.CALL_GLOBAL
            ])
        );

        instructions.push(
            writeString("print")
        );

        instructions.push(
            Buffer.from([
                0x01
            ])
        );

        instructions.push(
            Buffer.from([
                OP.RETURN
            ])
        );

        return Buffer.concat(
            instructions
        );
    }

    /*
        return "hello"
        return 'hello'
    */

    const returnString =
        /^return\s+(['"])([\s\S]*?)\1\s*$/;

    match =
        text.match(
            returnString
        );

    if (match) {

        instructions.push(
            Buffer.from([
                OP.PUSH_STRING
            ])
        );

        instructions.push(
            writeString(match[2])
        );

        instructions.push(
            Buffer.from([
                OP.RETURN
            ])
        );

        return Buffer.concat(
            instructions
        );
    }

    /*
        return true / false
    */

    const returnBool =
        /^return\s+(true|false)\s*$/;

    match =
        text.match(
            returnBool
        );

    if (match) {

        instructions.push(
            Buffer.from([
                OP.PUSH_BOOL,
                match[1] === "true"
                    ? 1
                    : 0
            ])
        );

        instructions.push(
            Buffer.from([
                OP.RETURN
            ])
        );

        return Buffer.concat(
            instructions
        );
    }

    /*
        return number
    */

    const returnNumber =
        /^return\s+(-?(?:\d+(?:\.\d*)?|\.\d+))\s*$/;

    match =
        text.match(
            returnNumber
        );

    if (match) {

        instructions.push(
            Buffer.from([
                OP.PUSH_NUMBER
            ])
        );

        instructions.push(
            writeF64(
                Number(match[1])
            )
        );

        instructions.push(
            Buffer.from([
                OP.RETURN
            ])
        );

        return Buffer.concat(
            instructions
        );
    }

    /*
        Empty source
    */

    if (!text) {

        return Buffer.from([
            OP.PUSH_NIL,
            OP.RETURN
        ]);
    }

    throw new Error(
        "Unsupported Lua syntax in prototype compiler."
    );
}

/* =========================================================
   VM KEY
========================================================= */

function deriveVMKey(
    scriptId
) {

    return crypto
        .createHash("sha256")
        .update(
            "LEXINX-V5-VM|" +
            scriptId,
            "utf8"
        )
        .digest();
}

/* =========================================================
   XOR
========================================================= */

function xorBuffer(
    data,
    key
) {

    const out =
        Buffer.alloc(
            data.length
        );

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

/* =========================================================
   PACK LXVM
========================================================= */

function packLXVM(
    bytecode,
    scriptId
) {

    const key =
        deriveVMKey(
            scriptId
        );

    const encrypted =
        xorBuffer(
            bytecode,
            key
        );

    const checksum =
        crypto
            .createHash("sha256")
            .update(bytecode)
            .digest();

    const header =
        Buffer.concat([

            Buffer.from(
                "LXVM",
                "ascii"
            ),

            Buffer.from([
                1
            ]),

            Buffer.from([
                1
            ]),

            writeU32(
                encrypted.length
            ),

            checksum
        ]);

    return Buffer.concat([
        header,
        encrypted
    ]);
}

/* =========================================================
   UNPACK LXVM
========================================================= */

function unpackLXVM(
    packet,
    scriptId
) {

    if (
        !Buffer.isBuffer(packet)
    ) {

        throw new Error(
            "Invalid LXVM packet."
        );
    }

    if (
        packet.length < 42
    ) {

        throw new Error(
            "LXVM packet too small."
        );
    }

    const magic =
        packet
        .subarray(0, 4)
        .toString("ascii");

    if (magic !== "LXVM") {

        throw new Error(
            "Invalid LXVM magic."
        );
    }

    const version =
        packet[4];

    if (version !== 1) {

        throw new Error(
            "Unsupported LXVM version."
        );
    }

    const payloadLength =
        packet.readUInt32BE(6);

    const checksum =
        packet.subarray(
            10,
            42
        );

    const encrypted =
        packet.subarray(42);

    if (
        encrypted.length !==
        payloadLength
    ) {

        throw new Error(
            "Invalid LXVM payload length."
        );
    }

    const key =
        deriveVMKey(
            scriptId
        );

    const bytecode =
        xorBuffer(
            encrypted,
            key
        );

    const actual =
        crypto
            .createHash("sha256")
            .update(bytecode)
            .digest();

    if (
        !crypto.timingSafeEqual(
            actual,
            checksum
        )
    ) {

        throw new Error(
            "LXVM checksum verification failed."
        );
    }

    return bytecode;
}

/* =========================================================
   AUTH API
========================================================= */

app.post(
    "/api/register",
    async (req, res) => {

        try {

            const username =
                String(
                    req.body?.username || ""
                ).trim();

            const password =
                String(
                    req.body?.password || ""
                );

            if (
                !/^[A-Za-z0-9_]{3,32}$/
                    .test(username)
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Username must be 3-32 characters and contain only letters, numbers, or underscore."
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

            if (
                exists.rows.length
            ) {

                return res
                    .status(409)
                    .json({
                        error:
                            "Username already exists."
                    });
            }

            const passwordHash =
                hashPassword(
                    password
                );

            const created =
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
                    RETURNING
                        id,
                        username
                    `,
                    [
                        username,
                        passwordHash
                    ]
                );

            const user =
                created.rows[0];

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
                    `${BASE_URL}/`
            });

        } catch (error) {

            console.error(
                "[REGISTER]",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Registration failed."
                });
        }
    }
);

/* =========================================================
   LOGIN API
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const username =
                String(
                    req.body?.username || ""
                ).trim();

            const password =
                String(
                    req.body?.password || ""
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

            if (
                result.rows.length === 0
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

            if (
                !verifyPassword(
                    password,
                    user.password_hash
                )
            ) {

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
                    `${BASE_URL}/`
            });

        } catch (error) {

            console.error(
                "[LOGIN]",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Login failed."
                });
        }
    }
);

/* =========================================================
   ME
========================================================= */

app.get(
    "/api/me",
    async (req, res) => {

        try {

            const token =
                getSessionToken(req);

            if (!token) {

                return res.json({
                    ok: false
                });
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
                    WHERE
                        s.session_token = $1
                        AND (
                            s.expires_at IS NULL
                            OR s.expires_at > NOW()
                        )
                    LIMIT 1
                    `,
                    [token]
                );

            if (
                result.rows.length === 0
            ) {

                return res.json({
                    ok: false
                });
            }

            res.json({
                ok: true,
                username:
                    result.rows[0].username,
                url:
                    `${BASE_URL}/`
            });

        } catch (error) {

            console.error(
                "[ME]",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Session check failed."
                });
        }
    }
);

/* =========================================================
   LOGOUT
========================================================= */

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

        } catch (error) {

            console.error(
                "[LOGOUT]",
                error
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

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/create",
    requireAuth,
    async (req, res) => {

        try {

            const name =
                String(
                    req.body?.name ||
                    "Untitled Script"
                )
                .trim()
                .slice(0, 100);

            const source =
                String(
                    req.body?.source ||
                    ""
                );

            if (
                !source.trim()
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Script source cannot be empty."
                    });
            }

            const scriptId =
                await createUniqueScriptId();

            const bytecode =
                compileLua(
                    source
                );

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
                    name || "Untitled Script",
                    source,
                    packet
                ]
            );

            res.json({
                ok: true,

                id:
                    scriptId,

                loader:
                    `${BASE_URL}/loader/${scriptId}`
            });

        } catch (error) {

            console.error(
                "[CREATE]",
                error
            );

            res
                .status(400)
                .json({
                    error:
                        error.message ||
                        "Create failed."
                });
        }
    }
);

/* =========================================================
   LIST USER SCRIPTS
========================================================= */

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
                        name
                    FROM scripts
                    WHERE
                        user_id = $1
                        AND enabled = TRUE
                    ORDER BY
                        created_at DESC
                    `,
                    [req.user.id]
                );

            res.json({
                ok: true,

                scripts:
                    result.rows.map(
                        row => ({
                            id:
                                row.script_id,

                            name:
                                row.name,

                            loader:
                                `${BASE_URL}/loader/${row.script_id}`
                        })
                    )
            });

        } catch (error) {

            console.error(
                "[LIST]",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Failed to load scripts."
                });
        }
    }
);

/* =========================================================
   GET SINGLE SCRIPT
========================================================= */

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
                        source
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
                result.rows.length === 0
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
                        script.source
                }
            });

        } catch (error) {

            console.error(
                "[GET SCRIPT]",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Failed to load script."
                });
        }
    }
);

/* =========================================================
   UPDATE SCRIPT
========================================================= */

app.put(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const id =
                req.params.id;

            const name =
                String(
                    req.body?.name ||
                    "Untitled Script"
                )
                .trim()
                .slice(0, 100);

            const source =
                String(
                    req.body?.source ||
                    ""
                );

            if (
                !source.trim()
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Script source cannot be empty."
                    });
            }

            /*
                Compile first so an invalid
                source does not replace the
                existing bytecode.
            */

            const bytecode =
                compileLua(
                    source
                );

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
                    RETURNING script_id
                    `,
                    [
                        name || "Untitled Script",
                        source,
                        packet,
                        id,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
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

        } catch (error) {

            console.error(
                "[UPDATE]",
                error
            );

            res
                .status(400)
                .json({
                    error:
                        error.message ||
                        "Save failed."
                });
        }
    }
);

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

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
                        req.params.id,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
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

        } catch (error) {

            console.error(
                "[DELETE]",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Delete failed."
                });
        }
    }
);

/* =========================================================
   VM BINARY ENDPOINT
========================================================= */

app.get(
    "/api/vm/:scriptId",
    async (req, res) => {

        const scriptId =
            req.params.scriptId;

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        bytecode
                    FROM scripts
                    WHERE
                        script_id = $1
                        AND enabled = TRUE
                    LIMIT 1
                    `,
                    [scriptId]
                );

            if (
                result.rows.length === 0
            ) {

                return res
                    .status(404)
                    .send(
                        "LEXINX SCRIPT NOT FOUND"
                    );
            }

            const packet =
                result.rows[0].bytecode;

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
                    req.ip
                ]
            );

            /*
                Binary packet.
                Base64 transport can be enabled
                later if an executor corrupts
                raw NUL bytes.
            */

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
                "[VM]",
                error
            );

            res
                .status(500)
                .send(
                    "LEXINX VM ERROR"
                );
        }
    }
);

/* =========================================================
   DYNAMIC LAYERS
========================================================= */

function layerCode(
    current,
    next,
    scriptId
) {

    return `
-- LEXINX PROTECT V5
-- ${current}

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local payload = game:HttpGet(
    BASE_URL .. "/api/${next}/" .. SCRIPT_ID
)

local fn, err = loadstring(payload)

if not fn then
    error(
        "LEXINX ${current} ERROR: " ..
        tostring(err)
    )
end

return fn()
`;
}

/* =========================================================
   L1
========================================================= */

app.get(
    "/api/l1/:scriptId",
    (req, res) => {

        res.type("text/plain");

        res.send(
            layerCode(
                "L1",
                "l2",
                req.params.scriptId
            )
        );
    }
);

/* =========================================================
   L2
========================================================= */

app.get(
    "/api/l2/:scriptId",
    (req, res) => {

        res.type("text/plain");

        res.send(
            layerCode(
                "L2",
                "l3",
                req.params.scriptId
            )
        );
    }
);

/* =========================================================
   L3
========================================================= */

app.get(
    "/api/l3/:scriptId",
    (req, res) => {

        res.type("text/plain");

        res.send(
            layerCode(
                "L3",
                "l4",
                req.params.scriptId
            )
        );
    }
);

/* =========================================================
   L4
========================================================= */

app.get(
    "/api/l4/:scriptId",
    (req, res) => {

        res.type("text/plain");

        res.send(
            layerCode(
                "L4",
                "l5",
                req.params.scriptId
            )
        );
    }
);

/* =========================================================
   L5
========================================================= */

app.get(
    "/api/l5/:scriptId",
    (req, res) => {

        const scriptId =
            req.params.scriptId;

        /*
            L5 receives the LXVM packet,
            parses it, derives the same key,
            XOR-decrypts it and verifies
            SHA-256.

            Lua-side VM implementation is
            intentionally kept small.
        */

        const code = `
-- LEXINX PROTECT V5
-- L5 CUSTOM VM

local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local raw = game:HttpGet(
    BASE_URL .. "/api/vm/" .. SCRIPT_ID
)

-- The executor must expose the response
-- as a byte-preserving Lua string.

local function readU32BE(s, p)
    local a,b,c,d =
        string.byte(
            s,
            p,
            p + 3
        )

    if not a then
        error("LXVM truncated")
    end

    return
        a * 16777216 +
        b * 65536 +
        c * 256 +
        d
end

local function readU8(s, p)
    local n =
        string.byte(s, p)

    if not n then
        error("LXVM truncated")
    end

    return n
end

local function readString(s, p)

    local len =
        readU32BE(
            s,
            p
        )

    p = p + 4

    local value =
        string.sub(
            s,
            p,
            p + len - 1
        )

    return value,
        p + len
end

if string.sub(raw, 1, 4) ~= "LXVM" then
    error("LEXINX: Invalid LXVM")
end

local version =
    readU8(raw, 5)

if version ~= 1 then
    error("LEXINX: Unsupported VM version")
end

local payloadLength =
    readU32BE(raw, 7)

local encrypted =
    string.sub(
        raw,
        43,
        42 + payloadLength
    )

if #encrypted ~= payloadLength then
    error("LEXINX: Invalid payload")
end

-- SHA-256 is intentionally expected
-- from the executor environment.
-- The VM refuses to execute if the
-- required hashing function is absent.

local sha256 =
    (crypt and crypt.hash) or
    (syn and syn.crypt and syn.crypt.hash)

if not sha256 then
    error(
        "LEXINX: SHA-256 API unavailable"
    )
end

local keyMaterial =
    "LEXINX-V5-VM|" ..
    SCRIPT_ID

local key =
    sha256(keyMaterial)

-- Normalize hex SHA-256 into bytes
local function hexToBytes(hex)

    local out = {}

    for i = 1, #hex, 2 do

        out[#out + 1] =
            string.char(
                tonumber(
                    string.sub(
                        hex,
                        i,
                        i + 1
                    ),
                    16
                )
            )
    end

    return table.concat(out)
end

key = hexToBytes(key)

local decrypted = {}

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

    decrypted[i] =
        string.char(
            a ~ b
        )
end

local bytecode =
    table.concat(decrypted)

-- =====================================================
-- CUSTOM VM
-- =====================================================

local pc = 1
local stack = {}

local function push(v)
    stack[#stack + 1] = v
end

local function pop()

    local n = #stack

    local v =
        stack[n]

    stack[n] = nil

    return v
end

while pc <= #bytecode do

    local op =
        string.byte(
            bytecode,
            pc
        )

    pc = pc + 1

    if op == 0x00 then

        -- NOP

    elseif op == 0x01 then

        local value

        value, pc =
            readString(
                bytecode,
                pc
            )

        push(value)

    elseif op == 0x03 then

        local value =
            readU8(
                bytecode,
                pc
            )

        pc = pc + 1

        push(
            value ~= 0
        )

    elseif op == 0x04 then

        push(nil)

    elseif op == 0x40 then

        local name

        name, pc =
            readString(
                bytecode,
                pc
            )

        local argc =
            readU8(
                bytecode,
                pc
            )

        pc = pc + 1

        local args = {}

        for i = argc, 1, -1 do
            args[i] = pop()
        end

        if name == "print" then
            print(
                table.unpack(args)
            )
        else
            error(
                "LEXINX VM: Unknown global " ..
                tostring(name)
            )
        end

    elseif op == 0xFF then

        return pop()

    else

        error(
            "LEXINX VM: Unknown opcode " ..
            tostring(op)
        )
    end
end
`;

        res.type(
            "text/plain"
        );

        res.send(code);
    }
);

/* =========================================================
   DYNAMIC LOADER
========================================================= */

app.get(
    "/loader/:scriptId",
    async (req, res) => {

        try {

            const scriptId =
                req.params.scriptId;

            const result =
                await pool.query(
                    `
                    SELECT script_id
                    FROM scripts
                    WHERE
                        script_id = $1
                        AND enabled = TRUE
                    LIMIT 1
                    `,
                    [scriptId]
                );

            if (
                result.rows.length === 0
            ) {

                return res
                    .status(404)
                    .type("text/plain")
                    .send(
                        "LEXINX SCRIPT NOT FOUND"
                    );
            }

            const loader = `
local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local l1 = game:HttpGet(
    BASE_URL .. "/api/l1/" .. SCRIPT_ID
)

local fn, err = loadstring(l1)

if not fn then
    error(
        "LEXINX LOADER ERROR: " ..
        tostring(err)
    )
end

return fn()
`;

            res
                .type("text/plain")
                .set(
                    "Cache-Control",
                    "no-store"
                )
                .send(loader);

        } catch (error) {

            console.error(
                "[LOADER]",
                error
            );

            res
                .status(500)
                .type("text/plain")
                .send(
                    "LEXINX LOADER ERROR"
                );
        }
    }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/health",
    async (req, res) => {

        try {

            await pool.query(
                "SELECT 1"
            );

            res.json({
                ok: true,
                server:
                    "LEXINX PROTECT V5",
                status:
                    "SERVER ONLINE",
                database:
                    "ONLINE",
                vm:
                    "CUSTOM VM",
                time:
                    new Date().toISOString()
            });

        } catch (error) {

            res
                .status(503)
                .json({
                    ok: false,
                    server:
                        "LEXINX PROTECT V5",
                    status:
                        "SERVER ONLINE",
                    database:
                        "OFFLINE"
                });
        }
    }
);

/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        res
            .status(404)
            .json({
                error:
                    "Not found."
            });
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "[SERVER ERROR]",
            error
        );

        if (
            res.headersSent
        ) {
            return next(error);
        }

        res
            .status(500)
            .json({
                error:
                    "Internal server error."
            });
    }
);

/* =========================================================
   START
========================================================= */

async function start() {

    try {

        await initDatabase();

        app.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log("");
                console.log(
                    "===================================="
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
                    " VM: CUSTOM LXVM"
                );

                console.log(
                    "===================================="
                );

                console.log("");
            }
        );

    } catch (error) {

        console.error(
            "[LEXINX] STARTUP ERROR:"
        );

        console.error(
            error
        );

        process.exit(1);
    }
}

start();
