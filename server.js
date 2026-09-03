"use strict";

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

app.set("trust proxy", true);

app.use(express.json({
    limit: "10mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "10mb"
}));

// ============================================================
// CONFIG
// ============================================================

const PORT = process.env.PORT || 3000;

const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://lexinx-protect-v230.vercel.app";

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error("[LEXINX] DATABASE_URL is missing");
}

// ============================================================
// POSTGRESQL
// ============================================================

const pool = new Pool({
    connectionString: DATABASE_URL,

    ssl: DATABASE_URL
        ? {
            rejectUnauthorized: false
        }
        : false,

    max: 10,

    idleTimeoutMillis: 30000,

    connectionTimeoutMillis: 10000
});

pool.on("error", (err) => {
    console.error("[POSTGRES]", err);
});

// ============================================================
// GENERAL HELPERS
// ============================================================

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function now() {
    return Date.now();
}

function base64Encode(value) {
    return Buffer
        .from(String(value), "utf8")
        .toString("base64");
}

function base64Decode(value) {
    return Buffer
        .from(String(value), "base64")
        .toString("utf8");
}

function safeEqual(a, b) {
    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const aa = Buffer.from(a);
    const bb = Buffer.from(b);

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.timingSafeEqual(aa, bb);
}

function hashPassword(password) {
    const salt = crypto
        .randomBytes(16)
        .toString("hex");

    const hash = crypto
        .scryptSync(
            password,
            salt,
            64
        )
        .toString("hex");

    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    try {
        const parts = stored.split(":");

        if (parts.length !== 2) {
            return false;
        }

        const salt = parts[0];
        const original = Buffer.from(
            parts[1],
            "hex"
        );

        const calculated = crypto.scryptSync(
            password,
            salt,
            64
        );

        if (
            calculated.length !==
            original.length
        ) {
            return false;
        }

        return crypto.timingSafeEqual(
            calculated,
            original
        );
    } catch {
        return false;
    }
}

function getIP(req) {
    return (
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.headers["x-real-ip"] ||
        req.socket?.remoteAddress ||
        null
    );
}

function getAuthToken(req) {
    const authorization =
        req.headers.authorization;

    if (
        authorization &&
        authorization.startsWith("Bearer ")
    ) {
        return authorization
            .slice(7)
            .trim();
    }

    if (req.headers["x-session-token"]) {
        return req.headers[
            "x-session-token"
        ];
    }

    if (req.body?.token) {
        return req.body.token;
    }

    if (req.query?.token) {
        return req.query.token;
    }

    return null;
}

// ============================================================
// LOGIN SESSION
// ============================================================

async function getLoginSession(req) {
    const token = getAuthToken(req);

    if (!token) {
        return null;
    }

    const result = await pool.query(
        `
        SELECT
            ls.id,
            ls.user_id,
            ls.session_token,
            ls.expires_at,
            ls.last_seen_at,
            u.username
        FROM login_sessions ls
        INNER JOIN users u
            ON u.id = ls.user_id
        WHERE ls.session_token = $1
          AND ls.expires_at > NOW()
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
        WHERE id = $1
        `,
        [result.rows[0].id]
    );

    return result.rows[0];
}

async function requireAuth(req, res, next) {
    try {
        const session =
            await getLoginSession(req);

        if (!session) {
            return res.status(401).json({
                success: false,
                error: "Unauthorized"
            });
        }

        req.session = session;

        req.user = {
            id: session.user_id,
            username: session.username
        };

        next();
    } catch (err) {
        console.error(
            "[AUTH]",
            err
        );

        res.status(500).json({
            success: false,
            error: "Authentication error"
        });
    }
}

// ============================================================
// LOADER SESSION HELPERS
// ============================================================

async function createLoaderSession(
    scriptId,
    req
) {
    const token = randomHex(48);

    const stageToken = randomHex(32);

    const expiresSeconds =
        Number(
            process.env.LOADER_SESSION_SECONDS ||
            300
        );

    const result = await pool.query(
        `
        INSERT INTO loader_sessions
        (
            session_token,
            script_id,
            ip_address,
            current_stage,
            stage_token,
            expires_at,
            created_at,
            last_seen_at
        )
        VALUES
        (
            $1,
            $2,
            $3,
            1,
            $4,
            NOW() +
                ($5 * INTERVAL '1 second'),
            NOW(),
            NOW()
        )
        RETURNING
            id,
            session_token,
            script_id,
            current_stage,
            stage_token,
            expires_at
        `,
        [
            token,
            scriptId,
            getIP(req),
            stageToken,
            expiresSeconds
        ]
    );

    return result.rows[0];
}

async function getLoaderSession(token) {
    if (!token) {
        return null;
    }

    const result = await pool.query(
        `
        SELECT
            id,
            session_token,
            script_id,
            ip_address,
            current_stage,
            stage_token,
            expires_at,
            created_at,
            last_seen_at
        FROM loader_sessions
        WHERE session_token = $1
          AND expires_at > NOW()
        LIMIT 1
        `,
        [token]
    );

    if (!result.rows.length) {
        return null;
    }

    return result.rows[0];
}

async function updateLoaderStage(
    id,
    stage,
    newToken
) {
    const result = await pool.query(
        `
        UPDATE loader_sessions
        SET
            current_stage = $1,
            stage_token = $2,
            last_seen_at = NOW()
        WHERE id = $3
          AND expires_at > NOW()
        RETURNING *
        `,
        [
            stage,
            newToken,
            id
        ]
    );

    return result.rows[0] || null;
}

async function deleteLoaderSession(token) {
    await pool.query(
        `
        DELETE FROM loader_sessions
        WHERE session_token = $1
        `,
        [token]
    );
}

// ============================================================
// ACCESS LOG
// ============================================================

async function writeAccessLog({
    userId = null,
    scriptId,
    req,
    success,
    stage = null
}) {
    try {
        await pool.query(
            `
            INSERT INTO script_access_logs
            (
                user_id,
                script_id,
                ip_address,
                success,
                stage,
                created_at
            )
            VALUES
            (
                $1,
                $2,
                $3,
                $4,
                $5,
                NOW()
            )
            `,
            [
                userId,
                scriptId,
                getIP(req),
                success,
                stage
            ]
        );
    } catch (err) {
        console.error(
            "[ACCESS LOG]",
            err.message
        );
    }
}

// ============================================================
// ROOT
// ============================================================

app.get("/", (req, res) => {
    res.status(200).send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>LEXINX PROTECT</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;

    display: flex;
    align-items: center;
    justify-content: center;

    background:
        radial-gradient(
            circle at center,
            #151515 0%,
            #070707 45%,
            #000 100%
        );

    color: #fff;
    font-family: Arial, sans-serif;
}

.box {
    width: min(600px, 92%);
    text-align: center;
    padding: 45px 30px;

    border: 1px solid #292929;
    border-radius: 18px;

    background: rgba(10,10,10,.9);

    box-shadow:
        0 20px 80px rgba(0,0,0,.6);
}

.logo {
    font-size: 38px;
    font-weight: 900;
    letter-spacing: 3px;
}

.sub {
    margin-top: 12px;
    color: #777;
}

.status {
    margin-top: 25px;
    color: #777;
    font-size: 13px;
}
</style>
</head>

<body>

<div class="box">

    <div class="logo">
        LEXINX PROTECT
    </div>

    <div class="sub">
        Protected API Service
    </div>

    <div class="status">
        API ONLINE
    </div>

</div>

</body>
</html>
    `);
});

// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.json({
            success: true,
            status: "online",
            database: "connected",
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            status: "online",
            database: "disconnected"
        });
    }
});

// ============================================================
// REGISTER
// ============================================================

app.post(
    "/api/register",
    async (req, res) => {
        try {
            const {
                username,
                password
            } = req.body;

            if (
                typeof username !== "string" ||
                typeof password !== "string"
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Username and password are required"
                });
            }

            if (
                !/^[a-zA-Z0-9_]{3,32}$/
                    .test(username)
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid username"
                });
            }

            if (password.length < 6) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Password must contain at least 6 characters"
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

            if (existing.rows.length) {
                return res.status(409).json({
                    success: false,
                    error:
                        "Username already exists"
                });
            }

            const passwordHash =
                hashPassword(password);

            const result =
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
                        username,
                        created_at,
                        updated_at
                    `,
                    [
                        username,
                        passwordHash
                    ]
                );

            res.json({
                success: true,
                user: result.rows[0]
            });

        } catch (err) {
            console.error(
                "[REGISTER]",
                err
            );

            res.status(500).json({
                success: false,
                error:
                    "Registration failed"
            });
        }
    }
);

// ============================================================
// LOGIN
// ============================================================

app.post(
    "/api/login",
    async (req, res) => {
        try {
            const {
                username,
                password
            } = req.body;

            if (
                !username ||
                !password
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Username and password are required"
                });
            }

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

            const token =
                randomHex(48);

            await pool.query(
                `
                INSERT INTO login_sessions
                (
                    user_id,
                    session_token,
                    created_at,
                    expires_at,
                    last_seen_at
                )
                VALUES
                (
                    $1,
                    $2,
                    NOW(),
                    NOW() + INTERVAL '30 days',
                    NOW()
                )
                `,
                [
                    user.id,
                    token
                ]
            );

            res.json({
                success: true,

                token,

                expires_in:
                    60 * 60 * 24 * 30,

                user: {
                    id: user.id,
                    username:
                        user.username
                }
            });

        } catch (err) {
            console.error(
                "[LOGIN]",
                err
            );

            res.status(500).json({
                success: false,
                error:
                    "Login failed"
            });
        }
    }
);

// ============================================================
// ME
// ============================================================

app.get(
    "/api/me",
    requireAuth,
    async (req, res) => {
        res.json({
            success: true,
            user: req.user
        });
    }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
    "/api/logout",
    requireAuth,
    async (req, res) => {
        try {
            await pool.query(
                `
                DELETE FROM login_sessions
                WHERE session_token = $1
                `,
                [
                    req.session.session_token
                ]
            );

            res.json({
                success: true
            });
        } catch (err) {
            res.status(500).json({
                success: false,
                error:
                    "Logout failed"
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
            const {
                name,
                source
            } = req.body;

            if (
                typeof name !== "string" ||
                typeof source !== "string"
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        "name and source are required"
                });
            }

            if (
                name.length < 1 ||
                name.length > 255
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid script name"
                });
            }

            const scriptId =
                randomHex(16);

            const result =
                await pool.query(
                    `
                    INSERT INTO scripts
                    (
                        user_id,
                        script_id,
                        name,
                        source,
                        enabled,
                        created_at,
                        updated_at
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        TRUE,
                        NOW(),
                        NOW()
                    )
                    RETURNING
                        id,
                        script_id,
                        name,
                        enabled,
                        created_at,
                        updated_at
                    `,
                    [
                        req.user.id,
                        scriptId,
                        name,
                        source
                    ]
                );

            res.json({
                success: true,

                script:
                    result.rows[0],

                loader:
                    `${PUBLIC_URL}/api/loader/${scriptId}`,

                roblox:
                    `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${scriptId}"))()`
            });

        } catch (err) {
            console.error(
                "[CREATE]",
                err
            );

            res.status(500).json({
                success: false,
                error:
                    "Failed to create script"
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
                        id,
                        script_id,
                        name,
                        enabled,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE user_id = $1
                    ORDER BY id DESC
                    `,
                    [
                        req.user.id
                    ]
                );

            res.json({
                success: true,
                scripts:
                    result.rows
            });

        } catch (err) {
            res.status(500).json({
                success: false,
                error:
                    "Failed to get scripts"
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
                        id,
                        script_id,
                        name,
                        source,
                        enabled,
                        created_at,
                        updated_at
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

            res.json({
                success: true,
                script:
                    result.rows[0]
            });

        } catch (err) {
            res.status(500).json({
                success: false,
                error:
                    "Failed to get script"
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
            const {
                name,
                source,
                enabled
            } = req.body;

            const result =
                await pool.query(
                    `
                    UPDATE scripts
                    SET
                        name =
                            COALESCE(
                                $1,
                                name
                            ),

                        source =
                            COALESCE(
                                $2,
                                source
                            ),

                        enabled =
                            COALESCE(
                                $3,
                                enabled
                            ),

                        updated_at =
                            NOW()

                    WHERE script_id = $4
                      AND user_id = $5

                    RETURNING
                        id,
                        script_id,
                        name,
                        source,
                        enabled,
                        created_at,
                        updated_at
                    `,
                    [
                        name ?? null,
                        source ?? null,

                        typeof enabled ===
                        "boolean"
                            ? enabled
                            : null,

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
                success: true,
                script:
                    result.rows[0]
            });

        } catch (err) {
            console.error(
                "[UPDATE]",
                err
            );

            res.status(500).json({
                success: false,
                error:
                    "Failed to update script"
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
                    RETURNING id
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
                success: true,
                message:
                    "Script deleted"
            });

        } catch (err) {
            res.status(500).json({
                success: false,
                error:
                    "Failed to delete script"
            });
        }
    }
);

// ============================================================
// TOGGLE SCRIPT
// ============================================================

app.post(
    "/api/script/:id/toggle",
    requireAuth,
    async (req, res) => {
        try {
            const result =
                await pool.query(
                    `
                    UPDATE scripts
                    SET
                        enabled =
                            NOT enabled,
                        updated_at =
                            NOW()
                    WHERE script_id = $1
                      AND user_id = $2
                    RETURNING
                        script_id,
                        name,
                        enabled,
                        updated_at
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
                success: true,
                script:
                    result.rows[0]
            });

        } catch (err) {
            res.status(500).json({
                success: false,
                error:
                    "Failed to toggle script"
            });
        }
    }
);

// ============================================================
// PUBLIC LOADER
// ============================================================
//
// Browser mở trực tiếp:
// /api/loader/ID
//
// -> tạo loader session
// -> trả L1
//
// Roblox:
// loadstring(game:HttpGet(URL))()
//
// ============================================================

app.get(
    "/api/loader/:id",
    async (req, res) => {
        const scriptId =
            req.params.id;

        try {
            // --------------------------------------------
            // SCRIPT
            // --------------------------------------------

            const scriptResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        user_id,
                        script_id,
                        name,
                        source,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                    LIMIT 1
                    `,
                    [scriptId]
                );

            if (
                !scriptResult.rows.length
            ) {
                await writeAccessLog({
                    scriptId,
                    req,
                    success: false,
                    stage: "L1_NOT_FOUND"
                });

                return res.status(404)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Script not found"
                    );
            }

            const script =
                scriptResult.rows[0];

            if (!script.enabled) {
                await writeAccessLog({
                    userId: script.user_id,
                    scriptId,
                    req,
                    success: false,
                    stage: "L1_DISABLED"
                });

                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Script disabled"
                    );
            }

            // --------------------------------------------
            // CREATE PERSISTENT LOADER SESSION
            // --------------------------------------------

            const session =
                await createLoaderSession(
                    scriptId,
                    req
                );

            await writeAccessLog({
                userId: script.user_id,
                scriptId,
                req,
                success: true,
                stage: "L1"
            });

            // --------------------------------------------
            // L1 RESPONSE
            // --------------------------------------------

            const payload = {
                ok: true,
                version: "LEXINX-L1",
                session:
                    session.session_token,

                next:
                    `${PUBLIC_URL}/api/l3`
            };

            /*
             * L1 chỉ trả bootstrap data.
             * Source không nằm trong L1.
             */

            const encoded =
                base64Encode(
                    JSON.stringify(payload)
                );

            res.status(200)
                .type("text/plain")
                .send(
                    `-- LEXINX PROTECT L1\n` +
                    `-- ${encoded}`
                );

        } catch (err) {
            console.error(
                "[L1]",
                err
            );

            res.status(500)
                .type("text/plain")
                .send(
                    "-- LEXINX PROTECT\n" +
                    "-- Internal error"
                );
        }
    }
);

// ============================================================
// L3
// ============================================================

app.get(
    "/api/l3",
    async (req, res) => {
        try {
            const token =
                req.query.session ||
                req.headers[
                    "x-loader-session"
                ];

            const session =
                await getLoaderSession(
                    token
                );

            if (!session) {
                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid or expired session"
                    );
            }

            if (
                Number(
                    session.current_stage
                ) !== 1
            ) {
                await deleteLoaderSession(
                    token
                );

                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid stage"
                    );
            }

            const nextToken =
                randomHex(32);

            await updateLoaderStage(
                session.id,
                3,
                nextToken
            );

            const payload = {
                version: "LEXINX-L3",

                session:
                    session.session_token,

                stage_token:
                    nextToken,

                next:
                    `${PUBLIC_URL}/api/l4`
            };

            const encoded =
                base64Encode(
                    JSON.stringify(payload)
                );

            await writeAccessLog({
                scriptId:
                    session.script_id,

                req,

                success: true,

                stage: "L3"
            });

            res.status(200)
                .type("text/plain")
                .send(
                    `-- LEXINX PROTECT L3\n` +
                    encoded
                );

        } catch (err) {
            console.error(
                "[L3]",
                err
            );

            res.status(500)
                .type("text/plain")
                .send(
                    "-- LEXINX PROTECT\n" +
                    "-- L3 error"
                );
        }
    }
);

// ============================================================
// L4
// ============================================================

app.get(
    "/api/l4",
    async (req, res) => {
        try {
            const sessionToken =
                req.query.session ||
                req.headers[
                    "x-loader-session"
                ];

            const stageToken =
                req.query.token ||
                req.headers[
                    "x-stage-token"
                ];

            const session =
                await getLoaderSession(
                    sessionToken
                );

            if (!session) {
                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid session"
                    );
            }

            if (
                Number(
                    session.current_stage
                ) !== 3
            ) {
                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid stage"
                    );
            }

            if (
                !safeEqual(
                    String(
                        session.stage_token
                    ),
                    String(
                        stageToken || ""
                    )
                )
            ) {
                await deleteLoaderSession(
                    sessionToken
                );

                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid stage token"
                    );
            }

            const nextToken =
                randomHex(32);

            await updateLoaderStage(
                session.id,
                4,
                nextToken
            );

            const payload = {
                version: "LEXINX-L4",

                session:
                    session.session_token,

                stage_token:
                    nextToken,

                next:
                    `${PUBLIC_URL}/api/l5`
            };

            const encoded =
                base64Encode(
                    JSON.stringify(payload)
                );

            await writeAccessLog({
                scriptId:
                    session.script_id,

                req,

                success: true,

                stage: "L4"
            });

            res.status(200)
                .type("text/plain")
                .send(
                    `-- LEXINX PROTECT L4\n` +
                    encoded
                );

        } catch (err) {
            console.error(
                "[L4]",
                err
            );

            res.status(500)
                .type("text/plain")
                .send(
                    "-- LEXINX PROTECT\n" +
                    "-- L4 error"
                );
        }
    }
);

// ============================================================
// L5
// ============================================================

app.get(
    "/api/l5",
    async (req, res) => {
        try {
            const sessionToken =
                req.query.session ||
                req.headers[
                    "x-loader-session"
                ];

            const stageToken =
                req.query.token ||
                req.headers[
                    "x-stage-token"
                ];

            const session =
                await getLoaderSession(
                    sessionToken
                );

            if (!session) {
                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid session"
                    );
            }

            if (
                Number(
                    session.current_stage
                ) !== 4
            ) {
                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid stage"
                    );
            }

            if (
                !safeEqual(
                    String(
                        session.stage_token
                    ),
                    String(
                        stageToken || ""
                    )
                )
            ) {
                await deleteLoaderSession(
                    sessionToken
                );

                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid token"
                    );
            }

            const nextToken =
                randomHex(32);

            await updateLoaderStage(
                session.id,
                5,
                nextToken
            );

            const payload = {
                version: "LEXINX-L5",

                session:
                    session.session_token,

                stage_token:
                    nextToken,

                next:
                    `${PUBLIC_URL}/api/l5/final`
            };

            const encoded =
                base64Encode(
                    JSON.stringify(payload)
                );

            await writeAccessLog({
                scriptId:
                    session.script_id,

                req,

                success: true,

                stage: "L5"
            });

            res.status(200)
                .type("text/plain")
                .send(
                    `-- LEXINX PROTECT L5\n` +
                    encoded
                );

        } catch (err) {
            console.error(
                "[L5]",
                err
            );

            res.status(500)
                .type("text/plain")
                .send(
                    "-- LEXINX PROTECT\n" +
                    "-- L5 error"
                );
        }
    }
);

// ============================================================
// FINAL
// ============================================================

app.get(
    "/api/l5/final",
    async (req, res) => {
        try {
            const sessionToken =
                req.query.session ||
                req.headers[
                    "x-loader-session"
                ];

            const stageToken =
                req.query.token ||
                req.headers[
                    "x-stage-token"
                ];

            const session =
                await getLoaderSession(
                    sessionToken
                );

            if (!session) {
                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid session"
                    );
            }

            if (
                Number(
                    session.current_stage
                ) !== 5
            ) {
                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid stage"
                    );
            }

            if (
                !safeEqual(
                    String(
                        session.stage_token
                    ),
                    String(
                        stageToken || ""
                    )
                )
            ) {
                await deleteLoaderSession(
                    sessionToken
                );

                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Invalid final token"
                    );
            }

            // --------------------------------------------
            // GET SOURCE
            // --------------------------------------------

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        user_id,
                        script_id,
                        source,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                    LIMIT 1
                    `,
                    [
                        session.script_id
                    ]
                );

            if (!result.rows.length) {
                await deleteLoaderSession(
                    sessionToken
                );

                return res.status(404)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Script not found"
                    );
            }

            const script =
                result.rows[0];

            if (!script.enabled) {
                await deleteLoaderSession(
                    sessionToken
                );

                return res.status(403)
                    .type("text/plain")
                    .send(
                        "-- LEXINX PROTECT\n" +
                        "-- Script disabled"
                    );
            }

            // --------------------------------------------
            // FINAL WRAPPER
            // --------------------------------------------

            const source =
                String(script.source);

            const encodedSource =
                Buffer
                    .from(
                        source,
                        "utf8"
                    )
                    .toString("base64");

            const finalScript = `
-- ============================================================
-- LEXINX PROTECT
-- FINAL PAYLOAD
-- ============================================================

local __LEXINX_DATA = [[${encodedSource}]]

local __LEXINX_B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function __LEXINX_DECODE(data)

    data = data:gsub("[^" .. __LEXINX_B64 .. "=]", "")

    local result = {}

    local chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    local map = {}

    for i = 1, #chars do
        map[chars:sub(i,i)] = i - 1
    end

    local buffer = 0
    local bits = 0

    for i = 1, #data do

        local c = data:sub(i,i)

        if c == "=" then
            break
        end

        local v = map[c]

        if v then

            buffer =
                buffer * 64 + v

            bits =
                bits + 6

            if bits >= 8 then

                bits =
                    bits - 8

                local byte =
                    math.floor(
                        buffer /
                        (2 ^ bits)
                    ) % 256

                result[#result + 1] =
                    string.char(byte)

                buffer =
                    buffer %
                    (2 ^ bits)

            end

        end

    end

    return table.concat(result)

end

local __LEXINX_SOURCE =
    __LEXINX_DECODE(
        __LEXINX_DATA
    )

local __LEXINX_LOAD =
    loadstring

if type(__LEXINX_LOAD) ~= "function" then
    error("LEXINX_NO_LOADSTRING")
end

local __LEXINX_FN,
      __LEXINX_ERR =
    __LEXINX_LOAD(
        __LEXINX_SOURCE
    )

if not __LEXINX_FN then
    error(
        "LEXINX_COMPILE_ERROR " ..
        tostring(__LEXINX_ERR)
    )
end

return __LEXINX_FN()
`;

            // --------------------------------------------
            // LOG
            // --------------------------------------------

            await writeAccessLog({
                userId:
                    script.user_id,

                scriptId:
                    script.script_id,

                req,

                success: true,

                stage: "FINAL"
            });

            // --------------------------------------------
            // DELETE SESSION
            // --------------------------------------------

            await deleteLoaderSession(
                sessionToken
            );

            // --------------------------------------------
            // RESPONSE
            // --------------------------------------------

            res.status(200)
                .type("text/plain")
                .send(finalScript);

        } catch (err) {
            console.error(
                "[FINAL]",
                err
            );

            res.status(500)
                .type("text/plain")
                .send(
                    "-- LEXINX PROTECT\\n" +
                    "-- Final error"
                );
        }
    }
);

// ============================================================
// BLOCK INVALID LOADER ROUTES
// ============================================================

app.get(
    "/api/loader",
    (req, res) => {
        res.status(403)
            .type("text/plain")
            .send(
                "-- LEXINX PROTECT\n" +
                "-- Invalid loader request"
            );
    }
);

// ============================================================
// ACCESS LOGS
// ============================================================

app.get(
    "/api/logs/:id",
    requireAuth,
    async (req, res) => {
        try {
            const scriptCheck =
                await pool.query(
                    `
                    SELECT id
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

            if (!scriptCheck.rows.length) {
                return res.status(404).json({
                    success: false,
                    error:
                        "Script not found"
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        script_id,
                        ip_address,
                        success,
                        stage,
                        created_at
                    FROM script_access_logs
                    WHERE script_id = $1
                    ORDER BY id DESC
                    LIMIT 500
                    `,
                    [
                        req.params.id
                    ]
                );

            res.json({
                success: true,
                logs:
                    result.rows
            });

        } catch (err) {
            console.error(
                "[LOGS]",
                err
            );

            res.status(500).json({
                success: false,
                error:
                    "Failed to get logs"
            });
        }
    }
);

// ============================================================
// CLEAN EXPIRED SESSIONS
// ============================================================

async function cleanupSessions() {
    try {

        await pool.query(
            `
            DELETE FROM login_sessions
            WHERE expires_at < NOW()
            `
        );

        await pool.query(
            `
            DELETE FROM loader_sessions
            WHERE expires_at < NOW()
            `
        );

    } catch (err) {

        console.error(
            "[CLEANUP]",
            err.message
        );

    }
}

// Chạy cleanup nếu instance đang sống.
// Không phụ thuộc vào cleanup để bảo mật:
// expires_at vẫn được kiểm tra trong SQL.
setInterval(
    cleanupSessions,
    60 * 60 * 1000
);

// ============================================================
// 404
// ============================================================

app.use(
    (req, res) => {

        res.status(404)
            .type("text/plain")
            .send(
                "-- LEXINX PROTECT\n" +
                "-- 404 Not Found"
            );

    }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "[SERVER ERROR]",
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        res.status(500).json({
            success: false,
            error:
                "Internal server error"
        });

    }
);

// ============================================================
// VERCEL / LOCAL
// ============================================================

if (!process.env.VERCEL) {

    app.listen(
        PORT,
        () => {
            console.log(
                `[LEXINX] Server running on port ${PORT}`
            );
        }
    );

}

module.exports = app;
