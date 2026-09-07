const express = require("express");
const crypto = require("crypto");
const path = require("path");
const mysql = require("mysql2/promise");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 3000;

const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://lexinx-protect-v230.vercel.app";

const WEB_SESSION_TTL =
    7 * 24 * 60 * 60 * 1000;

const LOADER_SESSION_TTL =
    60 * 1000;

/* =========================================================
   MYSQL
========================================================= */

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || "lexinx_protect",

    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,

    charset: "utf8mb4",

    enableKeepAlive: true,
    keepAliveInitialDelay: 10000
});

/* =========================================================
   APP
========================================================= */

app.set("trust proxy", 1);

app.use(
    express.json({
        limit: "1mb"
    })
);

app.use(
    express.urlencoded({
        extended: false
    })
);

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

/* =========================================================
   DATABASE TEST
========================================================= */

async function testDatabase() {
    try {
        const connection =
            await pool.getConnection();

        await connection.ping();

        connection.release();

        console.log(
            "[MYSQL] Database connected."
        );

    } catch (error) {

        console.error(
            "[MYSQL] Database connection failed:"
        );

        console.error(error);
    }
}

/* =========================================================
   HELPERS
========================================================= */

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");
}

function luaString(value) {
    return JSON.stringify(
        String(value)
    );
}

function hexEncode(value) {
    return Buffer
        .from(String(value), "utf8")
        .toString("hex");
}

function now() {
    return Date.now();
}

function apiError(
    res,
    status,
    message
) {
    return res
        .status(status)
        .json({
            ok: false,
            error: message
        });
}

/* =========================================================
   COOKIE
========================================================= */

function getCookie(req, name) {

    const raw =
        req.headers.cookie || "";

    const parts =
        raw.split(";");

    for (const part of parts) {

        const item =
            part.trim();

        const index =
            item.indexOf("=");

        if (index === -1)
            continue;

        const key =
            item.slice(0, index);

        const value =
            item.slice(index + 1);

        if (key === name) {

            try {
                return decodeURIComponent(
                    value
                );
            } catch {
                return value;
            }
        }
    }

    return null;
}

/* =========================================================
   USER DATABASE
========================================================= */

async function getUser(
    usernameLower
) {

    const [rows] =
        await pool.execute(
            `
            SELECT
                id,
                username,
                username_lower,
                password_hash,
                created_at,
                updated_at
            FROM users
            WHERE username_lower = ?
            LIMIT 1
            `,
            [usernameLower]
        );

    return rows[0] || null;
}

/* =========================================================
   WEB SESSION DATABASE
========================================================= */

async function createWebSession(
    usernameLower
) {

    const sessionId =
        randomHex(32);

    const createdAt =
        now();

    const expiresAt =
        createdAt +
        WEB_SESSION_TTL;

    await pool.execute(
        `
        INSERT INTO web_sessions
        (
            session_id,
            username_lower,
            created_at,
            expires_at,
            last_accessed_at
        )
        VALUES (?, ?, ?, ?, ?)
        `,
        [
            sessionId,
            usernameLower,
            createdAt,
            expiresAt,
            createdAt
        ]
    );

    return sessionId;
}

async function getWebAuth(req) {

    const sid =
        getCookie(
            req,
            "lexinx_session"
        );

    if (!sid)
        return null;

    const current =
        now();

    const [rows] =
        await pool.execute(
            `
            SELECT
                ws.session_id,
                ws.username_lower,
                ws.created_at,
                ws.expires_at,

                u.id,
                u.username,
                u.password_hash,
                u.created_at AS user_created_at,
                u.updated_at

            FROM web_sessions ws

            INNER JOIN users u
                ON u.username_lower =
                   ws.username_lower

            WHERE
                ws.session_id = ?
                AND ws.expires_at > ?

            LIMIT 1
            `,
            [
                sid,
                current
            ]
        );

    const row =
        rows[0];

    if (!row) {

        await pool.execute(
            `
            DELETE FROM web_sessions
            WHERE session_id = ?
            `,
            [sid]
        );

        return null;
    }

    await pool.execute(
        `
        UPDATE web_sessions
        SET last_accessed_at = ?
        WHERE session_id = ?
        `,
        [
            current,
            sid
        ]
    );

    return {
        sid,
        username: row.username,
        username_lower:
            row.username_lower,

        user: {
            id: row.id,
            username: row.username,
            username_lower:
                row.username_lower,
            password_hash:
                row.password_hash,
            created_at:
                row.user_created_at,
            updated_at:
                row.updated_at
        }
    };
}

async function requireAuth(
    req,
    res,
    next
) {

    try {

        const auth =
            await getWebAuth(req);

        if (!auth) {

            return apiError(
                res,
                401,
                "Authentication required."
            );
        }

        req.auth =
            auth;

        next();

    } catch (error) {

        console.error(
            "AUTH ERROR:",
            error
        );

        return apiError(
            res,
            500,
            "Authentication server error."
        );
    }
}

/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/register",
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();

            const password =
                String(
                    req.body.password || ""
                );

            if (!username) {

                return apiError(
                    res,
                    400,
                    "Username is required."
                );
            }

            if (username.length < 3) {

                return apiError(
                    res,
                    400,
                    "Username must contain at least 3 characters."
                );
            }

            if (username.length > 32) {

                return apiError(
                    res,
                    400,
                    "Username is too long."
                );
            }

            if (
                !/^[a-zA-Z0-9_]+$/.test(
                    username
                )
            ) {

                return apiError(
                    res,
                    400,
                    "Username may only contain letters, numbers and underscore."
                );
            }

            if (password.length < 6) {

                return apiError(
                    res,
                    400,
                    "Password must contain at least 6 characters."
                );
            }

            const usernameLower =
                username.toLowerCase();

            const existing =
                await getUser(
                    usernameLower
                );

            if (existing) {

                return apiError(
                    res,
                    409,
                    "Username already exists."
                );
            }

            const timestamp =
                now();

            await pool.execute(
                `
                INSERT INTO users
                (
                    username,
                    username_lower,
                    password_hash,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    username,
                    usernameLower,
                    hashPassword(
                        password
                    ),
                    timestamp,
                    timestamp
                ]
            );

            const sid =
                await createWebSession(
                    usernameLower
                );

            res.cookie(
                "lexinx_session",
                sid,
                {
                    httpOnly: true,
                    sameSite: "lax",
                    secure: true,
                    maxAge:
                        WEB_SESSION_TTL,
                    path: "/"
                }
            );

            return res.json({
                ok: true,
                username,
                url:
                    PUBLIC_URL + "/"
            });

        } catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

            if (
                error.code ===
                "ER_DUP_ENTRY"
            ) {

                return apiError(
                    res,
                    409,
                    "Username already exists."
                );
            }

            return apiError(
                res,
                500,
                "Registration server error."
            );
        }
    }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();

            const password =
                String(
                    req.body.password || ""
                );

            const usernameLower =
                username.toLowerCase();

            const user =
                await getUser(
                    usernameLower
                );

            if (!user) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );
            }

            const passwordHash =
                hashPassword(
                    password
                );

            if (
                user.password_hash !==
                passwordHash
            ) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );
            }

            const sid =
                await createWebSession(
                    user.username_lower
                );

            res.cookie(
                "lexinx_session",
                sid,
                {
                    httpOnly: true,
                    sameSite: "lax",
                    secure: true,
                    maxAge:
                        WEB_SESSION_TTL,
                    path: "/"
                }
            );

            return res.json({
                ok: true,
                username:
                    user.username,
                url:
                    PUBLIC_URL + "/"
            });

        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Login server error."
            );
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

            const auth =
                await getWebAuth(req);

            if (!auth) {

                return apiError(
                    res,
                    401,
                    "Not authenticated."
                );
            }

            return res.json({
                ok: true,
                username:
                    auth.username,
                url:
                    PUBLIC_URL + "/"
            });

        } catch (error) {

            console.error(
                "ME ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Session server error."
            );
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

            const sid =
                getCookie(
                    req,
                    "lexinx_session"
                );

            if (sid) {

                await pool.execute(
                    `
                    DELETE FROM web_sessions
                    WHERE session_id = ?
                    `,
                    [sid]
                );
            }

            res.clearCookie(
                "lexinx_session",
                {
                    path: "/"
                }
            );

            return res.json({
                ok: true
            });

        } catch (error) {

            console.error(
                "LOGOUT ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Logout server error."
            );
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
                    req.body.name ||
                    "Untitled Script"
                )
                .trim()
                .slice(0, 100);

            const source =
                String(
                    req.body.source || ""
                );

            if (!source.trim()) {

                return apiError(
                    res,
                    400,
                    "Script source cannot be empty."
                );
            }

            if (
                Buffer.byteLength(
                    source,
                    "utf8"
                ) > 1024 * 1024
            ) {

                return apiError(
                    res,
                    400,
                    "Script is too large. Maximum size is 1MB."
                );
            }

            let id;

            while (true) {

                id =
                    randomHex(12);

                const [rows] =
                    await pool.execute(
                        `
                        SELECT id
                        FROM scripts
                        WHERE id = ?
                        LIMIT 1
                        `,
                        [id]
                    );

                if (
                    rows.length === 0
                ) {
                    break;
                }
            }

            const timestamp =
                now();

            await pool.execute(
                `
                INSERT INTO scripts
                (
                    id,
                    name,
                    source,
                    owner_username,
                    created_at,
                    updated_at,
                    is_active
                )
                VALUES (?, ?, ?, ?, ?, ?, 1)
                `,
                [
                    id,
                    name ||
                        "Untitled Script",
                    source,
                    req.auth.username_lower,
                    timestamp,
                    timestamp
                ]
            );

            const loader =
                `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${id}"))()`;

            return res.json({
                ok: true,
                id,
                loader
            });

        } catch (error) {

            console.error(
                "CREATE ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Create script server error."
            );
        }
    }
);

/* =========================================================
   LIST SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireAuth,
    async (req, res) => {

        try {

            const [rows] =
                await pool.execute(
                    `
                    SELECT
                        id,
                        name,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE
                        owner_username = ?
                        AND is_active = 1
                    ORDER BY created_at DESC
                    `,
                    [
                        req.auth.username_lower
                    ]
                );

            const result =
                rows.map(
                    script => ({
                        id:
                            script.id,

                        name:
                            script.name,

                        loader:
                            `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${script.id}"))()`,

                        created:
                            Number(
                                script.created_at
                            ),

                        updated:
                            Number(
                                script.updated_at
                            )
                    })
                );

            return res.json({
                ok: true,
                scripts: result
            });

        } catch (error) {

            console.error(
                "LIST ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to load scripts."
            );
        }
    }
);

/* =========================================================
   GET SCRIPT
========================================================= */

app.get(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const [rows] =
                await pool.execute(
                    `
                    SELECT
                        id,
                        name,
                        source,
                        owner_username,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE
                        id = ?
                        AND owner_username = ?
                        AND is_active = 1
                    LIMIT 1
                    `,
                    [
                        req.params.id,
                        req.auth.username_lower
                    ]
                );

            const script =
                rows[0];

            if (!script) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            return res.json({
                ok: true,
                script: {
                    id:
                        script.id,
                    name:
                        script.name,
                    source:
                        script.source
                }
            });

        } catch (error) {

            console.error(
                "GET SCRIPT ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to load script."
            );
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

            const [rows] =
                await pool.execute(
                    `
                    SELECT
                        id,
                        name,
                        source
                    FROM scripts
                    WHERE
                        id = ?
                        AND owner_username = ?
                        AND is_active = 1
                    LIMIT 1
                    `,
                    [
                        req.params.id,
                        req.auth.username_lower
                    ]
                );

            const script =
                rows[0];

            if (!script) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            let name =
                script.name;

            let source =
                script.source;

            if (
                typeof req.body.name ===
                "string"
            ) {

                name =
                    req.body.name
                        .trim()
                        .slice(0, 100) ||
                    "Untitled Script";
            }

            if (
                typeof req.body.source ===
                "string"
            ) {

                if (
                    !req.body.source.trim()
                ) {

                    return apiError(
                        res,
                        400,
                        "Script source cannot be empty."
                    );
                }

                if (
                    Buffer.byteLength(
                        req.body.source,
                        "utf8"
                    ) > 1024 * 1024
                ) {

                    return apiError(
                        res,
                        400,
                        "Script is too large. Maximum size is 1MB."
                    );
                }

                source =
                    req.body.source;
            }

            await pool.execute(
                `
                UPDATE scripts
                SET
                    name = ?,
                    source = ?,
                    updated_at = ?
                WHERE
                    id = ?
                    AND owner_username = ?
                    AND is_active = 1
                `,
                [
                    name,
                    source,
                    now(),
                    req.params.id,
                    req.auth.username_lower
                ]
            );

            return res.json({
                ok: true
            });

        } catch (error) {

            console.error(
                "UPDATE ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Update script server error."
            );
        }
    }
);

/* =========================================================
   DELETE SCRIPT
   Soft delete = is_active = 0
========================================================= */

app.delete(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const [result] =
                await pool.execute(
                    `
                    UPDATE scripts
                    SET
                        is_active = 0,
                        updated_at = ?
                    WHERE
                        id = ?
                        AND owner_username = ?
                        AND is_active = 1
                    `,
                    [
                        now(),
                        req.params.id,
                        req.auth.username_lower
                    ]
                );

            if (
                result.affectedRows === 0
            ) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            return res.json({
                ok: true
            });

        } catch (error) {

            console.error(
                "DELETE ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Delete script server error."
            );
        }
    }
);

/* =========================================================
   LOADER DATABASE
========================================================= */

async function getScriptById(id) {

    const [rows] =
        await pool.execute(
            `
            SELECT
                id,
                name,
                source,
                owner_username,
                created_at,
                updated_at,
                is_active
            FROM scripts
            WHERE
                id = ?
                AND is_active = 1
            LIMIT 1
            `,
            [id]
        );

    return rows[0] || null;
}

async function createLoaderSession(
    scriptId,
    req
) {

    const sessionId =
        randomHex(32);

    const firstToken =
        randomHex(32);

    const createdAt =
        now();

    const expiresAt =
        createdAt +
        LOADER_SESSION_TTL;

    const userAgent =
        String(
            req.headers["user-agent"] ||
            ""
        ).slice(0, 255);

    const ip =
        String(
            req.ip ||
            req.headers["x-forwarded-for"] ||
            req.socket?.remoteAddress ||
            ""
        ).slice(0, 45);

    const connection =
        await pool.getConnection();

    try {

        await connection.beginTransaction();

        await connection.execute(
            `
            INSERT INTO loader_sessions
            (
                session_id,
                script_id,
                stage,
                created_at,
                expires_at,
                user_agent,
                ip_address
            )
            VALUES (?, ?, 0, ?, ?, ?, ?)
            `,
            [
                sessionId,
                scriptId,
                createdAt,
                expiresAt,
                userAgent,
                ip
            ]
        );

        await connection.execute(
            `
            INSERT INTO loader_tokens
            (
                session_id,
                token,
                stage,
                is_used,
                created_at
            )
            VALUES (?, ?, 0, 0, ?)
            `,
            [
                sessionId,
                firstToken,
                createdAt
            ]
        );

        await connection.commit();

        return {
            id: sessionId,
            scriptId,
            stage: 0,
            token: firstToken,
            created: createdAt,
            expires: expiresAt
        };

    } catch (error) {

        await connection.rollback();

        throw error;

    } finally {

        connection.release();
    }
}

async function getLoaderSession(
    sessionId
) {

    if (!sessionId)
        return null;

    const current =
        now();

    const [rows] =
        await pool.execute(
            `
            SELECT
                session_id,
                script_id,
                stage,
                created_at,
                expires_at,
                completed_at
            FROM loader_sessions
            WHERE
                session_id = ?
                AND expires_at > ?
            LIMIT 1
            `,
            [
                sessionId,
                current
            ]
        );

    return rows[0] || null;
}

/*
 * Atomic one-time token consumption.
 *
 * This prevents the same token from being
 * successfully used twice.
 */
async function consumeToken(
    sessionId,
    token,
    stage
) {

    if (!sessionId || !token)
        return false;

    const timestamp =
        now();

    const [result] =
        await pool.execute(
            `
            UPDATE loader_tokens
            SET
                is_used = 1,
                used_at = ?
            WHERE
                session_id = ?
                AND token = ?
                AND stage = ?
                AND is_used = 0
            `,
            [
                timestamp,
                sessionId,
                token,
                stage
            ]
        );

    return (
        result.affectedRows === 1
    );
}

async function advanceLoaderStage(
    sessionId,
    expectedStage,
    nextStage
) {

    const [result] =
        await pool.execute(
            `
            UPDATE loader_sessions
            SET stage = ?
            WHERE
                session_id = ?
                AND stage = ?
                AND expires_at > ?
            `,
            [
                nextStage,
                sessionId,
                expectedStage,
                now()
            ]
        );

    return (
        result.affectedRows === 1
    );
}

async function issueLoaderToken(
    sessionId,
    stage
) {

    const token =
        randomHex(32);

    await pool.execute(
        `
        INSERT INTO loader_tokens
        (
            session_id,
            token,
            stage,
            is_used,
            created_at
        )
        VALUES (?, ?, ?, 0, ?)
        `,
        [
            sessionId,
            token,
            stage,
            now()
        ]
    );

    return token;
}

/* =========================================================
   PROTECT PAGE
========================================================= */

function blockPage(res) {

    return res
        .status(403)
        .type("html")
        .send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>LEXINX PROTECT</title>

<style>

html,body{
    margin:0;
    width:100%;
    height:100%;
    background:#050505;
    color:#eee;
    font-family:Arial,sans-serif;
}

body{
    display:flex;
    align-items:center;
    justify-content:center;
}

.box{
    width:min(520px,88%);
    padding:55px 30px;
    text-align:center;
    background:#111;
    border:1px solid #292929;
    border-radius:18px;
    box-shadow:
        0 0 60px
        rgba(255,255,255,.04);
}

.logo{
    font-size:42px;
    font-weight:900;
    letter-spacing:8px;
}

.sub{
    margin-top:16px;
    color:#777;
    font-size:13px;
    letter-spacing:4px;
}

</style>

</head>

<body>

<div class="box">

<div class="logo">
LEXINX
</div>

<div class="sub">
PROTECT
</div>

<div class="sub">
ANTI-SKID
</div>

</div>

</body>

</html>
`);
}

/* =========================================================
   LUA HELPERS
========================================================= */

function luaHexDecoder() {

    return `
local function decodeHex(s)

    local out = {}

    for i = 1, #s, 2 do

        local n =
            tonumber(
                s:sub(i, i + 1),
                16
            )

        if n then

            out[#out + 1] =
                string.char(n)

        end

    end

    return table.concat(out)

end
`;
}

function randomLuaName() {

    const chars =
        "abcdefghijklmnopqrstuvwxyz";

    let result = "_";

    for (
        let i = 0;
        i < 10;
        i++
    ) {

        result +=
            chars[
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];
    }

    return result;
}

/* =========================================================
   WRAPPER
========================================================= */

function buildWrapper(
    session,
    token
) {

    const endpoint =
        hexEncode(PUBLIC_URL);

    const endpointVar =
        randomLuaName();

    const sessionVar =
        randomLuaName();

    const tokenVar =
        randomLuaName();

    const request =
        randomLuaName();

    return `

-- LEXINX WRAPPER VM

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${sessionVar} =
    ${luaString(session.session_id)}

local ${tokenVar} =
    ${luaString(token)}

local function ${request}()

    local endpoint =
        decodeHex(
            ${endpointVar}
        )

    local url =
        endpoint
        .. "/api/l3"
        .. "?session="
        .. ${sessionVar}
        .. "&token="
        .. ${tokenVar}

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    if type(response)
        ~= "string"
    then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return ${request}()

`;
}

/* =========================================================
   L2
========================================================= */

function buildL2(
    session,
    token
) {

    const endpoint =
        hexEncode(PUBLIC_URL);

    const endpointVar =
        randomLuaName();

    const sessionVar =
        randomLuaName();

    const tokenVar =
        randomLuaName();

    const vm =
        randomLuaName();

    return `

-- LEXINX L2

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${vm} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(
            session.session_id
        )},

    token =
        ${luaString(token)}

}

local function runVM(state)

    local url =
        state.endpoint
        .. "/api/l4"
        .. "?session="
        .. state.session
        .. "&token="
        .. state.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return runVM(${vm})

`;
}

/* =========================================================
   L3
========================================================= */

function buildL3(
    session,
    token
) {

    const endpoint =
        hexEncode(PUBLIC_URL);

    const endpointVar =
        randomLuaName();

    const prototype =
        randomLuaName();

    return `

-- LEXINX L3
-- PACKED PROTOTYPE

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${prototype} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(
            session.session_id
        )},

    token =
        ${luaString(token)},

    opcode = {

        LOAD = 1,
        REQUEST = 2,
        EXEC = 3

    }

}

local function executeVM(p)

    local url =
        p.endpoint
        .. "/api/l5"
        .. "?session="
        .. p.session
        .. "&token="
        .. p.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return executeVM(
    ${prototype}
)

`;
}

/* =========================================================
   L4
========================================================= */

function buildL4(
    session,
    token
) {

    const endpoint =
        hexEncode(PUBLIC_URL);

    const endpointVar =
        randomLuaName();

    const runtime =
        randomLuaName();

    return `

-- LEXINX L4
-- RUNTIME BOOTSTRAP

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${runtime} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(
            session.session_id
        )},

    token =
        ${luaString(token)},

    stage = 4

}

local function bootstrap(state)

    local url =
        state.endpoint
        .. "/api/l5/final"
        .. "?session="
        .. state.session
        .. "&token="
        .. state.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    if type(response)
        ~= "string"
    then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return bootstrap(
    ${runtime}
)

`;
}

/* =========================================================
   L5
========================================================= */

function buildL5(
    session,
    source
) {

    const payload =
        Buffer
            .from(
                source,
                "utf8"
            )
            .toString("base64");

    const data =
        randomLuaName();

    const decode =
        randomLuaName();

    const execute =
        randomLuaName();

    return `

-- LEXINX L5
-- FINAL RUNTIME

local ${data} =
    ${luaString(payload)}

local function ${decode}(input)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    input =
        input:gsub(
            "[^"
            .. alphabet
            .. "=]",
            ""
        )

    local bits = {}

    for i = 1, #input do

        local c =
            input:sub(i, i)

        if c ~= "=" then

            local p =
                alphabet:find(
                    c,
                    1,
                    true
                )

            if p then

                p = p - 1

                for j = 6, 1, -1 do

                    if
                        p % 2^j >=
                        2^(j - 1)
                    then

                        bits[#bits + 1] =
                            "1"

                    else

                        bits[#bits + 1] =
                            "0"

                    end

                end

            end

        end

    end

    local output = {}

    for i = 1,
        #bits - 7,
        8
    do

        local byte = 0

        for j = 0, 7 do

            if
                bits[i + j]
                == "1"
            then

                byte =
                    byte +
                    2^(7 - j)

            end

        end

        output[#output + 1] =
            string.char(byte)

    end

    return table.concat(
        output
    )

end

local function ${execute}()

    local source =
        ${decode}(
            ${data}
        )

    local fn =
        loadstring(source)

    if fn then
        return fn()
    end

end

return ${execute}()

`;
}

/* =========================================================
   LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    async (req, res) => {

        const started =
            Date.now();

        try {

            const id =
                String(
                    req.params.id || ""
                ).trim();

            if (!id)
                return blockPage(res);

            const script =
                await getScriptById(id);

            if (!script)
                return blockPage(res);

            const accept =
                String(
                    req.headers.accept || ""
                ).toLowerCase();

            if (
                accept.includes(
                    "text/html"
                )
            ) {

                return blockPage(res);
            }

            const session =
                await createLoaderSession(
                    script.id,
                    req
                );

            const wrapper =
                buildWrapper(
                    session,
                    session.token
                );

            return res
                .status(200)
                .type("text/plain")
                .send(wrapper);

        } catch (error) {

            console.error(
                "LOADER ERROR:",
                error
            );

            return res
                .status(500)
                .type("text/plain")
                .send(
                    "LEXINX INTERNAL ERROR"
                );
        }
    }
);

/* =========================================================
   L3
========================================================= */

app.get(
    "/api/l3",
    async (req, res) => {

        try {

            const sessionId =
                String(
                    req.query.session || ""
                );

            const token =
                String(
                    req.query.token || ""
                );

            const session =
                await getLoaderSession(
                    sessionId
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                Number(session.stage) !==
                0
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const consumed =
                await consumeToken(
                    sessionId,
                    token,
                    0
                );

            if (!consumed) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const advanced =
                await advanceLoaderStage(
                    sessionId,
                    0,
                    1
                );

            if (!advanced) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const nextToken =
                await issueLoaderToken(
                    sessionId,
                    1
                );

            const output =
                buildL2(
                    session,
                    nextToken
                );

            return res
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "L3 ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "L3 SERVER ERROR"
            );
        }
    }
);

/* =========================================================
   L4
========================================================= */

app.get(
    "/api/l4",
    async (req, res) => {

        try {

            const sessionId =
                String(
                    req.query.session || ""
                );

            const token =
                String(
                    req.query.token || ""
                );

            const session =
                await getLoaderSession(
                    sessionId
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                Number(session.stage) !==
                1
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const consumed =
                await consumeToken(
                    sessionId,
                    token,
                    1
                );

            if (!consumed) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const advanced =
                await advanceLoaderStage(
                    sessionId,
                    1,
                    2
                );

            if (!advanced) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const nextToken =
                await issueLoaderToken(
                    sessionId,
                    2
                );

            const output =
                buildL3(
                    session,
                    nextToken
                );

            return res
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "L4 ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "L4 SERVER ERROR"
            );
        }
    }
);

/* =========================================================
   L5
========================================================= */

app.get(
    "/api/l5",
    async (req, res) => {

        try {

            const sessionId =
                String(
                    req.query.session || ""
                );

            const token =
                String(
                    req.query.token || ""
                );

            const session =
                await getLoaderSession(
                    sessionId
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                Number(session.stage) !==
                2
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const consumed =
                await consumeToken(
                    sessionId,
                    token,
                    2
                );

            if (!consumed) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const advanced =
                await advanceLoaderStage(
                    sessionId,
                    2,
                    3
                );

            if (!advanced) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const nextToken =
                await issueLoaderToken(
                    sessionId,
                    3
                );

            const output =
                buildL4(
                    session,
                    nextToken
                );

            return res
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "L5 ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "L5 SERVER ERROR"
            );
        }
    }
);

/* =========================================================
   FINAL
========================================================= */

app.get(
    "/api/l5/final",
    async (req, res) => {

        const started =
            Date.now();

        try {

            const sessionId =
                String(
                    req.query.session || ""
                );

            const token =
                String(
                    req.query.token || ""
                );

            const session =
                await getLoaderSession(
                    sessionId
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                Number(session.stage) !==
                3
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const consumed =
                await consumeToken(
                    sessionId,
                    token,
                    3
                );

            if (!consumed) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const script =
                await getScriptById(
                    session.script_id
                );

            if (!script) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const output =
                buildL5(
                    session,
                    script.source
                );

            const finished =
                now();

            /* =========================================
               EXECUTION LOG
            ========================================= */

            const userAgent =
                String(
                    req.headers[
                        "user-agent"
                    ] || ""
                ).slice(0, 255);

            const ip =
                String(
                    req.ip ||
                    req.headers[
                        "x-forwarded-for"
                    ] ||
                    req.socket?.remoteAddress ||
                    ""
                ).slice(0, 45);

            try {

                await pool.execute(
                    `
                    INSERT INTO
                    script_execution_logs
                    (
                        script_id,
                        loader_session_id,
                        executed_at,
                        success,
                        ip_address,
                        user_agent,
                        execution_time_ms
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?)
                    `,
                    [
                        script.id,
                        session.session_id,
                        finished,
                        ip,
                        userAgent,
                        finished - started
                    ]
                );

            } catch (logError) {

                console.error(
                    "EXECUTION LOG ERROR:",
                    logError
                );
            }

            /* =========================================
               MARK COMPLETED
            ========================================= */

            await pool.execute(
                `
                UPDATE loader_sessions
                SET
                    completed_at = ?
                WHERE
                    session_id = ?
                `,
                [
                    finished,
                    session.session_id
                ]
            );

            /*
             * Keep the session for the moment so
             * execution_logs foreign key remains valid.
             *
             * It will be removed by cleanup.
             */

            return res
                .status(200)
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "FINAL ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "FINAL SERVER ERROR"
            );
        }
    }
);

/* =========================================================
   API 404
========================================================= */

app.use(
    "/api",
    (req, res) => {

        return apiError(
            res,
            404,
            "API ROUTE NOT FOUND"
        );
    }
);

/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }
);

/* =========================================================
   UNKNOWN PAGE
========================================================= */

app.use(
    (req, res) => {

        return res
            .status(404)
            .send(
                "Page not found."
            );
    }
);

/* =========================================================
   DATABASE CLEANUP
========================================================= */

async function cleanupDatabase() {

    try {

        const current =
            now();

        /*
         * Web sessions
         */

        await pool.execute(
            `
            DELETE FROM web_sessions
            WHERE expires_at < ?
            `,
            [current]
        );

        /*
         * Loader sessions.
         *
         * Tokens have ON DELETE CASCADE,
         * so deleting the session removes
         * its tokens automatically.
         */

        await pool.execute(
            `
            DELETE FROM loader_sessions
            WHERE expires_at < ?
            `,
            [current]
        );

        /*
         * Old rate limits
         */

        await pool.execute(
            `
            DELETE FROM rate_limits
            WHERE window_start < ?
            `,
            [
                current -
                60 * 60 * 1000
            ]
        );

        console.log(
            "[CLEANUP] Database cleanup completed."
        );

    } catch (error) {

        console.error(
            "[CLEANUP ERROR]",
            error
        );
    }
}

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    async (req, res) => {

        try {

            const [rows] =
                await pool.query(
                    "SELECT 1 AS ok"
                );

            return res.json({
                ok:
                    rows[0]?.ok === 1,

                database:
                    "mysql",

                timestamp:
                    now()
            });

        } catch (error) {

            return res
                .status(503)
                .json({
                    ok: false,
                    database:
                        "unavailable"
                });
        }
    }
);

/* =========================================================
   STARTUP
========================================================= */

testDatabase();

/*
 * Cleanup every 5 minutes.
 *
 * The SQL EVENT in your schema can also
 * perform cleanup on a MySQL server that
 * has EVENT scheduler enabled.
 */

setInterval(
    cleanupDatabase,
    5 * 60 * 1000
);

/*
 * Vercel:
 * export the Express application.
 *
 * Normal Node hosting:
 * start app.listen().
 */

module.exports = app;

if (
    !process.env.VERCEL
) {

    app.listen(
        PORT,
        () => {

            console.log(
                "LEXINX server running on port " +
                PORT
            );

            console.log(
                "PUBLIC URL: " +
                PUBLIC_URL
            );
        }
    );
}
