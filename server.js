const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 3000;

const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://lexinx-protect.onrender.com";

const WEB_SESSION_TTL =
    7 * 24 * 60 * 60 * 1000;

const LOADER_SESSION_TTL =
    60 * 1000;

/* =========================================================
   POSTGRESQL
========================================================= */

if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    },

    max: 10,

    idleTimeoutMillis: 30000,

    connectionTimeoutMillis: 10000
});

pool.on("error", (err) => {
    console.error("POSTGRES POOL ERROR:", err);
});

/* =========================================================
   EXPRESS
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
    return JSON.stringify(String(value));
}

function hexEncode(value) {
    return Buffer
        .from(String(value), "utf8")
        .toString("hex");
}

function apiError(res, status, message) {
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
                return decodeURIComponent(value);
            } catch {
                return value;
            }
        }
    }

    return null;
}

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

            user_id BIGINT NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            script_id VARCHAR(64) NOT NULL UNIQUE,

            name VARCHAR(100)
                NOT NULL
                DEFAULT 'My Script',

            source TEXT
                NOT NULL
                DEFAULT '',

            enabled BOOLEAN
                NOT NULL
                DEFAULT TRUE,

            created_at TIMESTAMPTZ
                NOT NULL
                DEFAULT NOW(),

            updated_at TIMESTAMPTZ
                NOT NULL
                DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_scripts_user_id
        ON scripts(user_id);

        CREATE INDEX IF NOT EXISTS idx_scripts_script_id
        ON scripts(script_id);

        CREATE TABLE IF NOT EXISTS login_sessions (
            id BIGSERIAL PRIMARY KEY,

            user_id BIGINT NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            session_token TEXT
                NOT NULL
                UNIQUE,

            created_at TIMESTAMPTZ
                NOT NULL
                DEFAULT NOW(),

            expires_at TIMESTAMPTZ,

            last_seen_at TIMESTAMPTZ
                NOT NULL
                DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_login_sessions_token
        ON login_sessions(session_token);

        CREATE INDEX IF NOT EXISTS idx_login_sessions_user_id
        ON login_sessions(user_id);

        CREATE TABLE IF NOT EXISTS script_access_logs (
            id BIGSERIAL PRIMARY KEY,

            user_id BIGINT
                REFERENCES users(id)
                ON DELETE SET NULL,

            script_id VARCHAR(64),

            ip_address INET,

            success BOOLEAN
                NOT NULL
                DEFAULT FALSE,

            created_at TIMESTAMPTZ
                NOT NULL
                DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_access_logs_script
        ON script_access_logs(script_id);

        CREATE INDEX IF NOT EXISTS idx_access_logs_user
        ON script_access_logs(user_id);
    `);

    console.log("PostgreSQL database initialized.");
}

/* =========================================================
   WEB AUTH
========================================================= */

async function getWebAuth(req) {

    const sid =
        getCookie(
            req,
            "lexinx_session"
        );

    if (!sid)
        return null;

    try {

        const result =
            await pool.query(
                `
                SELECT
                    s.session_token,
                    s.user_id,
                    s.expires_at,
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
                [sid]
            );

        if (result.rowCount === 0)
            return null;

        const row =
            result.rows[0];

        await pool.query(
            `
            UPDATE login_sessions
            SET last_seen_at = NOW()
            WHERE session_token = $1
            `,
            [sid]
        );

        return {
            sid,
            userId: row.user_id,
            username: row.username
        };

    } catch (error) {

        console.error(
            "AUTH ERROR:",
            error
        );

        return null;
    }
}

async function requireAuth(req, res, next) {

    const auth =
        await getWebAuth(req);

    if (!auth) {

        return apiError(
            res,
            401,
            "Authentication required."
        );
    }

    req.auth = auth;

    next();
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
                    ($1, $2)
                    RETURNING id, username
                    `,
                    [
                        username,
                        passwordHash
                    ]
                );

            const user =
                result.rows[0];

            const sessionToken =
                randomHex(32);

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

            res.cookie(
                "lexinx_session",
                sessionToken,
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
                "REGISTER ERROR:",
                error
            );

            if (
                error.code === "23505"
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
                result.rowCount === 0
            ) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );
            }

            const user =
                result.rows[0];

            if (
                user.password_hash !==
                hashPassword(password)
            ) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );
            }

            const sessionToken =
                randomHex(32);

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

            res.cookie(
                "lexinx_session",
                sessionToken,
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

                await pool.query(
                    `
                    DELETE FROM login_sessions
                    WHERE session_token = $1
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
                "Logout error."
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
                    req.body.source ||
                    ""
                );

            if (!source.trim()) {

                return apiError(
                    res,
                    400,
                    "Script source cannot be empty."
                );
            }

            let scriptId;

            do {

                scriptId =
                    randomHex(12);

                const check =
                    await pool.query(
                        `
                        SELECT id
                        FROM scripts
                        WHERE script_id = $1
                        LIMIT 1
                        `,
                        [scriptId]
                    );

                if (
                    check.rowCount === 0
                ) {
                    break;
                }

            } while (true);

            await pool.query(
                `
                INSERT INTO scripts
                (
                    user_id,
                    script_id,
                    name,
                    source
                )
                VALUES
                (
                    $1,
                    $2,
                    $3,
                    $4
                )
                `,
                [
                    req.auth.userId,
                    scriptId,
                    name ||
                        "Untitled Script",
                    source
                ]
            );

            const loader =
                `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${scriptId}"))()`;

            return res.json({
                ok: true,
                id: scriptId,
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

            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        name,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    `,
                    [
                        req.auth.userId
                    ]
                );

            const scripts =
                result.rows.map(
                    (script) => ({
                        id:
                            script.script_id,

                        name:
                            script.name,

                        loader:
                            `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${script.script_id}"))()`,

                        created:
                            script.created_at,

                        updated:
                            script.updated_at
                    })
                );

            return res.json({
                ok: true,
                scripts
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
                        req.params.id,
                        req.auth.userId
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const script =
                result.rows[0];

            return res.json({
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
                "GET SCRIPT ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to get script."
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

            const id =
                req.params.id;

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM scripts
                    WHERE
                        script_id = $1
                        AND user_id = $2
                    LIMIT 1
                    `,
                    [
                        id,
                        req.auth.userId
                    ]
                );

            if (
                existing.rowCount === 0
            ) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const updates = [];
            const values = [];

            let index = 1;

            if (
                typeof req.body.name ===
                "string"
            ) {

                const name =
                    req.body.name
                        .trim()
                        .slice(0, 100)
                        ||
                        "Untitled Script";

                updates.push(
                    `name = $${index++}`
                );

                values.push(name);
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

                updates.push(
                    `source = $${index++}`
                );

                values.push(
                    req.body.source
                );
            }

            if (
                updates.length === 0
            ) {

                return res.json({
                    ok: true
                });
            }

            updates.push(
                "updated_at = NOW()"
            );

            values.push(id);
            values.push(
                req.auth.userId
            );

            await pool.query(
                `
                UPDATE scripts
                SET
                    ${updates.join(", ")}
                WHERE
                    script_id = $${index}
                    AND user_id = $${index + 1}
                `,
                values
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
                "Failed to update script."
            );
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
                    RETURNING id
                    `,
                    [
                        req.params.id,
                        req.auth.userId
                    ]
                );

            if (
                result.rowCount === 0
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
                "Failed to delete script."
            );
        }
    }
);

/* =========================================================
   LOADER SESSION
   Runtime sessions stay in RAM.
   Script/user data stays in PostgreSQL.
========================================================= */

const loaderSessions =
    new Map();

function createLoaderSession(
    scriptId
) {

    const id =
        randomHex(32);

    const session = {

        id,

        scriptId,

        stage: 0,

        tokens:
            new Set(),

        created:
            Date.now(),

        expires:
            Date.now() +
            LOADER_SESSION_TTL
    };

    loaderSessions.set(
        id,
        session
    );

    return session;
}

function issueToken(session) {

    const token =
        randomHex(32);

    session.tokens.add(
        token
    );

    return token;
}

function consumeToken(
    session,
    token
) {

    if (!token)
        return false;

    if (
        !session.tokens.has(token)
    ) {
        return false;
    }

    session.tokens.delete(
        token
    );

    return true;
}

function validLoaderSession(
    session
) {

    if (!session)
        return false;

    if (
        Date.now() >
        session.expires
    ) {

        loaderSessions.delete(
            session.id
        );

        return false;
    }

    return true;
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
   LUA HEX DECODER
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

/* =========================================================
   RANDOM LUA NAME
========================================================= */

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
   L2
========================================================= */

function buildL2(session) {

    const token =
        issueToken(session);

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
        ${luaString(session.id)},

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

    if type(response) ~= "string" then
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

function buildL3(session) {

    const token =
        issueToken(session);

    const endpoint =
        hexEncode(PUBLIC_URL);

    const endpointVar =
        randomLuaName();

    const prototype =
        randomLuaName();

    return `

-- LEXINX L3

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${prototype} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)}

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

    if type(response) ~= "string" then
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

function buildL4(session) {

    const token =
        issueToken(session);

    const endpoint =
        hexEncode(PUBLIC_URL);

    const endpointVar =
        randomLuaName();

    const runtime =
        randomLuaName();

    return `

-- LEXINX L4

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${runtime} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)}

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

    if type(response) ~= "string" then
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

        try {

            const id =
                String(
                    req.params.id || ""
                ).trim();

            if (!id) {
                return blockPage(res);
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                    LIMIT 1
                    `,
                    [id]
                );

            if (
                result.rowCount === 0
            ) {

                return blockPage(res);
            }

            const script =
                result.rows[0];

            if (!script.enabled) {
                return blockPage(res);
            }

            const accept =
                String(
                    req.headers.accept || ""
                ).toLowerCase();

            if (
                accept.includes("text/html")
            ) {

                return blockPage(res);
            }

            const session =
                createLoaderSession(
                    script.script_id
                );

            const token =
                issueToken(session);

            const endpoint =
                hexEncode(PUBLIC_URL);

            const endpointVar =
                randomLuaName();

            const sessionVar =
                randomLuaName();

            const tokenVar =
                randomLuaName();

            const wrapper = `

-- LEXINX WRAPPER

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${sessionVar} =
    ${luaString(session.id)}

local ${tokenVar} =
    ${luaString(token)}

local url =
    decodeHex(
        ${endpointVar}
    )
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

if type(response) ~= "string" then
    return
end

local fn =
    loadstring(response)

if fn then
    return fn()
end

`;

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

            const session =
                loaderSessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(session)
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                session.stage !== 0
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            session.stage = 1;

            return res
                .type("text/plain")
                .send(
                    buildL2(session)
                );

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

            const session =
                loaderSessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(session)
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                session.stage !== 1
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            session.stage = 2;

            return res
                .type("text/plain")
                .send(
                    buildL3(session)
                );

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

            const session =
                loaderSessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(session)
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                session.stage !== 2
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            session.stage = 3;

            return res
                .type("text/plain")
                .send(
                    buildL4(session)
                );

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

        try {

            const session =
                loaderSessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(session)
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                session.stage !== 3
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        source,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                    LIMIT 1
                    `,
                    [
                        session.scriptId
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                loaderSessions.delete(
                    session.id
                );

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const script =
                result.rows[0];

            if (!script.enabled) {

                loaderSessions.delete(
                    session.id
                );

                return apiError(
                    res,
                    403,
                    "Script disabled."
                );
            }

            const output =
                buildL5(
                    session,
                    script.source
                );

            /*
             * ACCESS LOG
             */

            const forwarded =
                req.headers["x-forwarded-for"];

            const ip =
                forwarded
                    ? String(forwarded)
                        .split(",")[0]
                        .trim()
                    : req.ip;

            try {

                await pool.query(
                    `
                    INSERT INTO script_access_logs
                    (
                        user_id,
                        script_id,
                        ip_address,
                        success
                    )
                    SELECT
                        user_id,
                        script_id,
                        $1::inet,
                        TRUE
                    FROM scripts
                    WHERE script_id = $2
                    `,
                    [
                        ip,
                        script.script_id
                    ]
                );

            } catch (logError) {

                console.error(
                    "ACCESS LOG ERROR:",
                    logError
                );
            }

            loaderSessions.delete(
                session.id
            );

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
   CLEANUP
========================================================= */

setInterval(
    async () => {

        const now =
            Date.now();

        for (
            const [
                id,
                session
            ]
            of loaderSessions
        ) {

            if (
                now >
                session.expires
            ) {

                loaderSessions.delete(id);
            }
        }

        try {

            await pool.query(
                `
                DELETE FROM login_sessions
                WHERE
                    expires_at IS NOT NULL
                    AND expires_at < NOW()
                `
            );

        } catch (error) {

            console.error(
                "SESSION CLEANUP ERROR:",
                error
            );
        }

    },
    30 * 1000
);

/* =========================================================
   START
========================================================= */

async function startServer() {

    try {

        await initDatabase();

        await pool.query(
            "SELECT NOW()"
        );

        console.log(
            "PostgreSQL connection OK."
        );

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

    } catch (error) {

        console.error(
            "SERVER START ERROR:",
            error
        );

        process.exit(1);
    }
}

startServer();
