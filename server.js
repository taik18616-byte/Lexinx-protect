const express = require("express");
const crypto = require("crypto");
const path = require("path");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 3000;
const PUBLIC_URL = process.env.PUBLIC_URL || "https://lexinx-protect-v230.vercel.app";

const WEB_SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const LOADER_SESSION_TTL = 60 * 1000;

app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

/* =========================================================
   STATIC
========================================================= */

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

/* =========================================================
   DATABASE CONNECTION
========================================================= */

const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "lexinx_protect",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    charset: "utf8mb4"
});

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
   WEB SESSION
========================================================= */

async function createWebSession(username) {

    const id =
        randomHex(32);

    const now =
        Date.now();

    const expires =
        now + WEB_SESSION_TTL;

    try {

        await pool.execute(
            `INSERT INTO web_sessions 
             (session_id, username_lower, created_at, expires_at) 
             VALUES (?, ?, ?, ?)`,
            [
                id,
                username.toLowerCase(),
                now,
                expires
            ]
        );

        return id;

    } catch (error) {

        console.error(
            "Error creating web session:",
            error
        );

        return null;
    }
}

async function getWebAuth(req) {

    const sid =
        getCookie(
            req,
            "lexinx_session"
        );

    if (!sid)
        return null;

    try {

        const [rows] = await pool.execute(
            `SELECT 
                ws.session_id,
                ws.username_lower,
                u.username,
                u.password_hash
             FROM web_sessions ws 
             JOIN users u ON ws.username_lower = u.username_lower 
             WHERE ws.session_id = ? 
               AND ws.expires_at > ?`,
            [
                sid,
                Date.now()
            ]
        );

        if (rows.length === 0) {

            await pool.execute(
                "DELETE FROM web_sessions WHERE session_id = ?",
                [sid]
            );

            return null;
        }

        const session = rows[0];

        return {
            sid: session.session_id,
            username: session.username,
            username_lower: session.username_lower,
            user: {
                username: session.username
            }
        };

    } catch (error) {

        console.error(
            "Error getting web auth:",
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

            const key =
                username.toLowerCase();

            const now =
                Date.now();

            const [existing] = await pool.execute(
                "SELECT username_lower FROM users WHERE username_lower = ?",
                [key]
            );

            if (existing.length > 0) {

                return apiError(
                    res,
                    409,
                    "Username already exists."
                );
            }

            await pool.execute(
                `INSERT INTO users 
                 (username, username_lower, password_hash, created_at, updated_at) 
                 VALUES (?, ?, ?, ?, ?)`,
                [
                    username,
                    key,
                    hashPassword(password),
                    now,
                    now
                ]
            );

            const sid =
                await createWebSession(username);

            if (!sid) {

                return apiError(
                    res,
                    500,
                    "Failed to create session."
                );
            }

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
                username: username,
                url:
                    PUBLIC_URL + "/"
            });

        } catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

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

            const key =
                username.toLowerCase();

            const [users] = await pool.execute(
                "SELECT username, username_lower, password_hash FROM users WHERE username_lower = ?",
                [key]
            );

            if (users.length === 0) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );
            }

            const user = users[0];

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

            const sid =
                await createWebSession(user.username);

            if (!sid) {

                return apiError(
                    res,
                    500,
                    "Failed to create session."
                );
            }

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

        const sid =
            getCookie(
                req,
                "lexinx_session"
            );

        if (sid) {

            try {

                await pool.execute(
                    "DELETE FROM web_sessions WHERE session_id = ?",
                    [sid]
                );

            } catch (error) {

                console.error(
                    "Error deleting session:",
                    error
                );
            }
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

            let id;

            do {
                id = randomHex(12);
            } while (
                await checkScriptExists(id)
            );

            const now =
                Date.now();

            await pool.execute(
                `INSERT INTO scripts 
                 (id, name, source, owner_username, created_at, updated_at, is_active) 
                 VALUES (?, ?, ?, ?, ?, ?, 1)`,
                [
                    id,
                    name || "Untitled Script",
                    source,
                    req.auth.username_lower,
                    now,
                    now
                ]
            );

            const loader =
                `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${id}"))()`;

            return res.json({
                ok: true,
                id: id,
                loader: loader
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

async function checkScriptExists(id) {

    try {

        const [rows] = await pool.execute(
            "SELECT id FROM scripts WHERE id = ?",
            [id]
        );

        return rows.length > 0;

    } catch (error) {

        console.error(
            "Error checking script:",
            error
        );

        return false;
    }
}

/* =========================================================
   LIST SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireAuth,
    async (req, res) => {

        try {

            const [scripts] = await pool.execute(
                `SELECT id, name, created_at, updated_at 
                 FROM scripts 
                 WHERE owner_username = ? 
                   AND is_active = 1 
                 ORDER BY created_at DESC`,
                [
                    req.auth.username_lower
                ]
            );

            const result = scripts.map(script => ({

                id:
                    script.id,

                name:
                    script.name,

                loader:
                    `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${script.id}"))()`,

                created:
                    script.created_at,

                updated:
                    script.updated_at

            }));

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

            const [scripts] = await pool.execute(
                `SELECT id, name, source, owner_username 
                 FROM scripts 
                 WHERE id = ? 
                   AND is_active = 1`,
                [
                    req.params.id
                ]
            );

            if (scripts.length === 0) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const script = scripts[0];

            if (
                script.owner_username !==
                req.auth.username_lower
            ) {

                return apiError(
                    res,
                    403,
                    "Access denied."
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

            const [scripts] = await pool.execute(
                "SELECT id, owner_username FROM scripts WHERE id = ? AND is_active = 1",
                [req.params.id]
            );

            if (scripts.length === 0) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const script = scripts[0];

            if (
                script.owner_username !==
                req.auth.username_lower
            ) {

                return apiError(
                    res,
                    403,
                    "Access denied."
                );
            }

            const updateFields = [];
            const updateValues = [];

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

                updateFields.push("name = ?");
                updateValues.push(name);
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

                updateFields.push("source = ?");
                updateValues.push(req.body.source);
            }

            if (updateFields.length === 0) {

                return apiError(
                    res,
                    400,
                    "No fields to update."
                );
            }

            updateFields.push("updated_at = ?");
            updateValues.push(Date.now());
            updateValues.push(req.params.id);

            await pool.execute(
                `UPDATE scripts SET ${updateFields.join(", ")} WHERE id = ?`,
                updateValues
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
========================================================= */

app.delete(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const [scripts] = await pool.execute(
                "SELECT id, owner_username FROM scripts WHERE id = ? AND is_active = 1",
                [req.params.id]
            );

            if (scripts.length === 0) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const script = scripts[0];

            if (
                script.owner_username !==
                req.auth.username_lower
            ) {

                return apiError(
                    res,
                    403,
                    "Access denied."
                );
            }

            await pool.execute(
                "UPDATE scripts SET is_active = 0, updated_at = ? WHERE id = ?",
                [Date.now(), req.params.id]
            );

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
   LOADER SESSION
========================================================= */

async function createLoaderSession(scriptId) {

    const id =
        randomHex(32);

    const now =
        Date.now();

    const expires =
        now + LOADER_SESSION_TTL;

    try {

        await pool.execute(
            `INSERT INTO loader_sessions 
             (session_id, script_id, stage, created_at, expires_at) 
             VALUES (?, ?, 0, ?, ?)`,
            [
                id,
                scriptId,
                now,
                expires
            ]
        );

    } catch (error) {

        console.error(
            "Error creating loader session:",
            error
        );
    }

    return {
        id: id,
        scriptId: scriptId,
        stage: 0,
        tokens: new Set(),
        created: now,
        expires: expires
    };
}

async function issueToken(session) {

    const token =
        randomHex(32);

    try {

        await pool.execute(
            `INSERT INTO loader_tokens 
             (session_id, token, stage, is_used, created_at) 
             VALUES (?, ?, ?, 0, ?)`,
            [
                session.id,
                token,
                session.stage,
                Date.now()
            ]
        );

        session.tokens.add(token);

        return token;

    } catch (error) {

        console.error(
            "Error issuing token:",
            error
        );

        return null;
    }
}

async function consumeToken(session, token) {

    if (!token)
        return false;

    if (
        !session.tokens.has(token)
    ) {
        return false;
    }

    session.tokens.delete(token);

    try {

        await pool.execute(
            `UPDATE loader_tokens 
             SET is_used = 1, used_at = ? 
             WHERE token = ? 
               AND is_used = 0`,
            [
                Date.now(),
                token
            ]
        );

    } catch (error) {

        console.error(
            "Error consuming token:",
            error
        );
    }

    return true;
}

async function getLoaderSession(sessionId, expectedStage) {

    try {

        const [sessions] = await pool.execute(
            `SELECT * FROM loader_sessions 
             WHERE session_id = ? 
               AND stage = ? 
               AND expires_at > ?`,
            [
                sessionId,
                expectedStage,
                Date.now()
            ]
        );

        if (sessions.length === 0) {
            return null;
        }

        const sessionData = sessions[0];

        const session = {
            id: sessionData.session_id,
            scriptId: sessionData.script_id,
            stage: sessionData.stage,
            tokens: new Set(),
            created: sessionData.created_at,
            expires: sessionData.expires_at
        };

        const [tokens] = await pool.execute(
            "SELECT token FROM loader_tokens WHERE session_id = ? AND is_used = 0",
            [session.id]
        );

        tokens.forEach(t => session.tokens.add(t.token));

        return session;

    } catch (error) {

        console.error(
            "Error getting loader session:",
            error
        );

        return null;
    }
}

async function updateLoaderStage(sessionId, newStage) {

    try {

        await pool.execute(
            "UPDATE loader_sessions SET stage = ? WHERE session_id = ?",
            [newStage, sessionId]
        );

    } catch (error) {

        console.error(
            "Error updating loader stage:",
            error
        );
    }
}

async function deleteLoaderSession(sessionId) {

    try {

        await pool.execute(
            "DELETE FROM loader_sessions WHERE session_id = ?",
            [sessionId]
        );

    } catch (error) {

        console.error(
            "Error deleting loader session:",
            error
        );
    }
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
   WRAPPER
========================================================= */

function buildWrapper(session) {

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

    const request =
        randomLuaName();

    return `

-- LEXINX WRAPPER VM

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${sessionVar} =
    ${luaString(session.id)}

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
   L3 PACKED PROTOTYPE
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
        ${luaString(session.id)},

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
   L4 RUNTIME
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
        ${luaString(session.id)},

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

        try {

            const id =
                String(
                    req.params.id || ""
                ).trim();

            if (!id) {
                return blockPage(res);
            }

            const [scripts] = await pool.execute(
                "SELECT id FROM scripts WHERE id = ? AND is_active = 1",
                [id]
            );

            if (scripts.length === 0) {

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
                await createLoaderSession(
                    id
                );

            const wrapper =
                buildWrapper(
                    session
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

            const session =
                await getLoaderSession(
                    req.query.session,
                    0
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !await consumeToken(
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

            await updateLoaderStage(
                session.id,
                1
            );

            session.stage = 1;

            const l2 =
                buildL2(
                    session
                );

            return res
                .type("text/plain")
                .send(l2);

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
                await getLoaderSession(
                    req.query.session,
                    1
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !await consumeToken(
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

            await updateLoaderStage(
                session.id,
                2
            );

            session.stage = 2;

            const l3 =
                buildL3(
                    session
                );

            return res
                .type("text/plain")
                .send(l3);

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
                await getLoaderSession(
                    req.query.session,
                    2
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !await consumeToken(
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

            await updateLoaderStage(
                session.id,
                3
            );

            session.stage = 3;

            const l4 =
                buildL4(
                    session
                );

            return res
                .type("text/plain")
                .send(l4);

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
                await getLoaderSession(
                    req.query.session,
                    3
                );

            if (!session) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );
            }

            if (
                !await consumeToken(
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

            const [scripts] = await pool.execute(
                "SELECT source FROM scripts WHERE id = ? AND is_active = 1",
                [session.scriptId]
            );

            if (scripts.length === 0) {

                await deleteLoaderSession(
                    session.id
                );

                return apiError(
                    res,
                    404,
                    "Script not found."
                );
            }

            const output =
                buildL5(
                    session,
                    scripts[0].source
                );

            await deleteLoaderSession(
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
   ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {

        console.error(
            "GLOBAL ERROR:",
            err
        );

        return apiError(
            res,
            500,
            "Internal server error"
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

        try {

            await pool.execute(
                "DELETE FROM loader_sessions WHERE expires_at < ?",
                [now]
            );

            await pool.execute(
                "DELETE FROM web_sessions WHERE expires_at < ?",
                [now]
            );

            await pool.execute(
                "DELETE FROM rate_limits WHERE window_start < ?",
                [now - 3600000]
            );

        } catch (error) {

            console.error(
                "CLEANUP ERROR:",
                error
            );
        }

    },
    5 * 60 * 1000
);

/* =========================================================
   SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            "========================================"
        );

        console.log(
            "LEXINX PROTECT SERVER"
        );

        console.log(
            "========================================"
        );

        console.log(
            "Server running on port: " +
            PORT
        );

        console.log(
            "Public URL: " +
            PUBLIC_URL
        );

        console.log(
            "Database: Connected"
        );

        console.log(
            "========================================"
        );

    }
);

process.on(
    'unhandledRejection',
    (error) => {

        console.error(
            'UNHANDLED REJECTION:',
            error
        );
    }
);

process.on(
    'uncaughtException',
    (error) => {

        console.error(
            'UNCAUGHT EXCEPTION:',
            error
        );
    }
);
