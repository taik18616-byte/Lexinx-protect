// server.js
// LEXINX PROTECT
// Persistent PostgreSQL storage + accounts + scripts + L1 -> L5 loader

const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error("ERROR: DATABASE_URL is missing.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   CONFIG
========================================================= */

const TOKEN_TTL = 60 * 1000;
const SESSION_TTL = 30 * 60 * 1000;

const sessions = new Map();

/* =========================================================
   RANDOM
========================================================= */

function randomHex(size = 32) {
    return crypto.randomBytes(size).toString("hex");
}

function randomLuaName() {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    let result = "_";

    for (let i = 0; i < 8; i++) {
        result += chars[
            crypto.randomInt(0, chars.length)
        ];
    }

    return result;
}

/* =========================================================
   PASSWORD
========================================================= */

function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString("hex");

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
                if (err) return reject(err);

                resolve(
                    salt +
                    ":" +
                    derivedKey.toString("hex")
                );
            }
        );
    });
}

function verifyPassword(password, stored) {
    return new Promise((resolve, reject) => {
        try {
            const parts = stored.split(":");

            if (parts.length !== 2) {
                return resolve(false);
            }

            const salt = parts[0];
            const original = Buffer.from(
                parts[1],
                "hex"
            );

            crypto.scrypt(
                password,
                salt,
                64,
                {
                    N: 16384,
                    r: 8,
                    p: 1
                },
                (err, derived) => {
                    if (err) return reject(err);

                    if (
                        original.length !==
                        derived.length
                    ) {
                        return resolve(false);
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
    });
}

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username VARCHAR(32) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS scripts (
            id VARCHAR(64) PRIMARY KEY,
            user_id UUID NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            source TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    console.log("PostgreSQL database ready.");
}

/* =========================================================
   COOKIE HELPERS
========================================================= */

function parseCookies(req) {
    const result = {};

    const header = req.headers.cookie;

    if (!header) {
        return result;
    }

    for (const part of header.split(";")) {

        const index = part.indexOf("=");

        if (index === -1) continue;

        const key =
            part.slice(0, index).trim();

        const value =
            part.slice(index + 1).trim();

        result[key] = decodeURIComponent(value);
    }

    return result;
}

function setCookie(res, name, value, maxAge) {

    const parts = [
        `${name}=${encodeURIComponent(value)}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax"
    ];

    if (process.env.NODE_ENV === "production") {
        parts.push("Secure");
    }

    if (maxAge !== undefined) {
        parts.push(`Max-Age=${maxAge}`);
    }

    res.setHeader(
        "Set-Cookie",
        parts.join("; ")
    );
}

/* =========================================================
   WEB LOGIN SESSION
========================================================= */

const webSessions = new Map();

function createWebSession(userId) {

    const token = randomHex(32);

    webSessions.set(token, {
        userId,
        created: Date.now(),
        expires:
            Date.now() +
            7 * 24 * 60 * 60 * 1000
    });

    return token;
}

function getWebUser(req) {

    const cookies = parseCookies(req);

    const token = cookies.lexinx_session;

    if (!token) {
        return null;
    }

    const session =
        webSessions.get(token);

    if (!session) {
        return null;
    }

    if (Date.now() > session.expires) {

        webSessions.delete(token);

        return null;
    }

    return session.userId;
}

/* =========================================================
   API AUTH
========================================================= */

async function requireAuth(req, res, next) {

    const userId = getWebUser(req);

    if (!userId) {
        return res.status(401).json({
            ok: false,
            error: "LOGIN_REQUIRED"
        });
    }

    const result = await pool.query(
        `
        SELECT id, username
        FROM users
        WHERE id = $1
        `,
        [userId]
    );

    if (!result.rows.length) {
        return res.status(401).json({
            ok: false,
            error: "USER_NOT_FOUND"
        });
    }

    req.user = result.rows[0];

    next();
}

/* =========================================================
   WEB PAGE
========================================================= */

function webPage() {

    return `
<!doctype html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>LEXINX PROTECT</title>

<style>

*{
    box-sizing:border-box;
}

html,body{
    margin:0;
    min-height:100%;
    background:#050505;
    color:#eee;
    font-family:Arial,sans-serif;
}

body{
    min-height:100vh;
}

.stars{
    position:fixed;
    inset:0;
    pointer-events:none;
    background-image:
        radial-gradient(#777 1px,transparent 1px),
        radial-gradient(#444 1px,transparent 1px);
    background-size:
        41px 41px,
        73px 73px;
    background-position:
        0 0,
        21px 37px;
    opacity:.2;
}

.wrap{
    position:relative;
    z-index:2;
    width:min(1100px,94%);
    margin:40px auto;
}

.logo{
    text-align:center;
    font-size:38px;
    font-weight:900;
    letter-spacing:8px;
    margin-bottom:30px;
}

.card{
    background:#111;
    border:1px solid #292929;
    border-radius:14px;
    padding:22px;
    margin-bottom:16px;
}

h2{
    margin-top:0;
}

input,textarea{
    width:100%;
    background:#070707;
    color:#eee;
    border:1px solid #333;
    border-radius:8px;
    padding:12px;
    outline:none;
}

textarea{
    min-height:300px;
    resize:vertical;
    font-family:Consolas,monospace;
}

button{
    border:0;
    background:#eee;
    color:#111;
    padding:11px 16px;
    border-radius:8px;
    font-weight:bold;
    cursor:pointer;
}

button.secondary{
    background:#222;
    color:#eee;
    border:1px solid #333;
}

.row{
    display:flex;
    gap:10px;
    margin-top:10px;
    flex-wrap:wrap;
}

.script{
    padding:14px;
    border:1px solid #292929;
    border-radius:9px;
    margin-top:10px;
    background:#0b0b0b;
}

.small{
    color:#777;
    font-size:13px;
}

</style>

</head>

<body>

<div class="stars"></div>

<div class="wrap">

<div class="logo">
LEXINX PROTECT
</div>

<div id="app"></div>

</div>

<script>

async function api(url, options = {}) {

    const response =
        await fetch(
            url,
            {
                credentials:"same-origin",
                ...options,
                headers:{
                    "Content-Type":
                        "application/json",
                    ...(options.headers || {})
                }
            }
        );

    let data;

    try {
        data = await response.json();
    } catch {
        data = {
            ok:false,
            error:"INVALID_RESPONSE"
        };
    }

    if (!response.ok) {
        throw new Error(
            data.error || "Request failed"
        );
    }

    return data;
}

function escapeHtml(value) {

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
}

async function loadUser() {

    const app =
        document.getElementById("app");

    try {

        const data =
            await api("/api/me");

        if (!data.authenticated) {

            app.innerHTML = \`
<div class="card">

<h2>Login</h2>

<input
    id="loginUser"
    placeholder="Username"
>

<br><br>

<input
    id="loginPass"
    type="password"
    placeholder="Password"
>

<div class="row">

<button onclick="login()">
LOGIN
</button>

<button
    class="secondary"
    onclick="showRegister()"
>
REGISTER
</button>

</div>

</div>
\`;

            return;
        }

        await dashboard(data.user);

    } catch (e) {

        app.innerHTML =
            "<div class='card'>" +
            escapeHtml(e.message) +
            "</div>";
    }
}

async function login() {

    try {

        await api(
            "/api/login",
            {
                method:"POST",
                body:JSON.stringify({
                    username:
                        document.getElementById(
                            "loginUser"
                        ).value,

                    password:
                        document.getElementById(
                            "loginPass"
                        ).value
                })
            }
        );

        location.reload();

    } catch(e) {

        alert(e.message);

    }
}

function showRegister() {

    document.getElementById("app").innerHTML = \`
<div class="card">

<h2>Create account</h2>

<input
    id="regUser"
    maxlength="32"
    placeholder="Username"
>

<br><br>

<input
    id="regPass"
    type="password"
    placeholder="Password"
>

<div class="row">

<button onclick="register()">
CREATE ACCOUNT
</button>

<button
    class="secondary"
    onclick="loadUser()"
>
BACK
</button>

</div>

</div>
\`;
}

async function register() {

    try {

        await api(
            "/api/register",
            {
                method:"POST",
                body:JSON.stringify({
                    username:
                        document.getElementById(
                            "regUser"
                        ).value,

                    password:
                        document.getElementById(
                            "regPass"
                        ).value
                })
            }
        );

        location.reload();

    } catch(e) {

        alert(e.message);

    }
}

async function dashboard(user) {

    const app =
        document.getElementById("app");

    app.innerHTML = \`
<div class="card">

<h2>
Welcome, \${escapeHtml(user.username)}
</h2>

<div class="small">
Your account is persistent.
</div>

<div class="row">

<button
    class="secondary"
    onclick="logout()"
>
LOGOUT
</button>

<button onclick="newScript()">
NEW SCRIPT
</button>

</div>

</div>

<div
    class="card"
    id="editor"
    style="display:none"
></div>

<div class="card">

<h2>Your scripts</h2>

<div id="scripts">
Loading...
</div>

</div>
\`;

    await loadScripts();
}

async function loadScripts() {

    const box =
        document.getElementById("scripts");

    try {

        const data =
            await api("/api/scripts");

        if (!data.scripts.length) {

            box.innerHTML =
                "<div class='small'>" +
                "No scripts yet." +
                "</div>";

            return;
        }

        box.innerHTML =
            data.scripts.map(
                script => \`
<div class="script">

<strong>
\${escapeHtml(script.name)}
</strong>

<div class="small">
ID: \${escapeHtml(script.id)}
</div>

<div class="row">

<button
    onclick="editScript(
        '\${escapeHtml(script.id)}'
    )"
>
EDIT
</button>

<button
    class="secondary"
    onclick="deleteScript(
        '\${escapeHtml(script.id)}'
    )"
>
DELETE
</button>

</div>

</div>
\`
            ).join("");

    } catch(e) {

        box.innerHTML =
            escapeHtml(e.message);

    }
}

function newScript() {

    const editor =
        document.getElementById("editor");

    editor.style.display = "block";

    editor.innerHTML = \`
<h2>New script</h2>

<input
    id="scriptName"
    placeholder="Script name"
>

<br><br>

<textarea
    id="scriptSource"
    placeholder="Lua / Luau source"
></textarea>

<div class="row">

<button onclick="createScript()">
SAVE
</button>

<button
    class="secondary"
    onclick="closeEditor()"
>
CANCEL
</button>

</div>
\`;
}

async function createScript() {

    try {

        await api(
            "/api/scripts",
            {
                method:"POST",
                body:JSON.stringify({
                    name:
                        document.getElementById(
                            "scriptName"
                        ).value,

                    source:
                        document.getElementById(
                            "scriptSource"
                        ).value
                })
            }
        );

        closeEditor();

        await loadScripts();

    } catch(e) {

        alert(e.message);

    }
}

async function editScript(id) {

    try {

        const data =
            await api(
                "/api/scripts/" +
                encodeURIComponent(id)
            );

        const editor =
            document.getElementById("editor");

        editor.style.display = "block";

        editor.innerHTML = \`
<h2>Edit script</h2>

<input
    id="scriptName"
    value="\${escapeHtml(data.script.name)}"
>

<br><br>

<textarea
    id="scriptSource"
>\${escapeHtml(data.script.source)}</textarea>

<div class="row">

<button
    onclick="saveEdit(
        '\${escapeHtml(data.script.id)}'
    )"
>
SAVE
</button>

<button
    class="secondary"
    onclick="closeEditor()"
>
CANCEL
</button>

</div>
\`;

    } catch(e) {

        alert(e.message);

    }
}

async function saveEdit(id) {

    try {

        await api(
            "/api/scripts/" +
            encodeURIComponent(id),
            {
                method:"PUT",
                body:JSON.stringify({
                    name:
                        document.getElementById(
                            "scriptName"
                        ).value,

                    source:
                        document.getElementById(
                            "scriptSource"
                        ).value
                })
            }
        );

        closeEditor();

        await loadScripts();

    } catch(e) {

        alert(e.message);

    }
}

async function deleteScript(id) {

    if (!confirm(
        "Delete this script?"
    )) {
        return;
    }

    try {

        await api(
            "/api/scripts/" +
            encodeURIComponent(id),
            {
                method:"DELETE"
            }
        );

        await loadScripts();

    } catch(e) {

        alert(e.message);

    }
}

function closeEditor() {

    const editor =
        document.getElementById("editor");

    editor.style.display = "none";
    editor.innerHTML = "";

}

async function logout() {

    await api(
        "/api/logout",
        {
            method:"POST"
        }
    );

    location.reload();
}

loadUser();

</script>

</body>
</html>
`;
}

/* =========================================================
   BLOCK PAGE
========================================================= */

function blockPage(res) {

    return res.status(403)
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
    overflow:hidden;
    background:#050505;
    color:#fff;
    font-family:Arial,sans-serif;
}

body{
    display:flex;
    align-items:center;
    justify-content:center;
}

.stars{
    position:absolute;
    inset:0;
    background-image:
        radial-gradient(#777 1px,transparent 1px),
        radial-gradient(#444 1px,transparent 1px);
    background-size:
        37px 37px,
        71px 71px;
    opacity:.3;
}

.box{
    position:relative;
    z-index:2;
    width:min(520px,88%);
    padding:55px 30px;
    text-align:center;
    border:1px solid #333;
    border-radius:18px;
    background:#111;
}

.logo{
    font-size:42px;
    font-weight:900;
    letter-spacing:8px;
    animation:pulse 4s infinite alternate;
}

.sub{
    margin-top:18px;
    color:#777;
    letter-spacing:3px;
    font-size:13px;
}

@keyframes pulse{
    from{
        color:#fff;
    }
    to{
        color:#777;
    }
}

</style>

</head>

<body>

<div class="stars"></div>

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
   API BLOCK
========================================================= */

function apiBlock(res) {

    return res.status(403).json({
        ok:false,
        error:"LEXINX BLOCK"
    });
}

/* =========================================================
   AUTH ROUTES
========================================================= */

app.get("/api/me", async (req, res) => {

    const userId =
        getWebUser(req);

    if (!userId) {

        return res.json({
            authenticated:false
        });
    }

    const result =
        await pool.query(
            `
            SELECT id, username, created_at
            FROM users
            WHERE id = $1
            `,
            [userId]
        );

    if (!result.rows.length) {

        return res.json({
            authenticated:false
        });
    }

    return res.json({
        authenticated:true,
        user:result.rows[0]
    });
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {

    try {

        const username =
            String(
                req.body.username || ""
            ).trim();

        const password =
            String(
                req.body.password || ""
            );

        if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {

            return res.status(400).json({
                ok:false,
                error:
                    "Username must contain 3-32 letters, numbers or underscore."
            });
        }

        if (password.length < 6) {

            return res.status(400).json({
                ok:false,
                error:
                    "Password must contain at least 6 characters."
            });
        }

        const existing =
            await pool.query(
                `
                SELECT id
                FROM users
                WHERE LOWER(username) = LOWER($1)
                `,
                [username]
            );

        if (existing.rows.length) {

            return res.status(409).json({
                ok:false,
                error:"USERNAME_ALREADY_EXISTS"
            });
        }

        const id =
            crypto.randomUUID();

        const passwordHash =
            await hashPassword(password);

        await pool.query(
            `
            INSERT INTO users
            (id, username, password_hash)
            VALUES ($1,$2,$3)
            `,
            [
                id,
                username,
                passwordHash
            ]
        );

        const session =
            createWebSession(id);

        setCookie(
            res,
            "lexinx_session",
            session,
            7 * 24 * 60 * 60
        );

        return res.json({
            ok:true,
            user:{
                id,
                username
            }
        });

    } catch (error) {

        console.error(
            "REGISTER ERROR:",
            error
        );

        return res.status(500).json({
            ok:false,
            error:"REGISTER_FAILED"
        });
    }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {

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
                SELECT id, username, password_hash
                FROM users
                WHERE LOWER(username) = LOWER($1)
                `,
                [username]
            );

        if (!result.rows.length) {

            return res.status(401).json({
                ok:false,
                error:"INVALID_LOGIN"
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

            return res.status(401).json({
                ok:false,
                error:"INVALID_LOGIN"
            });
        }

        const session =
            createWebSession(user.id);

        setCookie(
            res,
            "lexinx_session",
            session,
            7 * 24 * 60 * 60
        );

        return res.json({
            ok:true,
            user:{
                id:user.id,
                username:user.username
            }
        });

    } catch (error) {

        console.error(
            "LOGIN ERROR:",
            error
        );

        return res.status(500).json({
            ok:false,
            error:"LOGIN_FAILED"
        });
    }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {

    const cookies =
        parseCookies(req);

    const token =
        cookies.lexinx_session;

    if (token) {
        webSessions.delete(token);
    }

    setCookie(
        res,
        "lexinx_session",
        "",
        0
    );

    return res.json({
        ok:true
    });
});

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/scripts",
    requireAuth,
    async (req, res) => {

        try {

            const name =
                String(
                    req.body.name || ""
                ).trim();

            const source =
                String(
                    req.body.source || ""
                );

            if (
                name.length < 1 ||
                name.length > 100
            ) {

                return res.status(400).json({
                    ok:false,
                    error:
                        "Invalid script name."
                });
            }

            if (!source.trim()) {

                return res.status(400).json({
                    ok:false,
                    error:
                        "Script source is empty."
                });
            }

            const id =
                randomHex(16);

            await pool.query(
                `
                INSERT INTO scripts
                (id,user_id,name,source)
                VALUES ($1,$2,$3,$4)
                `,
                [
                    id,
                    req.user.id,
                    name,
                    source
                ]
            );

            return res.json({
                ok:true,
                id
            });

        } catch (error) {

            console.error(
                "CREATE SCRIPT ERROR:",
                error
            );

            return res.status(500).json({
                ok:false,
                error:"SCRIPT_CREATE_FAILED"
            });
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
                        id,
                        name,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE user_id = $1
                    ORDER BY updated_at DESC
                    `,
                    [req.user.id]
                );

            return res.json({
                ok:true,
                scripts:result.rows
            });

        } catch (error) {

            console.error(
                "LIST SCRIPT ERROR:",
                error
            );

            return res.status(500).json({
                ok:false,
                error:"SCRIPT_LIST_FAILED"
            });
        }
    }
);

/* =========================================================
   GET SCRIPT
========================================================= */

app.get(
    "/api/scripts/:id",
    requireAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        source,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE
                        id = $1
                        AND user_id = $2
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );

            if (!result.rows.length) {

                return res.status(404).json({
                    ok:false,
                    error:"SCRIPT_NOT_FOUND"
                });
            }

            return res.json({
                ok:true,
                script:result.rows[0]
            });

        } catch (error) {

            console.error(
                "GET SCRIPT ERROR:",
                error
            );

            return res.status(500).json({
                ok:false,
                error:"SCRIPT_GET_FAILED"
            });
        }
    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put(
    "/api/scripts/:id",
    requireAuth,
    async (req, res) => {

        try {

            const name =
                String(
                    req.body.name || ""
                ).trim();

            const source =
                String(
                    req.body.source || ""
                );

            if (
                !name ||
                name.length > 100
            ) {

                return res.status(400).json({
                    ok:false,
                    error:
                        "Invalid script name."
                });
            }

            if (!source.trim()) {

                return res.status(400).json({
                    ok:false,
                    error:
                        "Script source is empty."
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE scripts
                    SET
                        name = $1,
                        source = $2,
                        updated_at = NOW()
                    WHERE
                        id = $3
                        AND user_id = $4
                    RETURNING id
                    `,
                    [
                        name,
                        source,
                        req.params.id,
                        req.user.id
                    ]
                );

            if (!result.rows.length) {

                return res.status(404).json({
                    ok:false,
                    error:"SCRIPT_NOT_FOUND"
                });
            }

            return res.json({
                ok:true
            });

        } catch (error) {

            console.error(
                "EDIT SCRIPT ERROR:",
                error
            );

            return res.status(500).json({
                ok:false,
                error:"SCRIPT_UPDATE_FAILED"
            });
        }
    }
);

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete(
    "/api/scripts/:id",
    requireAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM scripts
                    WHERE
                        id = $1
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
                    ok:false,
                    error:"SCRIPT_NOT_FOUND"
                });
            }

            return res.json({
                ok:true
            });

        } catch (error) {

            console.error(
                "DELETE SCRIPT ERROR:",
                error
            );

            return res.status(500).json({
                ok:false,
                error:"SCRIPT_DELETE_FAILED"
            });
        }
    }
);

/* =========================================================
   LOADER SESSION
========================================================= */

function createLoaderSession(scriptId) {

    const id =
        randomHex(32);

    const session = {

        id,

        scriptId,

        stage:1,

        tokens:new Set(),

        created:Date.now(),

        expires:
            Date.now() +
            TOKEN_TTL

    };

    sessions.set(
        id,
        session
    );

    return session;
}

function issueToken(session) {

    const token =
        randomHex(32);

    session.tokens.add(token);

    return token;
}

function consumeToken(
    session,
    token
) {

    if (!token) {
        return false;
    }

    if (!session.tokens.has(token)) {
        return false;
    }

    session.tokens.delete(token);

    return true;
}

function validLoaderSession(session) {

    if (!session) {
        return false;
    }

    if (
        Date.now() >
        session.expires
    ) {

        sessions.delete(
            session.id
        );

        return false;
    }

    return true;
}

/* =========================================================
   LUA STRING
========================================================= */

function luaString(value) {

    return JSON.stringify(
        String(value)
    );
}

/* =========================================================
   L2
========================================================= */

function buildL2(
    session,
    token
) {

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const nextToken =
        issueToken(session);

    return `
-- LEXINX L2
-- This script can't be opened, you skid guys

local ${data} = {

    strings = {

        [0] = "/api/l3",

        [1] = ${luaString(
            nextToken
        )},

        [2] = ${luaString(
            session.id
        )}

    },

    constants = {

        [0] = 2

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(program)

    local stack = {}

    for _,instruction in ipairs(
        program.instructions
    ) do

        if instruction.opcode ==
            "LOADK"
        then

            stack[#stack+1] =
                program.strings[
                    instruction.arg
                ]

        end

    end

    return stack

end

local result =
    ${run}(${data})

local url =
    "https://Lexinx-protect.onrender.com/api/l3"
    .. "?session=" ..
    ${luaString(session.id)}
    .. "&token=" ..
    ${luaString(nextToken)}

local ok,response =
    pcall(function()

        return game:HttpGet(url)

    end)

if not ok then
    return
end

local fn =
    loadstring(response)

if fn then
    return fn()
end
`;
}

/* =========================================================
   L3
========================================================= */

function buildL3(session) {

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const nextToken =
        issueToken(session);

    return `
-- LEXINX L3

local ${data} = {

    strings = {

        [0] = "/api/l4",

        [1] = ${luaString(
            session.id
        )},

        [2] = ${luaString(
            nextToken
        )}

    },

    constants = {

        [0] = 3

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(program)

    local stack = {}

    for _,instruction in ipairs(
        program.instructions
    ) do

        if instruction.opcode ==
            "LOADK"
        then

            stack[#stack+1] =
                program.strings[
                    instruction.arg
                ]

        end

    end

    return stack

end

local result =
    ${run}(${data})

local url =
    "https://Lexinx-protect.onrender.com/api/l4"
    .. "?session=" ..
    ${luaString(session.id)}
    .. "&token=" ..
    ${luaString(nextToken)}

local ok,response =
    pcall(function()

        return game:HttpGet(url)

    end)

if not ok then
    return
end

local fn =
    loadstring(response)

if fn then
    return fn()
end
`;
}

/* =========================================================
   L4
========================================================= */

function buildL4(session) {

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const nextToken =
        issueToken(session);

    return `
-- LEXINX L4 RUNTIME

local ${data} = {

    strings = {

        [0] = "/api/l5",

        [1] = ${luaString(
            session.id
        )},

        [2] = ${luaString(
            nextToken
        )}

    },

    constants = {

        [0] = 4

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(program)

    local stack = {}

    for _,instruction in ipairs(
        program.instructions
    ) do

        if instruction.opcode ==
            "LOADK"
        then

            stack[#stack+1] =
                program.strings[
                    instruction.arg
                ]

        end

    end

    return stack

end

local result =
    ${run}(${data})

local url =
    "https://Lexinx-protect.onrender.com/api/l5"
    .. "?session=" ..
    ${luaString(session.id)}
    .. "&token=" ..
    ${luaString(nextToken)}

local ok,response =
    pcall(function()

        return game:HttpGet(url)

    end)

if not ok then
    return
end

local fn =
    loadstring(response)

if fn then
    return fn()
end
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
            .from(source,"utf8")
            .toString("base64");

    const data =
        randomLuaName();

    const decode =
        randomLuaName();

    return `
-- LEXINX L5 RUNTIME

local ${data} =
    "${payload}"

local ${decode} = function(input)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    local bits = ""

    input =
        input:gsub(
            "[^" .. alphabet .. "=]",
            ""
        )

    for i=1,#input do

        local c =
            input:sub(i,i)

        if c ~= "=" then

            local p =
                alphabet:find(
                    c,
                    1,
                    true
                )

            if p then

                p = p - 1

                for j=5,0,-1 do

                    if
                        math.floor(
                            p / 2^j
                        ) % 2 == 1
                    then

                        bits =
                            bits .. "1"

                    else

                        bits =
                            bits .. "0"

                    end

                end

            end

        end

    end

    local output = {}

    for i=1,#bits-7,8 do

        local byte = 0

        for j=0,7 do

            if
                bits:sub(
                    i+j,
                    i+j
                ) == "1"
            then

                byte =
                    byte +
                    2^(7-j)

            end

        end

        output[#output+1] =
            string.char(byte)

    end

    return table.concat(output)

end

local source =
    ${decode}(${data})

local execute =
    loadstring(source)

if execute then

    return execute()

end
`;
}

/* =========================================================
   L1
========================================================= */

app.get(
    "/api/loader/:id",
    async (req,res) => {

        try {

            const id =
                req.params.id;

            const result =
                await pool.query(
                    `
                    SELECT id
                    FROM scripts
                    WHERE id = $1
                    `,
                    [id]
                );

            if (!result.rows.length) {
                return apiBlock(res);
            }

            const session =
                createLoaderSession(id);

            const token =
                issueToken(session);

            session.stage = 2;

            return res
                .type("text/plain")
                .send(
                    buildL2(
                        session,
                        token
                    )
                );

        } catch (error) {

            console.error(
                "LOADER ERROR:",
                error
            );

            return apiBlock(res);
        }
    }
);

/* =========================================================
   L3
========================================================= */

app.get(
    "/api/l3",
    async (req,res) => {

        try {

            const session =
                sessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(
                    session
                )
            ) {
                return apiBlock(res);
            }

            if (session.stage !== 2) {
                return apiBlock(res);
            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {
                return apiBlock(res);
            }

            session.stage = 3;

            return res
                .type("text/plain")
                .send(
                    buildL3(session)
                );

        } catch {

            return apiBlock(res);

        }
    }
);

/* =========================================================
   L4
========================================================= */

app.get(
    "/api/l4",
    async (req,res) => {

        try {

            const session =
                sessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(
                    session
                )
            ) {
                return apiBlock(res);
            }

            if (session.stage !== 3) {
                return apiBlock(res);
            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {
                return apiBlock(res);
            }

            session.stage = 4;

            return res
                .type("text/plain")
                .send(
                    buildL4(session)
                );

        } catch {

            return apiBlock(res);

        }
    }
);

/* =========================================================
   L5
========================================================= */

app.get(
    "/api/l5",
    async (req,res) => {

        try {

            const session =
                sessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(
                    session
                )
            ) {
                return apiBlock(res);
            }

            if (session.stage !== 4) {
                return apiBlock(res);
            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {
                return apiBlock(res);
            }

            const result =
                await pool.query(
                    `
                    SELECT source
                    FROM scripts
                    WHERE id = $1
                    `,
                    [session.scriptId]
                );

            if (!result.rows.length) {

                sessions.delete(
                    session.id
                );

                return apiBlock(res);
            }

            session.stage = 5;

            const output =
                buildL5(
                    session,
                    result.rows[0].source
                );

            sessions.delete(
                session.id
            );

            return res
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "L5 ERROR:",
                error
            );

            return apiBlock(res);
        }
    }
);

/* =========================================================
   API PROTECTION
========================================================= */

app.use(
    "/api",
    (req,res) => {

        return apiBlock(res);

    }
);

/* =========================================================
   WEBSITE
========================================================= */

app.get("/", (req,res) => {

    return res
        .type("html")
        .send(webPage());

});

/* =========================================================
   UNKNOWN ROUTES
========================================================= */

app.use((req,res) => {

    return blockPage(res);

});

/* =========================================================
   CLEANUP
========================================================= */

setInterval(() => {

    const now =
        Date.now();

    for (
        const [id,session]
        of sessions
    ) {

        if (
            now >
            session.expires
        ) {

            sessions.delete(id);

        }

    }

    for (
        const [token,session]
        of webSessions
    ) {

        if (
            now >
            session.expires
        ) {

            webSessions.delete(token);

        }

    }

},30 * 1000);

/* =========================================================
   DATABASE + SERVER
========================================================= */

initDatabase()
    .then(() => {

        app.listen(
            PORT,
            () => {

                console.log(
                    `LEXINX PROTECT running on port ${PORT}`
                );

            }
        );

    })
    .catch(error => {

        console.error(
            "DATABASE INIT FAILED:",
            error
        );

        process.exit(1);

    });

/* =========================================================
   SHUTDOWN
========================================================= */

async function shutdown() {

    console.log(
        "Shutting down..."
    );

    await pool.end();

    process.exit(0);
}

process.on(
    "SIGTERM",
    shutdown
);

process.on(
    "SIGINT",
    shutdown
);
