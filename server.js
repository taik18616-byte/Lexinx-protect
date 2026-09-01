const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error("DATABASE_URL is missing");
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* =========================================================
   CONFIG
========================================================= */

const TOKEN_TTL = 60 * 1000;

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS scripts (
            id TEXT PRIMARY KEY,
            user_id INTEGER REFERENCES users(id)
                ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    console.log("Database initialized");
}

/* =========================================================
   MEMORY SESSION
========================================================= */

const sessions = new Map();

/*
session = {
    id,
    scriptId,
    stage,
    tokens,
    created,
    expires
}
*/

/* =========================================================
   RANDOM
========================================================= */

function randomHex(size = 32) {
    return crypto.randomBytes(size).toString("hex");
}

function passwordHash(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function createToken() {
    return randomHex(32);
}

/* =========================================================
   SESSION
========================================================= */

function createSession(scriptId) {

    const id = randomHex(32);

    const session = {
        id,
        scriptId,
        stage: 1,
        tokens: new Set(),
        created: Date.now(),
        expires: Date.now() + TOKEN_TTL
    };

    sessions.set(id, session);

    return session;
}

function issueToken(session) {

    const token = createToken();

    session.tokens.add(token);

    return token;
}

function consumeToken(session, token) {

    if (!token) {
        return false;
    }

    if (!session.tokens.has(token)) {
        return false;
    }

    session.tokens.delete(token);

    return true;
}

function validSession(session) {

    if (!session) {
        return false;
    }

    if (Date.now() > session.expires) {

        sessions.delete(session.id);

        return false;
    }

    return true;
}

/* =========================================================
   API BLOCK
========================================================= */

function apiBlock(res) {

    return res.status(403).json({
        ok: false,
        error: "LEXINX BLOCK"
    });
}

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );

});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/auth/register", async (req, res) => {

    try {

        const username =
            String(req.body.username || "").trim();

        const password =
            String(req.body.password || "");

        if (!username || !password) {

            return res.status(400).json({
                ok: false,
                error: "Username and password are required"
            });

        }

        if (username.length < 3) {

            return res.status(400).json({
                ok: false,
                error: "Username must contain at least 3 characters"
            });

        }

        if (password.length < 6) {

            return res.status(400).json({
                ok: false,
                error: "Password must contain at least 6 characters"
            });

        }

        const existing =
            await pool.query(
                `
                SELECT id
                FROM users
                WHERE username = $1
                `,
                [username]
            );

        if (existing.rows.length) {

            return res.status(409).json({
                ok: false,
                error: "Username already exists"
            });

        }

        const result =
            await pool.query(
                `
                INSERT INTO users
                (username, password_hash)
                VALUES ($1, $2)
                RETURNING id, username, created_at
                `,
                [
                    username,
                    passwordHash(password)
                ]
            );

        return res.json({
            ok: true,
            user: result.rows[0]
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            ok: false,
            error: "Registration failed"
        });

    }

});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {

    try {

        const username =
            String(req.body.username || "").trim();

        const password =
            String(req.body.password || "");

        const result =
            await pool.query(
                `
                SELECT id, username, created_at
                FROM users
                WHERE username = $1
                AND password_hash = $2
                `,
                [
                    username,
                    passwordHash(password)
                ]
            );

        if (!result.rows.length) {

            return res.status(401).json({
                ok: false,
                error: "Invalid username or password"
            });

        }

        return res.json({
            ok: true,
            user: result.rows[0]
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            ok: false,
            error: "Login failed"
        });

    }

});

/* =========================================================
   USER SCRIPTS
========================================================= */

app.get("/api/users/:userId/scripts", async (req, res) => {

    try {

        const userId =
            Number(req.params.userId);

        if (!Number.isInteger(userId)) {
            return apiBlock(res);
        }

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
                [userId]
            );

        return res.json({
            ok: true,
            scripts: result.rows
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            ok: false,
            error: "Failed to load scripts"
        });

    }

});

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post("/api/scripts", async (req, res) => {

    try {

        const userId =
            Number(req.body.userId);

        const name =
            String(req.body.name || "").trim();

        const source =
            String(req.body.source || "");

        if (!Number.isInteger(userId)) {

            return res.status(400).json({
                ok: false,
                error: "Invalid user"
            });

        }

        if (!name || !source) {

            return res.status(400).json({
                ok: false,
                error: "Name and source are required"
            });

        }

        const user =
            await pool.query(
                `
                SELECT id
                FROM users
                WHERE id = $1
                `,
                [userId]
            );

        if (!user.rows.length) {

            return res.status(404).json({
                ok: false,
                error: "User not found"
            });

        }

        const scriptId =
            randomHex(12);

        const result =
            await pool.query(
                `
                INSERT INTO scripts
                (
                    id,
                    user_id,
                    name,
                    source
                )
                VALUES ($1, $2, $3, $4)
                RETURNING
                    id,
                    name,
                    created_at,
                    updated_at
                `,
                [
                    scriptId,
                    userId,
                    name,
                    source
                ]
            );

        return res.json({
            ok: true,
            script: result.rows[0]
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            ok: false,
            error: "Failed to create script"
        });

    }

});

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put("/api/scripts/:id", async (req, res) => {

    try {

        const id =
            String(req.params.id);

        const userId =
            Number(req.body.userId);

        const name =
            String(req.body.name || "").trim();

        const source =
            String(req.body.source || "");

        if (!Number.isInteger(userId)) {

            return res.status(400).json({
                ok: false,
                error: "Invalid user"
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
                WHERE id = $3
                AND user_id = $4
                RETURNING
                    id,
                    name,
                    created_at,
                    updated_at
                `,
                [
                    name,
                    source,
                    id,
                    userId
                ]
            );

        if (!result.rows.length) {

            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });

        }

        return res.json({
            ok: true,
            script: result.rows[0]
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            ok: false,
            error: "Failed to edit script"
        });

    }

});

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete("/api/scripts/:id", async (req, res) => {

    try {

        const id =
            String(req.params.id);

        const userId =
            Number(req.body.userId);

        if (!Number.isInteger(userId)) {

            return res.status(400).json({
                ok: false,
                error: "Invalid user"
            });

        }

        const result =
            await pool.query(
                `
                DELETE FROM scripts
                WHERE id = $1
                AND user_id = $2
                RETURNING id
                `,
                [
                    id,
                    userId
                ]
            );

        if (!result.rows.length) {

            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });

        }

        return res.json({
            ok: true,
            deleted: true
        });

    } catch (err) {

        console.error(err);

        return res.status(500).json({
            ok: false,
            error: "Failed to delete script"
        });

    }

});

/* =========================================================
   LOADER L1
========================================================= */

app.get("/api/loader/:id", async (req, res) => {

    try {

        const id =
            String(req.params.id);

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
            createSession(id);

        const token =
            issueToken(session);

        session.stage = 2;

        /*
            L1 intentionally returns only the
            next stage bootstrap.
        */

        const code = `
-- LEXINX PROTECT L1

local session = ${JSON.stringify(session.id)}
local token = ${JSON.stringify(token)}

local url =
    "https://Lexinx-protect.onrender.com/api/l3"
    .. "?session=" .. session
    .. "&token=" .. token

local ok, response = pcall(function()
    return game:HttpGet(url)
end)

if not ok then
    return
end

local fn = loadstring(response)

if fn then
    return fn()
end
`;

        return res
            .type("text/plain")
            .send(code);

    } catch (err) {

        console.error(err);

        return apiBlock(res);

    }

});

/* =========================================================
   L3
========================================================= */

app.get("/api/l3", (req, res) => {

    const session =
        sessions.get(
            String(req.query.session || "")
        );

    if (!validSession(session)) {
        return apiBlock(res);
    }

    if (session.stage !== 2) {
        return apiBlock(res);
    }

    if (
        !consumeToken(
            session,
            String(req.query.token || "")
        )
    ) {
        return apiBlock(res);
    }

    session.stage = 3;

    const token =
        issueToken(session);

    const code = `
-- LEXINX PROTECT L3

local s = ${JSON.stringify(session.id)}
local t = ${JSON.stringify(token)}

local url =
    "https://Lexinx-protect.onrender.com/api/l4"
    .. "?session=" .. s
    .. "&token=" .. t

local ok, response = pcall(function()
    return game:HttpGet(url)
end)

if not ok then
    return
end

local fn = loadstring(response)

if fn then
    return fn()
end
`;

    return res
        .type("text/plain")
        .send(code);

});

/* =========================================================
   L4
========================================================= */

app.get("/api/l4", (req, res) => {

    const session =
        sessions.get(
            String(req.query.session || "")
        );

    if (!validSession(session)) {
        return apiBlock(res);
    }

    if (session.stage !== 3) {
        return apiBlock(res);
    }

    if (
        !consumeToken(
            session,
            String(req.query.token || "")
        )
    ) {
        return apiBlock(res);
    }

    session.stage = 4;

    const token =
        issueToken(session);

    const code = `
-- LEXINX PROTECT L4

local s = ${JSON.stringify(session.id)}
local t = ${JSON.stringify(token)}

local url =
    "https://Lexinx-protect.onrender.com/api/l5"
    .. "?session=" .. s
    .. "&token=" .. t

local ok, response = pcall(function()
    return game:HttpGet(url)
end)

if not ok then
    return
end

local fn = loadstring(response)

if fn then
    return fn()
end
`;

    return res
        .type("text/plain")
        .send(code);

});

/* =========================================================
   L5
========================================================= */

app.get("/api/l5", async (req, res) => {

    try {

        const session =
            sessions.get(
                String(req.query.session || "")
            );

        if (!validSession(session)) {
            return apiBlock(res);
        }

        if (session.stage !== 4) {
            return apiBlock(res);
        }

        if (
            !consumeToken(
                session,
                String(req.query.token || "")
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

            sessions.delete(session.id);

            return apiBlock(res);

        }

        session.stage = 5;

        const source =
            result.rows[0].source;

        /*
            Final payload is retrieved from
            PostgreSQL only after all stages
            have passed.
        */

        sessions.delete(session.id);

        return res
            .type("text/plain")
            .send(source);

    } catch (err) {

        console.error(err);

        return apiBlock(res);

    }

});

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req, res) => {

    return apiBlock(res);

});

/* =========================================================
   PAGE 404
========================================================= */

app.use((req, res) => {

    res.status(404);

    res.send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>LEXINX PROTECT</title>
<style>
body{
    margin:0;
    background:#050505;
    color:#fff;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    font-family:Arial,sans-serif;
}
h1{
    letter-spacing:8px;
}
</style>
</head>
<body>
<h1>LEXINX PROTECT</h1>
</body>
</html>
`);

});

/* =========================================================
   SESSION CLEANUP
========================================================= */

setInterval(() => {

    const now = Date.now();

    for (
        const [id, session]
        of sessions
    ) {

        if (now > session.expires) {
            sessions.delete(id);
        }

    }

}, 30 * 1000);

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

                console.log(
                    `LEXINX server running on ${PORT}`
                );

            }
        );

    } catch (err) {

        console.error(
            "Startup failed:",
            err
        );

        process.exit(1);

    }

}

start();
