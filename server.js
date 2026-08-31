"use strict";

const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET =
    process.env.SESSION_SECRET || crypto.randomBytes(48).toString("hex");

if (!DATABASE_URL) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

app.use(express.json({
    limit: "2mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "2mb"
}));

app.set("trust proxy", 1);

app.use(
    session({
        store: new pgSession({
            pool,
            tableName: "user_sessions",
            createTableIfMissing: true
        }),
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        rolling: true,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 24 * 30
        }
    })
);

app.use(express.static(path.join(__dirname, "public")));

/* =========================================================
   HELPERS
========================================================= */

function randomHex(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function sha256(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

function safeEqual(a, b) {
    try {
        const aa = Buffer.from(String(a));
        const bb = Buffer.from(String(b));

        if (aa.length !== bb.length) {
            return false;
        }

        return crypto.timingSafeEqual(aa, bb);
    } catch {
        return false;
    }
}

function blockPage(res, status = 403) {
    res.status(status).send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LEXINX PROTECT</title>
<style>
html,body{
    margin:0;
    width:100%;
    height:100%;
    overflow:hidden;
    background:#050505;
    color:white;
    font-family:Arial,sans-serif;
}
body{
    display:flex;
    align-items:center;
    justify-content:center;
}
.stars{
    position:fixed;
    inset:0;
    background-image:
        radial-gradient(#777 1px,transparent 1px),
        radial-gradient(#444 1px,transparent 1px);
    background-size:43px 43px,71px 71px;
    background-position:0 0,19px 31px;
    opacity:.22;
}
.box{
    position:relative;
    z-index:2;
    text-align:center;
}
.logo{
    font-size:42px;
    font-weight:900;
    letter-spacing:7px;
    animation:pulse 3s ease-in-out infinite;
}
.sub{
    margin-top:15px;
    color:#888;
    letter-spacing:3px;
    font-size:12px;
}
@keyframes pulse{
    0%,100%{opacity:.35}
    50%{opacity:1}
}
</style>
</head>
<body>
<div class="stars"></div>
<div class="box">
    <div class="logo">LEXINX PROTECT</div>
    <div class="sub">ANTI-SKID • ACCESS BLOCKED</div>
</div>
</body>
</html>`);
}

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            ok: false,
            error: "LOGIN_REQUIRED"
        });
    }

    next();
}

function normalizeUsername(username) {
    return String(username || "")
        .trim()
        .toLowerCase();
}

function validUsername(username) {
    return /^[a-z0-9_]{3,32}$/.test(username);
}

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(32) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS scripts (
            id UUID PRIMARY KEY,
            user_id INTEGER NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            source TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS loader_sessions (
            id UUID PRIMARY KEY,
            user_id INTEGER NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,
            script_id UUID NOT NULL
                REFERENCES scripts(id)
                ON DELETE CASCADE,
            stage INTEGER NOT NULL DEFAULT 2,
            token_hash TEXT NOT NULL,
            nonce_hash TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_scripts_user
        ON scripts(user_id)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_loader_token
        ON loader_sessions(token_hash)
    `);

    console.log("PostgreSQL initialized.");
}

/* =========================================================
   AUTH
========================================================= */

app.post("/api/auth/register", async (req, res) => {
    try {
        const username = normalizeUsername(req.body.username);
        const password = String(req.body.password || "");

        if (!validUsername(username)) {
            return res.status(400).json({
                ok: false,
                error: "INVALID_USERNAME"
            });
        }

        if (password.length < 6 || password.length > 200) {
            return res.status(400).json({
                ok: false,
                error: "INVALID_PASSWORD"
            });
        }

        const exists = await pool.query(
            "SELECT id FROM users WHERE username=$1",
            [username]
        );

        if (exists.rows.length) {
            return res.status(409).json({
                ok: false,
                error: "USERNAME_EXISTS"
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = await pool.query(
            `INSERT INTO users(username,password_hash)
             VALUES($1,$2)
             RETURNING id,username,created_at`,
            [username, passwordHash]
        );

        const user = result.rows[0];

        req.session.userId = user.id;
        req.session.username = user.username;

        req.session.save(() => {
            res.json({
                ok: true,
                user: {
                    id: user.id,
                    username: user.username,
                    created_at: user.created_at
                }
            });
        });
    } catch (err) {
        console.error("REGISTER:", err);

        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const username = normalizeUsername(req.body.username);
        const password = String(req.body.password || "");

        const result = await pool.query(
            `SELECT id,username,password_hash,created_at
             FROM users
             WHERE username=$1`,
            [username]
        );

        if (!result.rows.length) {
            return res.status(401).json({
                ok: false,
                error: "INVALID_LOGIN"
            });
        }

        const user = result.rows[0];

        const valid = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!valid) {
            return res.status(401).json({
                ok: false,
                error: "INVALID_LOGIN"
            });
        }

        req.session.userId = user.id;
        req.session.username = user.username;

        req.session.save(() => {
            res.json({
                ok: true,
                user: {
                    id: user.id,
                    username: user.username,
                    created_at: user.created_at
                }
            });
        });
    } catch (err) {
        console.error("LOGIN:", err);

        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

app.post("/api/auth/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({
            ok: true
        });
    });
});

app.get("/api/auth/me", async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.json({
                ok: true,
                loggedIn: false
            });
        }

        const result = await pool.query(
            `SELECT id,username,created_at
             FROM users
             WHERE id=$1`,
            [req.session.userId]
        );

        if (!result.rows.length) {
            req.session.destroy(() => {});

            return res.json({
                ok: true,
                loggedIn: false
            });
        }

        res.json({
            ok: true,
            loggedIn: true,
            user: result.rows[0]
        });
    } catch {
        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

/* =========================================================
   ACCOUNT
========================================================= */

app.get("/api/account", requireLogin, async (req, res) => {
    try {
        const userResult = await pool.query(
            `SELECT id,username,created_at
             FROM users
             WHERE id=$1`,
            [req.session.userId]
        );

        if (!userResult.rows.length) {
            return res.status(404).json({
                ok: false,
                error: "USER_NOT_FOUND"
            });
        }

        const scriptsResult = await pool.query(
            `SELECT id,name,created_at,updated_at
             FROM scripts
             WHERE user_id=$1
             ORDER BY updated_at DESC`,
            [req.session.userId]
        );

        res.json({
            ok: true,
            user: userResult.rows[0],
            scripts: scriptsResult.rows
        });
    } catch (err) {
        console.error("ACCOUNT:", err);

        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

/* =========================================================
   SCRIPT CREATE
========================================================= */

app.post("/api/scripts", requireLogin, async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const source = String(req.body.source || "");

        if (!name || name.length > 100) {
            return res.status(400).json({
                ok: false,
                error: "INVALID_SCRIPT_NAME"
            });
        }

        if (!source || source.length > 2 * 1024 * 1024) {
            return res.status(400).json({
                ok: false,
                error: "INVALID_SOURCE"
            });
        }

        const id = crypto.randomUUID();

        const result = await pool.query(
            `INSERT INTO scripts(id,user_id,name,source)
             VALUES($1,$2,$3,$4)
             RETURNING id,name,created_at,updated_at`,
            [
                id,
                req.session.userId,
                name,
                source
            ]
        );

        res.json({
            ok: true,
            script: result.rows[0]
        });
    } catch (err) {
        console.error("CREATE SCRIPT:", err);

        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

/* =========================================================
   SCRIPT READ
========================================================= */

app.get("/api/scripts/:id", requireLogin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id,name,source,created_at,updated_at
             FROM scripts
             WHERE id=$1 AND user_id=$2`,
            [
                req.params.id,
                req.session.userId
            ]
        );

        if (!result.rows.length) {
            return res.status(404).json({
                ok: false,
                error: "SCRIPT_NOT_FOUND"
            });
        }

        res.json({
            ok: true,
            script: result.rows[0]
        });
    } catch {
        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

/* =========================================================
   SCRIPT EDIT
========================================================= */

app.put("/api/scripts/:id", requireLogin, async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const source = String(req.body.source || "");

        if (!name || name.length > 100) {
            return res.status(400).json({
                ok: false,
                error: "INVALID_SCRIPT_NAME"
            });
        }

        if (!source || source.length > 2 * 1024 * 1024) {
            return res.status(400).json({
                ok: false,
                error: "INVALID_SOURCE"
            });
        }

        const result = await pool.query(
            `UPDATE scripts
             SET name=$1,
                 source=$2,
                 updated_at=NOW()
             WHERE id=$3 AND user_id=$4
             RETURNING id,name,created_at,updated_at`,
            [
                name,
                source,
                req.params.id,
                req.session.userId
            ]
        );

        if (!result.rows.length) {
            return res.status(404).json({
                ok: false,
                error: "SCRIPT_NOT_FOUND"
            });
        }

        res.json({
            ok: true,
            script: result.rows[0]
        });
    } catch (err) {
        console.error("EDIT SCRIPT:", err);

        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

/* =========================================================
   SCRIPT DELETE
========================================================= */

app.delete("/api/scripts/:id", requireLogin, async (req, res) => {
    try {
        const result = await pool.query(
            `DELETE FROM scripts
             WHERE id=$1 AND user_id=$2
             RETURNING id`,
            [
                req.params.id,
                req.session.userId
            ]
        );

        if (!result.rows.length) {
            return res.status(404).json({
                ok: false,
                error: "SCRIPT_NOT_FOUND"
            });
        }

        res.json({
            ok: true,
            deleted: result.rows[0].id
        });
    } catch (err) {
        console.error("DELETE SCRIPT:", err);

        res.status(500).json({
            ok: false,
            error: "SERVER_ERROR"
        });
    }
});

/* =========================================================
   LEXINX LOADER
========================================================= */

function loaderRequest(req) {
    const host = String(req.get("host") || "").toLowerCase();

    const allowedHost =
        host === "lexinx-protect.onrender.com" ||
        host.startsWith("localhost:") ||
        host.startsWith("127.0.0.1:");

    if (!allowedHost) {
        return false;
    }

    return true;
}

/*
    L1
    /api/loader/:id

    Only returns an L2 challenge.
    No source is returned here.
*/

app.get("/api/loader/:id", async (req, res) => {
    try {
        if (!loaderRequest(req)) {
            return blockPage(res, 403);
        }

        const scriptResult = await pool.query(
            `SELECT id,user_id
             FROM scripts
             WHERE id=$1`,
            [req.params.id]
        );

        if (!scriptResult.rows.length) {
            return blockPage(res, 404);
        }

        const script = scriptResult.rows[0];

        const sessionId = crypto.randomUUID();
        const token = randomHex(32);
        const nonce = randomHex(16);

        const expires = new Date(
            Date.now() + 60 * 1000
        );

        await pool.query(
            `INSERT INTO loader_sessions(
                id,
                user_id,
                script_id,
                stage,
                token_hash,
                nonce_hash,
                expires_at,
                used
            )
            VALUES($1,$2,$3,2,$4,$5,$6,FALSE)`,
            [
                sessionId,
                script.user_id,
                script.id,
                sha256(token),
                sha256(nonce),
                expires
            ]
        );

        res.json({
            ok: true,
            stage: 2,
            session: sessionId,
            token,
            nonce,
            next: "/api/l3"
        });
    } catch (err) {
        console.error("L1:", err);

        blockPage(res, 500);
    }
});

/* =========================================================
   GENERIC STAGE CHECK
========================================================= */

async function getLoaderSession(req, requiredStage) {
    const sessionId = String(req.body.session || "");
    const token = String(req.body.token || "");
    const nonce = String(req.body.nonce || "");

    if (!sessionId || !token || !nonce) {
        return null;
    }

    const result = await pool.query(
        `SELECT *
         FROM loader_sessions
         WHERE id=$1`,
        [sessionId]
    );

    if (!result.rows.length) {
        return null;
    }

    const row = result.rows[0];

    if (row.used) {
        return null;
    }

    if (row.stage !== requiredStage) {
        return null;
    }

    if (new Date(row.expires_at).getTime() < Date.now()) {
        await pool.query(
            `DELETE FROM loader_sessions WHERE id=$1`,
            [sessionId]
        );

        return null;
    }

    if (!safeEqual(row.token_hash, sha256(token))) {
        return null;
    }

    if (!safeEqual(row.nonce_hash, sha256(nonce))) {
        return null;
    }

    return row;
}

/* =========================================================
   L2 -> L3
========================================================= */

app.post("/api/l3", async (req, res) => {
    try {
        if (!loaderRequest(req)) {
            return blockPage(res, 403);
        }

        const row = await getLoaderSession(req, 2);

        if (!row) {
            return blockPage(res, 403);
        }

        const token = randomHex(32);
        const nonce = randomHex(16);

        await pool.query(
            `UPDATE loader_sessions
             SET stage=3,
                 token_hash=$1,
                 nonce_hash=$2
             WHERE id=$3`,
            [
                sha256(token),
                sha256(nonce),
                row.id
            ]
        );

        res.json({
            ok: true,
            stage: 3,
            session: row.id,
            token,
            nonce,
            next: "/api/l4"
        });
    } catch (err) {
        console.error("L2:", err);

        blockPage(res, 500);
    }
});

/* =========================================================
   L3 -> L4
========================================================= */

app.post("/api/l4", async (req, res) => {
    try {
        if (!loaderRequest(req)) {
            return blockPage(res, 403);
        }

        const row = await getLoaderSession(req, 3);

        if (!row) {
            return blockPage(res, 403);
        }

        const token = randomHex(32);
        const nonce = randomHex(16);

        await pool.query(
            `UPDATE loader_sessions
             SET stage=4,
                 token_hash=$1,
                 nonce_hash=$2
             WHERE id=$3`,
            [
                sha256(token),
                sha256(nonce),
                row.id
            ]
        );

        res.json({
            ok: true,
            stage: 4,
            session: row.id,
            token,
            nonce,
            next: "/api/l5"
        });
    } catch (err) {
        console.error("L3:", err);

        blockPage(res, 500);
    }
});

/* =========================================================
   L4 -> L5
========================================================= */

app.post("/api/l5", async (req, res) => {
    try {
        if (!loaderRequest(req)) {
            return blockPage(res, 403);
        }

        const row = await getLoaderSession(req, 4);

        if (!row) {
            return blockPage(res, 403);
        }

        const token = randomHex(32);
        const nonce = randomHex(16);

        await pool.query(
            `UPDATE loader_sessions
             SET stage=5,
                 token_hash=$1,
                 nonce_hash=$2
             WHERE id=$3`,
            [
                sha256(token),
                sha256(nonce),
                row.id
            ]
        );

        res.json({
            ok: true,
            stage: 5,
            session: row.id,
            token,
            nonce,
            next: "/api/source"
        });
    } catch (err) {
        console.error("L4:", err);

        blockPage(res, 500);
    }
});

/* =========================================================
   L5 -> SOURCE
========================================================= */

app.post("/api/source", async (req, res) => {
    try {
        if (!loaderRequest(req)) {
            return blockPage(res, 403);
        }

        const row = await getLoaderSession(req, 5);

        if (!row) {
            return blockPage(res, 403);
        }

        const scriptResult = await pool.query(
            `SELECT source
             FROM scripts
             WHERE id=$1 AND user_id=$2`,
            [
                row.script_id,
                row.user_id
            ]
        );

        if (!scriptResult.rows.length) {
            return blockPage(res, 404);
        }

        /*
         * One-time session.
         * The token cannot be reused after this point.
         */

        await pool.query(
            `UPDATE loader_sessions
             SET used=TRUE
             WHERE id=$1`,
            [row.id]
        );

        res.type("text/plain").send(
            scriptResult.rows[0].source
        );
    } catch (err) {
        console.error("SOURCE:", err);

        blockPage(res, 500);
    }
});

/* =========================================================
   INVALID API ROUTES
========================================================= */

app.use("/api", (req, res) => {
    blockPage(res, 403);
});

/* =========================================================
   ACCOUNT WEB ROUTE
========================================================= */

app.get("/acc/:username/:id/:id2", async (req, res) => {
    try {
        const username = normalizeUsername(
            req.params.username
        );

        const result = await pool.query(
            `SELECT id,username
             FROM users
             WHERE username=$1`,
            [username]
        );

        if (!result.rows.length) {
            return blockPage(res, 404);
        }

        if (
            !req.session.userId ||
            Number(req.session.userId) !==
            Number(result.rows[0].id)
        ) {
            return res.redirect("/");
        }

        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    } catch {
        return blockPage(res, 500);
    }
});

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
   404
========================================================= */

app.use((req, res) => {
    blockPage(res, 404);
});

/* =========================================================
   START
========================================================= */

async function start() {
    try {
        await initDatabase();

        app.listen(PORT, "0.0.0.0", () => {
            console.log(
                `LEXINX Protect running on port ${PORT}`
            );
        });
    } catch (err) {
        console.error("STARTUP ERROR:", err);
        process.exit(1);
    }
}

start();
