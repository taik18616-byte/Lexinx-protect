"use strict";

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   DATA
========================================================= */

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadDB() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            return {
                users: {},
                scripts: {}
            };
        }

        return JSON.parse(
            fs.readFileSync(DATA_FILE, "utf8")
        );
    } catch {
        return {
            users: {},
            scripts: {}
        };
    }
}

let db = loadDB();

function saveDB() {
    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(db, null, 2),
        "utf8"
    );
}

/* =========================================================
   HELPERS
========================================================= */

function id(size = 24) {
    return crypto
        .randomBytes(size)
        .toString("hex");
}

function passwordHash(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function cleanName(name) {
    return String(name || "")
        .trim()
        .replace(/[^a-zA-Z0-9_-]/g, "")
        .slice(0, 32);
}

function cleanScriptId(value) {
    return String(value || "")
        .trim()
        .replace(/[^a-zA-Z0-9_-]/g, "")
        .slice(0, 100);
}

/* =========================================================
   SESSION
========================================================= */

const sessions = new Map();

function createSession(userId) {
    const token = id(32);

    sessions.set(token, {
        userId,
        createdAt: Date.now()
    });

    return token;
}

function auth(req, res, next) {

    const header =
        req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return res.status(401).json({
            ok: false,
            error: "Authentication required"
        });
    }

    const token =
        header.slice(7).trim();

    const session =
        sessions.get(token);

    if (!session) {
        return res.status(401).json({
            ok: false,
            error: "Invalid session"
        });
    }

    const user =
        db.users[session.userId];

    if (!user) {
        sessions.delete(token);

        return res.status(401).json({
            ok: false,
            error: "User not found"
        });
    }

    req.user = user;
    req.userId = session.userId;
    req.sessionToken = token;

    next();
}

/* =========================================================
   BLOCK PAGE
========================================================= */

function blockPage() {

    const stars = Array.from(
        { length: 180 },
        () => {
            const x =
                Math.random() * 100;

            const y =
                Math.random() * 100;

            const size =
                Math.random() * 2 + 1;

            const duration =
                2 + Math.random() * 5;

            const delay =
                -Math.random() * 5;

            return `
                <span
                    class="star"
                    style="
                        left:${x}%;
                        top:${y}%;
                        width:${size}px;
                        height:${size}px;
                        --duration:${duration}s;
                        animation-delay:${delay}s;
                    "
                ></span>
            `;
        }
    ).join("");

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>LEXINX PROTECT</title>

<style>

* {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    width: 100%;
    height: 100%;
}

body {
    overflow: hidden;

    display: flex;
    align-items: center;
    justify-content: center;

    background: #111;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}

.scene {
    position: relative;

    width: 100%;
    height: 100%;

    overflow: hidden;

    background:
        radial-gradient(
            circle at center,
            #5a5a5a 0%,
            #343434 35%,
            #1a1a1a 70%,
            #090909 100%
        );
}

.stars {
    position: absolute;

    inset: 0;

    overflow: hidden;
}

.star {
    position: absolute;

    display: block;

    border-radius: 50%;

    background: #aaa;

    box-shadow:
        0 0 6px #aaa;

    animation:
        twinkle
        var(--duration)
        ease-in-out
        infinite;
}

@keyframes twinkle {

    0% {
        opacity: .1;
        transform: scale(.6);
    }

    50% {
        opacity: 1;
        transform: scale(1.4);
    }

    100% {
        opacity: .1;
        transform: scale(.6);
    }
}

.center {
    position: absolute;

    top: 50%;
    left: 50%;

    transform:
        translate(-50%, -50%);

    width: min(90%, 720px);

    padding: 48px 30px;

    text-align: center;

    border-radius: 20px;

    background:
        rgba(80,80,80,.35);

    border:
        1px solid
        rgba(255,255,255,.12);

    box-shadow:
        0 0 70px
        rgba(0,0,0,.65),

        inset 0 0 40px
        rgba(255,255,255,.04);

    backdrop-filter:
        blur(8px);
}

.logo {
    margin: 0;

    font-size:
        clamp(
            34px,
            7vw,
            76px
        );

    font-weight: 900;

    letter-spacing: 7px;

    color: #fff;

    animation:
        logoFade
        5s
        ease-in-out
        infinite;
}

@keyframes logoFade {

    0% {
        color: #fff;
    }

    50% {
        color: #555;
    }

    100% {
        color: #fff;
    }
}

.subtitle {
    margin-top: 20px;

    color: #aaa;

    font-size: 14px;

    letter-spacing: 5px;

    text-transform: uppercase;

    animation:
        pulse
        3s
        ease-in-out
        infinite;
}

@keyframes pulse {

    0% {
        opacity: .4;
    }

    50% {
        opacity: 1;
    }

    100% {
        opacity: .4;
    }
}

.block {
    display: inline-block;

    margin-top: 26px;

    padding:
        9px 20px;

    border-radius: 999px;

    border:
        1px solid
        rgba(255,255,255,.15);

    background:
        rgba(0,0,0,.25);

    color: #888;

    font-size: 12px;

    letter-spacing: 3px;
}

.scan {
    position: absolute;

    left: 0;
    right: 0;

    height: 1px;

    background:
        rgba(255,255,255,.08);

    animation:
        scan 6s
        linear
        infinite;
}

@keyframes scan {

    from {
        top: -5%;
    }

    to {
        top: 105%;
    }
}

</style>
</head>

<body>

<div class="scene">

    <div class="stars">
        ${stars}
    </div>

    <div class="scan"></div>

    <div class="center">

        <h1 class="logo">
            LEXINX PROTECT
        </h1>

        <div class="subtitle">
            Anti-Skid
        </div>

        <div class="block">
            LEXINX BLOCK
        </div>

    </div>

</div>

</body>
</html>`;
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {

    res.type("html").send(`
<!doctype html>

<html>
<head>
<meta charset="utf-8">

<title>LEXINX Protect</title>

<style>

body {
    margin: 0;
    background: #111;
    color: #eee;

    font-family: Arial;

    display: flex;
    align-items: center;
    justify-content: center;

    min-height: 100vh;
}

.box {
    text-align: center;

    padding: 40px;

    border:
        1px solid #333;

    border-radius: 16px;

    background: #181818;
}

h1 {
    margin: 0 0 10px;
}

p {
    color: #888;
}

</style>
</head>

<body>

<div class="box">

<h1>LEXINX PROTECT</h1>

<p>Script management server</p>

</div>

</body>
</html>
`);
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", (req, res) => {

    const username =
        cleanName(req.body.username);

    const password =
        String(req.body.password || "");

    if (!username || password.length < 6) {
        return res.status(400).json({
            ok: false,
            error:
                "Username and password are required. Password must contain at least 6 characters."
        });
    }

    const key =
        username.toLowerCase();

    if (db.users[key]) {
        return res.status(409).json({
            ok: false,
            error: "Username already exists"
        });
    }

    const userId = id(16);

    db.users[key] = {
        id: userId,
        username,
        password:
            passwordHash(password),

        createdAt:
            new Date().toISOString(),

        scripts: []
    };

    saveDB();

    const token =
        createSession(userId);

    res.json({
        ok: true,
        token,

        user: {
            id: userId,
            username
        }
    });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", (req, res) => {

    const username =
        cleanName(req.body.username);

    const password =
        String(req.body.password || "");

    const key =
        username.toLowerCase();

    const user =
        db.users[key];

    if (
        !user ||
        user.password !==
        passwordHash(password)
    ) {
        return res.status(401).json({
            ok: false,
            error: "Invalid username or password"
        });
    }

    const token =
        createSession(user.id);

    res.json({
        ok: true,
        token,

        user: {
            id: user.id,
            username: user.username
        }
    });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", auth, (req, res) => {

    sessions.delete(
        req.sessionToken
    );

    res.json({
        ok: true
    });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", auth, (req, res) => {

    res.json({
        ok: true,

        user: {
            id: req.user.id,
            username: req.user.username,

            scripts:
                req.user.scripts || []
        }
    });
});

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post("/api/scripts", auth, (req, res) => {

    const name =
        String(req.body.name || "")
            .trim()
            .slice(0, 100);

    const source =
        String(req.body.source || "");

    if (!name || !source) {
        return res.status(400).json({
            ok: false,
            error: "Name and source are required"
        });
    }

    const scriptId =
        id(16);

    const record = {
        id: scriptId,

        name,

        source,

        owner:
            req.user.id,

        createdAt:
            new Date().toISOString(),

        updatedAt:
            new Date().toISOString()
    };

    db.scripts[scriptId] =
        record;

    req.user.scripts.push(
        scriptId
    );

    saveDB();

    res.json({
        ok: true,

        script: {
            id: scriptId,
            name
        },

        loader:
            `/api/loader/${scriptId}`
    });
});

/* =========================================================
   LIST USER SCRIPTS
========================================================= */

app.get("/api/scripts", auth, (req, res) => {

    const scripts =
        (req.user.scripts || [])
            .map(scriptId =>
                db.scripts[scriptId]
            )
            .filter(Boolean)
            .map(script => ({
                id: script.id,
                name: script.name,
                createdAt:
                    script.createdAt,
                updatedAt:
                    script.updatedAt,

                loader:
                    `/api/loader/${script.id}`
            }));

    res.json({
        ok: true,
        scripts
    });
});

/* =========================================================
   GET SCRIPT
========================================================= */

app.get("/api/scripts/:id", auth, (req, res) => {

    const script =
        db.scripts[
            cleanScriptId(req.params.id)
        ];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    if (
        script.owner !==
        req.user.id
    ) {
        return res.status(403).json({
            ok: false,
            error: "Access denied"
        });
    }

    res.json({
        ok: true,

        script: {
            id: script.id,
            name: script.name,
            source: script.source,
            createdAt:
                script.createdAt,
            updatedAt:
                script.updatedAt
        }
    });
});

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put("/api/scripts/:id", auth, (req, res) => {

    const scriptId =
        cleanScriptId(req.params.id);

    const script =
        db.scripts[scriptId];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    if (
        script.owner !==
        req.user.id
    ) {
        return res.status(403).json({
            ok: false,
            error: "Access denied"
        });
    }

    if (req.body.name !== undefined) {

        const name =
            String(req.body.name)
                .trim()
                .slice(0, 100);

        if (name) {
            script.name = name;
        }
    }

    if (req.body.source !== undefined) {

        script.source =
            String(req.body.source);
    }

    script.updatedAt =
        new Date().toISOString();

    saveDB();

    res.json({
        ok: true,
        message: "Script updated"
    });
});

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete("/api/scripts/:id", auth, (req, res) => {

    const scriptId =
        cleanScriptId(req.params.id);

    const script =
        db.scripts[scriptId];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    if (
        script.owner !==
        req.user.id
    ) {
        return res.status(403).json({
            ok: false,
            error: "Access denied"
        });
    }

    delete db.scripts[scriptId];

    req.user.scripts =
        req.user.scripts.filter(
            x => x !== scriptId
        );

    saveDB();

    res.json({
        ok: true,
        message: "Script deleted"
    });
});

/* =========================================================
   LOADER
========================================================= */

app.get("/api/loader/:id", (req, res) => {

    const scriptId =
        cleanScriptId(req.params.id);

    const script =
        db.scripts[scriptId];

    /*
     * Browser navigation normally sends
     * text/html in Accept.
     *
     * Show the protected page instead
     * of exposing script information.
     */

    const accept =
        String(
            req.headers.accept || ""
        ).toLowerCase();

    const isBrowser =
        accept.includes("text/html");

    if (isBrowser) {

        return res
            .status(403)
            .type("html")
            .send(blockPage());
    }

    if (!script) {

        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    /*
     * Loader endpoint returns the stored
     * script for a valid script ID.
     *
     * The source is intentionally not
     * included in normal management
     * listing responses.
     */

    res
        .status(200)
        .type("text/plain")
        .send(script.source);
});

/* =========================================================
   UNKNOWN API
========================================================= */

app.use("/api", (req, res) => {

    res.status(404).json({
        ok: false,
        error: "LEXINX BLOCK"
    });
});

/* =========================================================
   UNKNOWN PAGE
========================================================= */

app.use((req, res) => {

    res.status(404).send(
        "LEXINX PROTECT - NOT FOUND"
    );
});

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    HOST,
    () => {

        console.log(
            `LEXINX PROTECT running on ${HOST}:${PORT}`
        );

        console.log(
            `Loader endpoint: /api/loader/:id`
        );
    }
);
