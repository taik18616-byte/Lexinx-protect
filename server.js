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
const PUBLIC_DIR = path.join(__dirname, "public");

/* =========================================================
   INIT
========================================================= */

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });
}

if (!fs.existsSync(PUBLIC_DIR)) {
    fs.mkdirSync(PUBLIC_DIR, {
        recursive: true
    });
}

function emptyDatabase() {
    return {
        users: {},
        scripts: {}
    };
}

function loadDatabase() {
    try {

        if (!fs.existsSync(DATA_FILE)) {
            return emptyDatabase();
        }

        const data =
            JSON.parse(
                fs.readFileSync(
                    DATA_FILE,
                    "utf8"
                )
            );

        return {
            users: data.users || {},
            scripts: data.scripts || {}
        };

    } catch (error) {

        console.error(
            "Database error:",
            error.message
        );

        return emptyDatabase();
    }
}

let database =
    loadDatabase();

function saveDatabase() {

    const temporary =
        DATA_FILE + ".tmp";

    fs.writeFileSync(
        temporary,
        JSON.stringify(
            database,
            null,
            2
        ),
        "utf8"
    );

    fs.renameSync(
        temporary,
        DATA_FILE
    );
}

/* =========================================================
   EXPRESS
========================================================= */

app.disable(
    "x-powered-by"
);

app.use(
    express.json({
        limit: "5mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "5mb"
    })
);

/* =========================================================
   HELPERS
========================================================= */

function randomId(bytes = 16) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(
            String(password)
        )
        .digest("hex");
}

function cleanUsername(value) {

    return String(value || "")
        .trim()
        .replace(
            /[^a-zA-Z0-9_-]/g,
            ""
        )
        .slice(0, 32);
}

function cleanId(value) {

    return String(value || "")
        .trim()
        .replace(
            /[^a-zA-Z0-9_-]/g,
            ""
        )
        .slice(0, 128);
}

/* =========================================================
   SESSION
========================================================= */

const sessions =
    new Map();

function createSession(userId) {

    const token =
        randomId(32);

    sessions.set(
        token,
        {
            userId,
            createdAt:
                Date.now()
        }
    );

    return token;
}

function getAuthenticatedUser(req) {

    const authorization =
        req.headers.authorization;

    if (
        !authorization ||
        !authorization.startsWith(
            "Bearer "
        )
    ) {
        return null;
    }

    const token =
        authorization
            .slice(7)
            .trim();

    if (!token) {
        return null;
    }

    const session =
        sessions.get(token);

    if (!session) {
        return null;
    }

    const users =
        Object.values(
            database.users
        );

    const user =
        users.find(
            item =>
                item.id ===
                session.userId
        );

    if (!user) {

        sessions.delete(token);

        return null;
    }

    return {
        token,
        user
    };
}

function requireAuth(
    req,
    res,
    next
) {

    const auth =
        getAuthenticatedUser(req);

    if (!auth) {

        return res
            .status(401)
            .json({
                ok: false,
                error:
                    "Authentication required"
            });
    }

    req.auth =
        auth;

    req.user =
        auth.user;

    next();
}

/* =========================================================
   LEXINX PROTECT BLOCK PAGE
========================================================= */

function generateStars(
    count = 240
) {

    let result = "";

    for (
        let i = 0;
        i < count;
        i++
    ) {

        const left =
            Math.random() * 100;

        const top =
            Math.random() * 100;

        const size =
            1 +
            Math.random() * 3;

        const duration =
            2 +
            Math.random() * 6;

        const delay =
            Math.random() * -8;

        result += `
<span
class="star"
style="
left:${left.toFixed(2)}%;
top:${top.toFixed(2)}%;
width:${size.toFixed(2)}px;
height:${size.toFixed(2)}px;
animation-duration:${duration.toFixed(2)}s;
animation-delay:${delay.toFixed(2)}s;
"></span>
`;
    }

    return result;
}

function blockPage() {

    const stars =
        generateStars();

    return `<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<meta
name="robots"
content="noindex,nofollow,noarchive"
>

<title>LEXINX PROTECT</title>

<style>

* {
    box-sizing: border-box;
}

html,
body {

    width: 100%;
    height: 100%;

    margin: 0;

    overflow: hidden;
}

body {

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #050505;
}

/* =====================================================
   BACKGROUND
===================================================== */

.scene {

    position: relative;

    width: 100%;
    height: 100%;

    overflow: hidden;

    background:
        radial-gradient(
            circle at 50% 50%,
            #777 0%,
            #4b4b4b 20%,
            #282828 48%,
            #080808 100%
        );

    animation:
        backgroundAnimation
        12s
        ease-in-out
        infinite
        alternate;
}

@keyframes backgroundAnimation {

    0% {

        background:
            radial-gradient(
                circle at 25% 30%,
                #666,
                #303030 38%,
                #090909 100%
            );
    }

    50% {

        background:
            radial-gradient(
                circle at 70% 35%,
                #777,
                #383838 38%,
                #090909 100%
            );
    }

    100% {

        background:
            radial-gradient(
                circle at 45% 75%,
                #666,
                #292929 38%,
                #070707 100%
            );
    }
}

/* =====================================================
   STARS
===================================================== */

.stars {

    position: absolute;

    inset: 0;
}

.star {

    position: absolute;

    display: block;

    border-radius: 50%;

    background: #fff;

    box-shadow:
        0 0 7px
        rgba(255,255,255,.8);

    animation:
        starAnimation
        ease-in-out
        infinite;
}

@keyframes starAnimation {

    0% {

        transform:
            scale(.25);

        opacity: .05;
    }

    50% {

        transform:
            scale(1.8);

        opacity: 1;
    }

    100% {

        transform:
            scale(.25);

        opacity: .05;
    }
}

/* =====================================================
   MOVING LIGHT
===================================================== */

.light {

    position: absolute;

    width: 600px;
    height: 600px;

    left: 50%;
    top: 50%;

    transform:
        translate(-50%,-50%);

    border-radius: 50%;

    background:
        radial-gradient(
            circle,
            rgba(255,255,255,.16),
            rgba(255,255,255,.04) 38%,
            transparent 70%
        );

    filter:
        blur(25px);

    animation:
        lightAnimation
        7s
        ease-in-out
        infinite;
}

@keyframes lightAnimation {

    0% {

        transform:
            translate(-50%,-50%)
            scale(.8);

        opacity: .4;
    }

    50% {

        transform:
            translate(-50%,-50%)
            scale(1.25);

        opacity: 1;
    }

    100% {

        transform:
            translate(-50%,-50%)
            scale(.8);

        opacity: .4;
    }
}

/* =====================================================
   MOVING LINES
===================================================== */

.lines {

    position: absolute;

    inset: -50%;

    opacity: .07;

    background:
        repeating-linear-gradient(
            120deg,
            transparent 0,
            transparent 90px,
            #fff 91px,
            transparent 92px
        );

    animation:
        linesAnimation
        20s
        linear
        infinite;
}

@keyframes linesAnimation {

    from {

        transform:
            translate(
                -8%,
                -8%
            );
    }

    to {

        transform:
            translate(
                8%,
                8%
            );
    }
}

/* =====================================================
   CENTER
===================================================== */

.center {

    position: absolute;

    left: 50%;
    top: 50%;

    transform:
        translate(-50%,-50%);

    width:
        min(94vw, 950px);

    min-height: 480px;

    display:
        flex;

    flex-direction:
        column;

    align-items:
        center;

    justify-content:
        center;

    text-align:
        center;

    padding:
        70px 35px;

    border-radius:
        30px;

    background:
        linear-gradient(
            145deg,
            rgba(110,110,110,.52),
            rgba(25,25,25,.64)
        );

    border:
        1px solid
        rgba(255,255,255,.17);

    box-shadow:

        0 35px 120px
        rgba(0,0,0,.8),

        inset 0 1px 0
        rgba(255,255,255,.12),

        inset 0 0 90px
        rgba(255,255,255,.035);

    backdrop-filter:
        blur(15px);

    animation:
        cardAnimation
        6s
        ease-in-out
        infinite;
}

@keyframes cardAnimation {

    0% {

        transform:
            translate(-50%,-50%)
            translateY(0);
    }

    50% {

        transform:
            translate(-50%,-50%)
            translateY(-9px);
    }

    100% {

        transform:
            translate(-50%,-50%)
            translateY(0);
    }
}

/* =====================================================
   LOGO
===================================================== */

.logo {

    margin: 0;

    font-size:
        clamp(
            50px,
            9vw,
            115px
        );

    line-height: 1;

    font-weight: 1000;

    letter-spacing:
        clamp(
            4px,
            1.2vw,
            15px
        );

    user-select: none;

    animation:
        logoAnimation
        6s
        ease-in-out
        infinite;
}

@keyframes logoAnimation {

    0% {

        color: #ffffff;

        text-shadow:
            0 0 25px
            rgba(255,255,255,.45);
    }

    20% {

        color: #dddddd;
    }

    40% {

        color: #999999;
    }

    60% {

        color: #555555;

        text-shadow:
            0 0 5px
            rgba(255,255,255,.08);
    }

    80% {

        color: #bbbbbb;
    }

    100% {

        color: #ffffff;

        text-shadow:
            0 0 25px
            rgba(255,255,255,.45);
    }
}

/* =====================================================
   ANTI-SKID
===================================================== */

.subtitle {

    margin-top: 34px;

    color: #aaa;

    font-size:
        clamp(
            13px,
            2vw,
            20px
        );

    letter-spacing: 9px;

    text-transform:
        uppercase;

    animation:
        subtitleAnimation
        4s
        ease-in-out
        infinite;
}

@keyframes subtitleAnimation {

    0% {

        opacity: .25;

        transform:
            translateY(5px);
    }

    50% {

        opacity: 1;

        transform:
            translateY(0);
    }

    100% {

        opacity: .25;

        transform:
            translateY(5px);
    }
}

/* =====================================================
   BLOCK
===================================================== */

.status {

    margin-top: 35px;

    padding:
        12px 28px;

    border-radius:
        999px;

    background:
        rgba(0,0,0,.25);

    border:
        1px solid
        rgba(255,255,255,.15);

    color: #888;

    font-size: 12px;

    letter-spacing: 5px;

    animation:
        statusAnimation
        3s
        ease-in-out
        infinite;
}

@keyframes statusAnimation {

    0% {
        opacity: .35;
    }

    50% {
        opacity: 1;
    }

    100% {
        opacity: .35;
    }
}

/* =====================================================
   SCANLINE
===================================================== */

.scan {

    position: absolute;

    left: 0;
    right: 0;

    height: 2px;

    background:
        linear-gradient(
            90deg,
            transparent,
            rgba(255,255,255,.25),
            transparent
        );

    animation:
        scanAnimation
        7s
        linear
        infinite;
}

@keyframes scanAnimation {

    from {
        top: -5%;
    }

    to {
        top: 105%;
    }
}

/* =====================================================
   VIGNETTE
===================================================== */

.vignette {

    position: absolute;

    inset: 0;

    pointer-events: none;

    background:
        radial-gradient(
            ellipse,
            transparent 30%,
            rgba(0,0,0,.7) 100%
        );
}

/* =====================================================
   MOBILE
===================================================== */

@media(max-width:600px) {

    .center {

        min-height: 360px;

        padding:
            50px 18px;
    }

    .logo {

        letter-spacing: 4px;
    }

    .subtitle {

        letter-spacing: 4px;
    }
}

</style>

</head>

<body>

<div class="scene">

    <div class="stars">
        ${stars}
    </div>

    <div class="lines"></div>

    <div class="light"></div>

    <div class="scan"></div>

    <div class="center">

        <h1 class="logo">
            LEXINX PROTECT
        </h1>

        <div class="subtitle">
            ANTI-SKID
        </div>

        <div class="status">
            LEXINX BLOCK
        </div>

    </div>

    <div class="vignette"></div>

</div>

</body>

</html>`;
}

/* =========================================================
   WEB ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        const index =
            path.join(
                PUBLIC_DIR,
                "index.html"
            );

        if (
            fs.existsSync(index)
        ) {

            return res.sendFile(
                index
            );
        }

        res.status(200).send(`
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
body {
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#090909;
    color:#fff;
    font-family:Arial,sans-serif;
}
.box {
    padding:50px;
    text-align:center;
    border:1px solid #333;
    border-radius:20px;
    background:#151515;
}
h1 {
    margin:0;
}
p {
    color:#888;
}
</style>
</head>
<body>
<div class="box">
<h1>LEXINX PROTECT</h1>
<p>Web interface is ready.</p>
</div>
</body>
</html>
`);
    }
);

/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/register",
    (req, res) => {

        const username =
            cleanUsername(
                req.body.username
            );

        const password =
            String(
                req.body.password || ""
            );

        if (
            username.length < 3
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Username must contain at least 3 characters"
                });
        }

        if (
            password.length < 6
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Password must contain at least 6 characters"
                });
        }

        const key =
            username.toLowerCase();

        if (
            database.users[key]
        ) {

            return res
                .status(409)
                .json({
                    ok: false,
                    error:
                        "Username already exists"
                });
        }

        const user = {

            id:
                randomId(16),

            username,

            password:
                hashPassword(
                    password
                ),

            createdAt:
                new Date()
                    .toISOString(),

            scripts: []
        };

        database.users[key] =
            user;

        saveDatabase();

        const token =
            createSession(
                user.id
            );

        res.json({

            ok: true,

            token,

            user: {

                id:
                    user.id,

                username:
                    user.username
            }
        });
    }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/login",
    (req, res) => {

        const username =
            cleanUsername(
                req.body.username
            );

        const password =
            String(
                req.body.password || ""
            );

        const key =
            username.toLowerCase();

        const user =
            database.users[key];

        if (
            !user ||
            user.password !==
            hashPassword(
                password
            )
        ) {

            return res
                .status(401)
                .json({
                    ok: false,
                    error:
                        "Invalid username or password"
                });
        }

        const token =
            createSession(
                user.id
            );

        res.json({

            ok: true,

            token,

            user: {

                id:
                    user.id,

                username:
                    user.username
            }
        });
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    requireAuth,
    (req, res) => {

        sessions.delete(
            req.auth.token
        );

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   CURRENT ACCOUNT
========================================================= */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        res.json({

            ok: true,

            user: {

                id:
                    req.user.id,

                username:
                    req.user.username,

                scripts:
                    req.user.scripts
            }
        });
    }
);

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const name =
            String(
                req.body.name || ""
            )
            .trim()
            .slice(0, 100);

        const source =
            String(
                req.body.source || ""
            );

        if (
            !name ||
            !source
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Name and source are required"
                });
        }

        const scriptId =
            randomId(16);

        database.scripts[
            scriptId
        ] = {

            id:
                scriptId,

            owner:
                req.user.id,

            name,

            source,

            createdAt:
                new Date()
                    .toISOString(),

            updatedAt:
                new Date()
                    .toISOString()
        };

        req.user.scripts.push(
            scriptId
        );

        saveDatabase();

        res.json({

            ok: true,

            script: {

                id:
                    scriptId,

                name,

                loader:
                    `/api/loader/${scriptId}`
            }
        });
    }
);

/* =========================================================
   LIST SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const scripts =
            req.user.scripts
                .map(
                    scriptId =>
                        database.scripts[
                            scriptId
                        ]
                )
                .filter(Boolean)
                .map(
                    script => ({

                        id:
                            script.id,

                        name:
                            script.name,

                        createdAt:
                            script.createdAt,

                        updatedAt:
                            script.updatedAt,

                        loader:
                            `/api/loader/${script.id}`
                    })
                );

        res.json({

            ok: true,

            scripts
        });
    }
);

/* =========================================================
   GET SCRIPT
========================================================= */

app.get(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const scriptId =
            cleanId(
                req.params.id
            );

        const script =
            database.scripts[
                scriptId
            ];

        if (!script) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found"
                });
        }

        if (
            script.owner !==
            req.user.id
        ) {

            return res
                .status(403)
                .json({
                    ok: false,
                    error:
                        "Access denied"
                });
        }

        res.json({

            ok: true,

            script: {

                id:
                    script.id,

                name:
                    script.name,

                source:
                    script.source,

                createdAt:
                    script.createdAt,

                updatedAt:
                    script.updatedAt
            }
        });
    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const scriptId =
            cleanId(
                req.params.id
            );

        const script =
            database.scripts[
                scriptId
            ];

        if (!script) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found"
                });
        }

        if (
            script.owner !==
            req.user.id
        ) {

            return res
                .status(403)
                .json({
                    ok: false,
                    error:
                        "Access denied"
                });
        }

        if (
            req.body.name !==
            undefined
        ) {

            const name =
                String(
                    req.body.name
                )
                .trim()
                .slice(0, 100);

            if (name) {
                script.name =
                    name;
            }
        }

        if (
            req.body.source !==
            undefined
        ) {

            script.source =
                String(
                    req.body.source
                );
        }

        script.updatedAt =
            new Date()
                .toISOString();

        saveDatabase();

        res.json({

            ok: true,

            message:
                "Script updated"
        });
    }
);

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const scriptId =
            cleanId(
                req.params.id
            );

        const script =
            database.scripts[
                scriptId
            ];

        if (!script) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found"
                });
        }

        if (
            script.owner !==
            req.user.id
        ) {

            return res
                .status(403)
                .json({
                    ok: false,
                    error:
                        "Access denied"
                });
        }

        delete database.scripts[
            scriptId
        ];

        req.user.scripts =
            req.user.scripts.filter(
                id =>
                    id !== scriptId
            );

        saveDatabase();

        res.json({

            ok: true,

            message:
                "Script deleted"
        });
    }
);

/* =========================================================
   LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const scriptId =
            cleanId(
                req.params.id
            );

        /*
         * Browser navigation receives
         * the visual block page.
         */

        const accept =
            String(
                req.headers.accept || ""
            ).toLowerCase();

        const browserRequest =
            accept.includes(
                "text/html"
            );

        if (
            browserRequest
        ) {

            return res
                .status(403)
                .type("html")
                .send(
                    blockPage()
                );
        }

        const script =
            database.scripts[
                scriptId
            ];

        if (!script) {

            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
         * Return the stored script
         * for the loader client.
         */

        return res
            .status(200)
            .type("text/plain")
            .send(
                script.source
            );
    }
);

/* =========================================================
   API 404
========================================================= */

app.use(
    "/api",
    (req, res) => {

        res
            .status(404)
            .json({
                ok: false,
                error:
                    "LEXINX BLOCK"
            });
    }
);

/* =========================================================
   GENERAL 404
========================================================= */

app.use(
    (req, res) => {

        res
            .status(404)
            .send(
                "LEXINX PROTECT - NOT FOUND"
            );
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "LEXINX SERVER ERROR:",
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
                ok: false,
                error:
                    "Internal server error"
            });
    }
);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    HOST,
    () => {

        console.log(
            "======================================"
        );

        console.log(
            "        LEXINX PROTECT SERVER"
        );

        console.log(
            "======================================"
        );

        console.log(
            `Server: http://${HOST}:${PORT}`
        );

        console.log(
            "Web: /"
        );

        console.log(
            "Register: POST /api/register"
        );

        console.log(
            "Login: POST /api/login"
        );

        console.log(
            "Scripts: /api/scripts"
        );

        console.log(
            "Loader: /api/loader/:id"
        );

        console.log(
            "Database:",
            DATA_FILE
        );
    }
);
