"use strict";

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

/* =========================================================
   DATABASE
========================================================= */

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

function defaultDB() {
    return {
        users: {},
        scripts: {}
    };
}

function loadDB() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            return defaultDB();
        }

        const raw =
            fs.readFileSync(
                DATA_FILE,
                "utf8"
            );

        const parsed =
            JSON.parse(raw);

        return {
            users:
                parsed.users || {},
            scripts:
                parsed.scripts || {}
        };
    } catch (err) {
        console.error(
            "Database load error:",
            err.message
        );

        return defaultDB();
    }
}

let db = loadDB();

function saveDB() {
    const temp =
        DATA_FILE + ".tmp";

    fs.writeFileSync(
        temp,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );

    fs.renameSync(
        temp,
        DATA_FILE
    );
}

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

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
        .update(String(password))
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

const sessions = new Map();

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

function getSession(req) {

    const header =
        req.headers.authorization;

    if (
        !header ||
        !header.startsWith(
            "Bearer "
        )
    ) {
        return null;
    }

    const token =
        header.slice(7).trim();

    if (!token) {
        return null;
    }

    const session =
        sessions.get(token);

    if (!session) {
        return null;
    }

    const user =
        Object.values(
            db.users
        ).find(
            x => x.id === session.userId
        );

    if (!user) {
        sessions.delete(token);
        return null;
    }

    return {
        token,
        session,
        user
    };
}

function requireAuth(
    req,
    res,
    next
) {

    const auth =
        getSession(req);

    if (!auth) {
        return res.status(401).json({
            ok: false,
            error:
                "Authentication required"
        });
    }

    req.auth = auth;
    req.user = auth.user;

    next();
}

/* =========================================================
   LEXINX PROTECT PAGE
========================================================= */

function createStars(count = 220) {

    let html = "";

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

        const opacity =
            0.15 +
            Math.random() * 0.7;

        html += `
<span
    class="star"
    style="
        left:${left.toFixed(2)}%;
        top:${top.toFixed(2)}%;
        width:${size.toFixed(1)}px;
        height:${size.toFixed(1)}px;
        opacity:${opacity.toFixed(2)};
        animation-duration:${duration.toFixed(2)}s;
        animation-delay:${delay.toFixed(2)}s;
">
</span>`;
    }

    return html;
}

function blockPage() {

    const stars =
        createStars(220);

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
    margin: 0;

    width: 100%;
    height: 100%;

    overflow: hidden;
}

body {

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #050505;

    color: #fff;
}

/* =====================================================
   ANIMATED BACKGROUND
===================================================== */

.scene {

    position: relative;

    width: 100%;
    height: 100%;

    overflow: hidden;

    background:
        radial-gradient(
            circle at 50% 50%,
            #727272 0%,
            #414141 22%,
            #222 52%,
            #090909 100%
        );

    animation:
        backgroundMove
        12s
        ease-in-out
        infinite
        alternate;
}

@keyframes backgroundMove {

    0% {

        background-position:
            0% 0%;
    }

    25% {

        background:
            radial-gradient(
                circle at 30% 40%,
                #686868 0%,
                #363636 28%,
                #1b1b1b 60%,
                #050505 100%
            );
    }

    50% {

        background:
            radial-gradient(
                circle at 70% 30%,
                #777 0%,
                #404040 30%,
                #181818 65%,
                #050505 100%
            );
    }

    75% {

        background:
            radial-gradient(
                circle at 40% 75%,
                #626262 0%,
                #323232 30%,
                #151515 65%,
                #050505 100%
            );
    }

    100% {

        background:
            radial-gradient(
                circle at 80% 70%,
                #737373 0%,
                #383838 30%,
                #171717 65%,
                #050505 100%
            );
    }
}

/* =====================================================
   MOVING GLOW
===================================================== */

.glow {

    position: absolute;

    width: 55vw;
    height: 55vw;

    min-width: 350px;
    min-height: 350px;

    border-radius: 50%;

    left: 50%;
    top: 50%;

    transform:
        translate(-50%, -50%);

    background:
        radial-gradient(
            circle,
            rgba(255,255,255,.14),
            rgba(255,255,255,.04) 35%,
            transparent 70%
        );

    filter:
        blur(25px);

    animation:
        glowPulse
        7s
        ease-in-out
        infinite;
}

@keyframes glowPulse {

    0% {

        transform:
            translate(-50%, -50%)
            scale(.85);

        opacity: .45;
    }

    50% {

        transform:
            translate(-50%, -50%)
            scale(1.15);

        opacity: .9;
    }

    100% {

        transform:
            translate(-50%, -50%)
            scale(.85);

        opacity: .45;
    }
}

/* =====================================================
   STARS
===================================================== */

.stars {

    position: absolute;

    inset: 0;

    overflow: hidden;
}

.star {

    position: absolute;

    display: block;

    border-radius: 50%;

    background: #fff;

    box-shadow:
        0 0 5px
        rgba(255,255,255,.8);

    animation:
        starPulse
        ease-in-out
        infinite;
}

@keyframes starPulse {

    0% {

        transform:
            scale(.3);

        opacity: .05;
    }

    50% {

        transform:
            scale(1.8);

        opacity: 1;
    }

    100% {

        transform:
            scale(.3);

        opacity: .05;
    }
}

/* =====================================================
   PARTICLE LINES
===================================================== */

.lines {

    position: absolute;

    inset: -30%;

    opacity: .08;

    background:
        repeating-linear-gradient(
            115deg,
            transparent 0px,
            transparent 80px,
            #fff 81px,
            transparent 82px,
            transparent 160px
        );

    animation:
        lineMove
        18s
        linear
        infinite;
}

@keyframes lineMove {

    from {

        transform:
            translate3d(
                -8%,
                -8%,
                0
            );
    }

    to {

        transform:
            translate3d(
                8%,
                8%,
                0
            );
    }
}

/* =====================================================
   CENTER CARD
===================================================== */

.center {

    position: absolute;

    left: 50%;
    top: 50%;

    transform:
        translate(-50%, -50%);

    width:
        min(94vw, 900px);

    min-height: 430px;

    display: flex;

    flex-direction: column;

    align-items: center;

    justify-content: center;

    text-align: center;

    padding:
        70px 40px;

    border-radius: 28px;

    background:
        linear-gradient(
            145deg,
            rgba(110,110,110,.48),
            rgba(35,35,35,.58)
        );

    border:
        1px solid
        rgba(255,255,255,.18);

    box-shadow:

        0 30px 100px
        rgba(0,0,0,.75),

        inset 0 1px 0
        rgba(255,255,255,.12),

        inset 0 0 80px
        rgba(255,255,255,.035);

    backdrop-filter:
        blur(14px);

    animation:
        cardFloat
        6s
        ease-in-out
        infinite;
}

@keyframes cardFloat {

    0% {

        transform:
            translate(-50%, -50%)
            translateY(0px);
    }

    50% {

        transform:
            translate(-50%, -50%)
            translateY(-8px);
    }

    100% {

        transform:
            translate(-50%, -50%)
            translateY(0px);
    }
}

/* =====================================================
   LOGO
===================================================== */

.logo {

    margin: 0;

    font-size:
        clamp(
            48px,
            9vw,
            110px
        );

    line-height: 1;

    font-weight: 1000;

    letter-spacing:
        clamp(
            5px,
            1.2vw,
            14px
        );

    color: #fff;

    animation:
        logoColor
        6s
        ease-in-out
        infinite;

    user-select: none;

    text-shadow:
        0 0 12px
        rgba(255,255,255,.18),

        0 0 45px
        rgba(255,255,255,.08);
}

@keyframes logoColor {

    0% {

        color: #fff;

        text-shadow:
            0 0 20px
            rgba(255,255,255,.45);
    }

    25% {

        color: #cfcfcf;
    }

    50% {

        color: #707070;

        text-shadow:
            0 0 4px
            rgba(255,255,255,.05);
    }

    75% {

        color: #dcdcdc;
    }

    100% {

        color: #fff;

        text-shadow:
            0 0 20px
            rgba(255,255,255,.45);
    }
}

/* =====================================================
   SUBTITLE
===================================================== */

.subtitle {

    margin-top: 32px;

    font-size:
        clamp(
            13px,
            2vw,
            19px
        );

    letter-spacing:
        8px;

    color: #aaa;

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

        opacity: .3;

        transform:
            translateY(5px);
    }

    50% {

        opacity: 1;

        transform:
            translateY(0);
    }

    100% {

        opacity: .3;

        transform:
            translateY(5px);
    }
}

/* =====================================================
   STATUS
===================================================== */

.status {

    margin-top: 30px;

    padding:
        11px 25px;

    border-radius:
        999px;

    border:
        1px solid
        rgba(255,255,255,.16);

    background:
        rgba(0,0,0,.24);

    color: #888;

    font-size: 12px;

    letter-spacing:
        4px;

    animation:
        statusPulse
        3s
        ease-in-out
        infinite;
}

@keyframes statusPulse {

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
            rgba(255,255,255,.2),
            transparent
        );

    filter:
        blur(.5px);

    animation:
        scanMove
        7s
        linear
        infinite;
}

@keyframes scanMove {

    0% {

        top: -5%;
    }

    100% {

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
            ellipse at center,
            transparent 30%,
            rgba(0,0,0,.25) 65%,
            rgba(0,0,0,.72) 100%
        );
}

/* =====================================================
   MOBILE
===================================================== */

@media(max-width:600px) {

    .center {

        min-height:
            340px;

        padding:
            45px 18px;
    }

    .logo {

        letter-spacing:
            4px;
    }

    .subtitle {

        letter-spacing:
            4px;
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

    <div class="glow"></div>

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
   HOME
========================================================= */

app.get("/", (req, res) => {

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
        #0b0b0b;

    color: #fff;

    font-family:
        Arial,
        sans-serif;
}

.box {

    width:
        min(90%, 650px);

    padding:
        50px;

    text-align: center;

    border:
        1px solid #333;

    border-radius:
        20px;

    background:
        #151515;

    box-shadow:
        0 20px 60px
        rgba(0,0,0,.6);
}

h1 {

    margin: 0;

    font-size: 42px;
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
            username.length < 3 ||
            password.length < 6
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Username must contain at least 3 characters and password at least 6 characters"
                });
        }

        const key =
            username.toLowerCase();

        if (db.users[key]) {

            return res
                .status(409)
                .json({
                    ok: false,
                    error:
                        "Username already exists"
                });
        }

        const userId =
            randomId(16);

        const user = {

            id: userId,

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

        db.users[key] =
            user;

        saveDB();

        const token =
            createSession(
                userId
            );

        res.json({

            ok: true,

            token,

            user: {
                id: user.id,
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
            db.users[key];

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
                id: user.id,
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
   CURRENT USER
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
                        "Script name and source are required"
                });
        }

        const scriptId =
            randomId(16);

        db.scripts[
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

        saveDB();

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
                    id =>
                        db.scripts[id]
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
            db.scripts[
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
            db.scripts[
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

        saveDB();

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
            db.scripts[
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

        delete db.scripts[
            scriptId
        ];

        req.user.scripts =
            req.user.scripts.filter(
                id =>
                    id !== scriptId
            );

        saveDB();

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

        const accept =
            String(
                req.headers.accept || ""
            ).toLowerCase();

        const isBrowser =
            accept.includes(
                "text/html"
            );

        /*
         * Direct browser navigation:
         * show the visual block page.
         */

        if (isBrowser) {

            return res
                .status(403)
                .type("html")
                .send(
                    blockPage()
                );
        }

        const script =
            db.scripts[
                scriptId
            ];

        if (!script) {

            return res
                .status(404)
                .type("text")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
         * Return the stored payload.
         *
         * This endpoint does not expose
         * the user's account information
         * or management metadata.
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
    (err, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            err
        );

        if (
            res.headersSent
        ) {
            return next(err);
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
            "================================="
        );

        console.log(
            "      LEXINX PROTECT SERVER"
        );

        console.log(
            "================================="
        );

        console.log(
            `Listening on ${HOST}:${PORT}`
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
