const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const BASE_URL =
    process.env.BASE_URL ||
    "https://lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "accounts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.disable("x-powered-by");

app.use(express.json({
    limit: "10mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "10mb"
}));

app.use(express.static(PUBLIC_DIR));

/* =========================================================
   DATABASE
========================================================= */

function readDB() {
    try {
        return JSON.parse(
            fs.readFileSync(DB_FILE, "utf8")
        );
    } catch {
        return {};
    }
}

function writeDB(db) {
    const tmp =
        DB_FILE + ".tmp";

    fs.writeFileSync(
        tmp,
        JSON.stringify(db, null, 2),
        "utf8"
    );

    fs.renameSync(
        tmp,
        DB_FILE
    );
}

/* =========================================================
   RANDOM
========================================================= */

function randomID(bytes = 24) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

/* =========================================================
   PASSWORD
========================================================= */

function hashPassword(password) {

    const salt =
        crypto.randomBytes(16);

    const hash =
        crypto.scryptSync(
            password,
            salt,
            64
        );

    return {
        salt:
            salt.toString("hex"),

        hash:
            hash.toString("hex")
    };
}

function verifyPassword(
    password,
    data
) {

    try {

        const salt =
            Buffer.from(
                data.salt,
                "hex"
            );

        const expected =
            Buffer.from(
                data.hash,
                "hex"
            );

        const actual =
            crypto.scryptSync(
                password,
                salt,
                64
            );

        return (
            actual.length ===
                expected.length &&
            crypto.timingSafeEqual(
                actual,
                expected
            )
        );

    } catch {

        return false;
    }
}

/* =========================================================
   COOKIES
========================================================= */

function parseCookies(req) {

    const result = {};

    const raw =
        req.headers.cookie;

    if (!raw) {
        return result;
    }

    for (
        const item
        of raw.split(";")
    ) {

        const index =
            item.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            item
                .slice(0, index)
                .trim();

        const value =
            item
                .slice(index + 1)
                .trim();

        result[key] =
            decodeURIComponent(value);
    }

    return result;
}

/* =========================================================
   SESSIONS
========================================================= */

const sessions =
    new Map();

const SESSION_TIME =
    30 * 24 * 60 * 60 * 1000;

function createSession(username) {

    const token =
        randomID(48);

    sessions.set(
        token,
        {
            username,
            createdAt:
                Date.now(),
            lastActivity:
                Date.now(),
            expires:
                Date.now() +
                SESSION_TIME
        }
    );

    return token;
}

function getCurrentUser(req) {

    const cookies =
        parseCookies(req);

    const token =
        cookies.lexinx_session;

    if (!token) {
        return null;
    }

    const session =
        sessions.get(token);

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expires
    ) {

        sessions.delete(token);

        return null;
    }

    session.lastActivity =
        Date.now();

    session.expires =
        Date.now() +
        SESSION_TIME;

    return session.username;
}

function setSession(
    res,
    token
) {

    res.setHeader(
        "Set-Cookie",
        [
            "lexinx_session=" +
                encodeURIComponent(token),

            "Path=/",

            "HttpOnly",

            "SameSite=Lax",

            "Max-Age=2592000"
        ].join("; ")
    );
}

function clearSession(res) {

    res.setHeader(
        "Set-Cookie",
        [
            "lexinx_session=",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=0"
        ].join("; ")
    );
}

function requireAuth(
    req,
    res,
    next
) {

    const username =
        getCurrentUser(req);

    if (!username) {

        return res
            .status(401)
            .json({
                ok: false,
                error:
                    "Authentication required"
            });
    }

    req.username =
        username;

    next();
}

/* =========================================================
   ACCOUNT URL
========================================================= */

function getAccountURL(
    account
) {

    return (
        BASE_URL +
        "/acc/" +
        encodeURIComponent(
            account.username
        ) +
        "/" +
        account.id
    );
}

/* =========================================================
   BROWSER BLOCK PAGE
========================================================= */

function renderBlockPage() {

    return `<!doctype html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>LEXINX PROTECT</title>

<style>

*{
    box-sizing:border-box;
}

html,
body{
    width:100%;
    height:100%;
    margin:0;
}

body{

    overflow:hidden;

    background:#050505;

    color:#fff;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}

#stars{

    position:fixed;

    inset:0;

    width:100%;
    height:100%;
}

.panel{

    position:absolute;

    z-index:2;

    left:50%;
    top:50%;

    transform:
        translate(-50%,-50%);

    width:min(
        560px,
        90%
    );

    padding:
        58px 30px;

    text-align:center;

    background:
        rgba(32,32,32,.76);

    border:
        1px solid #3a3a3a;

    border-radius:
        18px;

    box-shadow:
        0 0 60px
        rgba(255,255,255,.04),

        inset 0 0 35px
        rgba(255,255,255,.025);

    backdrop-filter:
        blur(8px);
}

.logo{

    margin:0;

    font-size:
        clamp(
            32px,
            7vw,
            60px
        );

    font-weight:900;

    letter-spacing:5px;

    animation:
        logoFade
        5s
        ease-in-out
        infinite;
}

.line{

    width:90px;

    height:1px;

    margin:
        24px auto;

    background:#666;

    animation:
        lineFade
        5s
        ease-in-out
        infinite;
}

.subtitle{

    color:#888;

    font-size:13px;

    letter-spacing:5px;

    text-transform:
        uppercase;
}

@keyframes logoFade{

    0%{

        color:#fff;

        text-shadow:
            0 0 10px
            rgba(255,255,255,.25);
    }

    50%{

        color:#111;

        text-shadow:
            0 0 12px
            rgba(0,0,0,.9);
    }

    100%{

        color:#fff;

        text-shadow:
            0 0 10px
            rgba(255,255,255,.25);
    }
}

@keyframes lineFade{

    0%{
        opacity:.25;
    }

    50%{
        opacity:1;
    }

    100%{
        opacity:.25;
    }
}

</style>

</head>

<body>

<canvas id="stars"></canvas>

<div class="panel">

    <h1 class="logo">
        LEXINX PROTECT
    </h1>

    <div class="line"></div>

    <div class="subtitle">
        Anti-Skid
    </div>

</div>

<script>

const canvas =
    document.getElementById(
        "stars"
    );

const ctx =
    canvas.getContext("2d");

let stars = [];

function resize(){

    canvas.width =
        window.innerWidth;

    canvas.height =
        window.innerHeight;

    stars = [];

    const count =
        Math.min(
            260,
            Math.floor(
                canvas.width *
                canvas.height /
                6000
            )
        );

    for(
        let i = 0;
        i < count;
        i++
    ){

        stars.push({

            x:
                Math.random() *
                canvas.width,

            y:
                Math.random() *
                canvas.height,

            r:
                Math.random() *
                1.5 +
                .25,

            speed:
                Math.random() *
                .35 +
                .08,

            alpha:
                Math.random() *
                .7 +
                .2
        });
    }
}

function draw(){

    ctx.clearRect(
        0,
        0,
        canvas.width,
        canvas.height
    );

    for(
        const star
        of stars
    ){

        star.y +=
            star.speed;

        if(
            star.y >
            canvas.height
        ){

            star.y = -2;

            star.x =
                Math.random() *
                canvas.width;
        }

        ctx.beginPath();

        ctx.arc(
            star.x,
            star.y,
            star.r,
            0,
            Math.PI * 2
        );

        ctx.fillStyle =
            "rgba(190,190,190," +
            star.alpha +
            ")";

        ctx.fill();
    }

    requestAnimationFrame(
        draw
    );
}

window.addEventListener(
    "resize",
    resize
);

resize();
draw();

</script>

</body>
</html>`;
}

/* =========================================================
   HOME
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);

/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/register",
    (req, res) => {

        try {

            const username =
                String(
                    req.body?.username ||
                    ""
                ).trim();

            const password =
                String(
                    req.body?.password ||
                    ""
                );

            if (
                !/^[A-Za-z0-9_]{3,24}$/
                    .test(username)
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        error:
                            "Username must contain 3-24 letters, numbers, or underscores."
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
                            "Password must contain at least 6 characters."
                    });
            }

            const db =
                readDB();

            const key =
                username.toLowerCase();

            if (db[key]) {

                return res
                    .status(409)
                    .json({
                        ok: false,
                        error:
                            "Username already exists."
                    });
            }

            const passwordData =
                hashPassword(
                    password
                );

            const account = {

                username,

                id:
                    randomID(16),

                password: {

                    salt:
                        passwordData.salt,

                    hash:
                        passwordData.hash
                },

                createdAt:
                    Date.now(),

                scripts: {}
            };

            db[key] =
                account;

            writeDB(db);

            const session =
                createSession(key);

            setSession(
                res,
                session
            );

            res.json({

                ok: true,

                username:
                    account.username,

                accountId:
                    account.id,

                url:
                    getAccountURL(
                        account
                    )
            });

        } catch(error) {

            console.error(
                error
            );

            res
                .status(500)
                .json({
                    ok: false,
                    error:
                        "Internal server error."
                });
        }
    }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/login",
    (req, res) => {

        try {

            const username =
                String(
                    req.body?.username ||
                    ""
                ).trim();

            const password =
                String(
                    req.body?.password ||
                    ""
                );

            const db =
                readDB();

            const key =
                username.toLowerCase();

            const account =
                db[key];

            if (
                !account ||
                !verifyPassword(
                    password,
                    account.password
                )
            ) {

                return res
                    .status(401)
                    .json({
                        ok: false,
                        error:
                            "Invalid username or password."
                    });
            }

            const session =
                createSession(key);

            setSession(
                res,
                session
            );

            res.json({

                ok: true,

                username:
                    account.username,

                accountId:
                    account.id,

                url:
                    getAccountURL(
                        account
                    )
            });

        } catch(error) {

            console.error(
                error
            );

            res
                .status(500)
                .json({
                    ok: false,
                    error:
                        "Internal server error."
                });
        }
    }
);

/* =========================================================
   ME
========================================================= */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        if (!account) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Account not found."
                });
        }

        res.json({

            ok: true,

            username:
                account.username,

            accountId:
                account.id,

            url:
                getAccountURL(
                    account
                )
        });
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    (req, res) => {

        const cookies =
            parseCookies(req);

        if (
            cookies.lexinx_session
        ) {

            sessions.delete(
                cookies.lexinx_session
            );
        }

        clearSession(res);

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   ACCOUNT PAGE
========================================================= */

app.get(
    "/acc/:username/:id",
    (req, res) => {

        const db =
            readDB();

        const key =
            String(
                req.params.username
            ).toLowerCase();

        const account =
            db[key];

        if (
            !account ||
            account.id !==
            req.params.id
        ) {

            return res
                .status(403)
                .type("html")
                .send(
                    renderBlockPage()
                );
        }

        const current =
            getCurrentUser(req);

        if (
            !current ||
            current !== key
        ) {

            return res.redirect(
                "/"
            );
        }

        res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/create",
    requireAuth,
    (req, res) => {

        const name =
            String(
                req.body?.name ||
                "Untitled Script"
            )
            .trim()
            .slice(0, 80);

        const source =
            String(
                req.body?.source ||
                ""
            );

        if (
            !source.trim()
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Script source cannot be empty."
                });
        }

        const db =
            readDB();

        const account =
            db[req.username];

        if (!account) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Account not found."
                });
        }

        const id =
            randomID(12);

        account.scripts[id] = {

            id,

            name,

            source,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()
        };

        writeDB(db);

        const endpoint =
            BASE_URL +
            "/api/loader/" +
            id;

        res.json({

            ok: true,

            id,

            name,

            endpoint,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(endpoint)}))()`
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

        const db =
            readDB();

        const account =
            db[req.username];

        if (!account) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Account not found."
                });
        }

        const scripts =
            Object.values(
                account.scripts ||
                {}
            );

        res.json({

            ok: true,

            scripts:
                scripts.map(
                    script => {

                        const endpoint =
                            BASE_URL +
                            "/api/loader/" +
                            script.id;

                        return {

                            id:
                                script.id,

                            name:
                                script.name,

                            createdAt:
                                script.createdAt,

                            updatedAt:
                                script.updatedAt,

                            endpoint,

                            loader:
                                `loadstring(game:HttpGet(${JSON.stringify(endpoint)}))()`
                        };
                    }
                )
        });
    }
);

/* =========================================================
   GET SCRIPT
========================================================= */

app.get(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        const script =
            account?.scripts?.[
                req.params.id
            ];

        if (!script) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found."
                });
        }

        res.json({

            ok: true,

            script
        });
    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        const script =
            account?.scripts?.[
                req.params.id
            ];

        if (!script) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found."
                });
        }

        if (
            req.body?.name !==
            undefined
        ) {

            script.name =
                String(
                    req.body.name
                )
                .trim()
                .slice(0, 80);
        }

        if (
            req.body?.source !==
            undefined
        ) {

            const source =
                String(
                    req.body.source
                );

            if (
                !source.trim()
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        error:
                            "Source cannot be empty."
                    });
            }

            script.source =
                source;
        }

        script.updatedAt =
            Date.now();

        writeDB(db);

        res.json({

            ok: true,

            script
        });
    }
);

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        if (
            !account?.scripts?.[
                req.params.id
            ]
        ) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found."
                });
        }

        delete account.scripts[
            req.params.id
        ];

        writeDB(db);

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   FIND SCRIPT
========================================================= */

function findScript(id) {

    const db =
        readDB();

    for (
        const username
        of Object.keys(db)
    ) {

        const account =
            db[username];

        if (
            account.scripts &&
            account.scripts[id]
        ) {

            return {
                account,
                script:
                    account.scripts[id]
            };
        }
    }

    return null;
}

/* =========================================================
   LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const accept =
            String(
                req.headers.accept ||
                ""
            ).toLowerCase();

        const destination =
            String(
                req.headers[
                    "sec-fetch-dest"
                ] || ""
            ).toLowerCase();

        /*
         * Browser navigation:
         * return the graphical 403 page.
         */

        if (
            accept.includes(
                "text/html"
            ) ||
            destination ===
                "document"
        ) {

            return res
                .status(403)
                .set(
                    "Cache-Control",
                    "no-store"
                )
                .type("html")
                .send(
                    renderBlockPage()
                );
        }

        const found =
            findScript(
                req.params.id
            );

        if (!found) {

            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
         * Only the loader is returned.
         * The stored source is not placed
         * inside this response.
         */

        const runtime =
            BASE_URL +
            "/api/runtime/" +
            found.script.id;

        const lua = `
local response = request({
    Url = ${JSON.stringify(runtime)},
    Method = "POST",
    Headers = {
        ["Content-Type"] = "application/json"
    },
    Body = "{}"
})

if not response then
    error("LEXINX BLOCK")
end

if response.StatusCode ~= 200 then
    error("LEXINX BLOCK")
end

local HttpService =
    game:GetService("HttpService")

local ok, data =
    pcall(function()
        return HttpService:JSONDecode(
            response.Body
        )
    end)

if not ok then
    error("LEXINX BLOCK")
end

if type(data) ~= "table" then
    error("LEXINX BLOCK")
end

if data.ok ~= true then
    error("LEXINX BLOCK")
end

if type(data.code) ~= "string" then
    error("LEXINX BLOCK")
end

local fn, err =
    loadstring(data.code)

if not fn then
    error(
        err or
        "LEXINX BLOCK"
    )
end

local success, runtimeError =
    pcall(fn)

if not success then
    error(runtimeError)
end
`.trim();

        res
            .status(200)
            .set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            )
            .set(
                "Pragma",
                "no-cache"
            )
            .set(
                "X-Content-Type-Options",
                "nosniff"
            )
            .type("text/plain")
            .send(lua);
    }
);

/* =========================================================
   RUNTIME
========================================================= */

app.post(
    "/api/runtime/:id",
    (req, res) => {

        const found =
            findScript(
                req.params.id
            );

        if (!found) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "LEXINX BLOCK"
                });
        }

        /*
         * Important:
         *
         * Any source that is executed by
         * Roblox must ultimately reach
         * the client/runtime.
         *
         * Therefore this endpoint does not
         * provide cryptographic "zero exposure".
         */

        res
            .status(200)
            .set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            )
            .set(
                "Pragma",
                "no-cache"
            )
            .json({

                ok: true,

                code:
                    found.script.source
            });
    }
);

/* =========================================================
   UNKNOWN ROUTES
========================================================= */

app.use(
    (req, res) => {

        res
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX BLOCK"
            );
    }
);

/* =========================================================
   SESSION CLEANUP
========================================================= */

setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [
                token,
                session
            ]
            of sessions
        ) {

            if (
                now >
                session.expires
            ) {

                sessions.delete(
                    token
                );
            }
        }

    },
    60 * 1000
);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "================================"
        );

        console.log(
            "LEXINX PROTECT ONLINE"
        );

        console.log(
            "PORT:",
            PORT
        );

        console.log(
            "BASE URL:",
            BASE_URL
        );

        console.log(
            "DATABASE:",
            DB_FILE
        );

        console.log(
            "================================"
        );
    }
);
