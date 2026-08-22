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

app.use(express.json({ limit: "10mb" }));
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
    const temp =
        DB_FILE + ".tmp";

    fs.writeFileSync(
        temp,
        JSON.stringify(db, null, 2),
        "utf8"
    );

    fs.renameSync(
        temp,
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
   PASSWORD HASHING
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
        salt: salt.toString("hex"),
        hash: hash.toString("hex")
    };
}

function verifyPassword(password, data) {
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
   COOKIE
========================================================= */

function parseCookies(req) {
    const result = {};
    const raw = req.headers.cookie;

    if (!raw) {
        return result;
    }

    for (const part of raw.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            part.slice(0, index).trim();

        const value =
            part.slice(index + 1).trim();

        result[key] =
            decodeURIComponent(value);
    }

    return result;
}

/* =========================================================
   SESSIONS
========================================================= */

const sessions = new Map();

const SESSION_TIME =
    30 * 24 * 60 * 60 * 1000;

function createSession(username) {
    const token = randomID(48);

    sessions.set(token, {
        username,
        createdAt: Date.now(),
        lastActivity: Date.now(),
        expires:
            Date.now() +
            SESSION_TIME
    });

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

    if (Date.now() > session.expires) {
        sessions.delete(token);
        return null;
    }

    /*
     * Keep the user logged in while
     * the session is still being used.
     */

    session.lastActivity =
        Date.now();

    session.expires =
        Date.now() +
        SESSION_TIME;

    return session.username;
}

function setSession(res, token) {
    res.setHeader(
        "Set-Cookie",
        [
            `lexinx_session=${encodeURIComponent(token)}`,
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

function requireAuth(req, res, next) {
    const username =
        getCurrentUser(req);

    if (!username) {
        return res.status(401).json({
            ok: false,
            error: "Authentication required"
        });
    }

    req.username = username;
    next();
}

/* =========================================================
   ACCOUNT URL
========================================================= */

function getAccountURL(account) {
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
   HOME
========================================================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            PUBLIC_DIR,
            "index.html"
        )
    );
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", (req, res) => {
    try {
        const username =
            String(
                req.body?.username || ""
            ).trim();

        const password =
            String(
                req.body?.password || ""
            );

        if (
            !/^[A-Za-z0-9_]{3,24}$/.test(
                username
            )
        ) {
            return res.status(400).json({
                ok: false,
                error:
                    "Username must contain 3-24 letters, numbers, or underscores."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                ok: false,
                error:
                    "Password must contain at least 6 characters."
            });
        }

        const db = readDB();

        const key =
            username.toLowerCase();

        if (db[key]) {
            return res.status(409).json({
                ok: false,
                error:
                    "That username is already registered."
            });
        }

        const passwordData =
            hashPassword(password);

        const account = {
            username,
            id: randomID(16),

            password: {
                salt:
                    passwordData.salt,
                hash:
                    passwordData.hash
            },

            createdAt: Date.now(),

            scripts: {}
        };

        db[key] = account;

        writeDB(db);

        const session =
            createSession(key);

        setSession(
            res,
            session
        );

        console.log(
            "[REGISTER]",
            username
        );

        return res.json({
            ok: true,
            username:
                account.username,
            accountId:
                account.id,
            url:
                getAccountURL(account)
        });

    } catch (error) {

        console.error(
            "[REGISTER ERROR]",
            error
        );

        return res.status(500).json({
            ok: false,
            error:
                "Internal server error."
        });
    }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", (req, res) => {
    try {
        const username =
            String(
                req.body?.username || ""
            ).trim();

        const password =
            String(
                req.body?.password || ""
            );

        const db = readDB();

        const key =
            username.toLowerCase();

        const account = db[key];

        if (
            !account ||
            !verifyPassword(
                password,
                account.password
            )
        ) {
            return res.status(401).json({
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

        console.log(
            "[LOGIN]",
            account.username
        );

        return res.json({
            ok: true,
            username:
                account.username,
            accountId:
                account.id,
            url:
                getAccountURL(account)
        });

    } catch (error) {

        console.error(
            "[LOGIN ERROR]",
            error
        );

        return res.status(500).json({
            ok: false,
            error:
                "Internal server error."
        });
    }
});

/* =========================================================
   CURRENT ACCOUNT
========================================================= */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.username];

        if (!account) {
            return res.status(401).json({
                ok: false,
                error:
                    "Account no longer exists."
            });
        }

        res.json({
            ok: true,
            username:
                account.username,
            accountId:
                account.id,
            url:
                getAccountURL(account)
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

        const db = readDB();

        const key =
            String(
                req.params.username
            ).toLowerCase();

        const account = db[key];

        if (
            !account ||
            account.id !==
            req.params.id
        ) {
            function blockPage() {
    return `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">

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
    display:flex;
    align-items:center;
    justify-content:center;

    background:#181818;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}

.scene{
    position:relative;

    width:100%;
    height:100%;

    overflow:hidden;

    background:
        radial-gradient(
            circle at center,
            #555 0%,
            #303030 35%,
            #181818 75%,
            #0b0b0b 100%
        );
}

/* =====================================================
   STARS
===================================================== */

.stars{
    position:absolute;
    inset:0;

    overflow:hidden;
}

.star{
    position:absolute;

    width:2px;
    height:2px;

    background:#aaa;

    border-radius:50%;

    box-shadow:
        0 0 5px #aaa;

    animation:
        twinkle
        var(--duration)
        ease-in-out
        infinite;
}

@keyframes twinkle{

    0%{
        opacity:.15;
        transform:scale(.6);
    }

    50%{
        opacity:1;
        transform:scale(1.4);
    }

    100%{
        opacity:.15;
        transform:scale(.6);
    }
}

/* =====================================================
   CENTER
===================================================== */

.center{
    position:absolute;

    top:50%;
    left:50%;

    transform:
        translate(-50%,-50%);

    text-align:center;

    z-index:10;

    width:min(90%,700px);

    padding:45px 30px;

    background:
        rgba(70,70,70,.35);

    border:
        1px solid
        rgba(255,255,255,.12);

    border-radius:18px;

    box-shadow:
        0 0 60px
        rgba(0,0,0,.55),

        inset 0 0 35px
        rgba(255,255,255,.04);

    backdrop-filter:
        blur(7px);
}

/* =====================================================
   LOGO
===================================================== */

.logo{

    margin:0;

    font-size:
        clamp(
            35px,
            7vw,
            78px
        );

    font-weight:900;

    letter-spacing:
        7px;

    color:#fff;

    animation:
        logoFade
        5s
        ease-in-out
        infinite;

    text-shadow:
        0 0 15px
        rgba(255,255,255,.15);
}

@keyframes logoFade{

    0%{
        color:#fff;

        text-shadow:
            0 0 18px
            rgba(255,255,255,.35);
    }

    50%{
        color:#777;

        text-shadow:
            0 0 3px
            rgba(255,255,255,.05);
    }

    100%{
        color:#fff;

        text-shadow:
            0 0 18px
            rgba(255,255,255,.35);
    }
}

/* =====================================================
   SUBTITLE
===================================================== */

.subtitle{

    margin-top:20px;

    color:#aaa;

    font-size:14px;

    letter-spacing:
        5px;

    text-transform:
        uppercase;

    animation:
        subtitlePulse
        3s
        ease-in-out
        infinite;
}

@keyframes subtitlePulse{

    0%{
        opacity:.45;
    }

    50%{
        opacity:1;
    }

    100%{
        opacity:.45;
    }
}

/* =====================================================
   BLOCK MESSAGE
===================================================== */

.block{

    margin-top:25px;

    display:inline-block;

    padding:
        9px 18px;

    border:
        1px solid
        rgba(255,255,255,.16);

    border-radius:999px;

    background:
        rgba(0,0,0,.22);

    color:#888;

    font-size:12px;

    letter-spacing:3px;
}

/* =====================================================
   SCANLINE
===================================================== */

.scan{

    position:absolute;

    left:0;
    right:0;

    height:1px;

    background:
        rgba(255,255,255,.05);

    box-shadow:
        0 0 10px
        rgba(255,255,255,.05);

    animation:
        scan
        6s
        linear
        infinite;
}

@keyframes scan{

    from{
        top:-5%;
    }

    to{
        top:105%;
    }
}

/* =====================================================
   MOBILE
===================================================== */

@media(max-width:600px){

    .center{
        padding:35px 15px;
    }

    .logo{
        letter-spacing:4px;
    }

    .subtitle{
        letter-spacing:3px;
    }
}
</style>
</head>

<body>

<div class="scene">

    <div class="stars" id="stars"></div>

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

<script>

const container =
    document.getElementById(
        "stars"
    );

const count = 180;

for(
    let i = 0;
    i < count;
    i++
){

    const star =
        document.createElement(
            "span"
        );

    star.className =
        "star";

    star.style.left =
        Math.random() * 100 +
        "%";

    star.style.top =
        Math.random() * 100 +
        "%";

    const size =
        Math.random() * 2 + 1;

    star.style.width =
        size + "px";

    star.style.height =
        size + "px";

    star.style.setProperty(
        "--duration",
        (2 + Math.random() * 5) +
        "s"
    );

    star.style.animationDelay =
        (-Math.random() * 5) +
        "s";

    container.appendChild(
        star
    );
}

</script>

</body>
</html>
`;
}
        }

        const username =
            getCurrentUser(req);

        if (
            !username ||
            username !== key
        ) {
            return res.redirect("/");
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

        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error:
                    "Script source cannot be empty."
            });
        }

        const db = readDB();

        const account =
            db[req.username];

        if (!account) {
            return res.status(401).json({
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
            createdAt: Date.now(),
            updatedAt: Date.now()
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
   LIST USER SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.username];

        if (!account) {
            return res.status(401).json({
                ok: false,
                error:
                    "Account not found."
            });
        }

        const scripts =
            Object.values(
                account.scripts || {}
            );

        res.json({
            ok: true,

            scripts:
                scripts.map(script => {

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
                })
        });
    }
);

/* =========================================================
   GET SCRIPT FOR EDITING
========================================================= */

app.get(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.username];

        const script =
            account?.scripts?.[
                req.params.id
            ];

        if (!script) {
            return res.status(404).json({
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

        const db = readDB();

        const account =
            db[req.username];

        const script =
            account?.scripts?.[
                req.params.id
            ];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found."
            });
        }

        if (
            req.body?.name !== undefined
        ) {
            script.name =
                String(
                    req.body.name
                )
                .trim()
                .slice(0, 80);
        }

        if (
            req.body?.source !== undefined
        ) {
            const source =
                String(
                    req.body.source
                );

            if (!source.trim()) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Script source cannot be empty."
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

        const db = readDB();

        const account =
            db[req.username];

        if (
            !account?.scripts?.[
                req.params.id
            ]
        ) {
            return res.status(404).json({
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
   LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const accept =
            String(
                req.headers.accept || ""
            ).toLowerCase();

        const destination =
            String(
                req.headers[
                    "sec-fetch-dest"
                ] || ""
            ).toLowerCase();

        /*
         * Normal browser navigation is blocked.
         */

        if (
            accept.includes("text/html") ||
            destination === "document"
        ) {
            return res
                .status(403)
                .type("text/plain")
                .send("LEXINX BLOCK");
        }

        /*
         * Find script.
         */

        const db = readDB();

        let script = null;

        for (
            const username
            of Object.keys(db)
        ) {

            const account =
                db[username];

            if (
                account.scripts &&
                account.scripts[
                    req.params.id
                ]
            ) {
                script =
                    account.scripts[
                        req.params.id
                    ];

                break;
            }
        }

        if (!script) {
            return res
                .status(404)
                .type("text/plain")
                .send("LEXINX BLOCK");
        }

        /*
         * L1 loader.
         *
         * The actual source is not included
         * in this response.
         */

        const runtime =
            BASE_URL +
            "/api/runtime/" +
            script.id;

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

if not ok or type(data) ~= "table" then
    error("LEXINX BLOCK")
end

if data.ok ~= true or
   type(data.code) ~= "string" then
    error("LEXINX BLOCK")
end

local fn, err =
    loadstring(data.code)

if not fn then
    error(err or "LEXINX BLOCK")
end

local success, runtimeError =
    pcall(fn)

if not success then
    error(runtimeError)
end
`.trim();

        res
            .status(200)
            .type("text/plain")
            .set(
                "Cache-Control",
                "no-store"
            )
            .set(
                "X-Content-Type-Options",
                "nosniff"
            )
            .send(lua);
    }
);

/* =========================================================
   RUNTIME PAYLOAD
========================================================= */

app.post(
    "/api/runtime/:id",
    (req, res) => {

        const db = readDB();

        let script = null;

        for (
            const username
            of Object.keys(db)
        ) {

            const account =
                db[username];

            if (
                account.scripts &&
                account.scripts[
                    req.params.id
                ]
            ) {
                script =
                    account.scripts[
                        req.params.id
                    ];

                break;
            }
        }

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "LEXINX BLOCK"
            });
        }

        /*
         * Source is only returned here,
         * after the loader reaches runtime.
         *
         * No client-side system can make
         * delivered source completely invisible
         * to a client that executes it.
         */

        res
            .status(200)
            .set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            )
            .json({
                ok: true,
                code: script.source
            });
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        res
            .status(404)
            .type("text/plain")
            .send("LEXINX BLOCK");
    }
);

/* =========================================================
   SESSION CLEANUP
========================================================= */

setInterval(() => {

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
            sessions.delete(token);
        }
    }

}, 60 * 1000);

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
