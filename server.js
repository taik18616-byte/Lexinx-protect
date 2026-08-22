const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");

const FILES = {
    users: path.join(DATA_DIR, "users.json"),
    scripts: path.join(DATA_DIR, "scripts.json"),
    sessions: path.join(DATA_DIR, "sessions.json"),
    keys: path.join(DATA_DIR, "keys.json")
};

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

for (const file of Object.values(FILES)) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, "{}", "utf8");
    }
}

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

/* =========================================================
   DATABASE
========================================================= */

function readJSON(file) {
    try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
        return {};
    }
}

function writeJSON(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2),
        "utf8"
    );
}

function readUsers() {
    return readJSON(FILES.users);
}

function readScripts() {
    return readJSON(FILES.scripts);
}

function readSessions() {
    return readJSON(FILES.sessions);
}

function readKeys() {
    return readJSON(FILES.keys);
}

/* =========================================================
   UTILITIES
========================================================= */

function randomID(bytes = 16) {
    return crypto.randomBytes(bytes).toString("hex");
}

function hash(value) {
    return crypto
        .createHash("sha256")
        .update(String(value))
        .digest("hex");
}

function cleanName(value) {
    return String(value || "")
        .trim()
        .replace(/[^\w.-]/g, "_")
        .slice(0, 32);
}

function now() {
    return Date.now();
}

function browserBlocked(req) {
    const ua = String(req.headers["user-agent"] || "").toLowerCase();

    /*
      Các request không có User-Agent thường đến từ
      executor/request/game HTTP client.
    */

    if (!ua) {
        return false;
    }

    const browserWords = [
        "mozilla",
        "chrome",
        "safari",
        "firefox",
        "edge",
        "opera",
        "android webview"
    ];

    return browserWords.some(x => ua.includes(x));
}

function block(res) {
    return res
        .status(403)
        .type("text/plain")
        .set("Cache-Control", "no-store")
        .send("LEXINX BLOCK");
}

function safeCompare(a, b) {
    if (
        typeof a !== "string" ||
        typeof b !== "string" ||
        a.length !== b.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        Buffer.from(a),
        Buffer.from(b)
    );
}

/* =========================================================
   SESSION
========================================================= */

const SESSION_TTL = 5 * 60 * 1000;

function createSession(userId, scriptId) {
    const sessions = readSessions();

    const session = randomID(32);
    const token = randomID(32);

    sessions[session] = {
        session,
        token,
        userId,
        scriptId,

        stage: 2,

        createdAt: now(),
        expiresAt: now() + SESSION_TTL,

        used: false
    };

    writeJSON(FILES.sessions, sessions);

    return sessions[session];
}

function getSession(session, token) {
    const sessions = readSessions();
    const data = sessions[session];

    if (!data) {
        return null;
    }

    if (!safeCompare(data.token, token)) {
        return null;
    }

    if (data.used) {
        return null;
    }

    if (data.expiresAt < now()) {
        delete sessions[session];
        writeJSON(FILES.sessions, sessions);
        return null;
    }

    return data;
}

function advanceStage(data, expectedStage, nextStage) {
    if (data.stage !== expectedStage) {
        return false;
    }

    const sessions = readSessions();

    if (!sessions[data.session]) {
        return false;
    }

    sessions[data.session].stage = nextStage;

    writeJSON(FILES.sessions, sessions);

    return true;
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(PUBLIC_DIR, "index.html")
    );
});

/* =========================================================
   ACCOUNT
========================================================= */

/*
POST /api/account/register

{
    "username": "test",
    "password": "123456"
}
*/

app.post("/api/account/register", (req, res) => {
    const username = cleanName(req.body?.username);
    const password = String(req.body?.password || "");

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

    const users = readUsers();

    const exists = Object.values(users).some(
        user =>
            user.username.toLowerCase() ===
            username.toLowerCase()
    );

    if (exists) {
        return res.status(409).json({
            ok: false,
            error: "Username already exists"
        });
    }

    const id = randomID(12);

    users[id] = {
        id,
        username,
        passwordHash: hash(password),
        createdAt: now(),
        scripts: []
    };

    writeJSON(FILES.users, users);

    res.json({
        ok: true,
        user: {
            id,
            username
        }
    });
});

/*
POST /api/account/login
*/

app.post("/api/account/login", (req, res) => {
    const username = cleanName(req.body?.username);
    const password = String(req.body?.password || "");

    const users = readUsers();

    const user = Object.values(users).find(
        item =>
            item.username.toLowerCase() ===
            username.toLowerCase()
    );

    if (!user) {
        return res.status(401).json({
            ok: false,
            error: "Invalid username or password"
        });
    }

    if (!safeCompare(user.passwordHash, hash(password))) {
        return res.status(401).json({
            ok: false,
            error: "Invalid username or password"
        });
    }

    res.json({
        ok: true,
        user: {
            id: user.id,
            username: user.username
        },

        accountURL:
            `${DOMAIN}/acc/${encodeURIComponent(user.username)}/${user.id}`
    });
});

/* =========================================================
   USER PAGE
========================================================= */

app.get("/acc/:username/:id", (req, res) => {
    const users = readUsers();
    const user = users[req.params.id];

    if (!user) {
        return res.status(404).send("Account not found");
    }

    if (
        user.username.toLowerCase() !==
        String(req.params.username).toLowerCase()
    ) {
        return res.status(404).send("Account not found");
    }

    res.sendFile(
        path.join(PUBLIC_DIR, "index.html")
    );
});

/* =========================================================
   CREATE SCRIPT
========================================================= */

/*
POST /api/scripts/create

{
    "userId": "...",
    "name": "My Script",
    "source": "print('hello')"
}
*/

app.post("/api/scripts/create", (req, res) => {
    const userId = String(req.body?.userId || "");
    const name = cleanName(req.body?.name || "Script");
    const source =
        typeof req.body?.source === "string"
            ? req.body.source
            : "";

    const users = readUsers();
    const scripts = readScripts();

    if (!users[userId]) {
        return res.status(401).json({
            ok: false,
            error: "Invalid account"
        });
    }

    if (!source.trim()) {
        return res.status(400).json({
            ok: false,
            error: "Script is empty"
        });
    }

    const id = randomID(12);

    scripts[id] = {
        id,
        name,
        owner: userId,
        source,
        createdAt: now(),
        updatedAt: now()
    };

    users[userId].scripts =
        Array.isArray(users[userId].scripts)
            ? users[userId].scripts
            : [];

    users[userId].scripts.push(id);

    writeJSON(FILES.scripts, scripts);
    writeJSON(FILES.users, users);

    res.json({
        ok: true,

        script: {
            id,
            name,
            owner: userId
        },

        loader:
            `loadstring(game:HttpGet("${DOMAIN}/api/loader/${id}"))()`
    });
});

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.post("/api/scripts/:id/edit", (req, res) => {
    const scripts = readScripts();

    const script = scripts[req.params.id];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    const source =
        typeof req.body?.source === "string"
            ? req.body.source
            : null;

    const name =
        typeof req.body?.name === "string"
            ? cleanName(req.body.name)
            : null;

    if (source !== null) {
        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error: "Script cannot be empty"
            });
        }

        script.source = source;
    }

    if (name !== null && name.length > 0) {
        script.name = name;
    }

    script.updatedAt = now();

    writeJSON(FILES.scripts, scripts);

    res.json({
        ok: true,
        script: {
            id: script.id,
            name: script.name,
            updatedAt: script.updatedAt
        }
    });
});

/* =========================================================
   LIST USER SCRIPTS
========================================================= */

app.get("/api/account/:userId/scripts", (req, res) => {
    const users = readUsers();
    const scripts = readScripts();

    const user = users[req.params.userId];

    if (!user) {
        return res.status(404).json({
            ok: false,
            error: "Account not found"
        });
    }

    const result = (user.scripts || [])
        .map(id => scripts[id])
        .filter(Boolean)
        .map(script => ({
            id: script.id,
            name: script.name,
            createdAt: script.createdAt,
            updatedAt: script.updatedAt,

            loader:
                `loadstring(game:HttpGet("${DOMAIN}/api/loader/${script.id}"))()`
        }));

    res.json({
        ok: true,
        scripts: result
    });
});

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete("/api/scripts/:id", (req, res) => {
    const scripts = readScripts();

    if (!scripts[req.params.id]) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    delete scripts[req.params.id];

    writeJSON(FILES.scripts, scripts);

    res.json({
        ok: true
    });
});

/* =========================================================
   L1
   SHORT LOADER
========================================================= */

app.get("/api/loader/:id", (req, res) => {

    if (browserBlocked(req)) {
        return block(res);
    }

    const scripts = readScripts();
    const script = scripts[req.params.id];

    if (!script) {
        return res.status(404)
            .type("text/plain")
            .send("LEXINX SCRIPT NOT FOUND");
    }

    const sessionData =
        createSession(
            script.owner,
            script.id
        );

    /*
       L1 trả code Lua nhỏ.

       Không trả source.
    */

    const lua = `
local HttpService = game:GetService("HttpService")

local BASE = ${JSON.stringify(DOMAIN)}
local SESSION = ${JSON.stringify(sessionData.session)}
local TOKEN = ${JSON.stringify(sessionData.token)}
local ID = ${JSON.stringify(script.id)}

local function request()
    local fn =
        (type(request) == "function" and request)
        or (syn and syn.request)
        or (http and http.request)

    if not fn then
        error("LEXINX: HTTP request unavailable", 0)
    end

    return fn({
        Url = BASE .. "/api/l2/" .. ID,
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json"
        },
        Body = HttpService:JSONEncode({
            session = SESSION,
            token = TOKEN
        })
    })
end

local response = request()

if not response or response.StatusCode ~= 200 then
    error("LEXINX: Stage 2 blocked", 0)
end

local data = HttpService:JSONDecode(response.Body)

if not data.ok then
    error("LEXINX: Stage 2 rejected", 0)
end

local fn = loadstring(data.code)

if not fn then
    error("LEXINX: Stage 2 compile failed", 0)
end

return fn()
`;

    res
        .status(200)
        .type("text/plain")
        .set("Cache-Control", "no-store")
        .set("X-Content-Type-Options", "nosniff")
        .send(lua);
});

/* =========================================================
   L2
========================================================= */

app.post("/api/l2/:id", (req, res) => {

    if (browserBlocked(req)) {
        return block(res);
    }

    const session =
        getSession(
            req.body?.session,
            req.body?.token
        );

    if (!session) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX BLOCK"
        });
    }

    if (session.scriptId !== req.params.id) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX BLOCK"
        });
    }

    if (!advanceStage(session, 2, 3)) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX STAGE BLOCK"
        });
    }

    const code = `
local HttpService = game:GetService("HttpService")

local BASE = ${JSON.stringify(DOMAIN)}
local SESSION = ${JSON.stringify(session.session)}
local TOKEN = ${JSON.stringify(session.token)}
local ID = ${JSON.stringify(session.scriptId)}

local function req()
    local fn =
        (type(request) == "function" and request)
        or (syn and syn.request)
        or (http and http.request)

    if not fn then
        error("LEXINX: HTTP unavailable", 0)
    end

    return fn({
        Url = BASE .. "/api/l3/" .. ID,
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json"
        },
        Body = HttpService:JSONEncode({
            session = SESSION,
            token = TOKEN
        })
    })
end

local r = req()

if not r or r.StatusCode ~= 200 then
    error("LEXINX: Stage 3 blocked", 0)
end

local d = HttpService:JSONDecode(r.Body)

if not d.ok then
    error("LEXINX: Stage 3 rejected", 0)
end

local f = loadstring(d.code)

if not f then
    error("LEXINX: Stage 3 compile failed", 0)
end

return f()
`;

    res.json({
        ok: true,
        stage: 3,
        code
    });
});

/* =========================================================
   L3
========================================================= */

app.post("/api/l3/:id", (req, res) => {

    if (browserBlocked(req)) {
        return block(res);
    }

    const session =
        getSession(
            req.body?.session,
            req.body?.token
        );

    if (!session) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX BLOCK"
        });
    }

    if (
        session.scriptId !== req.params.id ||
        session.stage !== 3
    ) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX STAGE BLOCK"
        });
    }

    if (!advanceStage(session, 3, 4)) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX STAGE BLOCK"
        });
    }

    const code = `
local HttpService = game:GetService("HttpService")

local BASE = ${JSON.stringify(DOMAIN)}
local SESSION = ${JSON.stringify(session.session)}
local TOKEN = ${JSON.stringify(session.token)}
local ID = ${JSON.stringify(session.scriptId)}

local function req()
    local fn =
        (type(request) == "function" and request)
        or (syn and syn.request)
        or (http and http.request)

    if not fn then
        error("LEXINX: HTTP unavailable", 0)
    end

    return fn({
        Url = BASE .. "/api/l4/" .. ID,
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json"
        },
        Body = HttpService:JSONEncode({
            session = SESSION,
            token = TOKEN
        })
    })
end

local r = req()

if not r or r.StatusCode ~= 200 then
    error("LEXINX: Stage 4 blocked", 0)
end

local d = HttpService:JSONDecode(r.Body)

if not d.ok then
    error("LEXINX: Stage 4 rejected", 0)
end

local f = loadstring(d.code)

if not f then
    error("LEXINX: Stage 4 compile failed", 0)
end

return f()
`;

    res.json({
        ok: true,
        stage: 4,
        code
    });
});

/* =========================================================
   L4
========================================================= */

app.post("/api/l4/:id", (req, res) => {

    if (browserBlocked(req)) {
        return block(res);
    }

    const session =
        getSession(
            req.body?.session,
            req.body?.token
        );

    if (!session) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX BLOCK"
        });
    }

    if (
        session.scriptId !== req.params.id ||
        session.stage !== 4
    ) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX STAGE BLOCK"
        });
    }

    if (!advanceStage(session, 4, 5)) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX STAGE BLOCK"
        });
    }

    const code = `
local HttpService = game:GetService("HttpService")

local BASE = ${JSON.stringify(DOMAIN)}
local SESSION = ${JSON.stringify(session.session)}
local TOKEN = ${JSON.stringify(session.token)}
local ID = ${JSON.stringify(session.scriptId)}

local fn =
    (type(request) == "function" and request)
    or (syn and syn.request)
    or (http and http.request)

if not fn then
    error("LEXINX: HTTP unavailable", 0)
end

local response = fn({
    Url = BASE .. "/api/l5/" .. ID,
    Method = "POST",
    Headers = {
        ["Content-Type"] = "application/json"
    },
    Body = HttpService:JSONEncode({
        session = SESSION,
        token = TOKEN
    })
})

if not response or response.StatusCode ~= 200 then
    error("LEXINX: Stage 5 blocked", 0)
end

local data = HttpService:JSONDecode(response.Body)

if not data.ok or type(data.source) ~= "string" then
    error("LEXINX: Payload unavailable", 0)
end

local execute = loadstring(data.source)

if not execute then
    error("LEXINX: Payload compile failed", 0)
end

return execute()
`;

    res.json({
        ok: true,
        stage: 5,
        code
    });
});

/* =========================================================
   L5 — SOURCE
========================================================= */

app.post("/api/l5/:id", (req, res) => {

    if (browserBlocked(req)) {
        return block(res);
    }

    const session =
        getSession(
            req.body?.session,
            req.body?.token
        );

    if (!session) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX BLOCK"
        });
    }

    if (
        session.scriptId !== req.params.id ||
        session.stage !== 5
    ) {
        return res.status(403).json({
            ok: false,
            error: "LEXINX STAGE BLOCK"
        });
    }

    const scripts = readScripts();
    const script = scripts[req.params.id];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "SCRIPT NOT FOUND"
        });
    }

    /*
       Đây là điểm DUY NHẤT trả source.
    */

    const sessions = readSessions();

    sessions[session.session].used = true;

    writeJSON(FILES.sessions, sessions);

    res
        .status(200)
        .json({
            ok: true,
            stage: 5,
            source: script.source
        });
});

/* =========================================================
   DIRECT API BLOCK
========================================================= */

app.get("/api/l2/:id", (req, res) => {
    return block(res);
});

app.get("/api/l3/:id", (req, res) => {
    return block(res);
});

app.get("/api/l4/:id", (req, res) => {
    return block(res);
});

app.get("/api/l5/:id", (req, res) => {
    return block(res);
});

/* =========================================================
   GLOBAL 404
========================================================= */

app.use((req, res) => {
    res
        .status(404)
        .type("text/plain")
        .send("LEXINX BLOCK");
});

/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

setInterval(() => {

    const sessions = readSessions();
    const current = now();

    let changed = false;

    for (const id of Object.keys(sessions)) {
        const session = sessions[id];

        if (
            session.expiresAt < current ||
            session.used === true
        ) {
            delete sessions[id];
            changed = true;
        }
    }

    if (changed) {
        writeJSON(FILES.sessions, sessions);
    }

}, 60 * 1000);

/* =========================================================
   START
========================================================= */

app.listen(PORT, () => {

    console.log(
        "======================================"
    );

    console.log(
        "LEXINX PROTECT SERVER"
    );

    console.log(
        `PORT   : ${PORT}`
    );

    console.log(
        `DOMAIN : ${DOMAIN}`
    );

    console.log(
        "FLOW   : L1 -> L2 -> L3 -> L4 -> L5"
    );

    console.log(
        "SOURCE : L5 ONLY"
    );

    console.log(
        "======================================"
    );
});
