const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================================================
   CONFIG
========================================================= */

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const TOKEN_TTL = 60 * 1000;

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const SCRIPTS_FILE = path.join(DATA_DIR, "scripts.json");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

function ensureFile(file, defaultValue) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(
            file,
            JSON.stringify(defaultValue, null, 2),
            "utf8"
        );
    }
}

ensureFile(USERS_FILE, []);
ensureFile(SCRIPTS_FILE, []);

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json({
    limit: "2mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "2mb"
}));

app.use(express.static(
    path.join(__dirname, "public")
));

/* =========================================================
   LOG
========================================================= */

app.use((req, res, next) => {
    console.log(
        `[${new Date().toISOString()}]`,
        req.method,
        req.originalUrl
    );

    next();
});

/* =========================================================
   JSON DATABASE
========================================================= */

function readJSON(file, fallback) {
    try {
        const raw = fs.readFileSync(file, "utf8");

        if (!raw.trim()) {
            return fallback;
        }

        return JSON.parse(raw);

    } catch (err) {
        console.error(
            "READ DATABASE ERROR:",
            file,
            err.message
        );

        return fallback;
    }
}

function writeJSON(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2),
        "utf8"
    );
}

function getUsers() {
    return readJSON(USERS_FILE, []);
}

function saveUsers(users) {
    writeJSON(USERS_FILE, users);
}

function getScripts() {
    return readJSON(SCRIPTS_FILE, []);
}

function saveScripts(scripts) {
    writeJSON(SCRIPTS_FILE, scripts);
}

/* =========================================================
   RANDOM
========================================================= */

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function randomID() {
    return randomHex(12);
}

/* =========================================================
   PASSWORD HASH
========================================================= */

function hashPassword(password) {
    const salt = crypto.randomBytes(16);

    const hash = crypto.scryptSync(
        password,
        salt,
        64
    );

    return {
        salt: salt.toString("hex"),
        hash: hash.toString("hex")
    };
}

function verifyPassword(password, stored) {
    try {
        const salt = Buffer.from(
            stored.salt,
            "hex"
        );

        const hash = crypto.scryptSync(
            password,
            salt,
            64
        );

        const original = Buffer.from(
            stored.hash,
            "hex"
        );

        return (
            hash.length === original.length &&
            crypto.timingSafeEqual(
                hash,
                original
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
    const header = req.headers.cookie;

    if (!header) {
        return {};
    }

    const cookies = {};

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key = part
            .slice(0, index)
            .trim();

        const value = part
            .slice(index + 1)
            .trim();

        cookies[key] =
            decodeURIComponent(value);
    }

    return cookies;
}

function setCookie(
    res,
    name,
    value,
    maxAge
) {
    const parts = [
        `${name}=${encodeURIComponent(value)}`,
        "Path=/",
        `Max-Age=${Math.floor(maxAge / 1000)}`,
        "HttpOnly",
        "SameSite=Lax"
    ];

    res.setHeader(
        "Set-Cookie",
        parts.join("; ")
    );
}

function clearCookie(res, name) {
    res.setHeader(
        "Set-Cookie",
        `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`
    );
}

/* =========================================================
   AUTH SESSIONS
========================================================= */

const authSessions = new Map();

function createAuthSession(userId) {
    const token = randomHex(32);

    authSessions.set(token, {
        userId,
        created: Date.now(),
        expires:
            Date.now() + SESSION_TTL
    });

    return token;
}

function getAuthUser(req) {
    const cookies = parseCookies(req);

    const token =
        cookies.lexinx_session;

    if (!token) {
        return null;
    }

    const session =
        authSessions.get(token);

    if (!session) {
        return null;
    }

    if (Date.now() > session.expires) {
        authSessions.delete(token);
        return null;
    }

    const users = getUsers();

    const user =
        users.find(
            x => x.id === session.userId
        );

    if (!user) {
        authSessions.delete(token);
        return null;
    }

    return {
        user,
        token,
        session
    };
}

function requireAuth(req, res, next) {
    const auth =
        getAuthUser(req);

    if (!auth) {
        return res.status(401).json({
            ok: false,
            error: "Not authenticated"
        });
    }

    req.user = auth.user;
    req.authToken = auth.token;

    next();
}

/* =========================================================
   SCRIPT LOADER
========================================================= */

function loaderURL(id) {
    return (
        "https://lexinx-protect.onrender.com" +
        "/api/loader/" +
        encodeURIComponent(id)
    );
}

/* =========================================================
   AUTH RESPONSE
========================================================= */

function accountResponse(user) {
    return {
        ok: true,
        username: user.username,
        url:
            "https://lexinx-protect.onrender.com"
    };
}

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", (req, res) => {
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
            return res.status(400).json({
                ok: false,
                error:
                    "Username is required"
            });
        }

        if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
            return res.status(400).json({
                ok: false,
                error:
                    "Username must be 3-32 characters and contain only letters, numbers, or underscore"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                ok: false,
                error:
                    "Password must contain at least 6 characters"
            });
        }

        const users = getUsers();

        const exists =
            users.some(
                user =>
                    user.username.toLowerCase() ===
                    username.toLowerCase()
            );

        if (exists) {
            return res.status(409).json({
                ok: false,
                error:
                    "Username already exists"
            });
        }

        const passwordData =
            hashPassword(password);

        const user = {
            id: randomID(),
            username,
            password: passwordData,
            createdAt: Date.now()
        };

        users.push(user);

        saveUsers(users);

        const session =
            createAuthSession(user.id);

        setCookie(
            res,
            "lexinx_session",
            session,
            SESSION_TTL
        );

        return res.json(
            accountResponse(user)
        );

    } catch (err) {
        console.error(
            "REGISTER ERROR:",
            err
        );

        return res.status(500).json({
            ok: false,
            error:
                "Internal server error"
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
                req.body.username || ""
            ).trim();

        const password =
            String(
                req.body.password || ""
            );

        if (!username || !password) {
            return res.status(400).json({
                ok: false,
                error:
                    "Username and password are required"
            });
        }

        const users = getUsers();

        const user =
            users.find(
                x =>
                    x.username.toLowerCase() ===
                    username.toLowerCase()
            );

        if (!user) {
            return res.status(401).json({
                ok: false,
                error:
                    "Invalid username or password"
            });
        }

        if (
            !verifyPassword(
                password,
                user.password
            )
        ) {
            return res.status(401).json({
                ok: false,
                error:
                    "Invalid username or password"
            });
        }

        const session =
            createAuthSession(user.id);

        setCookie(
            res,
            "lexinx_session",
            session,
            SESSION_TTL
        );

        return res.json(
            accountResponse(user)
        );

    } catch (err) {
        console.error(
            "LOGIN ERROR:",
            err
        );

        return res.status(500).json({
            ok: false,
            error:
                "Internal server error"
        });
    }
});

/* =========================================================
   ME
========================================================= */

app.get("/api/me", (req, res) => {
    const auth =
        getAuthUser(req);

    if (!auth) {
        return res.status(401).json({
            ok: false,
            error:
                "Not authenticated"
        });
    }

    return res.json(
        accountResponse(auth.user)
    );
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
        authSessions.delete(token);
    }

    clearCookie(
        res,
        "lexinx_session"
    );

    return res.json({
        ok: true,
        message:
            "Logged out successfully"
    });
});

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/create",
    requireAuth,
    (req, res) => {

        try {
            const name =
                String(
                    req.body.name ||
                    "Untitled Script"
                ).trim();

            const source =
                String(
                    req.body.source || ""
                );

            if (!source.trim()) {
                return res.status(400).json({
                    ok: false,
                    error:
                        "Script source cannot be empty"
                });
            }

            if (source.length > 2 * 1024 * 1024) {
                return res.status(413).json({
                    ok: false,
                    error:
                        "Script is too large"
                });
            }

            const scripts =
                getScripts();

            const id =
                randomID();

            const script = {
                id,
                ownerId: req.user.id,
                name:
                    name ||
                    "Untitled Script",
                source,
                createdAt: Date.now(),
                updatedAt: Date.now()
            };

            scripts.push(script);

            saveScripts(scripts);

            return res.json({
                ok: true,
                id,
                name: script.name,
                loader:
                    `loadstring(game:HttpGet("${loaderURL(id)}"))()`
            });

        } catch (err) {
            console.error(
                "CREATE SCRIPT ERROR:",
                err
            );

            return res.status(500).json({
                ok: false,
                error:
                    "Internal server error"
            });
        }
    }
);

/* =========================================================
   LIST USER SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const scripts =
            getScripts()
            .filter(
                script =>
                    script.ownerId ===
                    req.user.id
            )
            .map(script => ({
                id: script.id,
                name: script.name,
                loader:
                    `loadstring(game:HttpGet("${loaderURL(script.id)}"))()`,
                createdAt:
                    script.createdAt,
                updatedAt:
                    script.updatedAt
            }));

        return res.json({
            ok: true,
            scripts
        });
    }
);

/* =========================================================
   GET SINGLE SCRIPT
========================================================= */

app.get(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const id =
            req.params.id;

        const scripts =
            getScripts();

        const script =
            scripts.find(
                x =>
                    x.id === id &&
                    x.ownerId ===
                    req.user.id
            );

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        return res.json({
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
    }
);

/* =========================================================
   UPDATE SCRIPT
========================================================= */

app.put(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const id =
            req.params.id;

        const scripts =
            getScripts();

        const index =
            scripts.findIndex(
                x =>
                    x.id === id &&
                    x.ownerId ===
                    req.user.id
            );

        if (index === -1) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        const name =
            String(
                req.body.name ||
                "Untitled Script"
            ).trim();

        const source =
            String(
                req.body.source || ""
            );

        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error:
                    "Script source cannot be empty"
            });
        }

        if (source.length > 2 * 1024 * 1024) {
            return res.status(413).json({
                ok: false,
                error:
                    "Script is too large"
            });
        }

        scripts[index].name =
            name ||
            "Untitled Script";

        scripts[index].source =
            source;

        scripts[index].updatedAt =
            Date.now();

        saveScripts(scripts);

        return res.json({
            ok: true,
            message:
                "Script updated successfully"
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

        const id =
            req.params.id;

        const scripts =
            getScripts();

        const index =
            scripts.findIndex(
                x =>
                    x.id === id &&
                    x.ownerId ===
                    req.user.id
            );

        if (index === -1) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        scripts.splice(index, 1);

        saveScripts(scripts);

        return res.json({
            ok: true,
            message:
                "Script deleted successfully"
        });
    }
);

/* =========================================================
   LOADER SESSION
========================================================= */

const loaderSessions = new Map();

function createLoaderSession(scriptId) {
    const id = randomHex(32);

    const session = {
        id,
        scriptId,
        stage: 1,
        tokens: new Set(),
        created: Date.now(),
        expires:
            Date.now() + TOKEN_TTL
    };

    loaderSessions.set(
        id,
        session
    );

    return session;
}

function createLoaderToken(session) {
    const token =
        randomHex(32);

    session.tokens.add(token);

    return token;
}

function consumeLoaderToken(
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
        loaderSessions.delete(
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

function randomLuaName() {
    const chars =
        "abcdefghijklmnopqrstuvwxyz";

    let result = "_";

    for (let i = 0; i < 8; i++) {
        result += chars[
            crypto.randomInt(
                0,
                chars.length
            )
        ];
    }

    return result;
}

/* =========================================================
   L2
========================================================= */

function buildL2(
    session
) {
    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const nextToken =
        createLoaderToken(
            session
        );

    return `
local ${data} = {
    strings = {
        [0] = "/api/l3",
        [1] = ${luaString(nextToken)},
        [2] = ${luaString(session.id)}
    }
}

local function ${run}(p)
    return p.strings
end

${run}(${data})

local url =
    "https://lexinx-protect.onrender.com/api/l3"
    .. "?session=" .. ${luaString(session.id)}
    .. "&token=" .. ${luaString(nextToken)}

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
}

/* =========================================================
   L3
========================================================= */

function buildL3(
    session
) {
    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const nextToken =
        createLoaderToken(
            session
        );

    return `
local ${data} = {
    strings = {
        [0] = "/api/l4",
        [1] = ${luaString(session.id)},
        [2] = ${luaString(nextToken)}
    }
}

local function ${run}(p)
    return p.strings
end

${run}(${data})

local url =
    "https://lexinx-protect.onrender.com/api/l4"
    .. "?session=" .. ${luaString(session.id)}
    .. "&token=" .. ${luaString(nextToken)}

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
}

/* =========================================================
   L4
========================================================= */

function buildL4(
    session
) {
    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const nextToken =
        createLoaderToken(
            session
        );

    return `
local ${data} = {
    strings = {
        [0] = "/api/l5",
        [1] = ${luaString(session.id)},
        [2] = ${luaString(nextToken)}
    }
}

local function ${run}(p)
    return p.strings
end

${run}(${data})

local url =
    "https://lexinx-protect.onrender.com/api/l5"
    .. "?session=" .. ${luaString(session.id)}
    .. "&token=" .. ${luaString(nextToken)}

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
}

/* =========================================================
   L5
========================================================= */

function buildL5(
    session,
    source
) {
    const data =
        randomLuaName();

    const fn =
        randomLuaName();

    const payload =
        Buffer
        .from(source, "utf8")
        .toString("base64");

    return `
local ${data} = "${payload}"

local ${fn} = function(input)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    input = input:gsub(
        "[^" .. alphabet .. "=]",
        ""
    )

    local bits = ""

    for i = 1, #input do

        local c = input:sub(i, i)

        if c ~= "=" then

            local p =
                alphabet:find(
                    c,
                    1,
                    true
                )

            if p then

                p = p - 1

                for j = 5, 0, -1 do

                    if p % (2 ^ (j + 1))
                        >= (2 ^ j)
                    then
                        bits = bits .. "1"
                    else
                        bits = bits .. "0"
                    end

                end

            end

        end

    end

    local decoded = {}

    for i = 1, #bits - 7, 8 do

        local byte = 0

        for j = 0, 7 do

            if bits:sub(
                i + j,
                i + j
            ) == "1"
            then
                byte =
                    byte +
                    2 ^ (7 - j)
            end

        end

        decoded[#decoded + 1] =
            string.char(byte)

    end

    return table.concat(decoded)
end

local source =
    ${fn}(${data})

local execute =
    loadstring(source)

if execute then
    return execute()
end
`;
}

/* =========================================================
   LOADER L1
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const id =
            req.params.id;

        const scripts =
            getScripts();

        const script =
            scripts.find(
                x => x.id === id
            );

        if (!script) {
            return res.status(404).send(
                "Script not found"
            );
        }

        const session =
            createLoaderSession(id);

        const token =
            createLoaderToken(
                session
            );

        session.stage = 2;

        const code =
            buildL2(session, token);

        res.type("text/plain");

        return res.send(code);
    }
);

/* =========================================================
   L3
========================================================= */

app.get(
    "/api/l3",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (!validLoaderSession(session)) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        if (session.stage !== 2) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        if (
            !consumeLoaderToken(
                session,
                req.query.token
            )
        ) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        session.stage = 3;

        return res
            .type("text/plain")
            .send(
                buildL3(session)
            );
    }
);

/* =========================================================
   L4
========================================================= */

app.get(
    "/api/l4",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (!validLoaderSession(session)) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        if (session.stage !== 3) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        if (
            !consumeLoaderToken(
                session,
                req.query.token
            )
        ) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        session.stage = 4;

        return res
            .type("text/plain")
            .send(
                buildL4(session)
            );
    }
);

/* =========================================================
   L5
========================================================= */

app.get(
    "/api/l5",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (!validLoaderSession(session)) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        if (session.stage !== 4) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        if (
            !consumeLoaderToken(
                session,
                req.query.token
            )
        ) {
            return res.status(403).send(
                "LEXINX BLOCK"
            );
        }

        const scripts =
            getScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    session.scriptId
            );

        if (!script) {
            loaderSessions.delete(
                session.id
            );

            return res.status(404).send(
                "Script not found"
            );
        }

        session.stage = 5;

        const output =
            buildL5(
                session,
                script.source
            );

        loaderSessions.delete(
            session.id
        );

        return res
            .type("text/plain")
            .send(output);
    }
);

/* =========================================================
   API TEST
========================================================= */

app.get("/api/test", (req, res) => {
    res.json({
        ok: true,
        message:
            "LEXINX API ONLINE"
    });
});

/* =========================================================
   API NOT FOUND
========================================================= */

app.use("/api", (req, res) => {
    return res.status(404).json({
        ok: false,
        error:
            "API ROUTE NOT FOUND"
    });
});

/* =========================================================
   FRONTEND
========================================================= */

app.get("*", (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

/* =========================================================
   EXPIRED AUTH SESSIONS
========================================================= */

setInterval(() => {

    const now =
        Date.now();

    for (
        const [token, session]
        of authSessions
    ) {

        if (
            now >
            session.expires
        ) {
            authSessions.delete(
                token
            );
        }
    }

}, 60 * 1000);

/* =========================================================
   EXPIRED LOADER SESSIONS
========================================================= */

setInterval(() => {

    const now =
        Date.now();

    for (
        const [id, session]
        of loaderSessions
    ) {

        if (
            now >
            session.expires
        ) {
            loaderSessions.delete(id);
        }
    }

}, 30 * 1000);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        return res.status(500).json({
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
    "0.0.0.0",
    () => {

        console.log(
            "================================="
        );

        console.log(
            "LEXINX SERVER ONLINE"
        );

        console.log(
            `PORT: ${PORT}`
        );

        console.log(
            "================================="
        );

    }
);
