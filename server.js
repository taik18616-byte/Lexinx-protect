const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const BASE_URL = "https://lexinx-protect.onrender.com";

const AUTH_TTL = 7 * 24 * 60 * 60 * 1000;
const LOADER_TTL = 60 * 1000;

/* =========================================================
   PATHS
========================================================= */

const PUBLIC_DIR =
    path.join(__dirname, "public");

const DATA_DIR =
    path.join(__dirname, "data");

const USERS_FILE =
    path.join(DATA_DIR, "users.json");

const SCRIPTS_FILE =
    path.join(DATA_DIR, "scripts.json");

/* =========================================================
   INIT
========================================================= */

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });
}

function ensureJSON(file, value) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(
            file,
            JSON.stringify(
                value,
                null,
                2
            ),
            "utf8"
        );
    }
}

ensureJSON(USERS_FILE, []);
ensureJSON(SCRIPTS_FILE, []);

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "2mb"
    })
);

app.use(
    express.static(PUBLIC_DIR)
);

/* =========================================================
   JSON STORAGE
========================================================= */

function readJSON(file) {
    try {
        const raw =
            fs.readFileSync(
                file,
                "utf8"
            );

        if (!raw.trim()) {
            return [];
        }

        return JSON.parse(raw);

    } catch (err) {

        console.error(
            "READ ERROR:",
            err.message
        );

        return [];
    }
}

function writeJSON(
    file,
    data
) {
    fs.writeFileSync(
        file,
        JSON.stringify(
            data,
            null,
            2
        ),
        "utf8"
    );
}

function getUsers() {
    return readJSON(
        USERS_FILE
    );
}

function saveUsers(users) {
    writeJSON(
        USERS_FILE,
        users
    );
}

function getScripts() {
    return readJSON(
        SCRIPTS_FILE
    );
}

function saveScripts(scripts) {
    writeJSON(
        SCRIPTS_FILE,
        scripts
    );
}

/* =========================================================
   RANDOM
========================================================= */

function randomHex(
    bytes = 32
) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function randomID() {
    return randomHex(12);
}

function randomLuaName() {

    const chars =
        "abcdefghijklmnopqrstuvwxyz";

    let out = "_";

    for (
        let i = 0;
        i < 9;
        i++
    ) {

        out +=
            chars[
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];
    }

    return out;
}

function luaString(value) {
    return JSON.stringify(
        String(value)
    );
}

/* =========================================================
   PASSWORD
========================================================= */

function hashPassword(
    password
) {

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
    stored
) {

    try {

        const salt =
            Buffer.from(
                stored.salt,
                "hex"
            );

        const expected =
            Buffer.from(
                stored.hash,
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

    const header =
        req.headers.cookie;

    if (!header) {
        return {};
    }

    const result = {};

    for (
        const part
        of header.split(";")
    ) {

        const index =
            part.indexOf("=");

        if (index < 0) {
            continue;
        }

        const key =
            part
                .slice(0, index)
                .trim();

        const value =
            part
                .slice(index + 1)
                .trim();

        result[key] =
            decodeURIComponent(
                value
            );
    }

    return result;
}

function setCookie(
    res,
    name,
    value,
    maxAge
) {

    res.setHeader(
        "Set-Cookie",
        [
            `${name}=${encodeURIComponent(value)}`,
            "Path=/",
            `Max-Age=${Math.floor(maxAge / 1000)}`,
            "HttpOnly",
            "SameSite=Lax"
        ].join("; ")
    );
}

function clearCookie(
    res,
    name
) {

    res.setHeader(
        "Set-Cookie",
        `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`
    );
}

/* =========================================================
   AUTH SESSIONS
========================================================= */

const authSessions =
    new Map();

function createAuthSession(
    userId
) {

    const token =
        randomHex(32);

    authSessions.set(
        token,
        {
            userId,
            created:
                Date.now(),
            expires:
                Date.now() +
                AUTH_TTL
        }
    );

    return token;
}

function getAuth(req) {

    const cookies =
        parseCookies(req);

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

    if (
        Date.now() >
        session.expires
    ) {

        authSessions.delete(
            token
        );

        return null;
    }

    const users =
        getUsers();

    const user =
        users.find(
            x =>
                x.id ===
                session.userId
        );

    if (!user) {

        authSessions.delete(
            token
        );

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
        getAuth(req);

    if (!auth) {

        return res.status(401).json({
            ok: false,
            error:
                "Not authenticated"
        });
    }

    req.user =
        auth.user;

    req.auth =
        auth;

    next();
}

/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/register",
    (req, res) => {

        const username =
            String(
                req.body.username ||
                ""
            ).trim();

        const password =
            String(
                req.body.password ||
                ""
            );

        if (!username) {

            return res.status(400).json({
                ok: false,
                error:
                    "Username is required"
            });
        }

        if (
            !/^[A-Za-z0-9_]{3,32}$/
                .test(username)
        ) {

            return res.status(400).json({
                ok: false,
                error:
                    "Username must be 3-32 characters and use only letters, numbers or underscore"
            });
        }

        if (
            password.length < 6
        ) {

            return res.status(400).json({
                ok: false,
                error:
                    "Password must contain at least 6 characters"
            });
        }

        const users =
            getUsers();

        const exists =
            users.some(
                user =>
                    user.username
                        .toLowerCase() ===
                    username.toLowerCase()
            );

        if (exists) {

            return res.status(409).json({
                ok: false,
                error:
                    "Username already exists"
            });
        }

        const user = {
            id:
                randomID(),

            username,

            password:
                hashPassword(
                    password
                ),

            createdAt:
                Date.now()
        };

        users.push(user);

        saveUsers(users);

        const session =
            createAuthSession(
                user.id
            );

        setCookie(
            res,
            "lexinx_session",
            session,
            AUTH_TTL
        );

        return res.json({
            ok: true,

            username:
                user.username,

            url:
                BASE_URL
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
            String(
                req.body.username ||
                ""
            ).trim();

        const password =
            String(
                req.body.password ||
                ""
            );

        if (
            !username ||
            !password
        ) {

            return res.status(400).json({
                ok: false,
                error:
                    "Username and password are required"
            });
        }

        const users =
            getUsers();

        const user =
            users.find(
                x =>
                    x.username
                        .toLowerCase() ===
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
            createAuthSession(
                user.id
            );

        setCookie(
            res,
            "lexinx_session",
            session,
            AUTH_TTL
        );

        return res.json({
            ok: true,

            username:
                user.username,

            url:
                BASE_URL
        });
    }
);

/* =========================================================
   ME
========================================================= */

app.get(
    "/api/me",
    (req, res) => {

        const auth =
            getAuth(req);

        if (!auth) {

            return res.status(401).json({
                ok: false,
                error:
                    "Not authenticated"
            });
        }

        return res.json({
            ok: true,

            username:
                auth.user.username,

            url:
                BASE_URL
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

            authSessions.delete(
                cookies.lexinx_session
            );
        }

        clearCookie(
            res,
            "lexinx_session"
        );

        return res.json({
            ok: true
        });
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
                req.body.name ||
                "Untitled Script"
            ).trim();

        const source =
            String(
                req.body.source ||
                ""
            );

        if (!source.trim()) {

            return res.status(400).json({
                ok: false,
                error:
                    "Script source cannot be empty"
            });
        }

        if (
            source.length >
            2 * 1024 * 1024
        ) {

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

        scripts.push({
            id,

            ownerId:
                req.user.id,

            name:
                name ||
                "Untitled Script",

            source,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()
        });

        saveScripts(
            scripts
        );

        return res.json({

            ok: true,

            id,

            loader:
                `loadstring(game:HttpGet("${BASE_URL}/api/loader/${id}"))()`
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
            getScripts()
                .filter(
                    x =>
                        x.ownerId ===
                        req.user.id
                )
                .map(
                    x => ({
                        id:
                            x.id,

                        name:
                            x.name,

                        loader:
                            `loadstring(game:HttpGet("${BASE_URL}/api/loader/${x.id}"))()`,

                        createdAt:
                            x.createdAt,

                        updatedAt:
                            x.updatedAt
                    })
                );

        return res.json({
            ok: true,
            scripts
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

        const scripts =
            getScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id &&
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
                id:
                    script.id,

                name:
                    script.name,

                source:
                    script.source
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

        const scripts =
            getScripts();

        const index =
            scripts.findIndex(
                x =>
                    x.id ===
                    req.params.id &&
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
                req.body.source ||
                ""
            );

        if (!source.trim()) {

            return res.status(400).json({
                ok: false,
                error:
                    "Script source cannot be empty"
            });
        }

        scripts[index].name =
            name ||
            "Untitled Script";

        scripts[index].source =
            source;

        scripts[index].updatedAt =
            Date.now();

        saveScripts(
            scripts
        );

        return res.json({
            ok: true
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

        const scripts =
            getScripts();

        const index =
            scripts.findIndex(
                x =>
                    x.id ===
                    req.params.id &&
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

        scripts.splice(
            index,
            1
        );

        saveScripts(
            scripts
        );

        return res.json({
            ok: true
        });
    }
);

/* =========================================================
   LOADER SESSION
========================================================= */

const loaderSessions =
    new Map();

function createLoaderSession(
    scriptId
) {

    const id =
        randomHex(32);

    const session = {

        id,

        scriptId,

        stage: 1,

        tokens:
            new Set(),

        expires:
            Date.now() +
            LOADER_TTL
    };

    loaderSessions.set(
        id,
        session
    );

    return session;
}

function issueToken(
    session
) {

    const token =
        randomHex(32);

    session.tokens.add(
        token
    );

    return token;
}

function consumeToken(
    session,
    token
) {

    if (!token) {
        return false;
    }

    if (
        !session.tokens.has(
            token
        )
    ) {
        return false;
    }

    session.tokens.delete(
        token
    );

    return true;
}

function validLoaderSession(
    session
) {

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
   BROWSER DETECTION
========================================================= */

function isBrowserRequest(
    req
) {

    const ua =
        String(
            req.headers[
                "user-agent"
            ] || ""
        ).toLowerCase();

    const accept =
        String(
            req.headers.accept ||
            ""
        ).toLowerCase();

    const browserUA =
        ua.includes("mozilla") ||
        ua.includes("chrome") ||
        ua.includes("firefox") ||
        ua.includes("safari") ||
        ua.includes("edg") ||
        ua.includes("opera");

    const wantsHTML =
        accept.includes(
            "text/html"
        );

    return (
        browserUA &&
        wantsHTML
    );
}

/* =========================================================
   PROTECT PAGE
========================================================= */

function protectPage(
    res
) {

    return res
        .status(403)
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

*{
    box-sizing:border-box;
}

html,
body{
    margin:0;
    width:100%;
    height:100%;
}

body{
    display:flex;
    align-items:center;
    justify-content:center;

    background:#050505;
    color:#eee;

    font-family:
        Arial,
        sans-serif;
}

.box{
    width:min(
        520px,
        90%
    );

    padding:55px 30px;

    text-align:center;

    background:#101010;

    border:
        1px solid #292929;

    border-radius:18px;

    box-shadow:
        0 0 80px
        rgba(255,255,255,.04);
}

.logo{
    font-size:42px;
    font-weight:900;
    letter-spacing:8px;
}

.protect{
    margin-top:16px;
    color:#777;
    font-size:12px;
    letter-spacing:5px;
}

.line{
    height:1px;
    background:#292929;
    margin:28px 0;
}

.access{
    color:#777;
    font-size:11px;
    letter-spacing:3px;
}

.info{
    margin-top:14px;
    color:#444;
    font-size:11px;
    line-height:1.7;
}

</style>

</head>

<body>

<div class="box">

    <div class="logo">
        LEXINX
    </div>

    <div class="protect">
        PROTECT
    </div>

    <div class="line"></div>

    <div class="access">
        ACCESS DENIED
    </div>

    <div class="info">
        Protected loader endpoint.
        <br>
        Direct browser access is disabled.
    </div>

</div>

</body>

</html>
`);
}

/* =========================================================
   LOADER ERROR
========================================================= */

function loaderBlock(
    res
) {

    return res
        .status(403)
        .type("text/plain")
        .send(
            "LEXINX PROTECT"
        );
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

    const token =
        issueToken(
            session
        );

    return `
-- LEXINX L2

local ${data} = {
    session = ${luaString(session.id)},
    token = ${luaString(token)},
    stage = 2
}

local function ${run}(x)
    return x
end

${run}(${data})

local url =
    "${BASE_URL}/api/l3"
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(token)}

local ok, response =
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

function buildL3(
    session
) {

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const token =
        issueToken(
            session
        );

    return `
-- LEXINX L3

local ${data} = {
    session = ${luaString(session.id)},
    token = ${luaString(token)},
    stage = 3
}

local function ${run}(x)
    return x
end

${run}(${data})

local url =
    "${BASE_URL}/api/prototype"
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(token)}

local ok, response =
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
   PACKED PROTOTYPE
========================================================= */

function buildPrototype(
    session
) {

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const token =
        issueToken(
            session
        );

    /*
       This stage is intentionally separate
       from L3 and L4.
    */

    return `
-- LEXINX PACKED PROTOTYPE

local ${data} = {

    version = "PROTO-1",

    session = ${luaString(session.id)},

    token = ${luaString(token)},

    constants = {
        1,
        2,
        3,
        4
    },

    strings = {
        "LEXINX",
        "PROTECTED",
        "RUNTIME",
        "BOOTSTRAP"
    }
}

local function ${run}(prototype)

    local checksum = 0

    for _, value
    in ipairs(prototype.constants)
    do

        checksum =
            checksum +
            value

    end

    return checksum
end

${run}(${data})

local url =
    "${BASE_URL}/api/l4"
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(token)}

local ok, response =
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

function buildL4(
    session
) {

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const token =
        issueToken(
            session
        );

    return `
-- LEXINX L4

local ${data} = {

    session = ${luaString(session.id)},

    token = ${luaString(token)},

    stage = 4

}

local function ${run}(x)

    return
        x.session,
        x.token

end

${run}(${data})

local url =
    "${BASE_URL}/api/bootstrap"
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(token)}

local ok, response =
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
   RUNTIME BOOTSTRAP
========================================================= */

function buildBootstrap(
    session
) {

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const token =
        issueToken(
            session
        );

    return `
-- LEXINX RUNTIME BOOTSTRAP

local ${data} = {

    session = ${luaString(session.id)},

    token = ${luaString(token)},

    runtime = true,

    version = "RUNTIME-1"

}

local function ${run}(x)

    if not x.runtime then
        return false
    end

    return true

end

if not ${run}(${data}) then
    return
end

local url =
    "${BASE_URL}/api/l5"
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(token)}

local ok, response =
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
    source
) {

    const data =
        randomLuaName();

    const decode =
        randomLuaName();

    const payload =
        Buffer
            .from(
                source,
                "utf8"
            )
            .toString(
                "base64"
            );

    return `
-- LEXINX L5

local ${data} =
    "${payload}"

local function ${decode}(input)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    input =
        input:gsub(
            "[^" ..
            alphabet ..
            "=]",
            ""
        )

    local bits = ""

    for i = 1, #input do

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

                for j = 5, 0, -1 do

                    if
                        p %
                        (2 ^ (j + 1))
                        >=
                        (2 ^ j)
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

    for i = 1,
        #bits - 7,
        8
    do

        local byte = 0

        for j = 0, 7 do

            if
                bits:sub(
                    i + j,
                    i + j
                ) == "1"
            then

                byte =
                    byte +
                    2 ^ (7 - j)

            end

        end

        output[#output + 1] =
            string.char(byte)

    end

    return table.concat(
        output
    )

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
   L1 → L2
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        /*
         * Direct browser:
         *
         * /api/loader/:id
         *
         * => PROTECT PAGE
         */

        if (
            isBrowserRequest(req)
        ) {

            return protectPage(
                res
            );
        }

        const id =
            req.params.id;

        const scripts =
            getScripts();

        const script =
            scripts.find(
                x =>
                    x.id === id
            );

        if (!script) {

            return res.status(404)
                .type("text/plain")
                .send(
                    "Script not found"
                );
        }

        const session =
            createLoaderSession(
                id
            );

        session.stage = 2;

        return res
            .type("text/plain")
            .send(
                buildL2(session)
            );
    }
);

/* =========================================================
   L2 → L3
========================================================= */

app.get(
    "/api/l3",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return loaderBlock(res);
        }

        if (
            session.stage !== 2
        ) {

            return loaderBlock(res);
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return loaderBlock(res);
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
   L3 → PACKED PROTOTYPE
========================================================= */

app.get(
    "/api/prototype",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return loaderBlock(res);
        }

        if (
            session.stage !== 3
        ) {

            return loaderBlock(res);
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return loaderBlock(res);
        }

        session.stage = 3.5;

        return res
            .type("text/plain")
            .send(
                buildPrototype(
                    session
                )
            );
    }
);

/* =========================================================
   PACKED PROTOTYPE → L4
========================================================= */

app.get(
    "/api/l4",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return loaderBlock(res);
        }

        if (
            session.stage !== 3.5
        ) {

            return loaderBlock(res);
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return loaderBlock(res);
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
   L4 → RUNTIME BOOTSTRAP
========================================================= */

app.get(
    "/api/bootstrap",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return loaderBlock(res);
        }

        if (
            session.stage !== 4
        ) {

            return loaderBlock(res);
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return loaderBlock(res);
        }

        session.stage = 4.5;

        return res
            .type("text/plain")
            .send(
                buildBootstrap(
                    session
                )
            );
    }
);

/* =========================================================
   BOOTSTRAP → L5 → SOURCE
========================================================= */

app.get(
    "/api/l5",
    (req, res) => {

        const session =
            loaderSessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return loaderBlock(res);
        }

        if (
            session.stage !== 4.5
        ) {

            return loaderBlock(res);
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return loaderBlock(res);
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

            return res.status(404)
                .type("text/plain")
                .send(
                    "Script not found"
                );
        }

        session.stage = 5;

        const output =
            buildL5(
                script.source
            );

        /*
         * Destroy the session after
         * the final payload is delivered.
         */

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

app.get(
    "/api/test",
    (req, res) => {

        return res.json({
            ok: true,
            message:
                "LEXINX API ONLINE"
        });
    }
);

/* =========================================================
   UNKNOWN API
========================================================= */

app.use(
    "/api",
    (req, res) => {

        return res.status(404).json({
            ok: false,
            error:
                "API ROUTE NOT FOUND"
        });
    }
);

/* =========================================================
   FRONTEND
========================================================= */

app.get(
    "/",
    (req, res) => {

        return res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);

/*
 * Any non-API route can return
 * index.html for the frontend.
 */

app.use(
    (req, res) => {

        if (
            req.path.startsWith(
                "/api/"
            )
        ) {

            return res.status(404).json({
                ok: false,
                error:
                    "API ROUTE NOT FOUND"
            });
        }

        return res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);

/* =========================================================
   CLEAN AUTH SESSIONS
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

    },
    60 * 1000
);

/* =========================================================
   CLEAN LOADER SESSIONS
========================================================= */

setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [
                id,
                session
            ]
            of loaderSessions
        ) {

            if (
                now >
                session.expires
            ) {

                loaderSessions.delete(
                    id
                );
            }
        }

    },
    30 * 1000
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
            "================================"
        );

        console.log(
            "LEXINX PROTECT ONLINE"
        );

        console.log(
            `PORT: ${PORT}`
        );

        console.log(
            `BASE: ${BASE_URL}`
        );

        console.log(
            "================================"
        );
    }
);
