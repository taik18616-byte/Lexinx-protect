const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://lexinx-protect.onrender.com";

app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

/* =========================================================
   PUBLIC
========================================================= */

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

/* =========================================================
   CONFIG
========================================================= */

const WEB_SESSION_TTL =
    7 * 24 * 60 * 60 * 1000;

const LOADER_SESSION_TTL =
    60 * 1000;

/* =========================================================
   STORAGE
========================================================= */

const users = new Map();
const webSessions = new Map();
const scripts = new Map();
const loaderSessions = new Map();

/* =========================================================
   HELPERS
========================================================= */

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function luaString(value) {
    return JSON.stringify(
        String(value)
    );
}

function toHex(value) {
    return Buffer
        .from(
            String(value),
            "utf8"
        )
        .toString("hex");
}

function randomLuaName() {

    const chars =
        "abcdefghijklmnopqrstuvwxyz";

    let result = "_";

    for (let i = 0; i < 10; i++) {

        result +=
            chars[
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];
    }

    return result;
}

function apiError(
    res,
    code,
    message
) {

    return res
        .status(code)
        .json({
            ok: false,
            error: message
        });
}

/* =========================================================
   COOKIE
========================================================= */

function getCookie(
    req,
    name
) {

    const header =
        req.headers.cookie || "";

    for (
        const part
        of header.split(";")
    ) {

        const item =
            part.trim();

        const index =
            item.indexOf("=");

        if (index === -1)
            continue;

        const key =
            item.slice(
                0,
                index
            );

        const value =
            item.slice(
                index + 1
            );

        if (key === name) {

            return decodeURIComponent(
                value
            );
        }
    }

    return null;
}

/* =========================================================
   WEB SESSION
========================================================= */

function createWebSession(
    username
) {

    const id =
        randomHex(32);

    webSessions.set(
        id,
        {
            username,
            created:
                Date.now(),
            expires:
                Date.now() +
                WEB_SESSION_TTL
        }
    );

    return id;
}

function getWebAuth(req) {

    const sid =
        getCookie(
            req,
            "lexinx_session"
        );

    if (!sid)
        return null;

    const session =
        webSessions.get(sid);

    if (!session)
        return null;

    if (
        Date.now() >
        session.expires
    ) {

        webSessions.delete(sid);

        return null;
    }

    const user =
        users.get(
            session.username
        );

    if (!user)
        return null;

    return {
        sid,
        username:
            session.username,
        user
    };
}

function requireAuth(
    req,
    res,
    next
) {

    const auth =
        getWebAuth(req);

    if (!auth) {

        return apiError(
            res,
            401,
            "Authentication required."
        );
    }

    req.auth = auth;

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

            return apiError(
                res,
                400,
                "Username is required."
            );
        }

        if (
            username.length < 3
        ) {

            return apiError(
                res,
                400,
                "Username must contain at least 3 characters."
            );
        }

        if (
            username.length > 32
        ) {

            return apiError(
                res,
                400,
                "Username is too long."
            );
        }

        if (
            !/^[a-zA-Z0-9_]+$/
                .test(username)
        ) {

            return apiError(
                res,
                400,
                "Username may only contain letters, numbers and underscore."
            );
        }

        if (
            password.length < 6
        ) {

            return apiError(
                res,
                400,
                "Password must contain at least 6 characters."
            );
        }

        const key =
            username.toLowerCase();

        if (
            users.has(key)
        ) {

            return apiError(
                res,
                409,
                "Username already exists."
            );
        }

        users.set(
            key,
            {
                username,
                password:
                    hashPassword(
                        password
                    ),
                created:
                    Date.now()
            }
        );

        const sid =
            createWebSession(key);

        res.cookie(
            "lexinx_session",
            sid,
            {
                httpOnly: true,
                sameSite: "lax",
                secure: true,
                maxAge:
                    WEB_SESSION_TTL,
                path: "/"
            }
        );

        return res.json({
            ok: true,
            username,
            url:
                PUBLIC_URL + "/"
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

        const key =
            username.toLowerCase();

        const user =
            users.get(key);

        if (!user) {

            return apiError(
                res,
                401,
                "Invalid username or password."
            );
        }

        if (
            user.password !==
            hashPassword(password)
        ) {

            return apiError(
                res,
                401,
                "Invalid username or password."
            );
        }

        const sid =
            createWebSession(key);

        res.cookie(
            "lexinx_session",
            sid,
            {
                httpOnly: true,
                sameSite: "lax",
                secure: true,
                maxAge:
                    WEB_SESSION_TTL,
                path: "/"
            }
        );

        return res.json({
            ok: true,
            username:
                user.username,
            url:
                PUBLIC_URL + "/"
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
            getWebAuth(req);

        if (!auth) {

            return apiError(
                res,
                401,
                "Not authenticated."
            );
        }

        return res.json({
            ok: true,
            username:
                auth.username,
            url:
                PUBLIC_URL + "/"
        });
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    (req, res) => {

        const sid =
            getCookie(
                req,
                "lexinx_session"
            );

        if (sid) {
            webSessions.delete(sid);
        }

        res.clearCookie(
            "lexinx_session",
            {
                path: "/"
            }
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
            )
            .trim()
            .slice(0, 100);

        const source =
            String(
                req.body.source ||
                ""
            );

        if (!source.trim()) {

            return apiError(
                res,
                400,
                "Script source cannot be empty."
            );
        }

        if (
            Buffer.byteLength(
                source,
                "utf8"
            ) >
            1024 * 1024
        ) {

            return apiError(
                res,
                400,
                "Script is too large."
            );
        }

        let id;

        do {
            id =
                randomHex(12);
        } while (
            scripts.has(id)
        );

        scripts.set(
            id,
            {
                id,
                name:
                    name ||
                    "Untitled Script",
                source,
                owner:
                    req.auth.username,
                created:
                    Date.now(),
                updated:
                    Date.now()
            }
        );

        const loader =
            `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${id}"))()`;

        return res.json({
            ok: true,
            id,
            loader
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

        const result = [];

        for (
            const script
            of scripts.values()
        ) {

            if (
                script.owner !==
                req.auth.username
            ) {
                continue;
            }

            result.push({
                id:
                    script.id,

                name:
                    script.name,

                loader:
                    `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${script.id}"))()`,

                created:
                    script.created,

                updated:
                    script.updated
            });
        }

        result.sort(
            (a, b) =>
                b.created -
                a.created
        );

        return res.json({
            ok: true,
            scripts: result
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

        const script =
            scripts.get(
                req.params.id
            );

        if (!script) {

            return apiError(
                res,
                404,
                "Script not found."
            );
        }

        if (
            script.owner !==
            req.auth.username
        ) {

            return apiError(
                res,
                403,
                "Access denied."
            );
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

        const script =
            scripts.get(
                req.params.id
            );

        if (!script) {

            return apiError(
                res,
                404,
                "Script not found."
            );
        }

        if (
            script.owner !==
            req.auth.username
        ) {

            return apiError(
                res,
                403,
                "Access denied."
            );
        }

        if (
            typeof req.body.name ===
            "string"
        ) {

            script.name =
                req.body.name
                    .trim()
                    .slice(0, 100)
                    ||
                    "Untitled Script";
        }

        if (
            typeof req.body.source ===
            "string"
        ) {

            if (
                !req.body.source.trim()
            ) {

                return apiError(
                    res,
                    400,
                    "Script source cannot be empty."
                );
            }

            script.source =
                req.body.source;
        }

        script.updated =
            Date.now();

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

        const script =
            scripts.get(
                req.params.id
            );

        if (!script) {

            return apiError(
                res,
                404,
                "Script not found."
            );
        }

        if (
            script.owner !==
            req.auth.username
        ) {

            return apiError(
                res,
                403,
                "Access denied."
            );
        }

        scripts.delete(
            req.params.id
        );

        return res.json({
            ok: true
        });
    }
);

/* =========================================================
   LOADER SESSION
========================================================= */

function createLoaderSession(
    scriptId
) {

    const id =
        randomHex(32);

    const session = {

        id,

        scriptId,

        stage: 0,

        tokens:
            new Set(),

        created:
            Date.now(),

        expires:
            Date.now() +
            LOADER_SESSION_TTL
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

    if (!token)
        return false;

    if (
        !session.tokens.has(token)
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

    if (!session)
        return false;

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
   PROTECT PAGE
========================================================= */

function blockPage(res) {

    return res
        .status(403)
        .type("html")
        .send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>LEXINX PROTECT</title>

<style>

html,body{
    margin:0;
    width:100%;
    height:100%;
    background:#050505;
    color:#eee;
    font-family:Arial,sans-serif;
}

body{
    display:flex;
    align-items:center;
    justify-content:center;
}

.box{
    width:min(520px,88%);
    padding:55px 30px;
    text-align:center;
    background:#111;
    border:1px solid #292929;
    border-radius:18px;
    box-shadow:
        0 0 60px
        rgba(255,255,255,.04);
}

.logo{
    font-size:42px;
    font-weight:900;
    letter-spacing:8px;
}

.sub{
    margin-top:16px;
    color:#777;
    font-size:13px;
    letter-spacing:4px;
}

</style>
</head>

<body>

<div class="box">

<div class="logo">
LEXINX
</div>

<div class="sub">
PROTECT
</div>

<div class="sub">
ANTI-SKID
</div>

</div>

</body>
</html>`);
}

/* =========================================================
   HEX DECODER LUA
========================================================= */

function luaHexDecoder() {

    return `
local function decodeHex(s)

    local out = {}

    for i = 1, #s, 2 do

        local n =
            tonumber(
                s:sub(i, i + 1),
                16
            )

        if n then
            out[#out + 1] =
                string.char(n)
        end

    end

    return table.concat(out)

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

    const encoded =
        Buffer
            .from(
                source,
                "utf8"
            )
            .toString("base64");

    const data =
        randomLuaName();

    const decode =
        randomLuaName();

    const execute =
        randomLuaName();

    return `

-- LEXINX L5
-- FINAL RUNTIME

local ${data} =
    ${luaString(encoded)}

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

    local bits = {}

    for i = 1, #input do

        local c =
            input:sub(i, i)

        if c ~= "=" then

            local p =
                alphabet:find(
                    c,
                    1,
                    true
                )

            if p then

                p = p - 1

                for j = 6, 1, -1 do

                    if
                        p % 2^j >=
                        2^(j - 1)
                    then
                        bits[#bits + 1] =
                            "1"
                    else
                        bits[#bits + 1] =
                            "0"
                    end

                end

            end

        end

    end

    local output = {}

    for i = 1,
        #bits - 7,
        8 do

        local byte = 0

        for j = 0, 7 do

            if bits[i + j] ==
                "1"
            then

                byte =
                    byte +
                    2^(7 - j)

            end

        end

        output[#output + 1] =
            string.char(byte)

    end

    return table.concat(
        output
    )

end

local function ${execute}()

    local source =
        ${decode}(
            ${data}
        )

    local fn =
        loadstring(source)

    if fn then
        return fn()
    end

end

return ${execute}()

`;
}

/* =========================================================
   L4
========================================================= */

function buildL4(
    session
) {

    const token =
        issueToken(
            session
        );

    const endpoint =
        toHex(
            PUBLIC_URL
        );

    const h =
        randomLuaName();

    const decode =
        randomLuaName();

    const runtime =
        randomLuaName();

    const bootstrap =
        randomLuaName();

    return `

-- LEXINX L4
-- RUNTIME BOOTSTRAP

local ${h} =
    "${endpoint}"

${luaHexDecoder()}

local ${runtime} = {

    endpoint =
        decodeHex(${h}),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)},

    stage = 4

}

local function ${bootstrap}(state)

    local url =
        state.endpoint
        .. "/api/l5/final"
        .. "?session="
        .. state.session
        .. "&token="
        .. state.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return ${bootstrap}(
    ${runtime}
)

`;
}

/* =========================================================
   L3
========================================================= */

function buildL3(
    session
) {

    const token =
        issueToken(
            session
        );

    const endpoint =
        toHex(
            PUBLIC_URL
        );

    const h =
        randomLuaName();

    const prototype =
        randomLuaName();

    const execute =
        randomLuaName();

    return `

-- LEXINX L3
-- PACKED PROTOTYPE

local ${h} =
    "${endpoint}"

${luaHexDecoder()}

local ${prototype} = {

    opcode = {

        LOAD = 1,
        REQUEST = 2,
        EXEC = 3

    },

    endpoint =
        decodeHex(${h}),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)}

}

local function ${execute}(p)

    local url =
        p.endpoint
        .. "/api/l5"
        .. "?session="
        .. p.session
        .. "&token="
        .. p.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return ${execute}(
    ${prototype}
)

`;
}

/* =========================================================
   L2
========================================================= */

function buildL2(
    session
) {

    const token =
        issueToken(
            session
        );

    const endpoint =
        toHex(
            PUBLIC_URL
        );

    const h =
        randomLuaName();

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    return `

-- LEXINX L2

local ${h} =
    "${endpoint}"

${luaHexDecoder()}

local ${data} = {

    endpoint =
        decodeHex(${h}),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)}

}

local function ${run}(p)

    local url =
        p.endpoint
        .. "/api/l4"
        .. "?session="
        .. p.session
        .. "&token="
        .. p.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return ${run}(
    ${data}
)

`;
}

/* =========================================================
   WRAPPER VM
========================================================= */

function buildWrapper(
    session
) {

    const token =
        issueToken(
            session
        );

    const endpoint =
        toHex(
            PUBLIC_URL
        );

    const h =
        randomLuaName();

    const vm =
        randomLuaName();

    const run =
        randomLuaName();

    return `

-- LEXINX LOADER WRAPPER
-- VM BOOTSTRAP

local ${h} =
    "${endpoint}"

${luaHexDecoder()}

local ${vm} = {

    endpoint =
        decodeHex(${h}),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)},

    stage = 0

}

local function ${run}(state)

    if not state then
        return
    end

    local url =
        state.endpoint
        .. "/api/l3"
        .. "?session="
        .. state.session
        .. "&token="
        .. state.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    if type(response) ~= "string" then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return ${run}(
    ${vm}
)

`;
}

/* =========================================================
   LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const script =
            scripts.get(
                req.params.id
            );

        if (!script) {
            return blockPage(res);
        }

        /*
         * Browser -> PROTECT PAGE
         * Roblox/executor -> loader wrapper
         */

        const ua =
            String(
                req.headers[
                    "user-agent"
                ] || ""
            ).toLowerCase();

        const isBrowser =
            ua.includes("mozilla") &&
            !ua.includes("roblox");

        if (isBrowser) {
            return blockPage(res);
        }

        const session =
            createLoaderSession(
                script.id
            );

        return res
            .type("text/plain")
            .send(
                buildWrapper(
                    session
                )
            );
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

        if (
            !validLoaderSession(
                session
            )
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            session.stage !== 0
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        session.stage = 1;

        return res
            .type("text/plain")
            .send(
                buildL2(
                    session
                )
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

        if (
            !validLoaderSession(
                session
            )
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            session.stage !== 1
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        session.stage = 2;

        return res
            .type("text/plain")
            .send(
                buildL3(
                    session
                )
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

        if (
            !validLoaderSession(
                session
            )
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            session.stage !== 2
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        session.stage = 3;

        return res
            .type("text/plain")
            .send(
                buildL4(
                    session
                )
            );
    }
);

/* =========================================================
   FINAL
========================================================= */

app.get(
    "/api/l5/final",
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

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            session.stage !== 4
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const script =
            scripts.get(
                session.scriptId
            );

        if (!script) {

            loaderSessions.delete(
                session.id
            );

            return apiError(
                res,
                404,
                "Script not found."
            );
        }

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
   API 404
========================================================= */

app.use(
    "/api",
    (req, res) => {

        return apiError(
            res,
            404,
            "API ROUTE NOT FOUND"
        );
    }
);

/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        return res
            .status(404)
            .send(
                "Page not found."
            );
    }
);

/* =========================================================
   CLEANUP
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

        for (
            const [
                id,
                session
            ]
            of webSessions
        ) {

            if (
                now >
                session.expires
            ) {

                webSessions.delete(
                    id
                );
            }
        }

    },
    30 * 1000
);

/* =========================================================
   SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            "LEXINX server running on port " +
            PORT
        );

        console.log(
            "PUBLIC_URL: " +
            PUBLIC_URL
        );

    }
);
