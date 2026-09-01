const express = require("express");
const crypto = require("crypto");

const app = express();

app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;

const TOKEN_TTL = 60 * 1000;

const scripts = new Map();

scripts.set("58ceecd03f8a061d8af1d341", {
    source: `
print("LEXINX PAYLOAD RUNNING")
`
});

/* =========================================================
   SESSION STORAGE
========================================================= */

const sessions = new Map();

/* =========================================================
   RANDOM
========================================================= */

function randomHex(size = 32) {
    return crypto.randomBytes(size).toString("hex");
}

function createToken() {
    return randomHex(32);
}

function createNonce() {
    return randomHex(16);
}

/* =========================================================
   SESSION
========================================================= */

function createSession(scriptId) {
    const id = randomHex(32);

    const session = {
        id,
        scriptId,
        stage: 1,
        tokens: new Set(),
        created: Date.now(),
        expires: Date.now() + TOKEN_TTL
    };

    sessions.set(id, session);

    return session;
}

function issueToken(session) {
    const token = createToken();

    session.tokens.add(token);

    return token;
}

function consumeToken(session, token) {
    if (!token) {
        return false;
    }

    if (!session.tokens.has(token)) {
        return false;
    }

    session.tokens.delete(token);

    return true;
}

function validSession(session) {
    if (!session) {
        return false;
    }

    if (Date.now() > session.expires) {
        sessions.delete(session.id);
        return false;
    }

    return true;
}

/* =========================================================
   API BLOCK
========================================================= */

function apiBlock(res, message = "LEXINX BLOCK") {
    return res.status(403).json({
        ok: false,
        error: message
    });
}

/* =========================================================
   LUA ESCAPE
========================================================= */

function luaString(value) {
    return JSON.stringify(String(value));
}

/* =========================================================
   RANDOM LUA NAME
========================================================= */

function randomLuaName() {
    const chars = "abcdefghijklmnopqrstuvwxyz";

    let result = "_";

    for (let i = 0; i < 8; i++) {
        result += chars[
            crypto.randomInt(0, chars.length)
        ];
    }

    return result;
}

/* =========================================================
   L2
========================================================= */

function buildL2(session) {

    const vm = randomLuaName();
    const run = randomLuaName();
    const data = randomLuaName();
    const endpoint = randomLuaName();

    const nextToken = issueToken(session);

    return `
-- LEXINX L2

local ${data} = {

    strings = {

        [0] = "/api/l3",
        [1] = ${luaString(nextToken)},
        [2] = ${luaString(session.id)}

    },

    constants = {

        [0] = 2

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(p)

    local stack = {}

    for _, instruction in ipairs(p.instructions) do

        if instruction.opcode == "LOADK" then

            table.insert(
                stack,
                p.strings[instruction.arg]
            )

        end

    end

    return stack

end

local ${vm} = ${run}(${data})

local ${endpoint} =
    "https://Lexinx-protect.onrender.com/api/l3"

local ok, response = pcall(function()

    return game:HttpGet(
        ${endpoint}
        .. "?session=" .. ${luaString(session.id)}
        .. "&token=" .. ${luaString(nextToken)}
    )

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

function buildL3(session) {

    const nextToken = issueToken(session);

    const data = randomLuaName();
    const run = randomLuaName();

    return `
-- LEXINX L3

local ${data} = {

    strings = {

        [0] = "/api/l4",
        [1] = ${luaString(session.id)},
        [2] = ${luaString(nextToken)}

    },

    constants = {

        [0] = 3

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(program)

    local stack = {}

    for _, instruction in ipairs(
        program.instructions
    ) do

        if instruction.opcode == "LOADK" then

            stack[#stack + 1] =
                program.strings[instruction.arg]

        end

    end

    return stack

end

local result = ${run}(${data})

local url =
    "https://Lexinx-protect.onrender.com/api/l4"
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

function buildL4(session) {

    const nextToken = issueToken(session);

    const program = randomLuaName();
    const run = randomLuaName();

    return `
-- LEXINX L4 RUNTIME

local ${program} = {

    strings = {

        [0] = "/api/l5",
        [1] = ${luaString(session.id)},
        [2] = ${luaString(nextToken)}

    },

    constants = {

        [0] = 4

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(data)

    local stack = {}

    for _, instruction in ipairs(
        data.instructions
    ) do

        if instruction.opcode == "LOADK" then

            stack[#stack + 1] =
                data.strings[instruction.arg]

        end

    end

    return stack

end

local args = ${run}(${program})

local url =
    "https://Lexinx-protect.onrender.com/api/l5"
    .. "?session=" .. ${luaString(session.id)}
    .. "&token=" .. ${luaString(nextToken)}

local success, result = pcall(function()

    return game:HttpGet(url)

end)

if not success then
    return
end

local execute = loadstring(result)

if execute then
    return execute()
end
`;
}

/* =========================================================
   L5
========================================================= */

function buildL5(session, source) {

    const payload = Buffer
        .from(source, "utf8")
        .toString("base64");

    const fn = randomLuaName();
    const data = randomLuaName();

    return `
-- LEXINX L5 RUNTIME

local ${data} =
    "${payload}"

local ${fn} = function(input)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    local decoded = {}

    input = input:gsub(
        "[^" .. alphabet .. "=]",
        ""
    )

    local bits = ""

    for i = 1, #input do

        local c = input:sub(i,i)

        if c ~= "=" then

            local p =
                alphabet:find(c, 1, true)

            if p then

                p = p - 1

                local b = ""

                for j = 6, 1, -1 do

                    b = b ..
                        ((p % 2^j >= 2^(j-1))
                        and "1"
                        or "0")

                end

                bits = bits .. b

            end

        end

    end

    for i = 1, #bits - 7, 8 do

        local byte = 0

        for j = 0, 7 do

            if bits:sub(i+j,i+j) == "1" then
                byte = byte + 2^(7-j)
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
   ROOT
========================================================= */

app.get("/", (req, res) => {

    res.status(200).type("html").send(`
<!doctype html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>LEXINX Protect</title>

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

    background: #050505;

    color: #fff;

    font-family:
        Arial,
        sans-serif;

    display: flex;

    align-items: center;

    justify-content: center;
}

.box {

    width: min(520px, 90%);

    padding: 45px 30px;

    text-align: center;

    border: 1px solid #333;

    border-radius: 16px;

    background: #111;

    box-shadow:
        0 0 50px
        rgba(255,255,255,.04);
}

.logo {

    font-size: 38px;

    font-weight: 900;

    letter-spacing: 7px;
}

.status {

    margin-top: 15px;

    color: #777;

    font-size: 14px;

    letter-spacing: 2px;
}

.online {

    margin-top: 25px;

    color: #aaa;

    font-size: 13px;
}

</style>

</head>

<body>

<div class="box">

    <div class="logo">
        LEXINX
    </div>

    <div class="status">
        PROTECT
    </div>

    <div class="online">
        API ONLINE
    </div>

</div>

</body>

</html>
    `);

});

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", (req, res) => {

    return res.status(200).json({
        ok: true,
        status: "online",
        service: "LEXINX",
        uptime: process.uptime(),
        time: new Date().toISOString()
    });

});

/* =========================================================
   L1 LOADER
========================================================= */

app.get("/api/loader/:id", (req, res) => {

    const id = req.params.id;

    const script = scripts.get(id);

    if (!script) {
        return apiBlock(
            res,
            "SCRIPT NOT FOUND"
        );
    }

    const session =
        createSession(id);

    session.stage = 2;

    const code =
        buildL2(session);

    return res
        .status(200)
        .type("text/plain")
        .send(code);

});

/* =========================================================
   L3
========================================================= */

app.get("/api/l3", (req, res) => {

    const session =
        sessions.get(req.query.session);

    if (!validSession(session)) {

        return apiBlock(
            res,
            "INVALID SESSION"
        );

    }

    if (session.stage !== 2) {

        return apiBlock(
            res,
            "INVALID STAGE"
        );

    }

    if (
        !consumeToken(
            session,
            req.query.token
        )
    ) {

        return apiBlock(
            res,
            "INVALID TOKEN"
        );

    }

    session.stage = 3;

    return res
        .status(200)
        .type("text/plain")
        .send(
            buildL3(session)
        );

});

/* =========================================================
   L4
========================================================= */

app.get("/api/l4", (req, res) => {

    const session =
        sessions.get(req.query.session);

    if (!validSession(session)) {

        return apiBlock(
            res,
            "INVALID SESSION"
        );

    }

    if (session.stage !== 3) {

        return apiBlock(
            res,
            "INVALID STAGE"
        );

    }

    if (
        !consumeToken(
            session,
            req.query.token
        )
    ) {

        return apiBlock(
            res,
            "INVALID TOKEN"
        );

    }

    session.stage = 4;

    return res
        .status(200)
        .type("text/plain")
        .send(
            buildL4(session)
        );

});

/* =========================================================
   L5
========================================================= */

app.get("/api/l5", (req, res) => {

    const session =
        sessions.get(req.query.session);

    if (!validSession(session)) {

        return apiBlock(
            res,
            "INVALID SESSION"
        );

    }

    if (session.stage !== 4) {

        return apiBlock(
            res,
            "INVALID STAGE"
        );

    }

    if (
        !consumeToken(
            session,
            req.query.token
        )
    ) {

        return apiBlock(
            res,
            "INVALID TOKEN"
        );

    }

    const script =
        scripts.get(
            session.scriptId
        );

    if (!script) {

        sessions.delete(
            session.id
        );

        return apiBlock(
            res,
            "SCRIPT NOT FOUND"
        );

    }

    session.stage = 5;

    const output =
        buildL5(
            session,
            script.source
        );

    sessions.delete(
        session.id
    );

    return res
        .status(200)
        .type("text/plain")
        .send(output);

});

/* =========================================================
   UNKNOWN API ROUTES
========================================================= */

app.use("/api", (req, res) => {

    return apiBlock(
        res,
        "API ROUTE NOT FOUND"
    );

});

/* =========================================================
   UNKNOWN WEB ROUTES
========================================================= */

app.use((req, res) => {

    res.status(404).type("html").send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>404 - LEXINX</title>
<style>
body {
    margin: 0;
    background: #050505;
    color: white;
    font-family: Arial, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
    text-align: center;
}
h1 {
    font-size: 50px;
    margin: 0;
}
p {
    color: #777;
}
</style>
</head>

<body>

<div>
    <h1>404</h1>
    <p>LEXINX — Page not found</p>
</div>

</body>
</html>
    `);

});

/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

setInterval(() => {

    const now = Date.now();

    for (
        const [id, session]
        of sessions
    ) {

        if (now > session.expires) {

            sessions.delete(id);

        }

    }

}, 30 * 1000);

/* =========================================================
   SERVER
========================================================= */

app.listen(PORT, () => {

    console.log(
        `LEXINX server running on port ${PORT}`
    );

});
