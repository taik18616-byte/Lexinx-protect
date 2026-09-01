const express = require("express");
const crypto = require("crypto");

const app = express();

app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;

/* =========================================================
CONFIG
========================================================= */

const TOKEN_TTL = 60 * 1000;

const scripts = new Map();

/*
Example:

scripts.set("58ceecd03f8a061d8af1d341", {  
    source: `  
        print("LEXINX PAYLOAD")  
    `  
});

*/

scripts.set("58ceecd03f8a061d8af1d341", {
source:   print("LEXINX PAYLOAD RUNNING")  
});

/* =========================================================
SESSION STORAGE
========================================================= */

const sessions = new Map();

/*
session = {
id,
scriptId,
stage,
tokens: Set,
created,
expires
}
*/

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
BLOCK PAGE
========================================================= */

function blockPage(res) {
res.status(403);

res.type("html");  

return res.send(`

<!doctype html>

<html>  
<head>  
<meta charset="utf-8">  
<meta name="viewport" content="width=device-width,initial-scale=1">  <title>LEXINX PROTECT</title>  <style>  
  
html,body{  
    margin:0;  
    width:100%;  
    height:100%;  
    overflow:hidden;  
    background:#050505;  
    font-family:Arial,sans-serif;  
}  
  
body{  
    display:flex;  
    align-items:center;  
    justify-content:center;  
}  
  
.stars{  
    position:absolute;  
    inset:0;  
    background-image:  
        radial-gradient(#777 1px,transparent 1px),  
        radial-gradient(#444 1px,transparent 1px);  
    background-size:  
        37px 37px,  
        71px 71px;  
    background-position:  
        0 0,  
        25px 31px;  
    opacity:.28;  
}  
  
.box{  
    position:relative;  
    z-index:2;  
    width:min(520px,88%);  
    padding:55px 30px;  
    text-align:center;  
    border:1px solid #333;  
    border-radius:18px;  
    background:#111;  
    box-shadow:  
        0 0 50px rgba(255,255,255,.04);  
}  
  
.logo{  
    font-size:42px;  
    font-weight:900;  
    letter-spacing:8px;  
    animation:pulse 4s infinite alternate;  
}  
  
.sub{  
    margin-top:18px;  
    color:#777;  
    font-size:13px;  
    letter-spacing:3px;  
}  
  
@keyframes pulse{  
  
    0%{  
        color:#fff;  
    }  
  
    50%{  
        color:#777;  
    }  
  
    100%{  
        color:#fff;  
    }  
  
}  
  
</style>  </head>  <body>  <div class="stars"></div>  <div class="box">  <div class="logo">  
LEXINX  
</div>  <div class="sub">  
PROTECT  
</div>  <div class="sub">  
ANTI-SKID  
</div>  </div>  </body>  
</html>  
`);  
}  /* =========================================================
GENERIC API BLOCK
========================================================= */

function apiBlock(res) {
return res.status(403).json({
ok: false,
error: "LEXINX BLOCK"
});
}

/* =========================================================
LUA ESCAPE
========================================================= */

function luaString(value) {
return JSON.stringify(String(value));
}

/* =========================================================
VM HELPERS
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
L2 VM
========================================================= */

function buildL2(session, token) {

const vm = randomLuaName();  
const run = randomLuaName();  
const data = randomLuaName();  
const endpoint = randomLuaName();  

const nextToken = issueToken(session);  

return `

-- This script can't be opened, you skid guys

local ${data} = {

strings = {  

    [0] = ${luaString("/api/l3")},  
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
L3 VM
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
L4 RUNTIME
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

/*  
    L5 is the only place where source is inserted.  
*/  

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
L1
========================================================= */

app.get("/api/loader/:id", (req, res) => {

const id = req.params.id;  

const script = scripts.get(id);  

if (!script) {  
    return apiBlock(res);  
}  

const session = createSession(id);  

const token = issueToken(session);  

session.stage = 2;  

const code = buildL2(  
    session,  
    token  
);  

res.type("text/plain");  

return res.send(code);

});

/* =========================================================
L3 ENDPOINT
========================================================= */

app.get("/api/l3", (req, res) => {

const session =  
    sessions.get(req.query.session);  

if (!validSession(session)) {  
    return apiBlock(res);  
}  

if (session.stage !== 2) {  
    return apiBlock(res);  
}  

if (  
    !consumeToken(  
        session,  
        req.query.token  
    )  
) {  
    return apiBlock(res);  
}  

session.stage = 3;  

return res  
    .type("text/plain")  
    .send(buildL3(session));

});

/* =========================================================
L4 ENDPOINT
========================================================= */

app.get("/api/l4", (req, res) => {

const session =  
    sessions.get(req.query.session);  

if (!validSession(session)) {  
    return apiBlock(res);  
}  

if (session.stage !== 3) {  
    return apiBlock(res);  
}  

if (  
    !consumeToken(  
        session,  
        req.query.token  
    )  
) {  
    return apiBlock(res);  
}  

session.stage = 4;  

return res  
    .type("text/plain")  
    .send(buildL4(session));

});

/* =========================================================
L5 ENDPOINT
========================================================= */

app.get("/api/l5", (req, res) => {

const session =  
    sessions.get(req.query.session);  

if (!validSession(session)) {  
    return apiBlock(res);  
}  

if (session.stage !== 4) {  
    return apiBlock(res);  
}  

if (  
    !consumeToken(  
        session,  
        req.query.token  
    )  
) {  
    return apiBlock(res);  
}  

const script =  
    scripts.get(session.scriptId);  

if (!script) {  
    sessions.delete(session.id);  
    return apiBlock(res);  
}  

/*  
    Final stage.  
    Only here does the server expose  
    the actual payload.  
*/  

session.stage = 5;  

const output =  
    buildL5(  
        session,  
        script.source  
    );  

/*  
    Destroy session after final delivery.  
*/  

sessions.delete(session.id);  

return res  
    .type("text/plain")  
    .send(output);

});

/* =========================================================
DIRECT ENDPOINT PROTECTION
========================================================= */

app.use("/api", (req, res) => {
return apiBlock(res);
});

/* =========================================================
ROOT
========================================================= */

app.get("/", (req, res) => {

return blockPage(res);

});

/* =========================================================
UNKNOWN ROUTES
========================================================= */

app.use((req, res) => {

return blockPage(res);

});

/* =========================================================
CLEAN EXPIRED SESSIONS
========================================================= */

setInterval(() => {

const now = Date.now();  

for (const [id, session] of sessions) {  

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
