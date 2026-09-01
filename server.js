const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

/* =========================================================
   CONFIG
========================================================= */

const TOKEN_TTL = 60 * 1000;

/* =========================================================
   MEMORY STORAGE
========================================================= */

const users = new Map();
const authSessions = new Map();
const loaderSessions = new Map();
const scripts = new Map();

/* =========================================================
   RANDOM
========================================================= */

function randomHex(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function randomName() {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    let out = "_";

    for (let i = 0; i < 10; i++) {
        out += chars[
            crypto.randomInt(0, chars.length)
        ];
    }

    return out;
}

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function luaString(value) {
    return JSON.stringify(String(value));
}

/* =========================================================
   API RESPONSE
========================================================= */

function apiError(res, code, message) {
    return res.status(code).json({
        ok: false,
        error: message
    });
}

/* =========================================================
   AUTH
========================================================= */

function createAuthToken(username) {

    const token = randomHex(32);

    authSessions.set(token, {
        username,
        created: Date.now()
    });

    return token;
}

function getAuth(req) {

    const header =
        req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return null;
    }

    const token = header.slice(7);

    const session =
        authSessions.get(token);

    if (!session) {
        return null;
    }

    const user =
        users.get(session.username);

    if (!user) {
        return null;
    }

    return {
        token,
        username: session.username,
        user
    };
}

function requireAuth(req, res, next) {

    const auth = getAuth(req);

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

app.post("/api/register", (req, res) => {

    const username =
        String(req.body.username || "")
            .trim();

    const password =
        String(req.body.password || "");

    if (!username) {
        return apiError(
            res,
            400,
            "Username is required."
        );
    }

    if (username.length < 3) {
        return apiError(
            res,
            400,
            "Username must contain at least 3 characters."
        );
    }

    if (username.length > 32) {
        return apiError(
            res,
            400,
            "Username is too long."
        );
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return apiError(
            res,
            400,
            "Username may only contain letters, numbers and underscore."
        );
    }

    if (password.length < 6) {
        return apiError(
            res,
            400,
            "Password must contain at least 6 characters."
        );
    }

    const key =
        username.toLowerCase();

    if (users.has(key)) {
        return apiError(
            res,
            409,
            "Username already exists."
        );
    }

    users.set(key, {
        username,
        password: hashPassword(password),
        created: Date.now()
    });

    const token =
        createAuthToken(key);

    return res.json({
        ok: true,
        username,
        token,
        url:
            `${req.protocol}://${req.get("host")}/`
    });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", (req, res) => {

    const username =
        String(req.body.username || "")
            .trim();

    const password =
        String(req.body.password || "");

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

    const token =
        createAuthToken(key);

    return res.json({
        ok: true,
        username: user.username,
        token,
        url:
            `${req.protocol}://${req.get("host")}/`
    });
});

/* =========================================================
   ME
========================================================= */

app.get("/api/me", (req, res) => {

    const auth = getAuth(req);

    if (!auth) {
        return apiError(
            res,
            401,
            "Not authenticated."
        );
    }

    return res.json({
        ok: true,
        username: auth.user.username,
        token: auth.token,
        url:
            `${req.protocol}://${req.get("host")}/`
    });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {

    const auth = getAuth(req);

    if (auth) {
        authSessions.delete(auth.token);
    }

    return res.json({
        ok: true
    });
});

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

        if (source.length > 1024 * 1024) {
            return apiError(
                res,
                400,
                "Script is too large."
            );
        }

        let id;

        do {
            id = randomHex(12);
        } while (scripts.has(id));

        scripts.set(id, {
            id,
            name:
                name ||
                "Untitled Script",
            source,
            owner:
                req.auth.username,
            created: Date.now(),
            updated: Date.now()
        });

        return res.json({
            ok: true,
            id,
            loader:
                `${req.protocol}://${req.get("host")}/api/loader/${id}`
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

        const list = [];

        for (const script of scripts.values()) {

            if (
                script.owner !==
                req.auth.username
            ) {
                continue;
            }

            list.push({
                id: script.id,
                name: script.name,
                loader:
                    `${req.protocol}://${req.get("host")}/api/loader/${script.id}`,
                created: script.created,
                updated: script.updated
            });
        }

        list.sort(
            (a, b) =>
                b.created -
                a.created
        );

        return res.json({
            ok: true,
            scripts: list
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
            scripts.get(req.params.id);

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
                id: script.id,
                name: script.name,
                source: script.source
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
            scripts.get(req.params.id);

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

            if (!req.body.source.trim()) {
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
            scripts.get(req.params.id);

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

function createLoaderSession(scriptId) {

    const id = randomHex(32);

    const session = {
        id,
        scriptId,
        stage: 1,
        tokens: new Set(),
        created: Date.now(),
        expires:
            Date.now() +
            TOKEN_TTL
    };

    loaderSessions.set(
        id,
        session
    );

    return session;
}

function getLoaderSession(id) {

    return loaderSessions.get(id);
}

function validSession(session) {

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

function issueToken(session) {

    const token =
        randomHex(32);

    session.tokens.add(token);

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
        !session.tokens.has(token)
    ) {
        return false;
    }

    session.tokens.delete(token);

    return true;
}

/* =========================================================
   WRAPPER VM
========================================================= */

function buildWrapperVM(session) {

    const op =
        randomName();

    const execute =
        randomName();

    const program =
        randomName();

    const state =
        randomName();

    const token =
        issueToken(session);

    return `

-- LEXINX LOADER WRAPPER VM

local ${program} = {

    { op = "LOAD", value = "L2" },

    { op = "REQUEST",
      value = ${luaString(token)} },

    { op = "EXEC" }

}

local ${state} = {
    index = 1,
    session = ${luaString(session.id)}
}

local function ${op}(instruction)

    if instruction.op == "LOAD" then

        return instruction.value

    elseif instruction.op == "REQUEST" then

        return instruction.value

    elseif instruction.op == "EXEC" then

        return true

    end

end

local function ${execute}(vm)

    while vm.index <= #vm.program do

        local instruction =
            vm.program[vm.index]

        local result =
            ${op}(instruction)

        if result == nil then
            return
        end

        vm.index =
            vm.index + 1

    end

    local url =
        "https://lexinx-protect.onrender.com/api/l3"
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

    if type(response) ~= "string" then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return ${execute}({

    program = ${program},

    index = ${state}.index

})

`;
}

/* =========================================================
   L2
========================================================= */

function buildL2(session) {

    const data =
        randomName();

    const run =
        randomName();

    const token =
        issueToken(session);

    return `

-- LEXINX L2

local ${data} = {

    strings = {

        [0] = ${luaString(token)},

        [1] = ${luaString(session.id)}

    },

    instructions = {

        { opcode = "LOADK", arg = 0 },

        { opcode = "LOADK", arg = 1 }

    }

}

local function ${run}(program)

    local stack = {}

    for _, instruction in ipairs(
        program.instructions
    ) do

        if instruction.opcode ==
            "LOADK"
        then

            stack[#stack + 1] =
                program.strings[
                    instruction.arg
                ]

        end

    end

    return stack

end

local values =
    ${run}(${data})

local url =
    "https://lexinx-protect.onrender.com/api/l3"
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

function buildL3(session) {

    const vm =
        randomName();

    const run =
        randomName();

    const token =
        issueToken(session);

    return `

-- LEXINX L3
-- PACKED PROTOTYPE

local ${vm} = {

    version = 3,

    instructions = {

        { op = "LOADK", arg = 1 },

        { op = "LOADK", arg = 2 },

        { op = "REQUEST" },

        { op = "EXEC" }

    },

    constants = {

        [1] = ${luaString(session.id)},

        [2] = ${luaString(token)}

    }

}

local function ${run}(program)

    local stack = {}

    for _, instruction in ipairs(
        program.instructions
    ) do

        if instruction.op == "LOADK" then

            stack[#stack + 1] =
                program.constants[
                    instruction.arg
                ]

        elseif instruction.op == "REQUEST" then

            local url =
                "https://lexinx-protect.onrender.com/api/l4"
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

            stack.response =
                response

        elseif instruction.op == "EXEC" then

            if stack.response then

                local fn =
                    loadstring(
                        stack.response
                    )

                if fn then
                    return fn()
                end

            end

        end

    end

end

return ${run}(${vm})

`;
}

/* =========================================================
   L4
========================================================= */

function buildL4(session) {

    const runtime =
        randomName();

    const dispatch =
        randomName();

    const token =
        issueToken(session);

    return `

-- LEXINX L4
-- RUNTIME BOOTSTRAP

local ${runtime} = {

    stage = 4,

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)}

}

local function ${dispatch}(state)

    if state.stage ~= 4 then
        return
    end

    local url =
        "https://lexinx-protect.onrender.com/api/l5"
        .. "?session="
        .. state.session
        .. "&token="
        .. state.token

    local ok, response =
        pcall(function()

            return game:HttpGet(url)

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

return ${dispatch}(
    ${runtime}
)

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
        randomName();

    const decode =
        randomName();

    const execute =
        randomName();

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

                    bits[#bits + 1] =
                        (
                            p % 2^j >=
                            2^(j - 1)
                        )
                        and "1"
                        or "0"

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

            if bits[i + j] == "1" then

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
        ${decode}(${data})

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
   LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const userAgent =
            String(
                req.headers["user-agent"] ||
                ""
            )
            .toLowerCase();

        /*
         * Normal browsers receive the protection page.
         */

        const browser =
            userAgent.includes("mozilla") ||
            userAgent.includes("chrome") ||
            userAgent.includes("safari") ||
            userAgent.includes("firefox") ||
            userAgent.includes("edge");

        if (browser) {
            return blockPage(res);
        }

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

        const session =
            createLoaderSession(
                script.id
            );

        session.stage = 1;

        /*
         * Wrapper VM is the first layer.
         */

        return res
            .type("text/plain")
            .send(
                buildWrapperVM(
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
            getLoaderSession(
                req.query.session
            );

        if (
            !validSession(session)
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
                buildL2(session)
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
            getLoaderSession(
                req.query.session
            );

        if (
            !validSession(session)
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
                buildL3(session)
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
            getLoaderSession(
                req.query.session
            );

        if (
            !validSession(session)
        ) {
            return apiError(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        if (
            session.stage !== 3
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

        session.stage = 4;

        const output =
            buildL4(session);

        return res
            .type("text/plain")
            .send(output);
    }
);

/* =========================================================
   FINAL PAYLOAD
========================================================= */

app.get(
    "/api/l5/final",
    (req, res) => {

        const session =
            getLoaderSession(
                req.query.session
            );

        if (
            !validSession(session)
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
   PUBLIC ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.sendFile(
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

        res.status(404).send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>404</title>
</head>
<body style="
background:#070707;
color:#aaa;
font-family:Arial;
text-align:center;
padding-top:100px;
">
<h1>404</h1>
<p>Page not found.</p>
</body>
</html>
`);
    }
);

/* =========================================================
   CLEANUP
========================================================= */

setInterval(() => {

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

}, 30 * 1000);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            "LEXINX server running on port " +
            PORT
        );

    }
);
