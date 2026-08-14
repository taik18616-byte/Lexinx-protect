const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const DOMAIN =
    process.env.DOMAIN ||
    "https://lexinx-protect.onrender.com";

const DATA_DIR =
    path.join(__dirname, "data");

const DATA_FILE =
    path.join(DATA_DIR, "scripts.json");

const TOKEN_TTL = 60 * 1000;


// ============================================================
// MIDDLEWARE
// ============================================================

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);


// ============================================================
// DATABASE
// ============================================================

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });
}

if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(
        DATA_FILE,
        "[]",
        "utf8"
    );
}

function readScripts() {

    try {

        return JSON.parse(
            fs.readFileSync(
                DATA_FILE,
                "utf8"
            )
        );

    } catch {

        return [];
    }
}

function saveScripts(data) {

    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(
            data,
            null,
            2
        ),
        "utf8"
    );
}


// ============================================================
// RANDOM ID
// ============================================================

function randomString(length) {

    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ" +
        "abcdefghijkmnopqrstuvwxyz" +
        "23456789";

    let result = "";

    for (let i = 0; i < length; i++) {

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


function generateScriptId() {

    const scripts =
        readScripts();

    let id;

    do {

        id =
            randomString(10);

    } while (
        scripts.some(
            x => x.id === id
        )
    );

    return id;
}


// ============================================================
// BLOCK PAGE
// ============================================================

function blocked(res, reason = "LEXINX BLOCK") {

    let output = "";

    for (let i = 0; i < 1000; i++) {

        output +=
            i % 2 === 0
                ? "LEXINX PROTECT\n"
                : "BLOCKED BY LEXINX\n";
    }

    return res
        .status(403)
        .type("html")
        .send(`
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>LEXINX PROTECT</title>

<style>

html,
body {
    margin: 0;
    padding: 0;
    background: #050505;
    color: #ff3030;
    font-family: monospace;
}

body {
    padding: 30px;
}

h1 {
    font-size: 34px;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
}

</style>

</head>

<body>

<h1>BLOCKED BY LEXINX</h1>

<pre>${output}</pre>

</body>

</html>
        `);
}


// ============================================================
// BASIC BROWSER CHECK
// ============================================================

function isBrowser(req) {

    const ua =
        String(
            req.headers[
                "user-agent"
            ] || ""
        ).toLowerCase();

    const browserPatterns = [
        "mozilla",
        "chrome",
        "firefox",
        "safari",
        "edg",
        "opera"
    ];

    return browserPatterns.some(
        x => ua.includes(x)
    );
}


// ============================================================
// TOKEN DATABASE
// ============================================================

const sessions =
    new Map();


// ============================================================
// CLEAN EXPIRED TOKENS
// ============================================================

function cleanupSessions() {

    const now =
        Date.now();

    for (
        const [
            token,
            session
        ] of sessions
    ) {

        if (
            now >
            session.expiresAt
        ) {

            sessions.delete(
                token
            );
        }
    }
}

setInterval(
    cleanupSessions,
    30 * 1000
);


// ============================================================
// ADMIN CREATE
// ============================================================

app.post(
    "/admin/create",
    (req, res) => {

        const {
            name,
            payload
        } = req.body || {};

        if (
            typeof name !== "string" ||
            typeof payload !== "string"
        ) {

            return res.status(400).json({
                ok: false,
                error: "Invalid input"
            });
        }

        if (!name.trim()) {

            return res.status(400).json({
                ok: false,
                error: "Name required"
            });
        }

        if (!payload.trim()) {

            return res.status(400).json({
                ok: false,
                error: "Payload required"
            });
        }

        if (
            payload.length >
            1000000
        ) {

            return res.status(413).json({
                ok: false,
                error: "Payload too large"
            });
        }

        const scripts =
            readScripts();

        const id =
            generateScriptId();

        const script = {

            id,

            name:
                name.trim(),

            payload,

            active: true,

            createdAt:
                new Date()
                    .toISOString()
        };

        scripts.push(
            script
        );

        saveScripts(
            scripts
        );

        res.json({

            ok: true,

            script: {

                id,

                name:
                    script.name,

                loader:
                    `loadstring(game:HttpGet("${DOMAIN}/loader/${id}"))()`
            }
        });
    }
);


// ============================================================
// ADMIN LIST
// ============================================================

app.get(
    "/admin/list",
    (req, res) => {

        const scripts =
            readScripts();

        res.json({

            ok: true,

            scripts:
                scripts.map(
                    script => ({

                        id:
                            script.id,

                        name:
                            script.name,

                        active:
                            script.active,

                        createdAt:
                            script.createdAt,

                        loader:
                            `loadstring(game:HttpGet("${DOMAIN}/loader/${script.id}"))()`
                    })
                )
        });
    }
);


// ============================================================
// REVOKE
// ============================================================

app.post(
    "/admin/revoke/:id",
    (req, res) => {

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id
            );

        if (!script) {

            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        script.active = false;

        saveScripts(
            scripts
        );

        res.json({
            ok: true
        });
    }
);


// ============================================================
// ENABLE
// ============================================================

app.post(
    "/admin/enable/:id",
    (req, res) => {

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id
            );

        if (!script) {

            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        script.active = true;

        saveScripts(
            scripts
        );

        res.json({
            ok: true
        });
    }
);


// ============================================================
// DELETE
// ============================================================

app.delete(
    "/admin/delete/:id",
    (req, res) => {

        let scripts =
            readScripts();

        const oldLength =
            scripts.length;

        scripts =
            scripts.filter(
                x =>
                    x.id !==
                    req.params.id
            );

        if (
            scripts.length ===
            oldLength
        ) {

            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        saveScripts(
            scripts
        );

        res.json({
            ok: true
        });
    }
);


// ============================================================
// LOADER ENDPOINT
//
// Browser -> BLOCK
// Executor -> nhận Lua loader
// ============================================================

app.get(
    "/loader/:id",
    (req, res) => {

        if (isBrowser(req)) {

            return blocked(
                res,
                "BROWSER"
            );
        }

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id
            );

        if (!script) {

            return blocked(
                res,
                "INVALID ID"
            );
        }

        if (!script.active) {

            return blocked(
                res,
                "REVOKED"
            );
        }

        const loader = `
local HttpService = game:GetService("HttpService")

local API = "${DOMAIN}"

local ID = "${script.id}"

local function randomNonce()

    local chars =
        "abcdefghijklmnopqrstuvwxyz" ..
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ..
        "0123456789"

    local result = {}

    for i = 1, 32 do

        local n =
            math.random(
                1,
                #chars
            )

        result[i] =
            chars:sub(
                n,
                n
            )
    end

    return table.concat(result)
end

local nonce =
    randomNonce()

local timestamp =
    os.time()

local response =
    request({

        Url =
            API ..
            "/api/challenge/" ..
            ID,

        Method =
            "POST",

        Headers = {

            ["Content-Type"] =
                "application/json",

            ["X-Time"] =
                tostring(
                    timestamp
                ),

            ["X-Nonce"] =
                nonce
        },

        Body =
            "{}"
    })

if not response then

    warn(
        "LEXINX BLOCK"
    )

    return
end

if response.StatusCode ~= 200 then

    warn(
        "LEXINX BLOCK:",
        response.StatusCode
    )

    return
end

local success,
      challenge =
    pcall(
        function()

            return
                HttpService:
                JSONDecode(
                    response.Body
                )

        end
    )

if not success or
   not challenge.ok then

    warn(
        "LEXINX AUTH FAILED"
    )

    return
end

local payloadResponse =
    request({

        Url =
            API ..
            "/api/payload/" ..
            ID,

        Method =
            "POST",

        Headers = {

            ["Content-Type"] =
                "application/json",

            ["X-Session"] =
                challenge.token
        },

        Body =
            "{}"
    })

if not payloadResponse then

    warn(
        "LEXINX BLOCK"
    )

    return
end

if payloadResponse.StatusCode ~= 200 then

    warn(
        "LEXINX BLOCK:",
        payloadResponse.StatusCode
    )

    return
end

local payload =
    payloadResponse.Body

if type(payload) ~= "string" or
   #payload == 0 then

    warn(
        "LEXINX EMPTY PAYLOAD"
    )

    return
end

local fn,
      err =
    loadstring(
        payload
    )

if not fn then

    warn(
        "LEXINX COMPILE ERROR:",
        err
    )

    return
end

local ok,
      runtimeError =
    pcall(fn)

if not ok then

    warn(
        "LEXINX RUNTIME ERROR:",
        runtimeError
    )

end
`;

        return res
            .status(200)
            .type("text/plain")
            .send(loader);
    }
);


// ============================================================
// CHALLENGE
// ============================================================

app.post(
    "/api/challenge/:id",
    (req, res) => {

        if (isBrowser(req)) {

            return blocked(
                res,
                "BROWSER"
            );
        }

        const {
            id
        } = req.params;

        const {
            timestamp,
            nonce
        } = req.body || {};

        if (
            !timestamp ||
            !nonce
        ) {

            return blocked(
                res,
                "INVALID REQUEST"
            );
        }

        if (
            typeof nonce !==
            "string" ||
            nonce.length < 16 ||
            nonce.length > 128
        ) {

            return blocked(
                res,
                "INVALID NONCE"
            );
        }

        const ts =
            Number(timestamp);

        if (
            !Number.isFinite(ts)
        ) {

            return blocked(
                res,
                "INVALID TIME"
            );
        }

        const now =
            Math.floor(
                Date.now() / 1000
            );

        if (
            Math.abs(
                now - ts
            ) > 60
        ) {

            return blocked(
                res,
                "TIME CHECK FAILED"
            );
        }

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id === id
            );

        if (!script) {

            return blocked(
                res,
                "INVALID ID"
            );
        }

        if (!script.active) {

            return blocked(
                res,
                "REVOKED"
            );
        }

        const token =
            crypto.randomBytes(
                32
            ).toString("hex");

        sessions.set(
            token,
            {

                id,

                nonce,

                createdAt:
                    Date.now(),

                expiresAt:
                    Date.now() +
                    TOKEN_TTL,

                used: false
            }
        );

        return res.json({

            ok: true,

            token,

            expiresIn:
                TOKEN_TTL
        });
    }
);


// ============================================================
// PAYLOAD
// ============================================================

app.post(
    "/api/payload/:id",
    (req, res) => {

        if (isBrowser(req)) {

            return blocked(
                res,
                "BROWSER"
            );
        }

        const token =
            req.header(
                "X-Session"
            );

        if (!token) {

            return blocked(
                res,
                "NO SESSION"
            );
        }

        const session =
            sessions.get(
                token
            );

        if (!session) {

            return blocked(
                res,
                "INVALID SESSION"
            );
        }

        if (
            session.used
        ) {

            sessions.delete(
                token
            );

            return blocked(
                res,
                "TOKEN ALREADY USED"
            );
        }

        if (
            Date.now() >
            session.expiresAt
        ) {

            sessions.delete(
                token
            );

            return blocked(
                res,
                "TOKEN EXPIRED"
            );
        }

        if (
            session.id !==
            req.params.id
        ) {

            return blocked(
                res,
                "ID MISMATCH"
            );
        }

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id
            );

        if (!script) {

            sessions.delete(
                token
            );

            return blocked(
                res,
                "INVALID SCRIPT"
            );
        }

        if (!script.active) {

            sessions.delete(
                token
            );

            return blocked(
                res,
                "REVOKED"
            );
        }

        // ONE-TIME TOKEN
        session.used = true;

        sessions.delete(
            token
        );

        return res
            .status(200)
            .type("text/plain")
            .send(
                script.payload
            );
    }
);


// ============================================================
// DIRECT API ACCESS
// ============================================================

app.get(
    "/api/:id",
    (req, res) => {

        return blocked(
            res,
            "DIRECT ACCESS"
        );
    }
);


// ============================================================
// 404
// ============================================================

app.use(
    (req, res) => {

        return blocked(
            res,
            "NOT FOUND"
        );
    }
);


// ============================================================
// START
// ============================================================

app.listen(
    PORT,
    () => {

        console.log(
            "================================"
        );

        console.log(
            "LEXINX PROTECT ONLINE"
        );

        console.log(
            "================================"
        );

        console.log(
            "PORT:",
            PORT
        );

        console.log(
            "DOMAIN:",
            DOMAIN
        );
    }
);
