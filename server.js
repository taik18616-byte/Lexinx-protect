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
const DB_FILE = path.join(DATA_DIR, "scripts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_TTL = 2 * 60 * 1000;
const TOKEN_TTL = 20 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.disable("x-powered-by");

app.use(express.json({
    limit: "25mb"
}));

app.use(express.static(PUBLIC_DIR));

/* =====================================================
   DATABASE
===================================================== */

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
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify(db, null, 2),
        "utf8"
    );
}

/* =====================================================
   RANDOM
===================================================== */

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

/* =====================================================
   HEADERS
===================================================== */

function secure(res) {
    return res
        .set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        )
        .set("Pragma", "no-cache")
        .set(
            "X-Content-Type-Options",
            "nosniff"
        );
}

function block(res) {
    return secure(res)
        .status(403)
        .type("text/plain")
        .send("LEXINX BLOCK");
}

/* =====================================================
   BROWSER CHECK
===================================================== */

function browserNavigation(req) {
    const accept =
        String(
            req.headers.accept || ""
        ).toLowerCase();

    const mode =
        String(
            req.headers["sec-fetch-mode"] || ""
        ).toLowerCase();

    const dest =
        String(
            req.headers["sec-fetch-dest"] || ""
        ).toLowerCase();

    return (
        accept.includes("text/html") ||
        mode === "navigate" ||
        dest === "document"
    );
}

/* =====================================================
   SESSION
===================================================== */

const sessions = new Map();

function createChallenge() {
    const now = Date.now();

    return {
        token: randomHex(32),
        nonce: randomHex(16),
        expiresAt: now + TOKEN_TTL,
        used: false
    };
}

function createSession(scriptID) {
    const now = Date.now();

    const session = {
        id: randomHex(32),

        scriptID,

        createdAt: now,

        expiresAt:
            now + SESSION_TTL,

        stage: 2,

        l2: createChallenge(),

        l3: null,

        l4: null,

        l5: null
    };

    sessions.set(
        session.id,
        session
    );

    return session;
}

function getSession(id) {
    if (
        typeof id !== "string" ||
        !id
    ) {
        return null;
    }

    const session =
        sessions.get(id);

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expiresAt
    ) {
        sessions.delete(id);
        return null;
    }

    return session;
}

function consumeChallenge(
    challenge,
    token,
    nonce
) {
    if (!challenge) {
        return false;
    }

    if (challenge.used) {
        return false;
    }

    if (
        Date.now() >
        challenge.expiresAt
    ) {
        return false;
    }

    if (
        typeof token !== "string" ||
        typeof nonce !== "string"
    ) {
        return false;
    }

    if (
        token !== challenge.token
    ) {
        return false;
    }

    if (
        nonce !== challenge.nonce
    ) {
        return false;
    }

    challenge.used = true;

    return true;
}

/* =====================================================
   HOME
===================================================== */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            PUBLIC_DIR,
            "index.html"
        )
    );
});

/* =====================================================
   CREATE SCRIPT
===================================================== */

app.post(
    "/api/create",
    (req, res) => {
        const source =
            typeof req.body?.source === "string"
                ? req.body.source
                : "";

        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error: "Script is empty"
            });
        }

        const name =
            cleanName(req.body?.name);

        const id =
            randomHex(12);

        const db =
            readDB();

        db[id] = {
            id,
            name,
            source,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        writeDB(db);

        secure(res).json({
            ok: true,

            id,

            name,

            endpoint:
                `${DOMAIN}/api/loader/${id}`,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    `${DOMAIN}/api/loader/${id}`
                )}))()`
        });
    }
);

/* =====================================================
   EDIT SCRIPT
===================================================== */

app.post(
    "/api/edit/:id",
    (req, res) => {
        const db =
            readDB();

        const script =
            db[req.params.id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        if (
            typeof req.body?.source ===
            "string"
        ) {
            if (
                !req.body.source.trim()
            ) {
                return res.status(400).json({
                    ok: false,
                    error: "Script is empty"
                });
            }

            script.source =
                req.body.source;
        }

        if (
            typeof req.body?.name ===
                "string" &&
            req.body.name.trim()
        ) {
            script.name =
                cleanName(
                    req.body.name
                );
        }

        script.updatedAt =
            Date.now();

        writeDB(db);

        secure(res).json({
            ok: true,

            id: script.id,

            name: script.name,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    `${DOMAIN}/api/loader/${script.id}`
                )}))()`
        });
    }
);

/* =====================================================
   L1
===================================================== */

app.get(
    "/api/loader/:id",
    (req, res) => {

        if (
            browserNavigation(req)
        ) {
            return block(res);
        }

        const db =
            readDB();

        const script =
            db[req.params.id];

        if (!script) {
            return block(res);
        }

        const session =
            createSession(
                script.id
            );

        /*
         * L1 được tạo động.
         * L1 nhận challenge L2 rồi
         * tự chạy toàn bộ chain.
         */

        const lua = `
local HttpService = game:GetService("HttpService")

local DOMAIN = ${JSON.stringify(DOMAIN)}

local SESSION = ${JSON.stringify(
            session.id
        )}

local L2_TOKEN = ${JSON.stringify(
            session.l2.token
        )}

local L2_NONCE = ${JSON.stringify(
            session.l2.nonce
        )}

local function postJSON(url, body)

    local ok, response = pcall(function()

        return request({
            Url = url,

            Method = "POST",

            Headers = {
                ["Content-Type"] =
                    "application/json"
            },

            Body =
                HttpService:JSONEncode(body)
        })

    end)

    if not ok then
        error("LEXINX BLOCK")
    end

    if not response then
        error("LEXINX BLOCK")
    end

    if response.StatusCode ~= 200 then
        error(
            "LEXINX BLOCK HTTP " ..
            tostring(response.StatusCode)
        )
    end

    local decoded, data =
        pcall(function()

            return HttpService:JSONDecode(
                response.Body
            )

        end)

    if not decoded then
        error("LEXINX BLOCK")
    end

    if type(data) ~= "table" then
        error("LEXINX BLOCK")
    end

    if data.ok ~= true then
        error("LEXINX BLOCK")
    end

    return data
end

--------------------------------------------------------
-- L2 -> L3
--------------------------------------------------------

local L3 = postJSON(
    DOMAIN .. "/api/l3",
    {
        session = SESSION,
        token = L2_TOKEN,
        nonce = L2_NONCE
    }
)

if L3.stage ~= 3 then
    error("LEXINX BLOCK")
end

--------------------------------------------------------
-- L3 -> L4
--------------------------------------------------------

local L4 = postJSON(
    DOMAIN .. "/api/l4",
    {
        session = L3.session,
        token = L3.token,
        nonce = L3.nonce
    }
)

if L4.stage ~= 4 then
    error("LEXINX BLOCK")
end

--------------------------------------------------------
-- L4 -> L5
--------------------------------------------------------

local L5 = postJSON(
    DOMAIN .. "/api/l5",
    {
        session = L4.session,
        token = L4.token,
        nonce = L4.nonce
    }
)

if L5.stage ~= 5 then
    error("LEXINX BLOCK")
end

--------------------------------------------------------
-- L5 -> SOURCE
--------------------------------------------------------

local RESULT = postJSON(
    DOMAIN .. "/api/data",
    {
        session = L5.session,
        token = L5.token,
        nonce = L5.nonce
    }
)

if type(RESULT.code) ~= "string" then
    error("LEXINX BLOCK: SOURCE MISSING")
end

--------------------------------------------------------
-- EXECUTE
--------------------------------------------------------

local fn, compileError =
    loadstring(RESULT.code)

if not fn then
    error(
        "LEXINX COMPILE ERROR: " ..
        tostring(compileError)
    )
end

local success, runtimeError =
    pcall(fn)

if not success then
    error(
        "LEXINX RUNTIME ERROR: " ..
        tostring(runtimeError)
    )
end
`;

        secure(res)
            .type("text/plain")
            .send(lua);
    }
);

/* =====================================================
   L2 -> L3
===================================================== */

app.get(
    "/api/l3",
    (req, res) => {
        return block(res);
    }
);

app.post(
    "/api/l3",
    (req, res) => {

        if (
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(session);

        if (!s) {
            return block(res);
        }

        if (s.stage !== 2) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l2,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        s.l3 =
            createChallenge();

        s.stage = 3;

        secure(res).json({
            ok: true,

            stage: 3,

            session: s.id,

            token:
                s.l3.token,

            nonce:
                s.l3.nonce,

            next:
                `${DOMAIN}/api/l4`
        });
    }
);

/* =====================================================
   L3 -> L4
===================================================== */

app.get(
    "/api/l4",
    (req, res) => {
        return block(res);
    }
);

app.post(
    "/api/l4",
    (req, res) => {

        if (
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(session);

        if (!s) {
            return block(res);
        }

        if (s.stage !== 3) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l3,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        s.l4 =
            createChallenge();

        s.stage = 4;

        secure(res).json({
            ok: true,

            stage: 4,

            session: s.id,

            token:
                s.l4.token,

            nonce:
                s.l4.nonce,

            next:
                `${DOMAIN}/api/l5`
        });
    }
);

/* =====================================================
   L4 -> L5
===================================================== */

app.get(
    "/api/l5",
    (req, res) => {
        return block(res);
    }
);

app.post(
    "/api/l5",
    (req, res) => {

        if (
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(session);

        if (!s) {
            return block(res);
        }

        if (s.stage !== 4) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l4,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        s.l5 =
            createChallenge();

        s.stage = 5;

        secure(res).json({
            ok: true,

            stage: 5,

            session: s.id,

            token:
                s.l5.token,

            nonce:
                s.l5.nonce,

            next:
                `${DOMAIN}/api/data`
        });
    }
);

/* =====================================================
   L5 -> SOURCE
===================================================== */

app.get(
    "/api/data",
    (req, res) => {
        return block(res);
    }
);

app.post(
    "/api/data",
    (req, res) => {

        if (
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(session);

        if (!s) {
            return block(res);
        }

        if (s.stage !== 5) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l5,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        const db =
            readDB();

        const script =
            db[s.scriptID];

        if (!script) {
            sessions.delete(s.id);

            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        /*
         * Hủy session ngay khi challenge
         * cuối được consume.
         */

        sessions.delete(s.id);

        secure(res).json({
            ok: true,
            code: script.source
        });
    }
);

/* =====================================================
   LIST SCRIPTS
===================================================== */

app.get(
    "/api/scripts",
    (req, res) => {

        const db =
            readDB();

        const scripts =
            Object.values(db)
                .reverse()
                .map(script => ({
                    id: script.id,

                    name: script.name,

                    createdAt:
                        script.createdAt,

                    updatedAt:
                        script.updatedAt,

                    loader:
                        `loadstring(game:HttpGet(${JSON.stringify(
                            `${DOMAIN}/api/loader/${script.id}`
                        )}))()`
                }));

        secure(res).json({
            ok: true,
            scripts
        });
    }
);

/* =====================================================
   DELETE
===================================================== */

app.delete(
    "/api/delete/:id",
    (req, res) => {

        const db =
            readDB();

        if (
            !db[req.params.id]
        ) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        delete db[
            req.params.id
        ];

        writeDB(db);

        secure(res).json({
            ok: true
        });
    }
);

/* =====================================================
   UNKNOWN API
===================================================== */

app.use(
    "/api",
    (req, res) => {
        return block(res);
    }
);

/* =====================================================
   404
===================================================== */

app.use(
    (req, res) => {

        secure(res)
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX BLOCK"
            );
    }
);

/* =====================================================
   CLEANUP
===================================================== */

setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [id, session]
            of sessions
        ) {

            if (
                now >
                session.expiresAt
            ) {
                sessions.delete(id);
            }
        }

    },
    30 * 1000
);

/* =====================================================
   START
===================================================== */

app.listen(
    PORT,
    () => {

        console.log(
            "======================================"
        );

        console.log(
            "LEXINX PROTECT ONLINE"
        );

        console.log(
            "DOMAIN:",
            DOMAIN
        );

        console.log(
            "PORT:",
            PORT
        );

        console.log(
            "FLOW:",
            "L1 -> L2 -> L3 -> L4 -> L5 -> SOURCE"
        );

        console.log(
            "SESSION TTL:",
            SESSION_TTL,
            "ms"
        );

        console.log(
            "TOKEN TTL:",
            TOKEN_TTL,
            "ms"
        );

        console.log(
            "======================================"
        );
    }
);
