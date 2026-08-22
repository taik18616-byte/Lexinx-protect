const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { obfuscateLua } = require("./lexinx-obf");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "accounts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.disable("x-powered-by");

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({
    extended: true,
    limit: "15mb"
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

function createID() {
    return randomHex(12);
}

/* =====================================================
   PASSWORD
===================================================== */

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
        if (
            !stored ||
            !stored.salt ||
            !stored.hash
        ) {
            return false;
        }

        const salt = Buffer.from(
            stored.salt,
            "hex"
        );

        const expected = Buffer.from(
            stored.hash,
            "hex"
        );

        const actual = crypto.scryptSync(
            password,
            salt,
            64
        );

        return (
            actual.length === expected.length &&
            crypto.timingSafeEqual(
                actual,
                expected
            )
        );
    } catch {
        return false;
    }
}

/* =====================================================
   COOKIE
===================================================== */

function parseCookies(req) {
    const cookies = {};

    const header = req.headers.cookie;

    if (!header) {
        return cookies;
    }

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) continue;

        const key =
            part.slice(0, index).trim();

        const value =
            part.slice(index + 1).trim();

        try {
            cookies[key] =
                decodeURIComponent(value);
        } catch {
            cookies[key] = value;
        }
    }

    return cookies;
}

function setSessionCookie(res, sessionID) {
    res.setHeader(
        "Set-Cookie",
        [
            `lexinx_session=${encodeURIComponent(sessionID)}`,
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            `Max-Age=${Math.floor(
                SESSION_TTL / 1000
            )}`
        ].join("; ")
    );
}

function clearSessionCookie(res) {
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

/* =====================================================
   SESSION
===================================================== */

const sessions = new Map();

function createSession(username) {
    const sessionID = randomHex(48);

    sessions.set(sessionID, {
        username,
        createdAt: Date.now(),
        expiresAt:
            Date.now() + SESSION_TTL
    });

    return sessionID;
}

function getCurrentUser(req) {
    const cookies = parseCookies(req);

    const sessionID =
        cookies.lexinx_session;

    if (!sessionID) {
        return null;
    }

    const session =
        sessions.get(sessionID);

    if (!session) {
        return null;
    }

    if (Date.now() > session.expiresAt) {
        sessions.delete(sessionID);
        return null;
    }

    return {
        username: session.username,
        sessionID
    };
}

function requireAuth(req, res, next) {
    const user = getCurrentUser(req);

    if (!user) {
        return res.status(401).json({
            ok: false,
            error: "Not logged in"
        });
    }

    req.user = user;
    next();
}

/* =====================================================
   VALIDATION
===================================================== */

function validUsername(username) {
    return (
        typeof username === "string" &&
        /^[a-zA-Z0-9_]{3,24}$/.test(username)
    );
}

function validPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 6 &&
        password.length <= 128
    );
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

/* =====================================================
   ACCOUNT
===================================================== */

function ensureAccount(account) {
    let changed = false;

    if (!account.accountId) {
        account.accountId = randomHex(16);
        changed = true;
    }

    if (!account.scripts) {
        account.scripts = {};
        changed = true;
    }

    return changed;
}

function accountURL(account) {
    return (
        `${DOMAIN}/acc/` +
        `${encodeURIComponent(account.username)}/` +
        `${account.accountId}/dashboard`
    );
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
   REGISTER
===================================================== */

app.post("/api/register", (req, res) => {
    const {
        username,
        password
    } = req.body || {};

    if (!validUsername(username)) {
        return res.status(400).json({
            ok: false,
            error:
                "Username must contain 3-24 letters, numbers or _"
        });
    }

    if (!validPassword(password)) {
        return res.status(400).json({
            ok: false,
            error:
                "Password must contain 6-128 characters"
        });
    }

    const db = readDB();

    if (db[username]) {
        return res.status(409).json({
            ok: false,
            error:
                "Username already exists"
        });
    }

    const passwordData =
        hashPassword(password);

    const account = {
        username,
        accountId: randomHex(16),

        password: {
            salt: passwordData.salt,
            hash: passwordData.hash
        },

        createdAt: Date.now(),
        scripts: {}
    };

    db[username] = account;

    writeDB(db);

    const sessionID =
        createSession(username);

    setSessionCookie(
        res,
        sessionID
    );

    const url =
        accountURL(account);

    console.log(
        `[REGISTER] ${username} -> ${url}`
    );

    res.json({
        ok: true,
        username,
        accountId: account.accountId,
        url
    });
});

/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", (req, res) => {
    const {
        username,
        password
    } = req.body || {};

    if (
        typeof username !== "string" ||
        typeof password !== "string"
    ) {
        return res.status(400).json({
            ok: false,
            error: "Invalid login"
        });
    }

    const db = readDB();
    const account = db[username];

    if (!account) {
        return res.status(401).json({
            ok: false,
            error:
                "Invalid username or password"
        });
    }

    if (
        !verifyPassword(
            password,
            account.password
        )
    ) {
        return res.status(401).json({
            ok: false,
            error:
                "Invalid username or password"
        });
    }

    if (ensureAccount(account)) {
        writeDB(db);
    }

    const sessionID =
        createSession(username);

    setSessionCookie(
        res,
        sessionID
    );

    const url =
        accountURL(account);

    console.log(
        `[LOGIN] ${username} -> ${url}`
    );

    res.json({
        ok: true,
        username: account.username,
        accountId: account.accountId,
        url
    });
});

/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", (req, res) => {
    const cookies = parseCookies(req);

    if (cookies.lexinx_session) {
        sessions.delete(
            cookies.lexinx_session
        );
    }

    clearSessionCookie(res);

    res.json({
        ok: true
    });
});

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.user.username];

        if (!account) {
            return res.status(401).json({
                ok: false,
                error: "Account not found"
            });
        }

        if (ensureAccount(account)) {
            writeDB(db);
        }

        res.json({
            ok: true,
            username: account.username,
            accountId: account.accountId,
            url: accountURL(account)
        });
    }
);

/* =====================================================
   PRIVATE ACCOUNT PAGE
===================================================== */

app.get(
    "/acc/:username/:accountId/:page",
    (req, res) => {

        const {
            username,
            accountId,
            page
        } = req.params;

        if (page !== "dashboard") {
            return res.status(404)
                .type("text/plain")
                .send("LEXINX BLOCK");
        }

        const db = readDB();
        const account = db[username];

        if (!account) {
            return res.status(404)
                .type("text/plain")
                .send("LEXINX BLOCK");
        }

        if (
            account.accountId !==
            accountId
        ) {
            return res.status(403)
                .type("text/plain")
                .send("LEXINX BLOCK");
        }

        const user =
            getCurrentUser(req);

        if (
            !user ||
            user.username !== username
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

/* =====================================================
   CREATE SCRIPT
===================================================== */

app.post(
    "/api/create",
    requireAuth,
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

        const db = readDB();

        const account =
            db[req.user.username];

        if (!account) {
            return res.status(401).json({
                ok: false
            });
        }

        ensureAccount(account);

        const id = createID();

        const name =
            cleanName(
                req.body?.name
            );

        account.scripts[id] = {
            id,
            name,
            source,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        writeDB(db);

        const endpoint =
            `${DOMAIN}/api/loader/${id}`;

        const loader =
            `loadstring(game:HttpGet(${JSON.stringify(
                endpoint
            )}))()`;

        res.json({
            ok: true,
            id,
            name,
            endpoint,
            loader
        });
    }
);

/* =====================================================
   LIST SCRIPTS
===================================================== */

app.get(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.user.username];

        if (!account) {
            return res.status(401).json({
                ok: false
            });
        }

        const scripts =
            Object.values(
                account.scripts || {}
            )
            .sort(
                (a, b) =>
                    b.createdAt -
                    a.createdAt
            )
            .map(script => {

                const endpoint =
                    `${DOMAIN}/api/loader/${script.id}`;

                return {
                    id: script.id,
                    name: script.name,
                    createdAt:
                        script.createdAt,
                    updatedAt:
                        script.updatedAt,
                    endpoint,
                    loader:
                        `loadstring(game:HttpGet(${JSON.stringify(
                            endpoint
                        )}))()`
                };
            });

        res.json({
            ok: true,
            scripts
        });
    }
);

/* =====================================================
   GET SCRIPT
===================================================== */

app.get(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.user.username];

        const script =
            account?.scripts?.[
                req.params.id
            ];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        res.json({
            ok: true,
            script
        });
    }
);

/* =====================================================
   EDIT SCRIPT
===================================================== */

app.post(
    "/api/edit/:id",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.user.username];

        const script =
            account?.scripts?.[
                req.params.id
            ];

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
            if (!req.body.source.trim()) {
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

        res.json({
            ok: true,
            id: script.id,
            name: script.name
        });
    }
);

/* =====================================================
   DELETE SCRIPT
===================================================== */

app.delete(
    "/api/delete/:id",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const account =
            db[req.user.username];

        if (
            !account?.scripts?.[
                req.params.id
            ]
        ) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
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

/* =====================================================
   L1 LOADER
===================================================== */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const accept =
            String(
                req.headers.accept || ""
            ).toLowerCase();

        const fetchMode =
            String(
                req.headers[
                    "sec-fetch-mode"
                ] || ""
            ).toLowerCase();

        const fetchDest =
            String(
                req.headers[
                    "sec-fetch-dest"
                ] || ""
            ).toLowerCase();

        /*
         * Chặn truy cập dạng navigation
         * từ trình duyệt thông thường.
         */

        const browserNavigation =
            accept.includes("text/html") ||
            fetchMode === "navigate" ||
            fetchDest === "document";

        if (browserNavigation) {
            return res.status(403)
                .type("text/plain")
                .send("LEXINX BLOCK");
        }

        const db = readDB();

        let owner = null;
        let script = null;

        for (
            const username of
                Object.keys(db)
        ) {
            const account = db[username];

            if (
                account?.scripts?.[
                    req.params.id
                ]
            ) {
                owner = account;
                script =
                    account.scripts[
                        req.params.id
                    ];
                break;
            }
        }

        if (!script) {
            return res.status(404)
                .type("text/plain")
                .send("LEXINX BLOCK");
        }

        /*
         * Loader chỉ gọi runtime.
         * Không nhúng source vào L1.
         */

        const runtimeURL =
            `${DOMAIN}/api/runtime/${script.id}`;

        const lua = `
local r = request({
    Url = ${JSON.stringify(runtimeURL)},
    Method = "POST",
    Headers = {
        ["Content-Type"] = "application/json"
    },
    Body = "{}"
})

if not r then
    error("LEXINX BLOCK")
end

if r.StatusCode ~= 200 then
    error("LEXINX BLOCK HTTP " .. tostring(r.StatusCode))
end

local HttpService = game:GetService("HttpService")

local d = HttpService:JSONDecode(r.Body)

if type(d) ~= "table" or d.ok ~= true then
    error("LEXINX BLOCK")
end

if type(d.code) ~= "string" then
    error("LEXINX BLOCK")
end

local fn, err = loadstring(d.code)

if not fn then
    error(err)
end

local ok, runtimeError = pcall(fn)

if not ok then
    error(runtimeError)
end
`.trim();

        res.status(200)
            .type("text/plain")
            .set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            )
            .set(
                "Pragma",
                "no-cache"
            )
            .set(
                "X-Content-Type-Options",
                "nosniff"
            )
            .send(lua);
    }
);

/* =====================================================
   RUNTIME PAYLOAD
===================================================== */

app.post(
    "/api/runtime/:id",
    (req, res) => {

        const db = readDB();

        let script = null;

        for (
            const username of
                Object.keys(db)
        ) {

            const account = db[username];

            if (
                account?.scripts?.[
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
                error: "LEXINX BLOCK"
            });
        }

        try {

            /*
             * QUAN TRỌNG:
             *
             * Source trong DB không bị thay đổi.
             * Mỗi request tạo một payload
             * obfuscate mới.
             */

            const payload =
                obfuscateLua(
                    script.source,
                    {
                        stripComments: true,
                        packStrings: true
                    }
                );

            return res.status(200).json({
                ok: true,
                code: payload
            });

        } catch (error) {

            console.error(
                "[LEXINX OBF]",
                error
            );

            return res.status(500).json({
                ok: false,
                error:
                    "LEXINX PAYLOAD ERROR"
            });
        }
    }
);

/* =====================================================
   UNKNOWN ROUTE
===================================================== */

app.use((req, res) => {
    res.status(404)
        .type("text/plain")
        .send("LEXINX BLOCK");
});

/* =====================================================
   SESSION CLEANUP
===================================================== */

setInterval(() => {

    const now = Date.now();

    for (
        const [
            sessionID,
            session
        ] of sessions
    ) {
        if (
            now >
            session.expiresAt
        ) {
            sessions.delete(
                sessionID
            );
        }
    }

}, 60 * 1000);

/* =====================================================
   START
===================================================== */

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
            "DOMAIN:",
            DOMAIN
        );

        console.log(
            "PORT:",
            PORT
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
