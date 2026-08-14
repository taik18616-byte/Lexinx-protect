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
const DB_FILE = path.join(DATA_DIR, "database.json");
const PUBLIC_DIR = path.join(__dirname, "public");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify({
            users: {},
            sessions: {}
        }, null, 2),
        "utf8"
    );
}

app.use(express.json({
    limit: "20mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "20mb"
}));

app.use(express.static(PUBLIC_DIR));

/* =========================================================
   DATABASE
========================================================= */

function readDB() {
    try {
        const data = JSON.parse(
            fs.readFileSync(DB_FILE, "utf8")
        );

        if (!data.users) data.users = {};
        if (!data.sessions) data.sessions = {};

        return data;

    } catch {
        return {
            users: {},
            sessions: {}
        };
    }
}

function writeDB(db) {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify(db, null, 2),
        "utf8"
    );
}

/* =========================================================
   ID / RANDOM
========================================================= */

function randomHex(bytes = 16) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function createScriptID() {
    return randomHex(12);
}

function createSessionID() {
    return randomHex(32);
}

function createPassword() {
    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    let result = "";

    for (let i = 0; i < 14; i++) {
        result += chars[
            crypto.randomInt(0, chars.length)
        ];
    }

    return result;
}

function createUsername(db) {
    let username;

    do {
        username =
            "LEXINX_" +
            crypto
                .randomBytes(5)
                .toString("hex")
                .toUpperCase();

    } while (db.users[username]);

    return username;
}

/* =========================================================
   PASSWORD HASH
========================================================= */

function hashPassword(password, salt = randomHex(16)) {
    const hash = crypto.scryptSync(
        password,
        salt,
        64
    ).toString("hex");

    return {
        salt,
        hash
    };
}

function verifyPassword(password, user) {
    try {
        const hash = crypto.scryptSync(
            password,
            user.salt,
            64
        ).toString("hex");

        return crypto.timingSafeEqual(
            Buffer.from(hash, "hex"),
            Buffer.from(user.hash, "hex")
        );

    } catch {
        return false;
    }
}

/* =========================================================
   COOKIE
========================================================= */

function parseCookies(req) {
    const header = req.headers.cookie || "";
    const cookies = {};

    header.split(";").forEach(part => {
        const index = part.indexOf("=");

        if (index === -1) return;

        const key =
            part.slice(0, index).trim();

        const value =
            part.slice(index + 1).trim();

        cookies[key] =
            decodeURIComponent(value);
    });

    return cookies;
}

function setSessionCookie(res, sessionID) {
    res.setHeader(
        "Set-Cookie",
        `LEXINX_SESSION=${encodeURIComponent(sessionID)}; Path=/; HttpOnly; SameSite=Lax`
    );
}

function clearSessionCookie(res) {
    res.setHeader(
        "Set-Cookie",
        "LEXINX_SESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
    );
}

/* =========================================================
   AUTH
========================================================= */

function getCurrentUser(req) {
    const cookies = parseCookies(req);
    const sessionID =
        cookies.LEXINX_SESSION;

    if (!sessionID) {
        return null;
    }

    const db = readDB();

    const session =
        db.sessions[sessionID];

    if (!session) {
        return null;
    }

    const user =
        db.users[session.username];

    if (!user) {
        delete db.sessions[sessionID];
        writeDB(db);
        return null;
    }

    return {
        username: session.username,
        user
    };
}

function requireAuth(req, res, next) {
    const current =
        getCurrentUser(req);

    if (!current) {
        return res.status(401).json({
            ok: false,
            error: "Not logged in"
        });
    }

    req.currentUser =
        current;

    next();
}

/* =========================================================
   WEB
========================================================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            PUBLIC_DIR,
            "index.html"
        )
    );
});

/* =========================================================
   REGISTER
   Tự tạo username + password
========================================================= */

app.post("/api/register", (req, res) => {
    const db = readDB();

    const username =
        createUsername(db);

    const password =
        createPassword();

    const passwordData =
        hashPassword(password);

    db.users[username] = {
        username,

        salt:
            passwordData.salt,

        hash:
            passwordData.hash,

        createdAt:
            Date.now(),

        scripts: {}
    };

    const sessionID =
        createSessionID();

    db.sessions[sessionID] = {
        username,
        createdAt: Date.now()
    };

    writeDB(db);

    setSessionCookie(
        res,
        sessionID
    );

    res.json({
        ok: true,
        username,
        password
    });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", (req, res) => {
    const username =
        String(
            req.body?.username || ""
        ).trim();

    const password =
        String(
            req.body?.password || ""
        );

    if (!username || !password) {
        return res.status(400).json({
            ok: false,
            error: "Username and password are required"
        });
    }

    const db = readDB();

    const user =
        db.users[username];

    if (!user) {
        return res.status(401).json({
            ok: false,
            error: "Invalid username or password"
        });
    }

    if (
        !verifyPassword(
            password,
            user
        )
    ) {
        return res.status(401).json({
            ok: false,
            error: "Invalid username or password"
        });
    }

    const sessionID =
        createSessionID();

    db.sessions[sessionID] = {
        username,
        createdAt: Date.now()
    };

    writeDB(db);

    setSessionCookie(
        res,
        sessionID
    );

    res.json({
        ok: true,
        username
    });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
    const cookies =
        parseCookies(req);

    const sessionID =
        cookies.LEXINX_SESSION;

    if (sessionID) {
        const db = readDB();

        delete db.sessions[
            sessionID
        ];

        writeDB(db);
    }

    clearSessionCookie(res);

    res.json({
        ok: true
    });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        const user =
            req.currentUser.user;

        res.json({
            ok: true,

            username:
                user.username,

            createdAt:
                user.createdAt,

            scriptCount:
                Object.keys(
                    user.scripts || {}
                ).length
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
            String(
                req.body?.name ||
                "Script"
            )
                .replace(
                    /[^\w .-]/g,
                    "_"
                )
                .slice(0, 80);

        const id =
            createScriptID();

        const db = readDB();

        const username =
            req.currentUser.username;

        const user =
            db.users[username];

        if (!user.scripts) {
            user.scripts = {};
        }

        user.scripts[id] = {
            id,
            name,
            source,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        writeDB(db);

        const endpoint =
            `${DOMAIN}/api/${id}`;

        const loader =
            `loadstring(game:HttpGet("${endpoint}"))()`;

        res.json({
            ok: true,
            id,
            name,
            endpoint,
            loader
        });
    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.post(
    "/api/edit/:id",
    requireAuth,
    (req, res) => {

        const id =
            req.params.id;

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

        const username =
            req.currentUser.username;

        const user =
            db.users[username];

        const script =
            user.scripts?.[id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        script.source =
            source;

        if (
            typeof req.body?.name ===
            "string" &&
            req.body.name.trim()
        ) {
            script.name =
                req.body.name
                    .replace(
                        /[^\w .-]/g,
                        "_"
                    )
                    .slice(0, 80);
        }

        script.updatedAt =
            Date.now();

        writeDB(db);

        const endpoint =
            `${DOMAIN}/api/${id}`;

        res.json({
            ok: true,

            id,

            name:
                script.name,

            endpoint,

            loader:
                `loadstring(game:HttpGet("${endpoint}"))()`
        });
    }
);

/* =========================================================
   LIST USER SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const user =
            req.currentUser.user;

        const scripts =
            Object.values(
                user.scripts || {}
            )
                .map(script => {

                    const endpoint =
                        `${DOMAIN}/api/${script.id}`;

                    return {
                        id:
                            script.id,

                        name:
                            script.name,

                        createdAt:
                            script.createdAt,

                        updatedAt:
                            script.updatedAt,

                        endpoint,

                        loader:
                            `loadstring(game:HttpGet("${endpoint}"))()`
                    };
                })
                .reverse();

        res.json({
            ok: true,
            scripts
        });
    }
);

/* =========================================================
   GET SOURCE FOR EDITOR
========================================================= */

app.get(
    "/api/source/:id",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const user =
            db.users[
                req.currentUser.username
            ];

        const script =
            user.scripts?.[
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

            id:
                script.id,

            name:
                script.name,

            source:
                script.source
        });
    }
);

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete(
    "/api/delete/:id",
    requireAuth,
    (req, res) => {

        const db = readDB();

        const user =
            db.users[
                req.currentUser.username
            ];

        if (
            !user.scripts?.[
                req.params.id
            ]
        ) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        delete user.scripts[
            req.params.id
        ];

        writeDB(db);

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   LUA SOURCE ENDPOINT
   Không yêu cầu tài khoản.
   Loader chỉ cần URL.
   Chặn browser thông thường bằng User-Agent.
========================================================= */

function looksLikeRoblox(req) {
    const ua =
        String(
            req.headers["user-agent"] || ""
        ).toLowerCase();

    return (
        ua.includes("roblox") ||
        ua.includes("robloxapp")
    );
}

app.get(
    "/api/:id",
    (req, res) => {

        /*
            Chặn trình duyệt thông thường.
        */

        if (!looksLikeRoblox(req)) {
            return res
                .status(403)
                .type("text/plain")
                .send(
                    "LEXINX PROTECT\n\n" +
                    "This endpoint is only available to Roblox."
                );
        }

        const id =
            req.params.id;

        const db = readDB();

        /*
            Tìm script trong toàn bộ tài khoản.
            ID script là random nên mỗi script khác nhau.
        */

        let foundScript = null;

        for (
            const username of
            Object.keys(db.users)
        ) {

            const user =
                db.users[username];

            if (
                user.scripts &&
                user.scripts[id]
            ) {
                foundScript =
                    user.scripts[id];

                break;
            }
        }

        if (!foundScript) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "Script not found."
                );
        }

        res
            .status(200)
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
            .send(
                foundScript.source
            );
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {
        res
            .status(404)
            .type("text/plain")
            .send(
                "Blocked by LEXINX PROTECT"
            );
    }
);

/* =========================================================
   START
========================================================= */

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
            "PORT:",
            PORT
        );

        console.log(
            "DOMAIN:",
            DOMAIN
        );

        console.log(
            "================================"
        );
    }
);
