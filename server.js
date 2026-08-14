const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect-2.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const PUBLIC_DIR = path.join(__dirname, "public");

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SCRIPTS_FILE = path.join(DATA_DIR, "scripts.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");

const ONE_TIME_CODES = new Set([
    "LEXINX_6725YE7726d622",
    "LEXINX_8837yYe7726722"
]);

const PERMANENT_CODE =
    "LEXINX_King_2036";

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

function initFile(file) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, "{}", "utf8");
    }
}

initFile(USERS_FILE);
initFile(SCRIPTS_FILE);
initFile(SESSIONS_FILE);

app.use(express.json({
    limit: "20mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "20mb"
}));

app.use(express.static(PUBLIC_DIR));

function readDB(file) {
    try {
        return JSON.parse(
            fs.readFileSync(file, "utf8")
        );
    } catch {
        return {};
    }
}

function writeDB(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2),
        "utf8"
    );
}

function randomID(bytes = 16) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

function hashPassword(password, salt) {
    return crypto
        .scryptSync(password, salt, 64)
        .toString("hex");
}

function checkPassword(password, salt, hash) {
    try {
        const a = Buffer.from(
            hashPassword(password, salt),
            "hex"
        );

        const b = Buffer.from(
            hash,
            "hex"
        );

        return a.length === b.length &&
            crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

/* =========================================================
   COOKIE
========================================================= */

function cookies(req) {
    const result = {};

    for (
        const item of
        String(req.headers.cookie || "").split(";")
    ) {
        const i = item.indexOf("=");

        if (i === -1) continue;

        result[
            item.slice(0, i).trim()
        ] =
            decodeURIComponent(
                item.slice(i + 1).trim()
            );
    }

    return result;
}

/* =========================================================
   SESSION
========================================================= */

function session(req) {

    const token =
        cookies(req).LEXINX_SESSION;

    if (!token) return null;

    const sessions =
        readDB(SESSIONS_FILE);

    const s =
        sessions[token];

    if (!s) return null;

    const MAX_AGE =
        30 * 24 * 60 * 60 * 1000;

    if (
        Date.now() - s.createdAt >
        MAX_AGE
    ) {
        delete sessions[token];

        writeDB(
            SESSIONS_FILE,
            sessions
        );

        return null;
    }

    const users =
        readDB(USERS_FILE);

    if (!users[s.username])
        return null;

    return {
        token,
        username: s.username,
        user: users[s.username]
    };
}

function auth(req, res, next) {

    const s = session(req);

    if (!s) {
        return res.status(401).json({
            ok: false,
            error: "Unauthorized"
        });
    }

    req.auth = s;

    next();
}

/* =========================================================
   BROWSER FILTER
========================================================= */

function browserRequest(req) {

    const ua =
        String(
            req.headers["user-agent"] || ""
        ).toLowerCase();

    const accept =
        String(
            req.headers["accept"] || ""
        ).toLowerCase();

    /*
       Đây chỉ là heuristic.
       Không thể chứng minh tuyệt đối
       request đến từ Roblox.
    */

    if (
        ua.includes("mozilla") &&
        (
            accept.includes("text/html") ||
            accept.includes("application/xhtml")
        )
    ) {
        return true;
    }

    return false;
}

/* =========================================================
   HOME
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
========================================================= */

app.post("/api/register", (req, res) => {

    const username =
        String(
            req.body?.username || ""
        ).trim();

    const password =
        String(
            req.body?.password || ""
        );

    const code =
        String(
            req.body?.code || ""
        ).trim();

    if (
        !/^[a-zA-Z0-9_]{3,32}$/
            .test(username)
    ) {
        return res.status(400).json({
            ok: false,
            error:
                "Invalid username"
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            ok: false,
            error:
                "Password must contain at least 6 characters"
        });
    }

    const users =
        readDB(USERS_FILE);

    if (users[username]) {
        return res.status(409).json({
            ok: false,
            error:
                "Username already exists"
        });
    }

    let accessType;

    if (code === PERMANENT_CODE) {

        accessType =
            "permanent";

    } else if (
        ONE_TIME_CODES.has(code)
    ) {

        accessType =
            "one-time";

    } else {

        return res.status(403).json({
            ok: false,
            error:
                "Invalid access code"
        });
    }

    /*
       One-time code bị xoá sau
       khi đăng ký thành công.
    */

    if (
        accessType ===
        "one-time"
    ) {
        ONE_TIME_CODES.delete(code);
    }

    const salt =
        crypto
            .randomBytes(32)
            .toString("hex");

    users[username] = {
        username,
        salt,
        passwordHash:
            hashPassword(
                password,
                salt
            ),
        accessType,
        createdAt: Date.now(),
        scripts: []
    };

    writeDB(
        USERS_FILE,
        users
    );

    const token =
        randomID(48);

    const sessions =
        readDB(SESSIONS_FILE);

    sessions[token] = {
        username,
        createdAt: Date.now()
    };

    writeDB(
        SESSIONS_FILE,
        sessions
    );

    res.setHeader(
        "Set-Cookie",
        `LEXINX_SESSION=${token}; Path=/; HttpOnly; SameSite=Lax`
    );

    res.json({
        ok: true,
        username,
        accessType
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

    const users =
        readDB(USERS_FILE);

    const user =
        users[username];

    if (
        !user ||
        !checkPassword(
            password,
            user.salt,
            user.passwordHash
        )
    ) {
        return res.status(401).json({
            ok: false,
            error:
                "Invalid username or password"
        });
    }

    const token =
        randomID(48);

    const sessions =
        readDB(SESSIONS_FILE);

    sessions[token] = {
        username,
        createdAt: Date.now()
    };

    writeDB(
        SESSIONS_FILE,
        sessions
    );

    res.setHeader(
        "Set-Cookie",
        `LEXINX_SESSION=${token}; Path=/; HttpOnly; SameSite=Lax`
    );

    res.json({
        ok: true,
        username,
        accessType:
            user.accessType
    });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {

    const token =
        cookies(req).LEXINX_SESSION;

    if (token) {

        const sessions =
            readDB(SESSIONS_FILE);

        delete sessions[token];

        writeDB(
            SESSIONS_FILE,
            sessions
        );
    }

    res.setHeader(
        "Set-Cookie",
        "LEXINX_SESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
    );

    res.json({
        ok: true
    });
});

/* =========================================================
   ME
========================================================= */

app.get(
    "/api/me",
    auth,
    (req, res) => {

        res.json({
            ok: true,
            username:
                req.auth.user.username,
            accessType:
                req.auth.user.accessType,
            scriptCount:
                req.auth.user.scripts.length
        });
    }
);

/* =========================================================
   CREATE
========================================================= */

app.post(
    "/api/create",
    auth,
    (req, res) => {

        const source =
            typeof req.body?.source ===
            "string"
                ? req.body.source
                : "";

        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error:
                    "Script is empty"
            });
        }

        const name =
            cleanName(
                req.body?.name
            );

        const id =
            randomID(16);

        const token =
            randomID(32);

        const scripts =
            readDB(SCRIPTS_FILE);

        scripts[id] = {
            id,
            token,
            name,
            source,
            owner:
                req.auth.username,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        writeDB(
            SCRIPTS_FILE,
            scripts
        );

        const users =
            readDB(USERS_FILE);

        users[
            req.auth.username
        ].scripts.push(id);

        writeDB(
            USERS_FILE,
            users
        );

        const endpoint =
            `${DOMAIN}/api/${id}/${token}`;

        res.json({
            ok: true,
            id,
            name,
            endpoint,
            loader:
                `loadstring(game:HttpGet("${endpoint}"))()`
        });
    }
);

/* =========================================================
   LIST
========================================================= */

app.get(
    "/api/scripts",
    auth,
    (req, res) => {

        const scripts =
            readDB(SCRIPTS_FILE);

        const list =
            req.auth.user.scripts
                .map(id => scripts[id])
                .filter(Boolean)
                .map(s => {

                    const endpoint =
                        `${DOMAIN}/api/${s.id}/${s.token}`;

                    return {
                        id: s.id,
                        name: s.name,
                        createdAt:
                            s.createdAt,
                        updatedAt:
                            s.updatedAt,
                        endpoint,
                        loader:
                            `loadstring(game:HttpGet("${endpoint}"))()`
                    };
                })
                .reverse();

        res.json({
            ok: true,
            scripts: list
        });
    }
);

/* =========================================================
   GET SCRIPT FOR EDIT
========================================================= */

app.get(
    "/api/scripts/:id",
    auth,
    (req, res) => {

        const scripts =
            readDB(SCRIPTS_FILE);

        const script =
            scripts[req.params.id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        if (
            script.owner !==
            req.auth.username
        ) {
            return res.status(403).json({
                ok: false,
                error:
                    "Forbidden"
            });
        }

        res.json({
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
   EDIT
========================================================= */

app.put(
    "/api/scripts/:id",
    auth,
    (req, res) => {

        const scripts =
            readDB(SCRIPTS_FILE);

        const script =
            scripts[req.params.id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        if (
            script.owner !==
            req.auth.username
        ) {
            return res.status(403).json({
                ok: false,
                error:
                    "Forbidden"
            });
        }

        const source =
            typeof req.body?.source ===
            "string"
                ? req.body.source
                : script.source;

        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error:
                    "Script is empty"
            });
        }

        script.name =
            cleanName(
                req.body?.name ||
                script.name
            );

        script.source =
            source;

        script.updatedAt =
            Date.now();

        scripts[script.id] =
            script;

        writeDB(
            SCRIPTS_FILE,
            scripts
        );

        const endpoint =
            `${DOMAIN}/api/${script.id}/${script.token}`;

        res.json({
            ok: true,
            id: script.id,
            name: script.name,
            endpoint,
            loader:
                `loadstring(game:HttpGet("${endpoint}"))()`
        });
    }
);

/* =========================================================
   DELETE
========================================================= */

app.delete(
    "/api/scripts/:id",
    auth,
    (req, res) => {

        const scripts =
            readDB(SCRIPTS_FILE);

        const script =
            scripts[req.params.id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        if (
            script.owner !==
            req.auth.username
        ) {
            return res.status(403).json({
                ok: false,
                error:
                    "Forbidden"
            });
        }

        delete scripts[
            req.params.id
        ];

        writeDB(
            SCRIPTS_FILE,
            scripts
        );

        const users =
            readDB(USERS_FILE);

        users[
            req.auth.username
        ].scripts =
            users[
                req.auth.username
            ].scripts.filter(
                id =>
                    id !==
                    req.params.id
            );

        writeDB(
            USERS_FILE,
            users
        );

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   LUA DELIVERY
========================================================= */

app.get(
    "/api/:id/:token",
    (req, res) => {

        /*
           Browser mở trực tiếp:
           chặn theo heuristic.
        */

        if (browserRequest(req)) {

            return res
                .status(403)
                .type("text/plain")
                .send(
                    "BLOCKED BY LEXINX"
                );
        }

        const scripts =
            readDB(SCRIPTS_FILE);

        const script =
            scripts[req.params.id];

        if (!script) {

            return res
                .status(404)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX v50 protection"
                );
        }

        if (
            req.params.token !==
            script.token
        ) {

            return res
                .status(403)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX"
                );
        }

        /*
           Trả source Lua trực tiếp.
           Khi edit trên web, loader cũ
           tự nhận source mới.
        */

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
                script.source
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
                "Blocked by LEXINX v50 protection"
            );
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
    }
);
