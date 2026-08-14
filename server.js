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
const USERS_FILE = path.join(DATA_DIR, "users.json");
const SCRIPTS_FILE = path.join(DATA_DIR, "scripts.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const ONE_TIME_CODES = new Set([
    "LEXINX_6725YE7726d622",
    "LEXINX_8837yYe7726722"
]);

const PERMANENT_CODE =
    "LEXINX_King_2036";

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

function ensureFile(file) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, "{}", "utf8");
    }
}

ensureFile(USERS_FILE);
ensureFile(SCRIPTS_FILE);
ensureFile(SESSIONS_FILE);

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

function readJSON(file) {
    try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
        return {};
    }
}

function writeJSON(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2),
        "utf8"
    );
}

function randomID(bytes = 16) {
    return crypto.randomBytes(bytes).toString("hex");
}

function hashPassword(password, salt) {
    return crypto
        .scryptSync(password, salt, 64)
        .toString("hex");
}

function verifyPassword(password, salt, storedHash) {
    const hash = hashPassword(password, salt);

    try {
        return crypto.timingSafeEqual(
            Buffer.from(hash, "hex"),
            Buffer.from(storedHash, "hex")
        );
    } catch {
        return false;
    }
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

/* =========================================================
   COOKIE
========================================================= */

function parseCookies(req) {
    const header = req.headers.cookie || "";
    const cookies = {};

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) continue;

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        cookies[key] = decodeURIComponent(value);
    }

    return cookies;
}

function setSessionCookie(res, token) {
    res.setHeader(
        "Set-Cookie",
        `LEXINX_SESSION=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax`
    );
}

function clearSessionCookie(res) {
    res.setHeader(
        "Set-Cookie",
        "LEXINX_SESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
    );
}

/* =========================================================
   SESSION
========================================================= */

function getSession(req) {
    const cookies = parseCookies(req);
    const token = cookies.LEXINX_SESSION;

    if (!token) return null;

    const sessions = readJSON(SESSIONS_FILE);
    const session = sessions[token];

    if (!session) return null;

    const maxAge =
        30 * 24 * 60 * 60 * 1000;

    if (Date.now() - session.createdAt > maxAge) {
        delete sessions[token];
        writeJSON(SESSIONS_FILE, sessions);
        return null;
    }

    const users = readJSON(USERS_FILE);
    const user = users[session.username];

    if (!user) return null;

    return {
        token,
        username: session.username,
        user
    };
}

function requireAuth(req, res, next) {
    const session = getSession(req);

    if (!session) {
        return res.status(401).json({
            ok: false,
            error: "Unauthorized"
        });
    }

    req.auth = session;
    next();
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(PUBLIC_DIR, "index.html")
    );
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", (req, res) => {
    const username =
        String(req.body?.username || "").trim();

    const password =
        String(req.body?.password || "");

    const code =
        String(req.body?.code || "").trim();

    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
        return res.status(400).json({
            ok: false,
            error:
                "Username must be 3-32 characters"
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            ok: false,
            error:
                "Password must be at least 6 characters"
        });
    }

    if (!code) {
        return res.status(400).json({
            ok: false,
            error: "Access code required"
        });
    }

    const users = readJSON(USERS_FILE);

    if (users[username]) {
        return res.status(409).json({
            ok: false,
            error: "Username already exists"
        });
    }

    let accessType;

    if (code === PERMANENT_CODE) {
        accessType = "permanent";
    } else if (ONE_TIME_CODES.has(code)) {
        accessType = "one-time";
    } else {
        return res.status(403).json({
            ok: false,
            error: "Invalid access code"
        });
    }

    /*
       Xóa mã one-time sau khi
       đăng ký thành công.
    */

    if (accessType === "one-time") {
        ONE_TIME_CODES.delete(code);
    }

    const salt =
        crypto.randomBytes(32).toString("hex");

    const passwordHash =
        hashPassword(password, salt);

    users[username] = {
        username,
        passwordHash,
        salt,
        accessType,
        createdAt: Date.now(),
        scripts: []
    };

    writeJSON(USERS_FILE, users);

    const sessions =
        readJSON(SESSIONS_FILE);

    const sessionToken =
        randomID(48);

    sessions[sessionToken] = {
        username,
        createdAt: Date.now()
    };

    writeJSON(
        SESSIONS_FILE,
        sessions
    );

    setSessionCookie(
        res,
        sessionToken
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
        String(req.body?.username || "").trim();

    const password =
        String(req.body?.password || "");

    const users = readJSON(USERS_FILE);
    const user = users[username];

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

    const sessions =
        readJSON(SESSIONS_FILE);

    const token =
        randomID(48);

    sessions[token] = {
        username,
        createdAt: Date.now()
    };

    writeJSON(
        SESSIONS_FILE,
        sessions
    );

    setSessionCookie(
        res,
        token
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
    const cookies = parseCookies(req);
    const token = cookies.LEXINX_SESSION;

    if (token) {
        const sessions =
            readJSON(SESSIONS_FILE);

        delete sessions[token];

        writeJSON(
            SESSIONS_FILE,
            sessions
        );
    }

    clearSessionCookie(res);

    res.json({
        ok: true
    });
});

/* =========================================================
   ACCOUNT
========================================================= */

app.get("/api/me", requireAuth, (req, res) => {
    const user = req.auth.user;

    res.json({
        ok: true,
        username: user.username,
        accessType: user.accessType,
        createdAt: user.createdAt,
        scriptCount: user.scripts.length
    });
});

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post("/api/create", requireAuth, (req, res) => {
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
        randomID(16);

    const scriptToken =
        randomID(32);

    const db =
        readJSON(SCRIPTS_FILE);

    db[id] = {
        id,
        name,
        source,
        owner: req.auth.username,
        token: scriptToken,
        createdAt: Date.now(),
        updatedAt: Date.now()
    };

    writeJSON(
        SCRIPTS_FILE,
        db
    );

    const users =
        readJSON(USERS_FILE);

    users[
        req.auth.username
    ].scripts.push(id);

    writeJSON(
        USERS_FILE,
        users
    );

    const endpoint =
        `${DOMAIN}/api/${id}/${scriptToken}`;

    const loader =
        `loadstring(game:HttpGet("${endpoint}"))()`;

    res.json({
        ok: true,
        id,
        name,
        endpoint,
        loader
    });
});

/* =========================================================
   LIST SCRIPTS
========================================================= */

app.get("/api/scripts", requireAuth, (req, res) => {
    const db =
        readJSON(SCRIPTS_FILE);

    const ids =
        req.auth.user.scripts;

    const scripts =
        ids
            .map(id => db[id])
            .filter(Boolean)
            .map(script => {

                const endpoint =
                    `${DOMAIN}/api/${script.id}/${script.token}`;

                return {
                    id: script.id,
                    name: script.name,
                    createdAt: script.createdAt,
                    updatedAt: script.updatedAt,

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
});

/* =========================================================
   GET ONE SCRIPT FOR EDITOR
========================================================= */

app.get(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const db =
            readJSON(SCRIPTS_FILE);

        const script =
            db[req.params.id];

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
                createdAt: script.createdAt,
                updatedAt: script.updatedAt
            }
        });
    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const id =
            req.params.id;

        const db =
            readJSON(SCRIPTS_FILE);

        const script =
            db[id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        /*
           Chỉ owner mới được sửa.
        */

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

        const newSource =
            typeof req.body?.source ===
            "string"
                ? req.body.source
                : script.source;

        const newName =
            req.body?.name !== undefined
                ? cleanName(req.body.name)
                : script.name;

        if (!newSource.trim()) {
            return res.status(400).json({
                ok: false,
                error:
                    "Script cannot be empty"
            });
        }

        /*
           Cập nhật source.

           ID + token KHÔNG đổi.
           Loader cũ vẫn chạy source mới.
        */

        script.name =
            newName;

        script.source =
            newSource;

        script.updatedAt =
            Date.now();

        db[id] =
            script;

        writeJSON(
            SCRIPTS_FILE,
            db
        );

        const endpoint =
            `${DOMAIN}/api/${script.id}/${script.token}`;

        const loader =
            `loadstring(game:HttpGet("${endpoint}"))()`;

        res.json({
            ok: true,

            message:
                "Script updated",

            id:
                script.id,

            name:
                script.name,

            updatedAt:
                script.updatedAt,

            endpoint,

            loader
        });
    }
);

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const id =
            req.params.id;

        const db =
            readJSON(SCRIPTS_FILE);

        const script =
            db[id];

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

        delete db[id];

        writeJSON(
            SCRIPTS_FILE,
            db
        );

        const users =
            readJSON(USERS_FILE);

        users[
            req.auth.username
        ].scripts =
            users[
                req.auth.username
            ].scripts.filter(
                x => x !== id
            );

        writeJSON(
            USERS_FILE,
            users
        );

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   LUA SOURCE ENDPOINT
========================================================= */

app.get(
    "/api/:id/:token",
    (req, res) => {

        const {
            id,
            token
        } = req.params;

        const db =
            readJSON(SCRIPTS_FILE);

        const script =
            db[id];

        if (!script) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX v50 protection"
                );
        }

        if (
            token !==
            script.token
        ) {
            return res
                .status(403)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX v50 protection"
                );
        }

        /*
           Loader lấy source mới nhất.
           Vì script.source đã được edit
           nên loader cũ tự nhận source mới.
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

app.use((req, res) => {
    res
        .status(404)
        .type("text/plain")
        .send(
            "Blocked by LEXINX v50 protection"
        );
});

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "================================="
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
            "================================="
        );
    }
);
