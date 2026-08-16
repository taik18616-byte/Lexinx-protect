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

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify({
            users: {}
        }, null, 2),
        "utf8"
    );
}

app.disable("x-powered-by");

app.use(express.json({
    limit: "20mb"
}));

app.use(express.static(PUBLIC_DIR));

/* =====================================================
   DATABASE
===================================================== */

function readDB() {
    try {
        const data = JSON.parse(
            fs.readFileSync(DB_FILE, "utf8")
        );

        if (!data.users) {
            data.users = {};
        }

        return data;
    } catch {
        return {
            users: {}
        };
    }
}

function writeDB(db) {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );
}

/* =====================================================
   SECURITY
===================================================== */

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function hashPassword(password, salt) {
    return crypto
        .scryptSync(
            password,
            salt,
            64
        )
        .toString("hex");
}

function cleanName(name) {
    return String(
        name || "Script"
    )
        .replace(
            /[^\w .-]/g,
            "_"
        )
        .slice(0, 80);
}

function validUsername(username) {
    return /^[a-zA-Z0-9_]{3,32}$/
        .test(username);
}

function validPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 6 &&
        password.length <= 128
    );
}

/* =====================================================
   SESSION
===================================================== */

const sessions = new Map();

function createSession(userId) {

    const token =
        randomHex(48);

    sessions.set(
        token,
        {
            userId,
            createdAt: Date.now(),
            expiresAt:
                Date.now() +
                SESSION_TTL
        }
    );

    return token;
}

function getSession(req) {

    const header =
        req.headers.authorization;

    if (
        typeof header !== "string"
    ) {
        return null;
    }

    if (
        !header.startsWith(
            "Bearer "
        )
    ) {
        return null;
    }

    const token =
        header.slice(7).trim();

    if (!token) {
        return null;
    }

    const session =
        sessions.get(token);

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expiresAt
    ) {
        sessions.delete(token);
        return null;
    }

    return {
        token,
        ...session
    };
}

function requireAuth(
    req,
    res,
    next
) {

    const session =
        getSession(req);

    if (!session) {
        return res.status(401).json({
            ok: false,
            error: "Not logged in"
        });
    }

    req.userId =
        session.userId;

    req.session =
        session;

    next();
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

app.post(
    "/api/auth/register",
    (req, res) => {

        const username =
            String(
                req.body?.username ||
                ""
            ).trim();

        const password =
            req.body?.password;

        if (
            !validUsername(username)
        ) {
            return res.status(400).json({
                ok: false,
                error:
                    "Username must contain 3-32 letters, numbers or _"
            });
        }

        if (
            !validPassword(password)
        ) {
            return res.status(400).json({
                ok: false,
                error:
                    "Password must contain 6-128 characters"
            });
        }

        const db =
            readDB();

        const key =
            username.toLowerCase();

        if (
            db.users[key]
        ) {
            return res.status(409).json({
                ok: false,
                error:
                    "Username already exists"
            });
        }

        const userId =
            randomHex(16);

        const salt =
            randomHex(16);

        const passwordHash =
            hashPassword(
                password,
                salt
            );

        db.users[key] = {

            id:
                userId,

            username,

            passwordHash,

            salt,

            createdAt:
                Date.now(),

            scripts: {}

        };

        writeDB(db);

        const session =
            createSession(
                userId
            );

        res.json({

            ok: true,

            username,

            session

        });
    }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
    "/api/auth/login",
    (req, res) => {

        const username =
            String(
                req.body?.username ||
                ""
            ).trim();

        const password =
            req.body?.password;

        const db =
            readDB();

        const user =
            db.users[
                username.toLowerCase()
            ];

        if (!user) {
            return res.status(401).json({
                ok: false,
                error:
                    "Invalid username or password"
            });
        }

        if (
            !validPassword(password)
        ) {
            return res.status(401).json({
                ok: false,
                error:
                    "Invalid username or password"
            });
        }

        const hash =
            hashPassword(
                password,
                user.salt
            );

        const valid =
            crypto.timingSafeEqual(
                Buffer.from(hash),
                Buffer.from(
                    user.passwordHash
                )
            );

        if (!valid) {
            return res.status(401).json({
                ok: false,
                error:
                    "Invalid username or password"
            });
        }

        const session =
            createSession(
                user.id
            );

        res.json({

            ok: true,

            username:
                user.username,

            session

        });
    }
);

/* =====================================================
   LOGOUT
===================================================== */

app.post(
    "/api/auth/logout",
    requireAuth,
    (req, res) => {

        if (req.session?.token) {
            sessions.delete(
                req.session.token
            );
        }

        res.json({
            ok: true
        });
    }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
    "/api/auth/me",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const user =
            Object.values(
                db.users
            ).find(
                u =>
                    u.id ===
                    req.userId
            );

        if (!user) {
            return res.status(404).json({
                ok: false,
                error:
                    "User not found"
            });
        }

        res.json({

            ok: true,

            user: {
                id:
                    user.id,

                username:
                    user.username,

                createdAt:
                    user.createdAt
            }

        });
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

        const db =
            readDB();

        const user =
            Object.values(
                db.users
            ).find(
                u =>
                    u.id ===
                    req.userId
            );

        if (!user) {
            return res.status(404).json({
                ok: false,
                error:
                    "User not found"
            });
        }

        const id =
            randomHex(12);

        /*
         * QUAN TRỌNG:
         * Script nằm trong user.scripts,
         * không nằm ở database chung.
         */

        user.scripts[id] = {

            id,

            name,

            source,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()

        };

        writeDB(db);

        res.json({

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
   LIST USER SCRIPTS
===================================================== */

app.get(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const user =
            Object.values(
                db.users
            ).find(
                u =>
                    u.id ===
                    req.userId
            );

        if (!user) {
            return res.status(404).json({
                ok: false,
                error:
                    "User not found"
            });
        }

        const scripts =
            Object.values(
                user.scripts || {}
            )
                .reverse()
                .map(
                    script => ({

                        id:
                            script.id,

                        name:
                            script.name,

                        createdAt:
                            script.createdAt,

                        updatedAt:
                            script.updatedAt,

                        loader:
                            `loadstring(game:HttpGet(${JSON.stringify(
                                `${DOMAIN}/api/loader/${script.id}`
                            )}))()`

                    })
                );

        res.json({

            ok: true,

            scripts

        });
    }
);

/* =====================================================
   GET OWN SCRIPT
===================================================== */

app.get(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const user =
            Object.values(
                db.users
            ).find(
                u =>
                    u.id ===
                    req.userId
            );

        if (!user) {
            return res.status(404).json({
                ok: false,
                error:
                    "User not found"
            });
        }

        const script =
            user.scripts[
                req.params.id
            ];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        res.json({

            ok: true,

            script: {

                id:
                    script.id,

                name:
                    script.name,

                source:
                    script.source,

                createdAt:
                    script.createdAt,

                updatedAt:
                    script.updatedAt

            }

        });
    }
);

/* =====================================================
   EDIT OWN SCRIPT
===================================================== */

app.put(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const user =
            Object.values(
                db.users
            ).find(
                u =>
                    u.id ===
                    req.userId
            );

        if (!user) {
            return res.status(404).json({
                ok: false,
                error:
                    "User not found"
            });
        }

        const script =
            user.scripts[
                req.params.id
            ];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
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
                    error:
                        "Script is empty"
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

            id:
                script.id,

            name:
                script.name

        });
    }
);

/* =====================================================
   DELETE OWN SCRIPT
===================================================== */

app.delete(
    "/api/scripts/:id",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const user =
            Object.values(
                db.users
            ).find(
                u =>
                    u.id ===
                    req.userId
            );

        if (!user) {
            return res.status(404).json({
                ok: false,
                error:
                    "User not found"
            });
        }

        if (
            !user.scripts[
                req.params.id
            ]
        ) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
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

/* =====================================================
   LOADER
=====================================================

   Chỉ xác định script theo ID.
   Việc cấp quyền quản trị web vẫn dựa
   trên session tài khoản.
===================================================== */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const db =
            readDB();

        let found = null;

        for (
            const user of
            Object.values(
                db.users
            )
        ) {

            if (
                user.scripts &&
                user.scripts[
                    req.params.id
                ]
            ) {

                found = {
                    user,
                    script:
                        user.scripts[
                            req.params.id
                        ]
                };

                break;
            }
        }

        if (!found) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
         * Không trả source trực tiếp ở đây.
         * Endpoint loader chỉ xác định script tồn tại.
         */

        res
            .type("text/plain")
            .set(
                "Cache-Control",
                "no-store"
            )
            .send(
                "LEXINX SCRIPT READY"
            );
    }
);

/* =====================================================
   UNKNOWN API
===================================================== */

app.use(
    "/api",
    (req, res) => {

        res
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX BLOCK"
            );
    }
);

/* =====================================================
   404
===================================================== */

app.use(
    (req, res) => {

        res
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX BLOCK"
            );
    }
);

/* =====================================================
   SESSION CLEANUP
===================================================== */

setInterval(
    () => {

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

    },
    60 * 1000
);

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
            "USER ISOLATION: ENABLED"
        );

        console.log(
            "================================"
        );
    }
);
