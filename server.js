const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "accounts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_TTL =
    7 * 24 * 60 * 60 * 1000;

fs.mkdirSync(DATA_DIR, {
    recursive: true
});

fs.mkdirSync(PUBLIC_DIR, {
    recursive: true
});

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
        DB_FILE,
        "{}",
        "utf8"
    );
}

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "15mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "15mb"
    })
);

app.use(
    express.static(PUBLIC_DIR)
);

/* =====================================================
   DATABASE
===================================================== */

function readDB() {
    try {
        return JSON.parse(
            fs.readFileSync(
                DB_FILE,
                "utf8"
            )
        );
    } catch {
        return {};
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
   RANDOM
===================================================== */

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

/* =====================================================
   PASSWORD
===================================================== */

function hashPassword(password) {
    const salt =
        crypto.randomBytes(16);

    const hash =
        crypto.scryptSync(
            password,
            salt,
            64
        );

    return {
        salt: salt.toString("hex"),
        hash: hash.toString("hex")
    };
}

function verifyPassword(
    password,
    stored
) {
    try {
        const salt =
            Buffer.from(
                stored.salt,
                "hex"
            );

        const expected =
            Buffer.from(
                stored.hash,
                "hex"
            );

        const actual =
            crypto.scryptSync(
                password,
                salt,
                64
            );

        return (
            actual.length ===
                expected.length &&
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
   USERNAME
===================================================== */

function validUsername(username) {
    return (
        typeof username === "string" &&
        /^[A-Za-z0-9_]{3,24}$/.test(
            username
        )
    );
}

function validPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 6 &&
        password.length <= 128
    );
}

/* =====================================================
   SESSIONS
===================================================== */

const sessions = new Map();

function createSession(username) {
    const sessionID =
        randomHex(48);

    sessions.set(
        sessionID,
        {
            username,
            createdAt: Date.now(),
            expiresAt:
                Date.now() +
                SESSION_TTL
        }
    );

    return sessionID;
}

function parseCookies(req) {
    const cookies = {};
    const header =
        req.headers.cookie || "";

    for (
        const item of header.split(";")
    ) {
        const index =
            item.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            item
                .slice(0, index)
                .trim();

        const value =
            item
                .slice(index + 1)
                .trim();

        cookies[key] =
            decodeURIComponent(
                value
            );
    }

    return cookies;
}

function getSession(req) {
    const cookies =
        parseCookies(req);

    const sessionID =
        cookies.lexinx_session;

    if (!sessionID) {
        return null;
    }

    const session =
        sessions.get(
            sessionID
        );

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expiresAt
    ) {
        sessions.delete(
            sessionID
        );

        return null;
    }

    return {
        sessionID,
        username:
            session.username
    };
}

function setSession(
    res,
    sessionID
) {
    res.setHeader(
        "Set-Cookie",
        [
            `lexinx_session=${encodeURIComponent(
                sessionID
            )}`,
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=604800"
        ].join("; ")
    );
}

function clearSession(res) {
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
   AUTH MIDDLEWARE
===================================================== */

function requireAuth(
    req,
    res,
    next
) {
    const session =
        getSession(req);

    if (!session) {
        return res
            .status(401)
            .json({
                ok: false,
                error:
                    "LOGIN_REQUIRED"
            });
    }

    req.user = session;

    next();
}

/* =====================================================
   CLEAN NAME
===================================================== */

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

/* =====================================================
   HOME
===================================================== */

app.get("/", (req, res) => {
    const session =
        getSession(req);

    if (session) {
        const db =
            readDB();

        const account =
            db[
                session.username
            ];

        if (account) {
            return res.redirect(
                `/acc/${encodeURIComponent(
                    account.username
                )}/${account.accountId}/dashboard`
            );
        }
    }

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
    "/api/register",
    (req, res) => {
        const {
            username,
            password
        } = req.body || {};

        if (
            !validUsername(
                username
            )
        ) {
            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Username phải dài 3-24 ký tự và chỉ gồm A-Z, a-z, 0-9, _"
                });
        }

        if (
            !validPassword(
                password
            )
        ) {
            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Password phải dài từ 6 đến 128 ký tự"
                });
        }

        const db =
            readDB();

        if (db[username]) {
            return res
                .status(409)
                .json({
                    ok: false,
                    error:
                        "Username đã tồn tại"
                });
        }

        const passwordData =
            hashPassword(
                password
            );

        const accountId =
            randomHex(16);

        db[username] = {
            username,

            accountId,

            password: {
                salt:
                    passwordData.salt,
                hash:
                    passwordData.hash
            },

            createdAt:
                Date.now(),

            scripts: {}
        };

        writeDB(db);

        const sessionID =
            createSession(
                username
            );

        setSession(
            res,
            sessionID
        );

        res.json({
            ok: true,

            username,

            accountId,

            url:
                `${DOMAIN}/acc/${encodeURIComponent(
                    username
                )}/${accountId}/dashboard`
        });
    }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
    "/api/login",
    (req, res) => {
        const {
            username,
            password
        } = req.body || {};

        if (
            typeof username !==
                "string" ||
            typeof password !==
                "string"
        ) {
            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Thông tin đăng nhập không hợp lệ"
                });
        }

        const db =
            readDB();

        const account =
            db[username];

        if (
            !account ||
            !verifyPassword(
                password,
                account.password
            )
        ) {
            return res
                .status(401)
                .json({
                    ok: false,
                    error:
                        "Username hoặc password không đúng"
                });
        }

        const sessionID =
            createSession(
                username
            );

        setSession(
            res,
            sessionID
        );

        res.json({
            ok: true,

            username,

            accountId:
                account.accountId,

            url:
                `${DOMAIN}/acc/${encodeURIComponent(
                    account.username
                )}/${account.accountId}/dashboard`
        });
    }
);

/* =====================================================
   LOGOUT
===================================================== */

app.post(
    "/api/logout",
    (req, res) => {
        const session =
            getSession(req);

        if (session) {
            sessions.delete(
                session.sessionID
            );
        }

        clearSession(res);

        res.json({
            ok: true
        });
    }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {
        const db =
            readDB();

        const account =
            db[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        res.json({
            ok: true,

            username:
                account.username,

            accountId:
                account.accountId,

            url:
                `${DOMAIN}/acc/${encodeURIComponent(
                    account.username
                )}/${account.accountId}/dashboard`
        });
    }
);

/* =====================================================
   PRIVATE ACCOUNT DASHBOARD
===================================================== */

app.get(
    "/acc/:username/:accountId/dashboard",
    (req, res) => {
        const session =
            getSession(req);

        if (!session) {
            return res.redirect(
                "/"
            );
        }

        const db =
            readDB();

        const account =
            db[
                req.params.username
            ];

        if (!account) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        if (
            account.accountId !==
            req.params.accountId
        ) {
            return res
                .status(403)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        if (
            session.username !==
            account.username
        ) {
            return res
                .status(403)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
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
        const {
            name,
            source
        } = req.body || {};

        if (
            typeof source !==
                "string" ||
            !source.trim()
        ) {
            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Script rỗng"
                });
        }

        const db =
            readDB();

        const account =
            db[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        const id =
            randomHex(12);

        account.scripts[id] = {
            id,

            name:
                cleanName(name),

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

            name:
                account.scripts[id]
                    .name,

            createdAt:
                account.scripts[id]
                    .createdAt
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
        const db =
            readDB();

        const account =
            db[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        const scripts =
            Object.values(
                account.scripts || {}
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
                            script.updatedAt
                    })
                );

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
        const db =
            readDB();

        const account =
            db[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        const script =
            account.scripts[
                req.params.id
            ];

        if (!script) {
            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script không tồn tại"
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
   EDIT SCRIPT
===================================================== */

app.post(
    "/api/edit/:id",
    requireAuth,
    (req, res) => {
        const db =
            readDB();

        const account =
            db[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        const script =
            account.scripts[
                req.params.id
            ];

        if (!script) {
            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script không tồn tại"
                });
        }

        if (
            typeof req.body?.name ===
            "string"
        ) {
            script.name =
                cleanName(
                    req.body.name
                );
        }

        if (
            typeof req.body?.source ===
            "string"
        ) {
            if (
                !req.body.source.trim()
            ) {
                return res
                    .status(400)
                    .json({
                        ok: false,
                        error:
                            "Script rỗng"
                    });
            }

            script.source =
                req.body.source;
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
   DELETE SCRIPT
===================================================== */

app.delete(
    "/api/delete/:id",
    requireAuth,
    (req, res) => {
        const db =
            readDB();

        const account =
            db[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        if (
            !account.scripts[
                req.params.id
            ]
        ) {
            return res
                .status(404)
                .json({
                    ok: false
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
   SESSION CLEANUP
===================================================== */

setInterval(
    () => {
        const now =
            Date.now();

        for (
            const [
                id,
                session
            ] of sessions
        ) {
            if (
                now >
                session.expiresAt
            ) {
                sessions.delete(
                    id
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
            "================================"
        );
    }
);
