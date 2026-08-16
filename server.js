const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://lexinx-protect.onrender.com";

const TURNSTILE_SECRET =
    process.env.TURNSTILE_SECRET_KEY || "";

const DATA_DIR =
    path.join(__dirname, "data");

const DB_FILE =
    path.join(DATA_DIR, "accounts.json");

const PUBLIC_DIR =
    path.join(__dirname, "public");

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

function createAccountID() {
    return randomHex(16);
}

function createScriptID() {
    return randomHex(12);
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
        salt:
            salt.toString("hex"),

        hash:
            hash.toString("hex")
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
   COOKIE
===================================================== */

function parseCookies(req) {
    const result = {};

    const header =
        req.headers.cookie;

    if (!header) {
        return result;
    }

    for (
        const item
        of header.split(";")
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

        result[key] =
            decodeURIComponent(value);
    }

    return result;
}

/* =====================================================
   SESSION
===================================================== */

const sessions = new Map();

function createSession(username) {
    const sessionID =
        randomHex(48);

    sessions.set(
        sessionID,
        {
            username,
            createdAt:
                Date.now(),
            expiresAt:
                Date.now() +
                SESSION_TTL
        }
    );

    return sessionID;
}

function setSessionCookie(
    res,
    sessionID
) {
    res.setHeader(
        "Set-Cookie",
        [
            `lexinx_session=${encodeURIComponent(sessionID)}`,
            "Path=/",
            "HttpOnly",
            "Secure",
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
            "Secure",
            "SameSite=Lax",
            "Max-Age=0"
        ].join("; ")
    );
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
        sessions.get(sessionID);

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
        ...session,
        sessionID
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
        return res
            .status(401)
            .json({
                ok: false,
                error:
                    "LOGIN_REQUIRED"
            });
    }

    req.session =
        session;

    next();
}

/* =====================================================
   TURNSTILE
===================================================== */

async function verifyTurnstile(
    token,
    remoteIP
) {
    if (!TURNSTILE_SECRET) {
        console.error(
            "TURNSTILE_SECRET_KEY is missing"
        );

        return false;
    }

    if (
        typeof token !==
            "string" ||
        !token ||
        token.length > 2048
    ) {
        return false;
    }

    try {
        const response =
            await fetch(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            secret:
                                TURNSTILE_SECRET,

                            response:
                                token,

                            remoteip:
                                remoteIP
                        })
                }
            );

        if (!response.ok) {
            return false;
        }

        const result =
            await response.json();

        if (
            result.success !==
            true
        ) {
            console.warn(
                "Turnstile rejected:",
                result["error-codes"]
            );

            return false;
        }

        return true;

    } catch (error) {

        console.error(
            "Turnstile error:",
            error.message
        );

        return false;
    }
}

function getClientIP(req) {
    return (
        req.headers[
            "cf-connecting-ip"
        ] ||
        req.headers[
            "x-forwarded-for"
        ] ||
        req.socket.remoteAddress ||
        ""
    );
}

/* =====================================================
   VALIDATION
===================================================== */

function validUsername(
    username
) {
    return (
        typeof username ===
            "string" &&
        /^[A-Za-z0-9_]{3,24}$/
            .test(username)
    );
}

function validPassword(
    password
) {
    return (
        typeof password ===
            "string" &&
        password.length >= 6 &&
        password.length <= 128
    );
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

/* =====================================================
   WEB
===================================================== */

app.use(
    express.static(
        PUBLIC_DIR
    )
);

/*
   Root luôn là authentication page.
*/
app.get(
    "/",
    (req, res) => {
        res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);

/* =====================================================
   REGISTER
===================================================== */

app.post(
    "/api/register",
    async (req, res) => {

        const {
            username,
            password,
            turnstileToken
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
                        "Username phải dài 3-24 ký tự và chỉ gồm chữ, số, _"
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
                        "Password phải dài từ 6-128 ký tự"
                });
        }

        const verified =
            await verifyTurnstile(
                turnstileToken,
                getClientIP(req)
            );

        if (!verified) {
            return res
                .status(403)
                .json({
                    ok: false,
                    error:
                        "Cloudflare verification failed"
                });
        }

        const db =
            readDB();

        if (
            db[username]
        ) {
            return res
                .status(409)
                .json({
                    ok: false,
                    error:
                        "Username đã tồn tại"
                });
        }

        const accountID =
            createAccountID();

        const passwordData =
            hashPassword(
                password
            );

        db[username] = {
            username,

            accountId:
                accountID,

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

        setSessionCookie(
            res,
            sessionID
        );

        const url =
            `${DOMAIN}/acc/${encodeURIComponent(
                username
            )}/${accountID}/dashboard`;

        return res.json({
            ok: true,
            username,
            accountId:
                accountID,
            url
        });
    }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
    "/api/login",
    async (req, res) => {

        const {
            username,
            password,
            turnstileToken
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

        const verified =
            await verifyTurnstile(
                turnstileToken,
                getClientIP(req)
            );

        if (!verified) {
            return res
                .status(403)
                .json({
                    ok: false,
                    error:
                        "Cloudflare verification failed"
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

        setSessionCookie(
            res,
            sessionID
        );

        const url =
            `${DOMAIN}/acc/${encodeURIComponent(
                username
            )}/${account.accountId}/dashboard`;

        return res.json({
            ok: true,
            username,
            accountId:
                account.accountId,
            url
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

        clearSessionCookie(
            res
        );

        res.json({
            ok: true
        });
    }
);

/* =====================================================
   CURRENT ACCOUNT
===================================================== */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[
                req.session.username
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
                account.accountId
        });
    }
);

/* =====================================================
   ACCOUNT DASHBOARD
===================================================== */

app.get(
    "/acc/:username/:accountId/dashboard",
    (req, res) => {

        const {
            username,
            accountId
        } = req.params;

        const db =
            readDB();

        const account =
            db[username];

        /*
          Account phải tồn tại.
        */
        if (!account) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
          Account ID phải khớp.
        */
        if (
            account.accountId !==
            accountId
        ) {
            return res
                .status(403)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
          Phải có session.
        */
        const session =
            getSession(req);

        if (
            !session ||
            session.username !==
                username
        ) {
            return res.redirect(
                "/"
            );
        }

        return res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
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
                req.session.username
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
            .map(script => ({
                id:
                    script.id,

                name:
                    script.name,

                createdAt:
                    script.createdAt,

                updatedAt:
                    script.updatedAt
            }));

        res.json({
            ok: true,
            scripts
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
                        "Script is empty"
                });
        }

        const db =
            readDB();

        const account =
            db[
                req.session.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        const id =
            createScriptID();

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
            id
        });
    }
);

/* =====================================================
   GET SCRIPT FOR EDITOR
===================================================== */

app.get(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[
                req.session.username
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
                        "Script not found"
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

        const db =
            readDB();

        const account =
            db[
                req.session.username
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
                        "Script not found"
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
            script.source =
                req.body.source;
        }

        script.updatedAt =
            Date.now();

        writeDB(db);

        res.json({
            ok: true
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
                req.session.username
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
   UNKNOWN ROUTES
===================================================== */

app.use(
    (req, res) => {

        if (
            req.path.startsWith(
                "/api/"
            )
        ) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        return res.redirect(
            "/"
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
            "================================="
        );

        console.log(
            "LEXINX WEB ONLINE"
        );

        console.log(
            "Domain:",
            DOMAIN
        );

        console.log(
            "Port:",
            PORT
        );

        console.log(
            "Turnstile:",
            TURNSTILE_SECRET
                ? "CONFIGURED"
                : "MISSING"
        );

        console.log(
            "================================="
        );
    }
);
