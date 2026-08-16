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
const ACCOUNTS_FILE = path.join(DATA_DIR, "accounts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(ACCOUNTS_FILE)) {
    fs.writeFileSync(
        ACCOUNTS_FILE,
        "{}",
        "utf8"
    );
}

app.disable("x-powered-by");

app.use(express.json({
    limit: "15mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "15mb"
}));

app.use(express.static(PUBLIC_DIR));

/* =====================================================
   DATABASE
===================================================== */

function readAccounts() {
    try {
        return JSON.parse(
            fs.readFileSync(
                ACCOUNTS_FILE,
                "utf8"
            )
        );
    } catch {
        return {};
    }
}

function writeAccounts(accounts) {
    fs.writeFileSync(
        ACCOUNTS_FILE,
        JSON.stringify(
            accounts,
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

function createID() {
    return randomHex(12);
}

/* =====================================================
   PASSWORD HASH
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
   COOKIE
===================================================== */

function parseCookies(req) {
    const cookies = {};

    const header =
        req.headers.cookie;

    if (!header) {
        return cookies;
    }

    for (
        const part of header.split(";")
    ) {
        const index =
            part.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            part
                .slice(0, index)
                .trim();

        const value =
            part
                .slice(index + 1)
                .trim();

        cookies[key] =
            decodeURIComponent(value);
    }

    return cookies;
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
            "SameSite=Lax",
            "Max-Age=604800"
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
   SESSIONS
===================================================== */

const sessions = new Map();

function createSession(username) {
    const id =
        randomHex(48);

    sessions.set(id, {
        username,
        createdAt: Date.now(),
        expiresAt:
            Date.now() +
            SESSION_TTL
    });

    return id;
}

function getCurrentUser(req) {
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
        username:
            session.username,

        sessionID
    };
}

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

function requireAuth(
    req,
    res,
    next
) {
    const user =
        getCurrentUser(req);

    if (!user) {
        return res
            .status(401)
            .json({
                ok: false,
                error:
                    "Not logged in"
            });
    }

    req.user =
        user;

    next();
}

/* =====================================================
   USERNAME VALIDATION
===================================================== */

function validUsername(username) {
    return (
        typeof username ===
            "string" &&
        /^[a-zA-Z0-9_]{3,24}$/
            .test(username)
    );
}

function validPassword(password) {
    return (
        typeof password ===
            "string" &&
        password.length >= 6 &&
        password.length <= 128
    );
}

/* =====================================================
   SCRIPT HELPERS
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
                        "Username must contain 3-24 letters, numbers or _"
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
                        "Password must contain 6-128 characters"
                });
        }

        const accounts =
            readAccounts();

        if (
            accounts[username]
        ) {
            return res
                .status(409)
                .json({
                    ok: false,
                    error:
                        "Username already exists"
                });
        }

        const passwordData =
            hashPassword(
                password
            );

        accounts[username] = {
            username,

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

        writeAccounts(
            accounts
        );

        const sessionID =
            createSession(
                username
            );

        setSessionCookie(
            res,
            sessionID
        );

        res.json({
            ok: true,
            username
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
                        "Invalid login"
                });
        }

        const accounts =
            readAccounts();

        const account =
            accounts[username];

        if (!account) {
            return res
                .status(401)
                .json({
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
            return res
                .status(401)
                .json({
                    ok: false,
                    error:
                        "Invalid username or password"
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

        res.json({
            ok: true,
            username
        });
    }
);

/* =====================================================
   LOGOUT
===================================================== */

app.post(
    "/api/logout",
    (req, res) => {
        const cookies =
            parseCookies(req);

        const sessionID =
            cookies.lexinx_session;

        if (sessionID) {
            sessions.delete(
                sessionID
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
   CURRENT USER
===================================================== */

app.get(
    "/api/me",
    requireAuth,
    (req, res) => {
        res.json({
            ok: true,

            username:
                req.user.username
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
            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Script is empty"
                });
        }

        const accounts =
            readAccounts();

        const account =
            accounts[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false,
                    error:
                        "Account not found"
                });
        }

        const id =
            createID();

        const name =
            cleanName(
                req.body?.name
            );

        account.scripts[id] = {
            id,

            name,

            source,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()
        };

        writeAccounts(
            accounts
        );

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
   LIST ONLY CURRENT USER SCRIPTS
===================================================== */

app.get(
    "/api/scripts",
    requireAuth,
    (req, res) => {

        const accounts =
            readAccounts();

        const account =
            accounts[
                req.user.username
            ];

        if (!account) {
            return res
                .status(401)
                .json({
                    ok: false,
                    error:
                        "Account not found"
                });
        }

        const scripts =
            Object.values(
                account.scripts
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
   GET SCRIPT FOR EDITOR
===================================================== */

app.get(
    "/api/script/:id",
    requireAuth,
    (req, res) => {

        const accounts =
            readAccounts();

        const account =
            accounts[
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
   EDIT SCRIPT
===================================================== */

app.post(
    "/api/edit/:id",
    requireAuth,
    (req, res) => {

        const accounts =
            readAccounts();

        const account =
            accounts[
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
                return res
                    .status(400)
                    .json({
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

        writeAccounts(
            accounts
        );

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

        const accounts =
            readAccounts();

        const account =
            accounts[
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
                    ok: false,
                    error:
                        "Script not found"
                });
        }

        delete account.scripts[
            req.params.id
        ];

        writeAccounts(
            accounts
        );

        res.json({
            ok: true
        });
    }
);

/* =====================================================
   LOADER ENDPOINT
=====================================================

Chỉ tìm script trong tài khoản sở hữu ID đó.

Không có account -> không có script.
===================================================== */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const accounts =
            readAccounts();

        let owner = null;
        let script = null;

        for (
            const username
            of Object.keys(accounts)
        ) {
            const account =
                accounts[username];

            if (
                account.scripts &&
                account.scripts[
                    req.params.id
                ]
            ) {
                owner =
                    username;

                script =
                    account.scripts[
                        req.params.id
                    ];

                break;
            }
        }

        if (!script) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
         * Endpoint này chỉ minh họa loader.
         * Source không được đưa vào response.
         */

        const lua = `
local HttpService = game:GetService("HttpService")

local URL = ${JSON.stringify(
            `${DOMAIN}/api/runtime/${script.id}`
        )}

local response = request({
    Url = URL,
    Method = "POST",
    Headers = {
        ["Content-Type"] =
            "application/json"
    },
    Body = "{}"
})

if response.StatusCode ~= 200 then
    error("LEXINX BLOCK")
end

local data =
    HttpService:JSONDecode(
        response.Body
    )

if not data.ok then
    error("LEXINX BLOCK")
end

local fn, err =
    loadstring(data.code)

if not fn then
    error(err)
end

fn()
`;

        res
            .type("text/plain")
            .set(
                "Cache-Control",
                "no-store"
            )
            .send(lua);
    }
);

/*
========================================================
RUNTIME SOURCE
========================================================

Lưu ý:
Loader runtime hiện không có account cookie,
nên endpoint này chỉ là placeholder.

Nếu muốn bảo vệ runtime thật sự,
nên thêm license/key/session riêng
cho từng loader.
========================================================
*/

app.post(
    "/api/runtime/:id",
    (req, res) => {

        const accounts =
            readAccounts();

        let script = null;

        for (
            const username
            of Object.keys(accounts)
        ) {
            const account =
                accounts[username];

            if (
                account.scripts &&
                account.scripts[
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
            return res
                .status(404)
                .json({
                    ok: false
                });
        }

        res.json({
            ok: true,

            code:
                script.source
        });
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
            const [
                id,
                session
            ]
            of sessions
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
            "ACCOUNT STORAGE:",
            ACCOUNTS_FILE
        );

        console.log(
            "================================"
        );
    }
);
