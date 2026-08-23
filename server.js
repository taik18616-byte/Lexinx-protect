"use strict";

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

const DATA_FILE = path.join(__dirname, "data.json");

const SESSION_TTL = 60 * 60 * 24 * 7;
const STAGE_TTL = 60;
const MAX_BODY = 2 * 1024 * 1024;

/* =========================================================
   DATABASE
========================================================= */

function loadDB() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            return {
                users: {},
                scripts: {},
                sessions: {}
            };
        }

        return JSON.parse(
            fs.readFileSync(DATA_FILE, "utf8")
        );
    } catch {
        return {
            users: {},
            scripts: {},
            sessions: {}
        };
    }
}

let db = loadDB();

function saveDB() {
    const tmp = DATA_FILE + ".tmp";

    fs.writeFileSync(
        tmp,
        JSON.stringify(db, null, 2),
        "utf8"
    );

    fs.renameSync(tmp, DATA_FILE);
}

/* =========================================================
   CRYPTO
========================================================= */

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

function safeEqual(a, b) {
    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const aa = Buffer.from(a);
    const bb = Buffer.from(b);

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        aa,
        bb
    );
}

/* =========================================================
   GENERAL HELPERS
========================================================= */

function now() {
    return Math.floor(Date.now() / 1000);
}

function cleanUsername(username) {
    return String(username || "")
        .trim()
        .toLowerCase();
}

function validUsername(username) {
    return /^[a-z0-9_]{3,32}$/.test(
        username
    );
}

function validPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 6 &&
        password.length <= 200
    );
}

function getBearer(req) {
    const header =
        req.headers.authorization || "";

    if (
        !header.startsWith("Bearer ")
    ) {
        return null;
    }

    return header.slice(7).trim();
}

function errorJSON(res, code, message) {
    return res.status(code).json({
        ok: false,
        error: message
    });
}

/* =========================================================
   ACCOUNT
========================================================= */

function createUser(username, password) {
    const salt = randomHex(16);

    const user = {
        id: randomHex(16),
        username,
        salt,
        passwordHash: hashPassword(
            password,
            salt
        ),
        createdAt: now()
    };

    db.users[username] = user;

    saveDB();

    return user;
}

function verifyUser(username, password) {
    const user =
        db.users[username];

    if (!user) {
        return null;
    }

    const hash =
        hashPassword(
            password,
            user.salt
        );

    if (
        !safeEqual(
            hash,
            user.passwordHash
        )
    ) {
        return null;
    }

    return user;
}

/* =========================================================
   SESSIONS
========================================================= */

function createSession(user) {
    const token = randomHex(32);

    db.sessions[token] = {
        userId: user.id,
        username: user.username,
        createdAt: now(),
        expiresAt:
            now() + SESSION_TTL
    };

    saveDB();

    return token;
}

function getSession(token) {
    if (!token) {
        return null;
    }

    const session =
        db.sessions[token];

    if (!session) {
        return null;
    }

    if (
        session.expiresAt <= now()
    ) {
        delete db.sessions[token];
        saveDB();
        return null;
    }

    return session;
}

function requireAuth(req, res, next) {
    const token = getBearer(req);
    const session = getSession(token);

    if (!session) {
        return errorJSON(
            res,
            401,
            "Authentication required"
        );
    }

    req.auth = {
        token,
        ...session
    };

    next();
}

/* =========================================================
   SCRIPT STORAGE
========================================================= */

function createScript(
    username,
    name,
    source
) {
    const id = randomHex(16);

    db.scripts[id] = {
        id,
        owner: username,
        name,
        source,
        createdAt: now(),
        updatedAt: now(),
        deleted: false
    };

    saveDB();

    return db.scripts[id];
}

function userOwnsScript(
    script,
    username
) {
    return (
        script &&
        script.owner === username &&
        !script.deleted
    );
}

/* =========================================================
   PACKED PROTOTYPE
   Metadata only. It does NOT contain source.
========================================================= */

function createPackedPrototype() {
    function bytes(size) {
        return crypto
            .randomBytes(size)
            .toString("hex");
    }

    return {
        format: "LEXINX-CUSTOM-PROTOV1",

        protos: {
            0: {
                strings: {
                    0: "",
                    1: "LEXINX",
                    2: "runtime",
                    3: "session",
                    4: "challenge",
                    5: "payload"
                },

                booleans: {
                    0: true,
                    1: false
                },

                proto_references: {
                    0: { proto: 1 },
                    1: { proto: 2 },
                    2: { proto: 3 }
                },

                table_aliases: {
                    0: {
                        table_alias: 0
                    }
                },

                opaque_ascii: {
                    0: bytes(6),
                    1: bytes(8),
                    2: bytes(5)
                },

                byte_sequences: {
                    0: {
                        hex: bytes(8)
                    },
                    1: {
                        hex: bytes(8)
                    }
                }
            },

            1: {
                parent: 0,

                strings: {
                    0: "session",
                    1: "token"
                },

                byte_sequences: {
                    0: {
                        hex: bytes(8)
                    }
                }
            },

            2: {
                parent: 0,

                strings: {
                    0: "challenge",
                    1: "nonce"
                },

                booleans: {
                    0: true
                },

                byte_sequences: {
                    0: {
                        hex: bytes(8)
                    }
            },

            3: {
                parent: 0,

                strings: {
                    0: "runtime",
                    1: "bootstrap"
                },

                byte_sequences: {
                    0: {
                        hex: bytes(16)
                    }
                }
            }
        }
    };
}

/* =========================================================
   STAGE TOKENS
========================================================= */

function createStageToken(
    session,
    stage,
    scriptId
) {
    const token = randomHex(32);

    if (!session.stageTokens) {
        session.stageTokens = {};
    }

    session.stageTokens[token] = {
        stage,
        scriptId,
        expiresAt:
            now() + STAGE_TTL,
        used: false
    };

    saveDB();

    return token;
}

function consumeStageToken(
    session,
    token,
    expectedStage,
    scriptId
) {
    if (
        !session.stageTokens ||
        !token
    ) {
        return false;
    }

    const record =
        session.stageTokens[token];

    if (!record) {
        return false;
    }

    if (record.used) {
        return false;
    }

    if (
        record.expiresAt <= now()
    ) {
        delete session.stageTokens[token];
        saveDB();
        return false;
    }

    if (
        record.stage !== expectedStage ||
        record.scriptId !== scriptId
    ) {
        return false;
    }

    record.used = true;

    saveDB();

    return true;
}

/* =========================================================
   RUNTIME
========================================================= */

function runtimeBootstrap(
    sessionToken,
    stageToken
) {
    /*
     * Runtime does not contain the actual script.
     * It only carries the information necessary
     * to continue the authenticated protocol.
     */

    return {
        type: "LEXINX_RUNTIME",
        version: 1,
        session: sessionToken,
        stage: stageToken,
        next: "/api/runtime/l5"
    };
}

/* =========================================================
   PROTECT PAGE
========================================================= */

function blockPage() {
    return `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>LEXINX PROTECT</title>

<style>
html,body{
    margin:0;
    width:100%;
    height:100%;
    overflow:hidden;
    background:#050505;
    color:white;
    font-family:Arial,sans-serif;
}

body{
    display:flex;
    align-items:center;
    justify-content:center;
    position:relative;
}

.stars{
    position:absolute;
    inset:0;
    background-image:
        radial-gradient(
            white 1px,
            transparent 1px
        );
    background-size:47px 47px;
    opacity:.12;
}

.box{
    position:relative;
    z-index:2;
    text-align:center;
}

.logo{
    font-size:48px;
    font-weight:900;
    letter-spacing:8px;
    animation:pulse 4s infinite;
}

.sub{
    margin-top:16px;
    color:#777;
    font-size:12px;
    letter-spacing:3px;
}

@keyframes pulse{
    0%,100%{
        color:#fff;
    }

    50%{
        color:#222;
    }
}
</style>
</head>

<body>

<div class="stars"></div>

<div class="box">
    <div class="logo">
        LEXINX PROTECT
    </div>

    <div class="sub">
        ANTI-SKID
    </div>
</div>

</body>
</html>
`;
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    res.type("html").send(blockPage());
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/auth/register", (req, res) => {
    try {
        const username =
            cleanUsername(
                req.body.username
            );

        const password =
            req.body.password;

        if (
            !validUsername(username)
        ) {
            return errorJSON(
                res,
                400,
                "Invalid username"
            );
        }

        if (
            !validPassword(password)
        ) {
            return errorJSON(
                res,
                400,
                "Password must be 6-200 characters"
            );
        }

        if (
            db.users[username]
        ) {
            return errorJSON(
                res,
                409,
                "Username already exists"
            );
        }

        const user =
            createUser(
                username,
                password
            );

        const session =
            createSession(user);

        res.json({
            ok: true,
            user: {
                id: user.id,
                username: user.username
            },
            session
        });

    } catch (err) {
        console.error(err);

        errorJSON(
            res,
            500,
            "Registration failed"
        );
    }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", (req, res) => {
    try {
        const username =
            cleanUsername(
                req.body.username
            );

        const password =
            req.body.password;

        const user =
            verifyUser(
                username,
                password
            );

        if (!user) {
            return errorJSON(
                res,
                401,
                "Invalid credentials"
            );
        }

        const session =
            createSession(user);

        res.json({
            ok: true,
            user: {
                id: user.id,
                username: user.username
            },
            session
        });

    } catch (err) {
        console.error(err);

        errorJSON(
            res,
            500,
            "Login failed"
        );
    }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/auth/logout",
    requireAuth,
    (req, res) => {
        delete db.sessions[
            req.auth.token
        ];

        saveDB();

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/auth/me",
    requireAuth,
    (req, res) => {
        const scripts =
            Object.values(
                db.scripts
            )
            .filter(
                s =>
                    s.owner ===
                        req.auth.username &&
                    !s.deleted
            )
            .map(
                s => ({
                    id: s.id,
                    name: s.name,
                    createdAt:
                        s.createdAt,
                    updatedAt:
                        s.updatedAt
                })
            );

        res.json({
            ok: true,
            user: {
                id: req.auth.userId,
                username:
                    req.auth.username
            },
            scripts
        });
    }
);

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/scripts",
    requireAuth,
    (req, res) => {
        const name =
            String(
                req.body.name || ""
            ).trim();

        const source =
            String(
                req.body.source || ""
            );

        if (
            !name ||
            name.length > 100
        ) {
            return errorJSON(
                res,
                400,
                "Invalid script name"
            );
        }

        if (
            !source ||
            Buffer.byteLength(
                source,
                "utf8"
            ) > MAX_BODY
        ) {
            return errorJSON(
                res,
                400,
                "Invalid script source"
            );
        }

        const script =
            createScript(
                req.auth.username,
                name,
                source
            );

        res.json({
            ok: true,
            script: {
                id: script.id,
                name: script.name,
                createdAt:
                    script.createdAt
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
        const script =
            db.scripts[
                req.params.id
            ];

        if (
            !userOwnsScript(
                script,
                req.auth.username
            )
        ) {
            return errorJSON(
                res,
                404,
                "Script not found"
            );
        }

        if (
            typeof req.body.name ===
            "string"
        ) {
            const name =
                req.body.name.trim();

            if (
                name.length > 0 &&
                name.length <= 100
            ) {
                script.name = name;
            }
        }

        if (
            typeof req.body.source ===
            "string"
        ) {
            if (
                Buffer.byteLength(
                    req.body.source,
                    "utf8"
                ) > MAX_BODY
            ) {
                return errorJSON(
                    res,
                    400,
                    "Source too large"
                );
            }

            script.source =
                req.body.source;
        }

        script.updatedAt = now();

        saveDB();

        res.json({
            ok: true
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
        const script =
            db.scripts[
                req.params.id
            ];

        if (
            !userOwnsScript(
                script,
                req.auth.username
            )
        ) {
            return errorJSON(
                res,
                404,
                "Script not found"
            );
        }

        script.deleted = true;
        script.updatedAt = now();

        saveDB();

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   L1
   /api/loader/:id
========================================================= */

app.get(
    "/api/loader/:id",
    requireAuth,
    (req, res) => {
        const script =
            db.scripts[
                req.params.id
            ];

        if (
            !userOwnsScript(
                script,
                req.auth.username
            )
        ) {
            return res
                .status(404)
                .send("LEXINX BLOCK");
        }

        const session =
            db.sessions[
                req.auth.token
            ];

        session.stageTokens = {};

        const l2 =
            createStageToken(
                session,
                2,
                script.id
            );

        res.json({
            ok: true,
            stage: 2,
            session:
                req.auth.token,
            token: l2,
            next:
                "/api/runtime/l2"
        });
    }
);

/* =========================================================
   L2
========================================================= */

app.post(
    "/api/runtime/l2",
    requireAuth,
    (req, res) => {
        const {
            scriptId,
            token
        } = req.body;

        const script =
            db.scripts[
                scriptId
            ];

        if (
            !userOwnsScript(
                script,
                req.auth.username
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const session =
            db.sessions[
                req.auth.token
            ];

        if (
            !consumeStageToken(
                session,
                token,
                2,
                scriptId
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const next =
            createStageToken(
                session,
                3,
                scriptId
            );

        res.json({
            ok: true,
            stage: 3,
            token: next,
            next:
                "/api/runtime/l3"
        });
    }
);

/* =========================================================
   L3
   Packed prototype is metadata only.
========================================================= */

app.post(
    "/api/runtime/l3",
    requireAuth,
    (req, res) => {
        const {
            scriptId,
            token
        } = req.body;

        const script =
            db.scripts[
                scriptId
            ];

        if (
            !userOwnsScript(
                script,
                req.auth.username
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const session =
            db.sessions[
                req.auth.token
            ];

        if (
            !consumeStageToken(
                session,
                token,
                3,
                scriptId
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const next =
            createStageToken(
                session,
                4,
                scriptId
            );

        const packed =
            createPackedPrototype();

        res.json({
            ok: true,
            stage: 4,
            packed,
            token: next,
            next:
                "/api/runtime/l4"
        });
    }
);

/* =========================================================
   L4
   Runtime bootstrap.
========================================================= */

app.post(
    "/api/runtime/l4",
    requireAuth,
    (req, res) => {
        const {
            scriptId,
            token
        } = req.body;

        const script =
            db.scripts[
                scriptId
            ];

        if (
            !userOwnsScript(
                script,
                req.auth.username
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const session =
            db.sessions[
                req.auth.token
            ];

        if (
            !consumeStageToken(
                session,
                token,
                4,
                scriptId
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const next =
            createStageToken(
                session,
                5,
                scriptId
            );

        const runtime =
            runtimeBootstrap(
                req.auth.token,
                next
            );

        res.json({
            ok: true,
            stage: 5,
            runtime,
            token: next,
            next:
                "/api/runtime/l5"
        });
    }
);

/* =========================================================
   L5
   ONLY HERE IS SOURCE RELEASED.
========================================================= */

app.post(
    "/api/runtime/l5",
    requireAuth,
    (req, res) => {
        const {
            scriptId,
            token
        } = req.body;

        const script =
            db.scripts[
                scriptId
            ];

        if (
            !userOwnsScript(
                script,
                req.auth.username
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        const session =
            db.sessions[
                req.auth.token
            ];

        if (
            !consumeStageToken(
                session,
                token,
                5,
                scriptId
            )
        ) {
            return errorJSON(
                res,
                403,
                "LEXINX BLOCK"
            );
        }

        res.type("text/plain");

        res.send(
            script.source
        );
    }
);

/* =========================================================
   BLOCK UNKNOWN API
========================================================= */

app.use(
    "/api",
    (req, res) => {
        res
            .status(403)
            .send("LEXINX BLOCK");
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {
        console.error(err);

        if (
            res.headersSent
        ) {
            return next(err);
        }

        res
            .status(500)
            .json({
                ok: false,
                error:
                    "Internal server error"
            });
    }
);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    HOST,
    () => {
        console.log(
            `LEXINX server running on ${HOST}:${PORT}`
        );
    }
);
