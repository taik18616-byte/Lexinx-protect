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

/*
========================================================
CONFIG
========================================================
*/

const SESSION_TTL = 2 * 60 * 1000;
const TOKEN_TTL = 20 * 1000;

const RATE_WINDOW = 60 * 1000;
const RATE_LIMIT = 60;

/*
========================================================
FILES
========================================================
*/

fs.mkdirSync(DATA_DIR, {
    recursive: true
});

fs.mkdirSync(PUBLIC_DIR, {
    recursive: true
});

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

/*
========================================================
EXPRESS
========================================================
*/

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "25mb"
    })
);

app.use(
    express.static(PUBLIC_DIR)
);

/*
========================================================
DATABASE
========================================================
*/

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

/*
========================================================
RANDOM
========================================================
*/

function randomHex(bytes = 24) {
    return crypto
        .randomBytes(bytes)
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

/*
========================================================
CONSTANT-TIME COMPARE
========================================================
*/

function safeEqual(a, b) {

    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const A = Buffer.from(a);
    const B = Buffer.from(b);

    if (A.length !== B.length) {
        return false;
    }

    return crypto.timingSafeEqual(A, B);
}

/*
========================================================
IP
========================================================
*/

function getIP(req) {

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {
        return String(
            forwarded
        )
            .split(",")[0]
            .trim();
    }

    return (
        req.socket?.remoteAddress ||
        "unknown"
    );
}

/*
========================================================
RATE LIMIT
========================================================
*/

const rateMap = new Map();

function rateLimit(req, res, next) {

    const ip =
        getIP(req);

    const now =
        Date.now();

    let record =
        rateMap.get(ip);

    if (!record) {

        record = {
            count: 0,
            resetAt:
                now + RATE_WINDOW
        };

        rateMap.set(
            ip,
            record
        );
    }

    if (
        now >
        record.resetAt
    ) {

        record.count = 0;
        record.resetAt =
            now + RATE_WINDOW;
    }

    record.count++;

    if (
        record.count >
        RATE_LIMIT
    ) {

        return res
            .status(429)
            .type("text/plain")
            .set(
                "Retry-After",
                "60"
            )
            .send(
                "LEXINX RATE LIMIT"
            );
    }

    next();
}

app.use(
    "/api",
    rateLimit
);

/*
========================================================
BROWSER DIRECT ACCESS BLOCK
========================================================

Không cố xác định "Roblox".
Chỉ từ chối navigation/browser request
đến API.
========================================================
*/

function isBrowserNavigation(req) {

    const accept =
        String(
            req.headers.accept || ""
        ).toLowerCase();

    const mode =
        String(
            req.headers[
                "sec-fetch-mode"
            ] || ""
        ).toLowerCase();

    const dest =
        String(
            req.headers[
                "sec-fetch-dest"
            ] || ""
        ).toLowerCase();

    const documentRequest =
        dest === "document" ||
        mode === "navigate";

    const html =
        accept.includes(
            "text/html"
        );

    return (
        documentRequest ||
        html
    );
}

function block(res) {

    return res
        .status(403)
        .type("text/plain")
        .set(
            "Cache-Control",
            "no-store"
        )
        .send(
            "LEXINX BLOCK"
        );
}

/*
========================================================
SESSION STORE
========================================================

RAM store:
- nhanh
- session cũ chết khi server restart
========================================================
*/

const sessions =
    new Map();

/*
========================================================
TOKEN
========================================================
*/

function makeToken() {

    const now =
        Date.now();

    return {

        value:
            randomHex(32),

        nonce:
            randomHex(16),

        expiresAt:
            now + TOKEN_TTL,

        used:
            false
    };
}

/*
========================================================
SESSION
========================================================
*/

function createSession(
    scriptID,
    ip
) {

    const now =
        Date.now();

    const sessionID =
        randomHex(32);

    const session = {

        id:
            sessionID,

        scriptID,

        ip,

        stage:
            2,

        createdAt:
            now,

        expiresAt:
            now + SESSION_TTL,

        tokens: {

            l2:
                makeToken(),

            l3:
                null,

            l4:
                null,

            l5:
                null
        }

    };

    sessions.set(
        sessionID,
        session
    );

    return session;
}

/*
========================================================
SESSION VALIDATION
========================================================
*/

function getSession(
    sessionID,
    req
) {

    if (
        typeof sessionID !==
        "string"
    ) {
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

    /*
        Bind session to IP.

        Note:
        Nếu bạn dùng proxy/CDN,
        x-forwarded-for phải được
        cấu hình đúng ở hạ tầng.
    */

    if (
        session.ip !==
        getIP(req)
    ) {
        return null;
    }

    return session;
}

/*
========================================================
CONSUME TOKEN
========================================================
*/

function consumeToken(
    token,
    value,
    nonce
) {

    if (!token) {
        return false;
    }

    if (token.used) {
        return false;
    }

    if (
        Date.now() >
        token.expiresAt
    ) {
        return false;
    }

    if (
        !safeEqual(
            token.value,
            String(value || "")
        )
    ) {
        return false;
    }

    if (
        !safeEqual(
            token.nonce,
            String(nonce || "")
        )
    ) {
        return false;
    }

    token.used =
        true;

    return true;
}

/*
========================================================
COMMON RESPONSE HEADERS
========================================================
*/

function secureHeaders(res) {

    res.set(
        "Cache-Control",
        "no-store, no-cache, must-revalidate"
    );

    res.set(
        "Pragma",
        "no-cache"
    );

    res.set(
        "X-Content-Type-Options",
        "nosniff"
    );

    return res;
}

/*
========================================================
HOME
========================================================
*/

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            PUBLIC_DIR,
            "index.html"
        )
    );
});

/*
========================================================
CREATE SCRIPT
========================================================
*/

app.post(
    "/api/create",
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

        const name =
            cleanName(
                req.body?.name
            );

        const id =
            randomHex(12);

        const db =
            readDB();

        db[id] = {

            id,

            name,

            source,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()
        };

        writeDB(db);

        const loader =
            `loadstring(game:HttpGet(${JSON.stringify(
                `${DOMAIN}/api/loader/${id}`
            )}))()`;

        secureHeaders(res);

        res.json({

            ok: true,

            id,

            name,

            endpoint:
                `${DOMAIN}/api/loader/${id}`,

            loader
        });
    }
);

/*
========================================================
EDIT SCRIPT
========================================================
*/

app.post(
    "/api/edit/:id",
    (req, res) => {

        const db =
            readDB();

        const script =
            db[
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

        writeDB(db);

        secureHeaders(res);

        res.json({

            ok: true,

            id:
                script.id,

            name:
                script.name,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    `${DOMAIN}/api/loader/${script.id}`
                )}))()`
        });
    }
);

/*
========================================================
LIST SCRIPTS
========================================================
*/

app.get(
    "/api/scripts",
    (req, res) => {

        const db =
            readDB();

        const scripts =
            Object.values(db)
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

        secureHeaders(res);

        res.json({
            ok: true,
            scripts
        });
    }
);

/*
========================================================
L1 → L2
========================================================

GET /api/loader/:id

Browser navigation → 403.

Không trả source.
Chỉ tạo session.
========================================================
*/

app.get(
    "/api/loader/:id",
    (req, res) => {

        if (
            isBrowserNavigation(req)
        ) {
            return block(res);
        }

        const db =
            readDB();

        const script =
            db[
                req.params.id
            ];

        if (!script) {

            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        const session =
            createSession(
                script.id,
                getIP(req)
            );

        secureHeaders(res);

        res.json({

            ok: true,

            stage: 2,

            session:
                session.id,

            token:
                session.tokens.l2.value,

            nonce:
                session.tokens.l2.nonce,

            next:
                `${DOMAIN}/api/l3`

        });
    }
);

/*
========================================================
L2 → L3
========================================================
*/

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
            isBrowserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session:
                sessionID,

            token,

            nonce
        } =
            req.body || {};

        const session =
            getSession(
                sessionID,
                req
            );

        if (!session) {
            return block(res);
        }

        if (
            session.stage !== 2
        ) {

            return block(res);
        }

        if (
            !consumeToken(
                session.tokens.l2,
                token,
                nonce
            )
        ) {

            return block(res);
        }

        session.tokens.l3 =
            makeToken();

        session.stage =
            3;

        secureHeaders(res);

        res.json({

            ok: true,

            stage: 3,

            session:
                session.id,

            token:
                session.tokens.l3.value,

            nonce:
                session.tokens.l3.nonce,

            next:
                `${DOMAIN}/api/l4`
        });
    }
);

/*
========================================================
L3 → L4
========================================================
*/

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
            isBrowserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session:
                sessionID,

            token,

            nonce
        } =
            req.body || {};

        const session =
            getSession(
                sessionID,
                req
            );

        if (!session) {
            return block(res);
        }

        if (
            session.stage !== 3
        ) {
            return block(res);
        }

        if (
            !consumeToken(
                session.tokens.l3,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        session.tokens.l4 =
            makeToken();

        session.stage =
            4;

        secureHeaders(res);

        res.json({

            ok: true,

            stage: 4,

            session:
                session.id,

            token:
                session.tokens.l4.value,

            nonce:
                session.tokens.l4.nonce,

            next:
                `${DOMAIN}/api/l5`
        });
    }
);

/*
========================================================
L4 → L5
========================================================
*/

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
            isBrowserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session:
                sessionID,

            token,

            nonce
        } =
            req.body || {};

        const session =
            getSession(
                sessionID,
                req
            );

        if (!session) {
            return block(res);
        }

        if (
            session.stage !== 4
        ) {
            return block(res);
        }

        if (
            !consumeToken(
                session.tokens.l4,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        session.tokens.l5 =
            makeToken();

        session.stage =
            5;

        secureHeaders(res);

        res.json({

            ok: true,

            stage: 5,

            session:
                session.id,

            token:
                session.tokens.l5.value,

            nonce:
                session.tokens.l5.nonce,

            next:
                `${DOMAIN}/api/data`
        });
    }
);

/*
========================================================
L5 → SOURCE
========================================================

SOURCE CHỈ XUẤT HIỆN Ở ĐÂY.
========================================================
*/

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
            isBrowserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session:
                sessionID,

            token,

            nonce
        } =
            req.body || {};

        const session =
            getSession(
                sessionID,
                req
            );

        if (!session) {
            return block(res);
        }

        if (
            session.stage !== 5
        ) {
            return block(res);
        }

        if (
            !consumeToken(
                session.tokens.l5,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        const db =
            readDB();

        const script =
            db[
                session.scriptID
            ];

        if (!script) {

            sessions.delete(
                sessionID
            );

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "SCRIPT NOT FOUND"
                });
        }

        /*
            Xóa session ngay trước khi
            trả source để token không
            thể replay.
        */

        sessions.delete(
            sessionID
        );

        secureHeaders(res);

        res.json({

            ok: true,

            code:
                script.source
        });
    }
);

/*
========================================================
DELETE
========================================================
*/

app.delete(
    "/api/delete/:id",
    (req, res) => {

        const db =
            readDB();

        if (
            !db[
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

        delete db[
            req.params.id
        ];

        writeDB(db);

        secureHeaders(res);

        res.json({
            ok: true
        });
    }
);

/*
========================================================
UNKNOWN API
========================================================
*/

app.use(
    "/api",
    (req, res) => {

        return block(res);
    }
);

/*
========================================================
404
========================================================
*/

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

/*
========================================================
CLEANUP
========================================================
*/

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

        /*
            Dọn rate-limit records.
        */

        for (
            const [
                ip,
                record
            ]
            of rateMap
        ) {

            if (
                now >
                record.resetAt +
                RATE_WINDOW
            ) {

                rateMap.delete(
                    ip
                );
            }
        }

    },
    30 * 1000
);

/*
========================================================
START
========================================================
*/

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
            "CHAIN:",
            "L1 -> L2 -> L3 -> L4 -> L5 -> DATA"
        );

        console.log(
            "TOKEN TTL:",
            TOKEN_TTL,
            "ms"
        );

        console.log(
            "SESSION TTL:",
            SESSION_TTL,
            "ms"
        );

        console.log(
            "RATE LIMIT:",
            RATE_LIMIT,
            "/",
            RATE_WINDOW,
            "ms"
        );

        console.log(
            "======================================"
        );
    }
);
