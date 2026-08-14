const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect.onrender.com";

/*
========================================================
CONFIG
========================================================
*/

const TOKEN_TTL = 30 * 1000;          // 30 giây
const RATE_WINDOW = 60 * 1000;        // 1 phút
const MAX_REQUESTS = 60;              // mỗi IP / phút
const MAX_BURST = 10;                 // burst tối đa
const BURST_WINDOW = 5 * 1000;        // 5 giây
const MAX_BODY = "25mb";

/*
Secret nên đặt trong Render Environment Variables:

LEXINX_SECRET=mot-chuoi-bi-mat-rat-dai
*/

const SECRET =
    process.env.LEXINX_SECRET ||
    crypto.randomBytes(48).toString("hex");

/*
========================================================
FILES
========================================================
*/

const DATA_DIR =
    path.join(__dirname, "data");

const DB_FILE =
    path.join(DATA_DIR, "scripts.json");

const PUBLIC_DIR =
    path.join(__dirname, "public");

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

/*
========================================================
MIDDLEWARE
========================================================
*/

app.use(
    express.json({
        limit: MAX_BODY
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
ID
========================================================
*/

function createID() {
    return crypto
        .randomBytes(16)
        .toString("hex");
}

function randomString(bytes = 32) {
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
        .slice(
            0,
            80
        );
}

/*
========================================================
IP
========================================================
*/

function getIP(req) {

    /*
      Không tin tuyệt đối X-Forwarded-For.
      Render/proxy có thể thêm header này.
    */

    const forwarded =
        req.headers[
            "x-forwarded-for"
        ];

    if (forwarded) {

        return String(
            forwarded
        )
            .split(",")[0]
            .trim();

    }

    return String(
        req.socket?.remoteAddress ||
        "unknown"
    );
}

/*
========================================================
RATE LIMITER
========================================================

Lưu tạm trong RAM.
Restart server sẽ reset rate limit.

Nếu chạy nhiều instance thì nên chuyển
phần này sang Redis.
========================================================
*/

const rateStore = new Map();

function cleanupRateStore() {

    const now = Date.now();

    for (
        const [ip, item]
        of rateStore
    ) {

        if (
            now - item.windowStart >
            RATE_WINDOW
        ) {

            rateStore.delete(ip);

        }

    }
}

setInterval(
    cleanupRateStore,
    60 * 1000
).unref();

function rateLimit(req, res, next) {

    const ip =
        getIP(req);

    const now =
        Date.now();

    let item =
        rateStore.get(ip);

    if (!item) {

        item = {
            windowStart: now,
            count: 0,
            burstStart: now,
            burst: 0
        };

        rateStore.set(
            ip,
            item
        );

    }

    /*
    Reset minute window
    */

    if (
        now - item.windowStart >=
        RATE_WINDOW
    ) {

        item.windowStart = now;
        item.count = 0;

    }

    /*
    Reset burst
    */

    if (
        now - item.burstStart >=
        BURST_WINDOW
    ) {

        item.burstStart = now;
        item.burst = 0;

    }

    item.count++;
    item.burst++;

    if (
        item.count > MAX_REQUESTS ||
        item.burst > MAX_BURST
    ) {

        res.set(
            "Retry-After",
            "10"
        );

        return res
            .status(429)
            .type("text/plain")
            .send(
                "LEXINX BLOCK - RATE LIMITED"
            );

    }

    next();
}

/*
Áp rate limit toàn bộ API
*/

app.use(
    "/api/",
    rateLimit
);

/*
========================================================
REQUEST HEURISTIC
========================================================
*/

function looksLikeDirectBrowser(req) {

    const ua =
        String(
            req.headers[
                "user-agent"
            ] || ""
        ).toLowerCase();

    const accept =
        String(
            req.headers[
                "accept"
            ] || ""
        ).toLowerCase();

    const secFetchDest =
        String(
            req.headers[
                "sec-fetch-dest"
            ] || ""
        ).toLowerCase();

    const secFetchMode =
        String(
            req.headers[
                "sec-fetch-mode"
            ] || ""
        ).toLowerCase();

    /*
    Browser navigation thường có
    text/html + navigate/document.
    */

    const htmlNavigation =
        accept.includes(
            "text/html"
        ) &&
        (
            secFetchDest ===
                "document" ||

            secFetchMode ===
                "navigate"
        );

    /*
    Các header đặc trưng browser hiện đại.
    */

    const browserHeaders =
        Boolean(
            req.headers[
                "sec-ch-ua"
            ] ||
            req.headers[
                "sec-ch-ua-platform"
            ]
        );

    return (
        htmlNavigation ||
        browserHeaders
    );
}

/*
========================================================
BLOCK
========================================================
*/

function lexinxBlock(
    res,
    code = 403
) {

    return res
        .status(code)
        .type("text/plain")
        .set(
            "Cache-Control",
            "no-store"
        )
        .set(
            "X-Content-Type-Options",
            "nosniff"
        )
        .send(
            "LEXINX BLOCK"
        );
}

/*
========================================================
HMAC
========================================================
*/

function sign(value) {

    return crypto
        .createHmac(
            "sha256",
            SECRET
        )
        .update(
            value
        )
        .digest("hex");
}

function safeEqual(
    a,
    b
) {

    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const aa =
        Buffer.from(a);

    const bb =
        Buffer.from(b);

    if (
        aa.length !==
        bb.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        aa,
        bb
    );
}

/*
========================================================
ONE-TIME CHALLENGES
========================================================

challenge:
    ngắn hạn

token:
    ký HMAC

used:
    chỉ dùng một lần
========================================================
*/

const challenges =
    new Map();

const usedTokens =
    new Map();

function cleanupSecurityStore() {

    const now =
        Date.now();

    for (
        const [
            challenge,
            item
        ] of challenges
    ) {

        if (
            item.expiresAt <= now
        ) {

            challenges.delete(
                challenge
            );

        }

    }

    for (
        const [
            token,
            expiresAt
        ] of usedTokens
    ) {

        if (
            expiresAt <= now
        ) {

            usedTokens.delete(
                token
            );

        }

    }
}

setInterval(
    cleanupSecurityStore,
    10 * 1000
).unref();

/*
========================================================
CREATE SIGNED TOKEN
========================================================
*/

function createSecurityToken(
    id,
    challenge,
    ip
) {

    const timestamp =
        Date.now();

    const nonce =
        randomString(24);

    const payload =
        [
            id,
            challenge,
            timestamp,
            nonce,
            ip
        ].join("|");

    const signature =
        sign(payload);

    return Buffer
        .from(
            JSON.stringify({
                id,
                challenge,
                timestamp,
                nonce,
                signature
            })
        )
        .toString("base64url");
}

/*
========================================================
VERIFY TOKEN
========================================================
*/

function verifySecurityToken(
    token,
    expectedID,
    req
) {

    if (
        typeof token !==
        "string" ||
        token.length < 20
    ) {
        return {
            ok: false,
            error: "INVALID_TOKEN"
        };
    }

    let decoded;

    try {

        decoded =
            JSON.parse(
                Buffer
                    .from(
                        token,
                        "base64url"
                    )
                    .toString("utf8")
            );

    } catch {

        return {
            ok: false,
            error: "INVALID_TOKEN"
        };

    }

    if (
        !decoded ||
        typeof decoded !== "object"
    ) {

        return {
            ok: false,
            error: "INVALID_TOKEN"
        };

    }

    const {
        id,
        challenge,
        timestamp,
        nonce,
        signature
    } = decoded;

    if (
        id !== expectedID ||
        typeof challenge !== "string" ||
        typeof nonce !== "string" ||
        typeof timestamp !== "number" ||
        typeof signature !== "string"
    ) {

        return {
            ok: false,
            error: "INVALID_TOKEN"
        };

    }

    const now =
        Date.now();

    /*
    Token hết hạn
    */

    if (
        Math.abs(
            now - timestamp
        ) > TOKEN_TTL
    ) {

        return {
            ok: false,
            error: "TOKEN_EXPIRED"
        };

    }

    /*
    Challenge phải tồn tại
    */

    const challengeData =
        challenges.get(
            challenge
        );

    if (!challengeData) {

        return {
            ok: false,
            error: "CHALLENGE_INVALID"
        };

    }

    if (
        challengeData.expiresAt <=
        now
    ) {

        challenges.delete(
            challenge
        );

        return {
            ok: false,
            error: "CHALLENGE_EXPIRED"
        };

    }

    if (
        challengeData.id !==
        expectedID
    ) {

        return {
            ok: false,
            error: "CHALLENGE_ID"
        };

    }

    /*
    Kiểm tra IP.
    */

    const ip =
        getIP(req);

    if (
        challengeData.ip !==
        ip
    ) {

        return {
            ok: false,
            error: "IP_MISMATCH"
        };

    }

    /*
    Verify HMAC
    */

    const payload =
        [
            id,
            challenge,
            timestamp,
            nonce,
            ip
        ].join("|");

    const expectedSignature =
        sign(payload);

    if (
        !safeEqual(
            signature,
            expectedSignature
        )
    ) {

        return {
            ok: false,
            error: "BAD_SIGNATURE"
        };

    }

    /*
    One-time token
    */

    if (
        usedTokens.has(token)
    ) {

        return {
            ok: false,
            error: "TOKEN_USED"
        };

    }

    return {
        ok: true,
        challenge
    };
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
            createID();

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

        res.json({

            ok: true,

            id,

            name,

            loader:
                createLayer1(id),

            endpoint:
                `${DOMAIN}/api/loader/${id}`

        });

    }
);

/*
========================================================
EDIT
========================================================
*/

app.post(
    "/api/edit/:id",
    (req, res) => {

        const id =
            req.params.id;

        const db =
            readDB();

        if (!db[id]) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found"
                });

        }

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

        db[id].source =
            source;

        if (
            typeof req.body?.name ===
                "string" &&
            req.body.name.trim()
        ) {

            db[id].name =
                cleanName(
                    req.body.name
                );

        }

        db[id].updatedAt =
            Date.now();

        writeDB(db);

        res.json({

            ok: true,

            id,

            name:
                db[id].name,

            loader:
                createLayer1(id),

            endpoint:
                `${DOMAIN}/api/loader/${id}`

        });

    }
);

/*
========================================================
LIST
========================================================
*/

app.get(
    "/api/scripts",
    (req, res) => {

        const db =
            readDB();

        const scripts =
            Object
                .values(db)
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
                            createLayer1(
                                script.id
                            ),

                        endpoint:
                            `${DOMAIN}/api/loader/${script.id}`

                    })
                );

        res.json({

            ok: true,

            scripts

        });

    }
);

/*
========================================================
GET SOURCE FOR EDIT
========================================================
*/

app.get(
    "/api/source/:id",
    (req, res) => {

        const db =
            readDB();

        const script =
            db[req.params.id];

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

            id:
                script.id,

            name:
                script.name,

            source:
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

        if (!db[req.params.id]) {

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

        res.json({
            ok: true
        });

    }
);

/*
========================================================
LAYER 1
========================================================

Loader gọi:

GET /api/loader/:id

Server trả Layer 2 + challenge.
========================================================
*/

app.get(
    "/api/loader/:id",
    (req, res) => {

        if (
            looksLikeDirectBrowser(req)
        ) {

            return lexinxBlock(
                res,
                403
            );

        }

        const db =
            readDB();

        const script =
            db[req.params.id];

        if (!script) {

            return lexinxBlock(
                res,
                404
            );

        }

        const ip =
            getIP(req);

        const challenge =
            randomString(24);

        const expiresAt =
            Date.now() +
            TOKEN_TTL;

        challenges.set(
            challenge,
            {
                id:
                    req.params.id,

                ip,

                expiresAt
            }
        );

        const token =
            createSecurityToken(
                req.params.id,
                challenge,
                ip
            );

        const layer2 =
            createLayer2(
                req.params.id,
                token
            );

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
                layer2
            );

    }
);

/*
========================================================
DATA
========================================================

GET:
    BLOCK

POST:
    token verify
    challenge verify
    one-time verify
    source
========================================================
*/

app.get(
    "/api/data/:id",
    (req, res) => {

        return lexinxBlock(
            res,
            403
        );

    }
);

app.post(
    "/api/data/:id",
    (req, res) => {

        const token =
            req.headers[
                "x-lexinx-token"
            ];

        const verification =
            verifySecurityToken(
                token,
                req.params.id,
                req
            );

        if (
            !verification.ok
        ) {

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "LEXINX BLOCK",

                    reason:
                        verification.error

                });

        }

        /*
        Token được đánh dấu USED
        trước khi trả source.

        Vì vậy cùng token không thể
        dùng lại lần thứ hai.
        */

        usedTokens.set(
            token,
            Date.now() +
                TOKEN_TTL
        );

        /*
        Challenge cũng one-time.
        */

        challenges.delete(
            verification.challenge
        );

        const db =
            readDB();

        const script =
            db[req.params.id];

        if (!script) {

            return lexinxBlock(
                res,
                404
            );

        }

        res
            .status(200)
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
            .json({

                ok: true,

                id:
                    script.id,

                code:
                    script.source

            });

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
START
========================================================
*/

app.listen(
    PORT,
    () => {

        console.log(
            "================================"
        );

        console.log(
            "LEXINX PROTECT V2 ONLINE"
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
            "TOKEN TTL:",
            TOKEN_TTL,
            "ms"
        );

        console.log(
            "RATE LIMIT:",
            MAX_REQUESTS,
            "/ minute"
        );

        console.log(
            "================================"
        );

    }
);
