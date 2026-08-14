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

const TOKEN_TTL = 30 * 1000;

const RATE_WINDOW = 60 * 1000;
const MAX_REQUESTS = 60;

const BURST_WINDOW = 5 * 1000;
const MAX_BURST = 10;

/*
Đặt biến này trên Render:

LEXINX_SECRET=chuoi-bi-mat-cua-ban

Không bắt buộc để chạy,
nhưng nên đặt để secret không đổi
sau mỗi lần restart.
*/

const SECRET =
    process.env.LEXINX_SECRET ||
    crypto.randomBytes(48).toString("hex");

/*
========================================================
PATH
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
UTILITIES
========================================================
*/

function createID() {

    return crypto
        .randomBytes(16)
        .toString("hex");

}

function randomString(
    bytes = 32
) {

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
RATE LIMIT
========================================================
*/

const rateStore =
    new Map();

function cleanupRateStore() {

    const now =
        Date.now();

    for (
        const [ip, data]
        of rateStore
    ) {

        if (
            now - data.windowStart >
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

function rateLimit(
    req,
    res,
    next
) {

    const ip =
        getIP(req);

    const now =
        Date.now();

    let data =
        rateStore.get(ip);

    if (!data) {

        data = {

            windowStart: now,

            count: 0,

            burstStart: now,

            burst: 0

        };

        rateStore.set(
            ip,
            data
        );

    }

    if (
        now - data.windowStart >=
        RATE_WINDOW
    ) {

        data.windowStart = now;
        data.count = 0;

    }

    if (
        now - data.burstStart >=
        BURST_WINDOW
    ) {

        data.burstStart = now;
        data.burst = 0;

    }

    data.count++;
    data.burst++;

    if (
        data.count > MAX_REQUESTS ||
        data.burst > MAX_BURST
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

app.use(
    "/api/",
    rateLimit
);

/*
========================================================
BROWSER DETECTION
========================================================

Không kiểm tra "Mozilla" hoặc "Android"
để tránh chặn nhầm loader.

Chỉ coi request là browser khi có
các dấu hiệu navigation/browser rõ ràng.
========================================================
*/

function looksLikeDirectBrowser(req) {

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

    const secChUa =
        req.headers[
            "sec-ch-ua"
        ];

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

    const browserHeaders =
        Boolean(secChUa);

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
    status = 403
) {

    return res
        .status(status)
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
        .update(value)
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
SECURITY STORAGE
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
            data
        ] of challenges
    ) {

        if (
            data.expiresAt <= now
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
TOKEN
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

    const object = {

        id,

        challenge,

        timestamp,

        nonce,

        signature

    };

    return Buffer
        .from(
            JSON.stringify(object)
        )
        .toString(
            "base64url"
        );

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
        typeof token !== "string" ||
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
                    .toString(
                        "utf8"
                    )
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
        typeof timestamp !== "number" ||
        typeof nonce !== "string" ||
        typeof signature !== "string"
    ) {

        return {
            ok: false,
            error: "INVALID_TOKEN"
        };

    }

    const now =
        Date.now();

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
LAYER 2
========================================================
*/

function createLayer2(
    id,
    token
) {

    const endpoint =
        `${DOMAIN}/api/data/${id}`;

    return `
local HttpService = game:GetService("HttpService")

local URL = ${JSON.stringify(endpoint)}

local TOKEN = ${JSON.stringify(token)}

local response

local ok, result = pcall(function()

    return request({

        Url = URL,

        Method = "POST",

        Headers = {

            ["Content-Type"] =
                "application/json",

            ["X-Lexinx-Token"] =
                TOKEN

        },

        Body = "{}"

    })

end)

if not ok or not result then

    warn("[LEXINX] Request failed")

    return

end

response = result

if response.StatusCode ~= 200 then

    warn(
        "[LEXINX] HTTP:",
        response.StatusCode
    )

    return

end

local decoded, data = pcall(function()

    return HttpService:JSONDecode(
        response.Body
    )

end)

if not decoded or
   type(data) ~= "table" then

    warn(
        "[LEXINX] Invalid response"
    )

    return

end

if data.ok ~= true then

    warn(
        "[LEXINX] Server rejected request"
    )

    return

end

if type(data.code) ~= "string" then

    warn(
        "[LEXINX] Source missing"
    )

    return

end

local fn, compileError =
    loadstring(data.code)

if not fn then

    warn(
        "[LEXINX] Compile error:",
        compileError
    )

    return

end

local success, runtimeError =
    pcall(fn)

if not success then

    warn(
        "[LEXINX] Runtime error:",
        runtimeError
    )

end
`.trim();

}

/*
========================================================
LAYER 1
========================================================
*/

function createLayer1(id) {

    const endpoint =
        `${DOMAIN}/api/loader/${id}`;

    return `loadstring(game:HttpGet(${JSON.stringify(endpoint)}))()`;

}

/*
========================================================
HOME
========================================================
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

/*
========================================================
CREATE
========================================================
*/

app.post(
    "/api/create",
    (req, res) => {

        try {

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

            /*
            CREATE chỉ lưu source.
            Token được tạo khi loader
            thực sự được request.
            */

            res.json({

                ok: true,

                id,

                name,

                loader:
                    createLayer1(id),

                endpoint:
                    `${DOMAIN}/api/loader/${id}`

            });

        } catch (error) {

            console.error(
                "[CREATE ERROR]",
                error
            );

            res
                .status(500)
                .json({

                    ok: false,

                    error:
                        "Internal server error"

                });

        }

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

        try {

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

        } catch (error) {

            console.error(
                "[EDIT ERROR]",
                error
            );

            res
                .status(500)
                .json({

                    ok: false,

                    error:
                        "Internal server error"

                });

        }

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
SOURCE
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

Browser:
    GET /api/loader/ID

Loader:
    game:HttpGet(...)
========================================================
*/

app.get(
    "/api/loader/:id",
    (req, res) => {

        /*
        Chặn browser navigation.
        */

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

        /*
        Tạo challenge mới.
        */

        const challenge =
            randomString(24);

        const ip =
            getIP(req);

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

        /*
        Tạo signed token.
        */

        const token =
            createSecurityToken(
                req.params.id,
                challenge,
                ip
            );

        /*
        Tạo Layer 2 chứa token.
        */

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
DATA GET
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

/*
========================================================
DATA POST
========================================================
*/

app.post(
    "/api/data/:id",
    (req, res) => {

        try {

            const token =
                req.headers[
                    "x-lexinx-token"
                ];

            /*
            Verify token.
            */

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
            Token one-time.
            */

            usedTokens.set(
                token,
                Date.now() +
                    TOKEN_TTL
            );

            /*
            Challenge one-time.
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

            /*
            Trả source.
            */

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

        } catch (error) {

            console.error(
                "[DATA ERROR]",
                error
            );

            res
                .status(500)
                .json({

                    ok: false,

                    error:
                        "Internal server error"

                });

        }

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

Quan trọng: bản này cần "express" thôi nên "package.json" cũ của bạn vẫn đủ:

{
  "name": "lexinx-protect",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^5.1.0"
  }
}

Sau khi deploy, nếu CREATE vẫn không hoạt động, lỗi sẽ không còn nằm ở "createLayer2"; "/api/create" đã được bọc "try/catch" và trả JSON lỗi rõ ràng.
