/*
============================================================
 LEXINX PROTECT SERVER V5
 Layer 2 Payload Delivery
============================================================

 FLOW:

    Lua source
        ↓
    LEXINX Lua Obfuscator V4
        ↓
    Obfuscated Lua
        ↓
    POST /api/payload/upload
        ↓
    Server stores payload
        ↓
    Loader requests challenge
        ↓
    Loader sends signed request
        ↓
    Server verifies
        ↓
    One-time token
        ↓
    Server returns obfuscated Lua

============================================================
*/

"use strict";

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT =
    Number(process.env.PORT) || 3000;

const HOST =
    process.env.HOST || "0.0.0.0";

/*
 * Đổi secret này.
 *
 * KHÔNG commit secret thật lên GitHub.
 */
const MASTER_SECRET =
    process.env.MASTER_SECRET ||
    "CHANGE_THIS_LEXINX_SECRET_2026";

/*
 * Admin key dùng để upload payload.
 */
const ADMIN_KEY =
    process.env.ADMIN_KEY ||
    "CHANGE_THIS_ADMIN_KEY";

/*
 * Payload mặc định.
 *
 * Có thể thay bằng file payload.lua.
 */
const PAYLOAD_FILE =
    path.join(
        __dirname,
        "payload.lua"
    );

/*
 * Token sống trong bao lâu.
 */
const TOKEN_TTL =
    60 * 1000;

/*
 * Challenge sống trong bao lâu.
 */
const CHALLENGE_TTL =
    30 * 1000;

/*
 * Rate limit.
 */
const RATE_WINDOW =
    60 * 1000;

const RATE_LIMIT =
    30;

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "2mb"
    })
);

/* =========================================================
   STORAGE
========================================================= */

const dataDir =
    path.join(
        __dirname,
        "data"
    );

if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(
        dataDir,
        {
            recursive: true
        }
    );
}

const payloadStore =
    path.join(
        dataDir,
        "payload.lua"
    );

const metaStore =
    path.join(
        dataDir,
        "meta.json"
    );

/* =========================================================
   HELPERS
========================================================= */

function randomId(bytes = 18) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function now() {

    return Date.now();
}

function timingSafeEqualString(
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

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        aa,
        bb
    );
}

function sha256(value) {

    return crypto
        .createHash("sha256")
        .update(value)
        .digest("hex");
}

function hmac(
    value
) {

    return crypto
        .createHmac(
            "sha256",
            MASTER_SECRET
        )
        .update(value)
        .digest("hex");
}

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
        req.socket.remoteAddress ||
        "unknown"
    );
}

/* =========================================================
   PAYLOAD
========================================================= */

function readPayload() {

    try {

        if (
            !fs.existsSync(
                payloadStore
            )
        ) {

            if (
                fs.existsSync(
                    PAYLOAD_FILE
                )
            ) {

                fs.copyFileSync(
                    PAYLOAD_FILE,
                    payloadStore
                );
            }
        }

        if (
            !fs.existsSync(
                payloadStore
            )
        ) {

            return null;
        }

        return fs.readFileSync(
            payloadStore,
            "utf8"
        );

    } catch (err) {

        console.error(
            "[PAYLOAD READ]",
            err
        );

        return null;
    }
}

function savePayload(
    payload
) {

    fs.writeFileSync(
        payloadStore,
        payload,
        "utf8"
    );

    const meta = {

        hash:
            sha256(payload),

        size:
            Buffer.byteLength(
                payload,
                "utf8"
            ),

        updatedAt:
            new Date().toISOString()
    };

    fs.writeFileSync(
        metaStore,
        JSON.stringify(
            meta,
            null,
            2
        ),
        "utf8"
    );

    return meta;
}

/* =========================================================
   INITIAL PAYLOAD
========================================================= */

if (
    !fs.existsSync(
        payloadStore
    ) &&
    fs.existsSync(
        PAYLOAD_FILE
    )
) {

    try {

        const initial =
            fs.readFileSync(
                PAYLOAD_FILE,
                "utf8"
            );

        savePayload(
            initial
        );

        console.log(
            "[PAYLOAD] Loaded payload.lua"
        );

    } catch (err) {

        console.error(
            "[PAYLOAD INIT]",
            err
        );
    }
}

/* =========================================================
   CHALLENGE STORAGE
========================================================= */

const challenges =
    new Map();

/*
 challengeId => {

    nonce,
    ip,
    createdAt,
    used

 }
*/

/* =========================================================
   TOKEN STORAGE
========================================================= */

const tokens =
    new Map();

/*
 token => {

    ip,
    createdAt,
    expiresAt,
    used,
    payloadHash

 }
*/

/* =========================================================
   RATE LIMIT STORAGE
========================================================= */

const rate =
    new Map();

/*
 ip => {

    count,
    reset

 }
*/

/* =========================================================
   RATE LIMIT
========================================================= */

function rateLimit(
    req,
    res,
    next
) {

    const ip =
        getIP(req);

    const t =
        now();

    let entry =
        rate.get(ip);

    if (
        !entry ||
        t > entry.reset
    ) {

        entry = {

            count: 0,

            reset:
                t +
                RATE_WINDOW
        };

        rate.set(
            ip,
            entry
        );
    }

    entry.count++;

    if (
        entry.count >
        RATE_LIMIT
    ) {

        return res
            .status(429)
            .json({

                ok: false,

                error:
                    "RATE_LIMIT"
            });
    }

    next();
}

/* =========================================================
   CLEANUP
========================================================= */

setInterval(
    () => {

        const t =
            now();

        for (
            const [
                id,
                item
            ] of challenges
        ) {

            if (
                t -
                item.createdAt >
                CHALLENGE_TTL
            ) {

                challenges.delete(
                    id
                );
            }
        }

        for (
            const [
                token,
                item
            ] of tokens
        ) {

            if (
                t >
                item.expiresAt
            ) {

                tokens.delete(
                    token
                );
            }
        }

        for (
            const [
                ip,
                item
            ] of rate
        ) {

            if (
                t >
                item.reset
            ) {

                rate.delete(
                    ip
                );
            }
        }

    },
    15 * 1000
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            ok: true,

            service:
                "LEXINX PROTECT",

            version:
                "V5",

            payload:
                !!readPayload(),

            time:
                new Date().toISOString()
        });
    }
);

/* =========================================================
   PUBLIC STATUS
========================================================= */

app.get(
    "/api/status",
    rateLimit,
    (req, res) => {

        const payload =
            readPayload();

        res.json({

            ok: true,

            online: true,

            payload:
                !!payload,

            payloadHash:
                payload
                ? sha256(payload)
                : null
        });
    }
);

/* =========================================================
   CHALLENGE
========================================================= */

app.get(
    "/api/challenge",
    rateLimit,
    (req, res) => {

        const ip =
            getIP(req);

        const challengeId =
            randomId(16);

        const nonce =
            randomId(32);

        challenges.set(
            challengeId,
            {

                nonce,

                ip,

                createdAt:
                    now(),

                used: false
            }
        );

        res.json({

            ok: true,

            challenge:
                challengeId,

            nonce,

            expiresIn:
                CHALLENGE_TTL
        });
    }
);

/* =========================================================
   VERIFY CHALLENGE
========================================================= */

app.post(
    "/api/auth",
    rateLimit,
    (req, res) => {

        const {

            challenge,
            signature

        } = req.body || {};

        if (
            typeof challenge !==
                "string" ||

            typeof signature !==
                "string"
        ) {

            return res
                .status(400)
                .json({

                    ok: false,

                    error:
                        "INVALID_REQUEST"
                });
        }

        const item =
            challenges.get(
                challenge
            );

        if (!item) {

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "CHALLENGE_INVALID"
                });
        }

        if (
            item.used
        ) {

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "CHALLENGE_USED"
                });
        }

        if (
            now() -
            item.createdAt >
            CHALLENGE_TTL
        ) {

            challenges.delete(
                challenge
            );

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "CHALLENGE_EXPIRED"
                });
        }

        const ip =
            getIP(req);

        if (
            item.ip !== ip
        ) {

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "IP_MISMATCH"
                });
        }

        /*
         * Client phải ký:

             challenge + ":" + nonce

         */
        const message =
            challenge +
            ":" +
            item.nonce;

        const expected =
            hmac(
                message
            );

        if (
            !timingSafeEqualString(
                signature,
                expected
            )
        ) {

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "SIGNATURE_INVALID"
                });
        }

        item.used =
            true;

        const token =
            randomId(32);

        const payload =
            readPayload();

        if (!payload) {

            return res
                .status(503)
                .json({

                    ok: false,

                    error:
                        "PAYLOAD_NOT_AVAILABLE"
                });
        }

        tokens.set(
            token,
            {

                ip,

                createdAt:
                    now(),

                expiresAt:
                    now() +
                    TOKEN_TTL,

                used: false,

                payloadHash:
                    sha256(payload)
            }
        );

        return res.json({

            ok: true,

            token,

            expiresIn:
                TOKEN_TTL
        });
    }
);

/* =========================================================
   GET PAYLOAD
========================================================= */

app.get(
    "/api/payload",
    rateLimit,
    (req, res) => {

        const token =
            req.headers[
                "x-lexinx-token"
            ] ||
            req.query.token;

        if (
            typeof token !==
            "string"
        ) {

            return res
                .status(401)
                .json({

                    ok: false,

                    error:
                        "TOKEN_REQUIRED"
                });
        }

        const item =
            tokens.get(
                token
            );

        if (!item) {

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "TOKEN_INVALID"
                });
        }

        if (
            item.used
        ) {

            tokens.delete(
                token
            );

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "TOKEN_ALREADY_USED"
                });
        }

        if (
            now() >
            item.expiresAt
        ) {

            tokens.delete(
                token
            );

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "TOKEN_EXPIRED"
                });
        }

        const ip =
            getIP(req);

        if (
            item.ip !== ip
        ) {

            return res
                .status(403)
                .json({

                    ok: false,

                    error:
                        "IP_MISMATCH"
                });
        }

        const payload =
            readPayload();

        if (!payload) {

            return res
                .status(503)
                .json({

                    ok: false,

                    error:
                        "PAYLOAD_NOT_AVAILABLE"
                });
        }

        /*
         * One-time token.
         */
        item.used =
            true;

        tokens.delete(
            token
        );

        /*
         * Return RAW Lua payload.
         *
         * Đây chính là payload đã được
         * LEXINX V4 obfuscate.
         */
        res.status(200);

        res.setHeader(
            "Content-Type",
            "text/plain; charset=utf-8"
        );

        res.setHeader(
            "Cache-Control",
            "no-store, no-cache"
        );

        res.setHeader(
            "X-Lexinx-Payload",
            item.payloadHash
        );

        res.send(
            payload
        );
    }
);

/* =========================================================
   ADMIN AUTH
========================================================= */

function requireAdmin(
    req,
    res,
    next
) {

    const key =
        req.headers[
            "x-lexinx-admin"
        ];

    if (
        !timingSafeEqualString(
            String(key || ""),
            ADMIN_KEY
        )
    ) {

        return res
            .status(403)
            .json({

                ok: false,

                error:
                    "ADMIN_REQUIRED"
            });
    }

    next();
}

/* =========================================================
   ADMIN PAYLOAD UPLOAD
========================================================= */

app.post(
    "/api/admin/payload",
    requireAdmin,
    (req, res) => {

        const payload =
            typeof req.body.payload ===
            "string"
                ? req.body.payload
                : null;

        if (
            !payload ||
            !payload.trim()
        ) {

            return res
                .status(400)
                .json({

                    ok: false,

                    error:
                        "PAYLOAD_EMPTY"
                });
        }

        /*
         * Basic sanity checks.
         *
         * Không yêu cầu payload phải chứa
         * một VM/decoder cụ thể.
         */
        if (
            payload.length >
            2 * 1024 * 1024
        ) {

            return res
                .status(413)
                .json({

                    ok: false,

                    error:
                        "PAYLOAD_TOO_LARGE"
                });
        }

        const meta =
            savePayload(
                payload
            );

        console.log(
            "[PAYLOAD UPDATED]",
            meta
        );

        res.json({

            ok: true,

            message:
                "Payload updated",

            ...meta
        });
    }
);

/* =========================================================
   ADMIN PAYLOAD INFO
========================================================= */

app.get(
    "/api/admin/payload",
    requireAdmin,
    (req, res) => {

        const payload =
            readPayload();

        if (!payload) {

            return res
                .status(404)
                .json({

                    ok: false,

                    error:
                        "PAYLOAD_NOT_FOUND"
                });
        }

        res.json({

            ok: true,

            hash:
                sha256(payload),

            size:
                Buffer.byteLength(
                    payload,
                    "utf8"
                ),

            payload
        });
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        res
            .status(404)
            .json({

                ok: false,

                error:
                    "NOT_FOUND"
            });
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {

        console.error(
            "[SERVER ERROR]",
            err
        );

        res
            .status(500)
            .json({

                ok: false,

                error:
                    "INTERNAL_SERVER_ERROR"
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
            "=============================================="
        );

        console.log(
            "       LEXINX PROTECT SERVER V5"
        );

        console.log(
            "=============================================="
        );

        console.log(
            "[SERVER] http://" +
            HOST +
            ":" +
            PORT
        );

        console.log(
            "[PAYLOAD] " +
            (
                readPayload()
                    ? "READY"
                    : "NOT FOUND"
            )
        );

        console.log(
            "[TOKEN] One-time"
        );

        console.log(
            "[CHALLENGE] Enabled"
        );

        console.log(
            "[RATE LIMIT] " +
            RATE_LIMIT +
            "/minute/IP"
        );

        console.log(
            "=============================================="
        );
    }
);

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

function shutdown(
    signal
) {

    console.log(
        "\n[" +
        signal +
        "] shutting down..."
    );

    process.exit(
        0
    );
}

process.on(
    "SIGINT",
    () =>
        shutdown("SIGINT")
);

process.on(
    "SIGTERM",
    () =>
        shutdown("SIGTERM")
);
