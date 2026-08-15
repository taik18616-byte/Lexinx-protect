"use strict";

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";

const PUBLIC_DIR = path.join(__dirname, "public");

const MAX_PAYLOAD_SIZE = 5 * 1024 * 1024;

const PAYLOAD_TTL =
    30 * 60 * 1000;

const TOKEN_TTL =
    5 * 60 * 1000;

const RATE_WINDOW =
    60 * 1000;

const RATE_LIMIT =
    120;

/* =========================================================
   STORAGE
========================================================= */

const payloadStore = new Map();
const tokenStore = new Map();
const rateStore = new Map();

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "6mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "6mb"
    })
);

/* =========================================================
   STATIC
========================================================= */

app.use(
    express.static(PUBLIC_DIR, {
        index: "index.html",
        extensions: ["html"]
    })
);

/* =========================================================
   HELPERS
========================================================= */

function now() {
    return Date.now();
}

function randomHex(bytes) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function sha256(value) {
    return crypto
        .createHash("sha256")
        .update(value, "utf8")
        .digest("hex");
}

function getIP(req) {

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {

        return String(forwarded)
            .split(",")[0]
            .trim();
    }

    return (
        req.socket.remoteAddress ||
        "unknown"
    );
}

/* =========================================================
   RATE LIMIT
========================================================= */

function rateLimit(req, res, next) {

    const ip = getIP(req);
    const current = now();

    let item =
        rateStore.get(ip);

    if (!item) {

        item = {
            count: 0,
            reset:
                current +
                RATE_WINDOW
        };

        rateStore.set(
            ip,
            item
        );
    }

    if (
        current >=
        item.reset
    ) {

        item.count = 0;

        item.reset =
            current +
            RATE_WINDOW;
    }

    item.count++;

    res.setHeader(
        "X-RateLimit-Limit",
        RATE_LIMIT
    );

    res.setHeader(
        "X-RateLimit-Remaining",
        Math.max(
            0,
            RATE_LIMIT -
            item.count
        )
    );

    if (
        item.count >
        RATE_LIMIT
    ) {

        return res
            .status(429)
            .json({
                ok: false,
                error:
                    "rate_limited"
            });
    }

    next();
}

app.use(rateLimit);

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/health",
    (req, res) => {

        res.json({

            ok: true,

            service:
                "LEXINX V4 PAYLOAD SERVER",

            version:
                "1.0.0",

            uptime:
                process.uptime(),

            payloads:
                payloadStore.size,

            tokens:
                tokenStore.size,

            time:
                new Date()
                    .toISOString()

        });
    }
);

/* =========================================================
   CREATE
========================================================= */

async function createPayload(
    req,
    res
) {

    try {

        const payload =
            req.body &&
            req.body.payload;

        if (
            typeof payload !==
            "string"
        ) {

            return res
                .status(400)
                .json({

                    ok: false,

                    error:
                        "payload_required"

                });
        }

        if (
            payload.trim()
                .length === 0
        ) {

            return res
                .status(400)
                .json({

                    ok: false,

                    error:
                        "payload_empty"

                });
        }

        const size =
            Buffer.byteLength(
                payload,
                "utf8"
            );

        if (
            size >
            MAX_PAYLOAD_SIZE
        ) {

            return res
                .status(413)
                .json({

                    ok: false,

                    error:
                        "payload_too_large",

                    maxBytes:
                        MAX_PAYLOAD_SIZE

                });
        }

        /*
         * ID công khai.
         */

        const id =
            randomHex(16);

        /*
         * Token bí mật dùng để lấy payload.
         */

        const token =
            randomHex(32);

        const createdAt =
            now();

        const expiresAt =
            createdAt +
            PAYLOAD_TTL;

        const tokenExpiresAt =
            createdAt +
            TOKEN_TTL;

        const hash =
            sha256(payload);

        /*
         * Lưu NGUYÊN payload V4.
         */

        payloadStore.set(
            id,
            {

                id,

                payload,

                hash,

                size,

                createdAt,

                expiresAt

            }
        );

        tokenStore.set(
            token,
            {

                token,

                payloadId:
                    id,

                createdAt,

                expiresAt:
                    tokenExpiresAt,

                used: false

            }
        );

        return res
            .status(201)
            .json({

                ok: true,

                id,

                token,

                hash,

                size,

                createdAt,

                expiresAt,

                tokenExpiresAt,

                payloadUrl:
                    `/payload/${id}?token=${token}`,

                apiPayloadUrl:
                    `/api/payload/${id}?token=${token}`

            });

    } catch (error) {

        console.error(
            "[CREATE ERROR]",
            error
        );

        return res
            .status(500)
            .json({

                ok: false,

                error:
                    "internal_error"

            });
    }
}

/*
 * Hai endpoint để tránh frontend/loader cũ
 * gọi nhầm /create hoặc /api/create.
 */

app.post(
    "/create",
    createPayload
);

app.post(
    "/api/create",
    createPayload
);

/* =========================================================
   GET PAYLOAD
========================================================= */

async function sendPayload(
    req,
    res
) {

    try {

        const id =
            req.params.id;

        const token =
            req.query.token;

        if (
            typeof token !==
            "string" ||
            !token
        ) {

            return res
                .status(401)
                .send(
                    "LEXINX PROTECT: TOKEN REQUIRED"
                );
        }

        const record =
            payloadStore.get(id);

        if (!record) {

            return res
                .status(404)
                .send(
                    "LEXINX PROTECT: PAYLOAD NOT FOUND"
                );
        }

        if (
            now() >=
            record.expiresAt
        ) {

            payloadStore.delete(id);

            return res
                .status(410)
                .send(
                    "LEXINX PROTECT: PAYLOAD EXPIRED"
                );
        }

        const tokenRecord =
            tokenStore.get(token);

        if (!tokenRecord) {

            return res
                .status(403)
                .send(
                    "LEXINX PROTECT: INVALID TOKEN"
                );
        }

        if (
            tokenRecord.payloadId !==
            id
        ) {

            return res
                .status(403)
                .send(
                    "LEXINX PROTECT: TOKEN MISMATCH"
                );
        }

        if (
            now() >=
            tokenRecord.expiresAt
        ) {

            tokenStore.delete(token);

            return res
                .status(410)
                .send(
                    "LEXINX PROTECT: TOKEN EXPIRED"
                );
        }

        /*
         * Token one-time.
         */

        if (
            tokenRecord.used
        ) {

            return res
                .status(403)
                .send(
                    "LEXINX PROTECT: TOKEN ALREADY USED"
                );
        }

        tokenRecord.used = true;

        /*
         * Không cache.
         */

        res.setHeader(
            "Content-Type",
            "text/plain; charset=utf-8"
        );

        res.setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, proxy-revalidate"
        );

        res.setHeader(
            "Pragma",
            "no-cache"
        );

        res.setHeader(
            "Expires",
            "0"
        );

        res.setHeader(
            "X-Lexinx-Payload-Hash",
            record.hash
        );

        res.setHeader(
            "X-Lexinx-Payload-ID",
            record.id
        );

        /*
         * Trả nguyên V4.
         */

        return res.send(
            record.payload
        );

    } catch (error) {

        console.error(
            "[PAYLOAD ERROR]",
            error
        );

        return res
            .status(500)
            .send(
                "LEXINX PROTECT: INTERNAL ERROR"
            );
    }
}

app.get(
    "/payload/:id",
    sendPayload
);

app.get(
    "/api/payload/:id",
    sendPayload
);

/* =========================================================
   PAYLOAD INFO
========================================================= */

app.get(
    "/api/info/:id",
    (req, res) => {

        const record =
            payloadStore.get(
                req.params.id
            );

        if (!record) {

            return res
                .status(404)
                .json({

                    ok: false,

                    error:
                        "payload_not_found"

                });
        }

        if (
            now() >=
            record.expiresAt
        ) {

            payloadStore.delete(
                req.params.id
            );

            return res
                .status(410)
                .json({

                    ok: false,

                    error:
                        "payload_expired"

                });
        }

        return res.json({

            ok: true,

            id:
                record.id,

            hash:
                record.hash,

            size:
                record.size,

            createdAt:
                record.createdAt,

            expiresAt:
                record.expiresAt

        });
    }
);

/* =========================================================
   DELETE PAYLOAD
========================================================= */

app.delete(
    "/api/payload/:id",
    (req, res) => {

        const id =
            req.params.id;

        const existed =
            payloadStore.has(id);

        payloadStore.delete(id);

        for (
            const [
                token,
                record
            ]
            of tokenStore
        ) {

            if (
                record.payloadId ===
                id
            ) {

                tokenStore.delete(
                    token
                );
            }
        }

        return res.json({

            ok: true,

            deleted:
                existed,

            id

        });
    }
);

/* =========================================================
   FRONTEND
========================================================= */

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
                    "not_found",

                method:
                    req.method,

                path:
                    req.originalUrl

            });
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "[SERVER ERROR]",
            error
        );

        if (
            res.headersSent
        ) {

            return next(
                error
            );
        }

        return res
            .status(500)
            .json({

                ok: false,

                error:
                    "internal_error"

            });
    }
);

/* =========================================================
   CLEANUP
========================================================= */

setInterval(
    () => {

        const current =
            now();

        for (
            const [
                id,
                record
            ]
            of payloadStore
        ) {

            if (
                current >=
                record.expiresAt
            ) {

                payloadStore.delete(
                    id
                );
            }
        }

        for (
            const [
                token,
                record
            ]
            of tokenStore
        ) {

            if (
                current >=
                record.expiresAt
            ) {

                tokenStore.delete(
                    token
                );
            }
        }

        for (
            const [
                ip,
                record
            ]
            of rateStore
        ) {

            if (
                current >=
                record.reset
            ) {

                rateStore.delete(
                    ip
                );
            }
        }

    },
    30 * 1000
);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    HOST,
    () => {

        console.log("");
        console.log(
            "=========================================="
        );
        console.log(
            "       LEXINX V4 PAYLOAD SERVER"
        );
        console.log(
            "=========================================="
        );
        console.log(
            "Host : " + HOST
        );
        console.log(
            "Port : " + PORT
        );
        console.log(
            "Web  : http://localhost:" +
            PORT
        );
        console.log(
            "Create : POST /create"
        );
        console.log(
            "Payload: GET /payload/:id"
        );
        console.log(
            "Health : GET /health"
        );
        console.log(
            "=========================================="
        );
        console.log("");
    }
);
