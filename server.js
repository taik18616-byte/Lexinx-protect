"use strict";

const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";

const PAYLOAD_TTL = 10 * 60 * 1000;
const TOKEN_TTL = 60 * 1000;
const RATE_WINDOW = 60 * 1000;
const RATE_LIMIT = 60;
const MAX_PAYLOAD_SIZE = 5 * 1024 * 1024;

app.disable("x-powered-by");

app.use(express.json({
    limit: "6mb"
}));

app.use(express.urlencoded({
    extended: true,
    limit: "6mb"
}));

/* =========================================================
   STORAGE
========================================================= */

const payloads = new Map();
const tokens = new Map();
const rates = new Map();

/* =========================================================
   HELPERS
========================================================= */

function now() {
    return Date.now();
}

function randomHex(bytes = 16) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function sha256(data) {
    return crypto
        .createHash("sha256")
        .update(data)
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
    const time = now();

    let entry = rates.get(ip);

    if (!entry) {

        entry = {
            count: 0,
            reset: time + RATE_WINDOW
        };

        rates.set(ip, entry);
    }

    if (time >= entry.reset) {

        entry.count = 0;
        entry.reset =
            time + RATE_WINDOW;
    }

    entry.count++;

    res.setHeader(
        "X-RateLimit-Limit",
        RATE_LIMIT
    );

    res.setHeader(
        "X-RateLimit-Remaining",
        Math.max(
            0,
            RATE_LIMIT - entry.count
        )
    );

    if (entry.count > RATE_LIMIT) {

        return res.status(429).json({
            ok: false,
            error: "rate_limited"
        });
    }

    next();
}

app.use(rateLimit);

/* =========================================================
   HEALTH
========================================================= */

app.get("/health", (req, res) => {

    res.json({
        ok: true,
        service: "LEXINX PROTECT",
        version: "V60",
        uptime: process.uptime(),
        payloads: payloads.size,
        tokens: tokens.size,
        time: new Date().toISOString()
    });
});

/* =========================================================
   CREATE
========================================================= */

app.post("/create", (req, res) => {

    try {

        const payload =
            req.body?.payload;

        if (
            typeof payload !== "string"
        ) {

            return res.status(400).json({
                ok: false,
                error: "payload_required"
            });
        }

        if (!payload.trim()) {

            return res.status(400).json({
                ok: false,
                error: "payload_empty"
            });
        }

        const size =
            Buffer.byteLength(
                payload,
                "utf8"
            );

        if (
            size > MAX_PAYLOAD_SIZE
        ) {

            return res.status(413).json({
                ok: false,
                error: "payload_too_large"
            });
        }

        const id =
            randomHex(16);

        const token =
            randomHex(32);

        const createdAt =
            now();

        const expiresAt =
            createdAt +
            PAYLOAD_TTL;

        const hash =
            sha256(payload);

        payloads.set(id, {

            id,
            payload,
            hash,
            createdAt,
            expiresAt

        });

        tokens.set(token, {

            token,
            payloadId: id,
            createdAt,
            expiresAt:
                createdAt +
                TOKEN_TTL,
            used: false

        });

        return res.status(201).json({

            ok: true,

            id,

            token,

            hash,

            createdAt,

            expiresAt,

            payloadUrl:
                `/payload/${id}?token=${token}`

        });

    } catch (error) {

        console.error(
            "[CREATE]",
            error
        );

        res.status(500).json({
            ok: false,
            error: "internal_error"
        });
    }
});

/* =========================================================
   GET PAYLOAD
========================================================= */

app.get(
    "/payload/:id",
    (req, res) => {

        try {

            const id =
                req.params.id;

            const token =
                req.query.token;

            if (
                typeof token !== "string"
            ) {

                return res.status(401).send(
                    "LEXINX PROTECT: TOKEN REQUIRED"
                );
            }

            const record =
                payloads.get(id);

            if (!record) {

                return res.status(404).send(
                    "LEXINX PROTECT: PAYLOAD NOT FOUND"
                );
            }

            if (
                now() >=
                record.expiresAt
            ) {

                payloads.delete(id);

                return res.status(410).send(
                    "LEXINX PROTECT: PAYLOAD EXPIRED"
                );
            }

            const tokenData =
                tokens.get(token);

            if (!tokenData) {

                return res.status(403).send(
                    "LEXINX PROTECT: INVALID TOKEN"
                );
            }

            if (
                tokenData.payloadId !== id
            ) {

                return res.status(403).send(
                    "LEXINX PROTECT: TOKEN MISMATCH"
                );
            }

            if (
                now() >=
                tokenData.expiresAt
            ) {

                tokens.delete(token);

                return res.status(410).send(
                    "LEXINX PROTECT: TOKEN EXPIRED"
                );
            }

            if (tokenData.used) {

                return res.status(403).send(
                    "LEXINX PROTECT: TOKEN ALREADY USED"
                );
            }

            /*
             * One-time token.
             */
            tokenData.used = true;

            /*
             * Trả nguyên payload V4.
             * Server không decode/re-obfuscate.
             */

            res.setHeader(
                "Content-Type",
                "text/plain; charset=utf-8"
            );

            res.setHeader(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            );

            res.setHeader(
                "Pragma",
                "no-cache"
            );

            res.setHeader(
                "X-Lexinx-Payload-Hash",
                record.hash
            );

            return res.send(
                record.payload
            );

        } catch (error) {

            console.error(
                "[PAYLOAD]",
                error
            );

            return res.status(500).send(
                "LEXINX PROTECT: INTERNAL ERROR"
            );
        }
    }
);

/* =========================================================
   PAYLOAD INFO
========================================================= */

app.get(
    "/api/payload/:id",
    (req, res) => {

        const record =
            payloads.get(
                req.params.id
            );

        if (!record) {

            return res.status(404).json({
                ok: false,
                error: "payload_not_found"
            });
        }

        if (
            now() >=
            record.expiresAt
        ) {

            payloads.delete(
                req.params.id
            );

            return res.status(410).json({
                ok: false,
                error: "payload_expired"
            });
        }

        return res.json({

            ok: true,

            id: record.id,

            hash: record.hash,

            createdAt:
                record.createdAt,

            expiresAt:
                record.expiresAt

        });
    }
);

/* =========================================================
   DELETE
========================================================= */

app.delete(
    "/payload/:id",
    (req, res) => {

        const id =
            req.params.id;

        if (!payloads.has(id)) {

            return res.status(404).json({
                ok: false,
                error: "payload_not_found"
            });
        }

        payloads.delete(id);

        for (
            const [token, data]
            of tokens
        ) {

            if (
                data.payloadId === id
            ) {
                tokens.delete(token);
            }
        }

        return res.json({
            ok: true,
            deleted: id
        });
    }
);

/* =========================================================
   FRONTEND
========================================================= */

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "index.html"
        )
    );
});

/* =========================================================
   404
========================================================= */

app.use((req, res) => {

    res.status(404).json({

        ok: false,

        error: "not_found",

        method:
            req.method,

        path:
            req.originalUrl

    });
});

/* =========================================================
   ERROR
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "[ERROR]",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        res.status(500).json({
            ok: false,
            error: "internal_error"
        });
    }
);

/* =========================================================
   CLEANUP
========================================================= */

setInterval(() => {

    const time = now();

    for (
        const [id, data]
        of payloads
    ) {

        if (
            time >=
            data.expiresAt
        ) {

            payloads.delete(id);
        }
    }

    for (
        const [token, data]
        of tokens
    ) {

        if (
            time >=
            data.expiresAt
        ) {

            tokens.delete(token);
        }
    }

    for (
        const [ip, data]
        of rates
    ) {

        if (
            time >=
            data.reset
        ) {

            rates.delete(ip);
        }
    }

}, 30 * 1000);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    HOST,
    () => {

        console.log("");
        console.log(
            "======================================"
        );
        console.log(
            "       LEXINX PROTECT V60"
        );
        console.log(
            "======================================"
        );
        console.log(
            `PORT: ${PORT}`
        );
        console.log(
            `CREATE: POST /create`
        );
        console.log(
            `PAYLOAD: GET /payload/:id`
        );
        console.log(
            `HEALTH: GET /health`
        );
        console.log(
            "======================================"
        );
        console.log("");

    }
);
