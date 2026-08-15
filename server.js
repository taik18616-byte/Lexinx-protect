/*
============================================================
 LEXINX PAYLOAD SERVER
 V4 OBFUSCATOR -> LAYER 2 -> SIGNED PAYLOAD
============================================================

Node.js 18+

Install:
npm init -y
npm i express cors

Run:
node server.js

API:

POST /api/create
{
    "source": "print('hello')",
    "ttl": 300
}

Response:
{
    "ok": true,
    "id": "...",
    "token": "...",
    "expires": 1234567890
}

Loader:
GET /api/payload/:id?token=TOKEN

or:

GET /api/payload?id=ID&token=TOKEN
============================================================
*/

"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);

const HOST =
    process.env.HOST ||
    "0.0.0.0";

const MASTER_SECRET =
    process.env.LEXINX_SECRET ||
    "change-this-secret-before-production";

const DEFAULT_TTL =
    5 * 60;

const MAX_TTL =
    60 * 60;

const MAX_SOURCE_SIZE =
    2 * 1024 * 1024;

const MAX_PAYLOAD_SIZE =
    8 * 1024 * 1024;

const RATE_WINDOW =
    60 * 1000;

const RATE_MAX =
    60;

/*
 * Set false if your loader needs to fetch
 * the same payload more than once.
 */
const ONE_TIME_TOKEN =
    true;

/*
 * Layer 2 encryption.
 */
const LAYER2_VERSION =
    "LX2";

/* =========================================================
   APP
========================================================= */

const app =
    express();

app.disable("x-powered-by");

app.use(
    cors({
        origin: "*",
        methods: [
            "GET",
            "POST",
            "OPTIONS"
        ],
        allowedHeaders: [
            "Content-Type",
            "Authorization",
            "X-Lexinx-Token"
        ]
    })
);

app.use(
    express.json({
        limit: "3mb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "3mb"
    })
);

/* =========================================================
   MEMORY STORAGE
========================================================= */

const payloads =
    new Map();

const rateMap =
    new Map();

/* =========================================================
   RANDOM
========================================================= */

function rnd(min, max) {

    return crypto.randomInt(
        min,
        max + 1
    );
}

function randomByte() {

    return crypto.randomBytes(1)[0];
}

function randomHex(bytes = 16) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function randomId() {

    return (
        "lx_" +
        randomHex(16)
    );
}

function randomToken() {

    return randomHex(32);
}

function name8() {

    const chars =
        "abcdefghijklmnopqrstuvwxyz";

    let out = "_";

    for (let i = 0; i < 8; i++) {

        out +=
            chars[
                rnd(
                    0,
                    chars.length - 1
                )
            ];
    }

    return out;
}

/* =========================================================
   HASH / HMAC
========================================================= */

function sha256(data) {

    return crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");
}

function hmac(data) {

    return crypto
        .createHmac(
            "sha256",
            MASTER_SECRET
        )
        .update(data)
        .digest("hex");
}

function safeEqual(a, b) {

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

/* =========================================================
   BYTE HELPERS
========================================================= */

function bytesOf(text) {

    return Array.from(
        Buffer.from(
            text,
            "utf8"
        )
    );
}

function xorBytes(bytes, key) {

    const out =
        new Array(bytes.length);

    for (
        let i = 0;
        i < bytes.length;
        i++
    ) {

        out[i] =
            (bytes[i] ^ key) &
            255;
    }

    return out;
}

function addBytes(bytes, key) {

    return bytes.map(
        x =>
            (x + key) & 255
    );
}

function subBytes(bytes, key) {

    return bytes.map(
        x =>
            (x - key + 256) & 255
    );
}

function luaArray(a) {

    return (
        "{" +
        a.join(",") +
        "}"
    );
}

/* =========================================================
   LUA ESCAPES
========================================================= */

function decodeLuaEscapes(s) {

    return s.replace(
        /\\(\\|'|"|n|r|t|b|f|v|a|x[0-9a-fA-F]{2}|\d{1,3})/g,
        (full, x) => {

            if (x === "\\")
                return "\\";

            if (x === "'")
                return "'";

            if (x === '"')
                return '"';

            if (x === "n")
                return "\n";

            if (x === "r")
                return "\r";

            if (x === "t")
                return "\t";

            if (x === "b")
                return "\b";

            if (x === "f")
                return "\f";

            if (x === "v")
                return "\v";

            if (x === "a")
                return "\x07";

            if (x[0] === "x") {

                return String.fromCharCode(
                    parseInt(
                        x.slice(1),
                        16
                    )
                );
            }

            if (
                /^\d+$/.test(x)
            ) {

                return String.fromCharCode(
                    parseInt(
                        x,
                        10
                    )
                );
            }

            return full;
        }
    );
}

/* =========================================================
   COMMENT STRIP
========================================================= */

function stripCommentsSafe(source) {

    let out = "";

    let i = 0;

    let quote = null;

    let escaped = false;

    while (
        i < source.length
    ) {

        const c =
            source[i];

        if (quote) {

            out += c;

            if (escaped) {

                escaped = false;

            } else if (
                c === "\\"
            ) {

                escaped = true;

            } else if (
                c === quote
            ) {

                quote = null;
            }

            i++;

            continue;
        }

        if (
            c === '"' ||
            c === "'"
        ) {

            quote = c;

            out += c;

            i++;

            continue;
        }

        if (
            c === "-" &&
            source[i + 1] === "-"
        ) {

            if (
                source[i + 2] === "[" &&
                source[i + 3] === "["
            ) {

                const end =
                    source.indexOf(
                        "]]",
                        i + 4
                    );

                if (end !== -1) {

                    i =
                        end + 2;

                    continue;
                }
            }

            while (
                i < source.length &&
                source[i] !== "\n"
            ) {

                i++;
            }

            continue;
        }

        out += c;

        i++;
    }

    return out;
}

/* =========================================================
   TOKENIZE STRINGS
========================================================= */

function tokenizeStrings(source) {

    const strings = [];

    let out = "";

    let i = 0;

    while (
        i < source.length
    ) {

        const c =
            source[i];

        /*
         * Keep comments.
         */

        if (
            c === "-" &&
            source[i + 1] === "-"
        ) {

            const start =
                i;

            i += 2;

            while (
                i < source.length &&
                source[i] !== "\n"
            ) {

                i++;
            }

            out +=
                source.slice(
                    start,
                    i
                );

            continue;
        }

        /*
         * [[ string ]]
         */

        if (
            c === "[" &&
            source[i + 1] === "["
        ) {

            const end =
                source.indexOf(
                    "]]",
                    i + 2
                );

            if (end !== -1) {

                const value =
                    source.slice(
                        i + 2,
                        end
                    );

                strings.push(
                    value
                );

                out +=
                    "__LXSTR_" +
                    strings.length +
                    "__";

                i =
                    end + 2;

                continue;
            }
        }

        /*
         * "string"
         * 'string'
         */

        if (
            c === '"' ||
            c === "'"
        ) {

            const quote =
                c;

            let j =
                i + 1;

            let escaped =
                false;

            while (
                j < source.length
            ) {

                const x =
                    source[j];

                if (escaped) {

                    escaped = false;

                    j++;

                    continue;
                }

                if (
                    x === "\\"
                ) {

                    escaped = true;

                    j++;

                    continue;
                }

                if (
                    x === quote
                ) {

                    break;
                }

                j++;
            }

            if (
                j >=
                source.length
            ) {

                throw new Error(
                    "Unclosed Lua string at " +
                    i
                );
            }

            strings.push(
                source.slice(
                    i + 1,
                    j
                )
            );

            out +=
                "__LXSTR_" +
                strings.length +
                "__";

            i =
                j + 1;

            continue;
        }

        out += c;

        i++;
    }

    return {
        source: out,
        strings
    };
}

/* =========================================================
   FRAGMENTATION
========================================================= */

function splitFragments(bytes) {

    const result = [];

    let p = 0;

    while (
        p < bytes.length
    ) {

        const size =
            Math.min(
                bytes.length - p,
                rnd(4, 10)
            );

        result.push(
            bytes.slice(
                p,
                p + size
            )
        );

        p += size;
    }

    return result;
}

/* =========================================================
   SHUFFLE
========================================================= */

function shuffle(a) {

    const x =
        a.slice();

    for (
        let i =
            x.length - 1;
        i > 0;
        i--
    ) {

        const j =
            rnd(0, i);

        [
            x[i],
            x[j]
        ] = [
            x[j],
            x[i]
        ];
    }

    return x;
}

/* =========================================================
   V4 DECODER
========================================================= */

function makeDecoder() {

    const fn =
        name8();

    const input =
        name8();

    const result =
        name8();

    const index =
        name8();

    const value =
        name8();

    const code = `
local ${fn}=function(${input},k)

    local ${result}={}

    for ${index}=1,#${input} do

        local ${value}=${input}[${index}]

        local x=${value}
        local y=k
        local o=0
        local bit=1

        while x>0 or y>0 do

            local xb=x%2
            local yb=y%2

            if xb~=yb then
                o=o+bit
            end

            x=math.floor(x/2)
            y=math.floor(y/2)
            bit=bit*2
        end

        ${result}[${index}]=
            string.char(o%256)
    end

    return table.concat(${result})
end
`;

    return {
        name: fn,
        code
    };
}

/* =========================================================
   V4 STRING POOL
========================================================= */

function makePool(strings, options) {

    const decoder =
        makeDecoder();

    const poolName =
        name8();

    const entries = [];

    for (
        let i = 0;
        i < strings.length;
        i++
    ) {

        const original =
            decodeLuaEscapes(
                strings[i]
            );

        let data =
            bytesOf(
                original
            );

        const xorKey =
            randomByte() || 137;

        const addKey =
            options.stage2
                ? randomByte()
                : 0;

        data =
            xorBytes(
                data,
                xorKey
            );

        if (
            options.stage2
        ) {

            data =
                addBytes(
                    data,
                    addKey
                );
        }

        let fragments;

        if (
            options.fragments
        ) {

            fragments =
                splitFragments(
                    data
                );

        } else {

            fragments = [
                data
            ];
        }

        let order =
            fragments.map(
                (_, n) => n
            );

        if (
            options.shuffle
        ) {

            order =
                shuffle(order);
        }

        entries.push({
            fragments,
            order,
            xorKey,
            addKey
        });
    }

    const poolParts = [];

    for (
        let i = 0;
        i < entries.length;
        i++
    ) {

        const e =
            entries[i];

        const fragmentParts =
            e.fragments.map(
                luaArray
            );

        poolParts.push(`
[${i + 1}]={
    f={${fragmentParts.join(",")}},
    o=${luaArray(
        e.order.map(
            n => n + 1
        )
    )},
    x=${e.xorKey},
    a=${e.addKey}
}`);
    }

    const pool = `
local ${poolName}={
${poolParts.join(",\n")}
}
`;

    const getter =
        name8();

    const entry =
        name8();

    const parts =
        name8();

    const order =
        name8();

    const output =
        name8();

    const part =
        name8();

    const byte =
        name8();

    const xkey =
        name8();

    const akey =
        name8();

    const decoded =
        name8();

    const index =
        name8();

    const reconstruct = `
local ${getter}=function(id)

    local ${entry}=${poolName}[id]

    if not ${entry} then
        return nil
    end

    local ${parts}=${entry}.f
    local ${order}=${entry}.o
    local ${output}={}

    local ${xkey}=${entry}.x
    local ${akey}=${entry}.a

    for ${index}=1,#${order} do

        local ${part}=
            ${parts}[${order}[${index}]]

        for j=1,#${part} do

            local ${byte}=
                ${part}[j]

            if ${akey}~=0 then

                ${byte}=
                    (${byte}-${akey})%256
            end

            ${output}[#${output}+1]=
                ${byte}
        end
    end

    local ${decoded}=
        ${decoder.name}(
            ${output},
            ${xkey}
        )

    return ${decoded}
end
`;

    return {
        code:
            decoder.code +
            pool +
            reconstruct,

        getter,

        count:
            strings.length
    };
}

/* =========================================================
   MARKERS
========================================================= */

function replaceMarkers(
    source,
    getter,
    count
) {

    for (
        let i = 1;
        i <= count;
        i++
    ) {

        const marker =
            "__LXSTR_" +
            i +
            "__";

        source =
            source
                .split(marker)
                .join(
                    getter +
                    "(" +
                    i +
                    ")"
                );
    }

    return source;
}

/* =========================================================
   LAYER 1
========================================================= */

function layer1V4(source) {

    let clean =
        source;

    /*
     * Same options as your HTML:
     */

    clean =
        stripCommentsSafe(
            clean
        );

    const tokenized =
        tokenizeStrings(
            clean
        );

    const pool =
        makePool(
            tokenized.strings,
            {
                fragments: true,
                shuffle: true,
                stage2: true
            }
        );

    const rebuilt =
        replaceMarkers(
            tokenized.source,
            pool.getter,
            pool.count
        );

    const integrity =
        sha256(
            rebuilt
        );

    return `-- LEXINX Lua Packed V4
-- Strings: ${pool.count}
-- Fragmentation: enabled
-- Shuffle: enabled
-- Stage2: enabled
-- Integrity: ${integrity}

${pool.code}

${rebuilt}
`;
}

/* =========================================================
   LAYER 2
=========================================================

   AES-256-GCM wrapper.

   The server stores encrypted payload.
   The API only releases it after token verification.
========================================================= */

function deriveKey(id) {

    return crypto
        .createHash("sha256")
        .update(
            MASTER_SECRET +
            ":" +
            id
        )
        .digest();
}

function encryptLayer2(text, id) {

    const key =
        deriveKey(id);

    const iv =
        crypto.randomBytes(12);

    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    const encrypted =
        Buffer.concat([
            cipher.update(
                Buffer.from(
                    text,
                    "utf8"
                )
            ),
            cipher.final()
        ]);

    const tag =
        cipher.getAuthTag();

    return {
        v:
            LAYER2_VERSION,

        iv:
            iv.toString("base64"),

        tag:
            tag.toString("base64"),

        data:
            encrypted.toString(
                "base64"
            )
    };
}

/* =========================================================
   PAYLOAD RECORD
========================================================= */

function createPayloadRecord(
    source,
    ttl
) {

    const id =
        randomId();

    const token =
        randomToken();

    const created =
        Date.now();

    const expires =
        created +
        ttl * 1000;

    /*
     * Layer 1:
     * Provided LEXINX V4 logic.
     */

    const layer1 =
        layer1V4(
            source
        );

    /*
     * Layer 2:
     * AES-GCM.
     */

    const layer2 =
        encryptLayer2(
            layer1,
            id
        );

    const body =
        JSON.stringify(
            layer2
        );

    const signature =
        hmac(
            id +
            "." +
            token +
            "." +
            expires +
            "." +
            body
        );

    const record = {

        id,

        token,

        created,

        expires,

        body,

        signature,

        used: false,

        sourceHash:
            sha256(source),

        payloadHash:
            sha256(layer1)
    };

    payloads.set(
        id,
        record
    );

    return record;
}

/* =========================================================
   RATE LIMIT
========================================================= */

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

    return (
        req.socket
            ?.remoteAddress ||
        "unknown"
    );
}

function checkRate(req) {

    const ip =
        getIP(req);

    const now =
        Date.now();

    let item =
        rateMap.get(ip);

    if (!item) {

        item = {
            start: now,
            count: 0
        };

        rateMap.set(
            ip,
            item
        );
    }

    if (
        now - item.start >
        RATE_WINDOW
    ) {

        item.start =
            now;

        item.count =
            0;
    }

    item.count++;

    if (
        item.count >
        RATE_MAX
    ) {

        return false;
    }

    return true;
}

/* =========================================================
   API ERROR
========================================================= */

function apiError(
    res,
    status,
    code,
    message
) {

    return res
        .status(status)
        .json({
            ok: false,
            error: code,
            message
        });
}

/* =========================================================
   SECURITY HEADERS
========================================================= */

app.use(
    (req, res, next) => {

        res.setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        );

        res.setHeader(
            "Pragma",
            "no-cache"
        );

        res.setHeader(
            "X-Content-Type-Options",
            "nosniff"
        );

        res.setHeader(
            "Referrer-Policy",
            "no-referrer"
        );

        next();
    }
);

/* =========================================================
   RATE LIMIT MIDDLEWARE
========================================================= */

app.use(
    "/api/",
    (req, res, next) => {

        if (
            !checkRate(req)
        ) {

            return apiError(
                res,
                429,
                "RATE_LIMIT",
                "Too many requests."
            );
        }

        next();
    }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/health",
    (req, res) => {

        res.json({
            ok: true,
            service:
                "LEXINX Payload Server",
            version:
                "V4-L2",
            time:
                new Date().toISOString(),
            payloads:
                payloads.size
        });
    }
);

/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.type(
            "html"
        );

        res.send(`
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>LEXINX Protect</title>

<style>

body{
    margin:0;
    background:#070707;
    color:#eee;
    font-family:Arial,sans-serif;
}

.box{
    max-width:650px;
    margin:100px auto;
    padding:30px;
    background:#111;
    border:1px solid #292929;
    border-radius:16px;
    text-align:center;
}

h1{
    margin-top:0;
}

p{
    color:#888;
}

.status{
    color:#8cff9b;
}

</style>
</head>

<body>

<div class="box">

<h1>LEXINX Protect</h1>

<p>
Payload protection service is online.
</p>

<div class="status">
ONLINE
</div>

</div>

</body>
</html>
`);
    }
);

/* =========================================================
   CREATE
========================================================= */

app.post(
    "/api/create",
    (req, res) => {

        try {

            const source =
                typeof req.body?.source ===
                "string"
                    ? req.body.source
                    : "";

            if (
                !source.trim()
            ) {

                return apiError(
                    res,
                    400,
                    "EMPTY_SOURCE",
                    "source is required."
                );
            }

            if (
                Buffer.byteLength(
                    source,
                    "utf8"
                ) >
                MAX_SOURCE_SIZE
            ) {

                return apiError(
                    res,
                    413,
                    "SOURCE_TOO_LARGE",
                    "Lua source is too large."
                );
            }

            let ttl =
                Number(
                    req.body?.ttl
                );

            if (
                !Number.isFinite(ttl)
            ) {

                ttl =
                    DEFAULT_TTL;
            }

            ttl =
                Math.floor(
                    ttl
                );

            ttl =
                Math.max(
                    30,
                    Math.min(
                        ttl,
                        MAX_TTL
                    )
                );

            const record =
                createPayloadRecord(
                    source,
                    ttl
                );

            return res.json({
                ok: true,

                id:
                    record.id,

                token:
                    record.token,

                expires:
                    record.expires,

                ttl,

                sourceHash:
                    record.sourceHash,

                payloadHash:
                    record.payloadHash
            });

        } catch (err) {

            console.error(
                "[CREATE]",
                err
            );

            return apiError(
                res,
                500,
                "CREATE_FAILED",
                err.message ||
                    "Create failed."
            );
        }
    }
);

/* =========================================================
   PAYLOAD AUTH
========================================================= */

function extractToken(req) {

    /*
     * Supports:

       ?token=
       ?key=
       ?auth=

       X-Lexinx-Token

       Authorization: Bearer xxx
    */

    let token =
        req.query?.token ||
        req.query?.key ||
        req.query?.auth ||
        req.headers[
            "x-lexinx-token"
        ];

    if (
        !token &&
        typeof
