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

const SESSION_TTL = 120000;
const TOKEN_TTL = 30000;

fs.mkdirSync(DATA_DIR, {
    recursive: true
});

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.disable("x-powered-by");

app.use(express.json({
    limit: "25mb"
}));

/* =========================================================
   DATABASE
========================================================= */

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
        JSON.stringify(db, null, 2),
        "utf8"
    );
}

/* =========================================================
   RANDOM
========================================================= */

function randomHex(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function randomInt(min, max) {
    return Math.floor(
        Math.random() *
        (max - min + 1)
    ) + min;
}

function cleanName(name) {
    return String(
        name || "Script"
    )
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

/* =========================================================
   RESPONSE
========================================================= */

function secure(res) {
    return res
        .set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        )
        .set("Pragma", "no-cache")
        .set(
            "X-Content-Type-Options",
            "nosniff"
        );
}

function blocked(res) {
    return secure(res)
        .status(403)
        .type("text/plain")
        .send("LEXINX BLOCK");
}

/* =========================================================
   BROWSER DETECTION
========================================================= */

function isBrowser(req) {

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

    return (
        mode === "navigate" ||
        dest === "document" ||
        (
            accept.includes("text/html") &&
            !req.headers["user-agent"]?.includes(
                "Roblox"
            )
        )
    );
}

/* =========================================================
   SESSION
========================================================= */

const sessions = new Map();

function createSession(scriptId) {

    const session = {

        id:
            randomHex(32),

        scriptId,

        createdAt:
            Date.now(),

        expiresAt:
            Date.now() +
            SESSION_TTL,

        token:
            randomHex(32),

        nonce:
            randomHex(16),

        tokenExpiresAt:
            Date.now() +
            TOKEN_TTL,

        used: false
    };

    sessions.set(
        session.id,
        session
    );

    return session;
}

function getSession(id) {

    if (
        typeof id !==
        "string"
    ) {
        return null;
    }

    const s =
        sessions.get(id);

    if (!s) {
        return null;
    }

    if (
        Date.now() >
        s.expiresAt
    ) {
        sessions.delete(id);
        return null;
    }

    return s;
}

function safeEqual(a, b) {

    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const A =
        Buffer.from(a);

    const B =
        Buffer.from(b);

    if (
        A.length !== B.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        A,
        B
    );
}

function verifySession(
    sessionId,
    token,
    nonce
) {

    const s =
        getSession(sessionId);

    if (!s) {
        return null;
    }

    if (s.used) {
        return null;
    }

    if (
        Date.now() >
        s.tokenExpiresAt
    ) {
        sessions.delete(
            sessionId
        );

        return null;
    }

    if (
        !safeEqual(
            token,
            s.token
        )
    ) {
        return null;
    }

    if (
        !safeEqual(
            nonce,
            s.nonce
        )
    ) {
        return null;
    }

    s.used = true;

    return s;
}

/* =========================================================
   LUA IDENTIFIER
========================================================= */

function luaName() {

    const chars =
        "abcdefghijklmnopqrstuvwxyz";

    let result = "_";

    for (
        let i = 0;
        i < 8;
        i++
    ) {
        result +=
            chars[
                randomInt(
                    0,
                    chars.length - 1
                )
            ];
    }

    return result;
}

/* =========================================================
   PAYLOAD OBFUSCATION
========================================================= */

function encodeSource(source) {

    const bytes =
        Array.from(
            Buffer.from(
                source,
                "utf8"
            )
        );

    const fragments = [];

    let position = 0;

    while (
        position <
        bytes.length
    ) {

        const size =
            Math.min(
                bytes.length -
                position,

                randomInt(
                    4,
                    10
                )
            );

        const part =
            bytes.slice(
                position,
                position + size
            );

        position += size;

        fragments.push(part);
    }

    const xorKey =
        randomInt(1, 255);

    const addKey =
        randomInt(1, 255);

    const encoded =
        fragments.map(
            fragment =>
                fragment.map(
                    byte =>
                        (
                            (
                                byte ^
                                xorKey
                            ) +
                            addKey
                        ) & 255
                )
        );

    const order =
        encoded.map(
            (_, i) => i
        );

    for (
        let i =
            order.length - 1;
        i > 0;
        i--
    ) {

        const j =
            randomInt(0, i);

        [
            order[i],
            order[j]
        ] = [
            order[j],
            order[i]
        ];
    }

    return {
        fragments: encoded,
        order,
        xorKey,
        addKey
    };
}

/* =========================================================
   LUA ARRAY
========================================================= */

function luaArray(array) {
    return (
        "{" +
        array.join(",") +
        "}"
    );
}

/* =========================================================
   BUILD L2
========================================================= */

function buildLayer2(
    payloadUrl,
    session
) {

    const payload =
        session.payload;

    const Http =
        luaName();

    const Request =
        luaName();

    const Response =
        luaName();

    const Decode =
        luaName();

    const Parts =
        luaName();

    const Order =
        luaName();

    const Output =
        luaName();

    const XorKey =
        luaName();

    const AddKey =
        luaName();

    const Load =
        luaName();

    const Part =
        luaName();

    const Byte =
        luaName();

    const Decoded =
        luaName();

    const fragmentLua =
        payload.fragments
            .map(luaArray)
            .join(",");

    const orderLua =
        luaArray(
            payload.order.map(
                x => x + 1
            )
        );

    /*
     * L2 được sinh mới cho từng loader.
     */

    return `
local ${Http} =
    game:GetService("HttpService")

local ${Request} =
    request or
    http_request or
    (syn and syn.request)

if type(${Request}) ~= "function" then
    error("LEXINX BLOCK: request unavailable")
end

local ${Response}

local ok, result =
    pcall(function()

        return ${Request}({

            Url =
                ${JSON.stringify(
                    payloadUrl
                )},

            Method =
                "POST",

            Headers = {

                ["Content-Type"] =
                    "application/json",

                ["Accept"] =
                    "application/json"

            },

            Body =
                ${Http}:JSONEncode({

                    session =
                        ${JSON.stringify(
                            session.id
                        )},

                    token =
                        ${JSON.stringify(
                            session.token
                        )},

                    nonce =
                        ${JSON.stringify(
                            session.nonce
                        )}

                })

        })

    end)

if not ok or not result then
    error("LEXINX BLOCK")
end

if result.StatusCode ~= 200 then
    error(
        "LEXINX BLOCK HTTP " ..
        tostring(
            result.StatusCode
        )
    )
end

local parsedOk, data =
    pcall(function()

        return ${Http}:JSONDecode(
            result.Body
        )

    end)

if not parsedOk or
   type(data) ~= "table" then

    error("LEXINX BLOCK")

end

if data.ok ~= true or
   data.stage ~= 2 then

    error("LEXINX BLOCK")

end

local ${Parts} = {
    ${fragmentLua}
}

local ${Order} =
    ${orderLua}

local ${XorKey} =
    ${payload.xorKey}

local ${AddKey} =
    ${payload.addKey}

local ${Output} = {}

for i = 1,#${Order} do

    local ${Part} =
        ${Parts}[
            ${Order}[i]
        ]

    for j = 1,#${Part} do

        local ${Byte} =
            ${Part}[j]

        ${Byte} =
            (
                (
                    ${Byte} -
                    ${AddKey}
                ) % 256
            )

        local x =
            ${Byte}

        local y =
            ${XorKey}

        local out = 0
        local bit = 1

        while x > 0 or y > 0 do

            local xb =
                x % 2

            local yb =
                y % 2

            if xb ~= yb then
                out =
                    out + bit
            end

            x =
                math.floor(
                    x / 2
                )

            y =
                math.floor(
                    y / 2
                )

            bit =
                bit * 2

        end

        ${Output}[
            #${Output} + 1
        ] =
            string.char(
                out % 256
            )

    end
end

local ${Decoded} =
    table.concat(
        ${Output}
    )

${Output} = nil
${Parts} = nil
${Order} = nil

local ${Load} =
    loadstring or load

if type(${Load}) ~= "function" then
    error(
        "LEXINX BLOCK: loadstring unavailable"
    )
end

local fn, err =
    ${Load}(
        ${Decoded}
    )

${Decoded} = nil

if type(fn) ~= "function" then
    error(
        "LEXINX COMPILE ERROR: " ..
        tostring(err)
    )
end

local runOk, runErr =
    pcall(fn)

if not runOk then
    error(
        "LEXINX RUNTIME ERROR: " ..
        tostring(runErr)
    )
end
`;
}

/* =========================================================
   HOME
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }
);

/* =========================================================
   CREATE SCRIPT
========================================================= */

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

        const db =
            readDB();

        const id =
            randomHex(12);

        db[id] = {

            id,

            name:
                cleanName(
                    req.body?.name
                ),

            source,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()
        };

        writeDB(db);

        const endpoint =
            `${DOMAIN}/api/loader/${id}`;

        secure(res).json({

            ok: true,

            id,

            endpoint,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    endpoint
                )}))()`
        });
    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.post(
    "/api/edit/:id",
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

        if (
            typeof req.body?.source ===
            "string"
        ) {
            script.source =
                req.body.source;
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

        script.updatedAt =
            Date.now();

        writeDB(db);

        secure(res).json({
            ok: true,
            id:
                script.id
        });
    }
);

/* =========================================================
   L1
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        /*
         * Browser navigation bị block.
         *
         * Không block chỉ dựa vào User-Agent,
         * vì executor có thể không gửi User-Agent.
         */

        if (
            isBrowser(req)
        ) {
            return blocked(res);
        }

        const db =
            readDB();

        const script =
            db[req.params.id];

        if (!script) {
            return blocked(res);
        }

        const session =
            createSession(
                script.id
            );

        session.payload =
            encodeSource(
                script.source
            );

        const l2 =
            buildLayer2(
                `${DOMAIN}/api/payload`,
                session
            );

        /*
         * L1 cực ngắn:
         *
         * loadstring(
         *     HttpGet(...)
         * )()
         *
         * Endpoint trả L2.
         */

        const loader = `
local s =
    game:HttpGet(
        ${JSON.stringify(
            `${DOMAIN}/api/loader/${script.id}`
        )}
    )

local f =
    loadstring(s)

if type(f) ~= "function" then
    error("LEXINX BLOCK")
end

f()
`;

        /*
         * Lưu ý:
         * request /api/loader trực tiếp sẽ
         * nhận L1 chứa L2.
         */

        secure(res)
            .type("text/plain")
            .send(loader);
    }
);

/* =========================================================
   PAYLOAD GET = ALWAYS BLOCK
========================================================= */

app.get(
    "/api/payload",
    (req, res) => {

        return blocked(res);
    }
);

/* =========================================================
   PAYLOAD POST
========================================================= */

app.post(
    "/api/payload",
    (req, res) => {

        /*
         * Chỉ POST mới được xử lý.
         */

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            verifySession(
                session,
                token,
                nonce
            );

        if (!s) {
            return blocked(res);
        }

        /*
         * Session one-time.
         */

        sessions.delete(
            s.id
        );

        const db =
            readDB();

        const script =
            db[s.scriptId];

        if (!script) {
            return blocked(res);
        }

        /*
         * Tạo payload mới.
         */

        const payload =
            encodeSource(
                script.source
            );

        secure(res).json({

            ok: true,

            stage: 2,

            payload: {

                fragments:
                    payload.fragments,

                order:
                    payload.order,

                xorKey:
                    payload.xorKey,

                addKey:
                    payload.addKey
            }
        });
    }
);

/* =========================================================
   DIRECT SOURCE = BLOCK
========================================================= */

app.get(
    "/api/source/:id",
    (req, res) => {

        return blocked(res);
    }
);

/* =========================================================
   SCRIPT LIST
========================================================= */

app.get(
    "/api/scripts",
    (req, res) => {

        const db =
            readDB();

        const scripts =
            Object.values(db)
                .reverse()
                .map(script => {

                    const endpoint =
                        `${DOMAIN}/api/loader/${script.id}`;

                    return {

                        id:
                            script.id,

                        name:
                            script.name,

                        endpoint,

                        loader:
                            `loadstring(game:HttpGet(${JSON.stringify(
                                endpoint
                            )}))()`,

                        createdAt:
                            script.createdAt,

                        updatedAt:
                            script.updatedAt
                    };
                });

        secure(res).json({
            ok: true,
            scripts
        });
    }
);

/* =========================================================
   DELETE
========================================================= */

app.delete(
    "/api/delete/:id",
    (req, res) => {

        const db =
            readDB();

        if (
            !db[req.params.id]
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

        secure(res).json({
            ok: true
        });
    }
);

/* =========================================================
   UNKNOWN API
========================================================= */

app.use(
    "/api",
    (req, res) => {

        return blocked(res);
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        secure(res)
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX BLOCK"
            );
    }
);

/* =========================================================
   CLEAN SESSION
========================================================= */

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
    30000
);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    () => {

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
            "FLOW:",
            "L1 -> L2 -> PAYLOAD"
        );
    }
);
