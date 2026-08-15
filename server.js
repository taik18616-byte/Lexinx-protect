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

const SESSION_TTL = 2 * 60 * 1000;
const TOKEN_TTL = 20 * 1000;

fs.mkdirSync(DATA_DIR, { recursive: true });

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
            fs.readFileSync(DB_FILE, "utf8")
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

function cleanName(name) {
    return String(name || "Script")
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
   BROWSER BLOCK
========================================================= */

function isBrowserNavigation(req) {
    const accept =
        String(req.headers.accept || "")
            .toLowerCase();

    const fetchMode =
        String(
            req.headers["sec-fetch-mode"] || ""
        ).toLowerCase();

    const fetchDest =
        String(
            req.headers["sec-fetch-dest"] || ""
        ).toLowerCase();

    return (
        accept.includes("text/html") ||
        fetchMode === "navigate" ||
        fetchDest === "document"
    );
}

/* =========================================================
   SESSION
========================================================= */

const sessions = new Map();

function newChallenge() {
    return {
        token: randomHex(32),
        nonce: randomHex(16),
        expiresAt:
            Date.now() + TOKEN_TTL,
        used: false
    };
}

function createSession(scriptId) {
    const session = {
        id: randomHex(32),

        scriptId,

        createdAt: Date.now(),

        expiresAt:
            Date.now() + SESSION_TTL,

        challenge: newChallenge()
    };

    sessions.set(
        session.id,
        session
    );

    return session;
}

function getSession(id) {
    if (
        typeof id !== "string" ||
        !id
    ) {
        return null;
    }

    const session =
        sessions.get(id);

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expiresAt
    ) {
        sessions.delete(id);
        return null;
    }

    return session;
}

function consumeChallenge(
    challenge,
    token,
    nonce
) {
    if (!challenge) {
        return false;
    }

    if (challenge.used) {
        return false;
    }

    if (
        Date.now() >
        challenge.expiresAt
    ) {
        return false;
    }

    if (
        typeof token !== "string" ||
        typeof nonce !== "string"
    ) {
        return false;
    }

    if (
        !crypto.timingSafeEqual(
            Buffer.from(token),
            Buffer.from(challenge.token)
        )
    ) {
        return false;
    }

    if (
        !crypto.timingSafeEqual(
            Buffer.from(nonce),
            Buffer.from(challenge.nonce)
        )
    ) {
        return false;
    }

    challenge.used = true;

    return true;
}

/* =========================================================
   SIMPLE PAYLOAD ENCODING
========================================================= */

function encodePayload(source) {
    const compressed =
        Buffer.from(
            source,
            "utf8"
        );

    /*
     * Server-side representation.
     *
     * Đây không phải mã hóa tuyệt đối.
     * Client vẫn phải giải mã để thực thi.
     */

    const key =
        crypto.randomBytes(32);

    const iv =
        crypto.randomBytes(16);

    const cipher =
        crypto.createCipheriv(
            "aes-256-ctr",
            key,
            iv
        );

    const encrypted =
        Buffer.concat([
            cipher.update(compressed),
            cipher.final()
        ]);

    return {
        data:
            encrypted.toString("base64"),

        key:
            key.toString("base64"),

        iv:
            iv.toString("base64")
    };
}

/* =========================================================
   LUA NAME
========================================================= */

function luaName() {
    return (
        "_" +
        crypto
            .randomBytes(5)
            .toString("hex")
    );
}

/* =========================================================
   BUILD L2
========================================================= */

function buildLayer2(
    payloadUrl,
    session,
    token,
    nonce,
    payload
) {
    const HttpService = "HttpService";
    const Request = luaName();
    const Decode = luaName();
    const Response = luaName();
    const Data = luaName();
    const Result = luaName();
    const Load = luaName();

    /*
     * Payload được chia thành nhiều phần
     * để L2 không chứa trực tiếp Lua source.
     */

    const chunks = [];

    const chunkSize = 64;

    for (
        let i = 0;
        i < payload.data.length;
        i += chunkSize
    ) {
        chunks.push(
            payload.data.slice(
                i,
                i + chunkSize
            )
        );
    }

    const luaChunks =
        chunks
            .map(
                x =>
                    JSON.stringify(x)
            )
            .join(",");

    return `
local ${HttpService} =
    game:GetService("HttpService")

local ${Request} = request

local ${Decode} = function(url, body)

    local ok, response =
        pcall(function()

            return ${Request}({
                Url = url,
                Method = "POST",

                Headers = {
                    ["Content-Type"] =
                        "application/json"
                },

                Body =
                    ${HttpService}:JSONEncode(body)
            })

        end)

    if not ok or not response then
        error("LEXINX BLOCK")
    end

    if response.StatusCode ~= 200 then
        error(
            "LEXINX BLOCK HTTP " ..
            tostring(response.StatusCode)
        )
    end

    local success, data =
        pcall(function()

            return ${HttpService}:JSONDecode(
                response.Body
            )

        end)

    if not success then
        error("LEXINX BLOCK")
    end

    if type(data) ~= "table" then
        error("LEXINX BLOCK")
    end

    if data.ok ~= true then
        error("LEXINX BLOCK")
    end

    return data
end

local ${Response} =
    ${Decode}(
        ${JSON.stringify(payloadUrl)},
        {
            session =
                ${JSON.stringify(session)},

            token =
                ${JSON.stringify(token)},

            nonce =
                ${JSON.stringify(nonce)}
        }
    )

if ${Response}.stage ~= 2 then
    error("LEXINX BLOCK")
end

local ${Data} =
    ${Response}.payload

if type(${Data}) ~= "table" then
    error("LEXINX BLOCK")
end

local ${Result} = table.concat({
    ${luaChunks}
})

if ${Result} ~= ${Data}.data then
    error("LEXINX BLOCK")
end

local function base64Decode(data)

    local chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ..
        "abcdefghijklmnopqrstuvwxyz" ..
        "0123456789+/"

    data =
        data:gsub(
            "[^" .. chars .. "=]",
            ""
        )

    local result = {}

    local buffer = 0
    local bits = 0

    for i = 1, #data do

        local c =
            data:sub(i, i)

        if c ~= "=" then

            local p =
                chars:find(c, 1, true)

            if p then

                buffer =
                    buffer * 64 +
                    (p - 1)

                bits =
                    bits + 6

                if bits >= 8 then

                    bits =
                        bits - 8

                    result[#result + 1] =
                        string.char(
                            math.floor(
                                buffer /
                                2^bits
                            ) % 256
                        )
                end
            end
        end
    end

    return table.concat(result)
end

local ${Load} =
    loadstring or load

if type(${Load}) ~= "function" then
    error("LEXINX BLOCK: loadstring unavailable")
end

/*
 * Server payload hiện được truyền dưới
 * dạng base64. Đây là lớp vận chuyển,
 * không phải cơ chế giữ source tuyệt đối.
 */

local decoded =
    base64Decode(${Result})

if type(decoded) ~= "string" then
    error("LEXINX BLOCK")
end

local fn, err =
    ${Load}(decoded)

if not fn then
    error(
        "LEXINX COMPILE ERROR: " ..
        tostring(err)
    )
end

local ok, runtimeError =
    pcall(fn)

if not ok then
    error(
        "LEXINX RUNTIME ERROR: " ..
        tostring(runtimeError)
    )
end
`;
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    res.send("LEXINX PROTECT ONLINE");
});

/* =========================================================
   CREATE
========================================================= */

app.post(
    "/api/create",
    (req, res) => {

        const source =
            typeof req.body?.source === "string"
                ? req.body.source
                : "";

        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error: "Script is empty"
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
            `${DOMAIN}/api/loader/${id}`;

        secure(res).json({
            ok: true,

            id,

            name,

            endpoint:
                loader,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    loader
                )}))()`
        });
    }
);

/* =========================================================
   EDIT
========================================================= */

app.post(
    "/api/edit/:id",
    (req, res) => {

        const db =
            readDB();

        const script =
            db[req.params.id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
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
            id: script.id,
            name: script.name
        });
    }
);

/* =========================================================
   L1 -> L2
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        if (
            isBrowserNavigation(req)
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

        /*
         * Payload được tạo cho session này.
         */

        const payload =
            encodePayload(
                script.source
            );

        /*
         * L1 chỉ chứa L2.
         */

        const l2 =
            buildLayer2(
                `${DOMAIN}/api/payload`,
                session.id,
                session.challenge.token,
                session.challenge.nonce,
                payload
            );

        const l1 = `
return function()

    local ok, fn =
        pcall(function()

            return loadstring(
                ${JSON.stringify(l2)}
            )

        end)

    if not ok or type(fn) ~= "function" then
        error("LEXINX BLOCK")
    end

    local success, err =
        pcall(fn)

    if not success then
        error(err)
    end

end
`;

        /*
         * L1 phải tự gọi function,
         * để loader ngoài cùng chạy được
         * bằng loadstring(... )().
         */

        const finalLoader = `
local L1 = loadstring(
${JSON.stringify(l2)}
)

if type(L1) ~= "function" then
    error("LEXINX BLOCK")
end

local ok, err =
    pcall(L1)

if not ok then
    error(err)
end
`;

        secure(res)
            .type("text/plain")
            .send(finalLoader);
    }
);

/* =========================================================
   PAYLOAD
========================================================= */

app.get(
    "/api/payload",
    (req, res) => {
        return blocked(res);
    }
);

app.post(
    "/api/payload",
    (req, res) => {

        if (
            isBrowserNavigation(req)
        ) {
            return blocked(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(session);

        if (!s) {
            return blocked(res);
        }

        if (
            !consumeChallenge(
                s.challenge,
                token,
                nonce
            )
        ) {
            return blocked(res);
        }

        const db =
            readDB();

        const script =
            db[s.scriptId];

        if (!script) {
            sessions.delete(
                s.id
            );

            return blocked(res);
        }

        /*
         * Token dùng một lần.
         */

        sessions.delete(
            s.id
        );

        /*
         * Payload được tạo mới ở đây.
         */

        const payload =
            encodePayload(
                script.source
            );

        secure(res).json({
            ok: true,

            stage: 2,

            payload: {
                data:
                    payload.data
            }
        });
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

                        createdAt:
                            script.createdAt,

                        updatedAt:
                            script.updatedAt,

                        endpoint,

                        loader:
                            `loadstring(game:HttpGet(${JSON.stringify(
                                endpoint
                            )}))()`
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
            return res.status(404).json({
                ok: false,
                error: "Script not found"
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
   SESSION CLEANUP
========================================================= */

setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [id, session]
            of sessions
        ) {

            if (
                now >
                session.expiresAt
            ) {
                sessions.delete(id);
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
    () => {

        console.log(
            "================================="
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
            "FLOW:",
            "L1 -> L2 -> PAYLOAD -> SOURCE"
        );

        console.log(
            "SESSION TTL:",
            SESSION_TTL
        );

        console.log(
            "TOKEN TTL:",
            TOKEN_TTL
        );

        console.log(
            "================================="
        );
    }
);
