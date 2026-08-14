const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect.onrender.com";

/*
========================================================
CONFIG
========================================================
*/

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "scripts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_TTL = 2 * 60 * 1000;
const TOKEN_TTL = 20 * 1000;

/*
 * QUAN TRỌNG:
 *
 * Trên Render nên đặt:
 *
 * LEXINX_MASTER_KEY=<64 hex characters>
 *
 * Không hard-code key vào source.
 */

const MASTER_KEY_HEX =
    process.env.LEXINX_MASTER_KEY || "";

if (!/^[0-9a-fA-F]{64}$/.test(MASTER_KEY_HEX)) {
    console.error(
        "Missing/invalid LEXINX_MASTER_KEY."
    );
    console.error(
        "Set a 32-byte key as 64 hexadecimal characters."
    );
    process.exit(1);
}

const MASTER_KEY =
    Buffer.from(
        MASTER_KEY_HEX,
        "hex"
    );

/*
========================================================
DIRECTORIES
========================================================
*/

fs.mkdirSync(
    DATA_DIR,
    { recursive: true }
);

fs.mkdirSync(
    PUBLIC_DIR,
    { recursive: true }
);

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

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "25mb"
    })
);

app.use(
    express.static(
        PUBLIC_DIR
    )
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
    const temp =
        DB_FILE + ".tmp";

    fs.writeFileSync(
        temp,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );

    fs.renameSync(
        temp,
        DB_FILE
    );
}

/*
========================================================
RANDOM
========================================================
*/

function randomHex(bytes = 32) {
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
AES-256-GCM
========================================================

Storage format:

{
    algorithm,
    iv,
    tag,
    data
}

AES-GCM cung cấp:
- confidentiality
- integrity/authentication
========================================================
*/

function encryptSource(source) {

    const iv =
        crypto.randomBytes(12);

    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            MASTER_KEY,
            iv
        );

    const encrypted =
        Buffer.concat([
            cipher.update(
                Buffer.from(
                    source,
                    "utf8"
                )
            ),
            cipher.final()
        ]);

    const tag =
        cipher.getAuthTag();

    return {
        algorithm:
            "aes-256-gcm",

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

function decryptSource(record) {

    if (
        !record ||
        record.algorithm !==
            "aes-256-gcm"
    ) {
        throw new Error(
            "Invalid encrypted source"
        );
    }

    const iv =
        Buffer.from(
            record.iv,
            "base64"
        );

    const tag =
        Buffer.from(
            record.tag,
            "base64"
        );

    const encrypted =
        Buffer.from(
            record.data,
            "base64"
        );

    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            MASTER_KEY,
            iv
        );

    decipher.setAuthTag(
        tag
    );

    const decrypted =
        Buffer.concat([
            decipher.update(
                encrypted
            ),
            decipher.final()
        ]);

    return decrypted.toString(
        "utf8"
    );
}

/*
========================================================
SECURITY RESPONSE
========================================================
*/

function secure(res) {
    return res
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
        );
}

function block(res) {
    return secure(res)
        .status(403)
        .type("text/plain")
        .send(
            "LEXINX BLOCK"
        );
}

/*
========================================================
BROWSER NAVIGATION CHECK
========================================================
*/

function browserNavigation(req) {

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
        accept.includes(
            "text/html"
        ) ||
        mode === "navigate" ||
        dest === "document"
    );
}

/*
========================================================
SESSION
========================================================
*/

const sessions = new Map();

function createChallenge() {

    return {
        token:
            randomHex(32),

        nonce:
            randomHex(16),

        expiresAt:
            Date.now() +
            TOKEN_TTL,

        used:
            false
    };
}

function createSession(
    scriptID
) {

    const session = {

        id:
            randomHex(32),

        scriptID,

        createdAt:
            Date.now(),

        expiresAt:
            Date.now() +
            SESSION_TTL,

        stage:
            2,

        l2:
            createChallenge(),

        l3:
            null,

        l4:
            null,

        l5:
            null
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

    const session =
        sessions.get(id);

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expiresAt
    ) {

        sessions.delete(
            id
        );

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
        typeof token !==
            "string" ||
        typeof nonce !==
            "string"
    ) {
        return false;
    }

    if (
        !crypto.timingSafeEqual(
            Buffer.from(
                token
            ),
            Buffer.from(
                challenge.token
            )
        )
    ) {
        return false;
    }

    if (
        !crypto.timingSafeEqual(
            Buffer.from(
                nonce
            ),
            Buffer.from(
                challenge.nonce
            )
        )
    ) {
        return false;
    }

    challenge.used =
        true;

    return true;
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

        const encrypted =
            encryptSource(
                source
            );

        const db =
            readDB();

        db[id] = {

            id,

            name,

            source:
                encrypted,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()
        };

        writeDB(db);

        const loaderURL =
            `${DOMAIN}/api/loader/${id}`;

        secure(res).json({

            ok: true,

            id,

            name,

            endpoint:
                loaderURL,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    loaderURL
                )}))()`
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
                encryptSource(
                    req.body.source
                );
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

        const loaderURL =
            `${DOMAIN}/api/loader/${script.id}`;

        secure(res).json({

            ok: true,

            id:
                script.id,

            name:
                script.name,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    loaderURL
                )}))()`
        });
    }
);

/*
========================================================
L1
========================================================

L1 không chứa source.
Nó chỉ nhận challenge rồi chạy chain.
========================================================
*/

app.get(
    "/api/loader/:id",
    (req, res) => {

        if (
            browserNavigation(req)
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
            return block(res);
        }

        /*
         * Kiểm tra encrypted payload
         * trước khi tạo session.
         */

        if (
            !script.source ||
            script.source.algorithm !==
                "aes-256-gcm"
        ) {
            return block(res);
        }

        const session =
            createSession(
                script.id
            );

        const lua = `
local HttpService = game:GetService("HttpService")

local DOMAIN = ${JSON.stringify(
            DOMAIN
        )}

local SESSION = ${JSON.stringify(
            session.id
        )}

local TOKEN = ${JSON.stringify(
            session.l2.token
        )}

local NONCE = ${JSON.stringify(
            session.l2.nonce
        )}

local function requestJSON(
    url,
    body
)

    local ok, response =
        pcall(function()

            return request({

                Url = url,

                Method = "POST",

                Headers = {
                    ["Content-Type"] =
                        "application/json"
                },

                Body =
                    HttpService:JSONEncode(
                        body
                    )
            })

        end)

    if not ok then
        error("LEXINX BLOCK")
    end

    if not response then
        error("LEXINX BLOCK")
    end

    if response.StatusCode ~= 200 then
        error(
            "LEXINX BLOCK HTTP " ..
            tostring(
                response.StatusCode
            )
        )
    end

    local okJSON, data =
        pcall(function()

            return HttpService:JSONDecode(
                response.Body
            )

        end)

    if not okJSON then
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

--------------------------------------------------------
-- L2 -> L3
--------------------------------------------------------

local L3 =
    requestJSON(
        DOMAIN .. "/api/l3",
        {
            session = SESSION,
            token = TOKEN,
            nonce = NONCE
        }
    )

if L3.stage ~= 3 then
    error("LEXINX BLOCK")
end

--------------------------------------------------------
-- L3 -> L4
--------------------------------------------------------

local L4 =
    requestJSON(
        DOMAIN .. "/api/l4",
        {
            session = L3.session,
            token = L3.token,
            nonce = L3.nonce
        }
    )

if L4.stage ~= 4 then
    error("LEXINX BLOCK")
end

--------------------------------------------------------
-- L4 -> L5
--------------------------------------------------------

local L5 =
    requestJSON(
        DOMAIN .. "/api/l5",
        {
            session = L4.session,
            token = L4.token,
            nonce = L4.nonce
        }
    )

if L5.stage ~= 5 then
    error("LEXINX BLOCK")
end

--------------------------------------------------------
-- L5 -> SOURCE
--------------------------------------------------------

local result =
    requestJSON(
        DOMAIN .. "/api/data",
        {
            session = L5.session,
            token = L5.token,
            nonce = L5.nonce
        }
    )

if type(result.code) ~= "string" then
    error(
        "LEXINX BLOCK: SOURCE MISSING"
    )
end

--------------------------------------------------------
-- EXECUTE
--------------------------------------------------------

local fn, compileError =
    loadstring(result.code)

if not fn then
    error(
        "LEXINX COMPILE ERROR: " ..
        tostring(
            compileError
        )
    )
end

local success, runtimeError =
    pcall(fn)

if not success then
    error(
        "LEXINX RUNTIME ERROR: " ..
        tostring(
            runtimeError
        )
    )
end
`;

        secure(res)
            .type("text/plain")
            .send(lua);
    }
);

/*
========================================================
L2 -> L3
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
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(
                session
            );

        if (!s) {
            return block(res);
        }

        if (s.stage !== 2) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l2,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        s.l3 =
            createChallenge();

        s.stage = 3;

        secure(res).json({

            ok: true,

            stage: 3,

            session:
                s.id,

            token:
                s.l3.token,

            nonce:
                s.l3.nonce
        });
    }
);

/*
========================================================
L3 -> L4
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
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(
                session
            );

        if (!s) {
            return block(res);
        }

        if (s.stage !== 3) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l3,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        s.l4 =
            createChallenge();

        s.stage = 4;

        secure(res).json({

            ok: true,

            stage: 4,

            session:
                s.id,

            token:
                s.l4.token,

            nonce:
                s.l4.nonce
        });
    }
);

/*
========================================================
L4 -> L5
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
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(
                session
            );

        if (!s) {
            return block(res);
        }

        if (s.stage !== 4) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l4,
                token,
                nonce
            )
        ) {
            return block(res);
        }

        s.l5 =
            createChallenge();

        s.stage = 5;

        secure(res).json({

            ok: true,

            stage: 5,

            session:
                s.id,

            token:
                s.l5.token,

            nonce:
                s.l5.nonce
        });
    }
);

/*
========================================================
L5 -> SOURCE
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
            browserNavigation(req)
        ) {
            return block(res);
        }

        const {
            session,
            token,
            nonce
        } = req.body || {};

        const s =
            getSession(
                session
            );

        if (!s) {
            return block(res);
        }

        if (s.stage !== 5) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.l5,
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
                s.scriptID
            ];

        if (!script) {

            sessions.delete(
                s.id
            );

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found"
                });
        }

        /*
         * Decrypt chỉ tại bước cuối.
         */

        let source;

        try {

            source =
                decryptSource(
                    script.source
                );

        } catch {

            sessions.delete(
                s.id
            );

            return block(res);
        }

        /*
         * Session bị hủy ngay sau
         * khi lấy source.
         */

        sessions.delete(
            s.id
        );

        secure(res).json({

            ok: true,

            code:
                source
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
            Object.values(db)
                .reverse()
                .map(
                    script => {

                        const url =
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

                            endpoint:
                                url,

                            loader:
                                `loadstring(game:HttpGet(${JSON.stringify(
                                    url
                                )}))()`
                        };
                    }
                );

        secure(res).json({

            ok: true,

            scripts
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

        secure(res).json({
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

        secure(res)
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX BLOCK"
            );
    }
);

/*
========================================================
SESSION CLEANUP
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
            "================================"
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
            "L1 -> L2 -> L3 -> L4 -> L5 -> SOURCE"
        );

        console.log(
            "AES:",
            "AES-256-GCM"
        );

        console.log(
            "SESSION TTL:",
            SESSION_TTL,
            "ms"
        );

        console.log(
            "TOKEN TTL:",
            TOKEN_TTL,
            "ms"
        );

        console.log(
            "================================"
        );
    }
);
