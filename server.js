const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "scripts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_TTL = 2 * 60 * 1000;
const TOKEN_TTL = 20 * 1000;

const MASTER_KEY_HEX =
    process.env.LEXINX_MASTER_KEY || "";

if (!/^[0-9a-fA-F]{64}$/.test(MASTER_KEY_HEX)) {
    console.error(
        "LEXINX_MASTER_KEY must be exactly 64 hexadecimal characters."
    );
    process.exit(1);
}

const MASTER_KEY =
    Buffer.from(MASTER_KEY_HEX, "hex");

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

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "25mb"
    })
);

app.use(
    express.static(PUBLIC_DIR)
);

/* ========================================================
   DATABASE
======================================================== */

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
    const tmp =
        DB_FILE + ".tmp";

    fs.writeFileSync(
        tmp,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );

    fs.renameSync(
        tmp,
        DB_FILE
    );
}

/* ========================================================
   HELPERS
======================================================== */

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

function safeEqual(a, b) {
    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const aa = Buffer.from(a);
    const bb = Buffer.from(b);

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        aa,
        bb
    );
}

/* ========================================================
   AES-256-GCM
======================================================== */

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
        algorithm: "aes-256-gcm",
        iv: iv.toString("base64"),
        tag: tag.toString("base64"),
        data: encrypted.toString("base64")
    };
}

function decryptSource(record) {
    if (
        !record ||
        record.algorithm !== "aes-256-gcm"
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

    const data =
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

    decipher.setAuthTag(tag);

    const plain =
        Buffer.concat([
            decipher.update(data),
            decipher.final()
        ]);

    return plain.toString("utf8");
}

/* ========================================================
   L2 PACKER

   Chỉ dùng để đóng gói L2.
   Không chứa source.
======================================================== */

function createL2Payload() {
    const nonce = randomHex(16);

    const payload = [
        "local HttpService=game:GetService(\"HttpService\")",
        `local DOMAIN=${JSON.stringify(DOMAIN)}`,
        "return function(session,token,nonce)",
        "local r=request({",
        "Url=DOMAIN..\"/api/stage/2\",",
        "Method=\"POST\",",
        "Headers={[\"Content-Type\"]=\"application/json\"},",
        "Body=HttpService:JSONEncode({session=session,token=token,nonce=nonce})",
        "})",
        "if not r or r.StatusCode~=200 then error(\"LEXINX BLOCK\") end",
        "local ok,d=pcall(function() return HttpService:JSONDecode(r.Body) end)",
        "if not ok or type(d)~=\"table\" or d.ok~=true or d.stage~=2 then error(\"LEXINX BLOCK\") end",
        "return d",
        "end"
    ].join("\n");

    const encoded =
        Buffer.from(
            payload,
            "utf8"
        ).toString("base64");

    const checksum =
        crypto
            .createHash("sha256")
            .update(encoded)
            .digest("hex");

    return {
        version: 1,
        nonce,
        encoding: "base64",
        checksum,
        payload: encoded
    };
}

/* ========================================================
   SECURITY HEADERS
======================================================== */

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
        .send("LEXINX BLOCK");
}

function isBrowserNavigation(req) {
    const accept =
        String(
            req.headers.accept || ""
        ).toLowerCase();

    const mode =
        String(
            req.headers["sec-fetch-mode"] || ""
        ).toLowerCase();

    const dest =
        String(
            req.headers["sec-fetch-dest"] || ""
        ).toLowerCase();

    return (
        accept.includes("text/html") ||
        mode === "navigate" ||
        dest === "document"
    );
}

/* ========================================================
   SESSIONS
======================================================== */

const sessions = new Map();

function newChallenge() {
    return {
        token: randomHex(32),
        nonce: randomHex(16),
        expiresAt:
            Date.now() +
            TOKEN_TTL,
        used: false
    };
}

function createSession(scriptID) {
    const session = {
        id: randomHex(32),
        scriptID,
        createdAt: Date.now(),
        expiresAt:
            Date.now() +
            SESSION_TTL,
        stage: 1,
        challenges: {
            1: newChallenge(),
            2: null,
            3: null,
            4: null,
            5: null
        }
    };

    sessions.set(
        session.id,
        session
    );

    return session;
}

function getSession(id) {
    if (
        typeof id !== "string"
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
        !safeEqual(
            token,
            challenge.token
        )
    ) {
        return false;
    }

    if (
        !safeEqual(
            nonce,
            challenge.nonce
        )
    ) {
        return false;
    }

    challenge.used = true;

    return true;
}

function nextStage(
    session,
    expected,
    next
) {
    if (
        session.stage !==
        expected
    ) {
        return null;
    }

    const challenge =
        newChallenge();

    session.challenges[next] =
        challenge;

    session.stage = next;

    return challenge;
}

/* ========================================================
   HOME
======================================================== */

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

/* ========================================================
   CREATE SCRIPT
======================================================== */

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
            source:
                encryptSource(
                    source
                ),

            l2:
                createL2Payload(),

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
            name,
            endpoint,
            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    endpoint
                )}))()`
        });
    }
);

/* ========================================================
   EDIT SCRIPT

   Khi edit source, L2 cũng được tạo lại.
======================================================== */

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

            script.l2 =
                createL2Payload();
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

        const endpoint =
            `${DOMAIN}/api/loader/${script.id}`;

        secure(res).json({
            ok: true,
            id: script.id,
            name: script.name,
            endpoint,
            loader:
                `loadstring(game:HttpGet(${JSON.stringify(
                    endpoint
                )}))()`
        });
    }
);

/* ========================================================
   L1 -> L2

   Browser navigation => 403.
   Roblox loader => Lua L1.
======================================================== */

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
            return block(res);
        }

        const session =
            createSession(
                script.id
            );

        const l2 =
            script.l2 ||
            createL2Payload();

        /*
         * L1 chỉ chứa loader.
         * L2 payload được encode base64.
         */

        const lua = `
local HttpService=game:GetService("HttpService")

local B64=${JSON.stringify(
            l2.payload
        )}

local CHECK=${JSON.stringify(
            l2.checksum
        )}

local function decodeBase64(s)
    local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local out={}
    local buffer=0
    local bits=0

    for i=1,#s do
        local c=s:sub(i,i)
        if c~="=" then
            local p=chars:find(c,1,true)
            if p then
                buffer=buffer*64+(p-1)
                bits=bits+6

                if bits>=8 then
                    bits=bits-8
                    local b=math.floor(buffer/2^bits)%256
                    out[#out+1]=string.char(b)
                end
            end
        end
    end

    return table.concat(out)
end

local L2=decodeBase64(B64)

local DOMAIN=${JSON.stringify(
            DOMAIN
        )}

local SESSION=${JSON.stringify(
            session.id
        )}

local TOKEN=${JSON.stringify(
            session.challenges[1].token
        )}

local NONCE=${JSON.stringify(
            session.challenges[1].nonce
        )}

local response=request({
    Url=DOMAIN.."/api/stage/2",
    Method="POST",
    Headers={
        ["Content-Type"]="application/json"
    },
    Body=HttpService:JSONEncode({
        session=SESSION,
        token=TOKEN,
        nonce=NONCE
    })
})

if not response or response.StatusCode~=200 then
    error("LEXINX BLOCK")
end

local ok,data=pcall(function()
    return HttpService:JSONDecode(
        response.Body
    )
end)

if not ok or type(data)~="table" then
    error("LEXINX BLOCK")
end

if data.ok~=true or data.stage~=2 then
    error("LEXINX BLOCK")
end

local function post(path,body)
    local r=request({
        Url=DOMAIN..path,
        Method="POST",
        Headers={
            ["Content-Type"]="application/json"
        },
        Body=HttpService:JSONEncode(body)
    })

    if not r or r.StatusCode~=200 then
        error("LEXINX BLOCK")
    end

    local success,result=pcall(function()
        return HttpService:JSONDecode(
            r.Body
        )
    end)

    if not success or type(result)~="table" then
        error("LEXINX BLOCK")
    end

    if result.ok~=true then
        error("LEXINX BLOCK")
    end

    return result
end

local L3=post(
    "/api/stage/3",
    {
        session=data.session,
        token=data.token,
        nonce=data.nonce
    }
)

if L3.stage~=3 then
    error("LEXINX BLOCK")
end

local L4=post(
    "/api/stage/4",
    {
        session=L3.session,
        token=L3.token,
        nonce=L3.nonce
    }
)

if L4.stage~=4 then
    error("LEXINX BLOCK")
end

local L5=post(
    "/api/stage/5",
    {
        session=L4.session,
        token=L4.token,
        nonce=L4.nonce
    }
)

if L5.stage~=5 then
    error("LEXINX BLOCK")
end

local source=post(
    "/api/source",
    {
        session=L5.session,
        token=L5.token,
        nonce=L5.nonce
    }
)

if type(source.code)~="string" then
    error("LEXINX BLOCK")
end

local fn,err=loadstring(source.code)

if not fn then
    error(
        "LEXINX COMPILE ERROR: "
        ..tostring(err)
    )
end

local success,runtimeErr=pcall(fn)

if not success then
    error(
        "LEXINX RUNTIME ERROR: "
        ..tostring(runtimeErr)
    )
end
`;

        secure(res)
            .type("text/plain")
            .send(lua);
    }
);

/* ========================================================
   STAGE 2
======================================================== */

app.get(
    "/api/stage/2",
    (req, res) => block(res)
);

app.post(
    "/api/stage/2",
    (req, res) => {
        if (
            isBrowserNavigation(req)
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

        if (!s || s.stage !== 1) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.challenges[1],
                token,
                nonce
            )
        ) {
            return block(res);
        }

        const next =
            nextStage(
                s,
                1,
                2
            );

        if (!next) {
            return block(res);
        }

        secure(res).json({
            ok: true,
            stage: 2,
            session: s.id,
            token: next.token,
            nonce: next.nonce
        });
    }
);

/* ========================================================
   STAGE 3
======================================================== */

app.get(
    "/api/stage/3",
    (req, res) => block(res)
);

app.post(
    "/api/stage/3",
    (req, res) => {
        if (
            isBrowserNavigation(req)
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

        if (!s || s.stage !== 2) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.challenges[2],
                token,
                nonce
            )
        ) {
            return block(res);
        }

        const next =
            nextStage(
                s,
                2,
                3
            );

        if (!next) {
            return block(res);
        }

        secure(res).json({
            ok: true,
            stage: 3,
            session: s.id,
            token: next.token,
            nonce: next.nonce
        });
    }
);

/* ========================================================
   STAGE 4
======================================================== */

app.get(
    "/api/stage/4",
    (req, res) => block(res)
);

app.post(
    "/api/stage/4",
    (req, res) => {
        if (
            isBrowserNavigation(req)
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

        if (!s || s.stage !== 3) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.challenges[3],
                token,
                nonce
            )
        ) {
            return block(res);
        }

        const next =
            nextStage(
                s,
                3,
                4
            );

        if (!next) {
            return block(res);
        }

        secure(res).json({
            ok: true,
            stage: 4,
            session: s.id,
            token: next.token,
            nonce: next.nonce
        });
    }
);

/* ========================================================
   STAGE 5
======================================================== */

app.get(
    "/api/stage/5",
    (req, res) => block(res)
);

app.post(
    "/api/stage/5",
    (req, res) => {
        if (
            isBrowserNavigation(req)
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

        if (!s || s.stage !== 4) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.challenges[4],
                token,
                nonce
            )
        ) {
            return block(res);
        }

        const next =
            nextStage(
                s,
                4,
                5
            );

        if (!next) {
            return block(res);
        }

        secure(res).json({
            ok: true,
            stage: 5,
            session: s.id,
            token: next.token,
            nonce: next.nonce
        });
    }
);

/* ========================================================
   SOURCE
======================================================== */

app.get(
    "/api/source",
    (req, res) => block(res)
);

app.post(
    "/api/source",
    (req, res) => {
        if (
            isBrowserNavigation(req)
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

        if (!s || s.stage !== 5) {
            return block(res);
        }

        if (
            !consumeChallenge(
                s.challenges[5],
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

            return block(res);
        }

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
         * One-time session destroyed.
         */

        sessions.delete(
            s.id
        );

        secure(res).json({
            ok: true,
            code: source
        });
    }
);

/* ========================================================
   LIST
======================================================== */

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

/* ========================================================
   DELETE
======================================================== */

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

/* ========================================================
   UNKNOWN API
======================================================== */

app.use(
    "/api",
    (req, res) => {
        block(res);
    }
);

/* ========================================================
   404
======================================================== */

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

/* ========================================================
   CLEAN EXPIRED SESSIONS
======================================================== */

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
                sessions.delete(id);
            }
        }
    },
    30 * 1000
);

/* ========================================================
   START
======================================================== */

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
            "Domain:",
            DOMAIN
        );

        console.log(
            "Port:",
            PORT
        );

        console.log(
            "Flow:",
            "L1 -> L2(encoded) -> L3 -> L4 -> L5 -> SOURCE"
        );

        console.log(
            "Encryption:",
            "AES-256-GCM"
        );

        console.log(
            "======================================"
        );
    }
);
