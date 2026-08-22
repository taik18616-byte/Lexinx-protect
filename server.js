const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://lexinx-protect.onrender.com";

const DATA_DIR =
    path.join(__dirname, "data");

const DB_FILE =
    path.join(DATA_DIR, "accounts.json");

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

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "10mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "10mb"
    })
);

app.use(
    express.static(PUBLIC_DIR)
);

/* =====================================================
   DATABASE
===================================================== */

function readDB() {
    try {
        const text =
            fs.readFileSync(
                DB_FILE,
                "utf8"
            );

        return JSON.parse(text);
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

/* =====================================================
   RANDOM
===================================================== */

function randomID(bytes = 24) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

/* =====================================================
   PASSWORD
===================================================== */

function createPasswordHash(
    password
) {
    const salt =
        crypto.randomBytes(16);

    const hash =
        crypto.scryptSync(
            password,
            salt,
            64
        );

    return {
        salt:
            salt.toString("hex"),

        hash:
            hash.toString("hex")
    };
}

function checkPassword(
    password,
    data
) {
    try {

        const salt =
            Buffer.from(
                data.salt,
                "hex"
            );

        const expected =
            Buffer.from(
                data.hash,
                "hex"
            );

        const actual =
            crypto.scryptSync(
                password,
                salt,
                64
            );

        return (
            actual.length ===
                expected.length &&
            crypto.timingSafeEqual(
                actual,
                expected
            )
        );

    } catch {
        return false;
    }
}

/* =====================================================
   SESSION
===================================================== */

const sessions =
    new Map();

const SESSION_TIME =
    7 * 24 * 60 * 60 * 1000;

function createSession(
    username
) {
    const id =
        randomID(48);

    sessions.set(
        id,
        {
            username,
            expires:
                Date.now() +
                SESSION_TIME
        }
    );

    return id;
}

function cookies(req) {

    const result = {};

    const raw =
        req.headers.cookie;

    if (!raw) {
        return result;
    }

    for (
        const part
        of raw.split(";")
    ) {

        const index =
            part.indexOf("=");

        if (index < 0)
            continue;

        const key =
            part
                .slice(0, index)
                .trim();

        const value =
            part
                .slice(index + 1)
                .trim();

        result[key] =
            decodeURIComponent(
                value
            );
    }

    return result;
}

function setSession(
    res,
    session
) {

    res.setHeader(
        "Set-Cookie",
        [
            `lexinx_session=${encodeURIComponent(session)}`,
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=604800"
        ].join("; ")
    );
}

function removeSession(
    res
) {

    res.setHeader(
        "Set-Cookie",
        [
            "lexinx_session=",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=0"
        ].join("; ")
    );
}

function currentUser(req) {

    const c =
        cookies(req);

    const sid =
        c.lexinx_session;

    if (!sid)
        return null;

    const session =
        sessions.get(sid);

    if (!session)
        return null;

    if (
        Date.now() >
        session.expires
    ) {

        sessions.delete(sid);

        return null;
    }

    return session.username;
}

function auth(
    req,
    res,
    next
) {

    const username =
        currentUser(req);

    if (!username) {

        return res
            .status(401)
            .json({
                ok: false,
                error:
                    "Not logged in"
            });
    }

    req.username =
        username;

    next();
}

/* =====================================================
   ACCOUNT URL
===================================================== */

function accountURL(
    account
) {

    return (
        DOMAIN +
        "/acc/" +
        encodeURIComponent(
            account.username
        ) +
        "/" +
        account.id +
        "/dashboard"
    );
}

/* =====================================================
   HOME
===================================================== */

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

/* =====================================================
   REGISTER
===================================================== */

app.post(
    "/api/register",
    (req, res) => {

        const username =
            String(
                req.body?.username ||
                ""
            ).trim();

        const password =
            String(
                req.body?.password ||
                ""
            );

        if (
            !/^[a-zA-Z0-9_]{3,24}$/
                .test(username)
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Username không hợp lệ"
                });
        }

        if (
            password.length < 6
        ) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Password tối thiểu 6 ký tự"
                });
        }

        const db =
            readDB();

        if (
            db[
                username.toLowerCase()
            ]
        ) {

            return res
                .status(409)
                .json({
                    ok: false,
                    error:
                        "Username đã tồn tại"
                });
        }

        const passwordData =
            createPasswordHash(
                password
            );

        const account = {

            username,

            id:
                randomID(16),

            password: {
                salt:
                    passwordData.salt,

                hash:
                    passwordData.hash
            },

            createdAt:
                Date.now(),

            scripts: {}
        };

        db[
            username.toLowerCase()
        ] = account;

        writeDB(db);

        const session =
            createSession(
                username.toLowerCase()
            );

        setSession(
            res,
            session
        );

        console.log(
            "[REGISTER]",
            username
        );

        return res.json({
            ok: true,

            username:
                account.username,

            accountId:
                account.id,

            url:
                accountURL(
                    account
                )
        });
    }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
    "/api/login",
    (req, res) => {

        const username =
            String(
                req.body?.username ||
                ""
            ).trim();

        const password =
            String(
                req.body?.password ||
                ""
            );

        const db =
            readDB();

        const account =
            db[
                username.toLowerCase()
            ];

        if (
            !account ||
            !checkPassword(
                password,
                account.password
            )
        ) {

            return res
                .status(401)
                .json({
                    ok: false,
                    error:
                        "Sai username hoặc password"
                });
        }

        const session =
            createSession(
                username.toLowerCase()
            );

        setSession(
            res,
            session
        );

        console.log(
            "[LOGIN]",
            account.username
        );

        return res.json({
            ok: true,

            username:
                account.username,

            accountId:
                account.id,

            url:
                accountURL(
                    account
                )
        });
    }
);

/* =====================================================
   ME
===================================================== */

app.get(
    "/api/me",
    auth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        if (!account) {

            return res
                .status(401)
                .json({
                    ok: false
                });
        }

        res.json({
            ok: true,

            username:
                account.username,

            accountId:
                account.id,

            url:
                accountURL(
                    account
                )
        });
    }
);

/* =====================================================
   LOGOUT
===================================================== */

app.post(
    "/api/logout",
    (req, res) => {

        const c =
            cookies(req);

        if (
            c.lexinx_session
        ) {

            sessions.delete(
                c.lexinx_session
            );
        }

        removeSession(res);

        res.json({
            ok: true
        });
    }
);

/* =====================================================
   ACCOUNT PAGE
===================================================== */

app.get(
    "/acc/:username/:id/dashboard",
    (req, res) => {

        const db =
            readDB();

        const account =
            db[
                String(
                    req.params.username
                ).toLowerCase()
            ];

        if (
            !account ||
            account.id !==
                req.params.id
        ) {

            return res
                .status(403)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        const username =
            currentUser(req);

        if (
            !username ||
            username !==
                String(
                    req.params.username
                ).toLowerCase()
        ) {

            return res.redirect(
                "/"
            );
        }

        res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);

/* =====================================================
   CREATE SCRIPT
===================================================== */

app.post(
    "/api/create",
    auth,
    (req, res) => {

        const source =
            String(
                req.body?.source ||
                ""
            );

        const name =
            String(
                req.body?.name ||
                "Script"
            )
            .replace(
                /[^\w .-]/g,
                "_"
            )
            .slice(0, 80);

        if (!source.trim()) {

            return res
                .status(400)
                .json({
                    ok: false,
                    error:
                        "Source rỗng"
                });
        }

        const db =
            readDB();

        const account =
            db[req.username];

        const id =
            randomID(12);

        account.scripts[id] = {

            id,

            name,

            source,

            createdAt:
                Date.now(),

            updatedAt:
                Date.now()
        };

        writeDB(db);

        const endpoint =
            DOMAIN +
            "/api/loader/" +
            id;

        res.json({

            ok: true,

            id,

            name,

            endpoint,

            loader:
                `loadstring(game:HttpGet(${JSON.stringify(endpoint)}))()`
        });
    }
);

/* =====================================================
   LIST SCRIPTS
===================================================== */

app.get(
    "/api/scripts",
    auth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        const scripts =
            Object.values(
                account.scripts || {}
            );

        res.json({
            ok: true,
            scripts:
                scripts.map(
                    script => {

                        const endpoint =
                            DOMAIN +
                            "/api/loader/" +
                            script.id;

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
                                `loadstring(game:HttpGet(${JSON.stringify(endpoint)}))()`
                        };
                    }
                )
        });
    }
);

/* =====================================================
   GET ONE SCRIPT
===================================================== */

app.get(
    "/api/script/:id",
    auth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        const script =
            account?.scripts?.[
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

        res.json({
            ok: true,
            script
        });
    }
);

/* =====================================================
   DELETE
===================================================== */

app.delete(
    "/api/delete/:id",
    auth,
    (req, res) => {

        const db =
            readDB();

        const account =
            db[req.username];

        if (
            !account?.scripts?.[
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

        delete account.scripts[
            req.params.id
        ];

        writeDB(db);

        res.json({
            ok: true
        });
    }
);

/* =====================================================
   LOADER
===================================================== */

app.get(
    "/api/loader/:id",
    (req, res) => {

        /*
         * Browser navigation:
         * block.
         */

        const accept =
            String(
                req.headers.accept ||
                ""
            ).toLowerCase();

        const fetchDest =
            String(
                req.headers[
                    "sec-fetch-dest"
                ] ||
                ""
            ).toLowerCase();

        if (
            accept.includes(
                "text/html"
            ) ||
            fetchDest ===
                "document"
        ) {

            return res
                .status(403)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        const db =
            readDB();

        let script = null;

        for (
            const username
            of Object.keys(db)
        ) {

            const account =
                db[username];

            if (
                account.scripts &&
                account.scripts[
                    req.params.id
                ]
            ) {

                script =
                    account.scripts[
                        req.params.id
                    ];

                break;
            }
        }

        if (!script) {

            return res
                .status(404)
                .type("text/plain")
                .send(
                    "LEXINX BLOCK"
                );
        }

        /*
         * L1 chỉ trả runtime loader.
         * Không đặt source trực tiếp ở đây.
         */

        const runtime =
            DOMAIN +
            "/api/runtime/" +
            script.id;

        const lua = `
local response = request({
    Url = ${JSON.stringify(runtime)},
    Method = "POST",
    Headers = {
        ["Content-Type"] = "application/json"
    },
    Body = "{}"
})

if not response then
    error("LEXINX BLOCK")
end

if response.StatusCode ~= 200 then
    error("LEXINX BLOCK")
end

local HttpService =
    game:GetService("HttpService")

local data =
    HttpService:JSONDecode(
        response.Body
    )

if type(data) ~= "table"
or data.ok ~= true
or type(data.code) ~= "string" then
    error("LEXINX BLOCK")
end

local fn, err =
    loadstring(data.code)

if not fn then
    error(err)
end

local success, runtimeError =
    pcall(fn)

if not success then
    error(runtimeError)
end
`.trim();

        res
            .status(200)
            .type("text/plain")
            .set(
                "Cache-Control",
                "no-store"
            )
            .set(
                "X-Content-Type-Options",
                "nosniff"
            )
            .send(lua);
    }
);

/* =====================================================
   RUNTIME
===================================================== */

app.post(
    "/api/runtime/:id",
    (req, res) => {

        const db =
            readDB();

        let script = null;

        for (
            const username
            of Object.keys(db)
        ) {

            const account =
                db[username];

            if (
                account.scripts &&
                account.scripts[
                    req.params.id
                ]
            ) {

                script =
                    account.scripts[
                        req.params.id
                    ];

                break;
            }
        }

        if (!script) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "LEXINX BLOCK"
                });
        }

        /*
         * Nếu có lexinx-obf.js,
         * obfuscate source tại runtime.
         *
         * Nếu chưa có file obfuscator,
         * trả source nguyên bản để hệ thống
         * vẫn hoạt động.
         */

        let code =
            script.source;

        try {

            const obf =
                require(
                    "./lexinx-obf.js"
                );

            if (
                typeof obf.obfuscateLua ===
                "function"
            ) {

                code =
                    obf.obfuscateLua(
                        script.source,
                        {
                            stripComments:
                                true,

                            packStrings:
                                true
                        }
                    );
            }

        } catch (error) {

            console.warn(
                "[OBF WARNING]",
                error.message
            );
        }

        res
            .status(200)
            .json({
                ok: true,
                code
            });
    }
);

/* =====================================================
   404
===================================================== */

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

/* =====================================================
   SESSION CLEANUP
===================================================== */

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
                session.expires
            ) {

                sessions.delete(
                    id
                );
            }
        }

    },
    60 * 1000
);

/* =====================================================
   START
===================================================== */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "================================"
        );

        console.log(
            "LEXINX PROTECT ONLINE"
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
            "PUBLIC:",
            PUBLIC_DIR
        );

        console.log(
            "DATABASE:",
            DB_FILE
        );

        console.log(
            "================================"
        );
    }
);
