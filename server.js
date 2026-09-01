const express = require("express");
const crypto = require("crypto");
const path = require("path");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

const TOKEN_TTL = 60 * 1000;

/* =========================================================
   EXPRESS
========================================================= */

app.use(express.json({ limit: "1mb" }));

const publicPath =
    path.join(__dirname, "public");

app.use(
    express.static(publicPath)
);

/* =========================================================
   POSTGRESQL
========================================================= */

if (!process.env.DATABASE_URL) {

    console.error(
        "DATABASE_URL is missing"
    );

}

const pool = new Pool({
    connectionString:
        process.env.DATABASE_URL,

    ssl:
        process.env.NODE_ENV === "production"
            ? { rejectUnauthorized: false }
            : false
});

/* =========================================================
   DATABASE INIT
========================================================= */

async function initDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (

            id BIGSERIAL PRIMARY KEY,

            username VARCHAR(32)
                UNIQUE NOT NULL,

            password_hash TEXT
                NOT NULL,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW(),

            last_login TIMESTAMPTZ

        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS sessions (

            id TEXT PRIMARY KEY,

            user_id BIGINT
                NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW(),

            expires_at TIMESTAMPTZ
                NOT NULL

        );
    `);

    console.log(
        "PostgreSQL database ready"
    );
}

/* =========================================================
   DATABASE START
========================================================= */

initDatabase().catch(error => {

    console.error(
        "Database initialization failed:",
        error
    );

});

/* =========================================================
   RANDOM
========================================================= */

function randomHex(size = 32) {

    return crypto
        .randomBytes(size)
        .toString("hex");

}

function createToken() {

    return randomHex(32);

}

/* =========================================================
   SCRIPTS
========================================================= */

const scripts = new Map();

scripts.set(
    "58ceecd03f8a061d8af1d341",
    {
        source: `
print("LEXINX PAYLOAD RUNNING")
`
    }
);

/* =========================================================
   LOADER SESSION STORAGE
========================================================= */

const sessions = new Map();

/* =========================================================
   LOADER SESSION
========================================================= */

function createLoaderSession(scriptId) {

    const id =
        randomHex(32);

    const session = {

        id,

        scriptId,

        stage: 1,

        tokens: new Set(),

        created: Date.now(),

        expires:
            Date.now() +
            TOKEN_TTL

    };

    sessions.set(
        id,
        session
    );

    return session;
}

function issueToken(session) {

    const token =
        createToken();

    session.tokens.add(
        token
    );

    return token;
}

function consumeToken(
    session,
    token
) {

    if (!token) {
        return false;
    }

    if (
        !session.tokens.has(
            token
        )
    ) {
        return false;
    }

    session.tokens.delete(
        token
    );

    return true;
}

function validLoaderSession(
    session
) {

    if (!session) {
        return false;
    }

    if (
        Date.now() >
        session.expires
    ) {

        sessions.delete(
            session.id
        );

        return false;
    }

    return true;
}

/* =========================================================
   API ERROR
========================================================= */

function apiBlock(
    res,
    message = "LEXINX BLOCK"
) {

    return res.status(403).json({

        ok: false,

        error: message

    });

}

/* =========================================================
   LUA
========================================================= */

function luaString(value) {

    return JSON.stringify(
        String(value)
    );

}

function randomLuaName() {

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
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];

    }

    return result;
}

/* =========================================================
   L2
========================================================= */

function buildL2(session) {

    const vm =
        randomLuaName();

    const run =
        randomLuaName();

    const data =
        randomLuaName();

    const endpoint =
        randomLuaName();

    const nextToken =
        issueToken(session);

    return `
-- LEXINX L2

local ${data} = {

    strings = {

        [0] = "/api/l3",
        [1] = ${luaString(nextToken)},
        [2] = ${luaString(session.id)}

    },

    constants = {

        [0] = 2

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(p)

    local stack = {}

    for _, instruction in ipairs(
        p.instructions
    ) do

        if instruction.opcode == "LOADK" then

            table.insert(
                stack,
                p.strings[
                    instruction.arg
                ]
            )

        end

    end

    return stack

end

local ${vm} =
    ${run}(${data})

local ${endpoint} =
    "https://Lexinx-protect.onrender.com/api/l3"

local ok, response =
    pcall(function()

        return game:HttpGet(
            ${endpoint}
            .. "?session="
            .. ${luaString(session.id)}
            .. "&token="
            .. ${luaString(nextToken)}
        )

    end)

if not ok then
    return
end

local fn =
    loadstring(response)

if fn then
    return fn()
end
`;
}

/* =========================================================
   L3
========================================================= */

function buildL3(session) {

    const nextToken =
        issueToken(session);

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    return `
-- LEXINX L3

local ${data} = {

    strings = {

        [0] = "/api/l4",
        [1] = ${luaString(session.id)},
        [2] = ${luaString(nextToken)}

    },

    constants = {

        [0] = 3

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(program)

    local stack = {}

    for _, instruction in ipairs(
        program.instructions
    ) do

        if instruction.opcode == "LOADK" then

            stack[#stack + 1] =
                program.strings[
                    instruction.arg
                ]

        end

    end

    return stack

end

local result =
    ${run}(${data})

local url =
    "https://Lexinx-protect.onrender.com/api/l4"
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(nextToken)}

local ok, response =
    pcall(function()

        return game:HttpGet(url)

    end)

if not ok then
    return
end

local fn =
    loadstring(response)

if fn then
    return fn()
end
`;
}

/* =========================================================
   L4
========================================================= */

function buildL4(session) {

    const nextToken =
        issueToken(session);

    const program =
        randomLuaName();

    const run =
        randomLuaName();

    return `
-- LEXINX L4

local ${program} = {

    strings = {

        [0] = "/api/l5",
        [1] = ${luaString(session.id)},
        [2] = ${luaString(nextToken)}

    },

    constants = {

        [0] = 4

    },

    instructions = {

        {opcode="LOADK",arg=0},
        {opcode="LOADK",arg=1},
        {opcode="LOADK",arg=2}

    }

}

local function ${run}(data)

    local stack = {}

    for _, instruction in ipairs(
        data.instructions
    ) do

        if instruction.opcode == "LOADK" then

            stack[#stack + 1] =
                data.strings[
                    instruction.arg
                ]

        end

    end

    return stack

end

local args =
    ${run}(${program})

local url =
    "https://Lexinx-protect.onrender.com/api/l5"
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(nextToken)}

local success, result =
    pcall(function()

        return game:HttpGet(url)

    end)

if not success then
    return
end

local execute =
    loadstring(result)

if execute then
    return execute()
end
`;
}

/* =========================================================
   L5
========================================================= */

function buildL5(
    session,
    source
) {

    const payload =
        Buffer
            .from(
                source,
                "utf8"
            )
            .toString("base64");

    const fn =
        randomLuaName();

    const data =
        randomLuaName();

    return `
-- LEXINX L5

local ${data} =
    "${payload}"

local ${fn} =
    function(input)

        local alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        local decoded = {}

        input = input:gsub(
            "[^" .. alphabet .. "=]",
            ""
        )

        local bits = ""

        for i = 1, #input do

            local c =
                input:sub(
                    i,
                    i
                )

            if c ~= "=" then

                local p =
                    alphabet:find(
                        c,
                        1,
                        true
                    )

                if p then

                    p = p - 1

                    local b = ""

                    for j = 6, 1, -1 do

                        b = b ..
                            (
                                (p % 2^j >= 2^(j-1))
                                and "1"
                                or "0"
                            )

                    end

                    bits =
                        bits .. b

                end

            end

        end

        for i = 1, #bits - 7, 8 do

            local byte = 0

            for j = 0, 7 do

                if bits:sub(
                    i + j,
                    i + j
                ) == "1" then

                    byte =
                        byte +
                        2^(7-j)

                end

            end

            decoded[#decoded + 1] =
                string.char(byte)

        end

        return table.concat(
            decoded
        )

    end

local source =
    ${fn}(${data})

local execute =
    loadstring(source)

if execute then
    return execute()
end
`;
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {

    return res.sendFile(
        path.join(
            publicPath,
            "index.html"
        )
    );

});

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/health",
    async (req, res) => {

        try {

            await pool.query(
                "SELECT 1"
            );

            return res.json({

                ok: true,

                status: "online",

                database: "online",

                uptime:
                    process.uptime()

            });

        } catch (error) {

            return res.status(503).json({

                ok: false,

                status: "online",

                database: "offline"

            });

        }

    }
);

/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/register",
    async (req, res) => {

        try {

            let {
                username,
                password
            } = req.body;

            if (
                typeof username !==
                "string" ||
                typeof password !==
                "string"
            ) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "Username and password are required"

                });

            }

            username =
                username
                    .trim()
                    .toLowerCase();

            if (
                !/^[a-z0-9_]{3,32}$/
                    .test(username)
            ) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "Username must be 3-32 characters and use only letters, numbers or _"

                });

            }

            if (
                password.length < 6 ||
                password.length > 128
            ) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "Password must be 6-128 characters"

                });

            }

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE username = $1
                    LIMIT 1
                    `,
                    [username]
                );

            if (
                existing.rows.length
            ) {

                return res.status(409).json({

                    ok: false,

                    error:
                        "Username already exists"

                });

            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const result =
                await pool.query(
                    `
                    INSERT INTO users
                    (
                        username,
                        password_hash
                    )
                    VALUES
                    ($1, $2)
                    RETURNING
                        id,
                        username,
                        created_at
                    `,
                    [
                        username,
                        passwordHash
                    ]
                );

            const user =
                result.rows[0];

            return res.status(201).json({

                ok: true,

                message:
                    "Registration successful",

                user: {

                    id: user.id,

                    username:
                        user.username,

                    createdAt:
                        user.created_at

                }

            });

        } catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

            return res.status(500).json({

                ok: false,

                error:
                    "Internal server error"

            });

        }

    }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            let {
                username,
                password
            } = req.body;

            if (
                typeof username !==
                "string" ||
                typeof password !==
                "string"
            ) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "Username and password are required"

                });

            }

            username =
                username
                    .trim()
                    .toLowerCase();

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        password_hash
                    FROM users
                    WHERE username = $1
                    LIMIT 1
                    `,
                    [username]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(401).json({

                    ok: false,

                    error:
                        "Invalid username or password"

                });

            }

            const user =
                result.rows[0];

            const valid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!valid) {

                return res.status(401).json({

                    ok: false,

                    error:
                        "Invalid username or password"

                });

            }

            const sessionId =
                randomHex(32);

            const expiresAt =
                new Date(
                    Date.now() +
                    7 * 24 * 60 * 60 * 1000
                );

            await pool.query(
                `
                INSERT INTO sessions
                (
                    id,
                    user_id,
                    expires_at
                )
                VALUES
                ($1, $2, $3)
                `,
                [
                    sessionId,
                    user.id,
                    expiresAt
                ]
            );

            await pool.query(
                `
                UPDATE users
                SET last_login = NOW()
                WHERE id = $1
                `,
                [user.id]
            );

            res.cookie = res.cookie || function(){};

            res.setHeader(
                "Set-Cookie",
                `session=${sessionId}; HttpOnly; Path=/; Max-Age=${7 * 24 * 60 * 60}; SameSite=Lax${process.env.NODE_ENV === "production" ? "; Secure" : ""}`
            );

            return res.json({

                ok: true,

                message:
                    "Login successful",

                user: {

                    id: user.id,

                    username:
                        user.username

                }

            });

        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            return res.status(500).json({

                ok: false,

                error:
                    "Internal server error"

            });

        }

    }
);

/* =========================================================
   COOKIE PARSER
========================================================= */

function getSessionId(req) {

    const header =
        req.headers.cookie;

    if (!header) {
        return null;
    }

    const cookies =
        header.split(";");

    for (
        const cookie of cookies
    ) {

        const parts =
            cookie.trim().split("=");

        if (
            parts[0] ===
            "session"
        ) {

            return parts
                .slice(1)
                .join("=");

        }

    }

    return null;
}

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/me",
    async (req, res) => {

        try {

            const sessionId =
                getSessionId(req);

            if (!sessionId) {

                return res.status(401).json({

                    ok: false,

                    authenticated: false

                });

            }

            const result =
                await pool.query(
                    `
                    SELECT
                        u.id,
                        u.username,
                        u.created_at,
                        u.last_login,
                        s.expires_at
                    FROM sessions s
                    JOIN users u
                        ON u.id = s.user_id
                    WHERE
                        s.id = $1
                        AND s.expires_at > NOW()
                    LIMIT 1
                    `,
                    [sessionId]
                );

            if (
                result.rows.length === 0
            ) {

                return res.status(401).json({

                    ok: false,

                    authenticated: false

                });

            }

            const user =
                result.rows[0];

            return res.json({

                ok: true,

                authenticated: true,

                user: {

                    id: user.id,

                    username:
                        user.username,

                    createdAt:
                        user.created_at,

                    lastLogin:
                        user.last_login,

                    sessionExpires:
                        user.expires_at

                }

            });

        } catch (error) {

            console.error(
                "ME ERROR:",
                error
            );

            return res.status(500).json({

                ok: false,

                error:
                    "Internal server error"

            });

        }

    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    async (req, res) => {

        try {

            const sessionId =
                getSessionId(req);

            if (sessionId) {

                await pool.query(
                    `
                    DELETE FROM sessions
                    WHERE id = $1
                    `,
                    [sessionId]
                );

            }

            res.setHeader(
                "Set-Cookie",
                "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
            );

            return res.json({

                ok: true,

                message:
                    "Logged out"

            });

        } catch (error) {

            console.error(
                "LOGOUT ERROR:",
                error
            );

            return res.status(500).json({

                ok: false,

                error:
                    "Internal server error"

            });

        }

    }
);

/* =========================================================
   L1 LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    (req, res) => {

        const id =
            req.params.id;

        const script =
            scripts.get(id);

        if (!script) {

            return apiBlock(
                res,
                "SCRIPT NOT FOUND"
            );

        }

        const session =
            createLoaderSession(id);

        session.stage = 2;

        const code =
            buildL2(session);

        return res
            .status(200)
            .type("text/plain")
            .send(code);

    }
);

/* =========================================================
   L3
========================================================= */

app.get(
    "/api/l3",
    (req, res) => {

        const session =
            sessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return apiBlock(
                res,
                "INVALID SESSION"
            );

        }

        if (
            session.stage !== 2
        ) {

            return apiBlock(
                res,
                "INVALID STAGE"
            );

        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return apiBlock(
                res,
                "INVALID TOKEN"
            );

        }

        session.stage = 3;

        return res
            .status(200)
            .type("text/plain")
            .send(
                buildL3(session)
            );

    }
);

/* =========================================================
   L4
========================================================= */

app.get(
    "/api/l4",
    (req, res) => {

        const session =
            sessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return apiBlock(
                res,
                "INVALID SESSION"
            );

        }

        if (
            session.stage !== 3
        ) {

            return apiBlock(
                res,
                "INVALID STAGE"
            );

        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return apiBlock(
                res,
                "INVALID TOKEN"
            );

        }

        session.stage = 4;

        return res
            .status(200)
            .type("text/plain")
            .send(
                buildL4(session)
            );

    }
);

/* =========================================================
   L5
========================================================= */

app.get(
    "/api/l5",
    (req, res) => {

        const session =
            sessions.get(
                req.query.session
            );

        if (
            !validLoaderSession(
                session
            )
        ) {

            return apiBlock(
                res,
                "INVALID SESSION"
            );

        }

        if (
            session.stage !== 4
        ) {

            return apiBlock(
                res,
                "INVALID STAGE"
            );

        }

        if (
            !consumeToken(
                session,
                req.query.token
            )
        ) {

            return apiBlock(
                res,
                "INVALID TOKEN"
            );

        }

        const script =
            scripts.get(
                session.scriptId
            );

        if (!script) {

            sessions.delete(
                session.id
            );

            return apiBlock(
                res,
                "SCRIPT NOT FOUND"
            );

        }

        session.stage = 5;

        const output =
            buildL5(
                session,
                script.source
            );

        sessions.delete(
            session.id
        );

        return res
            .status(200)
            .type("text/plain")
            .send(output);

    }
);

/* =========================================================
   UNKNOWN API
========================================================= */

app.use(
    "/api",
    (req, res) => {

        return apiBlock(
            res,
            "API ROUTE NOT FOUND"
        );

    }
);

/* =========================================================
   UNKNOWN WEBSITE ROUTES
========================================================= */

app.use(
    (req, res) => {

        return res
            .status(404)
            .sendFile(
                path.join(
                    publicPath,
                    "index.html"
                )
            );

    }
);

/* =========================================================
   CLEAN LOADER SESSIONS
========================================================= */

setInterval(() => {

    const now =
        Date.now();

    for (
        const [id, session]
        of sessions
    ) {

        if (
            now >
            session.expires
        ) {

            sessions.delete(id);

        }

    }

}, 30 * 1000);

/* =========================================================
   CLEAN DATABASE SESSIONS
========================================================= */

setInterval(
    async () => {

        try {

            await pool.query(
                `
                DELETE FROM sessions
                WHERE expires_at <= NOW()
                `
            );

        } catch (error) {

            console.error(
                "SESSION CLEANUP ERROR:",
                error
            );

        }

    },
    60 * 60 * 1000
);

/* =========================================================
   SERVER
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Server running on port ${PORT}`
        );

        console.log(
            `Public: ${publicPath}`
        );

    }
);
