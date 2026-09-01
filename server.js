const express = require("express");
const crypto = require("crypto");
const path = require("path");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================================================
   CONFIG
========================================================= */

const SESSION_TTL =
    7 * 24 * 60 * 60 * 1000;

const LOADER_TTL =
    60 * 1000;

const BASE_URL =
    process.env.PUBLIC_URL ||
    "";

/* =========================================================
   EXPRESS
========================================================= */

app.use(
    express.json({
        limit: "2mb"
    })
);

/* =========================================================
   PUBLIC
========================================================= */

const publicPath =
    path.join(
        __dirname,
        "public"
    );

app.use(
    express.static(publicPath)
);

/* =========================================================
   POSTGRESQL
========================================================= */

if (!process.env.DATABASE_URL) {

    console.error(
        "ERROR: DATABASE_URL is not configured."
    );

}

const pool = new Pool({

    connectionString:
        process.env.DATABASE_URL,

    ssl:
        process.env.NODE_ENV === "production"
            ? {
                rejectUnauthorized: false
            }
            : false

});

/* =========================================================
   DATABASE
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
        CREATE TABLE IF NOT EXISTS auth_sessions (

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

    await pool.query(`
        CREATE TABLE IF NOT EXISTS scripts (

            id VARCHAR(64) PRIMARY KEY,

            user_id BIGINT
                NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            name VARCHAR(100)
                NOT NULL,

            source TEXT
                NOT NULL,

            created_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW(),

            updated_at TIMESTAMPTZ
                NOT NULL DEFAULT NOW()

        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        scripts_user_id_idx
        ON scripts(user_id);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        auth_sessions_user_id_idx
        ON auth_sessions(user_id);
    `);

    console.log(
        "PostgreSQL initialized."
    );
}

initDatabase().catch(error => {

    console.error(
        "DATABASE INIT ERROR:",
        error
    );

});

/* =========================================================
   RANDOM
========================================================= */

function randomHex(
    bytes = 32
) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");

}

/* =========================================================
   COOKIE
========================================================= */

function getCookie(
    req,
    name
) {

    const header =
        req.headers.cookie;

    if (!header) {
        return null;
    }

    const cookies =
        header.split(";");

    for (
        const item of cookies
    ) {

        const index =
            item.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            item
                .slice(0, index)
                .trim();

        const value =
            item
                .slice(index + 1)
                .trim();

        if (key === name) {
            return decodeURIComponent(
                value
            );
        }

    }

    return null;
}

/* =========================================================
   SET SESSION COOKIE
========================================================= */

function setSessionCookie(
    res,
    sessionId
) {

    const maxAge =
        Math.floor(
            SESSION_TTL / 1000
        );

    let cookie =
        `session=${encodeURIComponent(sessionId)}; ` +
        `Path=/; ` +
        `HttpOnly; ` +
        `SameSite=Lax; ` +
        `Max-Age=${maxAge}`;

    if (
        process.env.NODE_ENV ===
        "production"
    ) {

        cookie +=
            "; Secure";

    }

    res.setHeader(
        "Set-Cookie",
        cookie
    );
}

/* =========================================================
   CLEAR SESSION COOKIE
========================================================= */

function clearSessionCookie(
    res
) {

    res.setHeader(
        "Set-Cookie",
        "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    );

}

/* =========================================================
   AUTH USER
========================================================= */

async function getAuthUser(
    req
) {

    const sessionId =
        getCookie(
            req,
            "session"
        );

    if (!sessionId) {
        return null;
    }

    const result =
        await pool.query(
            `
            SELECT
                u.id,
                u.username,
                u.created_at,
                u.last_login,
                s.id AS session_id,
                s.expires_at
            FROM auth_sessions s
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

        return null;

    }

    return result.rows[0];
}

/* =========================================================
   REQUIRE AUTH
========================================================= */

async function requireAuth(
    req,
    res,
    next
) {

    try {

        const user =
            await getAuthUser(req);

        if (!user) {

            return res
                .status(401)
                .json({
                    ok: false,
                    error:
                        "Not authenticated"
                });

        }

        req.user =
            user;

        next();

    } catch (error) {

        console.error(
            "AUTH ERROR:",
            error
        );

        return res
            .status(500)
            .json({
                ok: false,
                error:
                    "Internal server error"
            });

    }

}

/* =========================================================
   API ERROR
========================================================= */

function apiError(
    res,
    status,
    message
) {

    return res
        .status(status)
        .json({

            ok: false,

            error: message

        });

}

/* =========================================================
   HOME
========================================================= */

app.get(
    "/",
    (req, res) => {

        return res.sendFile(
            path.join(
                publicPath,
                "index.html"
            )
        );

    }
);

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

                status:
                    "API ONLINE",

                database:
                    "ONLINE",

                uptime:
                    process.uptime()

            });

        } catch (error) {

            return res
                .status(503)
                .json({

                    ok: false,

                    status:
                        "API ONLINE",

                    database:
                        "OFFLINE"

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

            let username =
                req.body.username;

            const password =
                req.body.password;

            if (
                typeof username !==
                "string" ||
                typeof password !==
                "string"
            ) {

                return apiError(
                    res,
                    400,
                    "Username and password are required."
                );

            }

            username =
                username
                    .trim()
                    .toLowerCase();

            if (
                !/^[a-z0-9_]{3,32}$/
                    .test(username)
            ) {

                return apiError(
                    res,
                    400,
                    "Username must be 3-32 characters and use only letters, numbers or underscore."
                );

            }

            if (
                password.length < 6
            ) {

                return apiError(
                    res,
                    400,
                    "Password must contain at least 6 characters."
                );

            }

            if (
                password.length > 128
            ) {

                return apiError(
                    res,
                    400,
                    "Password is too long."
                );

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

                return apiError(
                    res,
                    409,
                    "Username already exists."
                );

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

            /* Automatically login after registration */

            const sessionId =
                randomHex(32);

            const expires =
                new Date(
                    Date.now() +
                    SESSION_TTL
                );

            await pool.query(
                `
                INSERT INTO auth_sessions
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
                    expires
                ]
            );

            setSessionCookie(
                res,
                sessionId
            );

            return res
                .status(201)
                .json({

                    ok: true,

                    message:
                        "Account created successfully.",

                    username:
                        user.username,

                    url:
                        BASE_URL ||
                        `${req.protocol}://${req.get("host")}`,

                    user: {

                        id:
                            user.id,

                        username:
                            user.username

                    }

                });

        } catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

            if (
                error.code ===
                "23505"
            ) {

                return apiError(
                    res,
                    409,
                    "Username already exists."
                );

            }

            return apiError(
                res,
                500,
                "Internal server error."
            );

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

            let username =
                req.body.username;

            const password =
                req.body.password;

            if (
                typeof username !==
                "string" ||
                typeof password !==
                "string"
            ) {

                return apiError(
                    res,
                    400,
                    "Username and password are required."
                );

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

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );

            }

            const user =
                result.rows[0];

            const valid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!valid) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );

            }

            const sessionId =
                randomHex(32);

            const expires =
                new Date(
                    Date.now() +
                    SESSION_TTL
                );

            await pool.query(
                `
                INSERT INTO auth_sessions
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
                    expires
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

            setSessionCookie(
                res,
                sessionId
            );

            return res.json({

                ok: true,

                message:
                    "Login successful.",

                username:
                    user.username,

                url:
                    BASE_URL ||
                    `${req.protocol}://${req.get("host")}`,

                user: {

                    id:
                        user.id,

                    username:
                        user.username

                }

            });

        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Internal server error."
            );

        }

    }
);

/* =========================================================
   ME
========================================================= */

app.get(
    "/api/me",
    async (req, res) => {

        try {

            const user =
                await getAuthUser(req);

            if (!user) {

                return apiError(
                    res,
                    401,
                    "Not authenticated."
                );

            }

            return res.json({

                ok: true,

                username:
                    user.username,

                url:
                    BASE_URL ||
                    `${req.protocol}://${req.get("host")}`,

                user: {

                    id:
                        user.id,

                    username:
                        user.username,

                    createdAt:
                        user.created_at,

                    lastLogin:
                        user.last_login

                }

            });

        } catch (error) {

            console.error(
                "ME ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Internal server error."
            );

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
                getCookie(
                    req,
                    "session"
                );

            if (sessionId) {

                await pool.query(
                    `
                    DELETE FROM auth_sessions
                    WHERE id = $1
                    `,
                    [sessionId]
                );

            }

            clearSessionCookie(
                res
            );

            return res.json({

                ok: true,

                message:
                    "Logged out successfully."

            });

        } catch (error) {

            console.error(
                "LOGOUT ERROR:",
                error
            );

            clearSessionCookie(
                res
            );

            return res.json({

                ok: true

            });

        }

    }
);

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/create",
    requireAuth,
    async (req, res) => {

        try {

            let name =
                req.body.name;

            const source =
                req.body.source;

            if (
                typeof source !==
                "string"
            ) {

                return apiError(
                    res,
                    400,
                    "Script source is required."
                );

            }

            if (
                !source.trim()
            ) {

                return apiError(
                    res,
                    400,
                    "Script source cannot be empty."
                );

            }

            if (
                source.length >
                2 * 1024 * 1024
            ) {

                return apiError(
                    res,
                    413,
                    "Script is too large."
                );

            }

            if (
                typeof name !==
                "string"
            ) {

                name =
                    "Untitled Script";

            }

            name =
                name.trim();

            if (!name) {

                name =
                    "Untitled Script";

            }

            if (
                name.length >
                100
            ) {

                name =
                    name.slice(
                        0,
                        100
                    );

            }

            const id =
                randomHex(12);

            await pool.query(
                `
                INSERT INTO scripts
                (
                    id,
                    user_id,
                    name,
                    source
                )
                VALUES
                ($1, $2, $3, $4)
                `,
                [
                    id,
                    req.user.id,
                    name,
                    source
                ]
            );

            const loader =
                `${BASE_URL || `${req.protocol}://${req.get("host")}`}/api/loader/${id}`;

            return res
                .status(201)
                .json({

                    ok: true,

                    id,

                    name,

                    loader

                });

        } catch (error) {

            console.error(
                "CREATE SCRIPT ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to create script."
            );

        }

    }
);

/* =========================================================
   LIST SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    `,
                    [req.user.id]
                );

            const base =
                BASE_URL ||
                `${req.protocol}://${req.get("host")}`;

            const scripts =
                result.rows.map(
                    script => ({

                        id:
                            script.id,

                        name:
                            script.name,

                        createdAt:
                            script.created_at,

                        updatedAt:
                            script.updated_at,

                        loader:
                            `${base}/api/loader/${script.id}`

                    })
                );

            return res.json({

                ok: true,

                scripts

            });

        } catch (error) {

            console.error(
                "LIST SCRIPTS ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to load scripts."
            );

        }

    }
);

/* =========================================================
   GET ONE SCRIPT
========================================================= */

app.get(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        source,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE
                        id = $1
                        AND user_id = $2
                    LIMIT 1
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );

            }

            const script =
                result.rows[0];

            return res.json({

                ok: true,

                script: {

                    id:
                        script.id,

                    name:
                        script.name,

                    source:
                        script.source,

                    createdAt:
                        script.created_at,

                    updatedAt:
                        script.updated_at

                }

            });

        } catch (error) {

            console.error(
                "GET SCRIPT ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to load script."
            );

        }

    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.put(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            let name =
                req.body.name;

            const source =
                req.body.source;

            if (
                typeof name !==
                "string" ||
                typeof source !==
                "string"
            ) {

                return apiError(
                    res,
                    400,
                    "Name and source are required."
                );

            }

            name =
                name.trim();

            if (!name) {

                name =
                    "Untitled Script";

            }

            if (
                name.length >
                100
            ) {

                name =
                    name.slice(
                        0,
                        100
                    );

            }

            if (
                !source.trim()
            ) {

                return apiError(
                    res,
                    400,
                    "Script source cannot be empty."
                );

            }

            if (
                source.length >
                2 * 1024 * 1024
            ) {

                return apiError(
                    res,
                    413,
                    "Script is too large."
                );

            }

            const result =
                await pool.query(
                    `
                    UPDATE scripts
                    SET
                        name = $1,
                        source = $2,
                        updated_at = NOW()
                    WHERE
                        id = $3
                        AND user_id = $4
                    RETURNING
                        id,
                        name,
                        updated_at
                    `,
                    [
                        name,
                        source,
                        req.params.id,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );

            }

            const script =
                result.rows[0];

            return res.json({

                ok: true,

                message:
                    "Script updated successfully.",

                script: {

                    id:
                        script.id,

                    name:
                        script.name,

                    updatedAt:
                        script.updated_at

                }

            });

        } catch (error) {

            console.error(
                "EDIT SCRIPT ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to update script."
            );

        }

    }
);

/* =========================================================
   DELETE SCRIPT
========================================================= */

app.delete(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM scripts
                    WHERE
                        id = $1
                        AND user_id = $2
                    RETURNING id
                    `,
                    [
                        req.params.id,
                        req.user.id
                    ]
                );

            if (
                result.rows.length === 0
            ) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );

            }

            return res.json({

                ok: true,

                message:
                    "Script deleted successfully."

            });

        } catch (error) {

            console.error(
                "DELETE SCRIPT ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Failed to delete script."
            );

        }

    }
);

/* =========================================================
   LOADER SESSIONS
========================================================= */

const loaderSessions =
    new Map();

/* =========================================================
   CREATE LOADER SESSION
========================================================= */

function createLoaderSession(
    scriptId
) {

    const id =
        randomHex(32);

    const session = {

        id,

        scriptId,

        stage: 1,

        tokens:
            new Set(),

        expires:
            Date.now() +
            LOADER_TTL

    };

    loaderSessions.set(
        id,
        session
    );

    return session;
}

/* =========================================================
   TOKEN
========================================================= */

function issueToken(
    session
) {

    const token =
        randomHex(32);

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

        loaderSessions.delete(
            session.id
        );

        return false;

    }

    return true;
}

/* =========================================================
   LUA HELPERS
========================================================= */

function luaString(
    value
) {

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

function buildL2(
    session,
    base
) {

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

    const l3 =
        `${base}/api/l3`;

    return `
-- LEXINX L2

local ${data} = {

    strings = {

        [0] = ${luaString("/api/l3")},
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
    ${luaString(l3)}

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

function buildL3(
    session,
    base
) {

    const nextToken =
        issueToken(session);

    const data =
        randomLuaName();

    const run =
        randomLuaName();

    const endpoint =
        `${base}/api/l4`;

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
    ${luaString(endpoint)}
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(nextToken)}

local ok, response =
    pcall(function()

        return game:HttpGet(
            url
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
   L4
========================================================= */

function buildL4(
    session,
    base
) {

    const nextToken =
        issueToken(session);

    const program =
        randomLuaName();

    const run =
        randomLuaName();

    const endpoint =
        `${base}/api/l5`;

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
    ${luaString(endpoint)}
    .. "?session="
    .. ${luaString(session.id)}
    .. "&token="
    .. ${luaString(nextToken)}

local success, result =
    pcall(function()

        return game:HttpGet(
            url
        )

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
   LOADER L1
========================================================= */

app.get(
    "/api/loader/:id",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id
                    FROM scripts
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [req.params.id]
                );

            if (
                result.rows.length === 0
            ) {

                return apiError(
                    res,
                    404,
                    "Script not found."
                );

            }

            const session =
                createLoaderSession(
                    req.params.id
                );

            session.stage = 2;

            const base =
                BASE_URL ||
                `${req.protocol}://${req.get("host")}`;

            const output =
                buildL2(
                    session,
                    base
                );

            return res
                .status(200)
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "LOADER ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Loader error."
            );

        }

    }
);

/* =========================================================
   L3
========================================================= */

app.get(
    "/api/l3",
    async (req, res) => {

        try {

            const session =
                loaderSessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(
                    session
                )
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid session."
                );

            }

            if (
                session.stage !== 2
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid stage."
                );

            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid token."
                );

            }

            session.stage = 3;

            const base =
                BASE_URL ||
                `${req.protocol}://${req.get("host")}`;

            return res
                .type("text/plain")
                .send(
                    buildL3(
                        session,
                        base
                    )
                );

        } catch (error) {

            console.error(
                "L3 ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "L3 error."
            );

        }

    }
);

/* =========================================================
   L4
========================================================= */

app.get(
    "/api/l4",
    async (req, res) => {

        try {

            const session =
                loaderSessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(
                    session
                )
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid session."
                );

            }

            if (
                session.stage !== 3
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid stage."
                );

            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid token."
                );

            }

            session.stage = 4;

            const base =
                BASE_URL ||
                `${req.protocol}://${req.get("host")}`;

            return res
                .type("text/plain")
                .send(
                    buildL4(
                        session,
                        base
                    )
                );

        } catch (error) {

            console.error(
                "L4 ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "L4 error."
            );

        }

    }
);

/* =========================================================
   L5
========================================================= */

app.get(
    "/api/l5",
    async (req, res) => {

        try {

            const session =
                loaderSessions.get(
                    req.query.session
                );

            if (
                !validLoaderSession(
                    session
                )
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid session."
                );

            }

            if (
                session.stage !== 4
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid stage."
                );

            }

            if (
                !consumeToken(
                    session,
                    req.query.token
                )
            ) {

                return apiError(
                    res,
                    403,
                    "Invalid token."
                );

            }

            const result =
                await pool.query(
                    `
                    SELECT
                        source
                    FROM scripts
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [session.scriptId]
                );

            if (
                result.rows.length === 0
            ) {

                loaderSessions.delete(
                    session.id
                );

                return apiError(
                    res,
                    404,
                    "Script not found."
                );

            }

            const source =
                result.rows[0].source;

            session.stage = 5;

            const output =
                buildL5(
                    source
                );

            loaderSessions.delete(
                session.id
            );

            return res
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "L5 ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "L5 error."
            );

        }

    }
);

/* =========================================================
   UNKNOWN API
========================================================= */

app.use(
    "/api",
    (req, res) => {

        return apiError(
            res,
            404,
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

setInterval(
    () => {

        const now =
            Date.now();

        for (
            const [
                id,
                session
            ]
            of loaderSessions
        ) {

            if (
                now >
                session.expires
            ) {

                loaderSessions.delete(
                    id
                );

            }

        }

    },
    30 * 1000
);

/* =========================================================
   CLEAN AUTH SESSIONS
========================================================= */

setInterval(
    async () => {

        try {

            await pool.query(
                `
                DELETE FROM auth_sessions
                WHERE expires_at <= NOW()
                `
            );

        } catch (error) {

            console.error(
                "AUTH SESSION CLEANUP:",
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
            `LEXINX Protect running on port ${PORT}`
        );

        console.log(
            `Public directory: ${publicPath}`
        );

    }
);
