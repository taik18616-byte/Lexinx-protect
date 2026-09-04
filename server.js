const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;

const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://lexinx-protect-v230.vercel.app";

const WEB_SESSION_TTL =
    7 * 24 * 60 * 60 * 1000;

const LOADER_SESSION_TTL =
    60 * 1000;

app.set("trust proxy", 1);

app.use(
    express.json({
        limit: "1mb"
    })
);

app.use(
    express.urlencoded({
        extended: false
    })
);

/* =========================================================
   POSTGRESQL
========================================================= */

if (!process.env.DATABASE_URL) {

    console.warn(
        "WARNING: DATABASE_URL is not configured."
    );
}

const pool = new Pool({

    connectionString:
        process.env.DATABASE_URL,

    ssl:
        process.env.DATABASE_URL
            ? {
                rejectUnauthorized: false
            }
            : false,

    max: 10,

    idleTimeoutMillis:
        30000,

    connectionTimeoutMillis:
        10000

});

pool.on(
    "error",
    (error) => {

        console.error(
            "POSTGRES POOL ERROR:",
            error
        );

    }
);

/* =========================================================
   STATIC
========================================================= */

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);

/* =========================================================
   HELPERS
========================================================= */

function randomHex(bytes = 32) {

    return crypto
        .randomBytes(bytes)
        .toString("hex");

}

function hashPassword(password) {

    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");

}

function luaString(value) {

    return JSON.stringify(
        String(value)
    );

}

function hexEncode(value) {

    return Buffer
        .from(
            String(value),
            "utf8"
        )
        .toString("hex");

}

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

function dbError(error) {

    console.error(
        "DATABASE ERROR:",
        error
    );

}

/* =========================================================
   COOKIE
========================================================= */

function getCookie(
    req,
    name
) {

    const raw =
        req.headers.cookie || "";

    const parts =
        raw.split(";");

    for (
        const part of parts
    ) {

        const item =
            part.trim();

        const index =
            item.indexOf("=");

        if (
            index === -1
        )
            continue;

        const key =
            item.slice(
                0,
                index
            );

        const value =
            item.slice(
                index + 1
            );

        if (
            key === name
        ) {

            try {

                return decodeURIComponent(
                    value
                );

            } catch {

                return value;

            }

        }

    }

    return null;

}

/* =========================================================
   WEB SESSION
========================================================= */

async function createWebSession(
    username
) {

    const sessionToken =
        randomHex(32);

    const expires =
        new Date(
            Date.now() +
            WEB_SESSION_TTL
        );

    const result =
        await pool.query(
            `
            INSERT INTO login_sessions
            (
                user_id,
                session_token,
                created_at,
                expires_at,
                last_seen_at
            )
            SELECT
                id,
                $1,
                NOW(),
                $2,
                NOW()
            FROM users
            WHERE LOWER(username) = LOWER($3)
            RETURNING
                session_token,
                expires_at
            `,
            [
                sessionToken,
                expires,
                username
            ]
        );

    if (
        result.rowCount === 0
    ) {

        throw new Error(
            "Unable to create web session."
        );

    }

    return sessionToken;

}

async function getWebAuth(
    req
) {

    const sid =
        getCookie(
            req,
            "lexinx_session"
        );

    if (!sid)
        return null;

    try {

        const result =
            await pool.query(
                `
                SELECT
                    ls.session_token,
                    ls.expires_at,
                    u.id,
                    u.username,
                    u.password_hash,
                    u.created_at,
                    u.updated_at
                FROM login_sessions ls
                INNER JOIN users u
                    ON u.id = ls.user_id
                WHERE
                    ls.session_token = $1
                    AND (
                        ls.expires_at IS NULL
                        OR ls.expires_at > NOW()
                    )
                LIMIT 1
                `,
                [sid]
            );

        if (
            result.rowCount === 0
        ) {

            return null;

        }

        const row =
            result.rows[0];

        await pool.query(
            `
            UPDATE login_sessions
            SET last_seen_at = NOW()
            WHERE session_token = $1
            `,
            [sid]
        );

        return {

            sid,

            username:
                row.username,

            user: {

                id:
                    row.id,

                username:
                    row.username,

                password:
                    row.password_hash,

                created:
                    row.created_at,

                updated:
                    row.updated_at

            }

        };

    } catch (error) {

        dbError(error);

        return null;

    }

}

async function requireAuth(
    req,
    res,
    next
) {

    try {

        const auth =
            await getWebAuth(req);

        if (!auth) {

            return apiError(
                res,
                401,
                "Authentication required."
            );

        }

        req.auth =
            auth;

        next();

    } catch (error) {

        dbError(error);

        return apiError(
            res,
            500,
            "Authentication server error."
        );

    }

}

/* =========================================================
   REGISTER
========================================================= */

app.post(
    "/api/register",
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();

            const password =
                String(
                    req.body.password || ""
                );

            if (!username) {

                return apiError(
                    res,
                    400,
                    "Username is required."
                );

            }

            if (
                username.length < 3
            ) {

                return apiError(
                    res,
                    400,
                    "Username must contain at least 3 characters."
                );

            }

            if (
                username.length > 32
            ) {

                return apiError(
                    res,
                    400,
                    "Username is too long."
                );

            }

            if (
                !/^[a-zA-Z0-9_]+$/.test(
                    username
                )
            ) {

                return apiError(
                    res,
                    400,
                    "Username may only contain letters, numbers and underscore."
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

            const passwordHash =
                hashPassword(
                    password
                );

            let user;

            try {

                const result =
                    await pool.query(
                        `
                        INSERT INTO users
                        (
                            username,
                            password_hash
                        )
                        VALUES
                        (
                            $1,
                            $2
                        )
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

                user =
                    result.rows[0];

            } catch (error) {

                if (
                    error.code === "23505"
                ) {

                    return apiError(
                        res,
                        409,
                        "Username already exists."
                    );

                }

                throw error;

            }

            const sid =
                await createWebSession(
                    user.username
                );

            res.cookie(
                "lexinx_session",
                sid,
                {
                    httpOnly: true,
                    sameSite: "lax",
                    secure: true,
                    maxAge:
                        WEB_SESSION_TTL,
                    path: "/"
                }
            );

            return res.json({

                ok: true,

                username:
                    user.username,

                url:
                    PUBLIC_URL + "/"

            });

        } catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Registration server error."
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

            const username =
                String(
                    req.body.username || ""
                ).trim();

            const password =
                String(
                    req.body.password || ""
                );

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        password_hash,
                        created_at,
                        updated_at
                    FROM users
                    WHERE LOWER(username) = LOWER($1)
                    LIMIT 1
                    `,
                    [username]
                );

            if (
                result.rowCount === 0
            ) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );

            }

            const row =
                result.rows[0];

            if (
                row.password_hash !==
                hashPassword(password)
            ) {

                return apiError(
                    res,
                    401,
                    "Invalid username or password."
                );

            }

            const sid =
                await createWebSession(
                    row.username
                );

            res.cookie(
                "lexinx_session",
                sid,
                {
                    httpOnly: true,
                    sameSite: "lax",
                    secure: true,
                    maxAge:
                        WEB_SESSION_TTL,
                    path: "/"
                }
            );

            return res.json({

                ok: true,

                username:
                    row.username,

                url:
                    PUBLIC_URL + "/"

            });

        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Login server error."
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

        const auth =
            await getWebAuth(req);

        if (!auth) {

            return apiError(
                res,
                401,
                "Not authenticated."
            );

        }

        return res.json({

            ok: true,

            username:
                auth.username,

            url:
                PUBLIC_URL + "/"

        });

    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    async (req, res) => {

        const sid =
            getCookie(
                req,
                "lexinx_session"
            );

        try {

            if (sid) {

                await pool.query(
                    `
                    DELETE FROM login_sessions
                    WHERE session_token = $1
                    `,
                    [sid]
                );

            }

        } catch (error) {

            dbError(error);

        }

        res.clearCookie(
            "lexinx_session",
            {
                path: "/"
            }
        );

        return res.json({
            ok: true
        });

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

            const name =
                String(
                    req.body.name ||
                    "Untitled Script"
                )
                .trim()
                .slice(
                    0,
                    100
                );

            const source =
                String(
                    req.body.source ||
                    ""
                );

            if (
                !source.trim()
            ) {

                return apiError(
                    res,
                    400,
                    "Script source cannot be empty."
                );

            }

            let id;

            do {

                id =
                    randomHex(12);

                const exists =
                    await pool.query(
                        `
                        SELECT 1
                        FROM scripts
                        WHERE script_id = $1
                        LIMIT 1
                        `,
                        [id]
                    );

                if (
                    exists.rowCount === 0
                ) {

                    break;

                }

            } while (true);

            const result =
                await pool.query(
                    `
                    INSERT INTO scripts
                    (
                        user_id,
                        script_id,
                        name,
                        source,
                        enabled
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        TRUE
                    )
                    RETURNING
                        script_id,
                        name,
                        created_at,
                        updated_at
                    `,
                    [
                        req.auth.user.id,
                        id,
                        name ||
                            "Untitled Script",
                        source
                    ]
                );

            const script =
                result.rows[0];

            const loader =
                `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${script.script_id}"))()`;

            return res.json({

                ok: true,

                id:
                    script.script_id,

                loader

            });

        } catch (error) {

            console.error(
                "CREATE ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Create script server error."
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
                        script_id,
                        name,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    `,
                    [
                        req.auth.user.id
                    ]
                );

            const scripts =
                result.rows.map(
                    (script) => {

                        return {

                            id:
                                script.script_id,

                            name:
                                script.name,

                            loader:
                                `loadstring(game:HttpGet("${PUBLIC_URL}/api/loader/${script.script_id}"))()`,

                            created:
                                new Date(
                                    script.created_at
                                ).getTime(),

                            updated:
                                new Date(
                                    script.updated_at
                                ).getTime()

                        };

                    }
                );

            return res.json({

                ok: true,

                scripts

            });

        } catch (error) {

            console.error(
                "LIST ERROR:",
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
   GET SCRIPT
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
                        script_id,
                        name,
                        source,
                        enabled
                    FROM scripts
                    WHERE
                        script_id = $1
                        AND user_id = $2
                    LIMIT 1
                    `,
                    [
                        req.params.id,
                        req.auth.user.id
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                const exists =
                    await pool.query(
                        `
                        SELECT 1
                        FROM scripts
                        WHERE script_id = $1
                        LIMIT 1
                        `,
                        [
                            req.params.id
                        ]
                    );

                if (
                    exists.rowCount === 0
                ) {

                    return apiError(
                        res,
                        404,
                        "Script not found."
                    );

                }

                return apiError(
                    res,
                    403,
                    "Access denied."
                );

            }

            const script =
                result.rows[0];

            return res.json({

                ok: true,

                script: {

                    id:
                        script.script_id,

                    name:
                        script.name,

                    source:
                        script.source

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
   UPDATE SCRIPT
========================================================= */

app.put(
    "/api/script/:id",
    requireAuth,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        name,
                        source
                    FROM scripts
                    WHERE
                        script_id = $1
                        AND user_id = $2
                    LIMIT 1
                    `,
                    [
                        req.params.id,
                        req.auth.user.id
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                const exists =
                    await pool.query(
                        `
                        SELECT 1
                        FROM scripts
                        WHERE script_id = $1
                        LIMIT 1
                        `,
                        [
                            req.params.id
                        ]
                    );

                if (
                    exists.rowCount === 0
                ) {

                    return apiError(
                        res,
                        404,
                        "Script not found."
                    );

                }

                return apiError(
                    res,
                    403,
                    "Access denied."
                );

            }

            const current =
                result.rows[0];

            let name =
                current.name;

            let source =
                current.source;

            if (
                typeof req.body.name ===
                "string"
            ) {

                name =
                    req.body.name
                        .trim()
                        .slice(
                            0,
                            100
                        )
                        ||
                        "Untitled Script";

            }

            if (
                typeof req.body.source ===
                "string"
            ) {

                if (
                    !req.body.source.trim()
                ) {

                    return apiError(
                        res,
                        400,
                        "Script source cannot be empty."
                    );

                }

                source =
                    req.body.source;

            }

            await pool.query(
                `
                UPDATE scripts
                SET
                    name = $1,
                    source = $2,
                    updated_at = NOW()
                WHERE
                    script_id = $3
                    AND user_id = $4
                `,
                [
                    name,
                    source,
                    req.params.id,
                    req.auth.user.id
                ]
            );

            return res.json({
                ok: true
            });

        } catch (error) {

            console.error(
                "UPDATE ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Update script server error."
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
                        script_id = $1
                        AND user_id = $2
                    RETURNING script_id
                    `,
                    [
                        req.params.id,
                        req.auth.user.id
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                const exists =
                    await pool.query(
                        `
                        SELECT 1
                        FROM scripts
                        WHERE script_id = $1
                        LIMIT 1
                        `,
                        [
                            req.params.id
                        ]
                    );

                if (
                    exists.rowCount === 0
                ) {

                    return apiError(
                        res,
                        404,
                        "Script not found."
                    );

                }

                return apiError(
                    res,
                    403,
                    "Access denied."
                );

            }

            return res.json({
                ok: true
            });

        } catch (error) {

            console.error(
                "DELETE ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "Delete script server error."
            );

        }

    }
);

/* =========================================================
   LOADER SESSION
========================================================= */

async function createLoaderSession(
    scriptId
) {

    const id =
        randomHex(32);

    const expires =
        new Date(
            Date.now() +
            LOADER_SESSION_TTL
        );

    const result =
        await pool.query(
            `
            INSERT INTO loader_sessions
            (
                session_token,
                script_id,
                stage,
                tokens,
                created_at,
                expires_at,
                last_seen_at
            )
            VALUES
            (
                $1,
                $2,
                0,
                '[]'::jsonb,
                NOW(),
                $3,
                NOW()
            )
            RETURNING
                session_token,
                script_id,
                stage,
                tokens,
                created_at,
                expires_at
            `,
            [
                id,
                scriptId,
                expires
            ]
        );

    const row =
        result.rows[0];

    return {

        id:
            row.session_token,

        scriptId:
            row.script_id,

        stage:
            row.stage,

        tokens:
            Array.isArray(row.tokens)
                ? row.tokens
                : [],

        created:
            new Date(
                row.created_at
            ).getTime(),

        expires:
            new Date(
                row.expires_at
            ).getTime()

    };

}

async function getLoaderSession(
    sessionId
) {

    if (!sessionId)
        return null;

    const result =
        await pool.query(
            `
            SELECT
                session_token,
                script_id,
                stage,
                tokens,
                created_at,
                expires_at,
                last_seen_at
            FROM loader_sessions
            WHERE
                session_token = $1
                AND expires_at > NOW()
            LIMIT 1
            `,
            [sessionId]
        );

    if (
        result.rowCount === 0
    ) {

        await pool.query(
            `
            DELETE FROM loader_sessions
            WHERE
                session_token = $1
            `,
            [sessionId]
        );

        return null;

    }

    const row =
        result.rows[0];

    await pool.query(
        `
        UPDATE loader_sessions
        SET last_seen_at = NOW()
        WHERE session_token = $1
        `,
        [sessionId]
    );

    return {

        id:
            row.session_token,

        scriptId:
            row.script_id,

        stage:
            row.stage,

        tokens:
            Array.isArray(row.tokens)
                ? row.tokens
                : [],

        created:
            new Date(
                row.created_at
            ).getTime(),

        expires:
            new Date(
                row.expires_at
            ).getTime()

    };

}

async function saveLoaderSession(
    session
) {

    await pool.query(
        `
        UPDATE loader_sessions
        SET
            stage = $1,
            tokens = $2::jsonb,
            last_seen_at = NOW()
        WHERE
            session_token = $3
            AND expires_at > NOW()
        `,
        [
            session.stage,
            JSON.stringify(
                session.tokens
            ),
            session.id
        ]
    );

}

async function deleteLoaderSession(
    sessionId
) {

    await pool.query(
        `
        DELETE FROM loader_sessions
        WHERE session_token = $1
        `,
        [sessionId]
    );

}

async function issueToken(
    session
) {

    const token =
        randomHex(32);

    session.tokens.push(
        token
    );

    await saveLoaderSession(
        session
    );

    return token;

}

async function consumeToken(
    session,
    token
) {

    if (!token)
        return false;

    const index =
        session.tokens.indexOf(
            token
        );

    if (
        index === -1
    ) {

        return false;

    }

    session.tokens.splice(
        index,
        1
    );

    await saveLoaderSession(
        session
    );

    return true;

}

async function validLoaderSession(
    session
) {

    if (!session)
        return false;

    if (
        Date.now() >
        session.expires
    ) {

        await deleteLoaderSession(
            session.id
        );

        return false;

    }

    return true;

}

/* =========================================================
   PROTECT PAGE
========================================================= */

function blockPage(res) {

    return res
        .status(403)
        .type("html")
        .send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>LEXINX PROTECT</title>

<style>

html,body{
    margin:0;
    width:100%;
    height:100%;
    background:#050505;
    color:#eee;
    font-family:Arial,sans-serif;
}

body{
    display:flex;
    align-items:center;
    justify-content:center;
}

.box{
    width:min(520px,88%);
    padding:55px 30px;
    text-align:center;
    background:#111;
    border:1px solid #292929;
    border-radius:18px;
    box-shadow:
        0 0 60px
        rgba(255,255,255,.04);
}

.logo{
    font-size:42px;
    font-weight:900;
    letter-spacing:8px;
}

.sub{
    margin-top:16px;
    color:#777;
    font-size:13px;
    letter-spacing:4px;
}

</style>

</head>

<body>

<div class="box">

<div class="logo">
LEXINX
</div>

<div class="sub">
PROTECT
</div>

<div class="sub">
ANTI-SKID
</div>

</div>

</body>

</html>
`);

}

/* =========================================================
   LUA HEX DECODER
========================================================= */

function luaHexDecoder() {

    return `
local function decodeHex(s)

    local out = {}

    for i = 1, #s, 2 do

        local n =
            tonumber(
                s:sub(i, i + 1),
                16
            )

        if n then

            out[#out + 1] =
                string.char(n)

        end

    end

    return table.concat(out)

end
`;

}

/* =========================================================
   RANDOM LUA NAME
========================================================= */

function randomLuaName() {

    const chars =
        "abcdefghijklmnopqrstuvwxyz";

    let result = "_";

    for (
        let i = 0;
        i < 10;
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
   WRAPPER
========================================================= */

async function buildWrapper(
    session
) {

    const token =
        await issueToken(
            session
        );

    const endpoint =
        hexEncode(
            PUBLIC_URL
        );

    const endpointVar =
        randomLuaName();

    const sessionVar =
        randomLuaName();

    const tokenVar =
        randomLuaName();

    const request =
        randomLuaName();

    return `

-- LEXINX WRAPPER VM

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${sessionVar} =
    ${luaString(session.id)}

local ${tokenVar} =
    ${luaString(token)}

local function ${request}()

    local endpoint =
        decodeHex(
            ${endpointVar}
        )

    local url =
        endpoint
        .. "/api/l3"
        .. "?session="
        .. ${sessionVar}
        .. "&token="
        .. ${tokenVar}

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    if type(response)
        ~= "string"
    then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return ${request}()

`;

}

/* =========================================================
   L2
========================================================= */

async function buildL2(
    session
) {

    const token =
        await issueToken(
            session
        );

    const endpoint =
        hexEncode(
            PUBLIC_URL
        );

    const endpointVar =
        randomLuaName();

    const sessionVar =
        randomLuaName();

    const tokenVar =
        randomLuaName();

    const vm =
        randomLuaName();

    return `

-- LEXINX L2

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${vm} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)}

}

local function runVM(state)

    local url =
        state.endpoint
        .. "/api/l4"
        .. "?session="
        .. state.session
        .. "&token="
        .. state.token

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

end

return runVM(${vm})

`;

}

/* =========================================================
   L3 PACKED PROTOTYPE
========================================================= */

async function buildL3(
    session
) {

    const token =
        await issueToken(
            session
        );

    const endpoint =
        hexEncode(
            PUBLIC_URL
        );

    const endpointVar =
        randomLuaName();

    const prototype =
        randomLuaName();

    return `

-- LEXINX L3
-- PACKED PROTOTYPE

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${prototype} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)},

    opcode = {

        LOAD = 1,
        REQUEST = 2,
        EXEC = 3

    }

}

local function executeVM(p)

    local url =
        p.endpoint
        .. "/api/l5"
        .. "?session="
        .. p.session
        .. "&token="
        .. p.token

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

end

return executeVM(
    ${prototype}
)

`;

}

/* =========================================================
   L4 RUNTIME
========================================================= */

async function buildL4(
    session
) {

    const token =
        await issueToken(
            session
        );

    const endpoint =
        hexEncode(
            PUBLIC_URL
        );

    const endpointVar =
        randomLuaName();

    const runtime =
        randomLuaName();

    return `

-- LEXINX L4
-- RUNTIME BOOTSTRAP

local ${endpointVar} =
    "${endpoint}"

${luaHexDecoder()}

local ${runtime} = {

    endpoint =
        decodeHex(
            ${endpointVar}
        ),

    session =
        ${luaString(session.id)},

    token =
        ${luaString(token)},

    stage = 4

}

local function bootstrap(state)

    local url =
        state.endpoint
        .. "/api/l5/final"
        .. "?session="
        .. state.session
        .. "&token="
        .. state.token

    local ok, response =
        pcall(function()

            return game:HttpGet(
                url
            )

        end)

    if not ok then
        return
    end

    if type(response)
        ~= "string"
    then
        return
    end

    local fn =
        loadstring(response)

    if fn then
        return fn()
    end

end

return bootstrap(
    ${runtime}
)

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

    const data =
        randomLuaName();

    const decode =
        randomLuaName();

    const execute =
        randomLuaName();

    return `

-- LEXINX L5
-- FINAL RUNTIME

local ${data} =
    ${luaString(payload)}

local function ${decode}(input)

    local alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    input =
        input:gsub(
            "[^"
            .. alphabet
            .. "=]",
            ""
        )

    local bits = {}

    for i = 1, #input do

        local c =
            input:sub(i, i)

        if c ~= "=" then

            local p =
                alphabet:find(
                    c,
                    1,
                    true
                )

            if p then

                p = p - 1

                for j = 6, 1, -1 do

                    if
                        p % 2^j >=
                        2^(j - 1)
                    then

                        bits[#bits + 1] =
                            "1"

                    else

                        bits[#bits + 1] =
                            "0"

                    end

                end

            end

        end

    end

    local output = {}

    for i = 1,
        #bits - 7,
        8
    do

        local byte = 0

        for j = 0, 7 do

            if
                bits[i + j]
                == "1"
            then

                byte =
                    byte +
                    2^(7 - j)

            end

        end

        output[#output + 1] =
            string.char(byte)

    end

    return table.concat(
        output
    )

end

local function ${execute}()

    local source =
        ${decode}(
            ${data}
        )

    local fn =
        loadstring(source)

    if fn then
        return fn()
    end

end

return ${execute}()

`;

}

/* =========================================================
   LOADER
========================================================= */

app.get(
    "/api/loader/:id",
    async (req, res) => {

        try {

            const id =
                String(
                    req.params.id || ""
                ).trim();

            if (!id) {

                return blockPage(
                    res
                );

            }

            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                    LIMIT 1
                    `,
                    [id]
                );

            if (
                result.rowCount === 0
            ) {

                return blockPage(
                    res
                );

            }

            const script =
                result.rows[0];

            if (
                script.enabled === false
            ) {

                return blockPage(
                    res
                );

            }

            /*
             * Direct browser navigation normally
             * contains text/html in Accept.
             */

            const accept =
                String(
                    req.headers.accept || ""
                ).toLowerCase();

            if (
                accept.includes(
                    "text/html"
                )
            ) {

                return blockPage(
                    res
                );

            }

            /*
             * Create a fresh loader session.
             */

            const session =
                await createLoaderSession(
                    script.script_id
                );

            const wrapper =
                await buildWrapper(
                    session
                );

            return res
                .status(200)
                .type("text/plain")
                .send(wrapper);

        } catch (error) {

            console.error(
                "LOADER ERROR:",
                error
            );

            return res
                .status(500)
                .type("text/plain")
                .send(
                    "LEXINX INTERNAL ERROR"
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
                await getLoaderSession(
                    req.query.session
                );

            if (
                !(await validLoaderSession(
                    session
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            if (
                session.stage !== 0
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            if (
                !(await consumeToken(
                    session,
                    req.query.token
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            session.stage =
                1;

            await saveLoaderSession(
                session
            );

            return res
                .type("text/plain")
                .send(
                    await buildL2(
                        session
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
                "L3 SERVER ERROR"
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
                await getLoaderSession(
                    req.query.session
                );

            if (
                !(await validLoaderSession(
                    session
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            if (
                session.stage !== 1
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            if (
                !(await consumeToken(
                    session,
                    req.query.token
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            session.stage =
                2;

            await saveLoaderSession(
                session
            );

            return res
                .type("text/plain")
                .send(
                    await buildL3(
                        session
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
                "L4 SERVER ERROR"
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
                await getLoaderSession(
                    req.query.session
                );

            if (
                !(await validLoaderSession(
                    session
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            if (
                session.stage !== 2
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            if (
                !(await consumeToken(
                    session,
                    req.query.token
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            session.stage =
                3;

            await saveLoaderSession(
                session
            );

            return res
                .type("text/plain")
                .send(
                    await buildL4(
                        session
                    )
                );

        } catch (error) {

            console.error(
                "L5 ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "L5 SERVER ERROR"
            );

        }

    }
);

/* =========================================================
   FINAL
========================================================= */

app.get(
    "/api/l5/final",
    async (req, res) => {

        try {

            const session =
                await getLoaderSession(
                    req.query.session
                );

            if (
                !(await validLoaderSession(
                    session
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            /*
             * /api/l5 changes:
             *
             * stage 2 -> stage 3
             *
             * Therefore final requires stage 3.
             */

            if (
                session.stage !== 3
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            if (
                !(await consumeToken(
                    session,
                    req.query.token
                ))
            ) {

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            const result =
                await pool.query(
                    `
                    SELECT
                        script_id,
                        source,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                    LIMIT 1
                    `,
                    [
                        session.scriptId
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                await deleteLoaderSession(
                    session.id
                );

                return apiError(
                    res,
                    404,
                    "Script not found."
                );

            }

            const script =
                result.rows[0];

            if (
                script.enabled === false
            ) {

                await deleteLoaderSession(
                    session.id
                );

                return apiError(
                    res,
                    403,
                    "LEXINX BLOCK"
                );

            }

            /*
             * Access log
             */

            try {

                await pool.query(
                    `
                    INSERT INTO script_access_logs
                    (
                        user_id,
                        script_id,
                        ip_address,
                        success
                    )
                    VALUES
                    (
                        NULL,
                        $1,
                        $2,
                        TRUE
                    )
                    `,
                    [
                        script.script_id,
                        req.ip || null
                    ]
                );

            } catch (logError) {

                console.error(
                    "ACCESS LOG ERROR:",
                    logError
                );

            }

            const output =
                buildL5(
                    session,
                    script.source
                );

            await deleteLoaderSession(
                session.id
            );

            return res
                .status(200)
                .type("text/plain")
                .send(output);

        } catch (error) {

            console.error(
                "FINAL ERROR:",
                error
            );

            return apiError(
                res,
                500,
                "FINAL SERVER ERROR"
            );

        }

    }
);

/* =========================================================
   API 404
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
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );

    }
);

/* =========================================================
   UNKNOWN PAGE
========================================================= */

app.use(
    (req, res) => {

        return res
            .status(404)
            .send(
                "Page not found."
            );

    }
);

/* =========================================================
   DATABASE CLEANUP
========================================================= */

async function cleanupDatabase() {

    try {

        await pool.query(
            `
            DELETE FROM login_sessions
            WHERE
                expires_at IS NOT NULL
                AND expires_at <= NOW()
            `
        );

        await pool.query(
            `
            DELETE FROM loader_sessions
            WHERE
                expires_at <= NOW()
            `
        );

    } catch (error) {

        console.error(
            "DATABASE CLEANUP ERROR:",
            error
        );

    }

}

setInterval(
    cleanupDatabase,
    30 * 1000
);

/* =========================================================
   SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            "LEXINX server running on port " +
            PORT
        );

        console.log(
            "PUBLIC URL: " +
            PUBLIC_URL
        );

        console.log(
            "POSTGRESQL: " +
            (
                process.env.DATABASE_URL
                    ? "CONFIGURED"
                    : "NOT CONFIGURED"
            )
        );

    }
);
