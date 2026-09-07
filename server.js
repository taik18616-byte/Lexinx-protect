const express = require("express");
const crypto = require("crypto");
const path = require("path");
const mysql = require("mysql2/promise");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://lexinx-protect-v230.vercel.app";

const WEB_SESSION_TTL =
    7 * 24 * 60 * 60 * 1000;

const LOADER_SESSION_TTL =
    60 * 1000;

/*
==================================================
MYSQL
==================================================
*/

let pool = null;

function getPool() {

    if (pool) {
        return pool;
    }

    if (
        !process.env.DB_HOST ||
        !process.env.DB_USER ||
        !process.env.DB_PASSWORD ||
        !process.env.DB_NAME
    ) {
        throw new Error(
            "Missing MySQL environment variables: " +
            "DB_HOST, DB_USER, DB_PASSWORD, DB_NAME"
        );
    }

    pool = mysql.createPool({
        host: process.env.DB_HOST,
        port: Number(process.env.DB_PORT || 3306),

        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,

        waitForConnections: true,

        /*
        Vercel serverless không nên để quá lớn
        */
        connectionLimit: 5,

        queueLimit: 0,

        charset: "utf8mb4",

        enableKeepAlive: true,

        keepAliveInitialDelay: 10000,

        connectTimeout: 10000
    });

    return pool;
}


/*
==================================================
EXPRESS
==================================================
*/

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


/*
==================================================
PUBLIC
==================================================
*/

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);


/*
==================================================
HELPERS
==================================================
*/

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


function now() {

    return Date.now();
}


function luaString(value) {

    return JSON.stringify(
        String(value)
    );
}


function hexEncode(value) {

    return Buffer
        .from(String(value), "utf8")
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


function getCookie(
    req,
    name
) {

    const raw =
        req.headers.cookie || "";

    const parts =
        raw.split(";");

    for (const part of parts) {

        const item =
            part.trim();

        const index =
            item.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            item.slice(0, index);

        const value =
            item.slice(index + 1);

        if (key === name) {

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


/*
==================================================
DATABASE TEST
==================================================
*/

async function testDatabase() {

    try {

        const db =
            getPool();

        const [rows] =
            await db.query(
                "SELECT 1 AS ok"
            );

        return rows[0]?.ok === 1;

    } catch (error) {

        console.error(
            "[MYSQL ERROR]",
            error
        );

        return false;
    }
}


/*
==================================================
HEALTH
==================================================
*/

app.get(
    "/api/health",
    async (req, res) => {

        try {

            const db =
                getPool();

            const [rows] =
                await db.query(
                    "SELECT 1 AS ok"
                );

            return res.json({
                ok: rows[0]?.ok === 1,
                database: "mysql",
                timestamp: now()
            });

        } catch (error) {

            console.error(
                "[HEALTH ERROR]",
                error
            );

            return res.status(503).json({
                ok: false,
                database: "unavailable",
                error:
                    process.env.NODE_ENV ===
                    "production"
                        ? "Database unavailable"
                        : error.message
            });

        }
    }
);


/*
==================================================
ROOT
==================================================
*/

app.get(
    "/",
    (req, res) => {

        res.status(200).send(
            "LEXINX PROTECT API ONLINE"
        );

    }
);


/*
==================================================
STARTUP TEST
==================================================
*/

if (!process.env.VERCEL) {

    testDatabase()
        .then(() => {

            app.listen(
                PORT,
                () => {

                    console.log(
                        `LEXINX server running on port ${PORT}`
                    );

                }
            );

        })
        .catch(error => {

            console.error(
                "[STARTUP ERROR]",
                error
            );

        });

}


/*
==================================================
VERCEL EXPORT
==================================================
*/

module.exports = app;
