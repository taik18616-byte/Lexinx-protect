const express = require("express");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");
const PUBLIC_DIR = path.join(__dirname, "public");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify({
            users: {},
            sessions: {}
        }, null, 2)
    );
}

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({
    extended: true,
    limit: "20mb"
}));
app.use(express.static(PUBLIC_DIR));

/* =========================================================
   DATABASE
========================================================= */

function readDB() {
    try {
        return JSON.parse(
            fs.readFileSync(DB_FILE, "utf8")
        );
    } catch {
        return {
            users: {},
            sessions: {}
        };
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
   HELPERS
========================================================= */

function randomID(bytes = 12) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
}

function verificationCode() {
    return String(
        crypto.randomInt(100000, 1000000)
    );
}

function generatedPassword() {
    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";

    let result = "";

    for (let i = 0; i < 14; i++) {
        result += chars[
            crypto.randomInt(0, chars.length)
        ];
    }

    return result;
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);
}

function hashPassword(password, salt) {
    return crypto
        .scryptSync(password, salt, 64)
        .toString("hex");
}

function createPasswordHash(password) {
    const salt = crypto
        .randomBytes(16)
        .toString("hex");

    return {
        salt,
        hash: hashPassword(password, salt)
    };
}

function verifyPassword(password, user) {
    const hash =
        hashPassword(password, user.salt);

    return crypto.timingSafeEqual(
        Buffer.from(hash, "hex"),
        Buffer.from(user.passwordHash, "hex")
    );
}

function createLoader(id) {
    return `loadstring(game:HttpGet("${DOMAIN}/api/${id}"))()`;
}

/* =========================================================
   EMAIL
========================================================= */

let transporter = null;

if (
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
) {
    transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(
            process.env.SMTP_PORT || 587
        ),
        secure:
            String(
                process.env.SMTP_SECURE || "false"
            ) === "true",

        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });
}

async function sendVerificationMail(
    email,
    code,
    password
) {
    if (!transporter) {
        console.log(
            "\n=============================="
        );

        console.log(
            "SMTP NOT CONFIGURED"
        );

        console.log(
            "EMAIL:",
            email
        );

        console.log(
            "CODE:",
            code
        );

        console.log(
            "PASSWORD:",
            password
        );

        console.log(
            "==============================\n"
        );

        return;
    }

    await transporter.sendMail({
        from:
            process.env.MAIL_FROM ||
            process.env.SMTP_USER,

        to: email,

        subject:
            "LEXINX PROTECT - Verification",

        text:
`LEXINX PROTECT

Your verification code:

${code}

Your generated password:

${password}

The verification code expires in 10 minutes.

Do not share this information with anyone.`
    });
}

/* =========================================================
   SESSION
========================================================= */

function getSession(req) {
    const token =
        req.headers["x-session-token"];

    if (!token) {
        return null;
    }

    const db = readDB();

    const session =
        db.sessions[token];

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expiresAt
    ) {
        delete db.sessions[token];
        writeDB(db);
        return null;
    }

    return {
        token,
        userId: session.userId
    };
}

function requireSession(req, res, next) {
    const session =
        getSession(req);

    if (!session) {
        return res.status(401).json({
            ok: false,
            error: "Not logged in"
        });
    }

    req.session = session;
    next();
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            PUBLIC_DIR,
            "index.html"
        )
    );
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
    try {
        const email =
            String(
                req.body?.email || ""
            )
            .trim()
            .toLowerCase();

        if (!validEmail(email)) {
            return res.status(400).json({
                ok: false,
                error: "Invalid Gmail address"
            });
        }

        if (!email.endsWith("@gmail.com")) {
            return res.status(400).json({
                ok: false,
                error:
                    "Only Gmail addresses are allowed"
            });
        }

        const db = readDB();

        if (db.users[email]) {
            return res.status(409).json({
                ok: false,
                error:
                    "This Gmail is already registered"
            });
        }

        const password =
            generatedPassword();

        const code =
            verificationCode();

        const passwordData =
            createPasswordHash(password);

        db.users[email] = {
            email,

            passwordHash:
                passwordData.hash,

            salt:
                passwordData.salt,

            verified: false,

            verificationCode: code,

            verificationExpires:
                Date.now() +
                10 * 60 * 1000,

            createdAt:
                Date.now(),

            scripts: {}
        };

        writeDB(db);

        await sendVerificationMail(
            email,
            code,
            password
        );

        res.json({
            ok: true,
            message:
                "Verification email sent"
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            ok: false,
            error:
                "Could not send verification email"
        });
    }
});

/* =========================================================
   VERIFY
========================================================= */

app.post("/api/verify", (req, res) => {
    const email =
        String(
            req.body?.email || ""
        )
        .trim()
        .toLowerCase();

    const code =
        String(
            req.body?.code || ""
        ).trim();

    const db = readDB();
    const user = db.users[email];

    if (!user) {
        return res.status(404).json({
            ok: false,
            error: "Account not found"
        });
    }

    if (user.verified) {
        return res.json({
            ok: true,
            message:
                "Account already verified"
        });
    }

    if (
        Date.now() >
        user.verificationExpires
    ) {
        return res.status(400).json({
            ok: false,
            error:
                "Verification code expired"
        });
    }

    if (
        code !==
        String(user.verificationCode)
    ) {
        return res.status(400).json({
            ok: false,
            error:
                "Invalid verification code"
        });
    }

    user.verified = true;
    delete user.verificationCode;
    delete user.verificationExpires;

    writeDB(db);

    res.json({
        ok: true,
        message:
            "Account verified"
    });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", (req, res) => {
    const email =
        String(
            req.body?.email || ""
        )
        .trim()
        .toLowerCase();

    const password =
        String(
            req.body?.password || ""
        );

    const db = readDB();
    const user = db.users[email];

    if (!user) {
        return res.status(401).json({
            ok: false,
            error:
                "Invalid email or password"
        });
    }

    if (!user.verified) {
        return res.status(403).json({
            ok: false,
            error:
                "Account is not verified"
        });
    }

    if (
        !verifyPassword(
            password,
            user
        )
    ) {
        return res.status(401).json({
            ok: false,
            error:
                "Invalid email or password"
        });
    }

    const token =
        randomID(32);

    db.sessions[token] = {
        userId: email,

        expiresAt:
            Date.now() +
            7 * 24 * 60 * 60 * 1000
    };

    writeDB(db);

    res.json({
        ok: true,
        token,
        email
    });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    requireSession,
    (req, res) => {
        const db = readDB();

        delete db.sessions[
            req.session.token
        ];

        writeDB(db);

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
    "/api/me",
    requireSession,
    (req, res) => {
        res.json({
            ok: true,
            email:
                req.session.userId
        });
    }
);

/* =========================================================
   CREATE SCRIPT
========================================================= */

app.post(
    "/api/create",
    requireSession,
    (req, res) => {

        const source =
            typeof req.body?.source ===
            "string"
                ? req.body.source
                : "";

        if (!source.trim()) {
            return res.status(400).json({
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
            randomID(12);

        const db = readDB();

        const user =
            db.users[
                req.session.userId
            ];

        user.scripts[id] = {
            id,
            name,
            source,
            createdAt:
                Date.now(),
            updatedAt:
                Date.now()
        };

        writeDB(db);

        res.json({
            ok: true,
            id,
            name,
            endpoint:
                `${DOMAIN}/api/${id}`,
            loader:
                createLoader(id)
        });
    }
);

/* =========================================================
   LIST USER SCRIPTS
========================================================= */

app.get(
    "/api/scripts",
    requireSession,
    (req, res) => {

        const db = readDB();

        const user =
            db.users[
                req.session.userId
            ];

        const scripts =
            Object.values(
                user.scripts || {}
            )
            .map(script => ({
                id:
                    script.id,

                name:
                    script.name,

                createdAt:
                    script.createdAt,

                updatedAt:
                    script.updatedAt,

                endpoint:
                    `${DOMAIN}/api/${script.id}`,

                loader:
                    createLoader(
                        script.id
                    )
            }))
            .reverse();

        res.json({
            ok: true,
            scripts
        });
    }
);

/* =========================================================
   EDIT SCRIPT
========================================================= */

app.post(
    "/api/edit/:id",
    requireSession,
    (req, res) => {

        const id =
            req.params.id;

        const source =
            typeof req.body?.source ===
            "string"
                ? req.body.source
                : "";

        if (!source.trim()) {
            return res.status(400).json({
                ok: false,
                error:
                    "Script is empty"
            });
        }

        const db = readDB();

        const user =
            db.users[
                req.session.userId
            ];

        const script =
            user.scripts[id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        script.source =
            source;

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

        res.json({
            ok: true,
            id,
            name:
                script.name,
            endpoint:
                `${DOMAIN}/api/${id}`,
            loader:
                createLoader(id)
        });
    }
);

/* =========================================================
   GET SOURCE
========================================================= */

app.get("/api/:id", (req, res) => {

    /*
       Browser thông thường sẽ bị chặn.
       Đây chỉ là basic User-Agent filtering,
       không phải bảo mật tuyệt đối.
    */

    const ua =
        String(
            req.headers["user-agent"] ||
            ""
        )
        .toLowerCase();

    const browser =
        ua.includes("mozilla") ||
        ua.includes("chrome") ||
        ua.includes("safari") ||
        ua.includes("firefox") ||
        ua.includes("edg");

    if (browser) {
        return res
            .status(403)
            .type("text/plain")
            .send(
                "LEXINX PROTECT - Browser blocked"
            );
    }

    const id =
        req.params.id;

    const db = readDB();

    let found = null;

    for (
        const email of Object.keys(
            db.users
        )
    ) {
        const user =
            db.users[email];

        if (
            user.scripts &&
            user.scripts[id]
        ) {
            found =
                user.scripts[id];
            break;
        }
    }

    if (!found) {
        return res
            .status(404)
            .type("text/plain")
            .send(
                "Script not found"
            );
    }

    res
        .status(200)
        .type("text/plain")
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
        )
        .send(found.source);
});

/* =========================================================
   DELETE
========================================================= */

app.delete(
    "/api/delete/:id",
    requireSession,
    (req, res) => {

        const db = readDB();

        const user =
            db.users[
                req.session.userId
            ];

        if (
            !user.scripts[
                req.params.id
            ]
        ) {
            return res.status(404).json({
                ok: false,
                error:
                    "Script not found"
            });
        }

        delete user.scripts[
            req.params.id
        ];

        writeDB(db);

        res.json({
            ok: true
        });
    }
);

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
    res
        .status(404)
        .type("text/plain")
        .send(
            "Blocked by LEXINX PROTECT"
        );
});

/* =========================================================
   START
========================================================= */

app.listen(PORT, () => {
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
        "SMTP:",
        transporter
            ? "CONFIGURED"
            : "NOT CONFIGURED"
    );

    console.log(
        "================================"
    );
});
