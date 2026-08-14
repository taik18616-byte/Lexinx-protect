const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const SCRIPT_DIR = path.join(DATA_DIR, "scripts");
const DB_FILE = path.join(DATA_DIR, "scripts.json");

const ADMIN_TOKEN =
    process.env.ADMIN_TOKEN || "CHANGE_THIS_ADMIN_TOKEN";

fs.mkdirSync(SCRIPT_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

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

function randomID() {
    return crypto.randomBytes(18).toString("hex");
}

function randomToken() {
    return crypto.randomBytes(32).toString("hex");
}

function safeName(name) {
    return String(name || "script")
        .replace(/[^a-zA-Z0-9._ -]/g, "_")
        .slice(0, 80);
}

function validAdmin(req) {
    return req.get("X-Admin-Token") === ADMIN_TOKEN;
}

/*
 * Token sống 60 giây.
 * Token chỉ được dùng một lần.
 */
const sessions = new Map();

function cleanupSessions() {
    const now = Date.now();

    for (const [token, session] of sessions) {
        if (
            session.expiresAt < now ||
            session.used
        ) {
            sessions.delete(token);
        }
    }
}

setInterval(cleanupSessions, 30_000);

/* =========================
   WEB
========================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

/* =========================
   CREATE SCRIPT
========================= */

app.post("/api/create", (req, res) => {
    if (!validAdmin(req)) {
        return res.status(401).json({
            ok: false,
            error: "Unauthorized"
        });
    }

    const code =
        typeof req.body.code === "string"
            ? req.body.code
            : "";

    if (!code.trim()) {
        return res.status(400).json({
            ok: false,
            error: "Script is empty"
        });
    }

    const name =
        safeName(req.body.name);

    const id = randomID();

    const filename =
        `${id}.lua`;

    fs.writeFileSync(
        path.join(SCRIPT_DIR, filename),
        code,
        "utf8"
    );

    const db = readDB();

    db[id] = {
        id,
        name,
        filename,
        createdAt: Date.now()
    };

    writeDB(db);

    res.json({
        ok: true,
        id,
        name
    });
});

/* =========================
   LIST
========================= */

app.get("/api/scripts", (req, res) => {
    if (!validAdmin(req)) {
        return res.status(401).json({
            ok: false,
            error: "Unauthorized"
        });
    }

    const db = readDB();

    res.json({
        ok: true,
        scripts: Object.values(db)
            .sort(
                (a, b) =>
                    b.createdAt -
                    a.createdAt
            )
    });
});

/* =========================
   CREATE SHORT SESSION
========================= */

app.post("/api/session", (req, res) => {
    const id = req.body?.id;

    if (
        typeof id !== "string" ||
        !/^[a-f0-9]{36}$/.test(id)
    ) {
        return res.status(400).json({
            ok: false,
            error: "Invalid ID"
        });
    }

    const db = readDB();

    if (!db[id]) {
        return res.status(404).json({
            ok: false,
            error: "Not found"
        });
    }

    const token = randomToken();

    sessions.set(token, {
        id,
        expiresAt:
            Date.now() + 60_000,
        used: false
    });

    res.json({
        ok: true,
        token,
        expiresIn: 60
    });
});

/* =========================
   PAYLOAD
========================= */

app.get("/api/payload/:token", (req, res) => {
    const token =
        req.params.token;

    const session =
        sessions.get(token);

    if (!session) {
        return res
            .status(403)
            .type("text/plain")
            .send(
                "Blocked by LEXINX v50 protection"
            );
    }

    if (
        session.used ||
        session.expiresAt < Date.now()
    ) {
        sessions.delete(token);

        return res
            .status(401)
            .type("text/plain")
            .send(
                "Expired or already used"
            );
    }

    const db = readDB();
    const item = db[session.id];

    if (!item) {
        sessions.delete(token);

        return res
            .status(404)
            .type("text/plain")
            .send(
                "Blocked by LEXINX v50 protection"
            );
    }

    const file =
        path.join(
            SCRIPT_DIR,
            item.filename
        );

    if (!fs.existsSync(file)) {
        sessions.delete(token);

        return res
            .status(404)
            .type("text/plain")
            .send(
                "Blocked by LEXINX v50 protection"
            );
    }

    session.used = true;

    const source =
        fs.readFileSync(
            file,
            "utf8"
        );

    /*
     * Không obfuscate.
     * Trả source nguyên bản.
     */

    res
        .type("text/plain")
        .set(
            "Cache-Control",
            "no-store, no-cache"
        )
        .send(source);
});

/* =========================
   DELETE
========================= */

app.delete("/api/scripts/:id", (req, res) => {
    if (!validAdmin(req)) {
        return res.status(401).json({
            ok: false,
            error: "Unauthorized"
        });
    }

    const id =
        req.params.id;

    const db = readDB();
    const item = db[id];

    if (!item) {
        return res.status(404).json({
            ok: false,
            error: "Not found"
        });
    }

    const file =
        path.join(
            SCRIPT_DIR,
            item.filename
        );

    if (fs.existsSync(file)) {
        fs.unlinkSync(file);
    }

    delete db[id];

    writeDB(db);

    res.json({
        ok: true
    });
});

/* =========================
   BLOCK UNKNOWN ROUTES
========================= */

app.use((req, res) => {
    res.status(404)
        .type("text/plain")
        .send(
            "Blocked by LEXINX v50 protection"
        );
});

app.listen(PORT, () => {
    console.log(
        `LEXINX PROTECT running on port ${PORT}`
    );
});
