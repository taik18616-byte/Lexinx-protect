const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN = (
    process.env.DOMAIN ||
    "https://Lexinx-protect.onrender.com"
).replace(/\/+$/, "");

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "scripts.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.use(express.json({ limit: "15mb" }));

function readDB() {
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
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

function randomID(bytes = 16) {
    return crypto.randomBytes(bytes).toString("hex");
}

function blocked(res) {
    return res
        .status(403)
        .type("text/plain")
        .send("LEXINX BLOCK");
}

function validID(id) {
    return /^[a-f0-9]{16,64}$/i.test(id);
}

/*
=========================================================
WEB PANEL
=========================================================
*/

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "index.html")
    );
});

/*
=========================================================
CREATE SCRIPT
=========================================================
*/

app.post("/api/create", (req, res) => {

    const source =
        typeof req.body?.source === "string"
            ? req.body.source
            : "";

    const name =
        typeof req.body?.name === "string"
            ? req.body.name.trim().slice(0, 80)
            : "Script";

    if (!source.trim()) {
        return res.status(400).json({
            ok: false,
            error: "Script is empty"
        });
    }

    const id = randomID(12);

    const db = readDB();

    db[id] = {
        id,
        name,
        source,
        createdAt: Date.now()
    };

    writeDB(db);

    res.json({
        ok: true,
        id,
        name,
        loader:
            `loadstring(game:HttpGet("${DOMAIN}/api/loader/${id}"))()`
    });
});

/*
=========================================================
LIST SCRIPT
=========================================================
*/

app.get("/api/scripts", (req, res) => {

    const db = readDB();

    const scripts = Object.values(db)
        .map(x => ({
            id: x.id,
            name: x.name,
            createdAt: x.createdAt,
            loader:
                `loadstring(game:HttpGet("${DOMAIN}/api/loader/${x.id}"))()`
        }))
        .reverse();

    res.json({
        ok: true,
        scripts
    });
});

/*
=========================================================
L1
/api/loader/:id

KHÔNG TRẢ SOURCE
TẠO SESSION
=========================================================
*/

app.get("/api/loader/:id", (req, res) => {
    return blocked(res);
});

app.post("/api/loader/:id", (req, res) => {

    const id = req.params.id;

    if (!validID(id)) {
        return blocked(res);
    }

    const db = readDB();

    if (!db[id]) {
        return blocked(res);
    }

    const session = randomID(32);
    const token = randomID(32);

    const expiresAt =
        Date.now() + 60 * 1000;

    db.__sessions ??= {};

    db.__sessions[session] = {
        scriptId: id,
        token,
        stage: 1,
        expiresAt,
        used: false
    };

    writeDB(db);

    res.json({
        ok: true,
        stage: 1,
        session,
        token,
        expiresAt,
        next:
            `${DOMAIN}/api/payload`
    });
});

/*
=========================================================
PAYLOAD

CHỈ CHO TOKEN HỢP LỆ
TOKEN DÙNG 1 LẦN
=========================================================
*/

app.get("/api/payload", (req, res) => {
    return blocked(res);
});

app.post("/api/payload", (req, res) => {

    const session =
        typeof req.body?.session === "string"
            ? req.body.session
            : "";

    const token =
        typeof req.body?.token === "string"
            ? req.body.token
            : "";

    if (!session || !token) {
        return blocked(res);
    }

    const db = readDB();

    const sessions = db.__sessions || {};
    const s = sessions[session];

    if (!s) {
        return blocked(res);
    }

    if (s.used) {
        delete sessions[session];
        writeDB(db);
        return blocked(res);
    }

    if (Date.now() > s.expiresAt) {
        delete sessions[session];
        writeDB(db);
        return blocked(res);
    }

    if (s.token !== token) {
        return blocked(res);
    }

    if (s.stage !== 1) {
        return blocked(res);
    }

    const script =
        db[s.scriptId];

    if (!script) {
        delete sessions[session];
        writeDB(db);
        return blocked(res);
    }

    /*
        Đánh dấu one-time trước khi gửi payload.
    */

    s.used = true;
    s.stage = 2;

    writeDB(db);

    /*
        Source chỉ xuất hiện ở bước cuối.
    */

    res.status(200).json({
        ok: true,
        stage: 2,
        scriptId: script.id,
        code: script.source
    });
});

/*
=========================================================
XÓA SESSION HẾT HẠN
=========================================================
*/

setInterval(() => {

    const db = readDB();

    if (!db.__sessions) {
        return;
    }

    const now = Date.now();

    for (const id of Object.keys(db.__sessions)) {

        const s =
            db.__sessions[id];

        if (
            s.used ||
            s.expiresAt <= now
        ) {
            delete db.__sessions[id];
        }
    }

    writeDB(db);

}, 30 * 1000);

/*
=========================================================
404
=========================================================
*/

app.use((req, res) => {
    return blocked(res);
});

app.listen(PORT, () => {

    console.log(
        "LEXINX PROTECT ONLINE"
    );

    console.log(
        `PORT: ${PORT}`
    );

    console.log(
        `DOMAIN: ${DOMAIN}`
    );
});
