const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const SCRIPT_DIR = path.join(DATA_DIR, "scripts");
const DB_FILE = path.join(DATA_DIR, "scripts.json");

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

function generateID() {
    const db = readDB();

    let id;

    do {
        id = crypto.randomBytes(12).toString("hex");
    } while (db[id]);

    return id;
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^a-zA-Z0-9._-]/g, "_")
        .slice(0, 100);
}

/* =========================
   HOME
========================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "index.html")
    );
});

/* =========================
   CREATE SCRIPT
========================= */

app.post("/api/create", (req, res) => {
    try {
        const code =
            typeof req.body.code === "string"
                ? req.body.code
                : "";

        const name =
            cleanName(
                req.body.name || "Script"
            );

        if (!code.trim()) {
            return res.status(400).json({
                ok: false,
                error: "Script is empty"
            });
        }

        const id = generateID();

        const filename = `${id}.lua`;

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
            createdAt: new Date().toISOString()
        };

        writeDB(db);

        const baseURL =
            `${req.protocol}://${req.get("host")}`;

        const loader =
            `loadstring(game:HttpGet("${baseURL}/api/${id}"))()`;

        res.json({
            ok: true,
            id,
            name,
            loader
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            ok: false,
            error: "Failed to create script"
        });
    }
});

/* =========================
   LIST SCRIPTS
========================= */

app.get("/api/scripts", (req, res) => {
    try {
        const db = readDB();

        const scripts =
            Object.values(db).sort(
                (a, b) =>
                    new Date(b.createdAt) -
                    new Date(a.createdAt)
            );

        res.json({
            ok: true,
            scripts
        });

    } catch {
        res.status(500).json({
            ok: false,
            error: "Failed to load scripts"
        });
    }
});

/* =========================
   PAYLOAD
========================= */

app.get("/api/:id", (req, res) => {

    const id = req.params.id;

    /*
       ID được server tạo ra luôn có
       24 ký tự hexadecimal.
    */

    if (!/^[a-f0-9]{24}$/.test(id)) {
        return res
            .status(404)
            .type("text/plain")
            .send(
                "Blocked by LEXINX v50 protection"
            );
    }

    const db = readDB();
    const script = db[id];

    if (!script) {
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
            script.filename
        );

    if (!fs.existsSync(file)) {
        return res
            .status(404)
            .type("text/plain")
            .send(
                "Blocked by LEXINX v50 protection"
            );
    }

    const payload =
        fs.readFileSync(file, "utf8");

    res
        .status(200)
        .type("text/plain")
        .set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        )
        .send(payload);
});

/* =========================
   DELETE
========================= */

app.delete("/api/scripts/:id", (req, res) => {

    const id = req.params.id;

    const db = readDB();
    const script = db[id];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    const file =
        path.join(
            SCRIPT_DIR,
            script.filename
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
   UNKNOWN ROUTES
========================= */

app.use((req, res) => {
    res
        .status(404)
        .type("text/plain")
        .send(
            "Blocked by LEXINX v50 protection"
        );
});

/* =========================
   START
========================= */

app.listen(PORT, () => {
    console.log(
        `LEXINX API running on port ${PORT}`
    );
});
