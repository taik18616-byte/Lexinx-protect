const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect-2.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "scripts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.use(express.json({
    limit: "15mb"
}));

app.use(express.static(PUBLIC_DIR));

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

function createID() {
    return crypto
        .randomBytes(10)
        .toString("hex");
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

/*
    Trang web
*/

app.get("/", (req, res) => {
    res.sendFile(
        path.join(PUBLIC_DIR, "index.html")
    );
});

/*
    Tạo script
*/

app.post("/api/create", (req, res) => {

    const source =
        typeof req.body?.source === "string"
            ? req.body.source
            : "";

    if (!source.trim()) {
        return res.status(400).json({
            ok: false,
            error: "Script is empty"
        });
    }

    const name =
        cleanName(req.body?.name);

    const id = createID();

    const db = readDB();

    db[id] = {
        id,
        name,
        source,
        createdAt: Date.now()
    };

    writeDB(db);

    const endpoint =
        `${DOMAIN}/api/${id}`;

    const loader =
        `loadstring(game:HttpGet("${endpoint}"))()`;

    res.json({
        ok: true,
        id,
        name,
        endpoint,
        loader
    });
});

/*
    Danh sách script
*/

app.get("/api/scripts", (req, res) => {

    const db = readDB();

    const scripts =
        Object.values(db)
            .map(script => {

                const endpoint =
                    `${DOMAIN}/api/${script.id}`;

                return {
                    id: script.id,
                    name: script.name,
                    createdAt: script.createdAt,
                    endpoint,
                    loader:
                        `loadstring(game:HttpGet("${endpoint}"))()`
                };
            })
            .reverse();

    res.json({
        ok: true,
        scripts
    });
});

/*
    SERVER GỬI SOURCE THẲNG
*/

app.get("/api/:id", (req, res) => {

    const id = req.params.id;

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

    /*
        Không trả HTML.
        Endpoint này chỉ trả Lua source.
    */

    res
        .status(200)
        .type("text/plain")
        .set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate"
        )
        .set(
            "X-Content-Type-Options",
            "nosniff"
        )
        .send(script.source);
});

/*
    Route không tồn tại
*/

app.use((req, res) => {
    res
        .status(404)
        .type("text/plain")
        .send(
            "Blocked by LEXINX v50 protection"
        );
});

app.listen(PORT, () => {
    console.log(
        `LEXINX PROTECT running on port ${PORT}`
    );

    console.log(
        `Domain: ${DOMAIN}`
    );
});
