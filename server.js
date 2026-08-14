const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA = path.join(__dirname, "data");
const PUBLIC = path.join(__dirname, "public");
const DB = path.join(DATA, "scripts.json");

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(PUBLIC, { recursive: true });

if (!fs.existsSync(DB)) {
    fs.writeFileSync(DB, "{}", "utf8");
}

app.use(express.json({ limit: "10mb" }));
app.use(express.static(PUBLIC));

function readDB() {
    try {
        return JSON.parse(fs.readFileSync(DB, "utf8"));
    } catch {
        return {};
    }
}

function writeDB(db) {
    fs.writeFileSync(DB, JSON.stringify(db, null, 2));
}

function makeID() {
    return crypto.randomBytes(12).toString("hex");
}

/*
 * Browser/direct URL blocker.
 * Đây chỉ là lớp lọc cơ bản, không phải
 * xác thực Roblox tuyệt đối.
 */
function looksLikeBrowser(req) {
    const ua = String(req.get("user-agent") || "").toLowerCase();

    return (
        ua.includes("mozilla") ||
        ua.includes("chrome") ||
        ua.includes("firefox") ||
        ua.includes("safari") ||
        ua.includes("edg")
    );
}

/* Web */

app.get("/", (req, res) => {
    res.sendFile(path.join(PUBLIC, "index.html"));
});

/* Tạo script */

app.post("/api/create", (req, res) => {
    const name =
        String(req.body?.name || "Script")
            .replace(/[^\w .-]/g, "_")
            .slice(0, 80);

    const source =
        typeof req.body?.source === "string"
            ? req.body.source
            : "";

    if (!source.trim()) {
        return res.status(400).json({
            ok: false,
            error: "Script rỗng"
        });
    }

    const id = makeID();
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
        name
    });
});

/* Danh sách */

app.get("/api/scripts", (req, res) => {
    const db = readDB();

    res.json({
        ok: true,
        scripts: Object.values(db).map(x => ({
            id: x.id,
            name: x.name,
            createdAt: x.createdAt
        }))
    });
});

/*
 * Payload endpoint.
 *
 * Mở trực tiếp bằng browser:
 * → Blocked
 *
 * Request không giống browser:
 * → source được trả về.
 */

app.get("/api/:id", (req, res) => {
    const id = req.params.id;
    const db = readDB();
    const script = db[id];

    if (!script) {
        return res
            .status(404)
            .type("text/plain")
            .send("Blocked by LEXINX v50 protection");
    }

    if (looksLikeBrowser(req)) {
        return res
            .status(403)
            .type("text/plain")
            .send("Blocked by LEXINX v50 protection");
    }

    res
        .type("text/plain")
        .set("Cache-Control", "no-store")
        .send(script.source);
});

/* Route không tồn tại */

app.use((req, res) => {
    res
        .status(404)
        .type("text/plain")
        .send("Blocked by LEXINX v50 protection");
});

app.listen(PORT, () => {
    console.log(
        `LEXINX PROTECT running on port ${PORT}`
    );
});
