const express = require("express");
const multer = require("multer");
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
    fs.writeFileSync(DB_FILE, "{}");
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({
    storage: multer.memoryStorage(),

    limits: {
        fileSize: 1024 * 1024
    },

    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();

        if (ext !== ".lua" && ext !== ".txt") {
            return cb(new Error("Only .lua and .txt files are allowed"));
        }

        cb(null, true);
    }
});

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
        JSON.stringify(db, null, 2)
    );
}

function createID() {
    return crypto
        .randomBytes(9)
        .toString("base64url");
}

function cleanName(name) {
    return name
        .replace(/[^a-zA-Z0-9._-]/g, "_")
        .slice(0, 100);
}

/*
==================================================
WEB
==================================================
*/

app.get("/", (req, res) => {
    res.type("html").send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>LEXINX PROTECT</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #050505;
    color: white;
    font-family: Arial, sans-serif;
}

.container {
    width: min(900px, 94%);
    margin: 50px auto;
}

.title {
    text-align: center;
    font-size: 42px;
    font-weight: bold;
}

.subtitle {
    text-align: center;
    color: #888;
    margin-bottom: 40px;
}

.card {
    background: #101010;
    border: 1px solid #252525;
    border-radius: 16px;
    padding: 25px;
    margin-bottom: 25px;
}

input[type=file] {
    width: 100%;
    padding: 15px;
    background: #080808;
    color: white;
    border: 1px solid #333;
    border-radius: 10px;
}

button {
    margin-top: 15px;
    padding: 12px 18px;
    border: 0;
    border-radius: 9px;
    background: white;
    color: black;
    cursor: pointer;
    font-weight: bold;
}

button:hover {
    opacity: .85;
}

.script {
    background: #080808;
    border: 1px solid #252525;
    padding: 18px;
    border-radius: 12px;
    margin-top: 15px;
}

.name {
    font-weight: bold;
    margin-bottom: 8px;
}

.id {
    color: #777;
    font-size: 13px;
}

.loader {
    margin-top: 10px;
    padding: 10px;
    background: #000;
    border-radius: 8px;
    overflow-x: auto;
    white-space: nowrap;
    font-family: monospace;
    color: #aaa;
}

.status {
    margin-top: 15px;
    color: #aaa;
}

</style>
</head>

<body>

<div class="container">

<div class="title">
LEXINX PROTECT
</div>

<div class="subtitle">
Lua / TXT Script Protection System
</div>

<div class="card">

<h2>Upload Script</h2>

<form id="uploadForm">

<input
    type="file"
    id="file"
    name="script"
    accept=".lua,.txt"
    required
>

<button type="submit">
Protect Script
</button>

</form>

<div id="status" class="status"></div>

</div>

<div class="card">

<h2>Protected Scripts</h2>

<div id="scripts">
Loading...
</div>

</div>

</div>

<script>

const form =
    document.getElementById("uploadForm");

const status =
    document.getElementById("status");

form.addEventListener("submit", async (e) => {

    e.preventDefault();

    const file =
        document.getElementById("file").files[0];

    if (!file) return;

    status.textContent =
        "Uploading...";

    const formData =
        new FormData();

    formData.append("script", file);

    try {

        const response =
            await fetch("/api/upload", {
                method: "POST",
                body: formData
            });

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "Upload failed"
            );
        }

        status.textContent =
            "Protected successfully: " +
            data.id;

        form.reset();

        loadScripts();

    } catch (err) {

        status.textContent =
            "Error: " + err.message;
    }
});

async function loadScripts() {

    const container =
        document.getElementById("scripts");

    try {

        const response =
            await fetch("/api/scripts");

        const scripts =
            await response.json();

        if (!scripts.length) {

            container.innerHTML =
                "<p>No scripts yet.</p>";

            return;
        }

        container.innerHTML = "";

        for (const script of scripts) {

            const div =
                document.createElement("div");

            div.className = "script";

            const loader =
                "loadstring(game:HttpGet(\"" +
                location.origin +
                "/api/" +
                script.id +
                "\"))()";

            div.innerHTML = `

                <div class="name">
                    ${escapeHTML(script.name)}
                </div>

                <div class="id">
                    ID: ${script.id}
                </div>

                <div class="loader">
                    ${escapeHTML(loader)}
                </div>

                <button>
                    Copy Loader
                </button>
            `;

            div.querySelector("button")
                .addEventListener("click", async () => {

                    await navigator.clipboard.writeText(
                        loader
                    );

                    div.querySelector("button")
                        .textContent =
                        "Copied!";
                });

            container.appendChild(div);
        }

    } catch {

        container.innerHTML =
            "<p>Failed to load scripts.</p>";
    }
}

function escapeHTML(str) {

    return String(str)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

loadScripts();

</script>

</body>
</html>
`);
});

/*
==================================================
UPLOAD
==================================================
*/

app.post(
    "/api/upload",
    upload.single("script"),
    (req, res) => {

        try {

            if (!req.file) {
                return res.status(400).json({
                    error: "No file uploaded"
                });
            }

            const source =
                req.file.buffer.toString("utf8");

            if (!source.trim()) {
                return res.status(400).json({
                    error: "Script is empty"
                });
            }

            const id = createID();

            const filename =
                id + ".lua";

            const filepath =
                path.join(
                    SCRIPT_DIR,
                    filename
                );

            fs.writeFileSync(
                filepath,
                source,
                "utf8"
            );

            const db = readDB();

            db[id] = {
                id,
                name: cleanName(
                    req.file.originalname
                ),
                filename,
                createdAt:
                    new Date().toISOString()
            };

            writeDB(db);

            res.json({
                ok: true,
                id,

                loader:
                    `loadstring(game:HttpGet("${req.protocol}://${req.get("host")}/api/${id}"))()`
            });

        } catch (err) {

            console.error(err);

            res.status(500).json({
                error: "Upload failed"
            });
        }
    }
);

/*
==================================================
SCRIPT LIST
==================================================
*/

app.get("/api/scripts", (req, res) => {

    const db = readDB();

    const result =
        Object.values(db)
        .sort(
            (a, b) =>
                new Date(b.createdAt) -
                new Date(a.createdAt)
        );

    res.json(result);
});

/*
==================================================
PAYLOAD ENDPOINT
==================================================
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

    const filepath =
        path.join(
            SCRIPT_DIR,
            script.filename
        );

    if (!fs.existsSync(filepath)) {

        return res
            .status(404)
            .type("text/plain")
            .send("Payload unavailable");
    }

    const payload =
        fs.readFileSync(
            filepath,
            "utf8"
        );

    res
        .status(200)
        .type("text/plain")
        .send(payload);
});

/*
==================================================
404
==================================================
*/

app.use((req, res) => {

    res
        .status(404)
        .type("text/plain")
        .send(
            "Blocked by LEXINX v50 protection"
        );
});

/*
==================================================
ERROR HANDLER
==================================================
*/

app.use((err, req, res, next) => {

    console.error(err);

    res.status(400).json({
        error: err.message
    });
});

/*
==================================================
START
==================================================
*/

app.listen(PORT, () => {

    console.log(
        "LEXINX PROTECT running on port " +
        PORT
    );
});
