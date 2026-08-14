const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "scripts.json");
const PUBLIC_DIR = path.join(__dirname, "public");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "{}", "utf8");
}

app.use(express.json({ limit: "25mb" }));
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
        .randomBytes(12)
        .toString("hex");
}

function cleanName(name) {
    return String(name || "Script")
        .replace(/[^\w .-]/g, "_")
        .slice(0, 80);
}

/*
====================================================
LAYER 2
====================================================
Server tự tạo Layer 2 cho từng ID.
*/

function createLayer2(id) {

    const endpoint =
        `${DOMAIN}/api/data/${id}`;

    return `local HttpService = game:GetService("HttpService")

local response

local ok, result = pcall(function()

    return request({
        Url = ${JSON.stringify(endpoint)},
        Method = "POST",

        Headers = {
            ["Content-Type"] = "application/json"
        },

        Body = "{}"
    })

end)

if not ok or not result then
    warn("[LEXINX] Request failed")
    return
end

response = result

if response.StatusCode ~= 200 then
    warn("[LEXINX] HTTP:", response.StatusCode)
    return
end

local decoded, data = pcall(function()
    return HttpService:JSONDecode(response.Body)
end)

if not decoded or type(data) ~= "table" then
    warn("[LEXINX] Invalid response")
    return
end

if data.ok ~= true then
    warn("[LEXINX] Server rejected request")
    return
end

if type(data.code) ~= "string" then
    warn("[LEXINX] Source missing")
    return
end

local fn, compileError = loadstring(data.code)

if not fn then
    warn("[LEXINX] Compile error:", compileError)
    return
end

local executed, runtimeError = pcall(fn)

if not executed then
    warn("[LEXINX] Runtime error:", runtimeError)
end
`;
}

/*
====================================================
LAYER 1
====================================================
Đây chính là loader ngắn mà người dùng copy.
*/

function createLayer1(id) {

    const endpoint =
        `${DOMAIN}/api/loader/${id}`;

    return `loadstring(game:HttpGet(${JSON.stringify(endpoint)}))()`;
}

/*
====================================================
HOME
====================================================
*/

app.get("/", (req, res) => {
    res.sendFile(
        path.join(PUBLIC_DIR, "index.html")
    );
});

/*
====================================================
CREATE
====================================================
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

    const id =
        createID();

    const db =
        readDB();

    db[id] = {
        id,
        name,
        source,
        createdAt: Date.now(),
        updatedAt: Date.now()
    };

    writeDB(db);

    const layer2 =
        createLayer2(id);

    const layer1 =
        createLayer1(id);

    res.json({
        ok: true,
        id,
        name,

        layer1,
        layer2,

        loader: layer1,

        endpoint:
            `${DOMAIN}/api/data/${id}`
    });
});

/*
====================================================
EDIT
====================================================
*/

app.post("/api/edit/:id", (req, res) => {

    const id =
        req.params.id;

    const db =
        readDB();

    if (!db[id]) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

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

    db[id].source =
        source;

    if (
        typeof req.body?.name === "string" &&
        req.body.name.trim()
    ) {
        db[id].name =
            cleanName(req.body.name);
    }

    db[id].updatedAt =
        Date.now();

    writeDB(db);

    const layer2 =
        createLayer2(id);

    const layer1 =
        createLayer1(id);

    res.json({
        ok: true,
        id,
        name: db[id].name,
        layer1,
        layer2,
        loader: layer1
    });
});

/*
====================================================
LIST
====================================================
*/

app.get("/api/scripts", (req, res) => {

    const db =
        readDB();

    const scripts =
        Object.values(db)
            .reverse()
            .map(script => {

                const layer2 =
                    createLayer2(
                        script.id
                    );

                const layer1 =
                    createLayer1(
                        script.id
                    );

                return {
                    id: script.id,
                    name: script.name,

                    createdAt:
                        script.createdAt,

                    updatedAt:
                        script.updatedAt,

                    layer1,
                    layer2,

                    loader: layer1
                };
            });

    res.json({
        ok: true,
        scripts
    });
});

/*
====================================================
SOURCE FOR EDIT
====================================================
*/

app.get("/api/source/:id", (req, res) => {

    const db =
        readDB();

    const script =
        db[req.params.id];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    res.json({
        ok: true,
        id: script.id,
        name: script.name,
        source: script.source
    });
});

/*
====================================================
DELETE
====================================================
*/

app.delete("/api/delete/:id", (req, res) => {

    const db =
        readDB();

    if (!db[req.params.id]) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    delete db[req.params.id];

    writeDB(db);

    res.json({
        ok: true
    });
});

/*
====================================================
LAYER 1 ENDPOINT
====================================================
GET /api/loader/:id

Server trả Layer 2.
*/

app.get("/api/loader/:id", (req, res) => {

    const db =
        readDB();

    if (!db[req.params.id]) {
        return res
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX BLOCK - Invalid ID"
            );
    }

    const layer2 =
        createLayer2(
            req.params.id
        );

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
        .send(layer2);
});

/*
====================================================
SOURCE ENDPOINT
====================================================
GET bị chặn.
POST mới trả source.
*/

app.get("/api/data/:id", (req, res) => {

    res
        .status(403)
        .type("text/plain")
        .send(
            "LEXINX BLOCK\n" +
            "Direct browser access is blocked."
        );
});

app.post("/api/data/:id", (req, res) => {

    const db =
        readDB();

    const script =
        db[req.params.id];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "Script not found"
        });
    }

    res
        .status(200)
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
        .json({
            ok: true,
            id: script.id,
            code: script.source
        });
});

/*
====================================================
404
====================================================
*/

app.use((req, res) => {

    res
        .status(404)
        .type("text/plain")
        .send(
            "Blocked by LEXINX PROTECT"
        );
});

/*
====================================================
START
====================================================
*/

app.listen(PORT, () => {

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

});
