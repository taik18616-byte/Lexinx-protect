const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://lexinx-protect.onrender.com";

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "scripts.json");

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));


// ==================================================
// DATABASE
// ==================================================

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });
}

if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(
        DATA_FILE,
        "[]",
        "utf8"
    );
}

function readScripts() {
    try {
        return JSON.parse(
            fs.readFileSync(
                DATA_FILE,
                "utf8"
            )
        );
    } catch {
        return [];
    }
}

function saveScripts(scripts) {
    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(
            scripts,
            null,
            2
        ),
        "utf8"
    );
}


// ==================================================
// RANDOM ID
// ==================================================

function generateId() {

    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ" +
        "abcdefghijkmnopqrstuvwxyz" +
        "23456789";

    let id;

    do {

        id = "";

        for (let i = 0; i < 8; i++) {

            id += chars[
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];
        }

    } while (
        readScripts().some(
            script => script.id === id
        )
    );

    return id;
}


// ==================================================
// HOME
// ==================================================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});


// ==================================================
// CREATE
// ==================================================

app.post("/admin/create", (req, res) => {

    const {
        name,
        payload
    } = req.body || {};

    if (
        typeof name !== "string" ||
        typeof payload !== "string"
    ) {
        return res.status(400).json({
            ok: false,
            error: "Invalid input"
        });
    }

    if (!name.trim()) {
        return res.status(400).json({
            ok: false,
            error: "Script name required"
        });
    }

    if (!payload.trim()) {
        return res.status(400).json({
            ok: false,
            error: "Payload required"
        });
    }

    if (payload.length > 1000000) {
        return res.status(413).json({
            ok: false,
            error: "Payload too large"
        });
    }

    const scripts = readScripts();

    const id = generateId();

    const script = {
        id,
        name: name.trim(),
        payload,
        active: true,
        createdAt: new Date().toISOString()
    };

    scripts.push(script);

    saveScripts(scripts);

    const loader =
        `loadstring(game:HttpGet("${DOMAIN}/api/${id}"))()`;

    return res.json({
        ok: true,

        script: {
            id,
            name: script.name,
            active: true,
            createdAt: script.createdAt,
            loader
        }
    });
});


// ==================================================
// LIST
// ==================================================

app.get("/admin/list", (req, res) => {

    const scripts = readScripts();

    return res.json({
        ok: true,

        scripts: scripts.map(script => ({
            id: script.id,
            name: script.name,
            active: script.active,
            createdAt: script.createdAt,

            loader:
                `loadstring(game:HttpGet("${DOMAIN}/api/${script.id}"))()`
        }))
    });
});


// ==================================================
// REVOKE
// ==================================================

app.post(
    "/admin/revoke/:id",
    (req, res) => {

        const scripts = readScripts();

        const script = scripts.find(
            x => x.id === req.params.id
        );

        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        script.active = false;

        saveScripts(scripts);

        return res.json({
            ok: true
        });
    }
);


// ==================================================
// ENABLE
// ==================================================

app.post(
    "/admin/enable/:id",
    (req, res) => {

        const scripts = readScripts();

        const script = scripts.find(
            x => x.id === req.params.id
        );

        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        script.active = true;

        saveScripts(scripts);

        return res.json({
            ok: true
        });
    }
);


// ==================================================
// DELETE
// ==================================================

app.delete(
    "/admin/delete/:id",
    (req, res) => {

        let scripts = readScripts();

        const oldLength =
            scripts.length;

        scripts = scripts.filter(
            x => x.id !== req.params.id
        );

        if (
            scripts.length === oldLength
        ) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        saveScripts(scripts);

        return res.json({
            ok: true
        });
    }
);


// ==================================================
// PUBLIC LOADER API
// ==================================================

app.get("/api/:id", (req, res) => {

    const scripts = readScripts();

    const script = scripts.find(
        x => x.id === req.params.id
    );

    if (!script) {

        return res
            .status(404)
            .type("text/plain")
            .send(
                "LEXINX: Invalid loader"
            );
    }

    if (!script.active) {

        return res
            .status(403)
            .type("text/plain")
            .send(
                "Blocked by LEXINX"
            );
    }

    /*
     * Trả trực tiếp Lua payload.
     *
     * Browser cũng có thể đọc endpoint này.
     * Nếu muốn phân biệt browser/client,
     * cần thêm cơ chế xác thực riêng.
     */

    return res
        .status(200)
        .type("text/plain")
        .send(script.payload);
});


// ==================================================
// 404
// ==================================================

app.use((req, res) => {

    res.status(404).json({
        ok: false,
        error: "Not found"
    });
});


// ==================================================
// START
// ==================================================

app.listen(
    PORT,
    () => {

        console.log(
            "================================"
        );

        console.log(
            " LEXINX PROTECT ONLINE"
        );

        console.log(
            "================================"
        );

        console.log(
            "PORT:",
            PORT
        );

        console.log(
            "DOMAIN:",
            DOMAIN
        );
    }
);
