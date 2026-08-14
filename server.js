const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const DOMAIN =
    process.env.DOMAIN ||
    "https://lexinx-protect.onrender.com";

const SECRET =
    process.env.PROTECT_SECRET ||
    "CHANGE_THIS_SECRET";

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "scripts.json");

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));


// ============================================================
// DATABASE
// ============================================================

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

function saveScripts(data) {
    fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(
            data,
            null,
            2
        ),
        "utf8"
    );
}


// ============================================================
// BLOCK PAGE
// ============================================================

function blockPage(res, reason = "LEXINX BLOCK") {

    let text = "";

    for (let i = 0; i < 1000; i++) {

        text +=
            i % 2 === 0
                ? "LEXINX PROTECT\n"
                : "BLOCKED BY LEXINX\n";
    }

    return res
        .status(403)
        .type("html")
        .send(`
<!doctype html>

<html>

<head>

<meta charset="UTF-8">

<title>LEXINX PROTECT</title>

<style>

html,
body {
    margin: 0;
    padding: 0;
    background: #050505;
    color: #ff3030;
    font-family: monospace;
}

body {
    padding: 30px;
}

h1 {
    font-size: 32px;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
}

</style>

</head>

<body>

<h1>BLOCKED BY LEXINX</h1>

<pre>${text}</pre>

</body>

</html>
        `);
}


// ============================================================
// BASIC BROWSER DETECTION
// ============================================================

function isBrowser(req) {

    const ua =
        String(
            req.headers["user-agent"] || ""
        ).toLowerCase();

    const browserPatterns = [
        "mozilla",
        "chrome",
        "safari",
        "firefox",
        "edg",
        "opera",
        "android browser"
    ];

    return browserPatterns.some(
        x => ua.includes(x)
    );
}


// ============================================================
// RANDOM ID
// ============================================================

function generateId() {

    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ" +
        "abcdefghijkmnopqrstuvwxyz" +
        "23456789";

    let id;

    const scripts =
        readScripts();

    do {

        id = "";

        for (let i = 0; i < 10; i++) {

            id += chars[
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];
        }

    } while (
        scripts.some(
            x => x.id === id
        )
    );

    return id;
}


// ============================================================
// HMAC
// ============================================================

function sign(value) {

    return crypto
        .createHmac(
            "sha256",
            SECRET
        )
        .update(value)
        .digest("hex");
}


function safeEqual(a, b) {

    if (
        typeof a !== "string" ||
        typeof b !== "string"
    ) {
        return false;
    }

    const aa =
        Buffer.from(a);

    const bb =
        Buffer.from(b);

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        aa,
        bb
    );
}


// ============================================================
// NONCE STORE
// ============================================================

const usedNonces = new Map();

function cleanupNonces() {

    const now =
        Date.now();

    for (
        const [nonce, time]
        of usedNonces
    ) {

        if (
            now - time >
            2 * 60 * 1000
        ) {
            usedNonces.delete(
                nonce
            );
        }
    }
}

setInterval(
    cleanupNonces,
    60 * 1000
);


// ============================================================
// HOME
// ============================================================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});


// ============================================================
// CREATE SCRIPT
// ============================================================

app.post(
    "/admin/create",
    (req, res) => {

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

        if (
            !name.trim() ||
            !payload.trim()
        ) {

            return res.status(400).json({
                ok: false,
                error: "Name and payload required"
            });
        }

        if (
            payload.length >
            1000000
        ) {

            return res.status(413).json({
                ok: false,
                error: "Payload too large"
            });
        }

        const scripts =
            readScripts();

        const id =
            generateId();

        const script = {

            id,

            name:
                name.trim(),

            payload,

            active: true,

            createdAt:
                new Date()
                    .toISOString()
        };

        scripts.push(
            script
        );

        saveScripts(
            scripts
        );

        res.json({

            ok: true,

            script: {

                id,

                name:
                    script.name,

                active: true,

                loader:
                    `loadstring(game:HttpGet("${DOMAIN}/api/${id}"))()`
            }
        });
    }
);


// ============================================================
// LIST
// ============================================================

app.get(
    "/admin/list",
    (req, res) => {

        const scripts =
            readScripts();

        res.json({

            ok: true,

            scripts:
                scripts.map(
                    script => ({

                        id:
                            script.id,

                        name:
                            script.name,

                        active:
                            script.active,

                        createdAt:
                            script.createdAt,

                        loader:
                            `loadstring(game:HttpGet("${DOMAIN}/api/${script.id}"))()`
                    })
                )
        });
    }
);


// ============================================================
// REVOKE
// ============================================================

app.post(
    "/admin/revoke/:id",
    (req, res) => {

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id
            );

        if (!script) {

            return res.status(404).json({
                ok: false,
                error: "Not found"
            });
        }

        script.active = false;

        saveScripts(
            scripts
        );

        res.json({
            ok: true
        });
    }
);


// ============================================================
// ENABLE
// ============================================================

app.post(
    "/admin/enable/:id",
    (req, res) => {

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id
            );

        if (!script) {

            return res.status(404).json({
                ok: false,
                error: "Not found"
            });
        }

        script.active = true;

        saveScripts(
            scripts
        );

        res.json({
            ok: true
        });
    }
);


// ============================================================
// DELETE
// ============================================================

app.delete(
    "/admin/delete/:id",
    (req, res) => {

        let scripts =
            readScripts();

        const old =
            scripts.length;

        scripts =
            scripts.filter(
                x =>
                    x.id !==
                    req.params.id
            );

        if (
            scripts.length ===
            old
        ) {

            return res.status(404).json({
                ok: false,
                error: "Not found"
            });
        }

        saveScripts(
            scripts
        );

        res.json({
            ok: true
        });
    }
);


// ============================================================
// AUTH / PAYLOAD
// ============================================================

app.post(
    "/api/execute/:id",
    (req, res) => {

        // Browser heuristic.
        if (isBrowser(req)) {
            return blockPage(res);
        }

        const {
            timestamp,
            nonce,
            signature
        } = req.body || {};

        if (
            !timestamp ||
            !nonce ||
            !signature
        ) {

            return blockPage(
                res,
                "INVALID REQUEST"
            );
        }

        const ts =
            Number(timestamp);

        if (
            !Number.isFinite(ts)
        ) {

            return blockPage(
                res,
                "INVALID TIME"
            );
        }

        // Real server time.
        const now =
            Math.floor(
                Date.now() / 1000
            );

        // 60 second window.
        if (
            Math.abs(
                now - ts
            ) > 60
        ) {

            return blockPage(
                res,
                "TIME CHECK FAILED"
            );
        }

        // Nonce replay protection.
        if (
            usedNonces.has(nonce)
        ) {

            return blockPage(
                res,
                "NONCE REPLAY"
            );
        }

        const expected =
            sign(
                `${req.params.id}:${ts}:${nonce}`
            );

        if (
            !safeEqual(
                signature,
                expected
            )
        ) {

            return blockPage(
                res,
                "SIGNATURE FAILED"
            );
        }

        usedNonces.set(
            nonce,
            Date.now()
        );

        const scripts =
            readScripts();

        const script =
            scripts.find(
                x =>
                    x.id ===
                    req.params.id
            );

        if (!script) {

            return blockPage(
                res,
                "INVALID LOADER"
            );
        }

        if (!script.active) {

            return blockPage(
                res,
                "SCRIPT REVOKED"
            );
        }

        // Payload is only returned after checks.
        return res
            .status(200)
            .type("text/plain")
            .send(
                script.payload
            );
    }
);


// ============================================================
// DIRECT API ACCESS = BLOCK
// ============================================================

app.get(
    "/api/:id",
    (req, res) => {

        return blockPage(
            res,
            "DIRECT ACCESS"
        );
    }
);


// ============================================================
// 404
// ============================================================

app.use(
    (req, res) => {

        return blockPage(
            res,
            "NOT FOUND"
        );
    }
);


// ============================================================
// START
// ============================================================

app.listen(
    PORT,
    () => {

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
    }
);
