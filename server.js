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

app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({
    extended: true,
    limit: "3mb"
}));

app.use(express.static(
    path.join(__dirname, "public")
));

const upload = multer({
    storage: multer.memoryStorage(),

    limits: {
        fileSize: 2 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {

        const ext =
            path.extname(file.originalname)
                .toLowerCase();

        if (ext !== ".lua" && ext !== ".txt") {
            return cb(
                new Error(
                    "Only .lua and .txt files are allowed"
                )
            );
        }

        cb(null, true);
    }
});

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

    const db = readDB();

    let id;

    do {
        id = crypto
            .randomBytes(12)
            .toString("base64url");
    } while (db[id]);

    return id;
}

function cleanName(name) {

    return String(name)
        .replace(/[^a-zA-Z0-9._-]/g, "_")
        .slice(0, 100);
}

/*
==================================================
HOME
==================================================
*/

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

/*
==================================================
UPLOAD FILE
==================================================
*/

app.post(
    "/api/upload",
    upload.single("script"),
    (req, res) => {

        try {

            if (!req.file) {
                return res.status(400).json({
                    ok: false,
                    error: "No file uploaded"
                });
            }

            const source =
                req.file.buffer.toString("utf8");

            if (!source.trim()) {
                return res.status(400).json({
                    ok: false,
                    error: "Script is empty"
                });
            }

            const id = createID();

            const filename =
                id + ".lua";

            fs.writeFileSync(
                path.join(
                    SCRIPT_DIR,
                    filename
                ),
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

            const loader =
                `loadstring(game:HttpGet("${req.protocol}://${req.get("host")}/api/${id}"))()`;

            res.json({
                ok: true,
                id,
                name: db[id].name,
                loader
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                ok: false,
                error: error.message
            });
        }
    }
);

/*
==================================================
WRITE SCRIPT DIRECTLY
==================================================
*/

app.post(
    "/api/create",
    (req, res) => {

        try {

            const code =
                typeof req.body.code === "string"
                    ? req.body.code
                    : "";

            const name =
                typeof req.body.name === "string"
                    ? req.body.name
                    : "script.lua";

            if (!code.trim()) {

                return res.status(400).json({
                    ok: false,
                    error: "Script is empty"
                });
            }

            const id =
                createID();

            const filename =
                id + ".lua";

            fs.writeFileSync(
                path.join(
                    SCRIPT_DIR,
                    filename
                ),
                code,
                "utf8"
            );

            const db =
                readDB();

            db[id] = {
                id,
                name:
                    cleanName(name)
                        .endsWith(".lua")
                        ? cleanName(name)
                        : cleanName(name) + ".lua",
                filename,
                createdAt:
                    new Date().toISOString()
            };

            writeDB(db);

            const loader =
                `loadstring(game:HttpGet("${req.protocol}://${req.get("host")}/api/${id}"))()`;

            res.json({
                ok: true,
                id,
                name: db[id].name,
                loader
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                ok: false,
                error: error.message
            });
        }
    }
);

/*
==================================================
LIST
==================================================
*/

app.get(
    "/api/scripts",
    (req, res) => {

        const db =
            readDB();

        const scripts =
            Object.values(db)
                .sort(
                    (a, b) =>
                        new Date(b.createdAt) -
                        new Date(a.createdAt)
                );

        res.json({
            ok: true,
            scripts
        });
    }
);

/*
==================================================
GET PAYLOAD
==================================================
*/

app.get(
    "/api/:id",
    (req, res) => {

        const id =
            req.params.id;

        if (
            !/^[A-Za-z0-9_-]{10,40}$/.test(id)
        ) {
            return res
                .status(404)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX v50 protection"
                );
        }

        const db =
            readDB();

        const script =
            db[id];

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
                .send(
                    "Payload unavailable"
                );
        }

        const payload =
            fs.readFileSync(
                filepath,
                "utf8"
            );

        res
            .status(200)
            .set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            )
            .type("text/plain")
            .send(payload);
    }
);

/*
==================================================
DELETE
==================================================
*/

app.delete(
    "/api/scripts/:id",
    (req, res) => {

        const id =
            req.params.id;

        const db =
            readDB();

        const script =
            db[id];

        if (!script) {
            return res.status(404).json({
                ok: false,
                error: "Script not found"
            });
        }

        const filepath =
            path.join(
                SCRIPT_DIR,
                script.filename
            );

        try {

            if (fs.existsSync(filepath)) {
                fs.unlinkSync(filepath);
            }

            delete db[id];

            writeDB(db);

            res.json({
                ok: true
            });

        } catch (error) {

            res.status(500).json({
                ok: false,
                error: "Delete failed"
            });
        }
    }
);

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
ERROR
==================================================
*/

app.use((err, req, res, next) => {

    console.error(err);

    res.status(400).json({
        ok: false,
        error:
            err.message ||
            "Request error"
    });
});

/*
==================================================
START
==================================================
*/

app.listen(PORT, () => {

    console.log(
        "LEXINX PROTECT ONLINE"
    );

    console.log(
        "PORT:",
        PORT
    );
});
