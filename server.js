"use strict";

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
    obfuscate
} = require("./obfuscator");

const app = express();

const PORT =
    process.env.PORT || 3000;

const DOMAIN =
    process.env.DOMAIN ||
    "https://Lexinx-protect-2.onrender.com";

const DATA_DIR =
    path.join(
        __dirname,
        "data"
    );

const DB_FILE =
    path.join(
        DATA_DIR,
        "scripts.json"
    );

const PUBLIC_DIR =
    path.join(
        __dirname,
        "public"
    );

fs.mkdirSync(
    DATA_DIR,
    {
        recursive: true
    }
);

fs.mkdirSync(
    PUBLIC_DIR,
    {
        recursive: true
    }
);

if (
    !fs.existsSync(
        DB_FILE
    )
) {

    fs.writeFileSync(
        DB_FILE,
        "{}",
        "utf8"
    );
}

app.use(
    express.json({
        limit: "25mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "25mb"
    })
);

app.use(
    express.static(
        PUBLIC_DIR
    )
);

function readDB() {

    try {

        return JSON.parse(
            fs.readFileSync(
                DB_FILE,
                "utf8"
            )
        );

    } catch {

        return {};
    }
}

function writeDB(db) {

    const temp =
        DB_FILE +
        ".tmp";

    fs.writeFileSync(
        temp,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );

    fs.renameSync(
        temp,
        DB_FILE
    );
}

function randomID() {

    return crypto
        .randomBytes(12)
        .toString("hex");
}

function randomToken() {

    return crypto
        .randomBytes(32)
        .toString("hex");
}

function cleanName(name) {

    return String(
        name || "Script"
    )
        .replace(
            /[^\w .-]/g,
            "_"
        )
        .slice(
            0,
            80
        );
}

function loaderFor(script) {

    const endpoint =
        `${DOMAIN}/api/${script.id}/${script.token}`;

    return (
        `loadstring(game:HttpGet("${endpoint}"))()`
    );
}

/*
========================================================
HOME
========================================================
*/

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                PUBLIC_DIR,
                "index.html"
            )
        );
    }
);

/*
========================================================
CREATE
========================================================
*/

app.post(
    "/api/create",
    (req, res) => {

        try {

            const source =
                typeof req.body.source ===
                "string"
                    ? req.body.source
                    : "";

            if (
                !source.trim()
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        error:
                            "Script is empty"
                    });
            }

            const name =
                cleanName(
                    req.body.name
                );

            const result =
                obfuscate(
                    source
                );

            const script = {

                id:
                    randomID(),

                token:
                    randomToken(),

                name,

                /*
                    SOURCE GỐC
                    Chỉ server sử dụng.
                */

                originalSource:
                    source,

                /*
                    SOURCE CLIENT NHẬN
                */

                protectedSource:
                    result.source,

                build:
                    result.build,

                hash:
                    result.hash,

                createdAt:
                    Date.now(),

                updatedAt:
                    Date.now()
            };

            const db =
                readDB();

            db[script.id] =
                script;

            writeDB(
                db
            );

            res.json({

                ok: true,

                id:
                    script.id,

                name:
                    script.name,

                build:
                    script.build,

                endpoint:
                    `${DOMAIN}/api/${script.id}/${script.token}`,

                loader:
                    loaderFor(
                        script
                    )
            });

        } catch (err) {

            console.error(err);

            res.status(500)
                .json({
                    ok: false,
                    error:
                        err.message
                });
        }
    }
);

/*
========================================================
LIST
========================================================
*/

app.get(
    "/api/scripts",
    (req, res) => {

        const db =
            readDB();

        const scripts =
            Object.values(db)
                .map(
                    script => ({

                        id:
                            script.id,

                        name:
                            script.name,

                        build:
                            script.build,

                        hash:
                            script.hash,

                        createdAt:
                            script.createdAt,

                        updatedAt:
                            script.updatedAt,

                        loader:
                            loaderFor(
                                script
                            )
                    })
                )
                .reverse();

        res.json({
            ok: true,
            scripts
        });
    }
);

/*
========================================================
GET ORIGINAL FOR EDIT
========================================================
*/

app.get(
    "/api/scripts/:id",
    (req, res) => {

        const db =
            readDB();

        const script =
            db[
                req.params.id
            ];

        if (!script) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found"
                });
        }

        res.json({

            ok: true,

            script: {

                id:
                    script.id,

                name:
                    script.name,

                source:
                    script.originalSource,

                build:
                    script.build
            }
        });
    }
);

/*
========================================================
EDIT + REBUILD
========================================================
*/

app.put(
    "/api/scripts/:id",
    (req, res) => {

        try {

            const db =
                readDB();

            const script =
                db[
                    req.params.id
                ];

            if (!script) {

                return res
                    .status(404)
                    .json({
                        ok: false,
                        error:
                            "Script not found"
                    });
            }

            const source =
                typeof req.body.source ===
                "string"
                    ? req.body.source
                    : "";

            if (
                !source.trim()
            ) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        error:
                            "Script is empty"
                    });
            }

            const result =
                obfuscate(
                    source
                );

            script.name =
                cleanName(
                    req.body.name ||
                    script.name
                );

            script.originalSource =
                source;

            script.protectedSource =
                result.source;

            script.build =
                result.build;

            script.hash =
                result.hash;

            script.updatedAt =
                Date.now();

            db[
                script.id
            ] = script;

            writeDB(
                db
            );

            res.json({

                ok: true,

                id:
                    script.id,

                build:
                    script.build,

                endpoint:
                    `${DOMAIN}/api/${script.id}/${script.token}`,

                loader:
                    loaderFor(
                        script
                    )
            });

        } catch (err) {

            console.error(err);

            res.status(500)
                .json({
                    ok: false,
                    error:
                        err.message
                });
        }
    }
);

/*
========================================================
DELETE
========================================================
*/

app.delete(
    "/api/scripts/:id",
    (req, res) => {

        const db =
            readDB();

        if (
            !db[
                req.params.id
            ]
        ) {

            return res
                .status(404)
                .json({
                    ok: false,
                    error:
                        "Script not found"
                });
        }

        delete db[
            req.params.id
        ];

        writeDB(
            db
        );

        res.json({
            ok: true
        });
    }
);

/*
========================================================
ROBLOX PAYLOAD
========================================================
*/

app.get(
    "/api/:id/:token",
    (req, res) => {

        const db =
            readDB();

        const script =
            db[
                req.params.id
            ];

        if (!script) {

            return res
                .status(404)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX"
                );
        }

        if (
            !crypto.timingSafeEqual(
                Buffer.from(
                    String(
                        req.params.token
                    )
                ),
                Buffer.from(
                    String(
                        script.token
                    )
                )
            )
        ) {

            return res
                .status(403)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX"
                );
        }

        res
            .status(200)
            .type("text/plain")
            .set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate, proxy-revalidate"
            )
            .set(
                "Pragma",
                "no-cache"
            )
            .set(
                "Expires",
                "0"
            )
            .set(
                "X-Content-Type-Options",
                "nosniff"
            )
            .send(
                script.protectedSource
            );
    }
);

/*
========================================================
404
========================================================
*/

app.use(
    (req, res) => {

        res
            .status(404)
            .type("text/plain")
            .send(
                "Blocked by LEXINX PROTECT"
            );
    }
);

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "================================"
        );

        console.log(
            "LEXINX PROTECT ONLINE"
        );

        console.log(
            `PORT: ${PORT}`
        );

        console.log(
            `DOMAIN: ${DOMAIN}`
        );

        console.log(
            "================================"
        );
    }
);
