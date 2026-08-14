const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const SCRIPT_DIR = path.join(DATA_DIR, "scripts");
const DB_FILE = path.join(DATA_DIR, "scripts.json");

fs.mkdirSync(SCRIPT_DIR, {
    recursive: true
});

if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
        DB_FILE,
        "{}",
        "utf8"
    );
}

app.use(express.json({
    limit: "15mb"
}));

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

/* =========================================
   DATABASE
========================================= */

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
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );
}

/* =========================================
   ID
========================================= */

function createID() {
    const db = readDB();

    let id;

    do {
        id =
            crypto
                .randomBytes(18)
                .toString("base64url");
    }
    while (db[id]);

    return id;
}

/* =========================================
   BASIC SOURCE PROTECTION
=========================================

   Đây là đóng gói source ở server.
   Không phải mã hóa tuyệt đối:
   code cuối cùng vẫn phải được
   giải mã/thực thi ở client.
========================================= */

function encodeLua(source) {

    const bytes =
        Buffer.from(
            source,
            "utf8"
        );

    const key =
        crypto.randomBytes(32);

    const output =
        Buffer.alloc(
            bytes.length
        );

    for (
        let i = 0;
        i < bytes.length;
        i++
    ) {
        output[i] =
            bytes[i] ^
            key[i % key.length];
    }

    return {
        data:
            output.toString("base64"),

        key:
            key.toString("base64")
    };
}

/* =========================================
   LUA WRAPPER
========================================= */

function makePayload(source) {

    const packed =
        encodeLua(source);

    const payload = `
-- LEXINX PROTECT
-- Generated payload

local function _bxor(a, b)
    local r = 0
    local p = 1

    while a > 0 or b > 0 do
        local aa = a % 2
        local bb = b % 2

        if aa ~= bb then
            r = r + p
        end

        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
    end

    return r
end

local function _b64(s)

    local chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    s = s:gsub(
        "[^" .. chars .. "=]",
        ""
    )

    local result = {}

    for i = 1, #s, 4 do

        local a =
            chars:find(
                s:sub(i, i),
                1,
                true
            )

        local b =
            chars:find(
                s:sub(i + 1, i + 1),
                1,
                true
            )

        local c =
            chars:find(
                s:sub(i + 2, i + 2),
                1,
                true
            )

        local d =
            chars:find(
                s:sub(i + 3, i + 3),
                1,
                true
            )

        a = (a or 1) - 1
        b = (b or 1) - 1
        c = (c or 1) - 1
        d = (d or 1) - 1

        local n1 =
            a * 4 +
            math.floor(b / 16)

        local n2 =
            (b % 16) * 16 +
            math.floor(c / 4)

        local n3 =
            (c % 4) * 64 +
            d

        result[#result + 1] =
            string.char(n1)

        if s:sub(i + 2, i + 2) ~= "=" then
            result[#result + 1] =
                string.char(n2)
        end

        if s:sub(i + 3, i + 3) ~= "=" then
            result[#result + 1] =
                string.char(n3)
        end
    end

    return table.concat(result)
end

local _data =
    _b64(${JSON.stringify(packed.data)})

local _key =
    _b64(${JSON.stringify(packed.key)})

local _out = {}

for i = 1, #_data do

    local a =
        string.byte(
            _data,
            i
        )

    local b =
        string.byte(
            _key,
            ((i - 1) % #_key) + 1
        )

    _out[i] =
        string.char(
            _bxor(a, b)
        )
end

local _source =
    table.concat(_out)

local _load =
    (getgenv and getgenv().loadstring)
    or loadstring

if type(_load) ~= "function" then
    warn("LEXINX: loadstring unavailable")
    return
end

local _fn, _err =
    _load(
        _source,
        "LEXINX_PAYLOAD"
    )

if not _fn then
    warn(
        "LEXINX COMPILE ERROR: "
        .. tostring(_err)
    )
    return
end

local _ok, _runtime =
    pcall(_fn)

if not _ok then
    warn(
        "LEXINX RUNTIME ERROR: "
        .. tostring(_runtime)
    )
end
`;

    return payload.trim();
}

/* =========================================
   HOME
========================================= */

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

/* =========================================
   CREATE
========================================= */

app.post(
    "/api/create",
    (req, res) => {

        try {

            const name =
                String(
                    req.body.name ||
                    "Script"
                )
                .replace(
                    /[^a-zA-Z0-9._ -]/g,
                    "_"
                )
                .slice(
                    0,
                    80
                );

            const source =
                String(
                    req.body.code ||
                    ""
                );

            if (!source.trim()) {

                return res
                    .status(400)
                    .json({
                        ok: false,
                        error:
                            "Script is empty"
                    });
            }

            const id =
                createID();

            const payload =
                makePayload(
                    source
                );

            const filename =
                id + ".lua";

            fs.writeFileSync(
                path.join(
                    SCRIPT_DIR,
                    filename
                ),
                payload,
                "utf8"
            );

            const db =
                readDB();

            db[id] = {
                id,
                name,
                filename,
                createdAt:
                    Date.now()
            };

            writeDB(db);

            const base =
                `${req.protocol}://${req.get("host")}`;

            const loader =
                `loadstring(game:HttpGet("${base}/api/${id}"))()`;

            res.json({
                ok: true,
                id,
                name,
                loader
            });

        } catch (err) {

            console.error(err);

            res
                .status(500)
                .json({
                    ok: false,
                    error:
                        "Failed to create loader"
                });
        }
    }
);

/* =========================================
   LIST
========================================= */

app.get(
    "/api/scripts",
    (req, res) => {

        const db =
            readDB();

        const scripts =
            Object.values(db)
                .sort(
                    (a, b) =>
                        b.createdAt -
                        a.createdAt
                );

        res.json({
            ok: true,
            scripts
        });
    }
);

/* =========================================
   PAYLOAD
========================================= */

app.get(
    "/api/:id",
    (req, res) => {

        const id =
            req.params.id;

        const db =
            readDB();

        const item =
            db[id];

        if (!item) {

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
                item.filename
            );

        if (
            !fs.existsSync(file)
        ) {

            return res
                .status(404)
                .type("text/plain")
                .send(
                    "Blocked by LEXINX v50 protection"
                );
        }

        const payload =
            fs.readFileSync(
                file,
                "utf8"
            );

        res
            .status(200)
            .type("text/plain")
            .set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            )
            .set(
                "Pragma",
                "no-cache"
            )
            .send(payload);
    }
);

/* =========================================
   DELETE
========================================= */

app.delete(
    "/api/scripts/:id",
    (req, res) => {

        const id =
            req.params.id;

        const db =
            readDB();

        const item =
            db[id];

        if (!item) {

            return res
                .status(404)
                .json({
                    ok: false
                });
        }

        const file =
            path.join(
                SCRIPT_DIR,
                item.filename
            );

        if (
            fs.existsSync(file)
        ) {
            fs.unlinkSync(file);
        }

        delete db[id];

        writeDB(db);

        res.json({
            ok: true
        });
    }
);

/* =========================================
   UNKNOWN
========================================= */

app.use(
    (req, res) => {

        res
            .status(404)
            .type("text/plain")
            .send(
                "Blocked by LEXINX v50 protection"
            );
    }
);

/* =========================================
   START
========================================= */

app.listen(
    PORT,
    () => {
        console.log(
            `LEXINX PROTECT running on port ${PORT}`
        );
    }
);
