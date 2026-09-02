//============================================================
// LEXINX PROTECT V5
// server.js
//============================================================

"use strict";

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "2mb" }));

//============================================================
// CONFIG
//============================================================

const PORT = process.env.PORT || 3000;
const BASE_URL =
    process.env.BASE_URL ||
    "https://lexinx-protect.onrender.com";

const DATABASE_URL = process.env.DATABASE_URL;

//============================================================
// DATABASE
//============================================================

const pool = new Pool({
    connectionString: DATABASE_URL,

    ssl:
        process.env.NODE_ENV === "production"
            ? { rejectUnauthorized: false }
            : false
});

//============================================================
// HELPERS
//============================================================

function randomScriptId(length = 20) {
    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    let out = "";

    while (out.length < length) {
        const bytes = crypto.randomBytes(length);

        for (const byte of bytes) {
            out += chars[byte % chars.length];

            if (out.length >= length) {
                break;
            }
        }
    }

    return out;
}

function sha256(data) {
    return crypto
        .createHash("sha256")
        .update(data)
        .digest();
}

function sha256Hex(data) {
    return crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");
}

function deriveVMKey(scriptId) {
    return sha256(
        Buffer.from(
            "LEXINX-V5-VM|" + scriptId,
            "utf8"
        )
    );
}

function xorBuffer(data, key) {
    const output = Buffer.alloc(data.length);

    for (let i = 0; i < data.length; i++) {
        output[i] =
            data[i] ^
            key[i % key.length];
    }

    return output;
}

//============================================================
// CUSTOM OPCODES
//============================================================

const OP = Object.freeze({
    NOP: 0x00,

    PUSH_STRING: 0x01,
    PUSH_NUMBER: 0x02,
    PUSH_BOOL: 0x03,
    PUSH_NIL: 0x04,

    GET_GLOBAL: 0x10,
    SET_GLOBAL: 0x11,

    ADD: 0x20,
    SUB: 0x21,
    MUL: 0x22,
    DIV: 0x23,

    CONCAT: 0x30,

    CALL_GLOBAL: 0x40,

    POP: 0x50,

    RETURN: 0xff
});

//============================================================
// BYTECODE WRITER
//============================================================

class BytecodeWriter {
    constructor() {
        this.parts = [];
    }

    byte(value) {
        this.parts.push(
            Buffer.from([value & 0xff])
        );
    }

    uint32(value) {
        const b = Buffer.alloc(4);

        b.writeUInt32BE(
            value >>> 0,
            0
        );

        this.parts.push(b);
    }

    number(value) {
        const b = Buffer.alloc(8);

        b.writeDoubleBE(
            Number(value),
            0
        );

        this.parts.push(b);
    }

    string(value) {
        const data = Buffer.from(
            String(value),
            "utf8"
        );

        this.uint32(data.length);
        this.parts.push(data);
    }

    result() {
        return Buffer.concat(this.parts);
    }
}

//============================================================
// SIMPLE LUA COMPILER
//
// Supported:
// print("hello")
// print('hello')
// return "hello"
// return 'hello'
// return 123
// return true
// return false
//============================================================

function compileLua(source) {
    if (typeof source !== "string") {
        throw new Error(
            "Source must be a string"
        );
    }

    const writer = new BytecodeWriter();

    const lines = source
        .replace(/\r/g, "")
        .split("\n");

    let compiledSomething = false;

    for (let rawLine of lines) {
        let line = rawLine.trim();

        if (!line) continue;

        if (line.startsWith("--")) {
            continue;
        }

        //====================================================
        // print("...")
        //====================================================

        let match =
            line.match(
                /^print\s*\(\s*"([\s\S]*)"\s*\)\s*$/
            );

        if (!match) {
            match =
                line.match(
                    /^print\s*\(\s*'([\s\S]*)'\s*\)\s*$/
                );
        }

        if (match) {
            writer.byte(OP.PUSH_STRING);
            writer.string(match[1]);

            writer.byte(OP.CALL_GLOBAL);
            writer.string("print");

            writer.byte(1);

            compiledSomething = true;
            continue;
        }

        //====================================================
        // return string
        //====================================================

        match =
            line.match(
                /^return\s*"([\s\S]*)"\s*$/
            );

        if (!match) {
            match =
                line.match(
                    /^return\s*'([\s\S]*)'\s*$/
                );
        }

        if (match) {
            writer.byte(OP.PUSH_STRING);
            writer.string(match[1]);

            writer.byte(OP.RETURN);

            compiledSomething = true;
            continue;
        }

        //====================================================
        // return number
        //====================================================

        match =
            line.match(
                /^return\s+(-?(?:\d+(?:\.\d*)?|\.\d+))\s*$/
            );

        if (match) {
            writer.byte(OP.PUSH_NUMBER);
            writer.number(
                Number(match[1])
            );

            writer.byte(OP.RETURN);

            compiledSomething = true;
            continue;
        }

        //====================================================
        // return boolean
        //====================================================

        match =
            line.match(
                /^return\s+(true|false)\s*$/
            );

        if (match) {
            writer.byte(OP.PUSH_BOOL);

            writer.byte(
                match[1] === "true"
                    ? 1
                    : 0
            );

            writer.byte(OP.RETURN);

            compiledSomething = true;
            continue;
        }

        throw new Error(
            "Unsupported Lua syntax: " +
            line
        );
    }

    if (!compiledSomething) {
        writer.byte(OP.PUSH_NIL);
        writer.byte(OP.RETURN);
    }

    return writer.result();
}

//============================================================
// LXVM PACKET
//
// 4 bytes  MAGIC
// 1 byte   VERSION
// 1 byte   FLAGS
// 4 bytes  PAYLOAD LENGTH
// 32 bytes SHA256(bytecode)
// payload  XOR encrypted bytecode
//============================================================

function packLXVM(bytecode, scriptId) {
    const magic = Buffer.from(
        "LXVM",
        "ascii"
    );

    const version = Buffer.from([1]);
    const flags = Buffer.from([1]);

    const length = Buffer.alloc(4);

    length.writeUInt32BE(
        bytecode.length,
        0
    );

    const checksum = sha256(bytecode);

    const key =
        deriveVMKey(scriptId);

    const encrypted =
        xorBuffer(bytecode, key);

    return Buffer.concat([
        magic,
        version,
        flags,
        length,
        checksum,
        encrypted
    ]);
}

//============================================================
// LAYERS
//============================================================

function makeL1(scriptId) {
    return `
local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local code = game:HttpGet(
    BASE_URL .. "/api/l2/" .. SCRIPT_ID
)

local fn, err = loadstring(code)

if not fn then
    error("LEXINX L1 ERROR: " .. tostring(err))
end

return fn()
`;
}

function makeL2(scriptId) {
    return `
local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local code = game:HttpGet(
    BASE_URL .. "/api/l3/" .. SCRIPT_ID
)

local fn, err = loadstring(code)

if not fn then
    error("LEXINX L2 ERROR: " .. tostring(err))
end

return fn()
`;
}

function makeL3(scriptId) {
    return `
local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local code = game:HttpGet(
    BASE_URL .. "/api/l4/" .. SCRIPT_ID
)

local fn, err = loadstring(code)

if not fn then
    error("LEXINX L3 ERROR: " .. tostring(err))
end

return fn()
`;
}

function makeL4(scriptId) {
    return `
local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local code = game:HttpGet(
    BASE_URL .. "/api/l5/" .. SCRIPT_ID
)

local fn, err = loadstring(code)

if not fn then
    error("LEXINX L4 ERROR: " .. tostring(err))
end

return fn()
`;
}

//============================================================
// L5
//
// Fetches LXVM packet.
// Parses header.
// XOR decrypts bytecode.
// Verifies SHA256.
// Executes supported custom VM instructions.
//============================================================

function makeL5(scriptId) {
    return `
local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local HttpService = game:GetService("HttpService")

local function xorBytes(data, key)
    local out = {}

    for i = 1, #data do
        local a = string.byte(data, i)
        local b = string.byte(
            key,
            ((i - 1) % #key) + 1
        )

        out[i] = string.char(
            bit32.bxor(a, b)
        )
    end

    return table.concat(out)
end

local function sha256(data)
    if crypt and crypt.hash then
        return crypt.hash(data, "sha256")
    end

    if syn and syn.crypt and syn.crypt.hash then
        return syn.crypt.hash(data, "sha256")
    end

    error(
        "LEXINX: SHA256 function unavailable"
    )
end

local function hexToBytes(hex)
    local out = {}

    for i = 1, #hex, 2 do
        out[#out + 1] =
            string.char(
                tonumber(
                    hex:sub(i, i + 1),
                    16
                )
            )
    end

    return table.concat(out)
end

local function deriveKey(id)
    return hexToBytes(
        sha256(
            "LEXINX-V5-VM|" .. id
        )
    )
end

local packet = game:HttpGet(
    BASE_URL .. "/api/vm/" .. SCRIPT_ID
)

assert(
    packet:sub(1, 4) == "LXVM",
    "LEXINX: invalid VM packet"
)

local version =
    string.byte(packet, 5)

local flags =
    string.byte(packet, 6)

local payloadLength =
    string.unpack(
        ">I4",
        packet,
        7
    )

local checksum =
    packet:sub(11, 42)

local encrypted =
    packet:sub(43)

assert(
    #encrypted == payloadLength,
    "LEXINX: payload length mismatch"
)

local key =
    deriveKey(SCRIPT_ID)

local bytecode =
    xorBytes(encrypted, key)

local actualHash =
    hexToBytes(
        sha256(bytecode)
    )

assert(
    actualHash == checksum,
    "LEXINX: bytecode integrity check failed"
)

--========================================================
-- CUSTOM VM
--========================================================

local VM = {}

function VM:readByte()
    local value =
        string.byte(
            self.code,
            self.pos
        )

    self.pos =
        self.pos + 1

    return value
end

function VM:readU32()
    local value

    value, self.pos =
        string.unpack(
            ">I4",
            self.code,
            self.pos
        )

    return value
end

function VM:readNumber()
    local value

    value, self.pos =
        string.unpack(
            ">d",
            self.code,
            self.pos
        )

    return value
end

function VM:readString()
    local length =
        self:readU32()

    local value =
        self.code:sub(
            self.pos,
            self.pos + length - 1
        )

    self.pos =
        self.pos + length

    return value
end

function VM:run(code)
    self.code = code
    self.pos = 1
    self.stack = {}
    self.globals = {}

    while self.pos <= #self.code do

        local op =
            self:readByte()

        -- NOP
        if op == 0x00 then

        -- PUSH_STRING
        elseif op == 0x01 then

            self.stack[#self.stack + 1] =
                self:readString()

        -- PUSH_NUMBER
        elseif op == 0x02 then

            self.stack[#self.stack + 1] =
                self:readNumber()

        -- PUSH_BOOL
        elseif op == 0x03 then

            local value =
                self:readByte()

            self.stack[#self.stack + 1] =
                value ~= 0

        -- PUSH_NIL
        elseif op == 0x04 then

            self.stack[#self.stack + 1] =
                nil

        -- GET_GLOBAL
        elseif op == 0x10 then

            local name =
                self:readString()

            self.stack[#self.stack + 1] =
                self.globals[name]

        -- SET_GLOBAL
        elseif op == 0x11 then

            local name =
                self:readString()

            local value =
                table.remove(
                    self.stack
                )

            self.globals[name] =
                value

        -- ADD
        elseif op == 0x20 then

            local b =
                table.remove(
                    self.stack
                )

            local a =
                table.remove(
                    self.stack
                )

            self.stack[#self.stack + 1] =
                a + b

        -- SUB
        elseif op == 0x21 then

            local b =
                table.remove(
                    self.stack
                )

            local a =
                table.remove(
                    self.stack
                )

            self.stack[#self.stack + 1] =
                a - b

        -- MUL
        elseif op == 0x22 then

            local b =
                table.remove(
                    self.stack
                )

            local a =
                table.remove(
                    self.stack
                )

            self.stack[#self.stack + 1] =
                a * b

        -- DIV
        elseif op == 0x23 then

            local b =
                table.remove(
                    self.stack
                )

            local a =
                table.remove(
                    self.stack
                )

            self.stack[#self.stack + 1] =
                a / b

        -- CONCAT
        elseif op == 0x30 then

            local b =
                table.remove(
                    self.stack
                )

            local a =
                table.remove(
                    self.stack
                )

            self.stack[#self.stack + 1] =
                tostring(a) ..
                tostring(b)

        -- CALL_GLOBAL
        elseif op == 0x40 then

            local name =
                self:readString()

            local argc =
                self:readByte()

            local args = {}

            for i = argc, 1, -1 do
                args[i] =
                    table.remove(
                        self.stack
                    )
            end

            if name == "print" then
                print(table.unpack(args))
            else
                error(
                    "LEXINX VM: unknown global " ..
                    tostring(name)
                )
            end

        -- POP
        elseif op == 0x50 then

            table.remove(
                self.stack
            )

        -- RETURN
        elseif op == 0xff then

            return table.remove(
                self.stack
            )

        else

            error(
                "LEXINX VM: unknown opcode 0x" ..
                string.format(
                    "%02X",
                    op
                )
            )
        end
    end
end

return VM:run(bytecode)
`;
}

//============================================================
// ROOT PAGE
// FIXES: Cannot GET /
//============================================================

app.get("/", (req, res) => {
    res.status(200).send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>LEXINX PROTECT V5</title>

<style>
body {
    margin: 0;
    background: #080808;
    color: #fff;
    font-family: Arial, sans-serif;
}

.container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
}

.box {
    padding: 40px;
}

h1 {
    font-size: 38px;
    margin-bottom: 10px;
}

.status {
    color: #55ff88;
    font-weight: bold;
}

.small {
    color: #888;
    margin-top: 20px;
}
</style>
</head>

<body>

<div class="container">
<div class="box">

<h1>LEXINX PROTECT V5</h1>

<p class="status">
● SERVER ONLINE
</p>

<p>
Protected VM / API Service
</p>

<p class="small">
LEXINX PROTECT
</p>

</div>
</div>

</body>
</html>
`);
});

//============================================================
// HEALTH
//============================================================

app.get("/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.json({
            success: true,
            status: "online",
            database: "connected"
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            status: "online",
            database: "error"
        });
    }
});

//============================================================
// CREATE SCRIPT
//============================================================

app.post("/api/scripts", async (req, res) => {
    try {
        const {
            name = "My Script",
            source = "",
            userId = null
        } = req.body;

        if (!source) {
            return res.status(400).json({
                success: false,
                error: "Source is required"
            });
        }

        let scriptId;

        while (true) {
            scriptId =
                randomScriptId(20);

            const check =
                await pool.query(
                    `SELECT 1
                     FROM scripts
                     WHERE script_id = $1
                     LIMIT 1`,
                    [scriptId]
                );

            if (check.rowCount === 0) {
                break;
            }
        }

        const bytecode =
            compileLua(source);

        const packet =
            packLXVM(
                bytecode,
                scriptId
            );

        await pool.query(
            `INSERT INTO scripts
            (
                user_id,
                script_id,
                name,
                source,
                bytecode,
                bytecode_version,
                vm_version,
                enabled
            )
            VALUES
            ($1,$2,$3,$4,$5,1,1,TRUE)`,
            [
                userId,
                scriptId,
                name,
                source,
                packet
            ]
        );

        res.json({
            success: true,

            script: {
                script_id: scriptId,
                name,
                bytecode_version: 1,
                vm_version: 1,

                loader:
                    BASE_URL +
                    "/loader/" +
                    scriptId
            }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

//============================================================
// GET SCRIPT INFO
//============================================================

app.get(
    "/api/scripts/:scriptId",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `SELECT
                        script_id,
                        name,
                        bytecode_version,
                        vm_version,
                        enabled,
                        created_at,
                        updated_at
                     FROM scripts
                     WHERE script_id = $1
                     LIMIT 1`,
                    [req.params.scriptId]
                );

            if (
                result.rowCount === 0
            ) {
                return res.status(404).json({
                    success: false,
                    error: "Script not found"
                });
            }

            res.json({
                success: true,
                script: result.rows[0]
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    }
);

//============================================================
// VM BINARY
//============================================================

app.get(
    "/api/vm/:scriptId",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `SELECT
                        bytecode,
                        enabled
                     FROM scripts
                     WHERE script_id = $1
                     LIMIT 1`,
                    [req.params.scriptId]
                );

            if (
                result.rowCount === 0
            ) {
                return res.status(404).send(
                    "LEXINX: Script not found"
                );
            }

            const row =
                result.rows[0];

            if (!row.enabled) {
                return res.status(403).send(
                    "LEXINX: Script disabled"
                );
            }

            const packet =
                row.bytecode;

            res.setHeader(
                "Content-Type",
                "application/octet-stream"
            );

            res.setHeader(
                "Cache-Control",
                "no-store"
            );

            res.send(packet);

        } catch (error) {

            console.error(error);

            res.status(500).send(
                "LEXINX: VM error"
            );
        }
    }
);

//============================================================
// L1
//============================================================

app.get(
    "/api/l1/:scriptId",
    async (req, res) => {

        const result =
            await pool.query(
                `SELECT enabled
                 FROM scripts
                 WHERE script_id = $1
                 LIMIT 1`,
                [req.params.scriptId]
            );

        if (
            result.rowCount === 0
        ) {
            return res.status(404).send(
                "LEXINX: Script not found"
            );
        }

        if (!result.rows[0].enabled) {
            return res.status(403).send(
                "LEXINX: Script disabled"
            );
        }

        res.type("text/plain");
        res.send(
            makeL1(req.params.scriptId)
        );
    }
);

//============================================================
// L2
//============================================================

app.get(
    "/api/l2/:scriptId",
    async (req, res) => {

        const result =
            await pool.query(
                `SELECT enabled
                 FROM scripts
                 WHERE script_id = $1
                 LIMIT 1`,
                [req.params.scriptId]
            );

        if (
            result.rowCount === 0
        ) {
            return res.status(404).send(
                "LEXINX: Script not found"
            );
        }

        if (!result.rows[0].enabled) {
            return res.status(403).send(
                "LEXINX: Script disabled"
            );
        }

        res.type("text/plain");
        res.send(
            makeL2(req.params.scriptId)
        );
    }
);

//============================================================
// L3
//============================================================

app.get(
    "/api/l3/:scriptId",
    async (req, res) => {

        const result =
            await pool.query(
                `SELECT enabled
                 FROM scripts
                 WHERE script_id = $1
                 LIMIT 1`,
                [req.params.scriptId]
            );

        if (
            result.rowCount === 0
        ) {
            return res.status(404).send(
                "LEXINX: Script not found"
            );
        }

        if (!result.rows[0].enabled) {
            return res.status(403).send(
                "LEXINX: Script disabled"
            );
        }

        res.type("text/plain");
        res.send(
            makeL3(req.params.scriptId)
        );
    }
);

//============================================================
// L4
//============================================================

app.get(
    "/api/l4/:scriptId",
    async (req, res) => {

        const result =
            await pool.query(
                `SELECT enabled
                 FROM scripts
                 WHERE script_id = $1
                 LIMIT 1`,
                [req.params.scriptId]
            );

        if (
            result.rowCount === 0
        ) {
            return res.status(404).send(
                "LEXINX: Script not found"
            );
        }

        if (!result.rows[0].enabled) {
            return res.status(403).send(
                "LEXINX: Script disabled"
            );
        }

        res.type("text/plain");
        res.send(
            makeL4(req.params.scriptId)
        );
    }
);

//============================================================
// L5
//============================================================

app.get(
    "/api/l5/:scriptId",
    async (req, res) => {

        const result =
            await pool.query(
                `SELECT enabled
                 FROM scripts
                 WHERE script_id = $1
                 LIMIT 1`,
                [req.params.scriptId]
            );

        if (
            result.rowCount === 0
        ) {
            return res.status(404).send(
                "LEXINX: Script not found"
            );
        }

        if (!result.rows[0].enabled) {
            return res.status(403).send(
                "LEXINX: Script disabled"
            );
        }

        res.type("text/plain");
        res.send(
            makeL5(req.params.scriptId)
        );
    }
);

//============================================================
// DYNAMIC LOADER
// No loader.lua file required
//============================================================

app.get(
    "/loader/:scriptId",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `SELECT enabled
                     FROM scripts
                     WHERE script_id = $1
                     LIMIT 1`,
                    [req.params.scriptId]
                );

            if (
                result.rowCount === 0
            ) {
                return res.status(404).send(
                    "LEXINX: Script not found"
                );
            }

            if (!result.rows[0].enabled) {
                return res.status(403).send(
                    "LEXINX: Script disabled"
                );
            }

            const scriptId =
                req.params.scriptId;

            const loader = `
local BASE_URL = ${JSON.stringify(BASE_URL)}
local SCRIPT_ID = ${JSON.stringify(scriptId)}

local l1 = game:HttpGet(
    BASE_URL .. "/api/l1/" .. SCRIPT_ID
)

local fn, err = loadstring(l1)

if not fn then
    error(
        "LEXINX LOADER ERROR: " ..
        tostring(err)
    )
end

return fn()
`;

            res.type("text/plain");
            res.send(loader);

        } catch (error) {

            console.error(error);

            res.status(500).send(
                "LEXINX: Loader error"
            );
        }
    }
);

//============================================================
// 404
//============================================================

app.use((req, res) => {

    res.status(404).json({
        success: false,
        error: "Not Found",
        path: req.path
    });

});

//============================================================
// ERROR HANDLER
//============================================================

app.use(
    (error, req, res, next) => {

        console.error(error);

        res.status(500).json({
            success: false,
            error: "Internal Server Error"
        });
    }
);

//============================================================
// START
//============================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "===================================="
        );

        console.log(
            "LEXINX PROTECT V5 ONLINE"
        );

        console.log(
            "PORT:",
            PORT
        );

        console.log(
            "BASE_URL:",
            BASE_URL
        );

        console.log(
            "===================================="
        );
    }
);
