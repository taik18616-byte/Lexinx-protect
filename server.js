"use strict";

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

app.use(express.json({
    limit: "2mb"
}));

const PORT = process.env.PORT || 3000;
const BASE_URL =
    process.env.BASE_URL ||
    "https://lexinx-protect.onrender.com";

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl:
        process.env.NODE_ENV === "production"
            ? { rejectUnauthorized: false }
            : false
});

// ============================================================
// DATABASE
// ============================================================

async function query(text, params = []) {
    return pool.query(text, params);
}

// ============================================================
// UTIL
// ============================================================

function randomId(length = 16) {
    return crypto
        .randomBytes(32)
        .toString("base64url")
        .replace(/[^a-zA-Z0-9]/g, "")
        .slice(0, length);
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
    const out = Buffer.alloc(data.length);

    for (let i = 0; i < data.length; i++) {
        out[i] =
            data[i] ^
            key[i % key.length];
    }

    return out;
}

// ============================================================
// BYTECODE
// ============================================================

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

    RETURN: 0xFF
});

// ============================================================
// BYTECODE WRITER
// ============================================================

class Writer {

    constructor() {
        this.parts = [];
    }

    u8(value) {
        const b = Buffer.alloc(1);

        b.writeUInt8(
            value & 0xFF,
            0
        );

        this.parts.push(b);
    }

    u32(value) {
        const b = Buffer.alloc(4);

        b.writeUInt32BE(
            value >>> 0,
            0
        );

        this.parts.push(b);
    }

    f64(value) {
        const b = Buffer.alloc(8);

        b.writeDoubleBE(
            Number(value),
            0
        );

        this.parts.push(b);
    }

    string(value) {
        const b =
            Buffer.from(
                String(value),
                "utf8"
            );

        this.u32(b.length);
        this.parts.push(b);
    }

    build() {
        return Buffer.concat(
            this.parts
        );
    }
}

// ============================================================
// LUA SUBSET COMPILER
// ============================================================

function compileSource(source) {

    if (typeof source !== "string") {
        throw new Error(
            "Source must be a string"
        );
    }

    const w = new Writer();

    const lines =
        source
            .replace(/\r/g, "")
            .split("\n");

    let returned = false;

    for (const rawLine of lines) {

        const line =
            rawLine.trim();

        if (!line || line.startsWith("--")) {
            continue;
        }

        // ----------------------------------------------------
        // print("...")
        // ----------------------------------------------------

        let match =
            line.match(
                /^print\s*\(\s*"([\s\S]*)"\s*\)\s*;?$/
            );

        if (!match) {
            match =
                line.match(
                    /^print\s*\(\s*'([\s\S]*)'\s*\)\s*;?$/
                );
        }

        if (match) {

            w.u8(OP.PUSH_STRING);
            w.string(match[1]);

            w.u8(OP.CALL_GLOBAL);
            w.string("print");
            w.u8(1);

            w.u8(OP.POP);

            continue;
        }

        // ----------------------------------------------------
        // return string
        // ----------------------------------------------------

        match =
            line.match(
                /^return\s+"([\s\S]*)"\s*;?$/
            );

        if (!match) {
            match =
                line.match(
                    /^return\s+'([\s\S]*)'\s*;?$/
                );
        }

        if (match) {

            w.u8(OP.PUSH_STRING);
            w.string(match[1]);

            w.u8(OP.RETURN);

            returned = true;

            break;
        }

        // ----------------------------------------------------
        // return number
        // ----------------------------------------------------

        match =
            line.match(
                /^return\s+(-?\d+(?:\.\d+)?)\s*;?$/
            );

        if (match) {

            w.u8(OP.PUSH_NUMBER);
            w.f64(
                Number(match[1])
            );

            w.u8(OP.RETURN);

            returned = true;

            break;
        }

        // ----------------------------------------------------
        // return true / false
        // ----------------------------------------------------

        match =
            line.match(
                /^return\s+(true|false)\s*;?$/
            );

        if (match) {

            w.u8(OP.PUSH_BOOL);

            w.u8(
                match[1] === "true"
                    ? 1
                    : 0
            );

            w.u8(OP.RETURN);

            returned = true;

            break;
        }

        // ----------------------------------------------------
        // unsupported
        // ----------------------------------------------------

        throw new Error(
            "Unsupported Lua syntax: " +
            line.slice(0, 120)
        );
    }

    if (!returned) {
        w.u8(OP.PUSH_NIL);
        w.u8(OP.RETURN);
    }

    return w.build();
}

// ============================================================
// LXVM PACKET
// ============================================================

function packLXVM(
    bytecode,
    scriptId
) {

    const key =
        deriveVMKey(scriptId);

    const encrypted =
        xorBuffer(
            bytecode,
            key
        );

    const checksum =
        sha256(bytecode);

    const header =
        Buffer.alloc(42);

    header.write(
        "LXVM",
        0,
        4,
        "ascii"
    );

    header.writeUInt8(
        1,
        4
    );

    header.writeUInt8(
        0,
        5
    );

    header.writeUInt32BE(
        encrypted.length,
        6
    );

    checksum.copy(
        header,
        10
    );

    return Buffer.concat([
        header,
        encrypted
    ]);
}

// ============================================================
// CREATE SCRIPT
// ============================================================

app.post(
    "/api/scripts",
    async (req, res) => {

        try {

            const {
                source = "",
                name = "My Script",
                userId = null
            } = req.body;

            if (
                typeof source !== "string"
            ) {
                return res.status(400).json({
                    error: "Invalid source"
                });
            }

            let scriptId;

            // Collision-safe ID generation
            for (;;) {

                const candidate =
                    randomId(16);

                const check =
                    await query(
                        `
                        SELECT 1
                        FROM scripts
                        WHERE script_id = $1
                        LIMIT 1
                        `,
                        [candidate]
                    );

                if (
                    check.rowCount === 0
                ) {
                    scriptId =
                        candidate;

                    break;
                }
            }

            const bytecode =
                compileSource(source);

            const packet =
                packLXVM(
                    bytecode,
                    scriptId
                );

            const result =
                await query(
                    `
                    INSERT INTO scripts
                    (
                        user_id,
                        script_id,
                        name,
                        source,
                        bytecode,
                        bytecode_version,
                        vm_version
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        1,
                        1
                    )
                    RETURNING
                        script_id,
                        name,
                        bytecode_version,
                        vm_version,
                        created_at
                    `,
                    [
                        userId,
                        scriptId,
                        name,
                        source,
                        packet
                    ]
                );

            return res.json({
                success: true,

                script: {
                    ...result.rows[0],

                    loader:
                        BASE_URL +
                        "/loader/" +
                        scriptId
                }
            });

        } catch (err) {

            console.error(
                "CREATE SCRIPT:",
                err
            );

            return res.status(500).json({
                error: err.message
            });
        }
    }
);

// ============================================================
// SCRIPT INFO
// ============================================================

app.get(
    "/api/scripts/:scriptId",
    async (req, res) => {

        try {

            const result =
                await query(
                    `
                    SELECT
                        script_id,
                        name,
                        bytecode_version,
                        vm_version,
                        enabled,
                        created_at,
                        updated_at
                    FROM scripts
                    WHERE script_id = $1
                    `,
                    [req.params.scriptId]
                );

            if (
                result.rowCount === 0
            ) {
                return res.status(404).json({
                    error: "Script not found"
                });
            }

            return res.json({
                success: true,
                script: result.rows[0]
            });

        } catch (err) {

            console.error(err);

            return res.status(500).json({
                error: "Database error"
            });
        }
    }
);

// ============================================================
// VM BINARY
// ============================================================

app.get(
    "/api/vm/:scriptId",
    async (req, res) => {

        const scriptId =
            req.params.scriptId;

        try {

            const result =
                await query(
                    `
                    SELECT
                        user_id,
                        bytecode,
                        enabled
                    FROM scripts
                    WHERE script_id = $1
                    `,
                    [scriptId]
                );

            if (
                result.rowCount === 0
            ) {

                return res.status(404).send(
                    "NOT_FOUND"
                );
            }

            const row =
                result.rows[0];

            if (!row.enabled) {

                return res.status(403).send(
                    "DISABLED"
                );
            }

            if (!row.bytecode) {

                return res.status(404).send(
                    "NO_BYTECODE"
                );
            }

            await query(
                `
                INSERT INTO script_access_logs
                (
                    user_id,
                    script_id,
                    ip_address,
                    success
                )
                VALUES
                (
                    $1,
                    $2,
                    $3,
                    TRUE
                )
                `,
                [
                    row.user_id,
                    scriptId,
                    req.ip
                ]
            );

            res.set(
                "Content-Type",
                "application/octet-stream"
            );

            res.set(
                "Cache-Control",
                "no-store"
            );

            return res.send(
                row.bytecode
            );

        } catch (err) {

            console.error(
                "VM:",
                err
            );

            return res.status(500).send(
                "SERVER_ERROR"
            );
        }
    }
);

// ============================================================
// LAYER GENERATOR
// ============================================================

function layerCode(
    number,
    next
) {

    return `
--// LEXINX PROTECT V5
--// L${number}

local BASE_URL =
    ${JSON.stringify(BASE_URL)}

local SCRIPT_ID =
    ${JSON.stringify(next.scriptId)}

local function get(url)
    return game:HttpGet(url)
end

local payload =
    get(
        BASE_URL ..
        "/api/${next.endpoint}/" ..
        SCRIPT_ID
    )

local fn, err =
    loadstring(payload)

if not fn then
    error(
        "LEXINX L${number} ERROR: " ..
        tostring(err)
    )
end

return fn()
`.trim();
}

// ============================================================
// L1
// ============================================================

app.get(
    "/api/l1/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const exists =
            await query(
                `
                SELECT script_id, enabled
                FROM scripts
                WHERE script_id = $1
                `,
                [id]
            );

        if (
            exists.rowCount === 0
        ) {
            return res.status(404).send(
                "NOT_FOUND"
            );
        }

        if (!exists.rows[0].enabled) {
            return res.status(403).send(
                "DISABLED"
            );
        }

        const code = `
--// LEXINX PROTECT V5
--// L1

local BASE_URL =
    ${JSON.stringify(BASE_URL)}

local SCRIPT_ID =
    ${JSON.stringify(id)}

local payload =
    game:HttpGet(
        BASE_URL ..
        "/api/l2/" ..
        SCRIPT_ID
    )

local fn, err =
    loadstring(payload)

if not fn then
    error(
        "LEXINX L1 ERROR: " ..
        tostring(err)
    )
end

return fn()
`.trim();

        res.type("text/plain").send(code);
    }
);

// ============================================================
// L2
// ============================================================

app.get(
    "/api/l2/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const code = `
--// LEXINX PROTECT V5
--// L2

local BASE_URL =
    ${JSON.stringify(BASE_URL)}

local SCRIPT_ID =
    ${JSON.stringify(id)}

local payload =
    game:HttpGet(
        BASE_URL ..
        "/api/l3/" ..
        SCRIPT_ID
    )

local fn, err =
    loadstring(payload)

if not fn then
    error(
        "LEXINX L2 ERROR: " ..
        tostring(err)
    )
end

return fn()
`.trim();

        res.type("text/plain").send(code);
    }
);

// ============================================================
// L3
// ============================================================

app.get(
    "/api/l3/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const code = `
--// LEXINX PROTECT V5
--// L3

local BASE_URL =
    ${JSON.stringify(BASE_URL)}

local SCRIPT_ID =
    ${JSON.stringify(id)}

local payload =
    game:HttpGet(
        BASE_URL ..
        "/api/l4/" ..
        SCRIPT_ID
    )

local fn, err =
    loadstring(payload)

if not fn then
    error(
        "LEXINX L3 ERROR: " ..
        tostring(err)
    )
end

return fn()
`.trim();

        res.type("text/plain").send(code);
    }
);

// ============================================================
// L4
// ============================================================

app.get(
    "/api/l4/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const code = `
--// LEXINX PROTECT V5
--// L4

local BASE_URL =
    ${JSON.stringify(BASE_URL)}

local SCRIPT_ID =
    ${JSON.stringify(id)}

local payload =
    game:HttpGet(
        BASE_URL ..
        "/api/l5/" ..
        SCRIPT_ID
    )

local fn, err =
    loadstring(payload)

if not fn then
    error(
        "LEXINX L4 ERROR: " ..
        tostring(err)
    )
end

return fn()
`.trim();

        res.type("text/plain").send(code);
    }
);

// ============================================================
// L5
// ============================================================

app.get(
    "/api/l5/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const code = `
--// LEXINX PROTECT V5
--// L5
--// BINARY VM STAGE

local BASE_URL =
    ${JSON.stringify(BASE_URL)}

local SCRIPT_ID =
    ${JSON.stringify(id)}

local function bxor(a, b)

    local result = 0
    local bit = 1

    while a > 0 or b > 0 do

        local aa = a % 2
        local bb = b % 2

        if aa ~= bb then
            result = result + bit
        end

        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end

    return result
end

local function base64Decode(data)

    local chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ..
        "abcdefghijklmnopqrstuvwxyz" ..
        "0123456789+/"

    data =
        data:gsub(
            "[^" .. chars .. "=]",
            ""
        )

    return (
        data:gsub(
            ".",
            function(x)

                if x == "=" then
                    return ""
                end

                local r = ""
                local f =
                    chars:find(
                        x,
                        1,
                        true
                    ) - 1

                for i = 6, 1, -1 do

                    if f % 2^i -
                       f % 2^(i-1) > 0 then

                        r = r .. "1"
                    else
                        r = r .. "0"
                    end
                end

                return r
            end
        )
        :gsub(
            "%d%d%d?%d?%d?%d?%d?%d?",
            function(x)

                if #x ~= 8 then
                    return ""
                end

                local c = 0

                for i = 1, 8 do
                    c = c * 2 +
                        (x:sub(i,i) == "1"
                            and 1
                            or 0)
                end

                return string.char(c)
            end
        )
    )
end

local function readU8(data, pos)

    return
        string.byte(
            data,
            pos
        ),
        pos + 1
end

local function readU32(data, pos)

    local a
    local b
    local c
    local d

    a, pos =
        readU8(data, pos)

    b, pos =
        readU8(data, pos)

    c, pos =
        readU8(data, pos)

    d, pos =
        readU8(data, pos)

    return
        a * 16777216 +
        b * 65536 +
        c * 256 +
        d,
        pos
end

local function readString(
    data,
    pos
)

    local len

    len, pos =
        readU32(
            data,
            pos
        )

    local value =
        data:sub(
            pos,
            pos + len - 1
        )

    return
        value,
        pos + len
end

-- =========================================================
-- GET BINARY
-- =========================================================

local raw =
    game:HttpGet(
        BASE_URL ..
        "/api/vm/" ..
        SCRIPT_ID
    )

-- Some environments may expose the
-- binary response as raw bytes.
-- This stage expects LXVM directly.

if raw:sub(1, 4) ~= "LXVM" then

    error(
        "LEXINX L5: invalid LXVM packet"
    )
end

-- =========================================================
-- HEADER
-- =========================================================

local version =
    string.byte(raw, 5)

if version ~= 1 then

    error(
        "LEXINX L5: unsupported VM version"
    )
end

local payloadLength

payloadLength =
    string.byte(raw, 7) * 16777216 +
    string.byte(raw, 8) * 65536 +
    string.byte(raw, 9) * 256 +
    string.byte(raw, 10)

local storedHash =
    raw:sub(11, 42)

local encrypted =
    raw:sub(
        43,
        42 + payloadLength
    )

if #encrypted ~= payloadLength then

    error(
        "LEXINX L5: invalid payload length"
    )
end

-- =========================================================
-- KEY
-- =========================================================
-- This prototype uses a deterministic
-- per-script key matching server.js.

local keySeed =
    "LEXINX-V5-VM|" ..
    SCRIPT_ID

-- SHA-256 implementation is required
-- here to exactly match server.js.
-- For production, replace this with
-- a compact audited SHA-256 implementation
-- compatible with the target executor.

local function sha256Bytes(input)

    -- Lua implementation intentionally
    -- omitted from the transport layer.
    -- The VM packet must be processed by
    -- an executor/runtime providing SHA-256,
    -- or this function must be replaced
    -- with an audited implementation.

    error(
        "LEXINX L5: SHA-256 runtime is required"
    )
end

local key =
    sha256Bytes(keySeed)

local decrypted =
    {}

for i = 1, #encrypted do

    local a =
        string.byte(
            encrypted,
            i
        )

    local b =
        string.byte(
            key,
            ((i - 1) % #key) + 1
        )

    decrypted[i] =
        string.char(
            bxor(a, b)
        )
end

local bytecode =
    table.concat(decrypted)

-- =========================================================
-- VM
-- =========================================================

local VM = {}

function VM.run(code)

    local pc = 1
    local stack = {}
    local globals = {}

    local function push(v)
        stack[#stack + 1] = v
    end

    local function pop()

        local v =
            stack[#stack]

        stack[#stack] = nil

        return v
    end

    while pc <= #code do

        local opcode

        opcode, pc =
            readU8(
                code,
                pc
            )

        if opcode == 0x00 then

        elseif opcode == 0x01 then

            local value

            value, pc =
                readString(
                    code,
                    pc
                )

            push(value)

        elseif opcode == 0x02 then

            error(
                "L5 VM: number decoder required"
            )

        elseif opcode == 0x03 then

            local value

            value, pc =
                readU8(
                    code,
                    pc
                )

            push(
                value ~= 0
            )

        elseif opcode == 0x04 then

            push(nil)

        elseif opcode == 0x10 then

            local name

            name, pc =
                readString(
                    code,
                    pc
                )

            push(
                globals[name]
            )

        elseif opcode == 0x11 then

            local name

            name, pc =
                readString(
                    code,
                    pc
                )

            globals[name] =
                pop()

        elseif opcode == 0x20 then

            local b = pop()
            local a = pop()

            push(a + b)

        elseif opcode == 0x21 then

            local b = pop()
            local a = pop()

            push(a - b)

        elseif opcode == 0x22 then

            local b = pop()
            local a = pop()

            push(a * b)

        elseif opcode == 0x23 then

            local b = pop()
            local a = pop()

            push(a / b)

        elseif opcode == 0x30 then

            local b = pop()
            local a = pop()

            push(
                tostring(a) ..
                tostring(b)
            )

        elseif opcode == 0x40 then

            local name

            name, pc =
                readString(
                    code,
                    pc
                )

            local argc

            argc, pc =
                readU8(
                    code,
                    pc
                )

            local args = {}

            for i = argc, 1, -1 do
                args[i] = pop()
            end

            if name == "print" then

                print(
                    table.unpack(args)
                )

                push(nil)

            else

                error(
                    "Unknown global call: " ..
                    tostring(name)
                )
            end

        elseif opcode == 0x50 then

            pop()

        elseif opcode == 0xFF then

            return pop()

        else

            error(
                "LEXINX VM: unknown opcode " ..
                tostring(opcode)
            )
        end
    end

    return nil
end

return VM.run(bytecode)
`.trim();

        res.type("text/plain").send(code);
    }
);

// ============================================================
// LOADER URL
// ============================================================

app.get(
    "/loader/:scriptId",
    async (req, res) => {

        const id =
            req.params.scriptId;

        const result =
            await query(
                `
                SELECT script_id, enabled
                FROM scripts
                WHERE script_id = $1
                `,
                [id]
            );

        if (
            result.rowCount === 0
        ) {
            return res.status(404).send(
                "NOT_FOUND"
            );
        }

        if (!result.rows[0].enabled) {
            return res.status(403).send(
                "DISABLED"
            );
        }

        const loader = `
local BASE_URL =
    ${JSON.stringify(BASE_URL)}

local SCRIPT_ID =
    ${JSON.stringify(id)}

local l1 =
    game:HttpGet(
        BASE_URL ..
        "/api/l1/" ..
        SCRIPT_ID
    )

local fn, err =
    loadstring(l1)

if not fn then
    error(
        "LEXINX LOADER ERROR: " ..
        tostring(err)
    )
end

return fn()
`.trim();

        res.type("text/plain").send(
            loader
        );
    }
);

// ============================================================
// HEALTH
// ============================================================

app.get(
    "/health",
    async (req, res) => {

        try {

            await query(
                "SELECT 1"
            );

            res.json({
                ok: true,
                service: "LEXINX PROTECT V5",
                database: "connected",
                vm: "LXVM v1"
            });

        } catch (err) {

            res.status(500).json({
                ok: false,
                database: "error"
            });
        }
    }
);

// ============================================================
// START
// ============================================================

app.listen(
    PORT,
    () => {

        console.log(
            "LEXINX PROTECT V5 running on port " +
            PORT
        );

    }
);
