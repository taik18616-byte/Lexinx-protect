"use strict";

const crypto = require("crypto");

/*
    LEXINX SAFE OBFUSCATOR

    - Token-based processing
    - Local identifier renaming
    - String encoding
    - Numeric encoding
    - Minification
    - Random build marker
    - SHA256 integrity marker

    Không sử dụng VM/anti-debug.
*/

const KEYWORDS = new Set([
    "and", "break", "do", "else", "elseif",
    "end", "false", "for", "function", "goto",
    "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true",
    "until", "while"
]);

const BUILTINS = new Set([
    "assert", "collectgarbage", "dofile",
    "error", "getmetatable", "ipairs",
    "load", "loadfile", "next", "pairs",
    "pcall", "print", "rawequal", "rawget",
    "rawset", "select", "setmetatable",
    "tonumber", "tostring", "type",
    "xpcall", "coroutine", "debug", "io",
    "math", "os", "package", "string",
    "table", "utf8"
]);

function randomBytes(n = 8) {
    return crypto.randomBytes(n).toString("hex");
}

function randomName() {
    return `_L${randomBytes(5)}`;
}

function hash(text) {
    return crypto
        .createHash("sha256")
        .update(text, "utf8")
        .digest("hex");
}

/*
    Lexer nhỏ để không thay đổi text bên trong
    string/comment khi xử lý identifier.
*/

function tokenizeLua(source) {
    const tokens = [];

    let i = 0;

    while (i < source.length) {

        const c = source[i];

        /* whitespace */

        if (/\s/.test(c)) {

            let j = i + 1;

            while (
                j < source.length &&
                /\s/.test(source[j])
            ) {
                j++;
            }

            tokens.push({
                type: "ws",
                value: source.slice(i, j)
            });

            i = j;
            continue;
        }

        /* comment */

        if (
            c === "-" &&
            source[i + 1] === "-"
        ) {

            let j = i + 2;

            while (
                j < source.length &&
                source[j] !== "\n"
            ) {
                j++;
            }

            tokens.push({
                type: "comment",
                value: source.slice(i, j)
            });

            i = j;
            continue;
        }

        /* quoted string */

        if (
            c === '"' ||
            c === "'"
        ) {

            const quote = c;

            let j = i + 1;

            while (j < source.length) {

                if (
                    source[j] === "\\" &&
                    j + 1 < source.length
                ) {
                    j += 2;
                    continue;
                }

                if (source[j] === quote) {
                    j++;
                    break;
                }

                j++;
            }

            tokens.push({
                type: "string",
                value: source.slice(i, j)
            });

            i = j;
            continue;
        }

        /* identifier */

        if (
            /[A-Za-z_]/.test(c)
        ) {

            let j = i + 1;

            while (
                j < source.length &&
                /[A-Za-z0-9_]/.test(
                    source[j]
                )
            ) {
                j++;
            }

            const value =
                source.slice(i, j);

            tokens.push({
                type:
                    KEYWORDS.has(value)
                        ? "keyword"
                        : "identifier",
                value
            });

            i = j;
            continue;
        }

        /* number */

        if (/\d/.test(c)) {

            let j = i + 1;

            while (
                j < source.length &&
                /[0-9A-Fa-f.xX]/.test(
                    source[j]
                )
            ) {
                j++;
            }

            tokens.push({
                type: "number",
                value: source.slice(i, j)
            });

            i = j;
            continue;
        }

        tokens.push({
            type: "symbol",
            value: c
        });

        i++;
    }

    return tokens;
}

function decodeLuaString(value) {

    if (
        value.length < 2
    ) {
        return null;
    }

    const quote =
        value[0];

    if (
        value[value.length - 1] !== quote
    ) {
        return null;
    }

    let body =
        value.slice(
            1,
            -1
        );

    /*
       Chỉ encode các string đơn giản.
       Escape phức tạp được giữ nguyên.
    */

    if (
        /\\/.test(body)
    ) {
        return null;
    }

    return body;
}

function encodeString(body) {

    const key =
        crypto.randomInt(
            17,
            240
        );

    const bytes = [];

    for (
        let i = 0;
        i < body.length;
        i++
    ) {

        bytes.push(
            body.charCodeAt(i) ^
            key
        );
    }

    const values =
        bytes.join(",");

    return (
        `(function()local k=${key};` +
        `local t={${values}};` +
        `for i=1,#t do ` +
        `t[i]=bit32.bxor(t[i],k)` +
        `end;` +
        `return string.char(table.unpack(t))` +
        `end)()`
    );
}

function buildRenameMap(tokens) {

    const map = new Map();

    for (
        let i = 0;
        i < tokens.length;
        i++
    ) {

        const token =
            tokens[i];

        if (
            token.type !==
            "keyword" ||
            token.value !==
            "local"
        ) {
            continue;
        }

        let j = i + 1;

        while (
            j < tokens.length
        ) {

            const t =
                tokens[j];

            if (
                t.type === "ws" ||
                t.type === "comment"
            ) {
                j++;
                continue;
            }

            if (
                t.type ===
                "identifier"
            ) {

                if (
                    !BUILTINS.has(
                        t.value
                    )
                ) {

                    if (
                        !map.has(
                            t.value
                        )
                    ) {
                        map.set(
                            t.value,
                            randomName()
                        );
                    }
                }

                j++;
                continue;
            }

            break;
        }
    }

    return map;
}

function renameTokens(tokens) {

    const renameMap =
        buildRenameMap(
            tokens
        );

    return tokens.map(
        token => {

            if (
                token.type ===
                "identifier" &&
                renameMap.has(
                    token.value
                )
            ) {

                return {
                    ...token,
                    value:
                        renameMap.get(
                            token.value
                        )
                };
            }

            return token;
        }
    );
}

function transformStrings(tokens) {

    return tokens.map(
        token => {

            if (
                token.type !==
                "string"
            ) {
                return token;
            }

            const body =
                decodeLuaString(
                    token.value
                );

            if (
                body === null ||
                body.length < 4
            ) {
                return token;
            }

            return {
                type: "raw",
                value:
                    encodeString(
                        body
                    )
            };
        }
    );
}

function transformNumbers(tokens) {

    return tokens.map(
        token => {

            if (
                token.type !==
                "number"
            ) {
                return token;
            }

            /*
               Tránh thay đổi asset ID /
               hexadecimal / decimal quá nhỏ.
            */

            if (
                !/^\d{2,}$/.test(
                    token.value
                )
            ) {
                return token;
            }

            const n =
                Number(
                    token.value
                );

            if (
                !Number.isSafeInteger(n)
            ) {
                return token;
            }

            const key =
                crypto.randomInt(
                    10,
                    1000
                );

            const encoded =
                n ^ key;

            return {
                type: "raw",
                value:
                    `bit32.bxor(${encoded},${key})`
            };
        }
    );
}

function minifyTokens(tokens) {

    return tokens
        .filter(
            token =>
                token.type !==
                    "comment" &&
                token.type !==
                    "ws"
        )
        .map(
            token =>
                token.value
        )
        .join("");
}

function obfuscate(source) {

    if (
        typeof source !==
        "string" ||
        !source.trim()
    ) {
        throw new Error(
            "Empty Lua source"
        );
    }

    let tokens =
        tokenizeLua(
            source
        );

    tokens =
        renameTokens(
            tokens
        );

    tokens =
        transformStrings(
            tokens
        );

    tokens =
        transformNumbers(
            tokens
        );

    let output =
        minifyTokens(
            tokens
        );

    const build =
        randomBytes(8);

    const digest =
        hash(output);

    output =
        `-- LEXINX PROTECT\n` +
        `-- BUILD:${build}\n` +
        `-- HASH:${digest}\n` +
        output;

    return {
        source: output,
        build,
        hash: digest
    };
}

module.exports = {
    obfuscate
};
