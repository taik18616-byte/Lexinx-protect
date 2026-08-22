const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, "{}", "utf8");
}

function loadUsers() {
    try {
        const raw = fs.readFileSync(USERS_FILE, "utf8");
        return JSON.parse(raw || "{}");
    } catch {
        return {};
    }
}

function saveUsers(users) {
    const tmp = USERS_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(users, null, 2), "utf8");
    fs.renameSync(tmp, USERS_FILE);
}

function makeId() {
    return crypto.randomBytes(10).toString("hex");
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
    try {
        const actual = crypto.scryptSync(password, salt, 64).toString("hex");

        const a = Buffer.from(actual, "hex");
        const b = Buffer.from(expectedHash, "hex");

        return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

function cleanUsername(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "");
}

function validUsername(username) {
    return /^[a-z0-9_]{3,24}$/.test(username);
}

function validPassword(password) {
    return typeof password === "string" && password.length >= 6 && password.length <= 128;
}

/*
    =========================
       HEALTH CHECK
    =========================
*/

app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        service: "LEXINX Protect",
        time: new Date().toISOString()
    });
});

/*
    =========================
       REGISTER
    =========================
*/

app.post("/api/auth/register", (req, res) => {
    try {
        const username = cleanUsername(req.body.username);
        const password = String(req.body.password || "");

        if (!validUsername(username)) {
            return res.status(400).json({
                ok: false,
                error: "Tên tài khoản phải dài 3-24 ký tự và chỉ gồm a-z, 0-9, _."
            });
        }

        if (!validPassword(password)) {
            return res.status(400).json({
                ok: false,
                error: "Mật khẩu phải có ít nhất 6 ký tự."
            });
        }

        const users = loadUsers();

        if (users[username]) {
            return res.status(409).json({
                ok: false,
                error: "Tài khoản đã tồn tại."
            });
        }

        const id = makeId();
        const passwordData = hashPassword(password);

        users[username] = {
            id,
            username,
            passwordHash: passwordData.hash,
            passwordSalt: passwordData.salt,
            createdAt: new Date().toISOString()
        };

        saveUsers(users);

        return res.status(201).json({
            ok: true,
            message: "Tạo tài khoản thành công.",
            user: {
                id,
                username
            },
            redirect: `/acc/${encodeURIComponent(username)}/${id}`
        });

    } catch (err) {
        console.error("REGISTER ERROR:", err);

        return res.status(500).json({
            ok: false,
            error: "Server error khi tạo tài khoản."
        });
    }
});

/*
    =========================
       LOGIN
    =========================
*/

app.post("/api/auth/login", (req, res) => {
    try {
        const username = cleanUsername(req.body.username);
        const password = String(req.body.password || "");

        const users = loadUsers();
        const user = users[username];

        if (!user) {
            return res.status(401).json({
                ok: false,
                error: "Sai tên tài khoản hoặc mật khẩu."
            });
        }

        const valid = verifyPassword(
            password,
            user.passwordSalt,
            user.passwordHash
        );

        if (!valid) {
            return res.status(401).json({
                ok: false,
                error: "Sai tên tài khoản hoặc mật khẩu."
            });
        }

        return res.json({
            ok: true,
            message: "Đăng nhập thành công.",
            user: {
                id: user.id,
                username: user.username
            },
            redirect: `/acc/${encodeURIComponent(user.username)}/${user.id}`
        });

    } catch (err) {
        console.error("LOGIN ERROR:", err);

        return res.status(500).json({
            ok: false,
            error: "Server error khi đăng nhập."
        });
    }
});

/*
    =========================
       USER INFO
    =========================
*/

app.get("/api/auth/user/:username/:id", (req, res) => {
    const username = cleanUsername(req.params.username);
    const id = String(req.params.id);

    const users = loadUsers();
    const user = users[username];

    if (!user || user.id !== id) {
        return res.status(404).json({
            ok: false,
            error: "Không tìm thấy tài khoản."
        });
    }

    res.json({
        ok: true,
        user: {
            id: user.id,
            username: user.username,
            createdAt: user.createdAt
        }
    });
});

/*
    =========================
       PRIVATE ACCOUNT PAGE
    =========================
*/

app.get("/acc/:username/:id", (req, res) => {
    const username = cleanUsername(req.params.username);
    const id = String(req.params.id);

    const users = loadUsers();
    const user = users[username];

    if (!user || user.id !== id) {
        return res.status(404).send(`
            <!doctype html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>LEXINX - Not Found</title>
                <style>
                    body {
                        background:#050505;
                        color:white;
                        font-family:Arial,sans-serif;
                        display:flex;
                        justify-content:center;
                        align-items:center;
                        height:100vh;
                        margin:0;
                    }
                </style>
            </head>
            <body>
                <h2>Account not found</h2>
            </body>
            </html>
        `);
    }

    res.sendFile(path.join(__dirname, "public", "account.html"));
});

/*
    =========================
       SCRIPT API
       Dùng cho hệ thống loader
    =========================
*/

const scripts = Object.create(null);

/*
    Tạo script:
    POST /api/scripts

    Body:
    {
        "id": "abc123",
        "source": "print('hello')"
    }

    Lưu ý:
    source chỉ nằm server.
*/

app.post("/api/scripts", (req, res) => {
    const id = String(req.body.id || "").trim();
    const source = String(req.body.source || "");

    if (!id || !source) {
        return res.status(400).json({
            ok: false,
            error: "Thiếu id hoặc source."
        });
    }

    scripts[id] = {
        id,
        source,
        createdAt: new Date().toISOString()
    };

    res.json({
        ok: true,
        id,
        message: "Script saved."
    });
});

/*
    Kiểm tra script tồn tại.
    Endpoint này không trả source.
*/

app.get("/api/scripts/:id/exists", (req, res) => {
    const id = String(req.params.id);

    res.json({
        ok: true,
        exists: !!scripts[id]
    });
});

/*
    =========================
       LOADER BLOCK
    =========================

    Truy cập bằng browser bình thường:
       GET /api/loader/:id

    -> 403.

    Loader có thể gửi:
       X-LEXINX-LOADER: 1

    Nhưng header này không phải cơ chế bảo mật tuyệt đối;
    client có thể giả mạo header.
*/

app.get("/api/loader/:id", (req, res) => {
    const id = String(req.params.id);

    if (req.get("X-LEXINX-LOADER") !== "1") {
        return res.status(403).send("LEXINX BLOCK");
    }

    if (!scripts[id]) {
        return res.status(404).send("SCRIPT NOT FOUND");
    }

    /*
        Không trả source ở endpoint loader.
        Chỉ trả thông tin cần thiết.
    */

    res.json({
        ok: true,
        id,
        stage: 1,
        next: `/api/l2/${encodeURIComponent(id)}`
    });
});

/*
    =========================
       L2
    =========================
*/

app.post("/api/l2/:id", (req, res) => {
    const id = String(req.params.id);

    if (!scripts[id]) {
        return res.status(404).json({
            ok: false,
            error: "SCRIPT NOT FOUND"
        });
    }

    const session = crypto.randomBytes(24).toString("hex");

    res.json({
        ok: true,
        stage: 2,
        session,
        next: `/api/l3/${encodeURIComponent(id)}`
    });
});

/*
    =========================
       L3
    =========================
*/

app.post("/api/l3/:id", (req, res) => {
    const id = String(req.params.id);

    if (!scripts[id]) {
        return res.status(404).json({
            ok: false,
            error: "SCRIPT NOT FOUND"
        });
    }

    const token = crypto.randomBytes(32).toString("hex");

    res.json({
        ok: true,
        stage: 3,
        token,
        next: `/api/l4/${encodeURIComponent(id)}`
    });
});

/*
    =========================
       L4
    =========================
*/

app.post("/api/l4/:id", (req, res) => {
    const id = String(req.params.id);

    if (!scripts[id]) {
        return res.status(404).json({
            ok: false,
            error: "SCRIPT NOT FOUND"
        });
    }

    const challenge = crypto.randomBytes(32).toString("hex");

    res.json({
        ok: true,
        stage: 4,
        challenge,
        next: `/api/l5/${encodeURIComponent(id)}`
    });
});

/*
    =========================
       L5
    =========================

    Đây mới là endpoint trả source.

    Không expose source ở L2/L3/L4.
*/

app.post("/api/l5/:id", (req, res) => {
    const id = String(req.params.id);

    const script = scripts[id];

    if (!script) {
        return res.status(404).json({
            ok: false,
            error: "SCRIPT NOT FOUND"
        });
    }

    res.json({
        ok: true,
        stage: 5,
        code: script.source
    });
});

/*
    =========================
       404
    =========================
*/

app.use((req, res) => {
    res.status(404).send("LEXINX 404");
});

/*
    =========================
       ERROR HANDLER
    =========================
*/

app.use((err, req, res, next) => {
    console.error("SERVER ERROR:", err);

    res.status(500).json({
        ok: false,
        error: "Internal server error."
    });
});

app.listen(PORT, () => {
    console.log("=================================");
    console.log(" LEXINX Protect Server");
    console.log(" Port:", PORT);
    console.log("=================================");
});
