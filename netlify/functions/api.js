const crypto = require("crypto");
const { getStore } = require("@netlify/blobs");

const userStore = getStore("lexinx-users");
const sessionStore = getStore("lexinx-sessions");
const scriptStore = getStore("lexinx-scripts");

exports.handler = async (event) => {
    try {
        const path = event.path
            .replace(/^\/\.netlify\/functions\/api/, "")
            .replace(/^\/api/, "")
            .replace(/\/+/g, "/");

        if (
            event.httpMethod === "POST" &&
            path === "/auth/register"
        ) {
            let body;

            try {
                body = JSON.parse(event.body || "{}");
            } catch {
                return response(400, {
                    ok: false,
                    error: "Invalid JSON"
                });
            }

            const username =
                String(body.username || "").trim();

            const password =
                String(body.password || "");

            if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
                return response(400, {
                    ok: false,
                    error: "Invalid username"
                });
            }

            if (password.length < 6) {
                return response(400, {
                    ok: false,
                    error: "Password must contain at least 6 characters"
                });
            }

            const existing =
                await userStore.get(username, {
                    type: "json"
                });

            if (existing) {
                return response(409, {
                    ok: false,
                    error: "Username already exists"
                });
            }

            const salt =
                crypto.randomBytes(16).toString("hex");

            const passwordHash =
                crypto
                    .pbkdf2Sync(
                        password,
                        salt,
                        120000,
                        64,
                        "sha512"
                    )
                    .toString("hex");

            await userStore.setJSON(username, {
                username,
                salt,
                passwordHash,
                createdAt: Date.now()
            });

            const session =
                crypto.randomBytes(32).toString("hex");

            await sessionStore.setJSON(session, {
                username,
                expiresAt:
                    Date.now() +
                    30 * 24 * 60 * 60 * 1000
            });

            return response(
                201,
                {
                    ok: true,
                    username
                },
                {
                    "Set-Cookie":
                        `lexinx_session=${session}; ` +
                        `Path=/; HttpOnly; Secure; ` +
                        `SameSite=Lax; Max-Age=2592000`
                }
            );
        }

        if (
            event.httpMethod === "POST" &&
            path === "/auth/login"
        ) {
            let body;

            try {
                body = JSON.parse(event.body || "{}");
            } catch {
                return response(400, {
                    ok: false,
                    error: "Invalid JSON"
                });
            }

            const username =
                String(body.username || "").trim();

            const password =
                String(body.password || "");

            const user =
                await userStore.get(username, {
                    type: "json"
                });

            if (!user) {
                return response(401, {
                    ok: false,
                    error: "Invalid username or password"
                });
            }

            const hash =
                crypto
                    .pbkdf2Sync(
                        password,
                        user.salt,
                        120000,
                        64,
                        "sha512"
                    )
                    .toString("hex");

            if (hash !== user.passwordHash) {
                return response(401, {
                    ok: false,
                    error: "Invalid username or password"
                });
            }

            const session =
                crypto.randomBytes(32).toString("hex");

            await sessionStore.setJSON(session, {
                username,
                expiresAt:
                    Date.now() +
                    30 * 24 * 60 * 60 * 1000
            });

            return response(
                200,
                {
                    ok: true,
                    username
                },
                {
                    "Set-Cookie":
                        `lexinx_session=${session}; ` +
                        `Path=/; HttpOnly; Secure; ` +
                        `SameSite=Lax; Max-Age=2592000`
                }
            );
        }

        if (
            event.httpMethod === "GET" &&
            path === "/auth/me"
        ) {
            const session =
                getCookie(event);

            if (!session) {
                return response(401, {
                    ok: false,
                    authenticated: false
                });
            }

            const data =
                await sessionStore.get(session, {
                    type: "json"
                });

            if (
                !data ||
                data.expiresAt < Date.now()
            ) {
                return response(401, {
                    ok: false,
                    authenticated: false
                });
            }

            return response(200, {
                ok: true,
                authenticated: true,
                username: data.username
            });
        }

        return response(404, {
            ok: false,
            error: "LEXINX 404"
        });

    } catch (error) {
        console.error(
            "LEXINX FUNCTION ERROR:",
            error
        );

        return response(500, {
            ok: false,
            error: "Server error",
            detail:
                process.env.CONTEXT === "deploy-preview"
                    ? error.message
                    : undefined
        });
    }
};

function getCookie(event) {
    const cookies =
        event.headers?.cookie ||
        event.headers?.Cookie ||
        "";

    const match =
        cookies.match(
            /(?:^|;\s*)lexinx_session=([^;]+)/
        );

    return match
        ? decodeURIComponent(match[1])
        : null;
}

function response(status, body, headers = {}) {
    return {
        statusCode: status,
        headers: {
            "Content-Type":
                "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            ...headers
        },
        body: JSON.stringify(body)
    };
}
