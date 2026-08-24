const crypto = require("crypto");
const { getStore } = require("@netlify/blobs");

const users = () => getStore("lexinx-users");
const sessions = () => getStore("lexinx-sessions");
const scripts = () => getStore("lexinx-scripts");

const json = (status, body, extra = {}) => ({
  statusCode: status,
  headers: {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extra
  },
  body: JSON.stringify(body)
});

const text = (status, body) => ({
  statusCode: status,
  headers: {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store"
  },
  body
});

function id(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function hashPassword(password, salt) {
  return crypto
    .pbkdf2Sync(password, salt, 120000, 64, "sha512")
    .toString("hex");
}

function parseBody(event) {
  try {
    return event.body ? JSON.parse(event.body) : {};
  } catch {
    return null;
  }
}

function getCookie(event, name) {
  const header =
    event.headers?.cookie ||
    event.headers?.Cookie ||
    "";

  const match = header.match(
    new RegExp(
      "(?:^|;\\s*)" +
      name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
      "=([^;]*)"
    )
  );

  return match ? decodeURIComponent(match[1]) : null;
}

function cookie(name, value, maxAge = 86400 * 30) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function loadUser(username) {
  return users().get(username, { type: "json" });
}

async function saveUser(user) {
  await users().setJSON(user.username, user);
}

async function requireSession(event) {
  const sid = getCookie(event, "lexinx_session");

  if (!sid) return null;

  const session = await sessions().get(sid, { type: "json" });

  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    await sessions().delete(sid);
    return null;
  }

  return session;
}

async function createSession(username) {
  const sid = id(32);

  await sessions().setJSON(sid, {
    username,
    createdAt: Date.now(),
    expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 30
  });

  return sid;
}

function validUsername(x) {
  return (
    typeof x === "string" &&
    /^[a-zA-Z0-9_-]{3,32}$/.test(x)
  );
}

function validPassword(x) {
  return typeof x === "string" && x.length >= 6 && x.length <= 200;
}

/* -------------------------------------------------------
   AUTH
------------------------------------------------------- */

async function register(event) {
  const body = parseBody(event);

  if (!body) {
    return json(400, {
      ok: false,
      error: "Invalid JSON"
    });
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!validUsername(username)) {
    return json(400, {
      ok: false,
      error: "Username must be 3-32 characters and contain only letters, numbers, _ or -."
    });
  }

  if (!validPassword(password)) {
    return json(400, {
      ok: false,
      error: "Password must contain at least 6 characters."
    });
  }

  const exists = await loadUser(username);

  if (exists) {
    return json(409, {
      ok: false,
      error: "Username already exists."
    });
  }

  const salt = id(16);

  const user = {
    username,
    passwordHash: hashPassword(password, salt),
    salt,
    createdAt: Date.now()
  };

  await saveUser(user);

  const sid = await createSession(username);

  return json(
    201,
    {
      ok: true,
      username
    },
    {
      "Set-Cookie": cookie("lexinx_session", sid)
    }
  );
}

async function login(event) {
  const body = parseBody(event);

  if (!body) {
    return json(400, {
      ok: false,
      error: "Invalid JSON"
    });
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  const user = await loadUser(username);

  if (!user) {
    return json(401, {
      ok: false,
      error: "Invalid username or password."
    });
  }

  const check = hashPassword(password, user.salt);

  if (
    !crypto.timingSafeEqual(
      Buffer.from(check, "hex"),
      Buffer.from(user.passwordHash, "hex")
    )
  ) {
    return json(401, {
      ok: false,
      error: "Invalid username or password."
    });
  }

  const sid = await createSession(username);

  return json(
    200,
    {
      ok: true,
      username
    },
    {
      "Set-Cookie": cookie("lexinx_session", sid)
    }
  );
}

async function logout(event) {
  const sid = getCookie(event, "lexinx_session");

  if (sid) {
    await sessions().delete(sid);
  }

  return json(
    200,
    { ok: true },
    {
      "Set-Cookie": cookie("lexinx_session", "", 0)
    }
  );
}

async function me(event) {
  const session = await requireSession(event);

  if (!session) {
    return json(401, {
      ok: false,
      authenticated: false
    });
  }

  return json(200, {
    ok: true,
    authenticated: true,
    username: session.username
  });
}

/* -------------------------------------------------------
   SCRIPT STORAGE
------------------------------------------------------- */

async function listScripts(event) {
  const session = await requireSession(event);

  if (!session) {
    return json(401, {
      ok: false,
      error: "Login required."
    });
  }

  const prefix = `${session.username}:`;

  const result = await scripts().list({
    prefix
  });

  const output = [];

  for (const item of result.blobs || []) {
    const data = await scripts().get(item.key, {
      type: "json"
    });

    if (data) {
      output.push({
        id: data.id,
        name: data.name,
        createdAt: data.createdAt,
        updatedAt: data.updatedAt
      });
    }
  }

  return json(200, {
    ok: true,
    scripts: output
  });
}

async function createScript(event) {
  const session = await requireSession(event);

  if (!session) {
    return json(401, {
      ok: false,
      error: "Login required."
    });
  }

  const body = parseBody(event);

  if (!body) {
    return json(400, {
      ok: false,
      error: "Invalid JSON"
    });
  }

  const name = String(body.name || "").trim();
  const source = String(body.source || "");

  if (!name || name.length > 100) {
    return json(400, {
      ok: false,
      error: "Invalid script name."
    });
  }

  if (!source || source.length > 1000000) {
    return json(400, {
      ok: false,
      error: "Invalid script source."
    });
  }

  const scriptId = id(16);

  const data = {
    id: scriptId,
    owner: session.username,
    name,
    source,
    createdAt: Date.now(),
    updatedAt: Date.now()
  };

  await scripts().setJSON(
    `${session.username}:${scriptId}`,
    data
  );

  return json(201, {
    ok: true,
    id: scriptId
  });
}

async function getScript(event, scriptId) {
  const session = await requireSession(event);

  if (!session) {
    return json(401, {
      ok: false,
      error: "Login required."
    });
  }

  const data = await scripts().get(
    `${session.username}:${scriptId}`,
    { type: "json" }
  );

  if (!data) {
    return json(404, {
      ok: false,
      error: "Script not found."
    });
  }

  return json(200, {
    ok: true,
    script: data
  });
}

async function editScript(event, scriptId) {
  const session = await requireSession(event);

  if (!session) {
    return json(401, {
      ok: false,
      error: "Login required."
    });
  }

  const key = `${session.username}:${scriptId}`;

  const data = await scripts().get(key, {
    type: "json"
  });

  if (!data) {
    return json(404, {
      ok: false,
      error: "Script not found."
    });
  }

  const body = parseBody(event);

  if (!body) {
    return json(400, {
      ok: false,
      error: "Invalid JSON"
    });
  }

  if (body.name !== undefined) {
    data.name = String(body.name).trim();
  }

  if (body.source !== undefined) {
    data.source = String(body.source);
  }

  data.updatedAt = Date.now();

  await scripts().setJSON(key, data);

  return json(200, {
    ok: true,
    script: data
  });
}

async function deleteScript(event, scriptId) {
  const session = await requireSession(event);

  if (!session) {
    return json(401, {
      ok: false,
      error: "Login required."
    });
  }

  const key = `${session.username}:${scriptId}`;

  const existing = await scripts().get(key, {
    type: "json"
  });

  if (!existing) {
    return json(404, {
      ok: false,
      error: "Script not found."
    });
  }

  await scripts().delete(key);

  return json(200, {
    ok: true
  });
}

/* -------------------------------------------------------
   LOADER
------------------------------------------------------- */

async function loader(event, scriptId) {
  const username = event.queryStringParameters?.user;

  /*
   * Loader does not expose source through the normal
   * account API. It uses a short-lived server session.
   */

  if (!scriptId) {
    return text(403, "LEXINX BLOCK");
  }

  const data = username
    ? await scripts().get(`${username}:${scriptId}`, {
        type: "json"
      })
    : null;

  if (!data) {
    return text(403, "LEXINX BLOCK");
  }

  /*
   * The loader endpoint returns a short-lived bootstrap
   * rather than the account-management API.
   */

  const token = id(24);

  await sessions().setJSON(`loader:${token}`, {
    type: "loader",
    owner: data.owner,
    scriptId,
    expiresAt: Date.now() + 60000
  });

  return json(200, {
    ok: true,
    stage: 2,
    token,
    next: "/api/l3"
  });
}

async function l3(event) {
  const body = parseBody(event);

  if (!body?.token) {
    return text(403, "LEXINX BLOCK");
  }

  const key = `loader:${body.token}`;

  const session = await sessions().get(key, {
    type: "json"
  });

  if (
    !session ||
    session.type !== "loader" ||
    session.expiresAt <= Date.now()
  ) {
    return text(403, "LEXINX BLOCK");
  }

  await sessions().setJSON(key, {
    ...session,
    stage: 3
  });

  return json(200, {
    ok: true,
    stage: 3,
    token: body.token,
    next: "/api/l4"
  });
}

async function l4(event) {
  const body = parseBody(event);

  if (!body?.token) {
    return text(403, "LEXINX BLOCK");
  }

  const key = `loader:${body.token}`;

  const session = await sessions().get(key, {
    type: "json"
  });

  if (
    !session ||
    session.stage !== 3 ||
    session.expiresAt <= Date.now()
  ) {
    return text(403, "LEXINX BLOCK");
  }

  await sessions().setJSON(key, {
    ...session,
    stage: 4
  });

  return json(200, {
    ok: true,
    stage: 4,
    token: body.token,
    next: "/api/l5"
  });
}

async function l5(event) {
  const body = parseBody(event);

  if (!body?.token) {
    return text(403, "LEXINX BLOCK");
  }

  const key = `loader:${body.token}`;

  const session = await sessions().get(key, {
    type: "json"
  });

  if (
    !session ||
    session.stage !== 4 ||
    session.expiresAt <= Date.now()
  ) {
    return text(403, "LEXINX BLOCK");
  }

  const script = await scripts().get(
    `${session.owner}:${session.scriptId}`,
    { type: "json" }
  );

  if (!script) {
    await sessions().delete(key);

    return text(403, "LEXINX BLOCK");
  }

  /*
   * One-time loader token.
   * Delete it before returning the payload.
   */

  await sessions().delete(key);

  return json(200, {
    ok: true,
    stage: 5,
    source: script.source
  });
}

/* -------------------------------------------------------
   ROUTER
------------------------------------------------------- */

exports.handler = async function(event) {
  try {
    const method = event.httpMethod;
    const path = event.path
      .replace(/^\/\.netlify\/functions\/api/, "")
      .replace(/^\/api/, "")
      .replace(/\/+/g, "/");

    if (method === "OPTIONS") {
      return {
        statusCode: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS"
        },
        body: ""
      };
    }

    if (method === "POST" && path === "/auth/register") {
      return await register(event);
    }

    if (method === "POST" && path === "/auth/login") {
      return await login(event);
    }

    if (method === "POST" && path === "/auth/logout") {
      return await logout(event);
    }

    if (method === "GET" && path === "/auth/me") {
      return await me(event);
    }

    if (method === "GET" && path === "/scripts") {
      return await listScripts(event);
    }

    if (method === "POST" && path === "/scripts") {
      return await createScript(event);
    }

    const scriptMatch =
      path.match(/^\/scripts\/([a-f0-9]+)$/i);

    if (scriptMatch) {
      const scriptId = scriptMatch[1];

      if (method === "GET") {
        return await getScript(event, scriptId);
      }

      if (method === "PATCH") {
        return await editScript(event, scriptId);
      }

      if (method === "DELETE") {
        return await deleteScript(event, scriptId);
      }
    }

    const loaderMatch =
      path.match(/^\/loader\/([a-f0-9]+)$/i);

    if (
      method === "GET" &&
      loaderMatch
    ) {
      return await loader(
        event,
        loaderMatch[1]
      );
    }

    if (
      method === "POST" &&
      path === "/l3"
    ) {
      return await l3(event);
    }

    if (
      method === "POST" &&
      path === "/l4"
    ) {
      return await l4(event);
    }

    if (
      method === "POST" &&
      path === "/l5"
    ) {
      return await l5(event);
    }

    return text(404, "LEXINX 404");
  } catch (err) {
    console.error(err);

    return json(500, {
      ok: false,
      error: "Internal server error."
    });
  }
};
