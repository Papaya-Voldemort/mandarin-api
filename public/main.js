const API = window.location.origin;
const STORAGE_SESSION = "mandarin.session";
const STORAGE_KEY = "mandarin.apiKey";
const page = document.body.dataset.page || "dashboard";

const state = {
  session: localStorage.getItem(STORAGE_SESSION) || "",
  apiKey: localStorage.getItem(STORAGE_KEY) || "",
  user: null,
  keys: [],
};

const $ = (id) => document.getElementById(id);

const nodes = {
  sessionStatus: $("sessionStatus"),
  sessionToken: $("sessionToken"),
  email: $("email"),
  password: $("password"),
  signupBtn: $("signupBtn"),
  loginBtn: $("loginBtn"),
  logoutBtn: $("logoutBtn"),
  keyLabel: $("keyLabel"),
  createKeyBtn: $("createKeyBtn"),
  refreshKeysBtn: $("refreshKeysBtn"),
  newKeyStatus: $("newKeyStatus"),
  latestKey: $("latestKey"),
  apiKeyInput: $("apiKeyInput"),
  copyKeyBtn: $("copyKeyBtn"),
  translateText: $("translateText"),
  translateBtn: $("translateBtn"),
  translateOutput: $("translateOutput"),
  keysList: $("keysList"),
};

function setStatus(text, tone = "muted") {
  if (!nodes.sessionStatus) return;
  nodes.sessionStatus.textContent = text;
  nodes.sessionStatus.dataset.tone = tone;
}

function formatTime(value) {
  if (!value) return "Never";
  return new Date(value).toLocaleString();
}

function saveSession(token) {
  state.session = token;
  localStorage.setItem(STORAGE_SESSION, token);
  if (nodes.sessionToken) {
    nodes.sessionToken.value = token;
  }
}

function saveApiKey(key) {
  state.apiKey = key;
  localStorage.setItem(STORAGE_KEY, key);
  if (nodes.apiKeyInput) {
    nodes.apiKeyInput.value = key;
  }
  if (nodes.latestKey) {
    nodes.latestKey.value = key;
  }
}

function clearSession() {
  state.session = "";
  state.user = null;
  localStorage.removeItem(STORAGE_SESSION);
  if (nodes.sessionToken) {
    nodes.sessionToken.value = "";
  }
  if (nodes.keysList) {
    nodes.keysList.innerHTML = "";
  }
  if (nodes.newKeyStatus) {
    nodes.newKeyStatus.textContent = "No key created yet.";
  }
  setStatus("Not signed in.");
}

async function request(path, options = {}, auth = false) {
  const headers = new Headers(options.headers || {});
  if (auth && state.session) {
    headers.set("Authorization", `Bearer ${state.session}`);
  }

  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API}${path}`, {
    ...options,
    headers,
  });

  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const error = data?.error || `Request failed (${response.status})`;
    throw new Error(error);
  }

  return data;
}

function renderKeys(keys) {
  if (!nodes.keysList) return;
  state.keys = keys;
  nodes.keysList.innerHTML = "";

  if (!keys.length) {
    nodes.keysList.innerHTML = '<p class="status">No keys yet.</p>';
    return;
  }

  for (const key of keys) {
    const el = document.createElement("div");
    el.className = "key-item";

    const meta = document.createElement("div");
    meta.className = "key-meta";

    const titleWrap = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = key.label || `${key.key_prefix}…${key.key_last4}`;
    const subtitle = document.createElement("span");
    subtitle.textContent = `${key.revoked_at ? "Revoked" : "Active"} • Created ${formatTime(
      key.created_at
    )}`;
    titleWrap.append(title, subtitle);

    const revoke = document.createElement("button");
    revoke.className = "secondary";
    revoke.textContent = "Revoke";
    revoke.disabled = Boolean(key.revoked_at);
    revoke.addEventListener("click", async () => {
      await revokeKey(key.id);
    });

    meta.append(titleWrap, revoke);
    el.append(meta);

    const lastUsed = document.createElement("p");
    lastUsed.textContent = `Last used: ${formatTime(key.last_used)}`;
    const requests = document.createElement("p");
    requests.textContent = `Requests: ${key.requests ?? 0}`;

    el.append(lastUsed, requests);
    nodes.keysList.appendChild(el);
  }
}

async function syncAccount() {
  if (!state.session) {
    clearSession();
    return;
  }

  try {
    const data = await request("/api/me", {}, true);
    state.user = data.user;
    if (nodes.sessionToken) {
      nodes.sessionToken.value = state.session;
    }
    setStatus(`Signed in as ${data.user.email}.`, "success");
    if (nodes.keysList) {
      const keys = await request("/api/keys", {}, true);
      renderKeys(keys.keys || []);
    }
  } catch (error) {
    clearSession();
    setStatus(error.message, "danger");
  }
}

async function auth(type) {
  if (!nodes.email || !nodes.password) return;
  const email = nodes.email.value.trim();
  const password = nodes.password.value;
  const data = await request(`/api/${type}`, {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });

  saveSession(data.token);
  setStatus(`Signed in as ${data.user.email}.`, "success");
  await syncAccount();
  if (page === "login") {
    window.location.href = "/";
  }
}

async function createKey() {
  if (!nodes.keyLabel || !nodes.newKeyStatus) return;
  if (!state.session) {
    throw new Error("Sign in first");
  }

  const label = nodes.keyLabel.value.trim();
  const data = await request(
    "/api/keys",
    {
      method: "POST",
      body: JSON.stringify({ label }),
    },
    true
  );

  saveApiKey(data.apiKey);
  nodes.newKeyStatus.textContent = `Created ${data.label || "an unnamed key"} at ${formatTime(
    data.createdAt
  )}.`;
  await syncAccount();
}

async function revokeKey(id) {
  await request(`/api/keys/${id}/revoke`, { method: "POST" }, true);
  await syncAccount();
}

async function translate() {
  if (!nodes.apiKeyInput || !nodes.translateText || !nodes.translateOutput) return;
  const apiKey = nodes.apiKeyInput.value.trim();
  const text = nodes.translateText.value.trim();

  if (!apiKey) {
    throw new Error("Add an API key first");
  }

  const data = await request("/api/translate", {
    method: "POST",
    headers: {
      "x-api-key": apiKey,
    },
    body: JSON.stringify({ text }),
  });

  nodes.translateOutput.textContent = JSON.stringify(data, null, 2);
}

async function copyKey() {
  if (!nodes.apiKeyInput || !nodes.newKeyStatus) return;
  const value = nodes.apiKeyInput.value.trim();
  if (!value) {
    throw new Error("No key to copy");
  }

  await navigator.clipboard.writeText(value);
  nodes.newKeyStatus.textContent = "API key copied to clipboard.";
}

if (nodes.signupBtn) {
  nodes.signupBtn.addEventListener("click", () =>
    auth("register").catch((error) => {
      setStatus(error.message, "danger");
    })
  );
}

if (nodes.loginBtn) {
  nodes.loginBtn.addEventListener("click", () =>
    auth("login").catch((error) => {
      setStatus(error.message, "danger");
    })
  );
}

if (nodes.logoutBtn) {
  nodes.logoutBtn.addEventListener("click", async () => {
    if (!state.session) return;

    try {
      await request("/api/logout", { method: "POST" }, true);
    } finally {
      clearSession();
    }
  });
}

if (nodes.createKeyBtn) {
  nodes.createKeyBtn.addEventListener("click", () =>
    createKey().catch((error) => {
      if (nodes.newKeyStatus) {
        nodes.newKeyStatus.textContent = error.message;
      }
    })
  );
}

if (nodes.refreshKeysBtn) {
  nodes.refreshKeysBtn.addEventListener("click", () =>
    syncAccount().catch((error) => {
      setStatus(error.message, "danger");
    })
  );
}

if (nodes.translateBtn) {
  nodes.translateBtn.addEventListener("click", () =>
    translate().catch((error) => {
      if (nodes.translateOutput) {
        nodes.translateOutput.textContent = JSON.stringify({ error: error.message }, null, 2);
      }
    })
  );
}

if (nodes.copyKeyBtn) {
  nodes.copyKeyBtn.addEventListener("click", () =>
    copyKey().catch((error) => {
      if (nodes.newKeyStatus) {
        nodes.newKeyStatus.textContent = error.message;
      }
    })
  );
}

if (nodes.sessionToken) {
  nodes.sessionToken.value = state.session;
}
if (nodes.apiKeyInput) {
  nodes.apiKeyInput.value = state.apiKey;
}
if (nodes.latestKey) {
  nodes.latestKey.value = state.apiKey;
}

syncAccount();

if (page === "dashboard" && !state.session) {
  setStatus("Sign in to manage keys and run authenticated requests.");
}
