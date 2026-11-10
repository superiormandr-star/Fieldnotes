// The caller keeps the existing owner authentication gate for googleRoute.
// The callback validates that same signed owner session from its encrypted state.
const TABLE = "superior_google_oauth";
const TABLE_SQL = "CREATE TABLE superior_google_oauth (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)";
const STATE_COOKIE = "__Secure-superior_google_oauth";
const CALLBACK_PATH = "/api/google/callback";
const SCOPE = "https://www.googleapis.com/auth/drive.file";
const FOLDER_NAME = "Superior Command Center — Private Backups";
const PURPOSE = "superior-command-center-private-backups";
const STATE_LIFETIME = 600000;
const NOTICE = "Your Google Drive connection is saved securely for this Command Center.";
const SETUP_NOTICE = "Google Drive secure setup is incomplete. Google OAuth credentials and a dedicated encryption key are required before connecting.";
const enc = new TextEncoder();
const dec = new TextDecoder();

class DriveError extends Error {
  constructor(message, status = 502, reconnect = false, ambiguous = false) {
    super(message);
    this.status = status;
    this.reconnect = reconnect;
    this.ambiguous = ambiguous;
  }
}
const problem = (message, status = 502, reconnect = false, ambiguous = false) => new DriveError(message, status, reconnect, ambiguous);
const stamp = () => new Date().toISOString();
const encryptionKeyReady = (env) => typeof env.GOOGLE_OAUTH_ENCRYPTION_SECRET === "string" && env.GOOGLE_OAUTH_ENCRYPTION_SECRET.trim().length >= 32;
const configured = (env) => typeof env.GOOGLE_CLIENT_ID === "string" && !!env.GOOGLE_CLIENT_ID.trim() && typeof env.GOOGLE_CLIENT_SECRET === "string" && !!env.GOOGLE_CLIENT_SECRET.trim() && encryptionKeyReady(env);
const publicError = (error) => error instanceof DriveError ? error.message : "Google Drive backup could not be completed. Try again.";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: {
    "Content-Type": "application/json; charset=utf-8", "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"
  } });
}
function redirect(location, cookie) {
  const headers = new Headers({ Location: location, "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer" });
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 303, headers });
}
function stateCookie(value, maxAge = 600) {
  return `${STATE_COOKIE}=${value}; Path=${CALLBACK_PATH}; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}
function cookie(req, name) {
  const matches = (req.headers.get("cookie") || "").split(";").map((part) => part.trim()).filter((part) => part.startsWith(name + "="));
  return matches.length === 1 ? matches[0].slice(name.length + 1) : "";
}
function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unbase64url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw problem("Google Drive secure connection data is invalid. Reconnect Google Drive.", 409);
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}
const random = () => base64url(crypto.getRandomValues(new Uint8Array(32)));
async function constantEqual(a, b) {
  const [x, y] = await Promise.all([a, b].map((s) => crypto.subtle.digest("SHA-256", enc.encode(s))));
  const left = new Uint8Array(x), right = new Uint8Array(y);
  let different = 0;
  for (let i = 0; i < left.length; i++) different |= left[i] ^ right[i];
  return different === 0;
}
function requireConfig(env) {
  if (!configured(env)) throw problem("Google Drive secure setup is incomplete. Google OAuth credentials and a dedicated encryption key are required.", 503);
}
async function cipherKey(env, origin, purpose) {
  if (!encryptionKeyReady(env)) throw problem("Google Drive secure storage configuration is incomplete.", 503);
  const material = await crypto.subtle.importKey("raw", enc.encode(env.GOOGLE_OAUTH_ENCRYPTION_SECRET), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("superior-command-center/google-oauth/v1"), info: enc.encode(`${purpose}\n${origin}`) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(value, env, origin, purpose) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`superior-google-oauth/v1\n${purpose}\n${origin}`) }, await cipherKey(env, origin, purpose), enc.encode(JSON.stringify(value))));
  return "v1." + base64url(iv) + "." + base64url(ciphertext);
}
async function open(value, env, origin, purpose) {
  try {
    if (typeof value !== "string" || value.length > 20000) throw Error();
    const parts = value.split(".");
    if (parts.length !== 3 || parts[0] !== "v1") throw Error();
    const iv = unbase64url(parts[1]);
    if (iv.length !== 12) throw Error();
    const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`superior-google-oauth/v1\n${purpose}\n${origin}`) }, await cipherKey(env, origin, purpose), unbase64url(parts[2]));
    const data = JSON.parse(dec.decode(clear));
    if (!data || typeof data !== "object" || Array.isArray(data)) throw Error();
    return data;
  } catch {
    throw problem("Google Drive secure connection data is invalid. Reconnect Google Drive.", 409);
  }
}

// A collision must never turn an unrelated table into OAuth storage. Status only
// inspects; creation is limited to an explicitly authenticated Connect action.
async function storage(env, create = false) {
  const entries = (await env.DB.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name=? COLLATE NOCASE OR tbl_name=? COLLATE NOCASE").bind(TABLE, TABLE).all()).results;
  if (!Array.isArray(entries)) throw problem("Google Drive connection storage could not be checked.", 503);
  if (!entries.length) {
    if (!create) return false;
    await env.DB.prepare(TABLE_SQL.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS")).run();
    if (!await storage(env, false)) throw problem("Google Drive connection storage could not be checked.", 503);
    return true;
  }
  const table = entries.find((row) => row.type === "table" && row.name === TABLE && row.tbl_name === TABLE);
  const normalize = (sql) => String(sql || "").replace(/\bIF\s+NOT\s+EXISTS\s+/i, "").replace(/\s+/g, " ").trim().toLowerCase();
  const schemaConflict = () => problem("Google Drive connection storage has a schema conflict. Contact support.", 503);
  if (!table || normalize(table.sql) !== normalize(TABLE_SQL) || entries.some((row) => row !== table && !(row.type === "index" && row.name === `sqlite_autoindex_${TABLE}_1` && row.tbl_name === TABLE && row.sql === null))) throw schemaConflict();
  const [columns, foreignKeys] = await Promise.all([
    env.DB.prepare("PRAGMA table_info(superior_google_oauth)").all(),
    env.DB.prepare("PRAGMA foreign_key_list(superior_google_oauth)").all()
  ]);
  const expected = [["key", 0, 1], ["value", 1, 0], ["updated_at", 1, 0]];
  if (!Array.isArray(columns.results) || columns.results.length !== expected.length || !Array.isArray(foreignKeys.results) || foreignKeys.results.length || columns.results.some((column, i) => column.cid !== i || column.name !== expected[i][0] || String(column.type).toUpperCase() !== "TEXT" || column.notnull !== expected[i][1] || column.pk !== expected[i][2] || column.dflt_value !== null)) throw schemaConflict();
  return true;
}
function validToken(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 4096 && /^[A-Za-z0-9._~+\/=\-]+$/.test(value);
}
const validId = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{1,200}$/.test(value);
function validateGrant(grant) {
  if (grant.v !== 1 || !validToken(grant.refreshToken) || grant.scope !== SCOPE || !validId(grant.accountId) || grant.folderId !== null && !validId(grant.folderId) || grant.lastBackupAt !== null && (typeof grant.lastBackupAt !== "string" || !Number.isFinite(Date.parse(grant.lastBackupAt))) || grant.lastError !== null && (typeof grant.lastError !== "string" || grant.lastError.length > 300) || typeof grant.needsReconnect !== "boolean") throw problem("Google Drive secure connection data is invalid. Reconnect Google Drive.", 409);
  return grant;
}
async function readConnection(env, origin) {
  if (!await storage(env)) return null;
  const row = await env.DB.prepare("SELECT value FROM superior_google_oauth WHERE key=?").bind("connection").first();
  return row ? { value: row.value, grant: validateGrant(await open(row.value, env, origin, "connection")) } : null;
}
async function saveConnection(env, origin, grant, previous) {
  if (!await storage(env)) throw problem("Google Drive connection storage is unavailable.", 503);
  const value = await seal(validateGrant(grant), env, origin, "connection");
  const result = previous
    ? await env.DB.prepare("UPDATE superior_google_oauth SET value=?,updated_at=? WHERE key=? AND value=?").bind(value, stamp(), "connection", previous.value).run()
    : await env.DB.prepare("INSERT INTO superior_google_oauth(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO NOTHING").bind("connection", value, stamp()).run();
  if (!result.meta?.changes) throw problem("Google Drive connection changed. Reload and try again.", 409);
  return { value, grant };
}
function sameOriginInitiation(req) {
  const origin = new URL(req.url).origin;
  const suppliedOrigin = req.headers.get("origin"), site = req.headers.get("sec-fetch-site"), referer = req.headers.get("referer");
  if (suppliedOrigin && suppliedOrigin !== origin || site && site !== "same-origin") return false;
  if (referer) {
    try { if (new URL(referer).origin !== origin) return false; } catch { return false; }
  }
  return true;
}
async function googleJSON(url, init, message, tokenRequest = false) {
  let response, data;
  try {
    response = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(30000) });
    const raw = await response.text();
    if (raw.length > 512000) throw Error();
    data = JSON.parse(raw);
  } catch {
    throw problem(message);
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw problem(message);
  if (!response.ok) throw problem(tokenRequest && data.error === "invalid_grant" ? "Google Drive authorization expired. Reconnect Google Drive." : message, 502, tokenRequest && data.error === "invalid_grant");
  return data;
}
async function tokens(env, fields, initial = false) {
  const data = await googleJSON("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, ...fields }).toString() }, "Google Drive authorization could not be completed. Reconnect Google Drive.", true);
  if (!validToken(data.access_token) || String(data.token_type).toLowerCase() !== "bearer" || typeof data.expires_in !== "number" || !Number.isFinite(data.expires_in) || data.expires_in <= 0 || data.expires_in > 86400 || data.refresh_token !== undefined && !validToken(data.refresh_token) || (initial || data.scope !== undefined) && (typeof data.scope !== "string" || !data.scope.split(/\s+/).includes(SCOPE))) throw problem("Google Drive did not return the required backup authorization. Reconnect Google Drive.", 502, true);
  return data;
}
const bearer = (accessToken) => ({ Authorization: "Bearer " + accessToken });
async function accountIdentity(accessToken) {
  const data = await googleJSON("https://www.googleapis.com/drive/v3/about?fields=user(permissionId)", { headers: bearer(accessToken) }, "Google Drive account could not be verified. Reconnect Google Drive.");
  if (!validId(data.user?.permissionId)) throw problem("Google Drive account could not be verified. Reconnect Google Drive.");
  return data.user.permissionId;
}
function privateFolder(file) {
  return validId(file?.id) && file.mimeType === "application/vnd.google-apps.folder" && file.trashed !== true && file.shared === false && file.ownedByMe === true;
}
async function findFolder(accessToken, previousId, create = true) {
  const fields = "id,mimeType,trashed,shared,ownedByMe";
  if (previousId) {
    let response;
    try { response = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(previousId)}?fields=${fields}`, { headers: bearer(accessToken), redirect: "error", signal: AbortSignal.timeout(30000) }); } catch { throw problem("Google Drive backup folder could not be checked. Try again."); }
    if (response.ok) {
      let file;
      try { file = await response.json(); } catch { throw problem("Google Drive backup folder could not be checked. Try again."); }
      if (privateFolder(file)) return file.id;
    } else if (response.status !== 404 && response.status !== 403) throw problem("Google Drive backup folder could not be checked. Try again.");
  }
  const query = `trashed = false and mimeType = 'application/vnd.google-apps.folder' and (appProperties has { key='purpose' and value='${PURPOSE}' } or name = '${FOLDER_NAME}')`;
  const url = new URL("https://www.googleapis.com/drive/v3/files");
  url.search = new URLSearchParams({ q: query, spaces: "drive", pageSize: "100", fields: `files(${fields}),nextPageToken` }).toString();
  const listed = await googleJSON(url.toString(), { headers: bearer(accessToken) }, "Google Drive backup folder could not be found. Try again.");
  if (!Array.isArray(listed.files)) throw problem("Google Drive backup folder could not be found. Try again.");
  const existing = listed.files.find(privateFolder);
  if (existing) return existing.id;
  if (!create) return null;
  const created = await googleJSON(`https://www.googleapis.com/drive/v3/files?fields=${fields}`, { method: "POST", headers: { ...bearer(accessToken), "Content-Type": "application/json" }, body: JSON.stringify({ name: FOLDER_NAME, mimeType: "application/vnd.google-apps.folder", appProperties: { purpose: PURPOSE } }) }, "Google Drive private backup folder could not be created. Try again.");
  if (!privateFolder(created)) throw problem("Google Drive did not confirm a private backup folder. Try again.");
  return created.id;
}
const RECEIPT_FIELDS = "id,name,mimeType,trashed,shared,ownedByMe,parents,appProperties,createdTime,size";
const unconfirmedUpload = () => problem("Google Drive upload is unconfirmed. Its receipt must be checked before uploading another copy.", 502, false, true);
function jobReceipt(file, folderId, jobId) {
  if (!validId(file?.id) || typeof file.name !== "string" || !/^Superior_Command_Center_Backup_[A-Za-z0-9_.-]+\.json$/.test(file.name) || file.mimeType !== "application/json" || file.trashed === true || file.shared !== false || file.ownedByMe !== true || !Array.isArray(file.parents) || !file.parents.includes(folderId) || file.appProperties?.purpose !== PURPOSE || file.appProperties?.backupJob !== jobId || typeof file.createdTime !== "string" || !Number.isFinite(Date.parse(file.createdTime)) || !/^[1-9]\d*$/.test(String(file.size || ""))) return null;
  return { filename: file.name, savedAt: file.createdTime, folderId, folderUrl: `https://drive.google.com/drive/folders/${folderId}` };
}
async function findJobReceipt(accessToken, folderId, jobId) {
  let pageToken;
  for (let page = 0; page < 10; page++) {
    const url = new URL("https://www.googleapis.com/drive/v3/files");
    const query = `trashed = false and '${folderId}' in parents and appProperties has { key='purpose' and value='${PURPOSE}' } and appProperties has { key='backupJob' and value='${jobId}' }`;
    url.search = new URLSearchParams({ q: query, spaces: "drive", pageSize: "100", fields: `files(${RECEIPT_FIELDS}),nextPageToken`, ...(pageToken ? { pageToken } : {}) }).toString();
    const listed = await googleJSON(url.toString(), { headers: bearer(accessToken) }, "Google Drive backup receipt could not be checked. Try again.");
    if (!Array.isArray(listed.files)) throw problem("Google Drive backup receipt could not be checked. Try again.");
    for (const candidate of listed.files) {
      if (!validId(candidate?.id)) throw unconfirmedUpload();
      // Confirm the listed receipt directly; a search result alone can be stale.
      let file;
      try {
        file = await googleJSON(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(candidate.id)}?fields=${RECEIPT_FIELDS}`, { headers: bearer(accessToken) }, "Google Drive backup receipt could not be verified. Try again.");
      } catch { throw unconfirmedUpload(); }
      const receipt = jobReceipt(file, folderId, jobId);
      if (!receipt) throw unconfirmedUpload();
      return receipt;
    }
    if (!listed.nextPageToken) return null;
    if (typeof listed.nextPageToken !== "string" || listed.nextPageToken.length > 2048 || listed.nextPageToken === pageToken) throw problem("Google Drive backup receipt could not be checked. Try again.");
    pageToken = listed.nextPageToken;
  }
  throw problem("Google Drive backup receipt could not be checked. Try again.");
}
async function uploadJob(accessToken, payload, boundary, filename, folderId, jobId) {
  let response;
  try {
    response = await fetch(`https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=${RECEIPT_FIELDS}`, { method: "POST", headers: { ...bearer(accessToken), "Content-Type": `multipart/related; boundary=${boundary}` }, body: payload, redirect: "error", signal: AbortSignal.timeout(30000) });
  } catch { throw unconfirmedUpload(); }
  // A returned client rejection confirms no accepted upload. Server failures or
  // unreadable success responses may follow an accepted file and stay unknown.
  if (!response.ok) {
    if (response.status >= 400 && response.status < 500) throw problem("Google Drive backup upload was rejected. Try again.");
    throw unconfirmedUpload();
  }
  let file;
  try { file = await response.json(); } catch { throw unconfirmedUpload(); }
  const receipt = jobReceipt(file, folderId, jobId);
  if (!receipt || receipt.filename !== filename) throw unconfirmedUpload();
  return receipt;
}
async function uploadBackup(env, accessToken, previousFolder, { jobId, recoverOnly = false } = {}) {
  const folderId = await findFolder(accessToken, previousFolder, !recoverOnly);
  if (!folderId) throw unconfirmedUpload();
  if (jobId) {
    const receipt = await findJobReceipt(accessToken, folderId, jobId);
    if (receipt) return receipt;
    if (recoverOnly) throw unconfirmedUpload();
  }
  const snapshot = await env.DB.batch([
    env.DB.prepare("SELECT data FROM records WHERE kind='estimate' ORDER BY created_at DESC"),
    env.DB.prepare("SELECT data FROM records WHERE kind='invoice' ORDER BY created_at DESC"),
    env.DB.prepare("SELECT data FROM customer_reviews ORDER BY created_at DESC")
  ]);
  const [estimates, invoices, reviews] = snapshot.map((result) => {
    if (!Array.isArray(result.results)) throw problem("Command Center records could not be read for backup.", 503);
    return result.results.map((row) => JSON.parse(row.data));
  });
  const exportedAt = stamp();
  const filename = `Superior_Command_Center_Backup_${exportedAt.replace(/[:.]/g, "-")}_${crypto.randomUUID().slice(0, 8)}.json`;
  const backup = JSON.stringify({ app: "Superior Maintenance and Remodeling - Command Center", version: 1, exportedAt, estimates, invoices, reviews }, null, 2);
  const boundary = "superior_" + random();
  const payload = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify({ name: filename, parents: [folderId], appProperties: { purpose: PURPOSE, ...(jobId ? { backupJob: jobId } : {}) } })}\r\n--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${backup}\r\n--${boundary}--\r\n`;
  if (jobId) return uploadJob(accessToken, payload, boundary, filename, folderId, jobId);
  const uploaded = await googleJSON("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name", { method: "POST", headers: { ...bearer(accessToken), "Content-Type": `multipart/related; boundary=${boundary}` }, body: payload }, "Google Drive backup upload failed. Try again.");
  if (!validId(uploaded.id) || uploaded.name !== filename) throw problem("Google Drive did not confirm the backup upload. Try again.");
  return { filename, savedAt: stamp(), folderId, folderUrl: `https://drive.google.com/drive/folders/${folderId}` };
}
async function backupAndSave(env, origin, connection, accessToken, options = {}) {
  let active = connection, receiptConfirmed = false;
  try {
    if (!accessToken) {
      const refreshed = await tokens(env, { grant_type: "refresh_token", refresh_token: active.grant.refreshToken });
      accessToken = refreshed.access_token;
      // Save rotations before using the access token, with a compare-and-swap.
      if (refreshed.refresh_token) active = await saveConnection(env, origin, { ...active.grant, refreshToken: refreshed.refresh_token, needsReconnect: false }, active);
    }
    if (options.jobId && await accountIdentity(accessToken) !== active.grant.accountId) throw problem("Google Drive account could not be verified. Reconnect Google Drive.", 502, true);
    const result = await uploadBackup(env, accessToken, active.grant.folderId, options);
    receiptConfirmed = true;
    await saveConnection(env, origin, { ...active.grant, folderId: result.folderId, lastBackupAt: result.savedAt, lastError: null, needsReconnect: false }, active);
    return { filename: result.filename, savedAt: result.savedAt, folderUrl: result.folderUrl };
  } catch (caught) {
    const error = caught instanceof DriveError ? caught : problem(publicError(caught));
    if (options.jobId && (options.recoverOnly || receiptConfirmed)) error.ambiguous = true;
    try { await saveConnection(env, origin, { ...active.grant, lastError: publicError(error), needsReconnect: !!error?.reconnect || active.grant.needsReconnect }, active); } catch { /* Keep a newer connection and never replace its status. */ }
    throw error;
  }
}

export async function googleBackupStatus(env, origin) {
  const ready = configured(env);
  let connection = null, lastError = null;
  if (ready) {
    try { connection = await readConnection(env, origin); } catch (error) { lastError = publicError(error); }
  }
  return { configured: ready, connected: !!connection && !connection.grant.needsReconnect, folderUrl: connection?.grant.folderId ? `https://drive.google.com/drive/folders/${connection.grant.folderId}` : null, lastBackupAt: connection?.grant.lastBackupAt || null, lastError: lastError || connection?.grant.lastError || null, notice: ready ? NOTICE : SETUP_NOTICE };
}

export async function backupToDrive(env, origin, options = {}) {
  try {
    if (!options || typeof options !== "object" || Array.isArray(options) || options.jobId !== undefined && (typeof options.jobId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(options.jobId)) || options.recoverOnly !== undefined && typeof options.recoverOnly !== "boolean" || options.recoverOnly && !options.jobId) throw problem("Invalid Google Drive backup job.", 400);
    requireConfig(env);
    const connection = await readConnection(env, origin);
    if (!connection || connection.grant.needsReconnect) throw problem("Connect Google Drive before saving a backup.", 409);
    return await backupAndSave(env, origin, connection, undefined, options);
  } catch (caught) {
    const error = caught instanceof DriveError ? caught : problem(publicError(caught));
    if (options?.recoverOnly) error.ambiguous = true;
    throw error;
  }
}

export async function googleRoute(req, env, context) {
  const url = new URL(req.url);
  try {
    if (req.method === "GET" && url.pathname === "/api/google/status") return json(await googleBackupStatus(env, url.origin));
    if (req.method === "GET" && url.pathname === "/api/google/connect") {
      if (!sameOriginInitiation(req)) throw problem("Invalid request origin.", 403);
      requireConfig(env);
      const sid = cookie(req, "superior_sid");
      if (!/^\d{13}\.[a-f0-9]{32}\.[a-f0-9]{64}$/.test(sid) || typeof context?.authorized !== "function" || !await context.authorized(req, env)) throw problem("Sign in as the owner.", 401);
      await storage(env, true);
      // Validate any existing grant before creating a reconnect handshake.
      const prior = await readConnection(env, url.origin);
      const state = random(), verifier = random(), issuedAt = Date.now();
      const value = await seal({ v: 1, state, verifier, sid, origin: url.origin, issuedAt, expiresAt: issuedAt + STATE_LIFETIME, connectionValue: prior?.value || null }, env, url.origin, "state");
      await storage(env);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM superior_google_oauth WHERE key LIKE 'state:%' AND updated_at<?").bind(new Date(issuedAt - STATE_LIFETIME).toISOString()),
        env.DB.prepare("INSERT INTO superior_google_oauth(key,value,updated_at) VALUES(?,?,?)").bind("state:" + state, value, new Date(issuedAt).toISOString())
      ]);
      const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      auth.search = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: new URL(CALLBACK_PATH, url.origin).href, response_type: "code", scope: SCOPE, access_type: "offline", prompt: "consent", state, code_challenge: base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(verifier)))), code_challenge_method: "S256" }).toString();
      return redirect(auth.toString(), stateCookie(state));
    }
    if (req.method === "POST" && url.pathname === "/api/google/backup-now") {
      if (!sameOriginInitiation(req)) throw problem("Invalid request origin.", 403);
      return json(await backupToDrive(env, url.origin));
    }
    return json({ error: "Not found." }, 404);
  } catch (error) {
    return json({ error: publicError(error) }, error instanceof DriveError ? error.status : 502);
  }
}

export async function googleCallback(req, env, context) {
  const url = new URL(req.url), clearCookie = stateCookie("", 0);
  try {
    if (req.method !== "GET" || url.pathname !== CALLBACK_PATH) return json({ error: "Not found." }, 404);
    requireConfig(env);
    const state = url.searchParams.get("state") || "", binder = cookie(req, STATE_COOKIE);
    if (url.href.length > 8192 || url.searchParams.getAll("state").length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(state) || !/^[A-Za-z0-9_-]{43}$/.test(binder) || !await constantEqual(state, binder)) throw problem("Google Drive authorization could not be verified.", 400);
    if (!await storage(env)) throw problem("Google Drive authorization expired. Try connecting again.", 400);
    const key = "state:" + state;
    const row = await env.DB.prepare("SELECT value FROM superior_google_oauth WHERE key=?").bind(key).first();
    if (!row) throw problem("Google Drive authorization expired. Try connecting again.", 400);
    const handshake = await open(row.value, env, url.origin, "state");
    const clock = Date.now();
    if (handshake.v !== 1 || handshake.origin !== url.origin || typeof handshake.state !== "string" || !await constantEqual(handshake.state, state) || !/^[A-Za-z0-9_-]{43}$/.test(handshake.verifier || "") || !/^\d{13}\.[a-f0-9]{32}\.[a-f0-9]{64}$/.test(handshake.sid || "") || !Number.isSafeInteger(handshake.issuedAt) || !Number.isSafeInteger(handshake.expiresAt) || handshake.issuedAt > clock || handshake.expiresAt <= clock || handshake.expiresAt - handshake.issuedAt !== STATE_LIFETIME || handshake.connectionValue !== null && typeof handshake.connectionValue !== "string") throw problem("Google Drive authorization expired. Try connecting again.", 400);
    const ownerRequest = new Request(new URL("/api/session", url.origin), { headers: { Cookie: "superior_sid=" + handshake.sid } });
    if (typeof context?.authorized !== "function" || !await context.authorized(ownerRequest, env)) throw problem("Sign in as the owner and connect Google Drive again.", 401);
    const denied = url.searchParams.has("error");
    const code = url.searchParams.get("code") || "";
    if (url.searchParams.getAll("error").length > 1 || url.searchParams.getAll("code").length > 1 || denied && url.searchParams.has("code") || !denied && (url.searchParams.getAll("code").length !== 1 || code.length > 4096 || !/^[A-Za-z0-9._~+\/=\-]+$/.test(code))) throw problem("Google Drive authorization response was invalid.", 400);
    // Verification precedes the atomic one-time consume; exchange never runs twice.
    await storage(env);
    const consumed = await env.DB.prepare("DELETE FROM superior_google_oauth WHERE key=? AND value=? RETURNING value").bind(key, row.value).first();
    if (!consumed || consumed.value !== row.value) throw problem("Google Drive authorization expired. Try connecting again.", 400);
    if (denied) return redirect("/owner/backup?drive=" + (url.searchParams.get("error") === "access_denied" ? "denied" : "error"), clearCookie);
    const prior = await readConnection(env, url.origin);
    if ((prior?.value || null) !== handshake.connectionValue) throw problem("Google Drive connection changed. Try connecting again.", 409);
    const token = await tokens(env, { grant_type: "authorization_code", code, code_verifier: handshake.verifier, redirect_uri: new URL(CALLBACK_PATH, url.origin).href }, true);
    const accountId = await accountIdentity(token.access_token);
    if (!token.refresh_token && (!prior || prior.grant.accountId !== accountId || prior.grant.needsReconnect)) throw problem("Google Drive did not return a renewable authorization. Reconnect Google Drive.", 502);
    const grant = { v: 1, refreshToken: token.refresh_token || prior.grant.refreshToken, scope: SCOPE, accountId, folderId: token.refresh_token ? null : prior.grant.folderId, lastBackupAt: token.refresh_token ? null : prior.grant.lastBackupAt, lastError: null, needsReconnect: false };
    const connected = await saveConnection(env, url.origin, grant, prior);
    await backupAndSave(env, url.origin, connected, token.access_token);
    return redirect("/owner/backup?drive=connected", clearCookie);
  } catch {
    // Never reflect provider text, code, state, token, or session into a response.
    return redirect("/owner/backup?drive=error", clearCookie);
  }
}
