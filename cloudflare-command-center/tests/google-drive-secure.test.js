import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import worker from '../src/worker.js';
import { googleBackupStatus } from '../src/google-oauth.js';
import {
  ACCESS_TOKEN, CLIENT_SECRET, OAUTH_COOKIE, ORIGIN, REFRESH_TOKEN, SCHEMA,
  ENCRYPTION_SECRET, SESSION_SECRET, TABLE, assertSnapshot, cookieValue, environment, fixtures,
  googleMock, request, sid
} from './google-drive-fixtures.js';

const fetchWorker = (req, env) => worker.fetch(req, env, { waitUntil() {} });
const isRedirect = response => [302, 303].includes(response.status);
const isConnected = response => isRedirect(response) && response.headers.get('location') === '/owner/backup?drive=connected';
const JOBS = 'superior_drive_backup_jobs';
const estimateInput = { customer: 'Saved during Google outage', email: 'customer@example.test', phone: '555-0101', address: 'Original save address', project: 'Durable automatic backup', items: [{ description: 'Saved work', qty: 2, rate: 25.5 }], taxRate: 5, notes: 'These notes must survive backup failure' };
function assertCallbackRejected(response) {
  assert.ok(response.status >= 400 || isRedirect(response) && response.headers.get('location') === '/owner/backup?drive=error', 'Callback must reject authorization without a connected result');
}

function setup(t) {
  const env = environment();
  t.after(() => env.DB.close());
  return env;
}

function replaceFetch(t, mock) {
  const previous = globalThis.fetch;
  globalThis.fetch = mock;
  t.after(() => { globalThis.fetch = previous; });
}

function backgroundContext() {
  const tasks = [];
  return { tasks, waitUntil(task) { tasks.push(Promise.resolve(task)); }, async drain() { await Promise.all(tasks); } };
}

async function callWithBackground(path, env, options = {}) {
  const context = backgroundContext();
  const response = await worker.fetch(request(path, options), env, context);
  return { response, context, data: await response.clone().json() };
}

function jsonRequest(body, options = {}) {
  return { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), ...options };
}

function queueRows(env) {
  return env.DB.sqlite.prepare(`SELECT * FROM ${JOBS} ORDER BY created_at,id`).all().map(row => ({ ...row }));
}

function emptyBusinessFixture(env) {
  env.DB.sqlite.exec('DELETE FROM customer_reviews; DELETE FROM records;');
  env.DB.originalBusinessRows = env.DB.businessRows();
}

async function scheduledRetry(env) {
  const context = backgroundContext();
  await worker.scheduled({ cron: '*/15 * * * *', scheduledTime: Date.now() }, env, context);
  await context.drain();
  return context;
}

async function advanceRetryClock(t) {
  const RealDate = globalThis.Date;
  class RetryDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : [RealDate.now() + 24 * 60 * 60 * 1000])); }
    static now() { return RealDate.now() + 24 * 60 * 60 * 1000; }
  }
  globalThis.Date = RetryDate;
  t.after(() => { globalThis.Date = RealDate; });
}

async function connect(env, options = {}) {
  const session = options.session || sid();
  const response = await fetchWorker(request('/api/google/connect', { ...options, session }), env);
  assert.ok(isRedirect(response), await response.clone().text());
  const destination = new URL(response.headers.get('location'));
  const state = destination.searchParams.get('state');
  const cookie = cookieValue(response);
  assert.equal(cookie, state);
  return { response, destination, state, cookie: `${OAUTH_COOKIE}=${cookie}`, session };
}

async function callback(env, flow, options = {}) {
  const path = `/api/google/callback?${new URLSearchParams({ state: flow.state, code: 'test-authorization-code', ...(options.query || {}) })}`;
  return fetchWorker(request(path, { owner: false, cookies: flow.cookie, ...(options.request || {}) }), env);
}

function assertNoSecrets(value, additional = []) {
  const content = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of [CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN, SESSION_SECRET, ENCRYPTION_SECRET, ...additional]) assert.ok(!content.includes(secret), 'Secret leaked to public response or unencrypted storage');
}

test('unconnected status is read only and missing Google configuration is safe', async t => {
  const env = setup(t);
  replaceFetch(t, async () => { throw Error('Status must not contact Google'); });
  const response = await fetchWorker(request('/api/google/status'), env);
  assert.equal(response.status, 200);
  const status = await response.json();
  assert.equal(status.configured, true);
  assert.equal(status.connected, false);
  assertNoSecrets(status);
  assert.equal(env.DB.sqlite.prepare("SELECT name FROM sqlite_schema WHERE name=?").get(TABLE), undefined);
  env.DB.assertNoWrites();
  for (const key of ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET']) {
    const incomplete = { ...env, [key]: '' };
    const unconfigured = await fetchWorker(request('/api/google/status'), incomplete);
    assert.equal(unconfigured.status, 200);
    const data = await unconfigured.json();
    assert.equal(data.configured, false);
    assert.equal(data.connected, false);
    assertNoSecrets(data);
  }
  env.DB.assertNoWrites();
});

test('a separate encryption key enables Drive while the existing short owner signing secret stays valid', async t => {
  const env = setup(t);
  const google = googleMock();
  replaceFetch(t, google.mock);
  const originalSecrets = { password: env.OWNER_PASSWORD, session: env.SESSION_SECRET, encryption: env.GOOGLE_OAUTH_ENCRYPTION_SECRET, client: env.GOOGLE_CLIENT_SECRET };
  assert.ok(env.SESSION_SECRET.length < 32, 'Fixture must model the existing short but valid signing secret');
  const ownerSession = sid();
  const before = await (await fetchWorker(request('/api/session', { session: ownerSession }), env)).json();
  assert.equal(before.authenticated, true);
  assert.equal((await googleBackupStatus(env, ORIGIN)).configured, true);
  const response = await callback(env, await connect(env, { session: ownerSession }));
  assert.ok(isConnected(response));
  const after = await (await fetchWorker(request('/api/session', { session: ownerSession }), env)).json();
  assert.equal(after.authenticated, true);
  assert.deepEqual({ password: env.OWNER_PASSWORD, session: env.SESSION_SECRET, encryption: env.GOOGLE_OAUTH_ENCRYPTION_SECRET, client: env.GOOGLE_CLIENT_SECRET }, originalSecrets);
  // Signing and encryption have independent keys: changing only the signing
  // input in a read-only fixture cannot make the saved grant undecryptable.
  assert.equal((await googleBackupStatus({ ...env, SESSION_SECRET: 'different-fixture-signing-key' }, ORIGIN)).connected, true);
  env.DB.assertBusinessPreserved();
});

test('a missing or weak dedicated key disables secure setup without generating credentials or touching D1', async t => {
  const env = setup(t);
  replaceFetch(t, async () => { throw Error('Incomplete secure setup must not contact Google'); });
  for (const key of [undefined, '', 'short-key', ' '.repeat(64), 'x'.repeat(31)]) {
    const incomplete = { ...env, SESSION_SECRET: 'a-long-existing-signing-key-is-still-not-the-drive-key', GOOGLE_OAUTH_ENCRYPTION_SECRET: key };
    const callsBefore = env.DB.calls.length;
    const status = await googleBackupStatus(incomplete, ORIGIN);
    assert.equal(status.configured, false);
    assert.equal(status.connected, false);
    assert.match(status.notice, /secure setup|encryption key/i);
    assert.equal(env.DB.calls.length, callsBefore, 'The helper must reject missing secure configuration before D1 inspection');
    const response = await fetchWorker(request('/api/google/connect', { owner: false, cookies: `superior_sid=${sid()}` }), { ...incomplete, SESSION_SECRET });
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('location'), null);
    assert.equal(incomplete.GOOGLE_OAUTH_ENCRYPTION_SECRET, key, 'No key may be generated implicitly');
    assert.equal(incomplete.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_ID);
    assert.equal(incomplete.GOOGLE_CLIENT_SECRET, CLIENT_SECRET);
  }
  assert.equal(env.DB.sqlite.prepare('SELECT name FROM sqlite_schema WHERE name=?').get(TABLE), undefined);
  env.DB.assertNoWrites();
});

test('status and connect reject a preexisting incompatible OAuth table without changing it', async t => {
  for (const schema of [
    `CREATE TABLE ${TABLE} (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
    `CREATE TABLE ${TABLE} (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL, extra TEXT)`,
    `CREATE TABLE ${TABLE} (key TEXT, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
    `CREATE TABLE ${TABLE} (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT NOT NULL)`,
    `CREATE VIEW ${TABLE} AS SELECT id AS key, data AS value, created_at AS updated_at FROM records`
  ]) {
    await t.test(schema.split('(')[0], async t => {
      const env = setup(t);
      env.DB.sqlite.exec(schema);
      const before = env.DB.sqlite.prepare('SELECT * FROM sqlite_schema ORDER BY name').all();
      const status = await fetchWorker(request('/api/google/status'), env);
      const statusData = await status.json();
      assert.equal(statusData.connected, false);
      assert.ok(statusData.lastError, `Incompatible OAuth schema accepted: ${schema}`);
      const response = await fetchWorker(request('/api/google/connect'), env);
      assert.ok(response.status >= 400);
      assert.equal(response.headers.get('location'), null);
      assert.deepEqual(env.DB.sqlite.prepare('SELECT * FROM sqlite_schema ORDER BY name').all(), before);
      env.DB.assertNoWrites();
    });
  }
});

test('OAuth table triggers, extra indexes and foreign keys are rejected before any write', async t => {
  for (const extra of [
    `CREATE TRIGGER unexpected_google_write AFTER INSERT ON ${TABLE} BEGIN DELETE FROM records; END`,
    `CREATE INDEX unexpected_google_index ON ${TABLE} (updated_at)`
  ]) {
    await t.test(extra.split(' ON ')[0], async t => {
      const env = setup(t);
      env.DB.sqlite.exec(SCHEMA);
      env.DB.sqlite.exec(extra);
      const response = await fetchWorker(request('/api/google/connect'), env);
      assert.ok(response.status >= 400);
      assert.equal(response.headers.get('location'), null);
      env.DB.assertNoWrites();
    });
  }
  await t.test('foreign key collision', async t => {
    const env = setup(t);
    env.DB.sqlite.exec(`CREATE TABLE ${TABLE} (key TEXT PRIMARY KEY REFERENCES records(id), value TEXT NOT NULL, updated_at TEXT NOT NULL)`);
    const response = await fetchWorker(request('/api/google/connect'), env);
    assert.ok(response.status >= 400);
    env.DB.assertNoWrites();
  });
});

test('case-variant SQLite table, view and trigger collisions are rejected without any write', async t => {
  const collisions = [
    {
      name: 'uppercase table with expected columns',
      sql: 'CREATE TABLE SUPERIOR_GOOGLE_OAUTH (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)'
    },
    {
      name: 'mixed-case table with expected columns',
      sql: 'CREATE TABLE Superior_Google_OAuth (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)'
    },
    {
      name: 'uppercase table with a business-data trigger',
      sql: `CREATE TABLE SUPERIOR_GOOGLE_OAUTH (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TRIGGER collision_business_write AFTER INSERT ON SUPERIOR_GOOGLE_OAUTH BEGIN DELETE FROM records; END`
    },
    {
      name: 'uppercase view',
      sql: 'CREATE VIEW SUPERIOR_GOOGLE_OAUTH AS SELECT id AS key, data AS value, created_at AS updated_at FROM records'
    },
    {
      name: 'mixed-case view',
      sql: 'CREATE VIEW Superior_Google_OAuth AS SELECT id AS key, data AS value, created_at AS updated_at FROM records'
    },
    {
      name: 'uppercase trigger named like OAuth storage',
      sql: 'CREATE TRIGGER SUPERIOR_GOOGLE_OAUTH AFTER UPDATE ON login_attempts BEGIN SELECT 1; END'
    },
    {
      name: 'mixed-case trigger named like OAuth storage',
      sql: 'CREATE TRIGGER Superior_Google_OAuth AFTER UPDATE ON login_attempts BEGIN SELECT 1; END'
    }
  ];
  for (const collision of collisions) {
    await t.test(collision.name, async t => {
      const env = setup(t);
      env.DB.sqlite.exec(collision.sql);
      // A preexisting trigger belongs to this database's preservation baseline.
      env.DB.originalBusinessSchema = env.DB.businessSchema();
      const before = env.DB.sqlite.prepare('SELECT * FROM sqlite_schema ORDER BY name').all();
      const status = await (await fetchWorker(request('/api/google/status'), env)).json();
      assert.equal(status.connected, false);
      assert.ok(status.lastError, 'Status must expose the case-variant storage conflict');
      const response = await fetchWorker(request('/api/google/connect'), env);
      assert.ok(response.status >= 400);
      assert.equal(response.headers.get('location'), null);
      assert.deepEqual(env.DB.sqlite.prepare('SELECT * FROM sqlite_schema ORDER BY name').all(), before);
      env.DB.assertNoWrites();
    });
  }
});

test('connect creates only isolated storage and sends PKCE with a separate callback cookie', async t => {
  const env = setup(t);
  replaceFetch(t, async () => { throw Error('Connect must redirect without contacting Google'); });
  const flow = await connect(env);
  const { destination, response } = flow;
  assert.equal(destination.origin, 'https://accounts.google.com');
  assert.equal(destination.pathname, '/o/oauth2/v2/auth');
  const query = destination.searchParams;
  assert.equal(query.get('client_id'), env.GOOGLE_CLIENT_ID);
  assert.equal(query.get('redirect_uri'), `${ORIGIN}/api/google/callback`);
  assert.equal(query.get('response_type'), 'code');
  assert.equal(query.get('scope'), 'https://www.googleapis.com/auth/drive.file');
  assert.equal(query.get('access_type'), 'offline');
  assert.equal(query.get('code_challenge_method'), 'S256');
  assert.match(query.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/);
  assert.match(flow.state, /^[A-Za-z0-9_-]{32,}$/);
  assertNoSecrets(destination.href, [flow.session]);
  const setCookie = response.headers.get('set-cookie');
  assert.match(setCookie, /^__Secure-superior_google_oauth=/);
  assert.match(setCookie, /Path=\/api\/google\/callback(?:;|$)/i);
  assert.match(setCookie, /; Secure(?:;|$)/i);
  assert.match(setCookie, /; HttpOnly(?:;|$)/i);
  assert.match(setCookie, /; SameSite=Lax(?:;|$)/i);
  assert.doesNotMatch(setCookie, /superior_sid=/);
  assertNoSecrets(setCookie, [flow.session]);
  assertNoSecrets(env.DB.oauthRows(), [flow.session]);
  const again = await connect(env);
  assert.notEqual(again.state, flow.state);
  assert.notEqual(again.destination.searchParams.get('code_challenge'), query.get('code_challenge'));
  env.DB.assertBusinessPreserved();
});

test('state, cookie and callback origin mismatches stop before token exchange', async t => {
  const env = setup(t);
  const google = googleMock();
  replaceFetch(t, google.mock);
  const flow = await connect(env);
  for (const options of [
    { request: { cookies: '' } },
    { request: { cookies: `${OAUTH_COOKIE}=different-browser-state` } },
    { query: { state: 'invalid-callback-state' } }
  ]) {
    const response = await callback(env, flow, options);
    assertCallbackRejected(response);
  }
  const mismatchedOrigin = await fetchWorker(new Request(`https://unrelated.example/api/google/callback?state=${flow.state}&code=test-authorization-code`, { headers: { Cookie: flow.cookie } }), env);
  assertCallbackRejected(mismatchedOrigin);
  assert.equal(google.calls.length, 0);
  env.DB.assertBusinessPreserved();
});

test('cross-origin connect and invalid signed owner sessions cannot create OAuth storage', async t => {
  const env = setup(t);
  replaceFetch(t, async () => { throw Error('Rejected connect must not contact Google'); });
  for (const options of [
    { headers: { Origin: 'https://unrelated.example' } },
    { headers: { 'Sec-Fetch-Site': 'cross-site' } },
    { headers: { Referer: 'https://unrelated.example/owner/backup' } },
    { session: sid(Date.now() - 1000) },
    { session: sid().slice(0, -1) + 'z' }
  ]) {
    const response = await fetchWorker(request('/api/google/connect', options), env);
    assert.ok([401, 403].includes(response.status));
    assert.equal(response.headers.get('location'), null);
  }
  assert.equal(env.DB.sqlite.prepare('SELECT name FROM sqlite_schema WHERE name=?').get(TABLE), undefined);
  env.DB.assertNoWrites();
});

test('altered encrypted state and encrypted connection data fail closed without exposing secrets', async t => {
  const env = setup(t);
  const google = googleMock();
  replaceFetch(t, google.mock);
  const altered = await connect(env);
  const stateRow = env.DB.sqlite.prepare(`SELECT value FROM ${TABLE} WHERE key=?`).get(`state:${altered.state}`);
  // Change an authenticated ciphertext byte while preserving its envelope shape.
  const envelope = stateRow.value.split('.');
  envelope[2] = (envelope[2][0] === 'A' ? 'B' : 'A') + envelope[2].slice(1);
  env.DB.sqlite.prepare(`UPDATE ${TABLE} SET value=? WHERE key=?`).run(envelope.join('.'), `state:${altered.state}`);
  const rejected = await callback(env, altered);
  assertCallbackRejected(rejected);
  assert.equal(google.tokenExchanges, 0);
  const fresh = await connect(env);
  assert.ok(isConnected(await callback(env, fresh)));
  const connection = env.DB.sqlite.prepare(`SELECT value FROM ${TABLE} WHERE key='connection'`).get();
  const connectionEnvelope = connection.value.split('.');
  connectionEnvelope[2] = (connectionEnvelope[2][0] === 'A' ? 'B' : 'A') + connectionEnvelope[2].slice(1);
  env.DB.sqlite.prepare(`UPDATE ${TABLE} SET value=? WHERE key='connection'`).run(connectionEnvelope.join('.'));
  env.DB.calls.length = 0;
  const beforeGoogleCalls = google.calls.length;
  const status = await (await fetchWorker(request('/api/google/status'), env)).json();
  assert.equal(status.connected, false);
  assert.ok(status.lastError);
  assertNoSecrets(status);
  const backup = await fetchWorker(request('/api/google/backup-now', { method: 'POST' }), env);
  assert.ok(backup.status >= 400);
  assertNoSecrets(await backup.text());
  assert.equal(google.calls.length, beforeGoogleCalls);
  env.DB.assertNoWrites();
});

test('expired owner session and expired OAuth state cannot exchange an authorization code', async t => {
  const env = setup(t);
  const google = googleMock();
  replaceFetch(t, google.mock);
  const realNow = Date.now;
  const start = realNow();
  const shortSessionFlow = await connect(env, { session: sid(start + 1000) });
  Date.now = () => start + 2000;
  t.after(() => { Date.now = realNow; });
  const expiredOwner = await callback(env, shortSessionFlow);
  assertCallbackRejected(expiredOwner);
  assert.equal(google.tokenExchanges, 0);
  Date.now = () => start;
  const expiredStateFlow = await connect(env);
  Date.now = () => start + 11 * 60 * 1000;
  const expiredState = await callback(env, expiredStateFlow);
  assertCallbackRejected(expiredState);
  assert.equal(google.tokenExchanges, 0);
  env.DB.assertBusinessPreserved();
});

test('successful callback consumes state once, saves encrypted tokens and uploads an exact durable snapshot', async t => {
  const env = setup(t);
  const google = googleMock();
  replaceFetch(t, google.mock);
  const flow = await connect(env);
  const responses = await Promise.all([callback(env, flow), callback(env, flow)]);
  const success = responses.find(isConnected);
  const rejected = responses.find(response => !isConnected(response));
  assert.ok(success, 'One callback should finish successfully');
  assert.ok(rejected, 'A concurrent replay should fail');
  assert.equal(success.headers.get('location'), '/owner/backup?drive=connected');
  assert.equal(google.tokenExchanges, 1);
  assert.equal(google.uploads.length, 1);
  assertSnapshot(google.uploads[0].backup);
  const exchange = google.calls.find(call => call.url.pathname === '/token');
  const verifier = new URLSearchParams(exchange.body).get('code_verifier');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  assert.equal(challenge, flow.destination.searchParams.get('code_challenge'));
  assert.ok(env.DB.calls.some(call => /^\s*DELETE\s+FROM\s+superior_google_oauth\b/i.test(call.sql) && /\bRETURNING\b/i.test(call.sql)), 'State must be consumed atomically before exchange');
  const statusResponse = await fetchWorker(request('/api/google/status'), env);
  const status = await statusResponse.json();
  assert.equal(status.connected, true);
  assert.ok(Number.isFinite(Date.parse(status.lastBackupAt)));
  assert.equal(status.lastError, null);
  assert.match(status.folderUrl, /^https:\/\/drive\.google\.com\//);
  assertNoSecrets(status);
  assertNoSecrets(env.DB.oauthRows(), [flow.session, verifier]);
  assertNoSecrets(success.headers.get('set-cookie') || '');
  const replay = await callback(env, flow);
  assertCallbackRejected(replay);
  assert.equal(google.tokenExchanges, 1);
  env.DB.assertBusinessPreserved();
});

test('saved credentials survive a new Worker request and back up again after access-token expiry', async t => {
  const env = setup(t);
  const google = googleMock();
  replaceFetch(t, google.mock);
  const flow = await connect(env);
  const completed = await callback(env, flow);
  assert.ok(isConnected(completed), await completed.clone().text());
  env.DB.reopen();
  const realNow = Date.now;
  Date.now = () => realNow() + 2 * 60 * 60 * 1000;
  t.after(() => { Date.now = realNow; });
  // New owner request carries no OAuth cookie or in-memory connection data.
  const response = await fetchWorker(request('/api/google/backup-now', { method: 'POST' }), { ...env });
  assert.equal(response.status, 200, await response.clone().text());
  const result = await response.json();
  assert.match(result.filename, /^Superior_Command_Center_Backup_.*\.json$/);
  assert.ok(Number.isFinite(Date.parse(result.savedAt)));
  assert.ok(google.refreshes >= 1);
  assert.equal(google.uploads.length, 2);
  google.uploads.forEach(({ backup }) => assertSnapshot(backup));
  assertNoSecrets(result);
  assertNoSecrets(env.DB.oauthRows());
  env.DB.assertBusinessPreserved();
});

test('reauthorization without a new refresh token preserves the previous durable grant', async t => {
  const env = setup(t);
  const firstGoogle = googleMock();
  replaceFetch(t, firstGoogle.mock);
  assert.ok(isConnected(await callback(env, await connect(env))));
  const reauthorizationGoogle = googleMock({ omitRefresh: true });
  globalThis.fetch = reauthorizationGoogle.mock;
  const reauthorization = await callback(env, await connect(env));
  assert.ok(isConnected(reauthorization), await reauthorization.clone().text());
  const realNow = Date.now;
  Date.now = () => realNow() + 2 * 60 * 60 * 1000;
  t.after(() => { Date.now = realNow; });
  const backup = await fetchWorker(request('/api/google/backup-now', { method: 'POST' }), env);
  assert.equal(backup.status, 200, await backup.clone().text());
  assert.ok(reauthorizationGoogle.refreshes >= 1);
  assert.equal(reauthorizationGoogle.uploads.length, 2);
  env.DB.assertBusinessPreserved();
});

test('a different Google account cannot reuse the existing account refresh token', async t => {
  const env = setup(t);
  const firstGoogle = googleMock();
  replaceFetch(t, firstGoogle.mock);
  assert.ok(isConnected(await callback(env, await connect(env))));
  const previousConnection = env.DB.sqlite.prepare(`SELECT value FROM ${TABLE} WHERE key='connection'`).get().value;
  const otherAccount = googleMock({ omitRefresh: true, accountId: 'different-google-account' });
  globalThis.fetch = otherAccount.mock;
  const response = await callback(env, await connect(env));
  assertCallbackRejected(response);
  assert.equal(otherAccount.refreshes, 0);
  assert.equal(otherAccount.uploads.length, 0);
  assert.equal(env.DB.sqlite.prepare(`SELECT value FROM ${TABLE} WHERE key='connection'`).get().value, previousConnection);
  env.DB.assertBusinessPreserved();
});

test('first upload failure never returns the connected success marker', async t => {
  const env = setup(t);
  const google = googleMock({ uploadFails: true });
  replaceFetch(t, google.mock);
  const flow = await connect(env);
  const response = await callback(env, flow);
  assert.notEqual(response.headers.get('location'), '/owner/backup?drive=connected');
  const status = await (await fetchWorker(request('/api/google/status'), env)).json();
  assert.equal(status.lastBackupAt, null);
  assert.ok(status.lastError, 'Failure remains visible after the callback');
  assertNoSecrets(status);
  assertNoSecrets(await response.text());
  assert.equal(google.tokenExchanges, 1);
  const replay = await callback(env, flow);
  assertCallbackRejected(replay);
  assert.equal(google.tokenExchanges, 1, 'A failed upload must not make OAuth state reusable');
  env.DB.assertBusinessPreserved();
});

test('original owner login, Strict session cookies, download shape and route protection remain intact', async t => {
  const env = setup(t);
  replaceFetch(t, async () => { throw Error('Unauthenticated calls must not contact Google'); });
  for (const [path, method] of [
    ['/api/google/status', 'GET'], ['/api/google/connect', 'GET'], ['/api/google/backup-now', 'POST'],
    ['/api/estimates', 'GET'], ['/api/invoices', 'GET'], ['/api/reviews', 'GET'], ['/api/backup', 'GET'],
    ['/api/restore', 'POST']
  ]) {
    const response = await fetchWorker(request(path, { method, owner: false }), env);
    assert.equal(response.status, 401, `${method} ${path} must stay owner protected`);
  }
  env.DB.assertNoWrites();
  const login = await fetchWorker(request('/api/login', { method: 'POST', owner: false, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: env.OWNER_PASSWORD }) }), env);
  assert.equal(login.status, 200);
  const session = cookieValue(login, 'superior_sid');
  assert.ok(session);
  assert.match(login.headers.get('set-cookie'), /Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=43200/);
  const sessionStatus = await (await fetchWorker(request('/api/session', { session }), env)).json();
  assert.equal(sessionStatus.authenticated, true);
  assert.deepEqual(sessionStatus.capabilities, { additiveRestore: true, customerFeedback: true });
  const download = await fetchWorker(request('/api/backup', { session }), env);
  assert.equal(download.status, 200);
  assertSnapshot(await download.json());
  const estimates = await (await fetchWorker(request('/api/estimates', { session }), env)).json();
  assert.equal(estimates.estimates.length, fixtures.estimates.length);
  assert.ok(estimates.estimates.every(record => !('reviewToken' in record)));
  assert.deepEqual(env.DB.businessRows(), env.DB.originalBusinessRows);
  assert.deepEqual(env.DB.businessSchema(), env.DB.originalBusinessSchema);
});

test('an actual estimate save survives a Google outage and its durable queued job completes on scheduled retry', async t => {
  const env = setup(t);
  emptyBusinessFixture(env);
  const google = googleMock();
  replaceFetch(t, google.mock);
  assert.ok(isConnected(await callback(env, await connect(env))));
  google.state.unavailable = true;
  const created = await callWithBackground('/api/estimates', env, jsonRequest(estimateInput));
  assert.equal(created.response.status, 201);
  assert.equal(created.data.estimate.customer, estimateInput.customer);
  assert.ok(created.context.tasks.length > 0, 'The real Worker must register its after-save task');
  await created.context.drain();
  const recordId = created.data.estimate.id;
  const saved = env.DB.sqlite.prepare('SELECT data FROM records WHERE id=?').get(recordId).data;
  assert.deepEqual(JSON.parse(saved), created.data.estimate);
  const queued = queueRows(env);
  assert.equal(queued.length, 1);
  assert.notEqual(queued[0].status, 'complete');
  const status = await (await fetchWorker(request('/api/google/status'), env)).json();
  assert.ok(status.pendingCount >= 1);
  assert.ok(status.lastError || status.lastQueueError, 'Failed automatic delivery remains visible');
  assertNoSecrets(status);
  env.DB.reopen();
  assert.deepEqual(queueRows(env), queued, 'A new SQLite connection must see the same durable pending job');
  google.state.unavailable = false;
  await advanceRetryClock(t);
  await scheduledRetry(env);
  const delivered = queueRows(env);
  assert.equal(delivered.length, 1);
  assert.equal(delivered[0].status, 'complete');
  assert.ok(delivered[0].completed_at);
  assert.equal(env.DB.sqlite.prepare('SELECT data FROM records WHERE id=?').get(recordId).data, saved);
  const snapshot = google.uploads.at(-1).backup;
  assert.deepEqual(snapshot.estimates, [created.data.estimate]);
  assert.deepEqual(snapshot.invoices, []);
  assert.deepEqual(snapshot.reviews, []);
  assert.equal(google.files.length, 2, 'One initial connection backup and one automatic backup are confirmed');
  const beforeRetryUploads = google.uploads.length;
  await scheduledRetry(env);
  assert.equal(google.uploads.length, beforeRetryUploads, 'Completed automatic jobs must not upload twice');
  assert.ok(google.calls.every(call => !call.url.pathname.includes('/gmail/')), 'The authorized automatic feature is Drive-only');
});

test('saving before Google is configured durably queues without consuming retries or changing credentials', async t => {
  const env = setup(t);
  emptyBusinessFixture(env);
  env.GOOGLE_OAUTH_ENCRYPTION_SECRET = '';
  const originalSession = env.SESSION_SECRET;
  replaceFetch(t, async () => { throw Error('Pending setup must not call Google'); });
  const created = await callWithBackground('/api/estimates', env, jsonRequest(estimateInput));
  assert.equal(created.response.status, 201);
  await created.context.drain();
  const before = queueRows(env);
  assert.equal(before.length, 1);
  assert.equal(before[0].status, 'pending');
  assert.equal(before[0].attempts, 0);
  env.DB.reopen();
  await scheduledRetry(env);
  assert.equal(queueRows(env)[0].attempts, 0);
  assert.equal(queueRows(env)[0].status, 'pending');
  assert.equal(env.SESSION_SECRET, originalSession);
  assert.equal(env.GOOGLE_OAUTH_ENCRYPTION_SECRET, '');
  assert.equal(env.DB.sqlite.prepare('SELECT COUNT(*) AS n FROM records').get().n, 1);
});

test('customer approval creates one invoice and one durable invoice job despite concurrent decisions and Google failure', async t => {
  const env = setup(t);
  emptyBusinessFixture(env);
  const google = googleMock();
  replaceFetch(t, google.mock);
  assert.ok(isConnected(await callback(env, await connect(env))));
  google.state.unavailable = true;
  const created = await callWithBackground('/api/estimates', env, jsonRequest(estimateInput));
  await created.context.drain();
  const shared = await callWithBackground(`/api/estimates/${created.data.estimate.id}/share`, env, jsonRequest({}));
  await shared.context.drain();
  const token = shared.data.url.split('/').pop();
  let readers = 0, release;
  const bothRead = new Promise(resolve => { release = resolve; });
  env.DB.hooks.afterRead = async sql => {
    if (!sql.includes("kind='estimate' AND review_token=?")) return;
    if (++readers === 2) release();
    await bothRead;
  };
  const decisions = await Promise.all([1, 2].map(() => callWithBackground(`/api/review/${token}/decision`, env, jsonRequest({ decision: 'approved', signature: estimateInput.customer }, { owner: false }))));
  env.DB.hooks.afterRead = undefined;
  await Promise.all(decisions.map(decision => decision.context.drain()));
  assert.deepEqual(decisions.map(decision => decision.response.status).sort(), [200, 409]);
  const invoice = env.DB.sqlite.prepare("SELECT data FROM records WHERE kind='invoice'").all();
  assert.equal(invoice.length, 1);
  assert.equal(JSON.parse(invoice[0].data).customer, estimateInput.customer);
  assert.equal(queueRows(env).filter(job => job.trigger === 'invoice-created').length, 1, 'The raced rejected write must not enqueue a phantom invoice');
  assert.ok(queueRows(env).every(job => job.status !== 'complete'));
  const successful = decisions.find(decision => decision.response.status === 200);
  assert.ok(successful.context.tasks.length > 0);
});

test('a failed business write does not enqueue a phantom automatic job', async t => {
  const env = setup(t);
  emptyBusinessFixture(env);
  replaceFetch(t, async () => { throw Error('Failed save must not call Google'); });
  env.DB.failNextBusinessWrite = true;
  const failed = await callWithBackground('/api/estimates', env, jsonRequest(estimateInput));
  assert.ok(failed.response.status >= 400);
  await failed.context.drain();
  assert.equal(env.DB.sqlite.prepare('SELECT COUNT(*) AS n FROM records').get().n, 0);
  const queueExists = env.DB.sqlite.prepare('SELECT name FROM sqlite_schema WHERE name=? COLLATE NOCASE').get(JOBS);
  assert.equal(queueExists ? queueRows(env).length : 0, 0);
});

test('an accepted upload with a lost response is recovered by its marker without another upload', async t => {
  const env = setup(t);
  emptyBusinessFixture(env);
  const google = googleMock();
  replaceFetch(t, google.mock);
  assert.ok(isConnected(await callback(env, await connect(env))));
  google.state.ambiguousUpload = true;
  const created = await callWithBackground('/api/estimates', env, jsonRequest(estimateInput));
  assert.equal(created.response.status, 201);
  await created.context.drain();
  const attempted = queueRows(env);
  assert.equal(attempted.length, 1);
  assert.notEqual(attempted[0].status, 'complete');
  assert.equal(google.files.length, 2, 'Google accepted the automatic backup despite losing its response');
  const jobId = attempted[0].id;
  assert.equal(google.files[1].appProperties.backupJob, jobId);
  const uploadCount = google.uploads.length;
  env.DB.reopen();
  google.state.ambiguousUpload = false;
  await advanceRetryClock(t);
  await scheduledRetry(env);
  assert.equal(queueRows(env)[0].status, 'complete');
  assert.equal(google.uploads.length, uploadCount, 'Recovery must verify the accepted marker without issuing a new upload');
  const saved = JSON.parse(env.DB.sqlite.prepare('SELECT data FROM records WHERE id=?').get(created.data.estimate.id).data);
  assert.deepEqual(saved, created.data.estimate);
});

test('an uncertain upload without a visible receipt stays pending without uploading another copy', async t => {
  const env = setup(t);
  emptyBusinessFixture(env);
  const google = googleMock();
  replaceFetch(t, google.mock);
  assert.ok(isConnected(await callback(env, await connect(env))));
  google.state.ambiguousUpload = true;
  const created = await callWithBackground('/api/estimates', env, jsonRequest(estimateInput));
  assert.equal(created.response.status, 201);
  await created.context.drain();
  const uploadCount = google.uploads.length;
  assert.equal(google.files.length, 2);
  google.state.ambiguousUpload = false;
  google.state.hideMarkers = true;
  env.DB.reopen();
  await advanceRetryClock(t);
  await scheduledRetry(env);
  assert.equal(google.uploads.length, uploadCount, 'Missing receipt after an uncertain upload cannot authorize another upload');
  const job = queueRows(env)[0];
  assert.notEqual(job.status, 'complete');
  assert.equal(job.upload_state, 'unknown');
  const status = await (await fetchWorker(request('/api/google/status'), env)).json();
  assert.ok(status.pendingCount >= 1);
  assert.ok(status.unknownCount >= 1);
  assert.deepEqual(JSON.parse(env.DB.sqlite.prepare('SELECT data FROM records WHERE id=?').get(created.data.estimate.id).data), created.data.estimate);
});

test('queue schema collisions cannot mutate existing tables or prevent saving the business record', async t => {
  for (const name of [JOBS, JOBS.toUpperCase(), 'Superior_Drive_Backup_Jobs']) {
    await t.test(name, async t => {
      const env = setup(t);
      emptyBusinessFixture(env);
      env.DB.sqlite.exec(`CREATE TABLE ${name} (unrelated TEXT NOT NULL); INSERT INTO ${name} VALUES ('preserve this unrelated row')`);
      const before = env.DB.sqlite.prepare(`SELECT * FROM ${name}`).all();
      const schemaBefore = env.DB.sqlite.prepare('SELECT * FROM sqlite_schema ORDER BY name').all();
      replaceFetch(t, async () => { throw Error('Queue collision must not call Google'); });
      const created = await callWithBackground('/api/estimates', env, jsonRequest(estimateInput));
      assert.equal(created.response.status, 201);
      await created.context.drain();
      assert.equal(created.data.backup.status, 'unavailable');
      assert.deepEqual(env.DB.sqlite.prepare(`SELECT * FROM ${name}`).all(), before);
      assert.deepEqual(env.DB.sqlite.prepare('SELECT * FROM sqlite_schema ORDER BY name').all(), schemaBefore);
      assert.deepEqual(JSON.parse(env.DB.sqlite.prepare('SELECT data FROM records WHERE id=?').get(created.data.estimate.id).data), created.data.estimate);
      assert.deepEqual(env.DB.businessSchema(), env.DB.originalBusinessSchema);
    });
  }
});
