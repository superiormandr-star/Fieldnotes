import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// These are local Request objects passed directly to worker.fetch, never an
// outbound fetch to the live site. Scheduled backups bind encryption to this
// configured production origin, so the local authorization fixture must match.
export const ORIGIN = 'https://superior-command-center.superiormandr.workers.dev';
// A short existing signing secret is valid for the unchanged owner login. Drive
// encryption must use the independent dedicated key rather than rotating it.
export const SESSION_SECRET = 'existing-signing-key';
export const ENCRYPTION_SECRET = 'local-drive-encryption-secret-at-least-thirty-two-characters';
export const CLIENT_SECRET = 'local-google-client-secret';
export const REFRESH_TOKEN = 'local-google-refresh-token';
export const ACCESS_TOKEN = 'local-google-access-token';
export const OAUTH_COOKIE = '__Secure-superior_google_oauth';
export const TABLE = 'superior_google_oauth';
export const SCHEMA = `CREATE TABLE ${TABLE} (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`;

export const fixtures = {
  estimates: [
    { id: 'EST-2026-SAVED', customer: 'Existing customer', email: 'customer@example.test', phone: '555-0100', address: 'Original address', project: 'Saved estimate', items: [{ description: 'Original service', qty: 2, rate: 50.25, total: 100.5 }], notes: 'Preserve original notes', taxRate: 5, subtotal: 100.5, tax: 5.03, total: 105.53, status: 'approved', createdAt: '2026-01-02T03:04:05.000Z', reviewToken: 'a'.repeat(64), customerSignature: 'Existing customer', customField: { preserved: true } },
    { id: 'EST-2026-DRAFT', customer: 'Second customer', email: 'second@example.test', items: [{ description: 'Draft service', qty: 1, rate: 10, total: 10 }], total: 10, status: 'draft', createdAt: '2026-01-03T03:04:05.000Z' }
  ],
  invoices: [
    { id: 'INV-2026-SAVED', estimateId: 'EST-2026-SAVED', customer: 'Existing customer', items: [{ description: 'Original service', qty: 2, rate: 50.25, total: 100.5 }], total: 105.53, paymentStatus: 'unpaid', createdAt: '2026-01-02T04:04:05.000Z' }
  ],
  reviews: [
    { id: 'REV-2026-SAVED', estimateId: 'EST-2026-SAVED', customer: 'Existing customer', rating: 5, comment: 'Existing feedback', createdAt: '2026-01-03T03:04:05.000Z' }
  ]
};

// This D1 adapter executes actual SQLite statements. Unknown or invalid SQL fails;
// the tests do not simulate the implementation's schema checks or atomic writes.
export class LocalD1 {
  constructor() {
    this.directory = mkdtempSync(join(tmpdir(), 'superior-secure-drive-'));
    this.path = join(this.directory, 'records.sqlite');
    this.sqlite = new DatabaseSync(this.path);
    this.calls = [];
    this.hooks = {};
    for (const name of readdirSync(new URL('../migrations/', import.meta.url)).filter(name => name.endsWith('.sql')).sort()) this.sqlite.exec(readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8'));
    const addRecord = this.sqlite.prepare('INSERT INTO records VALUES (?, ?, ?, ?, ?, ?)');
    for (const [kind, list] of [['estimate', fixtures.estimates], ['invoice', fixtures.invoices]]) {
      for (const record of list) addRecord.run(record.id, kind, record.status || record.paymentStatus, record.createdAt, record.reviewToken || null, JSON.stringify(record));
    }
    for (const review of fixtures.reviews) this.sqlite.prepare('INSERT INTO customer_reviews VALUES (?, ?, ?, ?)').run(review.id, review.estimateId, review.createdAt, JSON.stringify(review));
    this.sqlite.prepare('INSERT INTO login_attempts VALUES (?, ?, ?)').run('192.0.2.10', 2, 1700000000000);
    this.originalBusinessRows = this.businessRows();
    this.originalBusinessSchema = this.businessSchema();
  }
  prepare(sql) {
    const database = this;
    return {
      sql,
      values: [],
      bind(...values) { return { ...this, values }; },
      async all() { return database.execute(this, 'all'); },
      async first(column) {
        const row = database.execute(this, 'first');
        if (database.hooks.afterRead) await database.hooks.afterRead(this.sql);
        return column && row ? row[column] : row;
      },
      async run() { return database.execute(this, 'run'); },
      async raw() { return database.execute(this, 'all').results.map(Object.values); }
    };
  }
  execute(command, mode) {
    this.calls.push({ sql: command.sql, values: command.values, mode });
    if (this.failNextBusinessWrite && /^\s*(?:INSERT\s+INTO|UPDATE)\s+records\b/i.test(command.sql)) {
      this.failNextBusinessWrite = false;
      throw Error('Synthetic business record commit outage');
    }
    const statement = this.sqlite.prepare(command.sql);
    if (mode === 'first') return statement.get(...command.values) || null;
    if (mode === 'all') return { success: true, results: statement.all(...command.values), meta: {} };
    const result = statement.run(...command.values);
    return { success: true, results: [], meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
  }
  async batch(commands) {
    if (this.failNextBatch) { this.failNextBatch = false; throw Error('Synthetic database commit outage'); }
    this.sqlite.exec('BEGIN');
    try {
      const results = commands.map(command => this.execute(command, /^\s*(?:SELECT|PRAGMA|WITH)\b|\bRETURNING\b/i.test(command.sql) ? 'all' : 'run'));
      this.sqlite.exec('COMMIT');
      return results;
    } catch (error) {
      this.sqlite.exec('ROLLBACK');
      throw error;
    }
  }
  async exec(sql) {
    this.calls.push({ sql, values: [], mode: 'exec' });
    this.sqlite.exec(sql);
    return { count: 1, duration: 0 };
  }
  businessRows() {
    return Object.fromEntries(['records', 'customer_reviews', 'login_attempts'].map(name => [name, this.sqlite.prepare(`SELECT * FROM ${name} ORDER BY 1`).all().map(row => ({ ...row }))]));
  }
  oauthRows() {
    return this.sqlite.prepare(`SELECT * FROM ${TABLE} ORDER BY key`).all();
  }
  businessSchema() {
    return this.sqlite.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name IN ('records','customer_reviews','login_attempts') ORDER BY name").all().map(row => ({ ...row }));
  }
  assertBusinessPreserved() {
    assert.deepEqual(this.businessRows(), this.originalBusinessRows);
    assert.deepEqual(this.businessSchema(), this.originalBusinessSchema);
    for (const call of this.calls) {
      if (/^\s*(?:INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP|CREATE)\b/i.test(call.sql)) {
        assert.doesNotMatch(call.sql, /\b(?:records|customer_reviews|login_attempts)\b/i, `Business table mutation: ${call.sql}`);
      }
    }
  }
  assertNoWrites() {
    for (const call of this.calls) assert.doesNotMatch(call.sql, /^\s*(?:INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP|CREATE)\b/i);
    this.assertBusinessPreserved();
  }
  reopen() { this.sqlite.close(); this.sqlite = new DatabaseSync(this.path); }
  close() { this.sqlite.close(); rmSync(this.directory, { recursive: true, force: true }); }
}

export function environment(database = new LocalD1()) {
  return {
    DB: database,
    OWNER_PASSWORD: 'local-owner-password',
    SESSION_SECRET,
    GOOGLE_OAUTH_ENCRYPTION_SECRET: ENCRYPTION_SECRET,
    GOOGLE_CLIENT_ID: 'local-client.apps.googleusercontent.com',
    GOOGLE_CLIENT_SECRET: CLIENT_SECRET,
    ASSETS: { fetch: async () => new Response('local asset') }
  };
}

export function sid(expiry = Date.now() + 60 * 60 * 1000) {
  const unsigned = `${expiry}.${'b'.repeat(32)}`;
  return `${unsigned}.${createHmac('sha256', SESSION_SECRET).update(unsigned).digest('hex')}`;
}

export function request(path, { method = 'GET', owner = true, session = sid(), cookies = '', headers = {}, body } = {}) {
  const cookie = [owner ? `superior_sid=${session}` : '', cookies].filter(Boolean).join('; ');
  return new Request(new URL(path, ORIGIN), { method, headers: { ...(cookie ? { Cookie: cookie } : {}), ...headers }, body });
}

export function cookieValue(response, name = OAUTH_COOKIE) {
  const cookies = response.headers.getSetCookie?.() || [response.headers.get('set-cookie') || ''];
  for (const cookie of cookies) {
    const match = new RegExp(`(?:^|,\\s*)${name}=([^;]*)`).exec(cookie);
    if (match) return match[1];
  }
  return null;
}

export function googleMock({ omitRefresh = false, uploadFails = false, accountId = 'local-google-account' } = {}) {
  const calls = [];
  const uploads = [];
  const files = [];
  let folderCreated = false;
  let tokenExchanges = 0;
  let refreshes = 0;
  const privateFolder = { id: 'private-folder', mimeType: 'application/vnd.google-apps.folder', shared: false, ownedByMe: true, trashed: false };
  const state = { unavailable: false, uploadFails, ambiguousUpload: false, hideMarkers: false };
  const mock = async (input, init) => {
    const req = input instanceof Request && !init ? input : new Request(input, init);
    const url = new URL(req.url);
    const body = await req.text();
    calls.push({ url, method: req.method, headers: new Headers(req.headers), body });
    if (state.unavailable) throw Error('Synthetic Google network outage');
    if (url.href === 'https://oauth2.googleapis.com/token') {
      const form = new URLSearchParams(body);
      assert.equal(form.get('client_id'), 'local-client.apps.googleusercontent.com');
      assert.equal(form.get('client_secret'), CLIENT_SECRET);
      if (form.get('grant_type') === 'authorization_code') {
        tokenExchanges++;
        assert.equal(form.get('redirect_uri'), `${ORIGIN}/api/google/callback`);
        assert.equal(form.get('code'), 'test-authorization-code');
        assert.match(form.get('code_verifier') || '', /^[A-Za-z0-9_-]{43,128}$/);
      } else {
        assert.equal(form.get('grant_type'), 'refresh_token');
        assert.equal(form.get('refresh_token'), REFRESH_TOKEN);
        refreshes++;
      }
      return Response.json({ access_token: ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600, scope: 'https://www.googleapis.com/auth/drive.file', ...(!omitRefresh && form.get('grant_type') === 'authorization_code' ? { refresh_token: REFRESH_TOKEN } : {}) });
    }
    assert.equal(url.origin, 'https://www.googleapis.com', 'Unexpected external request');
    assert.equal(req.headers.get('authorization'), `Bearer ${ACCESS_TOKEN}`);
    if (url.pathname === '/drive/v3/about' && req.method === 'GET') return Response.json({ user: { permissionId: accountId } });
    if (url.pathname === '/drive/v3/files/private-folder' && req.method === 'GET') return Response.json(privateFolder);
    if (url.pathname === '/drive/v3/files' && req.method === 'GET') {
      const query = url.searchParams.get('q') || '';
      if (!query.includes('application/vnd.google-apps.folder')) {
        const marker = /key\s*=\s*'backupJob'\s+and\s+value\s*=\s*'([^']+)'/.exec(query)?.[1];
        return Response.json({ files: marker && !state.hideMarkers ? files.filter(file => file.appProperties?.backupJob === marker) : [] });
      }
      return Response.json({ files: folderCreated ? [privateFolder] : [] });
    }
    if (url.pathname === '/drive/v3/files' && req.method === 'POST') {
      const metadata = JSON.parse(body);
      assert.equal(metadata.mimeType, 'application/vnd.google-apps.folder');
      folderCreated = true;
      return Response.json({ ...privateFolder, webViewLink: 'https://drive.google.com/drive/folders/private-folder' });
    }
    if (url.pathname === '/upload/drive/v3/files' && req.method === 'POST') {
      assert.equal(url.searchParams.get('uploadType'), 'multipart');
      assert.match(req.headers.get('content-type') || '', /^multipart\/related;\s*boundary=/i);
      const boundary = /boundary="?([^";\s]+)/i.exec(req.headers.get('content-type'))?.[1];
      const parts = body.split(`--${boundary}`).filter(part => /content-type:/i.test(part));
      const jsonParts = parts.map(part => JSON.parse(part.split(/\r?\n\r?\n/).slice(1).join('\r\n\r\n').trim()));
      assert.equal(jsonParts.length, 2);
      const metadata = jsonParts.find(part => part.parents);
      const backup = jsonParts.find(part => part.app);
      assert.deepEqual(metadata.parents, ['private-folder']);
      uploads.push({ metadata, backup });
      if (state.uploadFails) return Response.json({ error: { message: 'Upload rejected' } }, { status: 500 });
      const file = { ...metadata, id: `backup-${uploads.length}`, mimeType: 'application/json', shared: false, ownedByMe: true, trashed: false, size: String(Buffer.byteLength(JSON.stringify(backup))), createdTime: new Date().toISOString(), webViewLink: 'https://drive.google.com/file/d/private-backup/view', backup };
      files.push(file);
      if (state.ambiguousUpload) throw Error('Synthetic response loss after Google accepted the upload');
      return Response.json({ ...file, backup: undefined });
    }
    if (url.pathname.startsWith('/drive/v3/files/') && req.method === 'GET') {
      const file = files.find(file => file.id === url.pathname.split('/').pop());
      if (!file) return Response.json({ error: { message: 'Local fixture file not found' } }, { status: 404 });
      return url.searchParams.get('alt') === 'media' ? Response.json(file.backup) : Response.json({ ...file, backup: undefined });
    }
    throw Error(`Unexpected Google mock request: ${req.method} ${url.pathname}`);
  };
  return { mock, calls, uploads, files, state, get tokenExchanges() { return tokenExchanges; }, get refreshes() { return refreshes; } };
}

export function assertSnapshot(backup) {
  assert.deepEqual(Object.keys(backup).sort(), ['app', 'version', 'exportedAt', 'estimates', 'invoices', 'reviews'].sort());
  assert.equal(backup.app, 'Superior Maintenance and Remodeling - Command Center');
  assert.equal(backup.version, 1);
  assert.ok(Number.isFinite(Date.parse(backup.exportedAt)));
  assert.deepEqual(backup.estimates, [...fixtures.estimates].sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  assert.deepEqual(backup.invoices, fixtures.invoices);
  assert.deepEqual(backup.reviews, fixtures.reviews);
}
