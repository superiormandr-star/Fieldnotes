// Durable Drive-only delivery. Business records are always saved before enqueue;
// the scheduled reconciliation closes a crash or transient enqueue-failure gap.
import {backupToDrive, googleBackupStatus} from './google-oauth.js';

export const DRIVE_BACKUP_ORIGIN = 'https://superior-command-center.superiormandr.workers.dev';
const TABLE = 'superior_drive_backup_jobs';
const TABLE_SQL = `CREATE TABLE superior_drive_backup_jobs (
 id TEXT PRIMARY KEY,
 trigger TEXT NOT NULL,
 status TEXT NOT NULL,
 attempts INTEGER NOT NULL,
 next_attempt_at TEXT NOT NULL,
 created_at TEXT NOT NULL,
 completed_at TEXT,
 last_error TEXT,
 lease_token TEXT,
 upload_state TEXT NOT NULL
)`;
const MAX_ATTEMPTS = 8;
const LEASE_MS = 10 * 60 * 1000;
const NOTICE = 'Estimates and invoices are backed up automatically after saving. Pending backups are checked every 15 minutes. Unconfirmed uploads are checked before any retry.';
const STORAGE_ERROR = 'Automatic backup storage is unavailable. Your saved records are unchanged; check the backup connection and retry.';
const SCHEMA_ERROR = 'Automatic backup storage has a schema conflict. Your saved records are unchanged; contact support.';
const DELIVERY_ERROR = 'Google Drive backup did not finish. Automatic retry is pending.';
const UNKNOWN_ERROR = 'Google Drive upload is unconfirmed. Automatic checks will look for its receipt without uploading another copy.';
const EXHAUSTED_ERROR = 'Automatic backup needs attention after repeated failures. Check Google Drive, then choose Save backup now or retry pending backups.';
const stamp = () => new Date().toISOString();
const changeCount = (result) => Number(result?.meta?.changes || 0);
const encoder = new TextEncoder();
const storageFailure = (message = STORAGE_ERROR) => Object.assign(new Error(message), {queueStorage: true});

// Never reuse a namespaced collision, including differently cased tables,
// triggers, unexpected indexes, foreign keys, defaults, or altered SQL.
async function storage(env, create = false) {
 try {
  const entries = (await env.DB.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name=? COLLATE NOCASE OR tbl_name=? COLLATE NOCASE').bind(TABLE, TABLE).all()).results;
  if (!Array.isArray(entries)) throw storageFailure();
  if (!entries.length) {
   if (!create) return false;
   await env.DB.prepare(TABLE_SQL.replace('CREATE TABLE', 'CREATE TABLE IF NOT EXISTS')).run();
   if (!await storage(env)) throw storageFailure();
   return true;
  }
  const table = entries.find(row => row.type === 'table' && row.name === TABLE && row.tbl_name === TABLE);
  const normalize = sql => String(sql || '').replace(/\bIF\s+NOT\s+EXISTS\s+/i, '').replace(/\s+/g, ' ').trim().toLowerCase();
  if (!table || normalize(table.sql) !== normalize(TABLE_SQL) || entries.some(row => row !== table && !(row.type === 'index' && row.name === `sqlite_autoindex_${TABLE}_1` && row.tbl_name === TABLE && row.sql === null))) throw storageFailure(SCHEMA_ERROR);
  const [columns, foreignKeys] = await Promise.all([
   env.DB.prepare('PRAGMA table_info(superior_drive_backup_jobs)').all(),
   env.DB.prepare('PRAGMA foreign_key_list(superior_drive_backup_jobs)').all()
  ]);
  const expected = [['id','TEXT',0,1],['trigger','TEXT',1,0],['status','TEXT',1,0],['attempts','INTEGER',1,0],['next_attempt_at','TEXT',1,0],['created_at','TEXT',1,0],['completed_at','TEXT',0,0],['last_error','TEXT',0,0],['lease_token','TEXT',0,0],['upload_state','TEXT',1,0]];
  if (!Array.isArray(columns.results) || columns.results.length !== expected.length || !Array.isArray(foreignKeys.results) || foreignKeys.results.length || columns.results.some((column, i) => column.cid !== i || column.name !== expected[i][0] || String(column.type).toUpperCase() !== expected[i][1] || column.notnull !== expected[i][2] || column.pk !== expected[i][3] || column.dflt_value !== null)) throw storageFailure(SCHEMA_ERROR);
  return true;
 } catch (error) {
  throw error?.queueStorage ? error : storageFailure();
 }
}
async function eventId(kind, sourceId, data) {
 const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(`${kind}\n${sourceId}\n${data}`)));
 return 'drive-' + [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
}
async function enqueueRecord(env, {record, kind, trigger, data = JSON.stringify(record)}) {
 if (!record || !['estimate','invoice'].includes(kind) || typeof record.id !== 'string' || typeof data !== 'string') throw storageFailure();
 const id = await eventId(kind, record.id, data), createdAt = stamp();
 // The exact successful record must still exist. A lost concurrent approval or
 // payment update can never enqueue a phantom invoice or a fabricated version.
 const result = await env.DB.prepare(`INSERT INTO ${TABLE}(id,trigger,status,attempts,next_attempt_at,created_at,completed_at,last_error,lease_token,upload_state)
 SELECT ?,?,'pending',0,?,?,NULL,NULL,NULL,'pending'
 WHERE EXISTS(SELECT 1 FROM records WHERE id=? AND kind=? AND data=?)
 ON CONFLICT(id) DO NOTHING`).bind(id, trigger, createdAt, createdAt, record.id, kind, data).run();
 if (changeCount(result)) return {status:'queued'};
 const existing = await env.DB.prepare(`SELECT status FROM ${TABLE} WHERE id=?`).bind(id).first();
 return existing ? {status:existing.status === 'complete' ? 'complete' : 'queued'} : {status:'superseded'};
}
export async function enqueueDriveBackup(env, event) {
 try {
  await storage(env, true);
  return await enqueueRecord(env, event);
 } catch (error) {
  // A backup outage must never turn a successful document save into a failure.
  return {status:'unavailable', error:error?.queueStorage ? error.message : STORAGE_ERROR};
 }
}

export async function reconcileDriveBackups(env) {
 await storage(env, true);
 const rows = (await env.DB.prepare("SELECT id,kind,data FROM records WHERE kind IN ('estimate','invoice') ORDER BY created_at,id").all()).results;
 if (!Array.isArray(rows)) throw storageFailure();
 for (const row of rows) {
  let record;
  try { record = JSON.parse(row.data); } catch { throw storageFailure('A saved record could not be read for automatic backup. Contact support.'); }
  if (record?.id !== row.id) throw storageFailure('A saved record could not be verified for automatic backup. Contact support.');
  await enqueueRecord(env, {record, kind:row.kind, data:row.data, trigger:'saved-record-reconciled'});
 }
}

export async function driveBackupQueueStatus(env) {
 const empty = {automatic:true, pendingCount:0, failedCount:0, unknownCount:0, queueError:null, lastQueueError:null, notice:NOTICE};
 try {
  if (!await storage(env)) return empty;
  const counts = await env.DB.prepare(`SELECT COUNT(*) AS pending_count,
   COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0) AS failed_count,
   COALESCE(SUM(CASE WHEN upload_state='unknown' THEN 1 ELSE 0 END),0) AS unknown_count
   FROM ${TABLE} WHERE status<>'complete'`).first();
  const latest = await env.DB.prepare(`SELECT last_error FROM ${TABLE} WHERE status<>'complete' AND last_error IS NOT NULL ORDER BY created_at DESC,id DESC LIMIT 1`).first();
  return {...empty,pendingCount:Number(counts?.pending_count || 0),failedCount:Number(counts?.failed_count || 0),unknownCount:Number(counts?.unknown_count || 0),lastQueueError:latest?.last_error || null};
 } catch (error) {
  return {...empty,queueError:error?.queueStorage ? error.message : STORAGE_ERROR};
 }
}

export async function retryFailedDriveBackups(env) {
 if (!await storage(env)) return;
 // Preserve upload_state: an unconfirmed attempt may only recover a receipt.
 await env.DB.prepare(`UPDATE ${TABLE} SET status='pending',attempts=0,next_attempt_at=?,lease_token=NULL WHERE status='failed'`).bind(stamp()).run();
}

export async function completeCoveredDriveBackups(env, {through, savedAt}) {
 if (!await storage(env)) return;
 if (!Number.isFinite(Date.parse(through)) || !Number.isFinite(Date.parse(savedAt))) throw storageFailure();
 if (Date.parse(savedAt) < Date.parse(through)) return;
 // A manually requested, confirmed full snapshot covers every save queued
 // before it began. This also resolves an old unconfirmed delivery without
 // ever repeating that upload. Later saves keep their own pending jobs.
 await env.DB.prepare(`UPDATE ${TABLE} SET status='complete',completed_at=?,last_error=NULL,lease_token=NULL,upload_state='saved' WHERE status<>'complete' AND created_at<=?`).bind(savedAt, through).run();
}

export async function processDriveBackupQueue(env, {limit = 3, origin = DRIVE_BACKUP_ORIGIN} = {}) {
 if (!await storage(env)) return {completed:0};
 const connection = await googleBackupStatus(env, origin);
 if (!connection.configured || !connection.connected) return {completed:0, pending:true};
 const count = Math.min(10, Math.max(1, Math.floor(Number(limit) || 3)));
 const rows = (await env.DB.prepare(`SELECT id,status,attempts,next_attempt_at,upload_state FROM ${TABLE}
  WHERE status IN ('pending','unknown','processing') AND next_attempt_at<=? AND attempts<? ORDER BY created_at,id LIMIT ?`).bind(stamp(), MAX_ATTEMPTS, count).all()).results;
 if (!Array.isArray(rows)) throw storageFailure();
 let completed = 0;
 for (const row of rows) {
  const token = crypto.randomUUID(), attempts = Number(row.attempts) + 1;
  const recoverOnly = row.upload_state === 'unknown' || row.status === 'processing';
  const claimed = await env.DB.prepare(`UPDATE ${TABLE} SET status='processing',attempts=attempts+1,next_attempt_at=?,lease_token=?,upload_state='unknown'
   WHERE id=? AND status=? AND next_attempt_at=? AND attempts=?`).bind(new Date(Date.now()+LEASE_MS).toISOString(), token, row.id, row.status, row.next_attempt_at, row.attempts).run();
  if (!changeCount(claimed)) continue;
  try {
   const receipt = await backupToDrive(env, origin, {jobId:row.id, recoverOnly});
   if (!receipt || typeof receipt.filename !== 'string' || typeof receipt.savedAt !== 'string' || !Number.isFinite(Date.parse(receipt.savedAt))) throw Error('Unconfirmed upload.');
   const saved = await env.DB.prepare(`UPDATE ${TABLE} SET status='complete',completed_at=?,last_error=NULL,lease_token=NULL,upload_state='saved' WHERE id=? AND lease_token=? AND status='processing'`).bind(receipt.savedAt, row.id, token).run();
   completed += changeCount(saved);
  } catch (error) {
   // Unknown exceptions are conservative too. Even a worker crash leaves the
   // pre-upload unknown marker, so a later lease cannot blindly upload again.
   const ambiguous = recoverOnly || error?.ambiguous !== false;
   const exhausted = attempts >= MAX_ATTEMPTS;
   const delay = Math.min(6*60*60*1000, 60*1000 * 2 ** Math.min(attempts-1, 9));
   await env.DB.prepare(`UPDATE ${TABLE} SET status=?,next_attempt_at=?,last_error=?,lease_token=NULL,upload_state=? WHERE id=? AND lease_token=? AND status='processing'`).bind(exhausted ? 'failed' : ambiguous ? 'unknown' : 'pending', new Date(Date.now()+delay).toISOString(), exhausted ? EXHAUSTED_ERROR : ambiguous ? UNKNOWN_ERROR : DELIVERY_ERROR, ambiguous ? 'unknown' : 'pending', row.id, token).run();
  }
 }
 // A crashed final attempt must also remain visible as an attention item.
 await env.DB.prepare(`UPDATE ${TABLE} SET status='failed',last_error=?,lease_token=NULL WHERE status='processing' AND attempts>=? AND next_attempt_at<=?`).bind(EXHAUSTED_ERROR, MAX_ATTEMPTS, stamp()).run();
 return {completed};
}
