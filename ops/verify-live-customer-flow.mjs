// Authorized production smoke test. All mutations are limited to newly generated QA IDs.
// Customer rows and approval tokens stay in memory; only fixed check results are logged.
import {createHash,randomBytes,randomUUID} from 'node:crypto';
const site='https://superior-command-center.superiormandr.workers.dev';
const root='https://api.cloudflare.com/client/v4/accounts/c917ac1c9a3824a210d0fb77e5879329';
const fixtureId='EST-2026-QA-'+randomUUID().toUpperCase();
const reviewToken=randomBytes(32).toString('hex');
let invoiceId=null,created=false;
function check(condition,message){if(!condition){const error=Error(message);error.qaSafe=true;throw error;}}
async function db(sql,params=[]){
 const response=await fetch(root+'/d1/database/4feb6f63-1102-467a-87e6-256309364f12/query',{method:'POST',headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({sql,params}),signal:AbortSignal.timeout(20000)});
 const payload=await response.json();
 check(response.ok&&payload.success===true&&payload.result?.[0]?.success!==false,'Read/write QA query failed; no response contents logged.');
 return payload.result[0].results||[];
}
async function api(path,body){
 const response=await fetch(site+path,{method:body?'POST':'GET',headers:{Origin:site,'Content-Type':'application/json','Cache-Control':'no-cache'},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(20000),redirect:'error'});
 let data;try{data=await response.json();}catch{check(false,'Live QA endpoint returned an invalid response.');}
 return {status:response.status,data};
}
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function fingerprint(){
 const records=await db('SELECT id,kind,status,created_at,review_token,data FROM records ORDER BY id');
 const reviews=await db('SELECT id,estimate_id,created_at,data FROM customer_reviews ORDER BY id');
 return new Map([...records.map(r=>[hash(['record',r.id]),hash([r.id,r.kind,r.status,r.created_at,r.review_token,r.data])]),...reviews.map(r=>[hash(['review',r.id]),hash([r.id,r.estimate_id,r.created_at,r.data])])]);
}
try{
 const before=await fingerprint();
 check(!before.has(hash(['record',fixtureId])),'Generated QA record ID already exists; stopped.');
 const stamp=new Date().toISOString();
 const estimate={id:fixtureId,customer:'QA readiness test - not a customer',email:'qa@example.invalid',phone:'QA only',address:'QA only',project:'Automated live readiness smoke test',items:[{description:'QA only - no billable work',qty:1,rate:0,total:0}],subtotal:0,tax:0,taxRate:0,total:0,notes:'Temporary automated QA fixture; not a business transaction.',createdAt:stamp,status:'sent',reviewToken};
 try{
  created=true;
  await db('INSERT INTO records(id,kind,status,created_at,review_token,data) VALUES(?,?,?,?,?,?)',[fixtureId,'estimate','sent',stamp,reviewToken,JSON.stringify(estimate)]);
  let result=await api('/api/review/'+reviewToken);
  check(result.status===200&&result.data.estimate?.id===fixtureId,'Live customer estimate could not be read.');
  check(!['email','phone','reviewToken','customerSignature'].some(key=>Object.hasOwn(result.data.estimate,key)),'Public customer review exposed a private field.');
  result=await api('/api/review/'+reviewToken+'/decision',{decision:'approved',signature:'QA automated tester',note:'QA only - automated approval test'});
  check(result.status===200&&typeof result.data.invoiceId==='string','Live customer approval did not create an invoice.');
  invoiceId=result.data.invoiceId;
  const invoices=await db("SELECT id,data FROM records WHERE kind='invoice' AND json_extract(data,'$.estimateId')=?",[fixtureId]);
  check(invoices.length===1&&invoices[0].id===invoiceId,'Live approval must create exactly one related invoice.');
  const invoice=JSON.parse(invoices[0].data);
  check(invoice.customer===estimate.customer&&invoice.email===estimate.email&&invoice.total===0&&invoice.paymentStatus==='unpaid','Live invoice did not preserve expected fixture details.');
  result=await api('/api/review/'+reviewToken+'/decision',{decision:'approved',signature:'QA automated tester'});
  check(result.status===409,'Duplicate customer approval was not rejected.');
  result=await api('/api/review/'+reviewToken+'/feedback',{rating:5,comment:'Temporary automated QA feedback - not a customer review.'});
  check(result.status===201,'Live customer feedback did not save.');
  result=await api('/api/review/'+reviewToken);
  check(result.status===200&&result.data.estimate?.status==='approved'&&result.data.feedback?.rating===5,'Live approval or feedback did not persist across HTTP requests.');
  const duplicates=await db("SELECT COUNT(*) AS count FROM records WHERE kind='invoice' AND json_extract(data,'$.estimateId')=?",[fixtureId]);
  check(duplicates[0]?.count===1,'Duplicate customer approval created multiple invoices.');
  console.log('PASS live: estimate review, private-field protection, customer approval, one invoice, duplicate-approval rejection, customer feedback, and persisted results across HTTP requests.');
 }finally{
  if(created){
   // Discover only invoices belonging to this generated QA estimate if a request failed before returning an ID.
   const related=await db("SELECT id FROM records WHERE kind='invoice' AND json_extract(data,'$.estimateId')=?",[fixtureId]);
   for(const row of related){
    await db('DELETE FROM backup_runs WHERE id=?',['invoice-'+row.id]);
    await db("DELETE FROM records WHERE id=? AND kind='invoice' AND json_extract(data,'$.estimateId')=?",[row.id,fixtureId]);
   }
   await db('DELETE FROM customer_reviews WHERE estimate_id=?',[fixtureId]);
   await db("DELETE FROM records WHERE id=? AND kind='estimate' AND review_token=?",[fixtureId,reviewToken]);
   console.log('Temporary QA estimate, invoice, feedback, and their queued backup entries removed. Existing customer IDs were never targeted.');
  }
 }
 const after=await fingerprint();
 check(before.size===after.size&&[...before].every(([id,digest])=>after.get(id)===digest),'Existing business records changed during the QA test.');
 console.log('PASS: all '+before.size+' existing business records are unchanged after live QA cleanup.');
}catch(error){console.error(error.qaSafe?error.message:'Live QA failed; sensitive request and response details suppressed.');process.exitCode=1;}
