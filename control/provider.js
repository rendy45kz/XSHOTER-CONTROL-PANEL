'use strict';
const path=require('node:path');

module.exports = function initProvider(ctx){
 const {db,json,readBody,needAuth,needCSRF,ownerOnly,audit,passHash,now,agent}=ctx;
 db.exec(`
 CREATE TABLE IF NOT EXISTS hosting_plans(
  id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,price_monthly INTEGER NOT NULL DEFAULT 0,
  disk_mb INTEGER NOT NULL DEFAULT 500,bandwidth_mb INTEGER NOT NULL DEFAULT 0,
  cpu_percent INTEGER NOT NULL DEFAULT 100,memory_mb INTEGER NOT NULL DEFAULT 512,processes INTEGER NOT NULL DEFAULT 64,
  domains INTEGER NOT NULL DEFAULT 1,subdomains INTEGER NOT NULL DEFAULT 5,databases INTEGER NOT NULL DEFAULT 2,
  email_accounts INTEGER NOT NULL DEFAULT 2,email_aliases INTEGER NOT NULL DEFAULT 5,ftp_accounts INTEGER NOT NULL DEFAULT 1,cron_jobs INTEGER NOT NULL DEFAULT 2,
  backups INTEGER NOT NULL DEFAULT 2,node_apps INTEGER NOT NULL DEFAULT 0,python_apps INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS hosting_accounts(
  id INTEGER PRIMARY KEY,user_id INTEGER UNIQUE NOT NULL,plan_id INTEGER NOT NULL,linux_user TEXT UNIQUE NOT NULL,
  primary_domain TEXT,status TEXT NOT NULL DEFAULT 'active',expires_at INTEGER NOT NULL DEFAULT 0,
  provision_state TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(plan_id) REFERENCES hosting_plans(id));
 CREATE TABLE IF NOT EXISTS hosting_resources(
  id INTEGER PRIMARY KEY,account_id INTEGER NOT NULL,type TEXT NOT NULL,name TEXT NOT NULL,created_at INTEGER NOT NULL,
  UNIQUE(type,name),FOREIGN KEY(account_id) REFERENCES hosting_accounts(id) ON DELETE CASCADE);
 `);
 const planCols=new Set(db.prepare('PRAGMA table_info(hosting_plans)').all().map(x=>x.name));
 if(!planCols.has('email_aliases'))db.exec("ALTER TABLE hosting_plans ADD COLUMN email_aliases INTEGER NOT NULL DEFAULT 5");
 if(!planCols.has('cpu_percent'))db.exec("ALTER TABLE hosting_plans ADD COLUMN cpu_percent INTEGER NOT NULL DEFAULT 100");
 if(!planCols.has('memory_mb'))db.exec("ALTER TABLE hosting_plans ADD COLUMN memory_mb INTEGER NOT NULL DEFAULT 512");
 if(!planCols.has('processes'))db.exec("ALTER TABLE hosting_plans ADD COLUMN processes INTEGER NOT NULL DEFAULT 64");
 const acctCols=new Set(db.prepare('PRAGMA table_info(hosting_accounts)').all().map(x=>x.name));
 if(!acctCols.has('provision_error'))db.exec("ALTER TABLE hosting_accounts ADD COLUMN provision_error TEXT NOT NULL DEFAULT ''");
 const resCols=new Set(db.prepare('PRAGMA table_info(hosting_resources)').all().map(x=>x.name));
 if(!resCols.has('meta'))db.exec("ALTER TABLE hosting_resources ADD COLUMN meta TEXT NOT NULL DEFAULT '{}'");
 const defaults={provider_name:'Xshoter Hosting',support_email:'',currency:'IDR',web_listen:process.env.XSHOTER_WEB_LISTEN||'80',tunnel_origin:process.env.XSHOTER_TUNNEL_ORIGIN||'http://127.0.0.1:80',default_php:process.env.XSHOTER_DEFAULT_PHP||'',auto_cloudflare:'1',primary_domain:'',installers_enabled:'1',upload_max_mb:'128',domain_aliases:'{}'};
 const set=db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
 const get=db.prepare('SELECT value FROM settings WHERE key=?');
 for(const [k,v] of Object.entries(defaults)){if(!get.get('provider_'+k))set.run('provider_'+k,v)}
 const settings=()=>Object.fromEntries(Object.keys(defaults).map(k=>[k,get.get('provider_'+k)?.value??defaults[k]]));
 const saveSettings=o=>{for(const k of Object.keys(defaults)){if(Object.prototype.hasOwnProperty.call(o,k))set.run('provider_'+k,String(o[k]??''))}};
 const uname=/^[a-zA-Z0-9_.-]{3,32}$/;
 const linux=/^[a-z_][a-z0-9_-]{2,30}$/;
 const domain=/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
 const num=(v,min,max)=>{const n=Number(v);return Number.isInteger(n)&&n>=min&&n<=max?n:null};
 function planBody(b){
  const o={name:String(b.name||'').trim(),price_monthly:num(b.price_monthly,0,1000000000),disk_mb:num(b.disk_mb,50,1048576),bandwidth_mb:num(b.bandwidth_mb,0,1073741824),cpu_percent:num(b.cpu_percent,10,6400),memory_mb:num(b.memory_mb,64,1048576),processes:num(b.processes,8,100000),domains:num(b.domains,1,1000),subdomains:num(b.subdomains,0,10000),databases:num(b.databases,0,10000),email_accounts:0,email_aliases:0,ftp_accounts:num(b.ftp_accounts,0,10000),cron_jobs:num(b.cron_jobs,0,10000),backups:num(b.backups,0,10000),node_apps:num(b.node_apps,0,1000),python_apps:num(b.python_apps,0,1000),active:b.active===false?0:1};
  if(o.name.length<2||o.name.length>64||Object.values(o).some(v=>v===null))return null;return o;
 }

 async function provisionAccount(a){
  const exp=Number(a.expires_at||0),effectiveStatus=String(a.status||'active')==='suspended'||(exp>0&&exp<=now())?'suspended':'active';
  const r=await agent('POST','/v1/hosting-provision',{user:a.linux_user,disk_mb:Number(a.disk_mb),sftp_enabled:Number(a.ftp_accounts||0)>0,status:effectiveStatus,cpu_percent:Number(a.cpu_percent||100),memory_mb:Number(a.memory_mb||512),processes:Number(a.processes||64)}).catch(e=>({status:502,data:{ok:false,error:e.message}}));
  if(r.data?.ok){
   const bw=await agent('POST','/v1/hosting-bandwidth',{user:a.linux_user,limit_mb:Number(a.bandwidth_mb||0)}).catch(e=>({status:502,data:{ok:false,error:e.message}}));
   if(!bw.data?.ok){const err=String(bw.data?.error||'bandwidth enforcement failed').slice(0,500);db.prepare("UPDATE hosting_accounts SET provision_state='error',provision_error=?,updated_at=? WHERE id=?").run(err,now(),a.id);return {ok:false,error:err}}
   if(effectiveStatus!==String(a.status||'active')){db.prepare('UPDATE hosting_accounts SET status=?,updated_at=? WHERE id=?').run(effectiveStatus,now(),a.id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(a.user_id)}db.prepare("UPDATE hosting_accounts SET provision_state='ready',provision_error='',updated_at=? WHERE id=?").run(now(),a.id);if(Number(a.ftp_accounts||0)>0)db.prepare("INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?) ON CONFLICT(type,name) DO UPDATE SET meta=excluded.meta").run(a.id,'ftp',a.linux_user,JSON.stringify({primary:true}),now());else db.prepare("DELETE FROM hosting_resources WHERE account_id=? AND type='ftp' AND name=?").run(a.id,a.linux_user);return {...r.data,status:effectiveStatus,bandwidth:bw.data}
  }
  const err=String(r.data?.error||'provision failed').slice(0,500);db.prepare("UPDATE hosting_accounts SET provision_state='error',provision_error=?,updated_at=? WHERE id=?").run(err,now(),a.id);return {ok:false,error:err}
 }
 async function bandwidthUsage(a){
  const expected=Number(a.bandwidth_mb||0),fallback={used_bytes:0,limit_bytes:expected*1048576,limit_mb:expected,over:false,month:''};
  if(a.provision_state!=='ready')return fallback;
  let r=await agent('GET','/v1/hosting-bandwidth?user='+encodeURIComponent(a.linux_user),null).catch(()=>null);
  if(!r?.data?.ok||Number(r.data.limit_mb||0)!==expected)r=await agent('POST','/v1/hosting-bandwidth',{user:a.linux_user,limit_mb:expected}).catch(()=>null);
  return r?.data?.ok?r.data:fallback
 }
 async function usageFor(a){
  if(a.provision_state!=='ready')return {used_bytes:0,home_used_bytes:0,database_used_bytes:0,disk_limit_bytes:Number(a.disk_mb||0)*1048576,hard_quota:false,quota_mode:'soft',over_quota:false};
  const r=await agent('GET','/v1/hosting-usage?user='+encodeURIComponent(a.linux_user),null).catch(()=>null);const base=r?.data?.ok?r.data:{used_bytes:0,disk_limit_bytes:Number(a.disk_mb||0)*1048576,hard_quota:false,quota_mode:'soft'};let dbBytes=0;
  const names=new Set(db.prepare("SELECT name FROM hosting_resources WHERE account_id=? AND type='database'").all(a.id).map(x=>x.name));if(names.size){const dr=await agent('GET','/v1/databases',null).catch(()=>null);if(dr?.data?.ok)for(const x of dr.data.items||[])if(names.has(x.name))dbBytes+=Number(x.size||0)}
  const home=Number(base.used_bytes||0),limit=Number(base.disk_limit_bytes||a.disk_mb*1048576),total=home+dbBytes;return {...base,home_used_bytes:home,database_used_bytes:dbBytes,used_bytes:total,disk_limit_bytes:limit,over_quota:limit>0&&total>limit}
 }
 const resourceColumns={domain:'domains',subdomain:'subdomains',database:'databases',ftp:'ftp_accounts',cron:'cron_jobs',backup:'backups',node:'node_apps',python:'python_apps'};
 function resourceUsage(accountId){return Object.fromEntries(Object.keys(resourceColumns).map(k=>[k,Number(db.prepare('SELECT count(*) n FROM hosting_resources WHERE account_id=? AND type=?').get(accountId,k).n||0)]))}
 function quotaSnapshot(a,usage){const limits=Object.fromEntries(Object.entries(resourceColumns).map(([k,col])=>[k,Number(a[col]||0)]));const allowed=Object.fromEntries(Object.keys(limits).map(k=>[k,limits[k]===0?false:Number(usage[k]||0)<limits[k]]));return {limits,usage,allowed}}
 function resourceTypeForDomain(a,host){const roots=[];if(a.primary_domain)roots.push(String(a.primary_domain).toLowerCase());for(const r of db.prepare("SELECT name FROM hosting_resources WHERE account_id=? AND type='domain'").all(a.id))roots.push(String(r.name).toLowerCase());return roots.some(root=>host!==root&&host.endsWith('.'+root))?'subdomain':'domain'}
 function resourceCapacity(a,type){const col=resourceColumns[type];if(!col)return {ok:false,used:0,limit:0};const used=Number(db.prepare('SELECT count(*) n FROM hosting_resources WHERE account_id=? AND type=?').get(a.id,type).n||0),limit=Number(a[col]||0);return {ok:limit>0&&used<limit,used,limit}}
 function ownedWebPath(a,p){const base=path.resolve('/home',a.linux_user,'web'),x=path.resolve(String(p||''));if(x!==base&&!x.startsWith(base+path.sep))return null;const rel=path.relative(base,x),parts=rel.split(path.sep);if(parts.length<2||parts[1]!=='public_html')return null;const host=parts[0];const own=db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND name=? AND type IN ('domain','subdomain')").get(a.id,host);return own?x:null}

 function accountRow(userId){return db.prepare(`SELECT a.*,p.name plan_name,p.disk_mb,p.bandwidth_mb,p.cpu_percent,p.memory_mb,p.processes,p.domains,p.subdomains,p.databases,p.email_accounts,p.email_aliases,p.ftp_accounts,p.cron_jobs,p.backups,p.node_apps,p.python_apps,u.username FROM hosting_accounts a JOIN hosting_plans p ON p.id=a.plan_id JOIN users u ON u.id=a.user_id WHERE a.user_id=?`).get(userId)}
 let expiryBusy=false;
 async function enforceExpiredAccounts(){
  if(expiryBusy)return;expiryBusy=true;
  try{const rows=db.prepare("SELECT id,user_id,linux_user FROM hosting_accounts WHERE status='active' AND expires_at>0 AND expires_at<=?").all(now());for(const a of rows){const r=await agent('POST','/v1/hosting-control',{user:a.linux_user,status:'suspended'}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){console.error('[HOSTING EXPIRY] suspend failed',a.id,r.data?.error||r.status);continue}db.prepare("UPDATE hosting_accounts SET status='suspended',updated_at=? WHERE id=?").run(now(),a.id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(a.user_id);db.prepare('INSERT INTO audit(actor,action,target,ip,created_at) VALUES(?,?,?,?,?)').run('system','hosting_account_expired',String(a.id),'127.0.0.1',now())}}
  finally{expiryBusy=false}
 }
 setTimeout(()=>enforceExpiredAccounts().catch(()=>{}),5000).unref();setInterval(()=>enforceExpiredAccounts().catch(()=>{}),60000).unref();
 let bandwidthBusy=false;
 async function refreshBandwidthAccounts(){if(bandwidthBusy)return;bandwidthBusy=true;try{const rows=db.prepare(`SELECT a.id,a.linux_user,a.provision_state,p.bandwidth_mb FROM hosting_accounts a JOIN hosting_plans p ON p.id=a.plan_id WHERE a.provision_state='ready'`).all();for(const a of rows){const r=await agent('POST','/v1/hosting-bandwidth',{user:a.linux_user,limit_mb:Number(a.bandwidth_mb||0)}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok)console.error('[HOSTING BANDWIDTH] refresh failed',a.id,r.data?.error||r.status)}}finally{bandwidthBusy=false}}
 setTimeout(()=>refreshBandwidthAccounts().catch(()=>{}),10000).unref();setInterval(()=>refreshBandwidthAccounts().catch(()=>{}),60000).unref();
 let resourceBusy=false;
 async function refreshResourceAccounts(){if(resourceBusy)return;resourceBusy=true;try{const rows=db.prepare(`SELECT a.id,a.linux_user,p.cpu_percent,p.memory_mb,p.processes FROM hosting_accounts a JOIN hosting_plans p ON p.id=a.plan_id WHERE a.provision_state='ready'`).all();for(const a of rows){const r=await agent('POST','/v1/hosting-resources',{user:a.linux_user,cpu_percent:Number(a.cpu_percent||100),memory_mb:Number(a.memory_mb||512),processes:Number(a.processes||64)}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok)console.error('[HOSTING RESOURCES] refresh failed',a.id,r.data?.error||r.status)}}finally{resourceBusy=false}}
 setTimeout(()=>refreshResourceAccounts().catch(()=>{}),12000).unref();setInterval(()=>refreshResourceAccounts().catch(()=>{}),60000).unref();
 return async function providerRoute(req,res,u){
  if(u.pathname==='/api/provider/settings'){
   const s=needAuth(req,res);if(!s||!ownerOnly(res,s))return true;
   if(req.method==='GET'){json(res,200,{ok:true,settings:settings()});return true}
   if(req.method==='POST'){
    if(!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null);if(!b){json(res,400,{ok:false,error:'invalid json'});return true}
    const clean={provider_name:String(b.provider_name||'').trim().slice(0,80),support_email:String(b.support_email||'').trim().slice(0,160),currency:String(b.currency||'IDR').trim().toUpperCase().slice(0,8),web_listen:String(b.web_listen||'').trim().slice(0,80),tunnel_origin:String(b.tunnel_origin||'').trim().slice(0,240),default_php:/^[0-9]+\.[0-9]+$/.test(String(b.default_php||''))?String(b.default_php):settings().default_php,auto_cloudflare:b.auto_cloudflare?'1':'0',primary_domain:String(b.primary_domain||'').trim().toLowerCase().replace(/\.$/,''),installers_enabled:b.installers_enabled?'1':'0',upload_max_mb:String(num(b.upload_max_mb,1,128)??num(settings().upload_max_mb,1,128)??128),domain_aliases:String(b.domain_aliases||'{}').trim().slice(0,12000)};
    try{const aliases=JSON.parse(clean.domain_aliases);if(!aliases||Array.isArray(aliases)||typeof aliases!=='object'||Object.entries(aliases).some(([k,v])=>!domain.test(k)||!domain.test(String(v))))throw new Error()}catch{json(res,400,{ok:false,error:'invalid domain aliases json'});return true}
    if(!clean.provider_name||!clean.web_listen||!/^https?:\/\/[^\s]+$/i.test(clean.tunnel_origin)||(clean.primary_domain&&!domain.test(clean.primary_domain))){json(res,400,{ok:false,error:'invalid provider settings'});return true}
    saveSettings(clean);audit(s.username,'provider_settings','hosting',req);json(res,200,{ok:true,settings:settings()});return true
   }
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/plans'){
   const s=needAuth(req,res);if(!s||!ownerOnly(res,s))return true;
   if(req.method==='GET'){json(res,200,{ok:true,items:db.prepare('SELECT * FROM hosting_plans ORDER BY active DESC,price_monthly,id').all()});return true}
   if(!needCSRF(req,res,s))return true;
   const b=await readBody(req).catch(()=>null);const p=b&&planBody(b);if(!p){json(res,400,{ok:false,error:'invalid hosting plan'});return true}
   if(req.method==='POST'){
    try{const t=now();const r=db.prepare(`INSERT INTO hosting_plans(name,price_monthly,disk_mb,bandwidth_mb,cpu_percent,memory_mb,processes,domains,subdomains,databases,email_accounts,email_aliases,ftp_accounts,cron_jobs,backups,node_apps,python_apps,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(p.name,p.price_monthly,p.disk_mb,p.bandwidth_mb,p.cpu_percent,p.memory_mb,p.processes,p.domains,p.subdomains,p.databases,p.email_accounts,p.email_aliases,p.ftp_accounts,p.cron_jobs,p.backups,p.node_apps,p.python_apps,p.active,t,t);audit(s.username,'hosting_plan_create',p.name,req);json(res,201,{ok:true,id:Number(r.lastInsertRowid)});return true}catch(e){json(res,409,{ok:false,error:'plan name already exists'});return true}
   }
   if(req.method==='PATCH'){
    const id=num(u.searchParams.get('id'),1,2147483647);if(!id){json(res,400,{ok:false,error:'invalid plan id'});return true}
    const r=db.prepare(`UPDATE hosting_plans SET name=?,price_monthly=?,disk_mb=?,bandwidth_mb=?,cpu_percent=?,memory_mb=?,processes=?,domains=?,subdomains=?,databases=?,email_accounts=?,email_aliases=?,ftp_accounts=?,cron_jobs=?,backups=?,node_apps=?,python_apps=?,active=?,updated_at=? WHERE id=?`).run(p.name,p.price_monthly,p.disk_mb,p.bandwidth_mb,p.cpu_percent,p.memory_mb,p.processes,p.domains,p.subdomains,p.databases,p.email_accounts,p.email_aliases,p.ftp_accounts,p.cron_jobs,p.backups,p.node_apps,p.python_apps,p.active,now(),id);if(!r.changes){json(res,404,{ok:false,error:'plan not found'});return true}
    const linked=db.prepare('SELECT * FROM hosting_accounts WHERE plan_id=?').all(id);let synced=0,sync_errors=0;for(const a of linked){const pr=await provisionAccount({...a,disk_mb:p.disk_mb,bandwidth_mb:p.bandwidth_mb,cpu_percent:p.cpu_percent,memory_mb:p.memory_mb,processes:p.processes,ftp_accounts:p.ftp_accounts});if(pr.ok)synced++;else sync_errors++}
    audit(s.username,'hosting_plan_update',String(id),req);json(res,200,{ok:true,synced,sync_errors});return true
   }
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/accounts'){
   const s=needAuth(req,res);if(!s||!ownerOnly(res,s))return true;
   if(req.method==='GET'){const items=db.prepare(`SELECT a.*,u.username,p.name plan_name,p.disk_mb,p.bandwidth_mb,p.cpu_percent,p.memory_mb,p.processes,p.domains,p.subdomains,p.databases,p.email_accounts,p.email_aliases,p.ftp_accounts,p.cron_jobs,p.backups,p.node_apps,p.python_apps FROM hosting_accounts a JOIN users u ON u.id=a.user_id JOIN hosting_plans p ON p.id=a.plan_id ORDER BY a.id DESC`).all();for(const x of items){const q=await usageFor(x),bw=await bandwidthUsage(x),ru=resourceUsage(x.id),qs=quotaSnapshot(x,ru);x.used_bytes=Number(q.used_bytes||0);x.disk_limit_bytes=Number(q.disk_limit_bytes||x.disk_mb*1048576);x.hard_quota=!!q.hard_quota;x.quota_mode=q.quota_mode||'soft';x.over_quota=!!q.over_quota;x.bandwidth_used_bytes=Number(bw.used_bytes||0);x.bandwidth_limit_bytes=Number(bw.limit_bytes??Number(x.bandwidth_mb||0)*1048576);x.bandwidth_over=!!bw.over;x.bandwidth_month=String(bw.month||'');x.resource_usage=ru;x.resource_limits=qs.limits}json(res,200,{ok:true,items});return true}
   if(req.method==='POST'){
    if(!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null);if(!b||!uname.test(String(b.username||''))||String(b.password||'').length<10||!linux.test(String(b.linux_user||''))){json(res,400,{ok:false,error:'invalid hosting account'});return true}
    const planId=num(b.plan_id,1,2147483647),plan=planId&&db.prepare('SELECT id FROM hosting_plans WHERE id=? AND active=1').get(planId);const primary=String(b.primary_domain||'').trim().toLowerCase().replace(/\.$/,'');const expires=num(b.expires_at??0,0,4102444800),initialStatus=String(b.status||'active')==='suspended'?'suspended':'active';if(!plan||(primary&&!domain.test(primary))||expires===null||(initialStatus==='active'&&expires>0&&expires<=now())){json(res,400,{ok:false,error:'invalid plan/domain/expiry'});return true}
    try{db.exec('BEGIN IMMEDIATE');const t=now();const ur=db.prepare('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)').run(String(b.username),passHash(String(b.password)),'client',t);const ar=db.prepare('INSERT INTO hosting_accounts(user_id,plan_id,linux_user,primary_domain,status,expires_at,provision_state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)').run(Number(ur.lastInsertRowid),planId,String(b.linux_user),primary,initialStatus,expires,'pending',t,t);db.exec('COMMIT');const a=db.prepare(`SELECT a.*,p.disk_mb,p.bandwidth_mb,p.cpu_percent,p.memory_mb,p.processes,p.ftp_accounts FROM hosting_accounts a JOIN hosting_plans p ON p.id=a.plan_id WHERE a.id=?`).get(Number(ar.lastInsertRowid));const pr=await provisionAccount(a);audit(s.username,'hosting_account_create',String(b.username),req);json(res,201,{ok:true,id:Number(ar.lastInsertRowid),provision_state:pr.ok?'ready':'error',provision_error:pr.ok?'':pr.error});return true}catch(e){try{db.exec('ROLLBACK')}catch{}json(res,409,{ok:false,error:'username or linux user already exists'});return true}
   }
   if(req.method==='PATCH'){
    if(!needCSRF(req,res,s))return true;const id=num(u.searchParams.get('id'),1,2147483647);const b=await readBody(req).catch(()=>null);const a=id&&db.prepare('SELECT * FROM hosting_accounts WHERE id=?').get(id);if(!a||!b){json(res,404,{ok:false,error:'hosting account not found'});return true}
    const planId=num(b.plan_id||a.plan_id,1,2147483647);if(!db.prepare('SELECT id FROM hosting_plans WHERE id=?').get(planId)){json(res,400,{ok:false,error:'invalid plan'});return true}
    if(String(b.action||'')==='provision'){const aa=db.prepare(`SELECT a.*,p.disk_mb,p.bandwidth_mb,p.cpu_percent,p.memory_mb,p.processes,p.ftp_accounts FROM hosting_accounts a JOIN hosting_plans p ON p.id=a.plan_id WHERE a.id=?`).get(id);const pr=await provisionAccount(aa);audit(s.username,'hosting_account_provision',String(id),req);json(res,pr.ok?200:502,{ok:!!pr.ok,provision_state:pr.ok?'ready':'error',error:pr.error||''});return true}
    const status=['active','suspended'].includes(String(b.status))?String(b.status):a.status;const expires=num(b.expires_at??a.expires_at,0,4102444800);if(expires===null){json(res,400,{ok:false,error:'invalid expiry'});return true}if(status==='active'&&expires>0&&expires<=now()){json(res,409,{ok:false,error:'extend or clear expiry before activating this account'});return true}db.prepare('UPDATE hosting_accounts SET plan_id=?,status=?,expires_at=?,updated_at=? WHERE id=?').run(planId,status,expires,now(),id);if(status!=='active')db.prepare('DELETE FROM sessions WHERE user_id=?').run(a.user_id);
    const ctl=await agent('POST','/v1/hosting-control',{user:a.linux_user,status}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!ctl.data?.ok){json(res,502,{ok:false,error:ctl.data?.error||'hosting status sync failed'});return true}
    let pr={ok:true};if(planId!==a.plan_id){const aa=db.prepare(`SELECT a.*,p.disk_mb,p.bandwidth_mb,p.cpu_percent,p.memory_mb,p.processes,p.ftp_accounts FROM hosting_accounts a JOIN hosting_plans p ON p.id=a.plan_id WHERE a.id=?`).get(id);pr=await provisionAccount(aa)}
    audit(s.username,'hosting_account_update',String(id),req);json(res,pr.ok?200:502,{ok:!!pr.ok,provision_state:pr.ok?'ready':'error',error:pr.error||''});return true
   }
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/runtimes'&&req.method==='GET'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'&&s.role!=='owner'){json(res,403,{ok:false,error:'hosting access required'});return true}const r=await agent('GET','/v1/runtimes',null).catch(e=>({status:502,data:{ok:false,error:e.message}}));json(res,r.status,r.data);return true
  }
  if(u.pathname==='/api/hosting/websites'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}
   const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   if(req.method==='GET'){
    const r=await agent('GET','/v1/websites',null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){json(res,r.status,r.data);return true}
    const owned=new Map(db.prepare("SELECT type,name,meta,created_at FROM hosting_resources WHERE account_id=? AND type IN ('domain','subdomain')").all(a.id).map(x=>[x.name,x]));const items=(r.data.items||[]).filter(x=>x.owner===a.linux_user&&owned.has(x.domain)).map(x=>({...x,resource_type:owned.get(x.domain).type}));const usage=resourceUsage(a.id),qs=quotaSnapshot(a,usage);json(res,200,{ok:true,items,usage,limits:qs.limits,allowed:qs.allowed});return true
   }
   if(req.method==='POST'){
    if(!needCSRF(req,res,s))return true;if(a.provision_state!=='ready'){json(res,409,{ok:false,error:'hosting account is not provisioned'});return true}const b=await readBody(req).catch(()=>null);const host=String(b?.domain||'').trim().toLowerCase().replace(/\.$/,'');const php=String(b?.php||settings().default_php||'').trim();if(!b||!domain.test(host)||!/^[0-9]+\.[0-9]+$/.test(php)){json(res,400,{ok:false,error:'invalid domain/php'});return true}
    if(db.prepare('SELECT id FROM hosting_resources WHERE name=?').get(host)){json(res,409,{ok:false,error:'domain already assigned'});return true}const fsu=await usageFor(a);if(fsu.over_quota){json(res,409,{ok:false,error:'disk quota exceeded'});return true}const type=resourceTypeForDomain(a,host),cap=resourceCapacity(a,type);if(!cap.ok){json(res,409,{ok:false,error:type+' limit reached',used:cap.used,limit:cap.limit});return true}
    const ps=settings();const r=await agent('POST','/v1/websites',{owner:a.linux_user,domain:host,php,cloudflare:ps.auto_cloudflare==='1',web_listen:ps.web_listen,tunnel_origin:ps.tunnel_origin}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){json(res,r.status,r.data);return true}
    try{db.prepare('INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?)').run(a.id,type,host,JSON.stringify({cloudflare:r.data.cloudflare||{}}),now());if(!a.primary_domain&&type==='domain')db.prepare('UPDATE hosting_accounts SET primary_domain=?,updated_at=? WHERE id=?').run(host,now(),a.id)}catch(e){await agent('DELETE','/v1/websites?domain='+encodeURIComponent(host),null).catch(()=>null);json(res,409,{ok:false,error:'domain resource conflict'});return true}audit(s.username,'hosting_website_create',host,req);json(res,201,{...r.data,resource_type:type});return true
   }
   if(req.method==='DELETE'){
    if(!needCSRF(req,res,s))return true;const host=String(u.searchParams.get('domain')||'').toLowerCase();const rr=db.prepare("SELECT id,type FROM hosting_resources WHERE account_id=? AND name=? AND type IN ('domain','subdomain')").get(a.id,host);if(!rr){json(res,404,{ok:false,error:'website not found'});return true}const r=await agent('DELETE','/v1/websites?domain='+encodeURIComponent(host),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){json(res,r.status,r.data);return true}db.prepare("DELETE FROM hosting_resources WHERE account_id=? AND name=? AND type IN ('domain','subdomain','app','node','python')").run(a.id,host);audit(s.username,'hosting_website_delete',host,req);json(res,200,{ok:true,cloudflare_warning:r.data.cloudflare_warning||''});return true
   }
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/files'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   if(req.method==='GET'){const p=ownedWebPath(a,u.searchParams.get('path'));if(!p){json(res,403,{ok:false,error:'file path outside your websites'});return true}const r=await agent('GET','/v1/files?path='+encodeURIComponent(p),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));json(res,r.status,r.data);return true}
   if(req.method==='POST'){if(!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null),p=b&&ownedWebPath(a,b.path);if(!b||!p||typeof b.content!=='string'){json(res,400,{ok:false,error:'invalid file request'});return true}const q=await usageFor(a),incoming=Buffer.byteLength(b.content);if(q.over_quota||Number(q.used_bytes||0)+incoming>Number(q.disk_limit_bytes||0)){json(res,409,{ok:false,error:'disk quota exceeded'});return true}const r=await agent('POST','/v1/files',{path:p,content:b.content}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok)audit(s.username,'hosting_file_save',p,req);json(res,r.status,r.data);return true}
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/file-actions'&&req.method==='POST'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}if(!needCSRF(req,res,s))return true;const a=accountRow(s.user_id),b=await readBody(req).catch(()=>null);if(!a||!b){json(res,400,{ok:false,error:'invalid file action'});return true}const p=ownedWebPath(a,b.path),t=b.target?ownedWebPath(a,b.target):null;if(!p||(b.action==='rename'&&!t)){json(res,403,{ok:false,error:'file path outside your websites'});return true}if(['mkdir','touch','rename'].includes(String(b.action))){const q=await usageFor(a);if(q.over_quota){json(res,409,{ok:false,error:'disk quota exceeded'});return true}}const r=await agent('POST','/v1/file-actions',{action:String(b.action||''),path:p,target:t||''}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok)audit(s.username,'hosting_file_'+String(b.action||''),p,req);json(res,r.status,r.data);return true
  }
  if(u.pathname==='/api/hosting/databases'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   if(req.method==='GET'){const owned=new Set(db.prepare("SELECT name FROM hosting_resources WHERE account_id=? AND type='database'").all(a.id).map(x=>x.name));const r=await agent('GET','/v1/databases',null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){json(res,r.status,r.data);return true}json(res,200,{ok:true,items:(r.data.items||[]).filter(x=>owned.has(x.name)),usage:resourceUsage(a.id),limits:quotaSnapshot(a,resourceUsage(a.id)).limits});return true}
   if(req.method==='POST'){
    if(!needCSRF(req,res,s))return true;if(a.provision_state!=='ready'){json(res,409,{ok:false,error:'hosting account is not provisioned'});return true}const b=await readBody(req).catch(()=>null),suffix=String(b?.name||'').trim().toLowerCase();if(!b||!/^[a-z0-9_]{1,24}$/.test(suffix)){json(res,400,{ok:false,error:'invalid database name'});return true}const cap=resourceCapacity(a,'database');if(!cap.ok){json(res,409,{ok:false,error:'database limit reached',used:cap.used,limit:cap.limit});return true}const fsu=await usageFor(a);if(fsu.over_quota){json(res,409,{ok:false,error:'disk quota exceeded'});return true}const name=(a.linux_user+'_'+suffix).slice(0,64),user=name;if(db.prepare('SELECT id FROM hosting_resources WHERE name=?').get(name)){json(res,409,{ok:false,error:'database already assigned'});return true}
    const r=await agent('POST','/v1/databases',{name,user}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){json(res,r.status,r.data);return true}try{db.prepare('INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?)').run(a.id,'database',name,'{}',now())}catch{await agent('DELETE','/v1/databases?name='+encodeURIComponent(name),null).catch(()=>null);json(res,409,{ok:false,error:'database resource conflict'});return true}audit(s.username,'hosting_database_create',name,req);json(res,201,r.data);return true
   }
   if(req.method==='DELETE'){
    if(!needCSRF(req,res,s))return true;const name=String(u.searchParams.get('name')||'');const rr=db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND type='database' AND name=?").get(a.id,name);if(!rr){json(res,404,{ok:false,error:'database not found'});return true}const r=await agent('DELETE','/v1/databases?name='+encodeURIComponent(name),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){json(res,r.status,r.data);return true}db.prepare('DELETE FROM hosting_resources WHERE id=?').run(rr.id);audit(s.username,'hosting_database_delete',name,req);json(res,200,{ok:true});return true
   }
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/installers'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   if(req.method==='GET'){const r=await agent('GET','/v1/hosting-installer',null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!r.data?.ok){json(res,r.status,r.data);return true}const installed=db.prepare("SELECT name,meta,created_at FROM hosting_resources WHERE account_id=? AND type='app' ORDER BY created_at DESC").all(a.id).map(x=>{let meta={};try{meta=JSON.parse(x.meta||'{}')}catch{}return {domain:x.name,...meta,created_at:x.created_at}});json(res,200,{ok:true,items:r.data.items||[],installed,enabled:settings().installers_enabled==='1'});return true}
   if(req.method==='POST'){
    if(!needCSRF(req,res,s))return true;if(settings().installers_enabled!=='1'){json(res,409,{ok:false,error:'application installer is disabled by provider'});return true}if(a.provision_state!=='ready'){json(res,409,{ok:false,error:'hosting account is not provisioned'});return true}const b=await readBody(req).catch(()=>null),app=String(b?.app||'').toLowerCase(),host=String(b?.domain||'').toLowerCase();if(!b||!['wordpress','laravel','node','python'].includes(app)){json(res,400,{ok:false,error:'invalid installer'});return true}if(!db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND name=? AND type IN ('domain','subdomain')").get(a.id,host)){json(res,404,{ok:false,error:'website not found'});return true}if(db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND type='app' AND name=?").get(a.id,host)){json(res,409,{ok:false,error:'an application is already installed on this website'});return true}const q=await usageFor(a);if(q.over_quota){json(res,409,{ok:false,error:'disk quota exceeded'});return true}
    if(app==='node'||app==='python'){const cap=resourceCapacity(a,app);if(!cap.ok){json(res,409,{ok:false,error:app+' application limit reached',used:cap.used,limit:cap.limit});return true}}
    let dbInfo=null;if(app==='wordpress'||app==='laravel'){const cap=resourceCapacity(a,'database');if(!cap.ok){json(res,409,{ok:false,error:'database limit reached',used:cap.used,limit:cap.limit});return true}const suffix=(app+'_'+Date.now().toString(36)).replace(/[^a-z0-9_]/g,'').slice(0,28),name=(a.linux_user+'_'+suffix).slice(0,64);const dr=await agent('POST','/v1/databases',{name,user:name}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!dr.data?.ok){json(res,dr.status,dr.data);return true}dbInfo=dr.data}
    const ps=settings(),payload={user:a.linux_user,domain:host,app,webListen:ps.web_listen,title:String(b.title||''),adminUser:String(b.admin_user||''),adminEmail:String(b.admin_email||'')};if(dbInfo){payload.dbName=dbInfo.name;payload.dbUser=dbInfo.user;payload.dbPassword=dbInfo.password}
    const ir=await agent('POST','/v1/hosting-installer',payload).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(!ir.data?.ok){if(dbInfo)await agent('DELETE','/v1/databases?name='+encodeURIComponent(dbInfo.name),null).catch(()=>null);json(res,ir.status,ir.data);return true}
    try{db.exec('BEGIN IMMEDIATE');if(dbInfo)db.prepare('INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?)').run(a.id,'database',dbInfo.name,JSON.stringify({installer:app,domain:host}),now());db.prepare('INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?)').run(a.id,'app',host,JSON.stringify({kind:app}),now());if(app==='node'||app==='python')db.prepare('INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?)').run(a.id,app,host,JSON.stringify({domain:host}),now());db.exec('COMMIT')}catch(e){try{db.exec('ROLLBACK')}catch{}json(res,500,{ok:false,error:'application installed but inventory update failed'});return true}audit(s.username,'hosting_installer_'+app,host,req);const out={ok:true,domain:host,app,result:ir.data.result||{}};json(res,201,out);return true
   }
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/sftp'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   if(req.method==='GET'){if(Number(a.ftp_accounts||0)<1){json(res,200,{ok:true,available:false,limit:0,user:a.linux_user});return true}const r=await agent('GET','/v1/hosting-sftp?user='+encodeURIComponent(a.linux_user),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok)r.data.available=true;json(res,r.status,r.data);return true}
   if(req.method==='POST'){if(!needCSRF(req,res,s))return true;if(Number(a.ftp_accounts||0)<1){json(res,409,{ok:false,error:'SFTP is not included in your plan'});return true}const b=await readBody(req).catch(()=>null),action=String(b?.action||'');if(!['enable','reset_password'].includes(action)){json(res,400,{ok:false,error:'invalid sftp action'});return true}const r=await agent('POST','/v1/hosting-sftp',{user:a.linux_user,action}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){db.prepare("INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?) ON CONFLICT(type,name) DO UPDATE SET meta=excluded.meta").run(a.id,'ftp',a.linux_user,JSON.stringify({primary:true}),now());audit(s.username,'hosting_sftp_'+action,a.linux_user,req)}json(res,r.status,r.data);return true}
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/backups'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   if(req.method==='GET'){const r=await agent('GET','/v1/hosting-backups?user='+encodeURIComponent(a.linux_user),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){const actual=new Set((r.data.items||[]).map(x=>x.file));for(const x of db.prepare("SELECT id,name FROM hosting_resources WHERE account_id=? AND type='backup'").all(a.id))if(!actual.has(x.name))db.prepare('DELETE FROM hosting_resources WHERE id=?').run(x.id);r.data.usage=resourceUsage(a.id);r.data.limit=Number(a.backups||0)}json(res,r.status,r.data);return true}
   if(req.method==='POST'){if(!needCSRF(req,res,s))return true;const cap=resourceCapacity(a,'backup');if(!cap.ok){json(res,409,{ok:false,error:'backup limit reached',used:cap.used,limit:cap.limit});return true}const q=await usageFor(a);if(q.over_quota){json(res,409,{ok:false,error:'disk quota exceeded'});return true}const b=await readBody(req).catch(()=>null),type=String(b?.type||''),name=String(b?.name||'');if(type==='website'&&!db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND name=? AND type IN ('domain','subdomain')").get(a.id,name)){json(res,404,{ok:false,error:'website not found'});return true}if(type==='database'&&!db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND name=? AND type='database'").get(a.id,name)){json(res,404,{ok:false,error:'database not found'});return true}const r=await agent('POST','/v1/hosting-backups',{user:a.linux_user,type,name,limit_mb:Number(a.disk_mb||0)}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){db.prepare('INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?)').run(a.id,'backup',r.data.file,JSON.stringify({type,target:name,size:r.data.size||0}),now());audit(s.username,'hosting_backup_create',r.data.file,req)}json(res,r.status,r.data);return true}
   if(req.method==='DELETE'){if(!needCSRF(req,res,s))return true;const f=String(u.searchParams.get('file')||'');const rr=db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND type='backup' AND name=?").get(a.id,f);if(!rr){json(res,404,{ok:false,error:'backup not found'});return true}const r=await agent('DELETE','/v1/hosting-backups?user='+encodeURIComponent(a.linux_user)+'&file='+encodeURIComponent(f),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){db.prepare('DELETE FROM hosting_resources WHERE id=?').run(rr.id);audit(s.username,'hosting_backup_delete',f,req)}json(res,r.status,r.data);return true}
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/cron'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   if(req.method==='GET'){const r=await agent('GET','/v1/hosting-cron?user='+encodeURIComponent(a.linux_user),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){r.data.limit=Number(a.cron_jobs||0);r.data.usage=resourceUsage(a.id).cron}json(res,r.status,r.data);return true}
   if(req.method==='POST'){if(!needCSRF(req,res,s))return true;const cap=resourceCapacity(a,'cron');if(!cap.ok){json(res,409,{ok:false,error:'cron limit reached',used:cap.used,limit:cap.limit});return true}const b=await readBody(req).catch(()=>null);if(!b){json(res,400,{ok:false,error:'invalid cron'});return true}const r=await agent('POST','/v1/hosting-cron',{user:a.linux_user,schedule:String(b.schedule||''),command:String(b.command||'')}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){db.prepare('INSERT INTO hosting_resources(account_id,type,name,meta,created_at) VALUES(?,?,?,?,?)').run(a.id,'cron',r.data.id,JSON.stringify({schedule:b.schedule,command:b.command}),now());audit(s.username,'hosting_cron_create',r.data.id,req)}json(res,r.status,r.data);return true}
   if(req.method==='PATCH'){if(!needCSRF(req,res,s))return true;const id=String(u.searchParams.get('id')||''),rr=db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND type='cron' AND name=?").get(a.id,id);if(!rr){json(res,404,{ok:false,error:'cron not found'});return true}const b=await readBody(req).catch(()=>null),r=await agent('PATCH','/v1/hosting-cron',{user:a.linux_user,id,schedule:String(b?.schedule||''),command:String(b?.command||'')}).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){db.prepare('UPDATE hosting_resources SET meta=? WHERE id=?').run(JSON.stringify({schedule:b.schedule,command:b.command}),rr.id);audit(s.username,'hosting_cron_update',id,req)}json(res,r.status,r.data);return true}
   if(req.method==='DELETE'){if(!needCSRF(req,res,s))return true;const id=String(u.searchParams.get('id')||''),rr=db.prepare("SELECT id FROM hosting_resources WHERE account_id=? AND type='cron' AND name=?").get(a.id,id);if(!rr){json(res,404,{ok:false,error:'cron not found'});return true}const r=await agent('DELETE','/v1/hosting-cron?user='+encodeURIComponent(a.linux_user)+'&id='+encodeURIComponent(id),null).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(r.data?.ok){db.prepare('DELETE FROM hosting_resources WHERE id=?').run(rr.id);audit(s.username,'hosting_cron_delete',id,req)}json(res,r.status,r.data);return true}
   json(res,405,{ok:false,error:'method not allowed'});return true
  }
  if(u.pathname==='/api/hosting/quota-status'&&req.method==='GET'){
   const s=needAuth(req,res);if(!s||!ownerOnly(res,s))return true;const r=await agent('GET','/v1/hosting-quota-status',null).catch(e=>({status:502,data:{ok:false,error:e.message}}));json(res,r.status,r.data);return true
  }
  if(u.pathname==='/api/hosting/me'&&req.method==='GET'){
   const s=needAuth(req,res);if(!s)return true;if(s.role!=='client'){json(res,403,{ok:false,error:'hosting client account required'});return true}
   const a=accountRow(s.user_id);if(!a){json(res,404,{ok:false,error:'hosting account not configured'});return true}
   const usage=resourceUsage(a.id),fsu=await usageFor(a),bw=await bandwidthUsage(a),qs=quotaSnapshot(a,usage);a.used_bytes=Number(fsu.used_bytes||0);a.disk_limit_bytes=Number(fsu.disk_limit_bytes||a.disk_mb*1048576);a.hard_quota=!!fsu.hard_quota;a.quota_mode=fsu.quota_mode||'soft';a.over_quota=!!fsu.over_quota;a.bandwidth_used_bytes=Number(bw.used_bytes||0);a.bandwidth_limit_bytes=Number(bw.limit_bytes??Number(a.bandwidth_mb||0)*1048576);a.bandwidth_over=!!bw.over;a.bandwidth_month=String(bw.month||'');json(res,200,{ok:true,account:a,usage,limits:qs.limits,allowed:qs.allowed,provider:settings()});return true
  }
  return false
 }
}
