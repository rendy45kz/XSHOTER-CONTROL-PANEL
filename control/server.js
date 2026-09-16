'use strict';
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.XSHOTER_PORT || 9100);
const DBFILE = process.env.XSHOTER_DB_FILE || '/var/lib/xshoter-control/control.db';
const STATIC = process.env.XSHOTER_WEB_DIR || '/opt/xshoter-control/web';
const AGENT = process.env.XSHOTER_AGENT_SOCKET || '/run/xshoter-agent.sock';
const SETUP = process.env.XSHOTER_SETUP_TOKEN_FILE || '/var/lib/xshoter-control/setup.token';
const VERSION = '1.0.2-beta';
const UPDATE_REPO = process.env.XSHOTER_UPDATE_REPO || 'rendy45kz/XSHOTER-CONTROL-PANEL';
const UPDATE_API = process.env.XSHOTER_UPDATE_API || `https://api.github.com/repos/${UPDATE_REPO}/releases/latest`;
const UPDATE_STATE = '/var/lib/xshoter-control/update';
const UPDATE_MODE_FILE = path.join(UPDATE_STATE,'mode');
const UPDATE_STATUS_FILE = path.join(UPDATE_STATE,'status.json');
const UPDATE_REQUEST_FILE = path.join(UPDATE_STATE,'request');
let releaseCache={at:0,data:null};
const db = new DatabaseSync(DBFILE);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'admin',totp_secret TEXT,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,csrf TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT,ip TEXT,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);`);
const rate = new Map();
const now = () => Math.floor(Date.now()/1000);
const token = (n=32) => crypto.randomBytes(n).toString('hex');
function json(res,code,obj){const b=JSON.stringify(obj);res.writeHead(code,{'content-type':'application/json','content-length':Buffer.byteLength(b)});res.end(b)}
function cookies(req){const o={};for(const p of (req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0)o[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1))}return o}
function ip(req){return String(req.headers['cf-connecting-ip']||req.headers['x-forwarded-for']||req.socket.remoteAddress||'').split(',')[0].trim()}
function cleanSessions(){db.prepare('DELETE FROM sessions WHERE expires_at<?').run(now())}
function session(req){cleanSessions();const id=cookies(req).xc_session;if(!id)return null;return db.prepare(`SELECT s.id,s.csrf,s.expires_at,u.id user_id,u.username,u.role,u.totp_secret FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>?`).get(id,now())||null}
function setSession(res,u){const id=token(),csrf=token(16),exp=now()+43200;db.prepare('INSERT INTO sessions(id,user_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?)').run(id,u.id,csrf,exp,now());res.setHeader('set-cookie',`xc_session=${id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`);return csrf}
function destroySession(req,res){const id=cookies(req).xc_session;if(id)db.prepare('DELETE FROM sessions WHERE id=?').run(id);res.setHeader('set-cookie','xc_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0')}
function audit(user,action,target,req){db.prepare('INSERT INTO audit(actor,action,target,ip,created_at) VALUES(?,?,?,?,?)').run(user||'system',action,target||'',ip(req),now())}
function passHash(p){const salt=crypto.randomBytes(16);const d=crypto.scryptSync(p,salt,64);return `scrypt$${salt.toString('hex')}$${d.toString('hex')}`}
function passOK(p,h){try{const [,s,d]=h.split('$');const got=crypto.scryptSync(p,Buffer.from(s,'hex'),64);return crypto.timingSafeEqual(got,Buffer.from(d,'hex'))}catch{return false}}
function readBody(req,max=2<<20){return new Promise((resolve,reject)=>{let a=[],n=0;req.on('data',c=>{n+=c.length;if(n>max){reject(new Error('body too large'));req.destroy();return}a.push(c)});req.on('end',()=>{try{resolve(a.length?JSON.parse(Buffer.concat(a).toString()):{})}catch(e){reject(e)}});req.on('error',reject)})}
function needAuth(req,res){const s=session(req);if(!s){json(res,401,{ok:false,error:'authentication required'});return null}return s}
function needCSRF(req,res,s){if(!s||req.headers['x-csrf-token']!==s.csrf){json(res,403,{ok:false,error:'invalid csrf token'});return false}return true}
function ownerOnly(res,s){if(!s||s.role!=='owner'){json(res,403,{ok:false,error:'owner permission required'});return false}return true}
function setupDone(){return Number(db.prepare('SELECT count(*) n FROM users').get().n)>0}
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf){let bits=0,val=0,out='';for(const b of buf){val=(val<<8)|b;bits+=8;while(bits>=5){out+=B32[(val>>>(bits-5))&31];bits-=5}}if(bits)out+=B32[(val<<(5-bits))&31];return out}
function b32dec(s){let bits=0,val=0,a=[];for(const c of String(s).replace(/=+$/,'').toUpperCase()){const x=B32.indexOf(c);if(x<0)continue;val=(val<<5)|x;bits+=5;if(bits>=8){a.push((val>>>(bits-8))&255);bits-=8}}return Buffer.from(a)}
function totp(secret,t=Math.floor(Date.now()/30000)){const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(t));const h=crypto.createHmac('sha1',b32dec(secret)).update(b).digest();const o=h[h.length-1]&15;const n=(h.readUInt32BE(o)&0x7fffffff)%1000000;return String(n).padStart(6,'0')}
function totpOK(secret,code){if(!secret||!/^[0-9]{6}$/.test(String(code)))return false;for(let d=-1;d<=1;d++)if(crypto.timingSafeEqual(Buffer.from(totp(secret,Math.floor(Date.now()/30000)+d)),Buffer.from(String(code))))return true;return false}
function loginBlocked(k){const r=rate.get(k);if(!r)return false;if(r.block&&r.block>now())return true;if(now()-r.start>600)rate.delete(k);return false}
function loginFail(k){let r=rate.get(k)||{n:0,start:now(),block:0};if(now()-r.start>600)r={n:0,start:now(),block:0};r.n++;if(r.n>=5)r.block=now()+900;rate.set(k,r)}
function loginClear(k){rate.delete(k)}
function semver(v){const m=String(v||'').replace(/^v/i,'').match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);return m?{n:m.slice(1,4).map(Number),pre:!!m[4]}:{n:[0,0,0],pre:false}}
function versionNewer(latest,current){const a=semver(latest),b=semver(current);for(let i=0;i<3;i++){if(a.n[i]>b.n[i])return true;if(a.n[i]<b.n[i])return false}return !a.pre&&b.pre}
function fetchJSON(url){return new Promise((resolve,reject)=>{let done=false;const q=https.get(url,{headers:{'user-agent':`Xshoter-Control/${VERSION}`,'accept':'application/vnd.github+json'}},r=>{if(r.statusCode>=300&&r.statusCode<400&&r.headers.location){r.resume();fetchJSON(r.headers.location).then(resolve,reject);return}if(r.statusCode!==200){r.resume();reject(new Error(`release API HTTP ${r.statusCode}`));return}let a=[],n=0;r.on('data',c=>{n+=c.length;if(n>1048576){q.destroy(new Error('release response too large'));return}a.push(c)});r.on('end',()=>{if(done)return;done=true;try{resolve(JSON.parse(Buffer.concat(a).toString()))}catch{reject(new Error('invalid release response'))}})});q.setTimeout(8000,()=>q.destroy(new Error('release API timeout')));q.on('error',e=>{if(!done){done=true;reject(e)}})})}
async function getUpdateInfo(force=false){const t=Date.now();if(!force&&releaseCache.data&&t-releaseCache.at<300000)return releaseCache.data;const r=await fetchJSON(UPDATE_API);const latest=String(r.tag_name||'').replace(/^v/i,'');if(!latest)throw new Error('latest release tag missing');const data={ok:true,current:VERSION,latest,available:versionNewer(latest,VERSION),channel:'stable',title:String(r.name||r.tag_name||latest),published_at:r.published_at||'',release_url:String(r.html_url||`https://github.com/${UPDATE_REPO}/releases/latest`),notes:String(r.body||'').slice(0,6000)};releaseCache={at:t,data};return data}
function readUpdateMode(){try{const m=fs.readFileSync(UPDATE_MODE_FILE,'utf8').trim();return ['off','notify','auto'].includes(m)?m:'notify'}catch{return 'notify'}}
function readUpdateStatus(){let d={state:'idle',message:'',current:VERSION,latest:'',updated_at:0};try{d={...d,...JSON.parse(fs.readFileSync(UPDATE_STATUS_FILE,'utf8'))}}catch{}const fresh=Number(d.updated_at||0)>now()-1200;return {...d,current:VERSION,ok:true,mode:readUpdateMode(),active:fs.existsSync(UPDATE_REQUEST_FILE)||(fresh&&['checking','available','updating','rollback'].includes(String(d.state||'')))}}
function writeAtomic(p,data,mode=0o640){fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o750});const t=p+'.tmp.'+process.pid;fs.writeFileSync(t,data,{mode});fs.renameSync(t,p)}
function securityHeaders(res){res.setHeader('x-content-type-options','nosniff');res.setHeader('x-frame-options','DENY');res.setHeader('referrer-policy','same-origin');res.setHeader('permissions-policy','camera=(), microphone=(), geolocation=()');res.setHeader('content-security-policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")}
function agent(method,payloadPath,data){return new Promise((resolve,reject)=>{const b=data?Buffer.from(JSON.stringify(data)):null;const q=http.request({socketPath:AGENT,path:payloadPath,method,headers:b?{'content-type':'application/json','content-length':b.length}:{}},r=>{let a=[];r.on('data',c=>a.push(c));r.on('end',()=>{const raw=Buffer.concat(a).toString();let v;try{v=JSON.parse(raw)}catch{v={ok:false,error:raw||'invalid agent response'}}resolve({status:r.statusCode||500,data:v})})});q.setTimeout(70000,()=>q.destroy(new Error('agent timeout')));q.on('error',reject);if(b)q.write(b);q.end()})}
async function authRoutes(req,res,u){
 if(u.pathname==='/api/setup/status'&&req.method==='GET'){json(res,200,{ok:true,configured:setupDone()});return true}
 if(u.pathname==='/api/setup'&&req.method==='POST'){if(setupDone()){json(res,409,{ok:false,error:'setup already completed'});return true}let b;try{b=await readBody(req)}catch{json(res,400,{ok:false,error:'invalid json'});return true}let wanted='';try{wanted=fs.readFileSync(SETUP,'utf8').trim()}catch{}if(!wanted||b.setup_token!==wanted){json(res,403,{ok:false,error:'invalid setup token'});return true}if(!/^[a-zA-Z0-9_.-]{3,32}$/.test(b.username||'')||String(b.password||'').length<10){json(res,400,{ok:false,error:'username/password invalid'});return true}const x=db.prepare('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)').run(b.username,passHash(b.password),'owner',now());const user=db.prepare('SELECT * FROM users WHERE id=?').get(x.lastInsertRowid);try{fs.unlinkSync(SETUP)}catch{}const csrf=setSession(res,user);audit(user.username,'setup','owner',req);json(res,201,{ok:true,user:{username:user.username,role:user.role},csrf});return true}
 if(u.pathname==='/api/login'&&req.method==='POST'){const k=ip(req);if(loginBlocked(k)){json(res,429,{ok:false,error:'too many login attempts'});return true}let b;try{b=await readBody(req)}catch{json(res,400,{ok:false,error:'invalid json'});return true}const user=db.prepare('SELECT * FROM users WHERE username=?').get(String(b.username||''));if(!user||!passOK(String(b.password||''),user.password_hash)){loginFail(k);json(res,401,{ok:false,error:'invalid credentials'});return true}if(user.totp_secret&&!b.otp){json(res,401,{ok:false,error:'otp_required',otp_required:true});return true}if(user.totp_secret&&!totpOK(user.totp_secret,b.otp)){loginFail(k);json(res,401,{ok:false,error:'invalid otp'});return true}loginClear(k);const csrf=setSession(res,user);audit(user.username,'login','panel',req);json(res,200,{ok:true,user:{username:user.username,role:user.role},csrf});return true}
 if(u.pathname==='/api/logout'&&req.method==='POST'){const s=needAuth(req,res);if(!s)return true;if(!needCSRF(req,res,s))return true;destroySession(req,res);audit(s.username,'logout','panel',req);json(res,200,{ok:true});return true}
 if(u.pathname==='/api/me'&&req.method==='GET'){const s=needAuth(req,res);if(!s)return true;json(res,200,{ok:true,user:{username:s.username,role:s.role,twofa:!!s.totp_secret},csrf:s.csrf,version:VERSION});return true}
 if(u.pathname==='/api/update-info'&&req.method==='GET'){const s=needAuth(req,res);if(!s)return true;try{json(res,200,await getUpdateInfo(u.searchParams.get('refresh')==='1'))}catch(e){json(res,200,{ok:false,current:VERSION,latest:'',available:false,channel:'stable',error:e.message})}return true}
 if(u.pathname==='/api/update-status'&&req.method==='GET'){const s=needAuth(req,res);if(!s)return true;json(res,200,readUpdateStatus());return true}
 if(u.pathname==='/api/update-settings'&&req.method==='POST'){const s=needAuth(req,res);if(!s)return true;if(s.role==='viewer'){json(res,403,{ok:false,error:'read only account'});return true}if(!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null);if(!b||!['off','notify','auto'].includes(String(b.mode||''))){json(res,400,{ok:false,error:'invalid update mode'});return true}writeAtomic(UPDATE_MODE_FILE,String(b.mode)+'\n');audit(s.username,'update_mode',String(b.mode),req);json(res,200,{ok:true,mode:String(b.mode)});return true}
 if(u.pathname==='/api/update-run'&&req.method==='POST'){const s=needAuth(req,res);if(!s)return true;if(s.role==='viewer'){json(res,403,{ok:false,error:'read only account'});return true}if(!needCSRF(req,res,s))return true;const st=readUpdateStatus();if(st.active){json(res,409,{ok:false,error:'Xshoter update is already running'});return true}writeAtomic(UPDATE_REQUEST_FILE,JSON.stringify({requested_at:now(),actor:s.username})+'\n',0o600);audit(s.username,'update_run','stable',req);json(res,202,{ok:true,started:true});return true}
 return false
}
async function accountRoutes(req,res,u){
 if(u.pathname==='/api/account/2fa/start'&&req.method==='POST'){const s=needAuth(req,res);if(!s||!needCSRF(req,res,s))return true;const secret=b32enc(crypto.randomBytes(20));db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run('2fa_pending_'+s.user_id,secret);const uri=`otpauth://totp/Xshoter%20Control:${encodeURIComponent(s.username)}?secret=${secret}&issuer=Xshoter%20Control`;json(res,200,{ok:true,secret,uri});return true}
 if(u.pathname==='/api/account/2fa/enable'&&req.method==='POST'){const s=needAuth(req,res);if(!s||!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null);if(!b){json(res,400,{ok:false,error:'invalid json'});return true}const row=db.prepare('SELECT value FROM settings WHERE key=?').get('2fa_pending_'+s.user_id);if(!row||!totpOK(row.value,b.code)){json(res,400,{ok:false,error:'invalid otp'});return true}db.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(row.value,s.user_id);db.prepare('DELETE FROM settings WHERE key=?').run('2fa_pending_'+s.user_id);audit(s.username,'2fa_enable','account',req);json(res,200,{ok:true});return true}
 if(u.pathname==='/api/account/2fa/disable'&&req.method==='POST'){const s=needAuth(req,res);if(!s||!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null);if(!b||!totpOK(s.totp_secret,b.code)){json(res,400,{ok:false,error:'invalid otp'});return true}db.prepare('UPDATE users SET totp_secret=NULL WHERE id=?').run(s.user_id);audit(s.username,'2fa_disable','account',req);json(res,200,{ok:true});return true}
 if(u.pathname==='/api/account/password'&&req.method==='POST'){const s=needAuth(req,res);if(!s||!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null);const cur=db.prepare('SELECT password_hash FROM users WHERE id=?').get(s.user_id);if(!b||!passOK(String(b.current||''),cur.password_hash)||String(b.password||'').length<10){json(res,400,{ok:false,error:'current/new password invalid'});return true}db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(passHash(b.password),s.user_id);db.prepare('DELETE FROM sessions WHERE user_id=? AND id<>?').run(s.user_id,s.id);audit(s.username,'password_change','account',req);json(res,200,{ok:true});return true}
 return false
}
async function adminRoutes(req,res,u){
 if(u.pathname==='/api/users'){
  const s=needAuth(req,res);if(!s||!ownerOnly(res,s))return true;
  if(req.method==='GET'){
   const items=db.prepare(`SELECT u.id,u.username,u.role,u.totp_secret IS NOT NULL twofa,u.created_at,(SELECT count(*) FROM sessions s WHERE s.user_id=u.id AND s.expires_at>?) sessions FROM users u ORDER BY u.id`).all(now());
   json(res,200,{ok:true,items});return true
  }
  if(req.method==='POST'){
   if(!needCSRF(req,res,s))return true;const b=await readBody(req).catch(()=>null);
   if(!b||!/^[a-zA-Z0-9_.-]{3,32}$/.test(b.username||'')||String(b.password||'').length<10||!['admin','viewer'].includes(b.role)){json(res,400,{ok:false,error:'invalid user'});return true}
   try{db.prepare('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)').run(b.username,passHash(b.password),b.role,now())}catch{json(res,409,{ok:false,error:'username exists'});return true}
   audit(s.username,'user_create',b.username,req);json(res,201,{ok:true});return true
  }
  if(req.method==='PATCH'){
   if(!needCSRF(req,res,s))return true;const id=Number(u.searchParams.get('id'));const x=db.prepare('SELECT id,username,role FROM users WHERE id=?').get(id);const b=await readBody(req).catch(()=>null);
   if(!x||!b){json(res,404,{ok:false,error:'user not found'});return true}
   const action=String(b.action||'');
   if(x.role==='owner'){json(res,400,{ok:false,error:'owner account is managed from Security'});return true}
   if(action==='role'){
    if(!['admin','viewer'].includes(b.role)){json(res,400,{ok:false,error:'invalid role'});return true}
    db.prepare('UPDATE users SET role=? WHERE id=?').run(b.role,id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(s.username,'user_role',x.username+':'+b.role,req);json(res,200,{ok:true});return true
   }
   if(action==='password'){
    if(String(b.password||'').length<10){json(res,400,{ok:false,error:'password minimum 10 characters'});return true}
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(passHash(b.password),id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(s.username,'user_password_reset',x.username,req);json(res,200,{ok:true});return true
   }
   if(action==='reset_2fa'){
    db.prepare('UPDATE users SET totp_secret=NULL WHERE id=?').run(id);db.prepare('DELETE FROM settings WHERE key=?').run('2fa_pending_'+id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(s.username,'user_2fa_reset',x.username,req);json(res,200,{ok:true});return true
   }
   if(action==='logout_sessions'){
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(s.username,'user_sessions_revoked',x.username,req);json(res,200,{ok:true});return true
   }
   json(res,400,{ok:false,error:'invalid user action'});return true
  }
  if(req.method==='DELETE'){
   if(!needCSRF(req,res,s))return true;const id=Number(u.searchParams.get('id'));const x=db.prepare('SELECT username,role FROM users WHERE id=?').get(id);
   if(!x||x.role==='owner'){json(res,400,{ok:false,error:'cannot delete user'});return true}
   db.prepare('DELETE FROM users WHERE id=?').run(id);audit(s.username,'user_delete',x.username,req);json(res,200,{ok:true});return true
  }
  json(res,405,{ok:false,error:'method not allowed'});return true
 }
 if(u.pathname==='/api/audit'&&req.method==='GET'){const s=needAuth(req,res);if(!s)return true;json(res,200,{ok:true,items:db.prepare('SELECT actor,action,target,ip,created_at FROM audit ORDER BY id DESC LIMIT 300').all()});return true}
 return false
}
const proxyMap={
 '/api/stats':'/v1/stats','/api/services':'/v1/services','/api/websites':'/v1/websites','/api/databases':'/v1/databases',
 '/api/firewall':'/v1/firewall','/api/cron':'/v1/cron','/api/backups':'/v1/backups','/api/logs':'/v1/logs',
 '/api/files':'/v1/files','/api/sshkeys':'/v1/sshkeys','/api/ssl':'/v1/ssl',
 '/api/system':'/v1/system','/api/processes':'/v1/processes','/api/packages':'/v1/packages','/api/ssl-status':'/v1/ssl-status',
 '/api/web-logs':'/v1/web-logs','/api/php-settings':'/v1/php-settings','/api/file-actions':'/v1/file-actions',
 '/api/backup-actions':'/v1/backup-actions','/api/dns':'/v1/dns','/api/security-overview':'/v1/security','/api/server-users':'/v1/server-users'
};
async function cloudflareRoute(req,res,u){
 const routes={
  '/api/cloudflare':'/v1/cloudflare','/api/cloudflare-test':'/v1/cloudflare-test','/api/cloudflare-zones':'/v1/cloudflare-zones',
  '/api/cloudflare-zone-settings':'/v1/cloudflare-zone-settings','/api/cloudflare-cache':'/v1/cloudflare-cache',
  '/api/cloudflare-tunnels':'/v1/cloudflare-tunnels','/api/cloudflare-tunnel-routes':'/v1/cloudflare-tunnel-routes'
 };
 const target=routes[u.pathname];if(!target)return false;const s=needAuth(req,res);if(!s)return true;
 const mut=!['GET','HEAD'].includes(req.method);if(mut){if(!ownerOnly(res,s))return true;if(!needCSRF(req,res,s))return true}
 let b=null;if(mut){b=await readBody(req).catch(()=>null);if(b===null){json(res,400,{ok:false,error:'invalid json'});return true}}
 let q='';for(const [k,v] of u.searchParams)q+=(q?'&':'?')+encodeURIComponent(k)+'='+encodeURIComponent(v);
 const a=await agent(req.method,target+q,b).catch(e=>({status:502,data:{ok:false,error:e.message}}));
 if(mut&&a.data.ok)audit(s.username,'cloudflare_'+req.method.toLowerCase(),u.pathname.replace('/api/',''),req);
 json(res,a.status,a.data);return true
}
async function uploadRoute(req,res,u){
 if(u.pathname!=='/api/upload')return false;
 const s=needAuth(req,res);if(!s)return true;
 if(req.method!=='POST'){json(res,405,{ok:false,error:'method not allowed'});return true}
 if(s.role==='viewer'){json(res,403,{ok:false,error:'read only account'});return true}
 if(!needCSRF(req,res,s))return true;
 const p=u.searchParams.get('path')||'';if(!p){json(res,400,{ok:false,error:'path required'});return true}
 await new Promise(resolve=>{const headers={'content-type':'application/octet-stream'};if(req.headers['content-length'])headers['content-length']=req.headers['content-length'];const q=http.request({socketPath:AGENT,path:'/v1/file-upload?path='+encodeURIComponent(p),method:'POST',headers},r=>{let a=[];r.on('data',c=>a.push(c));r.on('end',()=>{const raw=Buffer.concat(a).toString();let v;try{v=JSON.parse(raw)}catch{v={ok:false,error:raw||'invalid agent response'}}if(v.ok)audit(s.username,'upload_file',p,req);json(res,r.statusCode||500,v);resolve()})});q.on('error',e=>{json(res,502,{ok:false,error:e.message});resolve()});req.pipe(q)});
 return true
}
async function proxyRoute(req,res,u){
 if(u.pathname==='/api/pma-sso'&&req.method==='POST'){
  const s=needAuth(req,res);if(!s)return true;
  if(s.role==='viewer'){json(res,403,{ok:false,error:'phpMyAdmin requires admin access'});return true}
  if(!needCSRF(req,res,s))return true;
  const b=await readBody(req).catch(()=>null);
  if(!b||!/^[A-Za-z0-9_]{1,64}$/.test(String(b.name||''))){json(res,400,{ok:false,error:'invalid database'});return true}
  const a=await agent('POST','/v1/pma-token',{name:String(b.name)}).catch(e=>({status:502,data:{ok:false,error:e.message}}));
  if(!a.data.ok){json(res,a.status,a.data);return true}
  audit(s.username,'phpmyadmin_sso',String(b.name),req);
  json(res,200,{ok:true,url:'/phpmyadmin/xshoter-sso.php?token='+encodeURIComponent(a.data.token)});return true
 }
 const target=proxyMap[u.pathname];if(!target)return false;const s=needAuth(req,res);if(!s)return true
 const mut=!['GET','HEAD'].includes(req.method);if(mut){if(s.role==='viewer'){json(res,403,{ok:false,error:'read only account'});return true}if(!needCSRF(req,res,s))return true}
 let b=null;if(mut){b=await readBody(req).catch(()=>null);if(b===null){json(res,400,{ok:false,error:'invalid json'});return true}}
 let q='';for(const [k,v] of u.searchParams)q+=(q?'&':'?')+encodeURIComponent(k)+'='+encodeURIComponent(v);const a=await agent(req.method,target+q,b).catch(e=>({status:502,data:{ok:false,error:e.message}}));if(mut&&a.data.ok)audit(s.username,req.method.toLowerCase()+'_'+u.pathname.split('/').pop(),JSON.stringify(b||{}).slice(0,200),req);json(res,a.status,a.data);return true
}
function serveStatic(req,res,u){let p=u.pathname==='/'?'/index.html':u.pathname;if(!['/index.html','/app.css','/app.js','/features.js','/i18n.js','/logo.svg','/flags/id.png','/flags/us.png','/flags/ms.png','/flags/vi.png','/update-v101.js','/cloudflare-v102.js'].includes(p)){p='/index.html'}const f=path.join(STATIC,p);if(!fs.existsSync(f)){res.writeHead(404);res.end('not found');return}const ext=path.extname(f);const ct={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png'}[ext]||'application/octet-stream';const b=fs.readFileSync(f);res.writeHead(200,{'content-type':ct,'content-length':b.length,'cache-control':ext==='.html'?'no-store':'public,max-age=3600'});res.end(b)}
const server=http.createServer(async(req,res)=>{
 securityHeaders(res);const u=new URL(req.url,'http://local');
 try{
  if(await authRoutes(req,res,u))return;
  if(await accountRoutes(req,res,u))return;
  if(await adminRoutes(req,res,u))return;
  if(await cloudflareRoute(req,res,u))return;
  if(await uploadRoute(req,res,u))return;
  if(await proxyRoute(req,res,u))return;
  if(u.pathname.startsWith('/api/')){json(res,404,{ok:false,error:'api not found'});return}
  serveStatic(req,res,u)
 }catch(e){console.error(new Date().toISOString(),e);if(!res.headersSent)json(res,500,{ok:false,error:'internal error'});else res.end()}
});
server.listen(PORT,'127.0.0.1',()=>console.log(`Xshoter Control ${VERSION} on 127.0.0.1:${PORT}`));
process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
process.on('uncaughtException',e=>console.error('uncaught',e));
process.on('unhandledRejection',e=>console.error('rejection',e));
