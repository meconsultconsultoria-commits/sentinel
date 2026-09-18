import { getCloudflareContext } from "@opennextjs/cloudflare";

type Env={DB:any};
export type SessionUser={id:string;name:string;email:string;role:"ADMIN"|"SSMA"|"GESTOR"|"CONSULTA";companyId:string|null;unitId:string|null};

export function getDB(){const{env}=getCloudflareContext() as unknown as {env:Env};return env.DB}

const hex=(b:Uint8Array)=>Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("");
const bytes=(h:string)=>new Uint8Array(h.match(/.{1,2}/g)?.map(x=>parseInt(x,16))||[]);
async function sha256(v:string){return hex(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(v))))}

export async function ensureAuthSchema(db:any){
  await db.prepare("CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,token_hash TEXT UNIQUE NOT NULL,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id))").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)").run();
  try{await db.prepare("ALTER TABLE users ADD COLUMN password_hash TEXT").run()}catch{}
}

export async function hashPassword(password:string){
  const salt=crypto.getRandomValues(new Uint8Array(16)),iterations=120000;
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations},key,256);
  return `pbkdf2$${iterations}$${hex(salt)}$${hex(new Uint8Array(bits))}`;
}
export async function verifyPassword(password:string,stored:string){
  try{
    const [kind,it,saltHex,hashHex]=stored.split("$");if(kind!=="pbkdf2")return false;
    const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
    const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:bytes(saltHex),iterations:Number(it)},key,256);
    const a=new Uint8Array(bits),b=bytes(hashHex);if(a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];return diff===0;
  }catch{return false}
}
function cookie(req:Request,name:string){const raw=req.headers.get("cookie")||"";for(const p of raw.split(";")){const [k,...v]=p.trim().split("=");if(k===name)return decodeURIComponent(v.join("="))}return null}
export async function createSession(db:any,userId:string){
  const token=hex(crypto.getRandomValues(new Uint8Array(32))),tokenHash=await sha256(token),expires=Math.floor(Date.now()/1000)+60*60*12;
  await db.prepare("DELETE FROM sessions WHERE expires_at < strftime('%s','now')").run();
  await db.prepare("INSERT INTO sessions(id,token_hash,user_id,expires_at) VALUES(?,?,?,?)").bind("SES-"+crypto.randomUUID(),tokenHash,userId,expires).run();
  return {token,expires};
}
export function sessionCookie(token:string,maxAge=43200){return `sentinel_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`}
export function clearSessionCookie(){return "sentinel_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"}
export async function getCurrentUser(req:Request):Promise<SessionUser|null>{
  const db=getDB();await ensureAuthSchema(db);const token=cookie(req,"sentinel_session");if(!token)return null;
  const tokenHash=await sha256(token);
  const r=await db.prepare("SELECT u.id,u.name,u.email,u.role,u.company_id,u.unit_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>strftime('%s','now') AND u.active=1 LIMIT 1").bind(tokenHash).first();
  if(!r)return null;
  return {id:r.id,name:r.name,email:r.email,role:r.role,companyId:r.company_id||null,unitId:r.unit_id||null};
}
export async function destroySession(req:Request){const db=getDB();await ensureAuthSchema(db);const token=cookie(req,"sentinel_session");if(token)await db.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run()}
export async function authorize(req:Request,roles?:string[]){const user=await getCurrentUser(req);if(!user)return {user:null,response:Response.json({error:"unauthorized"},{status:401})};if(roles&&!roles.includes(user.role))return {user,response:Response.json({error:"forbidden"},{status:403})};return {user,response:null}}
