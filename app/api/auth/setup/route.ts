import{audit,createSession,ensureAuthSchema,getDB,hashPassword,sessionCookie}from'../../../../lib/auth-server';export const runtime='nodejs';export const dynamic='force-dynamic';
export async function POST(req:Request){
  try{
    const db=getDB();await ensureAuthSchema(db);
    const count=await db.prepare("SELECT COUNT(*) n FROM users WHERE password_hash IS NOT NULL AND password_hash<>''").first();
    if(Number(count?.n||0)>0)return Response.json({error:'already_configured'},{status:409});
    const x:any=await req.json();
    const name=String(x.name||'').trim(),email=String(x.email||'').trim().toLowerCase(),password=String(x.password||'');
    if(!name||!email||password.length<8)return Response.json({error:'invalid_data'},{status:400});
    const hash=await hashPassword(password);
    const existing=await db.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
    const id=existing?.id||("USR-"+crypto.randomUUID());
    if(existing)await db.prepare("UPDATE users SET name=?,role='ADMIN',active=1,password_hash=? WHERE id=?").bind(name,hash,id).run();
    else await db.prepare("INSERT INTO users(id,email,name,role,company_id,unit_id,active,password_hash) VALUES(?,?,?,'ADMIN',NULL,NULL,1,?)").bind(id,email,name,hash).run();
    await audit(db,id,'Administrador inicial criado','Primeiro administrador configurado no SENTINEL');const s=await createSession(db,id);
    return new Response(JSON.stringify({ok:true}),{status:201,headers:{'content-type':'application/json','set-cookie':sessionCookie(s.token)}});
  }catch(e:any){
    return Response.json({error:'setup_failed',detail:String(e?.message||e||'unknown')},{status:500});
  }
}