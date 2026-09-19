import{audit,createSession,ensureAuthSchema,getDB,sessionCookie}from"../../../../lib/auth-server";
export const runtime="nodejs";export const dynamic="force-dynamic";

export async function GET(req:Request){
  try{
    const ticket=new URL(req.url).searchParams.get("ticket")||"";
    if(!ticket)return Response.redirect(new URL("/login",req.url),302);

    const vr=await fetch("https://mesafety.meconsultconsultoria.com.br/api/sso/verify",{
      method:"POST",
      headers:{"content-type":"application/json"},
      body:JSON.stringify({ticket,target:"SENTINEL"}),
      cache:"no-store"
    });

    if(!vr.ok)return Response.redirect(new URL("/login?sso=invalid",req.url),302);
    const data:any=await vr.json();
    const incoming=data?.user;
    if(!incoming?.email)return Response.redirect(new URL("/login?sso=invalid",req.url),302);

    const db=getDB();await ensureAuthSchema(db);
    const email=String(incoming.email).trim().toLowerCase();
    const name=String(incoming.name||email);
    const role=["ADMIN","SSMA","GESTOR","CONSULTA"].includes(incoming.role)?incoming.role:"CONSULTA";

    let u=await db.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first();
    let id=String(u?.id||("USR-"+crypto.randomUUID()));

    if(u){
      await db.prepare("UPDATE users SET name=?,role=?,active=1 WHERE id=?").bind(name,role,id).run();
    }else{
      await db.prepare("INSERT INTO users(id,email,name,role,company_id,unit_id,active,password_hash) VALUES(?,?,?,?,NULL,NULL,1,NULL)")
        .bind(id,email,name,role).run();
    }

    const s=await createSession(db,id);
    await audit(db,id,"Login SSO","Sessão autenticada via ME Safety");

    return new Response(null,{
      status:302,
      headers:{
        location:new URL("/",req.url).toString(),
        "set-cookie":sessionCookie(s.token),
        "cache-control":"no-store"
      }
    });
  }catch(e){
    return Response.redirect(new URL("/login?sso=error",req.url),302);
  }
}