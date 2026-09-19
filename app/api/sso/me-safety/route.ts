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
    const companyId=incoming.companyId?String(incoming.companyId):null;
    const companyName=incoming.companyName?String(incoming.companyName):null;
    const unitId=incoming.unitId?String(incoming.unitId):null;
    const unitName=incoming.unitName?String(incoming.unitName):null;

    if(companyId&&companyName){
      await db.prepare("INSERT INTO companies(id,name,active) VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name,active=1")
        .bind(companyId,companyName).run();
    }
    if(companyId&&unitId&&unitName){
      await db.prepare("INSERT INTO units(id,company_id,name,active) VALUES(?,?,?,1) ON CONFLICT(id) DO UPDATE SET company_id=excluded.company_id,name=excluded.name,active=1")
        .bind(unitId,companyId,unitName).run();
    }

    let u=await db.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first();
    const id=String(u?.id||("USR-"+crypto.randomUUID()));
    const scopedCompany=role==="ADMIN"?companyId:companyId;
    const scopedUnit=companyId&&unitId?unitId:null;

    if(u){
      await db.prepare("UPDATE users SET name=?,role=?,company_id=?,unit_id=?,active=1 WHERE id=?")
        .bind(name,role,scopedCompany,scopedUnit,id).run();
    }else{
      await db.prepare("INSERT INTO users(id,email,name,role,company_id,unit_id,active,password_hash) VALUES(?,?,?,?,?,?,1,NULL)")
        .bind(id,email,name,role,scopedCompany,scopedUnit).run();
    }

    const s=await createSession(db,id);
    const scopeText=companyName?(companyName+(unitName?" / "+unitName:"")):"Sem restrição organizacional";
    await audit(db,id,"Login SSO","Sessão autenticada via ME Safety · "+scopeText);

    return new Response(null,{
      status:302,
      headers:{
        location:new URL("/",req.url).toString(),
        "set-cookie":sessionCookie(s.token),
        "cache-control":"no-store"
      }
    });
  }catch{
    return Response.redirect(new URL("/login?sso=error",req.url),302);
  }
}