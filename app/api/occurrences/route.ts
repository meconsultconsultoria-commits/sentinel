import { getCloudflareContext } from "@opennextjs/cloudflare";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Env={DB:any};

const mapOccurrence = (r:any) => ({
  id:r.id, createdAt:r.created_at, date:r.date||"", time:r.time||"", company:r.company_id||"", companyName:r.company_name||"",
  unit:r.unit_id||"", unitName:r.unit_name||"", operation:r.operation||"", location:r.location||"", city:r.city||"", uf:r.uf||"",
  nature:r.nature||"", type:r.type||"", potential:r.potential||"", victim:r.victim?"Sim":"Não",
  materialDamage:r.material_damage?"Sim":"Não", environmentalImpact:r.environmental_impact?"Sim":"Não",
  description:r.description||"", driver:r.driver||"", document:r.document||"", plate:r.plate||"",
  fleet:r.fleet||"", trailer:r.trailer||"", trailerPlate:r.trailer_plate||"", birdSuggested:r.bird_suggested||"",
  birdReason:r.bird_reason||"", birdValidated:r.bird_validated||"", status:r.status||"Registrado"
});

export async function GET(req:Request){
  const { env } = getCloudflareContext() as unknown as {env:Env};
  const url=new URL(req.url), id=url.searchParams.get("id");
  if(id){
    const row=await env.DB.prepare("SELECT o.*,c.name company_name,u.name unit_name FROM occurrences o LEFT JOIN companies c ON c.id=o.company_id LEFT JOIN units u ON u.id=o.unit_id WHERE o.id=?").bind(id).first();
    if(!row)return Response.json({error:"not_found"},{status:404});
    const third=await env.DB.prepare("SELECT * FROM third_parties WHERE occurrence_id=? ORDER BY rowid LIMIT 1").bind(id).first();
    return Response.json({...mapOccurrence(row),thirdParty:!!third,thirdPartyType:third?.type||"",thirdPartyName:third?.name||"",contactName:third?.contact_name||"",phone1:third?.phone1||"",phone2:third?.phone2||"",email:third?.email||"",thirdNotes:third?.notes||""});
  }
  const rows=await env.DB.prepare("SELECT o.*,c.name company_name,u.name unit_name FROM occurrences o LEFT JOIN companies c ON c.id=o.company_id LEFT JOIN units u ON u.id=o.unit_id ORDER BY o.created_at DESC").all();
  return Response.json(rows.results.map(mapOccurrence));
}

export async function POST(req:Request){
  const { env } = getCloudflareContext() as unknown as {env:Env};
  const o:any=await req.json();
  await env.DB.prepare(`INSERT INTO occurrences
  (id,company_id,unit_id,date,time,operation,location,city,uf,nature,type,potential,victim,material_damage,environmental_impact,description,driver,document,plate,fleet,trailer,trailer_plate,bird_suggested,bird_reason,bird_validated,status,created_at,updated_at)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  .bind(o.id,o.company||null,o.unit||null,o.date||null,o.time||null,o.operation||null,o.location||null,o.city||null,o.uf||null,o.nature||null,o.type||null,o.potential||null,o.victim==="Sim"?1:0,o.materialDamage==="Sim"?1:0,o.environmentalImpact==="Sim"?1:0,o.description||null,o.driver||null,o.document||null,o.plate||null,o.fleet||null,o.trailer||null,o.trailerPlate||null,o.birdSuggested||null,o.birdReason||null,o.birdValidated||null,o.status||"Registrado",o.createdAt||new Date().toISOString(),new Date().toISOString()).run();
  if(o.thirdParty&&o.thirdPartyName){
    await env.DB.prepare("INSERT INTO third_parties(id,occurrence_id,type,name,contact_name,phone1,phone2,email,notes) VALUES(?,?,?,?,?,?,?,?,?)")
      .bind("THR-"+crypto.randomUUID(),o.id,o.thirdPartyType||null,o.thirdPartyName,o.contactName||null,o.phone1||null,o.phone2||null,o.email||null,o.thirdNotes||null).run();
  }
  await env.DB.prepare("INSERT INTO audit_log(occurrence_id,event,details) VALUES(?,?,?)").bind(o.id,"Ocorrência registrada","Registro criado no SENTINEL").run();
  return Response.json({ok:true,id:o.id},{status:201});
}

export async function PATCH(req:Request){
  const { env } = getCloudflareContext() as unknown as {env:Env};
  const p:any=await req.json();
  if(!p.id)return Response.json({error:"id_required"},{status:400});
  if(p.birdValidated!==undefined)await env.DB.prepare("UPDATE occurrences SET bird_validated=?, status=COALESCE(?,status), updated_at=? WHERE id=?").bind(p.birdValidated,p.status||null,new Date().toISOString(),p.id).run();
  else if(p.status!==undefined)await env.DB.prepare("UPDATE occurrences SET status=?, updated_at=? WHERE id=?").bind(p.status,new Date().toISOString(),p.id).run();
  return Response.json({ok:true});
}

export async function DELETE(req:Request){
  const {env}=getCloudflareContext() as unknown as {env:Env};
  const id=new URL(req.url).searchParams.get("id");
  if(!id)return Response.json({error:"id_required"},{status:400});
  // TODO auth: this endpoint must be restricted to authenticated ADMIN users when login is enabled.
  const found=await env.DB.prepare("SELECT id FROM occurrences WHERE id=?").bind(id).first();
  if(!found)return Response.json({error:"not_found"},{status:404});
  const statements=[
    env.DB.prepare("DELETE FROM audit_log WHERE occurrence_id=?").bind(id),
    env.DB.prepare("DELETE FROM attachments WHERE occurrence_id=?").bind(id),
    env.DB.prepare("DELETE FROM closures WHERE occurrence_id=?").bind(id),
    env.DB.prepare("DELETE FROM actions WHERE occurrence_id=?").bind(id),
    env.DB.prepare("DELETE FROM investigations WHERE occurrence_id=?").bind(id),
    env.DB.prepare("DELETE FROM third_parties WHERE occurrence_id=?").bind(id),
    env.DB.prepare("DELETE FROM occurrences WHERE id=?").bind(id)
  ];
  await env.DB.batch(statements);
  return Response.json({ok:true});
}