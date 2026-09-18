import{getCloudflareContext}from'@opennextjs/cloudflare';
import{audit,authorize,canAccessOccurrence,getDB}from'../../../lib/auth-server';
export const runtime='nodejs';export const dynamic='force-dynamic';
type Env={DB:any;EVIDENCE:any};
const MAX_FILE_SIZE=25*1024*1024;
const safeName=(name:string)=>name.normalize('NFKD').replace(/[^a-zA-Z0-9._-]+/g,'_').slice(-140)||'arquivo';
function envAll(){return (getCloudflareContext() as unknown as {env:Env}).env}
export async function GET(req:Request){
  const a=await authorize(req);if(a.response)return a.response;
  const {DB,EVIDENCE}=envAll(),url=new URL(req.url),fileId=url.searchParams.get('fileId'),occurrenceId=url.searchParams.get('occurrenceId');
  if(fileId){
    const row=await DB.prepare("SELECT id,occurrence_id,object_key,file_name,mime_type,size,created_at FROM attachments WHERE id=?").bind(fileId).first();
    if(!row||!await canAccessOccurrence(DB,a.user!,row.occurrence_id))return Response.json({error:'not_found'},{status:404});
    const obj=await EVIDENCE.get(row.object_key);if(!obj)return Response.json({error:'object_not_found'},{status:404});
    const h=new Headers();h.set('content-type',row.mime_type||obj.httpMetadata?.contentType||'application/octet-stream');h.set('content-disposition',`attachment; filename*=UTF-8''${encodeURIComponent(row.file_name||'arquivo')}`);h.set('cache-control','private, no-store');
    return new Response(obj.body,{headers:h});
  }
  if(!occurrenceId)return Response.json({error:'occurrence_required'},{status:400});
  if(!await canAccessOccurrence(DB,a.user!,occurrenceId))return Response.json({error:'not_found'},{status:404});
  const r=await DB.prepare("SELECT id,occurrence_id,file_name,mime_type,size,uploaded_by,created_at FROM attachments WHERE occurrence_id=? ORDER BY created_at DESC").bind(occurrenceId).all();
  return Response.json(r.results);
}
export async function POST(req:Request){
  const a=await authorize(req,['ADMIN','SSMA','GESTOR']);if(a.response)return a.response;
  const {DB,EVIDENCE}=envAll(),form=await req.formData(),occurrenceId=String(form.get('occurrenceId')||'');
  if(!occurrenceId)return Response.json({error:'occurrence_required'},{status:400});
  if(!await canAccessOccurrence(DB,a.user!,occurrenceId))return Response.json({error:'not_found'},{status:404});
  const files=form.getAll('files').filter((x):x is File=>x instanceof File);
  if(!files.length)return Response.json({error:'files_required'},{status:400});
  const uploaded:any[]=[];
  for(const file of files){
    if(file.size<=0)continue;
    if(file.size>MAX_FILE_SIZE)return Response.json({error:'file_too_large',file:file.name,maxMB:25},{status:413});
    const id='ATT-'+crypto.randomUUID(),key=occurrenceId+'/'+crypto.randomUUID()+'-'+safeName(file.name),contentType=file.type||'application/octet-stream';
    await EVIDENCE.put(key,await file.arrayBuffer(),{httpMetadata:{contentType},customMetadata:{occurrenceId,originalName:file.name}});
    try{
      await DB.prepare("INSERT INTO attachments(id,occurrence_id,action_id,object_key,file_name,mime_type,size,uploaded_by) VALUES(?,?,?,?,?,?,?,?)").bind(id,occurrenceId,null,key,file.name,contentType,file.size,a.user!.id).run();
    }catch(e){await EVIDENCE.delete(key);throw e}
    uploaded.push({id,fileName:file.name,size:file.size,mimeType:contentType});
  }
  await audit(DB,a.user!.id,'Evidência anexada',uploaded.length+' arquivo(s) anexado(s)',occurrenceId);
  return Response.json({ok:true,files:uploaded},{status:201});
}
export async function DELETE(req:Request){
  const a=await authorize(req,['ADMIN','SSMA','GESTOR']);if(a.response)return a.response;
  const {DB,EVIDENCE}=envAll(),id=new URL(req.url).searchParams.get('fileId');if(!id)return Response.json({error:'file_required'},{status:400});
  const row=await DB.prepare("SELECT occurrence_id,object_key,file_name FROM attachments WHERE id=?").bind(id).first();
  if(!row||!await canAccessOccurrence(DB,a.user!,row.occurrence_id))return Response.json({error:'not_found'},{status:404});
  await EVIDENCE.delete(row.object_key);await DB.prepare("DELETE FROM attachments WHERE id=?").bind(id).run();
  await audit(DB,a.user!.id,'Evidência removida','Arquivo '+(row.file_name||id)+' removido',row.occurrence_id);
  return Response.json({ok:true});
}