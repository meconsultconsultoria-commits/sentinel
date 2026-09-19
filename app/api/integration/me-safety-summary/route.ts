export const runtime="nodejs";export const dynamic="force-dynamic";
import{getDB}from"../../../../lib/auth-server";

export async function POST(req:Request){
  try{
    const {ticket}=await req.json() as {ticket?:string};
    if(!ticket)return Response.json({error:"ticket_required"},{status:400});

    const vr=await fetch("https://mesafety.meconsultconsultoria.com.br/api/sso/verify",{
      method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify({ticket,target:"SENTINEL"}),cache:"no-store"
    });
    if(!vr.ok)return Response.json({error:"invalid_ticket"},{status:401});
    const data:any=await vr.json(),u=data?.user;
    if(!u)return Response.json({error:"invalid_user"},{status:401});

    const db=getDB();
    const where:string[]=["1=1"],vals:any[]=[];
    if(u.role!=="ADMIN"&&u.companyId){where.push("o.company_id=?");vals.push(u.companyId)}
    if(u.role!=="ADMIN"&&u.unitId){where.push("o.unit_id=?");vals.push(u.unitId)}
    const scope=where.join(" AND ");

    const [occ,actions,potential,nature,openItems,overdueItems,dueSoonItems]=await Promise.all([
      db.prepare(`SELECT
        COUNT(*) total,
        SUM(CASE WHEN o.status IN ('Encerrado','Concluído','Concluido','Fechado') THEN 1 ELSE 0 END) closed,
        SUM(CASE WHEN o.status NOT IN ('Encerrado','Concluído','Concluido','Fechado') THEN 1 ELSE 0 END) open,
        SUM(CASE WHEN date(o.created_at)>=date('now','-30 day') THEN 1 ELSE 0 END) last30,
        SUM(CASE WHEN COALESCE(o.bird_validated,'')<>'' THEN 1 ELSE 0 END) classified
        FROM occurrences o WHERE ${scope}`).bind(...vals).first(),
      db.prepare(`SELECT
        COUNT(*) total,
        SUM(CASE WHEN COALESCE(a.status,'') NOT IN ('Concluída','Concluida','Concluído','Concluido','Fechada','Fechado') THEN 1 ELSE 0 END) pending,
        SUM(CASE WHEN a.deadline IS NOT NULL AND date(a.deadline)<date('now') AND COALESCE(a.status,'') NOT IN ('Concluída','Concluida','Concluído','Concluido','Fechada','Fechado') THEN 1 ELSE 0 END) overdue
        FROM actions a JOIN occurrences o ON o.id=a.occurrence_id WHERE ${scope}`).bind(...vals).first(),
      db.prepare(`SELECT COALESCE(o.potential,'Não informado') label,COUNT(*) value FROM occurrences o WHERE ${scope} GROUP BY COALESCE(o.potential,'Não informado') ORDER BY value DESC LIMIT 6`).bind(...vals).all(),
      db.prepare(`SELECT COALESCE(o.nature,'Não informado') label,COUNT(*) value FROM occurrences o WHERE ${scope} GROUP BY COALESCE(o.nature,'Não informado') ORDER BY value DESC LIMIT 6`).bind(...vals).all(),
      db.prepare(`SELECT o.id,o.date,o.time,o.nature,o.potential,o.status,o.city,o.uf,c.name company_name,u.name unit_name,o.created_at FROM occurrences o LEFT JOIN companies c ON c.id=o.company_id LEFT JOIN units u ON u.id=o.unit_id WHERE ${scope} AND o.status NOT IN ('Encerrado','Concluído','Concluido','Fechado') ORDER BY COALESCE(o.date,o.created_at) DESC,o.created_at DESC LIMIT 50`).bind(...vals).all(),
      db.prepare(`SELECT a.id,a.occurrence_id,a.description,a.responsible,a.deadline,a.priority,a.status,o.nature,o.potential,c.name company_name,u.name unit_name FROM actions a JOIN occurrences o ON o.id=a.occurrence_id LEFT JOIN companies c ON c.id=o.company_id LEFT JOIN units u ON u.id=o.unit_id WHERE ${scope} AND a.deadline IS NOT NULL AND date(a.deadline)<date('now') AND COALESCE(a.status,'') NOT IN ('Concluída','Concluida','Concluído','Concluido','Fechada','Fechado') ORDER BY date(a.deadline) ASC LIMIT 50`).bind(...vals).all(),
      db.prepare(`SELECT a.id,a.occurrence_id,a.description,a.responsible,a.deadline,a.priority,a.status,o.nature,o.potential,c.name company_name,u.name unit_name FROM actions a JOIN occurrences o ON o.id=a.occurrence_id LEFT JOIN companies c ON c.id=o.company_id LEFT JOIN units u ON u.id=o.unit_id WHERE ${scope} AND a.deadline IS NOT NULL AND date(a.deadline)>=date('now') AND date(a.deadline)<=date('now','+7 day') AND COALESCE(a.status,'') NOT IN ('Concluída','Concluida','Concluído','Concluido','Fechada','Fechado') ORDER BY date(a.deadline) ASC LIMIT 50`).bind(...vals).all()
    ]);

    return Response.json({
      source:"SENTINEL",
      scope:{company:u.companyName||null,unit:u.unitName||null},
      occurrences:{
        total:Number(occ?.total||0),open:Number(occ?.open||0),closed:Number(occ?.closed||0),
        last30:Number(occ?.last30||0),classified:Number(occ?.classified||0)
      },
      actions:{total:Number(actions?.total||0),pending:Number(actions?.pending||0),overdue:Number(actions?.overdue||0)},
      byPotential:potential.results||[],byNature:nature.results||[],
      priority:{openOccurrences:openItems.results||[],overdueActions:overdueItems.results||[],dueSoonActions:dueSoonItems.results||[]}
    });
  }catch(e:any){
    return Response.json({error:"summary_failed",detail:String(e?.message||e||"unknown")},{status:500});
  }
}