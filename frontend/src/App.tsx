import { useEffect, useMemo, useState } from 'react'
import { ShieldCheck, Search, RefreshCw, Cloud, Bell, ChevronDown, ArrowUpRight, ShieldAlert, CheckCircle2, Clock3, FileSearch, Sparkles, Filter, Download, CircleHelp } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

type Finding = { id:string; rule_id:string; title:string; severity:string; resource_address:string; resource_type:string; evidence:string; remediation:string; status:string; scan_id:string }
const API = '/api'
const demo: Finding[] = [
 {id:'a1b2c3d4e5f607182930',scan_id:'demo',rule_id:'CG-NET-001',title:'Sensitive security-group ingress is open to the internet',severity:'critical',resource_address:'aws_security_group.admin_access',resource_type:'aws_security_group',evidence:'cidrs=[0.0.0.0/0]; ports=22-22; protocol=tcp',remediation:'Restrict ingress to approved CIDRs and expose only required ports.',status:'open'},
 {id:'b2c3d4e5f607182930a1',scan_id:'demo',rule_id:'CG-IAM-001',title:'IAM policy grants wildcard actions',severity:'critical',resource_address:'aws_iam_policy.admin',resource_type:'aws_iam_policy',evidence:"Sid=<none>; Action contains '*'; Resource=['*']",remediation:'Replace wildcard actions with the minimum required API actions.',status:'open'},
 {id:'c3d4e5f607182930a1b2',scan_id:'demo',rule_id:'CG-S3-001',title:'S3 bucket has no explicit server-side encryption',severity:'high',resource_address:'aws_s3_bucket.customer_uploads',resource_type:'aws_s3_bucket',evidence:'server_side_encryption_configuration is absent or empty',remediation:'Add server_side_encryption_configuration with aws:kms or AES256 encryption.',status:'in_progress'},
 {id:'d4e5f607182930a1b2c3',scan_id:'demo',rule_id:'CG-STO-001',title:'EBS volume encryption is not enabled',severity:'high',resource_address:'aws_ebs_volume.data',resource_type:'aws_ebs_volume',evidence:'encrypted=False',remediation:'Set encrypted = true and configure an approved KMS key if required.',status:'open'},
 {id:'e5f607182930a1b2c3d4',scan_id:'demo',rule_id:'CG-STO-002',title:'RDS storage encryption is not enabled',severity:'high',resource_address:'aws_db_instance.app',resource_type:'aws_db_instance',evidence:'storage_encrypted=False',remediation:'Set storage_encrypted = true; evaluate snapshot and key migration needs.',status:'open'},
 {id:'f607182930a1b2c3d4e5',scan_id:'demo',rule_id:'CG-S3-002',title:'S3 public access block is permissive',severity:'critical',resource_address:'aws_s3_bucket_public_access_block.customer_uploads',resource_type:'aws_s3_bucket_public_access_block',evidence:'False settings: block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets',remediation:'Set all four public-access-block settings to true and review bucket policies/ACLs.',status:'open'}
]
const sevColor: Record<string,string> = {critical:'#fb5474',high:'#ff9b52',medium:'#f5c451',low:'#4dbb9a',info:'#8d9bb8'}
const pretty = (s:string) => s.replace('_',' ')
function App() {
 const [findings,setFindings] = useState<Finding[]>(demo)
 const [apiMode,setApiMode] = useState<'demo'|'live'>('demo')
 const [query,setQuery] = useState('')
 const [severity,setSeverity] = useState('all')
 const [status,setStatus] = useState('all')
 const [selected,setSelected] = useState<Finding|null>(null)
 const [explanation,setExplanation] = useState<{explanation:string;proposed_fix:string}|null>(null)
 const [toast,setToast] = useState('')
 const [busy,setBusy] = useState(false)
 async function load() {
  try {
   const [f,s] = await Promise.all([fetch(`${API}/findings?limit=500`),fetch(`${API}/summary`)])
   if (!f.ok || !s.ok) throw new Error('API unavailable')
   setFindings(await f.json()); setApiMode('live')
  } catch { setApiMode('demo') }
 }
 useEffect(()=>{load()},[])
 const filtered = useMemo(()=>findings.filter(f=>(severity==='all'||f.severity===severity)&&(status==='all'||f.status===status)&&`${f.title} ${f.resource_address} ${f.rule_id}`.toLowerCase().includes(query.toLowerCase())),[findings,severity,status,query])
 const counts = useMemo(()=>({critical:findings.filter(f=>f.severity==='critical').length,high:findings.filter(f=>f.severity==='high').length,medium:findings.filter(f=>f.severity==='medium').length,open:findings.filter(f=>f.status==='open').length,resolved:findings.filter(f=>f.status==='resolved').length}),[findings])
 const trend = [{name:'Mon',critical:2,high:4,medium:3},{name:'Tue',critical:4,high:5,medium:6},{name:'Wed',critical:3,high:7,medium:4},{name:'Thu',critical:6,high:4,medium:7},{name:'Fri',critical:4,high:8,medium:5},{name:'Sat',critical:2,high:3,medium:2},{name:'Sun',critical:3,high:5,medium:4}]
 const pie = [{name:'Critical',value:counts.critical,color:sevColor.critical},{name:'High',value:counts.high,color:sevColor.high},{name:'Medium',value:counts.medium,color:sevColor.medium},{name:'Low',value:counts.medium?1:0,color:sevColor.low}]
 async function updateStatus(f:Finding,next:string) {
  try {
   const r=await fetch(`${API}/findings/${f.id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:next})})
   if(!r.ok) throw new Error()
   const updated=await r.json(); setFindings(prev=>prev.map(x=>x.id===f.id?updated:x)); setSelected(updated); setToast('Remediation status updated')
  } catch { setFindings(prev=>prev.map(x=>x.id===f.id?{...x,status:next}:x)); if(selected?.id===f.id)setSelected({...f,status:next}); setToast('Updated locally in demo mode') }
 }
 async function explain(f:Finding) {
  setBusy(true); setExplanation(null)
  try { const r=await fetch(`${API}/findings/${f.id}/explain`,{method:'POST'}); if(!r.ok) throw new Error(); setExplanation(await r.json()) }
  catch { setExplanation({explanation:`${f.title}. The scanner observed this configuration in ${f.resource_address}. Review the evidence and determine whether the exposure is justified.`,proposed_fix:f.remediation}) }
  finally { setBusy(false) }
 }
 function exportCsv() {
  const rows=[['rule_id','severity','status','resource_address','title'],...filtered.map(f=>[f.rule_id,f.severity,f.status,f.resource_address,f.title])]
  const csv=rows.map(row=>row.map(v=>`"${String(v).replaceAll('"','""')}"`).join(',')).join('\n')
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); const a=document.createElement('a');a.href=url;a.download='cloudguard-findings.csv';a.click();URL.revokeObjectURL(url)
 }
 async function scanDemo() {
  setBusy(true)
  try {
   const r=await fetch(`${API}/scans`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'vulnerable-plan-demo',plan_path:'/app/examples/vulnerable-plan.json'})})
   if(!r.ok) throw new Error()
   setToast('Scan queued. Refresh in a moment to view results.'); setTimeout(()=>load(),1500)
  } catch { setToast('Start Docker Compose to run a real scan; demo findings remain available.') }
  finally {setBusy(false)}
 }
 return <div className="app-shell">
  <aside className="sidebar">
   <div className="brand"><div className="brand-mark"><ShieldCheck size={22}/></div><div><b>CloudGuard</b><small>POSTURE INTELLIGENCE</small></div></div>
   <div className="workspace"><div className="cloud-icon"><Cloud size={17}/></div><div><b>Demo environment</b><small>AWS · Terraform plan</small></div><ChevronDown size={15}/></div>
   <div className="nav-label">WORKSPACE</div>
   <div className="nav-item active"><ShieldAlert size={17}/> Overview <span>6</span></div>
   <div className="nav-item"><FileSearch size={17}/> Findings</div>
   <div className="nav-item"><Clock3 size={17}/> Scan history</div>
   <div className="nav-label">MANAGE</div>
   <div className="nav-item"><CheckCircle2 size={17}/> Policies</div>
   <div className="nav-item"><Sparkles size={17}/> AI remediation</div>
   <div className="sidebar-bottom"><div className="health-dot"></div><div><b>Scanner status</b><small>{apiMode==='live'?'Connected to API':'Demo data · API offline'}</small></div><span className="pulse"></span></div>
   <div className="user-card"><div className="avatar">CG</div><div><b>CloudGuard Analyst</b><small>Security engineer</small></div><ChevronDown size={15}/></div>
  </aside>
  <main className="main">
   <header className="topbar"><div className="crumb">Workspace <span>/</span> <b>Overview</b></div><div className="top-actions"><div className={`mode ${apiMode}`}><i/> {apiMode==='live'?'API connected':'Demo mode'}</div><button className="icon-btn" aria-label="Notifications"><Bell size={18}/></button><div className="avatar small">CG</div></div></header>
   <section className="page-head"><div><div className="eyebrow">CLOUD SECURITY POSTURE MANAGEMENT</div><h1>Security overview <span className="spark">✳</span></h1><p>Find misconfigurations before they become incidents.</p></div><div className="head-buttons"><button className="btn secondary" onClick={load}><RefreshCw size={16}/> Refresh</button><button className="btn primary" onClick={scanDemo} disabled={busy}><Search size={16}/> {busy?'Working…':'Run a scan'} <ArrowUpRight size={15}/></button></div></section>
   <section className="metrics">
    <div className="metric-card"><div className="metric-top"><span>Total findings</span><div className="metric-icon purple"><FileSearch size={17}/></div></div><div className="metric-number">{findings.length}<small> findings</small></div><div className="metric-foot"><span className="dot purple-dot"/> Across scanned resources</div></div>
    <div className="metric-card"><div className="metric-top"><span>Critical severity</span><div className="metric-icon red"><ShieldAlert size={17}/></div></div><div className="metric-number">{counts.critical}<small> findings</small></div><div className="metric-foot"><span className="dot red-dot"/> Prioritize immediately</div></div>
    <div className="metric-card"><div className="metric-top"><span>Open remediation</span><div className="metric-icon orange"><Clock3 size={17}/></div></div><div className="metric-number">{counts.open}<small> findings</small></div><div className="metric-foot"><span className="dot orange-dot"/> Require analyst review</div></div>
    <div className="metric-card"><div className="metric-top"><span>Resolved</span><div className="metric-icon green"><CheckCircle2 size={17}/></div></div><div className="metric-number">{counts.resolved}<small> findings</small></div><div className="metric-foot"><span className="dot green-dot"/> Remediation complete</div></div>
   </section>
   <section className="charts-grid">
    <div className="panel trend-panel"><div className="panel-head"><div><h2>Finding activity</h2><p>Sample weekly trend · illustrative</p></div><button className="select-like">Last 7 days <ChevronDown size={14}/></button></div><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={trend} barGap={5}><XAxis dataKey="name" axisLine={false} tickLine={false} tick={{fill:'#8490a8',fontSize:11}}/><YAxis axisLine={false} tickLine={false} tick={{fill:'#8490a8',fontSize:11}}/><Tooltip contentStyle={{background:'#151b2c',border:'1px solid #2b354b',borderRadius:10,color:'#f5f7ff'}}/><Bar dataKey="critical" stackId="a" fill={sevColor.critical} radius={[3,3,0,0]}/><Bar dataKey="high" stackId="a" fill={sevColor.high}/><Bar dataKey="medium" stackId="a" fill={sevColor.medium}/></BarChart></ResponsiveContainer></div><div className="legend"><span><i style={{background:sevColor.critical}}/>Critical</span><span><i style={{background:sevColor.high}}/>High</span><span><i style={{background:sevColor.medium}}/>Medium</span></div></div>
    <div className="panel severity-panel"><div className="panel-head"><div><h2>Severity distribution</h2><p>Current findings by risk level</p></div><button className="dots">···</button></div><div className="donut-area"><ResponsiveContainer width="56%" height="100%"><PieChart><Pie data={pie} dataKey="value" nameKey="name" innerRadius={54} outerRadius={76} strokeWidth={3} stroke="#101625">{pie.map((p,i)=><Cell key={i} fill={p.color}/>)}</Pie><Tooltip contentStyle={{background:'#151b2c',border:'1px solid #2b354b',borderRadius:10}}/></PieChart></ResponsiveContainer><div className="severity-legend">{pie.map(p=><div key={p.name}><i style={{background:p.color}}/><span>{p.name}</span><b>{p.value}</b></div>)}</div></div></div>
   </section>
   <section className="panel findings-panel"><div className="panel-head findings-head"><div><h2>Priority findings <span className="count-pill">{filtered.length}</span></h2><p>Review evidence, assign remediation, and track risk reduction.</p></div><button className="btn secondary compact" onClick={exportCsv}><Download size={15}/> Export CSV</button></div>
    <div className="filters"><div className="searchbox"><Search size={16}/><input placeholder="Search findings or resources…" value={query} onChange={e=>setQuery(e.target.value)}/>{query&&<button onClick={()=>setQuery('')}>×</button>}</div><div className="filter-select"><Filter size={15}/><select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="all">All severity</option>{['critical','high','medium','low'].map(s=><option key={s} value={s}>{pretty(s)}</option>)}</select></div><div className="filter-select"><select value={status} onChange={e=>setStatus(e.target.value)}><option value="all">All status</option>{['open','in_progress','accepted_risk','resolved'].map(s=><option key={s} value={s}>{pretty(s)}</option>)}</select></div></div>
    <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Resource</th><th>Status</th><th>Rule</th><th></th></tr></thead><tbody>{filtered.map(f=><tr key={f.id} onClick={()=>{setSelected(f);setExplanation(null)}}><td><div className="finding-title"><span className="finding-icon" style={{color:sevColor[f.severity]}}><ShieldAlert size={17}/></span><div><b>{f.title}</b><small>{f.evidence}</small></div></div></td><td><span className={`severity-badge ${f.severity}`}><i/> {pretty(f.severity)}</span></td><td><code>{f.resource_address}</code></td><td><span className={`status-badge ${f.status}`}>{pretty(f.status)}</span></td><td><span className="rule-id">{f.rule_id}</span></td><td><button className="row-open" aria-label="Open finding" onClick={e=>{e.stopPropagation();setSelected(f);setExplanation(null)}}>↗</button></td></tr>)}</tbody></table>{filtered.length===0&&<div className="empty">No findings match these filters.</div>}</div>
    <div className="table-foot">Showing <b>{filtered.length}</b> of <b>{findings.length}</b> findings <span>Static analysis · Terraform plan JSON</span></div>
   </section>
   <footer>CloudGuard <span>·</span> Built for infrastructure security <span>·</span> <a href="https://developer.hashicorp.com/terraform" target="_blank" rel="noreferrer">Terraform plan analysis ↗</a></footer>
  </main>
  {selected&&<div className="drawer-backdrop" onClick={()=>setSelected(null)}><aside className="drawer" onClick={e=>e.stopPropagation()}><div className="drawer-head"><div><span className={`severity-badge ${selected.severity}`}><i/>{pretty(selected.severity)}</span><h2>Finding details</h2></div><button className="icon-btn" onClick={()=>setSelected(null)}>×</button></div><div className="drawer-body"><span className="eyebrow">{selected.rule_id}</span><h3>{selected.title}</h3><p className="muted">Detected in the planned infrastructure configuration.</p><label>RESOURCE ADDRESS</label><div className="code-box">{selected.resource_address}</div><label>DETECTION EVIDENCE</label><div className="evidence-box">{selected.evidence}</div><label>REMEDIATION STATUS</label><select className="status-control" value={selected.status} onChange={e=>updateStatus(selected,e.target.value)}>{['open','in_progress','accepted_risk','resolved'].map(s=><option key={s} value={s}>{pretty(s)}</option>)}</select><label>PROPOSED REMEDIATION</label><div className="fix-box">{selected.remediation}</div><button className="btn primary full" disabled={busy} onClick={()=>explain(selected)}><Sparkles size={16}/>{busy?'Generating…':'Explain finding & draft fix'}</button>{explanation&&<div className="ai-box"><div className="ai-title"><Sparkles size={15}/> AI-style explanation <span>Evidence linked</span></div><p>{explanation.explanation}</p><label>PROPOSED FIX</label><p>{explanation.proposed_fix}</p><div className="approval-note"><CircleHelp size={15}/> Review and approve changes before applying them.</div></div>}</div></aside></div>}
  {toast&&<div className="toast" role="status">{toast}<button onClick={()=>setToast('')}>×</button></div>}
 </div>
}
export default App
