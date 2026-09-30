#!/usr/bin/env python3
"""Board UI: stdlib HTTP server on 127.0.0.1, port 8788.

Same pattern as pentest-viewer: ThreadingHTTPServer + closure handler,
dark-theme CSS vars, polling with a `since=rev` cursor (no websockets).
Cytoscape.js is vendored at static/cytoscape.min.js.

The case file on disk is the source of truth — an MCP server process
mutates it concurrently, so every request re-reads case.json when it is
newer than our cache, and mutations load→apply→flush immediately.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import approval, gaps as gaps_mod, resolver
from .core import Graph
from .store import Store

HERE = os.path.dirname(os.path.abspath(__file__))
CYTO_JS = os.path.join(HERE, "static", "cytoscape.min.js")

_TYPE_COLORS = {
    "person": "#e692ff", "company": "#6db9ff", "domain": "#8de69c",
    "subdomain": "#5fcf7c", "ip": "#ffd166", "netblock": "#f2b24a",
    "asn": "#e08d3c", "username": "#c9a0ff", "account": "#a988f5",
    "email": "#ff9e9e", "phone": "#ffa8d0", "location": "#9ad9d9",
    "event": "#ffe08a", "document": "#b8c4d9", "device": "#7fd0c3",
    "money": "#7fe0a8",
}


def _state(g: Graph) -> dict:
    """Compact full snapshot for the board."""
    ents = {}
    for e in g.entities.values():
        ents[e.id] = {"id": e.id, "type": e.type, "name": e.name,
                      "depth": e.depth, "investigated": e.investigated}
    edges = [{"id": x.id, "source": x.source, "target": x.target,
              "relationship": x.relationship,
              "confidence": round(x.confidence, 2),
              "when": x.when, "amount": x.amount}
             for x in g.edges]
    notes = ""
    try:
        with open(os.path.join(_store.cases_dir, g.case_id, "notes.md"),
                  encoding="utf-8") as f:
            notes = f.read()
    except OSError:
        pass
    return {
        "rev": g.rev, "title": g.title, "case_id": g.case_id,
        "write_mode": g.write_mode,
        "seeds": list(g.seeds), "queue": [g.entities[s].name
                                          for s in g.search_queue
                                          if s in g.entities],
        "entities": ents, "edges": edges,
        "sources_count": len(g.sources),
        "gaps": list(g.gaps), "pending_merge": list(g.pending_merge),
        "staged": approval.review(g), "findings": g.findings[-25:],
        "no_links": len(g.no_links), "notes": notes,
    }


_store = None


def _resolve_case(store: Store, case_id: str) -> str:
    """Pick the case to serve: explicit id, else most recently modified."""
    if case_id:
        return case_id
    index = store.list_cases()
    if not index:
        r = store.new_case("Untitled Case")
        return r["case_id"]
    return index[0]["case_id"]


_STYLE = """
:root {
  --bg: #12141a; --panel: #1a1d26; --panel2: #20242f; --line: #2b3140;
  --text: #d8dde8; --dim: #8b93a5; --accent: #6db9ff; --warn: #e0a13c;
  --bad: #e05f5f; --good: #6fd08c;
}
@media (prefers-color-scheme: light) { :root:not([data-theme="dark"]) {
  --bg: #f2f3f7; --panel: #ffffff; --panel2: #eceef4; --line: #d5d9e2;
  --text: #22262f; --dim: #6b7280; --accent: #2472c8; --warn: #a8701d;
  --bad: #c04343; --good: #2e8a52;
} }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.45 system-ui, sans-serif; overflow: hidden; }
#shell { display: grid; grid-template-columns: 1fr 340px;
  grid-template-rows: 44px 1fr; height: 100vh; }
header { grid-column: 1 / 3; display: flex; align-items: center;
  gap: 10px; padding: 0 12px; background: var(--panel);
  border-bottom: 1px solid var(--line); white-space: nowrap; }
header h1 { font-size: 15px; margin: 0 6px 0 0; font-weight: 600; }
header .meta { color: var(--dim); font-size: 12px; }
header .hbtn { background: var(--panel2); color: var(--dim); font-size: 12px;
  padding: 3px 10px; border: 1px solid var(--line); border-radius: 9px;
  cursor: pointer; white-space: nowrap; }
header .hbtn:hover { color: var(--text); border-color: var(--accent); }
.badge { font-size: 11px; padding: 2px 8px; border-radius: 9px;
  border: 1px solid var(--line); color: var(--dim); cursor: pointer; }
.badge.on { color: var(--warn); border-color: var(--warn); }
.badge.alert { color: var(--bad); border-color: var(--bad); }
#cy { background: var(--bg); }
#side { background: var(--panel); border-left: 1px solid var(--line);
  overflow-y: auto; padding: 10px; }
.tabs { display: flex; gap: 6px; margin-bottom: 8px; }
.tabs button { flex: 1; background: var(--panel2); color: var(--dim);
  border: 1px solid var(--line); border-radius: 6px; padding: 4px 0;
  font: inherit; font-size: 12px; cursor: pointer; }
.tabs button.sel { color: var(--text); border-color: var(--accent); }
.card { background: var(--panel2); border: 1px solid var(--line);
  border-radius: 8px; padding: 8px 10px; margin-bottom: 8px; }
.card h3 { margin: 0 0 4px; font-size: 13px; }
.card .sub { color: var(--dim); font-size: 12px; }
.card .score { float: right; background: var(--bad); color: #fff;
  font-size: 11px; border-radius: 8px; padding: 1px 7px; }
.btns { margin-top: 6px; display: flex; gap: 6px; flex-wrap: wrap; }
.btns button { background: var(--panel); color: var(--text);
  border: 1px solid var(--line); border-radius: 5px; padding: 3px 9px;
  font: inherit; font-size: 12px; cursor: pointer; }
.btns button:hover { border-color: var(--accent); }
.btns button.hot:hover { border-color: var(--bad); color: var(--bad); }
#detail .kv { margin: 2px 0; font-size: 12px; }
#detail .kv b { color: var(--dim); font-weight: 500; }
.prov { color: var(--dim); font-size: 11px; }
.edge-line { font-size: 12px; margin: 2px 0; }
.edge-line .rel { color: var(--accent); }
#filters { position: absolute; top: 8px; left: 10px; display: flex;
  gap: 4px; flex-wrap: wrap; z-index: 5; }
#filters .chip { font-size: 11px; padding: 2px 8px; border-radius: 9px;
  border: 1px solid var(--line); color: var(--dim); cursor: pointer; }
#filters .chip.off { opacity: .3; }
#legend { position: absolute; left: 12px; bottom: 10px; font-size: 11px;
  color: var(--dim); background: color-mix(in srgb, var(--panel) 70%, transparent);
  padding: 6px 9px; border-radius: 8px; border: 1px solid var(--line);
}
#legend span { margin-right: 8px; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 3px; }
.finding { font-size: 12px; color: var(--dim); border-left: 2px solid
  var(--line); padding: 2px 8px; margin: 4px 0; }
textarea.note-in { width: 100%; background: var(--panel); color: var(--text);
  border: 1px solid var(--line); border-radius: 6px; font: inherit;
  font-size: 12px; padding: 4px; }
"""

_JS = r"""
const COLORS = %COLORS%;
const TYPES = Object.keys(COLORS);
let cy = null, cur = null, since = 0, tab = 'cards', sel = null;
const $ = id => document.getElementById(id);

function jsonGet(url, fn) {
  fetch(url).then(r => r.json()).then(fn).catch(()=>{});
}
function post(data, fn) {
  fetch('/api/action', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(data)})
    .then(r=>r.json()).then(fn||refresh).catch(()=>{});
}
function esc(s){ const d=document.createElement('div'); d.textContent=s==null?'':s; return d.innerHTML; }

// ------------------------------------------------ board
function nodeColor(t){ return COLORS[t] || '#999'; }
function mkNode(e){
  return { group:'nodes', data:{
    id:e.id, label:e.name, type:e.type, depth:e.depth,
    inv:e.investigated, seed:cur.seeds.includes(e.id) } };
}
function syncGraph(){
  const want = new Set(Object.keys(cur.entities));
  let added = 0;
  cy.nodes().forEach(n=>{ if(!want.has(n.id)) n.remove(); });
  cy.batch(()=>{
    for (const e of Object.values(cur.entities)){
      let n = cy.$id(e.id);
      if (n.empty()){
        n = cy.add(mkNode(e)); added++;
        if (laid){ // drop newcomers near the middle of the viewport
          const v = cy.viewport(), p = cy.pan();
          n.position({x: v.w/2 + (Math.random()*120-60),
                      y: v.h/2 + (Math.random()*120-60)});
        }
      }
      else { n.data({label:e.name, depth:e.depth, inv:e.investigated,
              seed:cur.seeds.includes(e.id)}); }
      n.style('background-color', nodeColor(e.type));
      n.style('border-width', e.investigated?2:1.2);
      n.style('border-style', e.investigated?'double':'solid');
    }
    const wantE = new Set(cur.edges.map(x=>x.id));
    cy.edges('[!ghost]').forEach(x=>{ if(!wantE.has(x.id)) x.remove(); });
    for (const x of cur.edges){
      let el = cy.$id(x.id);
      if (el.empty()){
        el = cy.add({group:'edges', data:{id:x.id, source:x.source,
          target:x.target, rel:x.relationship, conf:x.confidence}, classes:''});
      }
      el.data({rel:x.relationship, conf:x.confidence});
      const canon = ['owns','controls','employs','subsidiary_of','affiliated_with',
        'subdomain_of','resolves_to','hosted_on','registered_to','located_in',
        'uses_serves','communicates_with','mentions','paid_to','related_to']
        .includes(x.relationship);
      el.style({
        width: 0.4 + x.confidence*2.6,
        lineStyle: canon? 'solid':'dashed',
        opacity: x.confidence < 0.4 ? 0.3 : 0.85,
      });
    }
  });
  // gap ghosts (rebuilt from scratch)
  cy.edges('[ghost]').remove();
  for (const gp of cur.gaps){
    if (!cur.entities[gp.a] || !cur.entities[gp.c]) continue;
    cy.add({group:'edges', data:{id:'gap-'+gp.a+'-'+gp.c, source:gp.a,
      target:gp.c, rel:'? gap '+gp.score}, classes:'ghost', grabbable:false});
  }
  return added;
}
const GAP_STYLE = {
  'line-style':'dashed','line-dash-pattern':[3,5],'line-color':'#e05f5f',
  'width':1.2,'opacity':0.9,'curve-style':'bezier',
  'target-arrow-shape':'triangle','target-arrow-color':'#e05f5f',
  'arrow-scale':0.6,'label':'data(rel)','font-size':9,'color':'#e05f5f',
};
let laid = false;
function board(){
  cy = cytoscape({
    container: $('cy'), elements: [],
    layout: {name:'cose', animate:false, nodeOverlap:60, idealEdgeLength:120,
             gravity:60, padding:40},
    style: [
      {selector:'node', style:{
        shape:'ellipse','background-color':'#6db9ff','border-color':'#0c0e12',
        'border-width':1.2,label:'data(label)',color:'#75808f',
        'font-size':11,'text-valign':'bottom','text-margin-y':5,
        'font-weight':600,'text-wrap':'wrap','text-max-width':130}},
      {selector:'node[?seed]', style:{'border-color':'#6fd08c',
        'border-width':2.5}},
      {selector:'node[?inv]', style:{'background-opacity':0.6}},
      {selector:'edge', style:{
        color:'#75808f','font-size':9,label:'data(rel)',
        'line-color':'#4a5468','curve-style':'bezier'}},
      {selector:'edge.ghost', style: GAP_STYLE},
    ],
    wheelSensitivity: 0.2,
  });
  cy.on('tap','node', ev=>{ select(ev.target.id()); });
  cy.on('tap','edge.ghost', ev=>{
    const gp = cur.gaps.find(g=>'gap-'+g.a+'-'+g.c===ev.target.id());
    if (gp){ tabSwitch('cards'); showGap(gp); }
  });
  cy.on('tap', ev=>{ if(ev.target===cy) clearDetail(); });
}

// ------------------------------------------------ detail panel
function select(id){
  const e = cur.entities[id]; if (!e) return;
  sel = id;
  tabSwitch('detail');
  jsonGet('/api/entity?id='+encodeURIComponent(id), d=>{
    if (d.error){ $('detail').innerHTML = '<div class="card">'+esc(d.error)
      +'<br>…'+esc((d.candidates||[]).map(c=>c.name).join(', '))+'</div>'; return; }
    const x = d.entity, srcNames = d.sources||{};
    const meta = Object.entries(x.metadata||{}).map(([k,v])=>
      `<div class="kv"><b>${esc(k)}</b> ${esc(v.value)} <span class="prov">`
      +(v.src? '· '+esc(srcNames[v.src]||v.src):'')+'</span></div>').join('');
    const prov = Object.entries(x.provenance||{}).map(([k,vs])=>
      `<div class="kv"><b>${esc(k)}</b> older: `
      +vs.map(v=>esc(v.value)).join(' · ')+'</div>').join('');
    const edges = (d.edges||[]).map(x2=>{
      const a = cur.entities[x2.source], b = cur.entities[x2.target];
      return `<div class="edge-line"><span class="rel">${esc(x2.relationship)}</span> `
        +esc(a?a.name:'?')+' → '+esc(b?b.name:'?')
        +` <span class="prov">(${x2.confidence})</span></div>`;
    }).join('');
    $('detail').innerHTML = `
      <div class="card">
        <h3>${esc(x.name)}</h3>
        <div class="sub">${esc(x.type)} · ${esc(x.key)} · depth ${x.depth}</div>
        <div class="kv"><b>aliases</b> ${esc((x.aliases||[]).join(', ')||'—')}</div>
        <div class="kv"><b>discovered</b> ${esc(x.discovered_at||'—')}</div>
        ${x.merged_from?'<div class="kv"><b>merged</b> '+esc(x.merged_from.join(', '))+'</div>':''}
      </div>
      <div class="card"><h3>attributes</h3>${meta||'<div class="sub">none</div>'}${prov}</div>
      <div class="card"><h3>links (${(d.edges||[]).length})</h3>${edges||'<div class="sub">none</div>'}</div>
      <div class="btns">
        <button onclick="act('queue',{ref:'${x.id}'})">Queue</button>
        <button onclick="act('investigate',{ref:'${x.id}'})">Mark investigated</button>
        <button class="hot" onclick="prune('${x.id}')">Prune</button>
      </div>`;
  });
}
function clearDetail(){ sel=null; if(tab==='detail') $('detail').innerHTML =
  '<div class="sub">select a node on the board</div>'; }

// ------------------------------------------------ sidebar
function showGap(gp){
  if (!cur) return;
  const cards = $('cards');
  const gs = cur.gaps || [];
  cards.innerHTML = ''
    + '<div class="card sub">' + (gs.length
       ? gs.length + ' research gaps (scored)'
       : 'no gaps flagged yet') + '</div>'
    + gs.map(gapCard).join('')
    + (gp && gp.a ? '' : '')
    + (cur.pending_merge||[]).map(mergeCard).join('')
    + (cur.staged||[]).map(stagedCard).join('')
    + '<div class="card"><h3>notes</h3>'
    + '<textarea class="note-in" id="notein" rows="2" placeholder="note / research outcome…"></textarea>'
    + '<div class="btns"><button onclick="addNote()">Save note</button></div>'
    + '<div class="sub">'+esc(cur.notes&&cur.notes.split(/\n/).slice(-6).join('\n'))+'</div></div>'
    + '<div class="card"><h3>findings</h3>'+(cur.findings||[]).map(f=>
        '<div class="finding">'+esc(f)+'</div>').join('')+'</div>';
  if (gp && gp.a){ const el = document.getElementById(
      'gapcard-'+gp.a+'-'+gp.c); if (el) el.scrollIntoView({block:'center'}); }
  else if (gp){ // queue/staged/finding flash: no-op placeholder
  }
}
function gapCard(gp){
  return `<div class="card" id="gapcard-${gp.a}-${gp.c}"><span class="score">${gp.score}</span>
    <h3>${esc(gp.a_name)} ↔ ${esc(gp.c_name)}</h3>
    <div class="sub">${esc(gp.reasons||'')} · via ${esc((gp.bridges||[]).join(', ')||'—')}</div>
    <div class="btns">
      <button onclick="gapLink('${gp.a}','${gp.c}')">Link…</button>
      <button class="hot" onclick="gapRefute('${gp.a}','${gp.c}')">No connection</button>
      <button onclick="focusPair('${gp.a}','${gp.c}')">Show</button>
    </div></div>`;
}
function mergeCard(m){
  return `<div class="card"><span class="score" style="background:var(--warn)">merge</span>
    <h3>${esc(m.a_name)} ← ${esc(m.b_name)}</h3>
    <div class="sub">${esc(m.why||'')} (${esc(m.b_type)})</div>
    <div class="btns">
      <button onclick="act('approve',{ids:['${m.id}']})">Merge</button>
      <button class="hot" onclick="act('reject',{ids:['${m.id}']})">Different</button>
    </div></div>`;
}
function stagedCard(s){
  const p = s.payload||{};
  if (s.kind==='entity')
    return `<div class="card"><span class="score" style="background:var(--accent)">stage</span>
      <h3>+ ${esc(p.name)}</h3><div class="sub">${esc(p.type)}</div>
      <div class="btns"><button onclick="act('approve',{ids:['${s.id}']})">Add</button>
      <button class="hot" onclick="act('reject',{ids:['${s.id}']})">Reject</button></div></div>`;
  return `<div class="card"><span class="score" style="background:var(--accent)">stage</span>
    <h3>${esc(p.source)} → ${esc(p.target)}</h3>
    <div class="sub">${esc(p.relationship)} (${p.confidence||0.5})</div>
    <div class="btns"><button onclick="act('approve',{ids:['${s.id}']})">Add</button>
    <button class="hot" onclick="act('reject',{ids:['${s.id}']})">Reject</button></div></div>`;
}
function focusPair(a,c){
  for (const id of [a,c]) if (cur.entities[id]) cy.$id(id).select();
  cy.$id(a).neighborhood().nodes().select();
}

// ------------------------------------------------ actions
function act(action, data){ post(Object.assign({action},data)); }

// --------------------------------------------- new case / wipe (header)
function hardReset(){ since = 0; cur = null; laid = false;
  if (cy) cy.remove('*'); refresh(); }
function newCase(){
  const t = prompt('Name for the new case:', 'Untitled Case');
  if (t === null) return;                     // cancelled
  post({action:'new_case', title:t}, r=>{
    if (r && r.error) alert('Could not create case: '+r.error);
    else hardReset();
  });
}
function wipeCase(){
  const n = cur ? Object.keys(cur.entities).length : 0;
  const m = cur ? (cur.edges||[]).length : 0;
  if (!confirm('Wipe this case ('+n+' entities, '+m+' links)? '+
      'History stays in the .bak backups inside cases/.')) return;
  if (n > 8 && !confirm('That is a lot of work — really start from empty? '+
      '(the old graph stays in the .bak chain)')) return;
  post({action:'wipe_case'}, r=>{ if (r && r.error) alert(r.error);
    else hardReset(); });
}
function prune(id){ const n=cur.entities[id];
  if (n && confirm('Prune "'+n.name+'" and its links?'))
    act('prune',{id}); }
function gapRefute(a,c){ const why = prompt('Confirmed no connection because…');
  if (why===null) return;
  act('close_gap',{a,c,confirmed:false,detail:why||''}); }
function gapLink(a,c){ const rel = prompt('Relationship (owns, employs, paid_to…):');
  if (!rel) return;
  act('link',{source:cur.entities[a].name, target:cur.entities[c].name,
    relationship:rel.toLowerCase().replace(/ /g,'_'), confidence:0.6}); }
function addNote(){ const t=$('notein').value.trim(); if(!t) return;
  act('note',{text:t}); $('notein').value=''; }

// ------------------------------------------------ polling + filters
function renderMeta(){
  $('title').textContent = cur.title;
  $('meta').textContent = 'rev '+cur.rev+' · '
    +Object.keys(cur.entities).length+' nodes · '
    +cur.edges.length+' links · '+cur.sources_count+' sources';
  $('gapbadge').textContent = cur.gaps.length+' gaps';
  $('gapbadge').className = 'badge' + (cur.gaps.length?' alert':' on');
  $('mbadge').textContent = 'merges '+cur.pending_merge.length;
  $('mbadge').className = 'badge' + (cur.pending_merge.length?' alert':'');
  $('wbadge').textContent = 'write: '+cur.write_mode;
  $('wbadge').className = 'badge' + (cur.write_mode==='stage'?' on':'');
  document.title = cur.title + ' — OSINT Map';
}
function renderFilters(){
  const counts = {};
  for (const e of Object.values(cur.entities)) counts[e.type]=(counts[e.type]||0)+1;
  const lg = $('legend');
  lg.innerHTML = TYPES.filter(t=>counts[t]).map(t=>
    `<span><span class="dot" style="background:${nodeColor(t)}"></span>${t} ${counts[t]}</span>`
  ).join('') || 'empty case';
  const fc = $('filters');
  for (const t of TYPES){
    let el = document.querySelector('.chip[data-t="'+t+'"]');
    if (!el){ el=document.createElement('span'); el.className='chip';
      el.dataset.t=t; el.onclick=()=>filterToggle(el,t); fc.appendChild(el); }
    el.textContent = t+' '+(counts[t]||0);
  }
}
const hidden = new Set();
function filterToggle(el,t){
  el.classList.toggle('off');
  if (hidden.has(t)) hidden.delete(t); else hidden.add(t);
  cy.nodes('[type="'+t+'"]').style('display', hidden.has(t)?'none':'element');
  cy.nodes().connectedEdges().forEach(x2=>{
    const vis = !hidden.has(x2.source().data('type')) &&
                !hidden.has(x2.target().data('type'));
    x2.style('display', vis?'element':'none');
  });
}
function refresh(){
  jsonGet('/api/state?since='+since, d=>{
    if (d.unchanged) return;
    cur = d; since = d.rev;
    if (!cy) { board(); renderFilters(); }
    const added = syncGraph(); renderMeta();
    if (!laid && Object.keys(cur.entities).length){
      laid = true;
      cy.nodes().layout({name:'cose', animate:false, nodeOverlap:60,
                         idealEdgeLength:120, gravity:60}).run();
      cy.fit(undefined, 40);
    } else if (added){ /* newcomers keep their near-centre spot */ }
    if (tab==='cards') showGap({}); // rebuild cards
    if (tab==='detail' && sel && cur.entities[sel]) select(sel);
    if (tab==='detail' && sel && !cur.entities[sel]) clearDetail();
  });
}
function tabSwitch(t){
  tab = t;
  $('tab-cards').className = t==='cards'?'sel':'';
  $('tab-detail').className = t==='detail'?'sel':'';
  $('detail').style.display = t==='detail'?'block':'none';
  $('cards').style.display = t==='cards'?'block':'none';
  if (t==='cards') showGap({});
}
setInterval(refresh, 2500);
window.onload = ()=>{ tabSwitch('cards'); refresh(); };
"""

_HTML = f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Map</title>
<style>{_STYLE}</style>
</head><body>
<div id="shell">
<header>
  <h1 id="title">…</h1>
  <span class="meta" id="meta"></span>
  <span style="flex:1"></span>
  <button class="hbtn" onclick="newCase()">＋ New case</button>
  <button class="hbtn" onclick="wipeCase()">Wipe</button>
  <span class="badge" id="gapbadge">gaps</span>
  <span class="badge" id="mbadge">merges</span>
  <span class="badge" id="wbadge">write: auto</span>
</header>
<div id="cywrap" style="position:relative">
  <div id="cy" style="position:absolute;inset:0"></div>
  <div id="filters"></div>
  <div id="legend"></div>
</div>
<aside id="side">
  <div class="tabs">
    <button id="tab-cards" onclick="tabSwitch('cards')">Cards</button>
    <button id="tab-detail" onclick="tabSwitch('detail')">Detail</button>
  </div>
  <div id="cards"></div>
  <div id="detail" style="display:none"></div>
</aside>
</div>
<script src="static/cytoscape.min.js"></script>
<script>{_JS.replace("%COLORS%", json.dumps(_TYPE_COLORS))}</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    store: Store = None
    case_id: str = ""

    def log_message(self, fmt, *args):  # quieter
        pass

    # -------------------------------------------------- helpers

    def _g(self) -> Graph | None:
        """Fresh Graph from disk — the MCP server process mutates case.json
        concurrently, so we never rely on a stale in-memory copy. Each HTTP
        request gets a fresh handler instance, so there is no memory cache.
        An empty case_id means 'auto' — resolve the newest case per request
        (a wipe/new-case button must be able to change what is served)."""
        cid = self.case_id or _resolve_case(self.store, "")
        return self.store.load_case(cid)

    def _json(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _static(self) -> None:
        try:
            with open(CYTO_JS, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            self.send_error(404, "vendored cytoscape.min.js missing — "
                             "see static/ dir")

    # -------------------------------------------------- GET

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", ""):
            body = _HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/static/cytoscape.min.js":
            self._static()
        elif u.path == "/api/state":
            g = self._g()
            if g is None:
                return self._json({"error": "case not found"})
            q = parse_qs(u.query)
            try:
                since = int(q.get("since", ["0"])[0])
            except ValueError:
                since = 0
            # rebuild gap cards on every poll (cheap at this scale)
            g.gaps = gaps_mod.find_gaps(g) if g.seeds else g.gaps
            if g.dirty:
                self.store.write_case(g)
                g = self._g()
            st = _state(g)
            if since and since == st["rev"]:
                return self._json({"rev": since, "unchanged": True})
            self._json(st)
        elif u.path == "/api/entity":
            g = self._g()
            if g is None:
                return self._json({"error": "case not found"})
            q = parse_qs(u.query)
            ref = (q.get("id", [""])[0]).strip()
            r = g.resolve_ref(ref)
            if "error" in r:
                return self._json(r)
            e = r["entity"]
            edges = [x.to_dict() for x in g.edges
                     if x.source == e.id or x.target == e.id]
            self._json({"entity": e.to_dict(), "edges": edges,
                        "sources": {sid: s.get("tool", "?")
                                    for sid, s in g.sources.items()}})
        else:
            self.send_error(404)

    # -------------------------------------------------- POST actions

    def do_POST(self):
        if urlparse(self.path).path != "/api/action":
            return self.send_error(404)
        try:
            n = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._json({"error": "bad json"}, 400)
        g = self._g()
        if g is None:
            return self._json({"error": "case not found"})
        act = req.get("action", "")
        out: dict = {"done": act}

        if act == "queue":
            out = g.queue(req.get("ref", ""))
        elif act == "investigate":
            r = g.resolve_ref(req.get("ref", ""))
            if "error" in r:
                out = r
            else:
                r["entity"].investigated = True
                g.dirty = True
                out = {"investigated": r["entity"].id}
        elif act == "prune":
            r = g.resolve_ref(req.get("id", ""))
            out = g.prune(r["entity"].id) if "entity" in r else r
        elif act == "link":
            ra = g.resolve_ref(req.get("source", ""))
            rb = g.resolve_ref(req.get("target", ""))
            if "error" in ra:
                out = ra
            elif "error" in rb:
                out = rb
            else:
                out = g.link(ra["entity"].id, rb["entity"].id,
                             req.get("relationship", "related_to"),
                             float(req.get("confidence", 0.5)),
                             source_note="ui")
                if "id" in out and req.get("a") and req.get("c"):
                    gaps_mod.close_gap(g, ra["entity"].id, rb["entity"].id,
                                       True, out.get("relationship", ""))
        elif act == "close_gap":
            ra = g.resolve_ref(req.get("a", ""))
            rb = g.resolve_ref(req.get("c", ""))
            if "error" in ra:
                out = ra
            elif "error" in rb:
                out = rb
            else:
                out = gaps_mod.close_gap(
                    g, ra["entity"].id, rb["entity"].id,
                    bool(req.get("confirmed")), req.get("detail", ""))
        elif act == "approve" or act == "reject":
            out = approval.act(g, list(req.get("ids", [])), act)
        elif act == "set_write_mode":
            m = req.get("mode", "")
            if m in ("auto", "stage"):
                g.write_mode = m
                g.dirty = True
                out = {"write_mode": m}
            else:
                out = {"error": "mode must be auto|stage"}
        elif act == "note":
            g.add_finding(req.get("text", ""))
            out = {"note": True}
        elif act == "new_case":
            # The current case is untouched (already flushed); a fresh one
            # becomes index[0], so /api/state resolves to it next poll.
            t = str(req.get("title", "")).strip() or "Untitled Case"
            out = self.store.new_case(t)
        elif act == "wipe_case":
            # Empty THIS case in place (same id/title: board keeps serving
            # it). fresh.rev inherits the old rev so _flush drops a .bak-<rev>
            # copy first — the .bak chain is the undo for a wipe.
            fresh = Graph()
            fresh.case_id = g.case_id
            fresh.title = g.title
            fresh.rev = g.rev
            self.store.write_case(fresh, immediate=True)
            out = {"wiped": g.case_id}
        else:
            out = {"error": f"unknown action {act!r}"}

        if g.dirty:
            self.store.write_case(g, immediate=True)
            g.dirty = False
        self._json(out)


def serve(store: Store | None = None, case_id: str = "", port: int = 8788,
          host: str = "127.0.0.1") -> ThreadingHTTPServer:
    """Run the board. Returns the server (tests bind port=0 and poll).

    case_id pinning is opt-in: pinned serves THAT case forever; auto ("")
    serves the newest case per request, so UI case actions can switch."""
    store = store or Store()
    global _store
    _store = store
    if case_id:
        cid = _resolve_case(store, case_id)
        if not store.case_exists(cid):
            raise SystemExit(f"case {cid!r} not found")
    else:
        cid = ""

    handler = type("H", (_Handler,), {"store": store, "case_id": cid})
    httpd = ThreadingHTTPServer((host, port), handler)
    if cid:
        title = (store.load_case(cid) or Graph()).title
        print(f"osint-map board: {title!r} ({cid}) → http://{host}:{port}"
              "  (Ctrl-C to stop)", flush=True)
    else:
        print(f"osint-map board (auto: newest case) → http://{host}:{port}",
              flush=True)
    return httpd