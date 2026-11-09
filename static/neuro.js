'use strict';
(()=>{
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function request(url,options={}){
 const response=await fetch(url,{cache:'no-store',...options});
 let data={};try{data=await response.json();}catch{}
 if(!response.ok)throw Error(data.error||'Erreur HTTP '+response.status);
 return data;
}
function renderIncidents(rows){
 const box=$('incident-list');
 const counts=rows.reduce((a,x)=>(a[x.status]=(a[x.status]||0)+1,a),{});
 $('incident-status').textContent=rows.length+' incident(s) suivis — '+(counts.open||0)+' ouvert(s), '+(counts.in_progress||0)+' en cours, '+(counts.resolved||0)+' résolu(s).';
 box.innerHTML=rows.length?rows.map(x=>`
 <article class="incident-card ${x.status==='resolved'?'resolved':''}">
  <div class="panel-title"><h3>${esc(x.title)}</h3><span class="severity">${esc(x.severity)}</span></div>
  <div class="incident-meta"><span>${esc(x.ts)} UTC</span><span>${esc(x.category)}</span><span>IP : ${esc(x.ip||'non associée')}</span><span>Événement #${esc(x.event_id)}</span></div>
  <p>${esc(x.detail)}</p>
  <form class="incident-fields" data-incident-id="${Number(x.id)}">
   <label>État<select name="status"><option value="open" ${x.status==='open'?'selected':''}>Ouvert</option><option value="in_progress" ${x.status==='in_progress'?'selected':''}>En cours</option><option value="resolved" ${x.status==='resolved'?'selected':''}>Résolu</option></select></label>
   <label>Responsable<input name="assignee" maxlength="120" value="${esc(x.assignee||'')}" placeholder="Nom de l'analyste"></label>
   <label class="wide">Note / résolution<textarea name="resolution" maxlength="2000" placeholder="Constat, vérifications et action autorisée…">${esc(x.resolution||'')}</textarea></label>
   <button class="primary wide" type="submit">Enregistrer le suivi</button>
  </form>
  <small class="muted">Dernière modification : ${esc(x.updated_at||'—')}</small>
 </article>`).join(''):'<span class="muted">Aucun incident pour le moment. Les prochains événements enregistrés seront suivis ici.</span>';
}
async function loadIncidents(){try{renderIncidents(await request('/api/incidents'));}catch(e){$('incident-status').textContent='Chargement impossible : '+e.message;}}
$('incident-list').addEventListener('submit',async e=>{
 const form=e.target.closest('form[data-incident-id]');if(!form)return;e.preventDefault();
 const button=form.querySelector('button');button.disabled=true;button.textContent='Enregistrement…';
 const data=Object.fromEntries(new FormData(form).entries());data.incident_id=Number(form.dataset.incidentId);
 try{await request('/api/incidents/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});await loadIncidents();}
 catch(err){$('incident-status').textContent='Modification non enregistrée : '+err.message;}
 finally{button.disabled=false;button.textContent='Enregistrer le suivi';}
});
function renderKev(rows){
 const box=$('kev-list');
 box.innerHTML=rows.length?rows.map(v=>`
 <article class="vulnerability-card">
  <div class="panel-title"><h3>${esc(v.cve)} — ${esc(v.vulnerability_name||'Vulnérabilité connue')}</h3><span class="kev-tag">CISA KEV</span></div>
  <div class="incident-meta"><span>${esc(v.vendor)} / ${esc(v.product)}</span><span>Ajout : ${esc(v.date_added||'—')}</span><span>Échéance CISA : ${esc(v.due_date||'—')}</span><span>Ransomware : ${esc(v.ransomware_use)}</span></div>
  <p>${esc(v.description)}</p><div class="kev-action"><b>Action recommandée par CISA :</b> ${esc(v.required_action)}</div>
  <a href="${esc(v.source_url)}" target="_blank" rel="noopener noreferrer">Source officielle du catalogue CISA</a>
 </article>`).join(''):'<span class="muted">Catalogue vide. Lance une synchronisation CISA.</span>';
}
async function loadKev(){
 try{const [rows,status]=await Promise.all([request('/api/vulnerabilities'),request('/api/vulnerabilities/status')]);renderKev(rows);$('kev-status').textContent=status.status+' — '+rows.length+' CVE locales. Dernière synchronisation : '+(status.updated_at||'jamais')+'. Source : CISA KEV.';}
 catch(e){$('kev-status').textContent='Chargement impossible : '+e.message;}
}
$('kev-refresh').addEventListener('click',async()=>{
 const b=$('kev-refresh');b.disabled=true;b.textContent='Synchronisation…';
 try{
  await request('/api/vulnerabilities/refresh',{method:'POST'});
  let state;
  for(let i=0;i<60;i++){await new Promise(r=>setTimeout(r,1500));state=await request('/api/vulnerabilities/status');$('kev-status').textContent=state.status+'…';if(state.status!=='Synchronisation en cours')break;}
  await loadKev();
 }catch(e){$('kev-status').textContent='Synchronisation impossible : '+e.message;}
 finally{b.disabled=false;b.textContent='Synchroniser le catalogue CISA';}
});
$('telegram-test').addEventListener('click',async()=>{
 const b=$('telegram-test');b.disabled=true;b.textContent='Envoi…';
 try{const d=await request('/api/telegram/test',{method:'POST'});$('telegram-status').textContent=d.status+' — vérifie ton canal Telegram.';}
 catch(e){$('telegram-status').textContent='Test non envoyé : '+e.message;}
 finally{b.disabled=false;b.textContent='Tester Telegram';}
});
loadIncidents();loadKev();setInterval(loadIncidents,30000);setInterval(loadKev,60000);
})();