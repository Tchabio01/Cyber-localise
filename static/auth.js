'use strict';
(()=>{
const $=id=>document.getElementById(id);
const cfg=window.CW_SUPABASE_CONFIG||{};
let client=null,user=null,activeOrg='';
try{activeOrg=localStorage.getItem('cw_active_org')||'';}catch{}
const status=(id,msg)=>{const el=$(id);if(el)el.textContent=msg;};
const errorText=e=>e instanceof Error?e.message:String(e);
function storeActiveOrg(){try{localStorage.setItem('cw_active_org',activeOrg);}catch{status('cloud-state','Choix d’organisation actif pour cette session, mais le navigateur ne peut pas le mémoriser.');}}
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function showSession(on){$('auth-forms').hidden=on;$('account-session').hidden=!on;}
async function refreshOrgs(){
 const sel=$('org-select');sel.innerHTML='<option value="">Chargement…</option>';
 const {data,error}=await client.from('organization_members').select('organization_id,role,organizations(id,name)').eq('user_id',user.id);
 if(error)throw error;sel.innerHTML='<option value="">Choisir une organisation</option>';
 for(const m of data||[]){const o=document.createElement('option');o.value=m.organization_id;o.textContent=(m.organizations?.name||'Organisation')+' — '+m.role;sel.append(o);}
 if(data?.some(x=>x.organization_id===activeOrg))sel.value=activeOrg;
 else{activeOrg=data?.[0]?.organization_id||'';sel.value=activeOrg;storeActiveOrg();}
 await loadAdmin();
}
async function loadProfile(){
 const {data,error}=await client.from('profiles').select('display_name').eq('user_id',user.id).maybeSingle();
 if(error)throw error;$('profile-email').textContent=user.email||user.id;$('profile-name').value=data?.display_name||user.user_metadata?.display_name||'';
}
async function loadAdmin(){
 const admin=user?.app_metadata?.platform_role==='admin';$('admin-content').hidden=!admin;
 if(!admin){status('admin-state','Accès refusé : rôle administrateur non attribué côté serveur.');return;}
 status('admin-state','Accès administrateur autorisé.');
 const [profiles,orgs]=await Promise.all([client.from('profiles').select('user_id,display_name,created_at').order('created_at',{ascending:false}).limit(200),client.from('organizations').select('id,name,created_at').order('created_at',{ascending:false}).limit(200)]);
 if(profiles.error||orgs.error){status('admin-state','Erreur : '+(profiles.error||orgs.error).message);return;}
 $('admin-users-count').textContent=profiles.data.length;$('admin-orgs-count').textContent=orgs.data.length;
 $('admin-users').innerHTML=profiles.data.map(p=>'<div class="admin-user"><b>'+esc(p.display_name||'Sans nom')+'</b><small>'+esc(p.user_id)+' • '+esc(p.created_at)+'</small></div>').join('')||'Aucun profil';
 if(activeOrg){const {data,error}=await client.from('organization_members').select('user_id,role,created_at').eq('organization_id',activeOrg);$('admin-members').innerHTML=error?esc(error.message):(data||[]).map(m=>'<div class="admin-user">'+esc(m.user_id)+' — '+esc(m.role)+'</div>').join('')||'Aucun membre';}else $('admin-members').textContent='Choisis une organisation.';
}
async function syncCloud(){
 if(!activeOrg)throw Error('Choisis ou crée une organisation avant la synchronisation.');
 const box=$('sync-state');box.textContent='Lecture des données locales…';
 const res=await fetch('/api/data',{cache:'no-store'});if(!res.ok)throw Error('API SOC locale indisponible.');
 const d=await res.json();
 const threats=(d.points||[]).map(p=>({organization_id:activeOrg,ip:p.ip,source:p.src,kind:p.kind,label:p.label,country:p.country,country_code:p.cc,city:p.city,lat:p.lat,lon:p.lon,first_seen:p.first_seen,last_seen:p.last_seen,reported_by:user.id,origin:'local_collector'}));
 const events=(d.events||[]).map(e=>({organization_id:activeOrg,local_event_id:String(e.id),ts:e.ts,severity:e.severity,category:e.category,title:e.title,detail:e.detail,ip:e.ip||null,reported_by:user.id}));
 let tCount=0,eCount=0;
 if(threats.length){const {error}=await client.from('cloud_threat_observations').upsert(threats,{onConflict:'organization_id,ip,source,reported_by'});if(error)throw error;tCount=threats.length;}
 if(events.length){const {error}=await client.from('cloud_incident_events').upsert(events,{onConflict:'organization_id,local_event_id,reported_by'});if(error)throw error;eCount=events.length;}
 box.textContent='Synchronisation terminée : '+tCount+' observations et '+eCount+' événements envoyés. Contributions déclarées par un membre, non certifiées automatiquement.';
 await loadAdmin();
}
async function init(){
 if(!cfg.url||!cfg.publishableKey){status('cloud-state','Cloud non configuré. Renseigne CW_SUPABASE_URL et CW_SUPABASE_PUBLISHABLE_KEY sur le serveur.');return;}
 if(!window.supabase?.createClient){status('cloud-state','Bibliothèque Supabase indisponible. Vérifie la connexion Internet.');return;}
 try{client=window.supabase.createClient(cfg.url,cfg.publishableKey);}catch(e){status('cloud-state','Configuration Supabase invalide : '+errorText(e));return;}
 status('cloud-state','Service cloud configuré. Connecte-toi pour accéder à ton espace.');
 $('signup-form').onsubmit=async e=>{e.preventDefault();status('cloud-state','Création du compte…');try{const {data,error}=await client.auth.signUp({email:$('signup-email').value,password:$('signup-password').value,options:{data:{display_name:$('signup-name').value.trim()}}});if(error)throw error;if(data.session){user=data.user;await afterLogin();}else status('cloud-state','Compte créé. Consulte ta boîte e-mail pour confirmer ton adresse avant la première connexion.');}catch(error){status('cloud-state','Inscription impossible : '+errorText(error));}};
 $('signin-form').onsubmit=async e=>{e.preventDefault();status('cloud-state','Connexion…');try{const {data,error}=await client.auth.signInWithPassword({email:$('signin-email').value,password:$('signin-password').value});if(error)throw error;user=data.user;await afterLogin();}catch(error){status('cloud-state','Connexion impossible : '+errorText(error));}};
 $('signout-button').onclick=async()=>{try{const {error}=await client.auth.signOut();if(error)throw error;user=null;activeOrg='';storeActiveOrg();showSession(false);status('cloud-state','Déconnexion effectuée.');}catch(error){status('cloud-state','Déconnexion impossible : '+errorText(error));}};
 $('profile-form').onsubmit=async e=>{e.preventDefault();try{const {error}=await client.from('profiles').upsert({user_id:user.id,display_name:$('profile-name').value.trim(),updated_at:new Date().toISOString()});if(error)throw error;status('cloud-state','Profil enregistré dans le cloud.');}catch(error){status('cloud-state','Profil non enregistré : '+errorText(error));}};
 $('org-create-form').onsubmit=async e=>{e.preventDefault();const name=$('org-name').value.trim();try{const {data,error}=await client.from('organizations').insert({name,created_by:user.id}).select('id').single();if(error)throw error;activeOrg=data.id;storeActiveOrg();$('org-name').value='';await refreshOrgs();status('cloud-state','Organisation créée. Tu en es propriétaire.');}catch(error){status('cloud-state','Création impossible : '+errorText(error));}};
 $('org-select').onchange=async e=>{activeOrg=e.target.value;storeActiveOrg();try{await loadAdmin();}catch(error){status('admin-state','Chargement impossible : '+errorText(error));}};
 $('cloud-sync-button').onclick=async()=>{try{await syncCloud();}catch(e){status('sync-state','Échec de synchronisation : '+e.message);}};
 $('team-add-form').onsubmit=async e=>{e.preventDefault();if(!activeOrg){status('team-state','Choisis une organisation.');return;}try{const {error}=await client.from('organization_members').insert({organization_id:activeOrg,user_id:$('team-user-id').value.trim(),role:$('team-role').value});if(error)throw error;$('team-user-id').value='';status('team-state','Membre ajouté à l’organisation.');await refreshOrgs();}catch(error){status('team-state','Ajout refusé : '+errorText(error));}};
 try{const {data:{session},error}=await client.auth.getSession();if(error)throw error;if(session){user=session.user;await afterLogin();}}catch(error){status('cloud-state','Impossible de récupérer la session : '+errorText(error));}
 client.auth.onAuthStateChange((_event,session)=>{if(session){user=session.user;queueMicrotask(()=>afterLogin().catch(error=>status('cloud-state','Session active, mais chargement impossible : '+errorText(error))));}else{user=null;activeOrg='';showSession(false);}});
}
async function afterLogin(){showSession(true);status('cloud-state','Connecté : '+(user.email||user.id));try{await loadProfile();await refreshOrgs();}catch(e){status('cloud-state','Connecté, mais profil/organisations indisponibles : '+errorText(e));}}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();