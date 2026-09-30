let token=localStorage.getItem('synth_admin_token')||'';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
async function api(path,opt={}){opt.headers={...(opt.headers||{}),Authorization:`Bearer ${token}`};const r=await fetch(path,opt);if(r.status===401){localStorage.removeItem('synth_admin_token');showLogin();throw new Error('auth');}const ct=r.headers.get('content-type')||'';const d=ct.includes('application/json')?await r.json():{error:await r.text()};if(!r.ok){const msg=d.error||'error';const detail=d.detail?` — ${d.detail}`:'';throw new Error(msg+detail);}return d;}
function showApp(){document.querySelector('#login').classList.add('hidden');document.querySelector('#app').classList.remove('hidden');loadAll();loadFlowLogs();}
function showLogin(){document.querySelector('#login').classList.remove('hidden');document.querySelector('#app').classList.add('hidden');}
async function login(){const password=document.querySelector('#password').value;const r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});const d=await r.json();if(!r.ok){document.querySelector('#loginResult').textContent='❌ Credenciales inválidas';return;}token=d.token;localStorage.setItem('synth_admin_token',token);showApp();}
async function logout(){try{await api('/api/admin/logout',{method:'POST'})}catch{}localStorage.removeItem('synth_admin_token');token='';showLogin();}
async function loadAll(){const [plans,tickets,files,parserStatus]=await Promise.all([api('/api/admin/plans'),api('/api/admin/tickets'),api('/api/admin/files'),api('/api/admin/parser-webhook-status')]);document.querySelector('#parserSecretStatus').textContent=parserStatus.configured?'✅ Secreto configurado':'❌ PARSER_WEBHOOK_SECRET falta en Render';
document.querySelector('#ticketCount').textContent=`${tickets.length} tickets`;
document.querySelector('#plans').innerHTML=plans.map(p=>`<article class="plan"><div><span class="file-badge">${p.available_files||0} archivo(s) activos</span><h3>${esc(p.name)}</h3><p>${esc(p.description||'')}</p><p class="plan-meta">Precio actual: <b>${Number(p.price_cup).toFixed(2)} CUP</b></p></div><div class="plan-tools"><input class="name-edit" id="name-${p.id}" value="${esc(p.name)}" maxlength="120"><input id="price-${p.id}" type="number" min="0.01" step="0.01" value="${Number(p.price_cup)}"><button class="tiny" onclick="savePlan('${p.id}')">Guardar oferta</button><label class="upload">+ Añadir archivo<input type="file" onchange="uploadFile('${p.id}',this)"></label></div></article>`).join('');
document.querySelector('#tickets').innerHTML=tickets.length?tickets.map(t=>`<div class="item"><div><b>${esc(t.plans?.name||t.plan_id)}</b><br>${esc(t.transfer_number)} · ${esc(t.telegram_id)} · ${Number(t.amount_cup).toFixed(2)} CUP<br><small>${esc(t.status)} · ${new Date(t.created_at).toLocaleString()}</small></div><div style="display:flex;gap:6px;flex-wrap:wrap"><button class="tiny" onclick="testPayment('${t.id}')">Test pago</button><button class="tiny" style="background:#7b2fbe" onclick="testParser('${t.id}')">Test Parser</button></div></div>`).join(''):'<div class="empty">Sin tickets</div>';
document.querySelector('#files').innerHTML=files.length?files.map(f=>`<div class="item"><div><b>${esc(f.file_name)}</b><br>${esc(f.plans?.name||f.plan_id)} · ${Number(f.plans?.price_cup||0).toFixed(2)} CUP · ${new Date(f.created_at).toLocaleString()}</div><button class="tiny danger" onclick="removeFile('${f.id}')">Eliminar</button></div>`).join(''):'<div class="empty">Sin archivos</div>';
}
async function createOffer(event){event.preventDefault();const form=document.querySelector('#offerForm'),btn=document.querySelector('#offerSubmit'),result=document.querySelector('#offerResult');const file=document.querySelector('#offerFile').files?.[0];if(!file){result.textContent='❌ Selecciona un archivo.';return;}const fd=new FormData();fd.append('name',document.querySelector('#offerName').value.trim());fd.append('price_cup',document.querySelector('#offerPrice').value);fd.append('description',document.querySelector('#offerDescription').value.trim());fd.append('file',file);btn.disabled=true;result.textContent='Subiendo y creando oferta…';try{await api('/api/admin/plans',{method:'POST',body:fd});result.textContent='✅ Oferta creada.';form.reset();await loadAll();}catch(e){result.textContent='❌ '+e.message;}finally{btn.disabled=false;}}
async function savePlan(id){try{await api(`/api/admin/plans/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:document.querySelector(`#name-${id}`).value.trim(),price_cup:document.querySelector(`#price-${id}`).value})});await loadAll();}catch(e){alert(e.message)}}
async function uploadFile(planId,input){const file=input.files?.[0];if(!file)return;const fd=new FormData();fd.append('file',file);try{await api(`/api/admin/plans/${planId}/files`,{method:'POST',body:fd});await loadAll();}catch(e){alert(e.message)}}
async function removeFile(id){if(!confirm('¿Eliminar este archivo del pool?'))return;await api(`/api/admin/files/${id}`,{method:'DELETE'});await loadAll();}
async function testPayment(id){try{const d=await api(`/api/admin/test-payment/${id}`,{method:'POST'});alert(d.ok?'✅ Entrega de prueba realizada.':JSON.stringify(d));await loadAll();}catch(e){alert(e.message)}}
if(token)showApp();else showLogin();

async function loadFlowLogs(){
  const cont=document.querySelector('#flowLogs'); if(!cont)return;
  try{
    const rawLogs=await api('/api/admin/payment-flow-logs?limit=250');
    const logs=Array.isArray(rawLogs)?rawLogs.slice().sort((a,b)=>{const dt=Date.parse(b.created_at||'')-Date.parse(a.created_at||'');if(dt)return dt;return Number(b.id||0)-Number(a.id||0);}):[];
    if(!Array.isArray(logs)||!logs.length){cont.innerHTML='<div class="empty">Sin logs de flujo todavía.</div>';return;}
    cont.innerHTML=logs.map(l=>{
      const level=l.level||'INFO';
      const cls=level==='ERROR'?'flow-error':(level==='WARN'?'flow-warn':'flow-info');
      const detail=esc(JSON.stringify(l.details||{}));
      return '<div class="flow-row '+cls+'"><div><b>'+esc(l.stage||'')+'</b> · '+esc(l.status||'')+' · '+esc(l.event||'')+'</div><div class="flow-meta">'+esc(new Date(l.created_at).toLocaleString())+' · event='+esc(l.event_id||'—')+' · ticket='+esc(l.ticket_id||'—')+' · tg='+esc(l.telegram_id||'—')+'</div><details><summary>Detalles</summary><pre>'+detail+'</pre></details></div>';
    }).join('');
  }catch(e){cont.innerHTML='<div class="empty">Error: '+esc(e.message)+'</div>'; }
}

async function testParser(id){try{const d=await api(`/api/admin/test-parser/${id}`,{method:'POST'});alert(d.ok?'✅ Webhook Parser recibido y procesado.':'❌ '+JSON.stringify(d));await loadAll();await loadFlowLogs();}catch(e){alert(e.message)}}
