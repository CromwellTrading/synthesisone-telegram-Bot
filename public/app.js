let session=null, selected=null, sessionToken="";
const tg=window.Telegram?.WebApp;
if(tg){tg.ready();tg.expand();}
const qs=new URLSearchParams(location.search);
async function bootstrap(){
  const initData=tg?.initData||'';
  const body=initData?{init_data:initData}:{telegram_id:qs.get('telegram_id')||''};
  const r=await fetch('/api/session/bootstrap',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok){document.querySelector('#who').textContent='Abre esta tienda desde el bot de Telegram.';return false;}
  session=await r.json(); sessionToken=session.session_token||"";
  document.querySelector('#who').textContent=`Cuenta Telegram · ${session.username?`@${session.username}`:`ID ${session.telegram_id}`}`;
  return true;
}
async function load(){
  const ok=await bootstrap();
  if(!ok)return;
  const plans=await fetch('/api/plans').then(r=>r.json());
  document.querySelector('#plans').innerHTML=plans.map(p=>`<article class="card"><span class="tag">${p.available_files} disponibles</span><h2>${esc(p.name)}</h2><div class="price">${Number(p.price_cup).toFixed(0)}<small> CUP</small></div><p>${esc(p.description||'Archivo digital')}</p><button ${p.available_files?'':'disabled'} onclick='openPlan(${JSON.stringify(p)})'>${p.available_files?'Comprar':'Agotado'}</button></article>`).join('');
}
async function openPlan(p){selected=p;document.querySelector('#plans').classList.add('hidden');document.querySelector('#checkout').classList.remove('hidden');document.querySelector('#chosen').innerHTML=`<span class="tag">PLAN SELECCIONADO</span><h2>${esc(p.name)}</h2><div class="price">${Number(p.price_cup).toFixed(0)}<small> CUP</small></div>`;const d=await fetch('/api/payment-data').then(r=>r.json());document.querySelector('#payment').innerHTML=`<b>${esc(d.bank_name)}</b><br>Tarjeta: <strong>${esc(d.card)}</strong><br>Número a confirmar: <strong>${esc(d.confirmation_number)}</strong>`;ready();}
function ready(){document.querySelector('#buy').disabled=!session||!selected||!document.querySelector('#read').checked||!/^[0-9]{6,15}$/.test(document.querySelector('#number').value);}
async function createTicket(){const btn=document.querySelector('#buy'),result=document.querySelector('#result');btn.disabled=true;result.textContent='Creando ticket…';const r=await fetch('/api/tickets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({telegram_id:session.telegram_id,plan_id:selected.id,transfer_number:document.querySelector('#number').value,terms_read:true})});const d=await r.json();if(!r.ok){result.textContent='❌ '+(d.error||'No se pudo crear el ticket.');ready();return;}result.innerHTML=`✅ <b>Ticket pendiente creado</b><br>ID: <code>${esc(d.ticket_id)}</code><br>Importe: <b>${d.amount_cup} CUP</b><br><br>Realiza la transferencia con <b>“Mostrar número al destinatario”</b> activado. Cuando el pago sea confirmado recibirás el archivo aquí automáticamente.`;}
function backToPlans(){document.querySelector('#checkout').classList.add('hidden');document.querySelector('#plans').classList.remove('hidden');}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));}
load();
