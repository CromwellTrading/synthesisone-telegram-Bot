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
  document.querySelector('#plans').innerHTML=plans.map(p=>`<article class="card"><span class="tag">OFERTA · ${p.available_files} disponible(s)</span><h2>${esc(p.name)}</h2><div class="price">${Number(p.price_cup).toFixed(0)}<small> CUP</small></div><p>${esc(p.description||'Archivo digital')}</p><button ${p.available_files?'':'disabled'} onclick='openPlan(${JSON.stringify(p)})'>${p.available_files?'Comprar':'Agotado'}</button></article>`).join('');
}
async function openPlan(p){selected=p;document.querySelector('#plans').classList.add('hidden');document.querySelector('#checkout').classList.remove('hidden');document.querySelector('#chosen').innerHTML=`<span class="tag">PLAN SELECCIONADO</span><h2>${esc(p.name)}</h2><div class="price">${Number(p.price_cup).toFixed(0)}<small> CUP</small></div>`;document.querySelector('#payment').innerHTML='<b>Los datos de pago aparecerán después de crear el ticket.</b>';document.querySelector('#number').value='';document.querySelector('#number').disabled=false;document.querySelector('#read').checked=false;document.querySelector('#buy').textContent='Crear ticket de pago';document.querySelector('#buy').disabled=true;document.querySelector('#result').textContent='';ready();}
function ready(){document.querySelector('#buy').disabled=!sessionToken||!selected||!document.querySelector('#read').checked||!/^[0-9]{6,15}$/.test(document.querySelector('#number').value);}
async function createTicket(){const btn=document.querySelector('#buy'),result=document.querySelector('#result'),transferNumber=document.querySelector('#number').value.trim();if(!sessionToken){result.textContent='❌ Sesión de Telegram no válida. Cierra y vuelve a abrir la tienda desde el bot.';return;}btn.disabled=true;result.textContent='Creando ticket…';const r=await fetch('/api/tickets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_token:sessionToken,plan_id:selected.id,transfer_number:transferNumber,terms_read:true})});const d=await r.json();if(!r.ok){result.textContent='❌ '+(d.error||'No se pudo crear el ticket.');ready();return;}const payment=await fetch('/api/payment-data').then(x=>x.json()).catch(()=>null);if(payment){document.querySelector('#payment').innerHTML=`<b>✅ Ticket creado</b><br><br>${esc(payment.bank_name)}<br>Tarjeta: <strong>${esc(payment.card)}</strong><br>Número a confirmar: <strong>${esc(payment.confirmation_number)}</strong>`;}document.querySelector('#number').disabled=true;btn.disabled=true;btn.textContent='Ticket creado';result.innerHTML=`✅ <b>Ticket pendiente creado</b><br>ID: <code>${esc(d.ticket_id)}</code><br>Importe: <b>${d.amount_cup} CUP</b><br><br><strong>Ahora realiza la transferencia.</strong><br>Debes mantener <b>“Mostrar número al destinatario”</b> activado y enviar el importe exacto. El ticket debe crearse <strong>antes</strong> de realizar la transferencia. Cuando el pago sea confirmado recibirás el archivo aquí automáticamente.`;}
function backToPlans(){document.querySelector('#checkout').classList.add('hidden');document.querySelector('#plans').classList.remove('hidden');}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));}
load();
