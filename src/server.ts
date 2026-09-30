import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { Markup, Telegraf } from 'telegraf';
import type { Request, Response, NextFunction } from 'express';

type AuthedRequest = Request & { adminSession?: string; rawBody?: Buffer };

const required = (key: string) => {
  const v = process.env[key];
  if (!v) throw new Error(`Missing environment variable: ${key}`);
  return v;
};

const PORT = Number(process.env.PORT || 3000);
const BASE = required('PUBLIC_BASE_URL').replace(/\/$/, '');
const ADMIN_TELEGRAM_ID = BigInt(required('ADMIN_TELEGRAM_ID'));
const ADMIN_PASSWORD = required('ADMIN_PANEL_PASSWORD');
const SESSION_SECRET = required('SESSION_SECRET');
const TELEGRAM_BOT_TOKEN = required('TELEGRAM_BOT_TOKEN');
const SUPABASE_URL = required('SUPABASE_URL');
const SUPABASE_SERVICE_ROLE_KEY = required('SUPABASE_SERVICE_ROLE_KEY');
const BUCKET = process.env.SUPABASE_BUCKET || 'telegram-pool';
const PAYMENT_CARD = required('PAYMENT_CARD');
const PAYMENT_CONFIRMATION_NUMBER = required('PAYMENT_CONFIRMATION_NUMBER');
const PAYMENT_BANK_NAME = process.env.PAYMENT_BANK_NAME || 'Transfermóvil';
const WINDOW_MIN = Number(process.env.TRANSFER_MATCH_WINDOW_MINUTES || 30);
const TICKET_TTL_MIN = Number(process.env.TICKET_TTL_MINUTES || WINDOW_MIN);
const WEBHOOK_MAX_SKEW_SEC = Number(process.env.WEBHOOK_MAX_SKEW_SECONDS || 300);
const ALLOW_TEST_TELEGRAM_ID = process.env.ALLOW_UNVERIFIED_TELEGRAM_ID === 'true';
const ALLOW_PAYMENT_EVENT_WITHOUT_RECIPIENT_DATA = process.env.ALLOW_PAYMENT_EVENT_WITHOUT_RECIPIENT_DATA === 'true';
const MAX_FILE_BYTES = 49 * 1024 * 1024; // Telegram Bot API currently documents 50 MB for sendDocument.

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const bot = new Telegraf(TELEGRAM_BOT_TOKEN);
const app = express();
app.set('trust proxy', 1);

const APP_DIR = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(APP_DIR, '..', 'public');

app.use(express.json({ verify: (req, _res, buf) => { (req as AuthedRequest).rawBody = Buffer.from(buf); } }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));
app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
app.get('/admin', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));

const uploadDir = path.join(process.cwd(), '.uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir, limits: { fileSize: MAX_FILE_BYTES } });
const adminSessions = new Map<string, number>();

const normalizeDigits = (s: unknown) => String(s ?? '').replace(/\D/g, '');
const validTransferNumber = (s: unknown) => /^[0-9]{6,15}$/.test(normalizeDigits(s));
const safeEqual = (a: string, b: string) => {
  const aa = Buffer.from(a); const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
const hmac = (secret: string, value: string) => crypto.createHmac('sha256', secret).update(value).digest('hex');
const b64url = (input: string | Buffer) => Buffer.from(input).toString('base64url');
function makeTelegramSession(telegramId: string) {
  const payload = `${telegramId}.${Math.floor(Date.now()/1000)}`;
  return `${b64url(payload)}.${hmac(SESSION_SECRET, payload)}`;
}
function verifyTelegramSession(token: string) {
  const [enc, sig] = token.split('.');
  if (!enc || !sig) return null;
  const payload = Buffer.from(enc, 'base64url').toString('utf8');
  const [telegramId, issued] = payload.split('.');
  if (!/^\d+$/.test(telegramId || '') || !/^\d+$/.test(issued || '')) return null;
  if (Math.abs(Math.floor(Date.now()/1000)-Number(issued)) > 24*60*60) return null;
  return safeEqual(sig, hmac(SESSION_SECRET, payload)) ? telegramId : null;
}

function adminMiddleware(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.header('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const exp = token ? adminSessions.get(token) : undefined;
  if (!exp || exp <= Date.now()) {
    if (token) adminSessions.delete(token);
    return res.status(401).json({ error: 'admin_auth_required' });
  }
  req.adminSession = token;
  next();
}

function paymentWebhookMiddleware(req: AuthedRequest, res: Response, next: NextFunction) {
  const secret = process.env.PAYMENT_WEBHOOK_SECRET || SESSION_SECRET;
  const signature = req.header('x-synthesisone-signature') || '';
  const timestamp = req.header('x-synthesisone-timestamp') || '';
  const unix = Number(timestamp);
  if (!signature || !timestamp || !Number.isFinite(unix)) return res.status(401).json({ error: 'signature_required' });
  if (Math.abs(Math.floor(Date.now() / 1000) - unix) > WEBHOOK_MAX_SKEW_SEC) return res.status(401).json({ error: 'signature_expired' });
  const raw = (req.rawBody || Buffer.from(JSON.stringify(req.body || {}))).toString('utf8');
  const expected = `sha256=${hmac(secret, `${timestamp}.${raw}`)}`;
  if (!safeEqual(signature, expected)) return res.status(401).json({ error: 'invalid_signature' });
  next();
}

function telegramInitDataValid(initData: string) {
  const params = new URLSearchParams(initData);
  const receivedHash = params.get('hash');
  if (!receivedHash) return null;
  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || Math.abs(Math.floor(Date.now() / 1000) - authDate) > 24 * 60 * 60) return null;
  params.delete('hash');
  const dataCheckString = [...params.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('\n');
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(TELEGRAM_BOT_TOKEN).digest();
  const calculated = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  if (!safeEqual(receivedHash, calculated)) return null;
  const userRaw = params.get('user');
  if (!userRaw) return null;
  try { return JSON.parse(userRaw) as { id: number; username?: string; first_name?: string }; } catch { return null; }
}

app.get('/health', (_req, res) => res.json({ ok: true, service: 'synthesisone-telegram-shop' }));

app.post('/api/session/bootstrap', (req, res) => {
  const initData = String(req.body?.init_data || '');
  if (initData) {
    const user = telegramInitDataValid(initData);
    if (!user) return res.status(401).json({ error: 'invalid_telegram_session' });
    return res.json({ ok: true, telegram_id: String(user.id), username: user.username || null, first_name: user.first_name || null, session_token: makeTelegramSession(String(user.id)) });
  }
  if (ALLOW_TEST_TELEGRAM_ID && /^\d+$/.test(String(req.body?.telegram_id || ''))) {
    return res.json({ ok: true, test_mode: true, telegram_id: String(req.body.telegram_id), session_token: makeTelegramSession(String(req.body.telegram_id)) });
  }
  return res.status(401).json({ error: 'telegram_session_required' });
});

app.get('/api/plans', async (_req, res) => {
  const { data, error } = await supabase.from('plans').select('*').eq('active', true).order('price_cup');
  if (error) return res.status(500).json({ error: 'plans_unavailable' });
  const output = [];
  for (const p of data || []) {
    const { count } = await supabase.from('pool_files').select('*', { count: 'exact', head: true }).eq('plan_id', p.id).eq('active', true);
    output.push({ ...p, available_files: count || 0 });
  }
  res.json(output);
});

app.get('/api/payment-data', (_req, res) => res.json({ bank_name: PAYMENT_BANK_NAME, card: PAYMENT_CARD, confirmation_number: PAYMENT_CONFIRMATION_NUMBER }));

app.post('/api/tickets', async (req, res) => {
  const sessionTelegramId = verifyTelegramSession(String(req.body?.session_token || ''));
  const telegramId = sessionTelegramId || (ALLOW_TEST_TELEGRAM_ID ? String(req.body?.telegram_id || '') : '');
  const planId = String(req.body?.plan_id || '');
  const number = normalizeDigits(req.body?.transfer_number);
  const termsRead = req.body?.terms_read === true || req.body?.terms_read === 'true';
  if (!/^\d+$/.test(telegramId) || !planId || !termsRead || !validTransferNumber(number)) return res.status(400).json({ error: 'Datos incompletos o inválidos.' });

  // In normal use the Telegram ID comes from a validated Mini App session.
  // The frontend also sends it, but the server must only trust the validated session.
  const { data: plan } = await supabase.from('plans').select('*').eq('id', planId).eq('active', true).single();
  if (!plan) return res.status(404).json({ error: 'Plan no disponible.' });
  const { count } = await supabase.from('pool_files').select('*', { count: 'exact', head: true }).eq('plan_id', planId).eq('active', true);
  if (!count) return res.status(409).json({ error: 'El plan no tiene archivos disponibles.' });

  const { data: existingCustomer } = await supabase.from('customers').select('telegram_id,transfer_number').eq('transfer_number', number).maybeSingle();
  if (existingCustomer && String(existingCustomer.telegram_id) !== telegramId) {
    return res.status(409).json({ error: 'Ese número de transferencia ya está asociado a otra cuenta de Telegram.' });
  }

  const { data: pending } = await supabase.from('payment_tickets').select('id').eq('telegram_id', telegramId).eq('status', 'pending').gt('expires_at', new Date().toISOString()).limit(1);
  if (pending?.length) return res.status(409).json({ error: 'Ya tienes un ticket pendiente.' });

  const now = new Date();
  const expires = new Date(now.getTime() + TICKET_TTL_MIN * 60_000).toISOString();
  const { data: ticket, error } = await supabase.from('payment_tickets').insert({
    plan_id: planId,
    telegram_id: telegramId,
    transfer_number: number,
    amount_cup: Number(plan.price_cup),
    status: 'pending',
    expires_at: expires
  }).select('*').single();
  if (error) return res.status(500).json({ error: 'ticket_create_failed' });

  const { error: customerError } = await supabase.from('customers').upsert({ telegram_id: telegramId, transfer_number: number, updated_at: now.toISOString() }, { onConflict: 'telegram_id' });
  if (customerError) return res.status(500).json({ error: 'customer_save_failed' });

  res.json({ ok: true, ticket_id: ticket.id, expires_at: expires, amount_cup: Number(plan.price_cup), bank_name: PAYMENT_BANK_NAME, card: PAYMENT_CARD, confirmation_number: PAYMENT_CONFIRMATION_NUMBER });
});

app.post('/api/payments/incoming', paymentWebhookMiddleware, async (req, res) => {
  const transferNumber = normalizeDigits(req.body?.transfer_number);
  const amount = Number(req.body?.amount_cup);
  const providerReference = String(req.body?.provider_reference || '').trim();
  const recipientCard = normalizeDigits(req.body?.recipient_card || '');
  const confirmationPhone = normalizeDigits(req.body?.confirmation_phone || '');

  if (!validTransferNumber(transferNumber) || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'invalid_payment_event' });
  if (!ALLOW_PAYMENT_EVENT_WITHOUT_RECIPIENT_DATA) {
    if (!recipientCard || !confirmationPhone) return res.status(400).json({ error: 'recipient_data_required' });
    if (recipientCard !== normalizeDigits(PAYMENT_CARD) || confirmationPhone !== normalizeDigits(PAYMENT_CONFIRMATION_NUMBER)) return res.status(400).json({ error: 'recipient_mismatch' });
  }

  if (providerReference) {
    const { data: already } = await supabase.from('payment_tickets').select('id,status').eq('provider_reference', providerReference).maybeSingle();
    if (already) return res.json({ ok: true, duplicate: true, ticket_id: already.id, status: already.status });
  }

  const customer = (await supabase.from('customers').select('telegram_id,transfer_number').eq('transfer_number', transferNumber).maybeSingle()).data;
  if (!customer) return res.status(404).json({ error: 'transfer_number_unknown' });

  const now = new Date();
  const minDate = new Date(now.getTime() - WINDOW_MIN * 60_000).toISOString();
  const { data: tickets, error: ticketFindError } = await supabase.from('payment_tickets').select('*')
    .eq('status', 'pending').eq('telegram_id', String(customer.telegram_id)).eq('transfer_number', transferNumber).eq('amount_cup', amount)
    .gte('created_at', minDate).gt('expires_at', now.toISOString()).order('created_at', { ascending: true }).limit(1);
  if (ticketFindError) return res.status(500).json({ error: 'ticket_lookup_failed' });
  const ticket = tickets?.[0];
  if (!ticket) return res.status(404).json({ error: 'no_matching_pending_ticket' });

  // Atomic claim. Only one webhook request can move this ticket from pending -> processing.
  const { data: claimed, error: claimError } = await supabase.from('payment_tickets').update({ status: 'processing', provider_reference: providerReference || null, delivery_attempts: (ticket.delivery_attempts || 0) + 1 }).eq('id', ticket.id).eq('status', 'pending').select('*').single();
  if (claimError || !claimed) return res.status(409).json({ error: 'ticket_already_claimed' });

  try {
    const { data: files } = await supabase.from('pool_files').select('*').eq('plan_id', ticket.plan_id).eq('active', true).order('created_at');
    const available = files || [];
    if (!available.length) throw new Error('No file available for this plan');
    const file = available[Math.floor(Math.random() * available.length)];
    const { data: blob, error: storageError } = await supabase.storage.from(BUCKET).download(file.storage_path);
    if (storageError || !blob) throw new Error(storageError?.message || 'Pool file unavailable');

    const sent = await bot.telegram.sendDocument(String(ticket.telegram_id), {
      source: Buffer.from(await blob.arrayBuffer()),
      filename: file.file_name
    }, { caption: `✅ Pago confirmado · ${Number(ticket.amount_cup).toFixed(2)} CUP\nPlan: ${ticket.plan_id}` });

    await supabase.from('payment_tickets').update({ status: 'paid', paid_at: now.toISOString(), delivered_file_id: file.id, last_error: null }).eq('id', ticket.id).eq('status', 'processing');
    return res.json({ ok: true, ticket_id: ticket.id, telegram_message_id: sent.message_id, delivered_file_id: file.id });
  } catch (error) {
    await supabase.from('payment_tickets').update({ status: 'pending', last_error: String(error instanceof Error ? error.message : error) }).eq('id', ticket.id).eq('status', 'processing');
    return res.status(502).json({ error: 'delivery_failed_retryable' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const password = String(req.body?.password || '');
  if (!safeEqual(password, ADMIN_PASSWORD)) return res.status(401).json({ error: 'invalid_credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, Date.now() + 12 * 60 * 60 * 1000);
  res.json({ ok: true, token });
});
app.post('/api/admin/logout', adminMiddleware, (req: AuthedRequest, res) => { if (req.adminSession) adminSessions.delete(req.adminSession); res.json({ ok: true }); });
app.get('/api/admin/tickets', adminMiddleware, async (_req, res) => {
  const { data, error } = await supabase.from('payment_tickets').select('*,plans(name,price_cup)').order('created_at', { ascending: false }).limit(300);
  if (error) return res.status(500).json({ error: 'tickets_unavailable' }); res.json(data || []);
});
app.get('/api/admin/files', adminMiddleware, async (_req, res) => {
  const { data, error } = await supabase.from('pool_files').select('*,plans(name,price_cup)').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: 'files_unavailable' }); res.json(data || []);
});
app.get('/api/admin/plans', adminMiddleware, async (_req, res) => {
  const { data, error } = await supabase.from('plans').select('*').order('price_cup');
  if (error) return res.status(500).json({ error: 'plans_unavailable' }); res.json(data || []);
});
app.post('/api/admin/plans/:id/files', adminMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file_required' });
  const planId = String(req.params.id);
  const { data: plan } = await supabase.from('plans').select('id').eq('id', planId).maybeSingle();
  if (!plan) { fs.rmSync(req.file.path, { force: true }); return res.status(404).json({ error: 'plan_not_found' }); }
  const ext = path.extname(req.file.originalname);
  const storagePath = `${planId}/${crypto.randomUUID()}${ext}`;
  try {
    const buffer = fs.readFileSync(req.file.path);
    const { error: upError } = await supabase.storage.from(BUCKET).upload(storagePath, buffer, { contentType: req.file.mimetype || 'application/octet-stream', upsert: false });
    if (upError) return res.status(500).json({ error: 'storage_upload_failed' });
    const { data, error } = await supabase.from('pool_files').insert({ plan_id: planId, file_name: req.file.originalname, storage_path: storagePath }).select('*').single();
    if (error) { await supabase.storage.from(BUCKET).remove([storagePath]); return res.status(500).json({ error: 'pool_record_failed' }); }
    res.json(data);
  } finally { fs.rmSync(req.file.path, { force: true }); }
});
app.delete('/api/admin/files/:id', adminMiddleware, async (req, res) => {
  const { data: file } = await supabase.from('pool_files').select('*').eq('id', req.params.id).single();
  if (!file) return res.status(404).json({ error: 'not_found' });
  await supabase.storage.from(BUCKET).remove([file.storage_path]);
  await supabase.from('pool_files').delete().eq('id', file.id);
  res.json({ ok: true });
});
app.post('/api/admin/test-payment/:ticketId', adminMiddleware, async (req, res) => {
  const { data: ticket } = await supabase.from('payment_tickets').select('*').eq('id', req.params.ticketId).single();
  if (!ticket) return res.status(404).json({ error: 'ticket_not_found' });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const body = JSON.stringify({ transfer_number: ticket.transfer_number, amount_cup: Number(ticket.amount_cup), provider_reference: `TEST-${ticket.id}`, recipient_card: PAYMENT_CARD, confirmation_phone: PAYMENT_CONFIRMATION_NUMBER });
  const secret = process.env.PAYMENT_WEBHOOK_SECRET || SESSION_SECRET;
  const signature = `sha256=${hmac(secret, `${timestamp}.${body}`)}`;
  const target = `${BASE}/api/payments/incoming`;
  try {
    const response = await fetch(target, { method: 'POST', headers: { 'content-type': 'application/json', 'x-synthesisone-timestamp': timestamp, 'x-synthesisone-signature': signature }, body });
    const json = await response.json();
    res.status(response.status).json(json);
  } catch (error) { res.status(502).json({ error: String(error) }); }
});

bot.start(async ctx => {
  const url = `${BASE}/`;
  await ctx.reply('🛍️ *SynthesisOne*\n\nElige tu plan y completa el pago desde la tienda.', { parse_mode: 'Markdown', ...Markup.inlineKeyboard([[Markup.button.webApp('🛒 Abrir tienda', url)]]) });
});
bot.command('id', ctx => ctx.reply(`Tu ID de Telegram es: ${ctx.from.id}`));
bot.command('admin', async ctx => {
  if (BigInt(ctx.from.id) !== ADMIN_TELEGRAM_ID) return ctx.reply('⛔ No autorizado.');
  await ctx.reply(`🛠️ Panel de administración\n${BASE}/admin`);
});
bot.catch(err => console.error('[telegram]', err));

setInterval(async () => {
  const now = new Date().toISOString();
  await supabase.from('payment_tickets').update({ status: 'expired' }).eq('status', 'pending').lte('expires_at', now);
  for (const [token, exp] of adminSessions) if (exp <= Date.now()) adminSessions.delete(token);
}, 60_000).unref();

app.listen(PORT, () => {
  console.log(`SynthesisOne Telegram shop listening on ${PORT}`);
  console.log(`Public directory: ${PUBLIC_DIR}`);
  console.log(`Webapp: ${BASE}/`);
  console.log(`Admin: ${BASE}/admin`);
});
bot.launch().catch(console.error);
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
