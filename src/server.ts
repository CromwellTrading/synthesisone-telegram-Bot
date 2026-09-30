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
const configuredBase = process.env.PUBLIC_BASE_URL?.trim().replace(/\/$/, '');
const renderBase = process.env.RENDER_EXTERNAL_URL?.trim().replace(/\/$/, '');
const BASE = renderBase || required('PUBLIC_BASE_URL').replace(/\/$/, '');
if (configuredBase && renderBase && configuredBase !== renderBase) {
  console.warn(`[webapp] PUBLIC_BASE_URL (${configuredBase}) no coincide con RENDER_EXTERNAL_URL (${renderBase}); se usará RENDER_EXTERNAL_URL.`);
}
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
const PARSER_WEBHOOK_SECRET = (process.env.PARSER_WEBHOOK_SECRET || '').trim();
const MAX_FILE_BYTES = 49 * 1024 * 1024; // Telegram Bot API currently documents 50 MB for sendDocument.
const BUILD_VERSION = '1.2.0';

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
const normalizeCubaPhone = (s: unknown) => {
  const digits = normalizeDigits(s);
  return digits.length === 10 && digits.startsWith('53') ? digits.slice(2) : digits;
};
const transferNumberCandidates = (s: unknown) => {
  const raw = normalizeDigits(s);
  const normalized = normalizeCubaPhone(raw);
  return [...new Set([normalized, raw].filter(Boolean))];
};
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

function isParserWebhookRequest(req: Request) {
  return Boolean(
    req.header('x-webhook-event-id') ||
    req.header('x-webhook-signature-v2') ||
    req.header('x-webhook-signature')
  );
}

function verifyParserWebhook(req: AuthedRequest, res: Response) {
  if (!PARSER_WEBHOOK_SECRET) {
    res.status(500).json({ error: 'parser_webhook_secret_not_configured' });
    return false;
  }

  const signatureV2 = req.header('x-webhook-signature-v2') || '';
  const signatureV1 = req.header('x-webhook-signature') || '';
  const timestamp = req.header('x-webhook-timestamp') || '';
  const eventId = req.header('x-webhook-event-id') || '';
  const unix = Number(timestamp);

  if (!timestamp || !Number.isFinite(unix) || !eventId || (!signatureV2 && !signatureV1)) {
    res.status(401).json({ error: 'parser_webhook_signature_required' });
    return false;
  }
  if (Math.abs(Math.floor(Date.now() / 1000) - unix) > WEBHOOK_MAX_SKEW_SEC) {
    res.status(401).json({ error: 'parser_webhook_signature_expired' });
    return false;
  }

  const raw = (req.rawBody || Buffer.from(JSON.stringify(req.body || {}))).toString('utf8');
  const expectedV2 = hmac(PARSER_WEBHOOK_SECRET, `${timestamp}.${raw}`);
  const expectedV1 = hmac(PARSER_WEBHOOK_SECRET, raw);
  if (!safeEqual(signatureV2 || signatureV1, signatureV2 ? expectedV2 : expectedV1)) {
    res.status(401).json({ error: 'invalid_parser_webhook_signature' });
    return false;
  }
  return true;
}

function parserEventParts(req: AuthedRequest) {
  const payload = req.body || {};
  const transaction = payload.transaction || {};
  const rawTransferNumber = normalizeDigits(transaction.sender_phone);
  return {
    payload,
    eventId: String(req.header('x-webhook-event-id') || payload.event_id || '').trim(),
    transferNumber: normalizeCubaPhone(rawTransferNumber),
    transferNumberCandidates: transferNumberCandidates(rawTransferNumber),
    amount: Number(transaction.amount),
    currency: String(transaction.currency || '').toUpperCase(),
    transactionId: String(transaction.transaction_id || '').trim(),
  };
}

async function deliverTicket(ticket: any, providerReference: string, res: Response) {
  const { data: claimed, error: claimError } = await supabase.from('payment_tickets').update({
    status: 'processing',
    provider_reference: providerReference || null,
    delivery_attempts: (ticket.delivery_attempts || 0) + 1,
    last_error: null,
  }).eq('id', ticket.id).eq('status', 'pending').select('*').single();

  if (claimError || !claimed) return res.status(409).json({ error: 'ticket_already_claimed' });

  try {
    const { data: files, error: fileQueryError } = await supabase.from('pool_files').select('*')
      .eq('plan_id', ticket.plan_id).eq('active', true).order('created_at');
    if (fileQueryError) throw fileQueryError;
    const available = files || [];
    if (!available.length) throw new Error('No file available for this plan');
    const file = available[Math.floor(Math.random() * available.length)];
    const { data: blob, error: storageError } = await supabase.storage.from(BUCKET).download(file.storage_path);
    if (storageError || !blob) throw new Error(storageError?.message || 'Pool file unavailable');

    const sent = await bot.telegram.sendDocument(String(ticket.telegram_id), {
      source: Buffer.from(await blob.arrayBuffer()),
      filename: file.file_name
    }, { caption: `✅ Pago confirmado · ${Number(ticket.amount_cup).toFixed(2)} CUP\nPlan: ${ticket.plan_id}` });

    const { error: paidError } = await supabase.from('payment_tickets').update({
      status: 'paid',
      paid_at: new Date().toISOString(),
      delivered_file_id: file.id,
      last_error: null,
    }).eq('id', ticket.id).eq('status', 'processing');
    if (paidError) throw paidError;

    return res.json({
      ok: true,
      ticket_id: ticket.id,
      telegram_message_id: sent.message_id,
      delivered_file_id: file.id,
      provider_reference: providerReference || null,
    });
  } catch (error) {
    await supabase.from('payment_tickets').update({
      status: 'pending',
      provider_reference: null,
      last_error: String(error instanceof Error ? error.message : error),
    }).eq('id', ticket.id).eq('status', 'processing');
    console.error(`[payment] delivery failed ticket=${ticket.id}:`, error);
    return res.status(502).json({ error: 'delivery_failed_retryable' });
  }
}

async function handleParserPaymentWebhook(req: AuthedRequest, res: Response) {
  if (!verifyParserWebhook(req, res)) return;

  const { payload, eventId, transferNumber, transferNumberCandidates: candidates, amount, currency, transactionId } = parserEventParts(req);
  if (payload.event !== 'TRANSFER_DETECTED') return res.status(400).json({ error: 'unsupported_parser_event' });
  if (!eventId) return res.status(400).json({ error: 'parser_event_id_required' });
  if (!validTransferNumber(transferNumber) || !Number.isFinite(amount) || amount <= 0) {
    return res.status(422).json({ error: 'parser_payment_data_incomplete' });
  }
  if (currency && currency !== 'CUP') return res.status(422).json({ error: 'unsupported_currency' });

  const providerReference = `PARSER:${eventId}`;
  const { data: already, error: duplicateError } = await supabase.from('payment_tickets')
    .select('id,status,telegram_id,delivered_file_id').eq('provider_reference', providerReference).maybeSingle();
  if (duplicateError) return res.status(500).json({ error: 'duplicate_check_failed' });
  if (already) {
    if (already.status === 'pending') {
      // A previous attempt may have failed after claiming the ticket. The
      // failed-delivery path clears provider_reference, but pending tickets
      // from older builds may still carry it; let the event be retried.
    } else if (already.status === 'processing') {
      return res.status(503).json({ error: 'ticket_delivery_in_progress' });
    } else {
      return res.json({
        ok: true,
        duplicate: true,
        ticket_id: already.id,
        status: already.status,
        telegram_id: String(already.telegram_id),
        delivered_file_id: already.delivered_file_id || null,
      });
    }
  }

  const now = new Date();
  const minDate = new Date(now.getTime() - WINDOW_MIN * 60_000).toISOString();
  const { data: tickets, error: ticketFindError } = await supabase.from('payment_tickets').select('*')
    .eq('status', 'pending')
    .in('transfer_number', candidates)
    .eq('amount_cup', amount)
    .gte('created_at', minDate)
    .gt('expires_at', now.toISOString())
    .order('created_at', { ascending: true })
    .limit(1);
  if (ticketFindError) return res.status(500).json({ error: 'ticket_lookup_failed' });
  const ticket = tickets?.[0];
  if (!ticket) {
    console.warn(`[parser-webhook] no pending ticket | transfer=${transferNumber} | amount=${amount} | tx=${transactionId || '—'} | event=${eventId}`);
    return res.status(503).json({ error: 'no_matching_pending_ticket' });
  }

  console.log(`[parser-webhook] payment matched | ticket=${ticket.id} | telegram=${ticket.telegram_id} | transfer=${transferNumber} | amount=${amount} | tx=${transactionId || '—'} | event=${eventId}`);
  return deliverTicket(ticket, providerReference, res);
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

app.get('/health', (_req, res) => res.json({ ok: true, service: 'synthesisone-telegram-shop', version: BUILD_VERSION }));
app.get('/api/version', (_req, res) => res.json({ ok: true, version: BUILD_VERSION }));
app.get('/api/admin/diagnostics', adminMiddleware, async (_req, res) => {
  const result: any = { ok: true, version: BUILD_VERSION, bucket: BUCKET };
  const { error: plansError } = await supabase.from('plans').select('id').limit(1);
  const { error: filesError } = await supabase.from('pool_files').select('id').limit(1);
  result.plans = plansError ? { ok: false, code: plansError.code, message: plansError.message } : { ok: true };
  result.parser_webhook = { configured: Boolean(PARSER_WEBHOOK_SECRET), endpoint: `${BASE}/api/payments/incoming` };
  result.pool_files = filesError ? { ok: false, code: filesError.code, message: filesError.message } : { ok: true };
  try {
    const { data, error } = await supabase.storage.getBucket(BUCKET);
    result.storage = error ? { ok: false, message: error.message } : { ok: true, id: data?.id || BUCKET, name: data?.name || BUCKET, public: !!data?.public };
  } catch (e) {
    result.storage = { ok: false, message: String(e instanceof Error ? e.message : e) };
  }
  res.json(result);
});

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
  const rawNumber = normalizeDigits(req.body?.transfer_number);
  const number = normalizeCubaPhone(rawNumber);
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

app.post('/api/payments/incoming', async (req: AuthedRequest, res: Response, next: NextFunction) => {
  if (isParserWebhookRequest(req)) return handleParserPaymentWebhook(req, res);
  return paymentWebhookMiddleware(req, res, async () => {
    const transferNumber = normalizeCubaPhone(req.body?.transfer_number);
    const candidates = transferNumberCandidates(req.body?.transfer_number);
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
      if (already?.status === 'processing') return res.status(503).json({ error: 'ticket_delivery_in_progress' });
      if (already && already.status !== 'pending') return res.json({ ok: true, duplicate: true, ticket_id: already.id, status: already.status });
    }

    const customer = (await supabase.from('customers').select('telegram_id,transfer_number').in('transfer_number', candidates).maybeSingle()).data;
    if (!customer) return res.status(404).json({ error: 'transfer_number_unknown' });

    const now = new Date();
    const minDate = new Date(now.getTime() - WINDOW_MIN * 60_000).toISOString();
    const { data: tickets, error: ticketFindError } = await supabase.from('payment_tickets').select('*')
      .eq('status', 'pending').eq('telegram_id', String(customer.telegram_id)).in('transfer_number', candidates).eq('amount_cup', amount)
      .gte('created_at', minDate).gt('expires_at', now.toISOString()).order('created_at', { ascending: true }).limit(1);
    if (ticketFindError) return res.status(500).json({ error: 'ticket_lookup_failed' });
    const ticket = tickets?.[0];
    if (!ticket) return res.status(404).json({ error: 'no_matching_pending_ticket' });

    return deliverTicket(ticket, providerReference || `PAYMENT:${crypto.randomUUID()}`, res);
  });
});

// Alias explicitly named for the standard parser-to-client webhook contract.
// The existing /api/payments/incoming route also accepts this contract so an
// already-registered parser webhook URL does not have to be changed.
app.post('/api/payments/parser-webhook', handleParserPaymentWebhook);

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
  if (error) return res.status(500).json({ error: 'plans_unavailable' });
  const output = [];
  for (const plan of data || []) {
    const { count } = await supabase.from('pool_files').select('*', { count: 'exact', head: true }).eq('plan_id', plan.id).eq('active', true);
    output.push({ ...plan, available_files: count || 0 });
  }
  res.json(output);
});

// Crea una oferta completa desde el panel: nombre + precio + descripción + primer archivo.
// ADMIN CREATE-OFFER ENDPOINT v1.1.4: multipart/form-data name, price_cup, description, file
app.post('/api/admin/plans', adminMiddleware, upload.single('file'), async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const description = String(req.body?.description || '').trim();
  const price = Number(req.body?.price_cup);

  if (!name || !Number.isFinite(price) || price <= 0) {
    if (req.file?.path) fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: 'name_and_valid_price_required' });
  }
  if (!req.file) return res.status(400).json({ error: 'file_required' });

  console.log(`[admin:create-plan] name=${JSON.stringify(name)} price=${price} file=${JSON.stringify(req.file.originalname)}`);

  // El insert se hace primero en una forma compatible con esquemas antiguos.
  // Algunas instalaciones ya existentes pueden no tener `description`; en ese caso
  // reintentamos sin esa columna y mostramos una advertencia en la respuesta.
  let plan: any = null;
  let planError: any = null;
  let descriptionSkipped = false;

  const firstInsert = await supabase.from('plans').insert({
    name, price_cup: price, description, active: true
  }).select('*').single();
  plan = firstInsert.data;
  planError = firstInsert.error;

  if (planError) {
    console.error('[admin:create-plan] plans INSERT failed', {
      code: planError.code,
      message: planError.message,
      details: planError.details,
      hint: planError.hint
    });

    // Compatibilidad con una tabla `plans` anterior que no tenga `description`.
    const looksLikeMissingDescription = planError.code === '42703' || /description/i.test(String(planError.message || ''));
    if (looksLikeMissingDescription) {
      const retry = await supabase.from('plans').insert({
        name, price_cup: price, active: true
      }).select('*').single();
      plan = retry.data;
      planError = retry.error;
      descriptionSkipped = !planError && !!plan;
      if (planError) {
        console.error('[admin:create-plan] compatibility INSERT failed', {
          code: planError.code,
          message: planError.message,
          details: planError.details,
          hint: planError.hint
        });
      }
    }
  }

  if (planError || !plan) {
    if (req.file?.path) fs.rmSync(req.file.path, { force: true });
    const code = planError?.code ? String(planError.code) : '';
    const message = planError?.message ? String(planError.message) : '';
    const details = planError?.details ? String(planError.details) : '';
    let error = 'plan_create_failed';
    if (code === '42501') error = 'supabase_permission_denied';
    else if (code === '42P01' || /relation .*plans.* does not exist/i.test(message)) error = 'plans_table_missing';
    else if (code === '42703' || /column .* does not exist/i.test(message)) error = 'plans_schema_mismatch';
    return res.status(500).json({ error, detail: message || details || 'Supabase rechazó la creación de la oferta.' });
  }

  const ext = path.extname(req.file.originalname);
  const storagePath = `${plan.id}/${crypto.randomUUID()}${ext}`;
  try {
    const buffer = fs.readFileSync(req.file.path);
    const { error: upError } = await supabase.storage.from(BUCKET).upload(storagePath, buffer, {
      contentType: req.file.mimetype || 'application/octet-stream', upsert: false
    });
    if (upError) {
      console.error('[admin:create-plan] storage upload failed', {
        message: upError.message,
        details: upError.details,
        hint: upError.hint
      });
      await supabase.from('plans').delete().eq('id', plan.id);
      return res.status(500).json({ error: 'storage_upload_failed', detail: String(upError.message || 'No se pudo subir al Storage.') });
    }

    const { data: file, error: fileError } = await supabase.from('pool_files').insert({
      plan_id: plan.id, file_name: req.file.originalname, storage_path: storagePath
    }).select('*').single();
    if (fileError || !file) {
      console.error('[admin:create-plan] pool_files INSERT failed', {
        code: fileError?.code,
        message: fileError?.message,
        details: fileError?.details,
        hint: fileError?.hint
      });
      await supabase.storage.from(BUCKET).remove([storagePath]);
      await supabase.from('plans').delete().eq('id', plan.id);
      return res.status(500).json({ error: 'pool_record_failed', detail: String(fileError?.message || 'No se pudo registrar el archivo.') });
    }
    console.log(`[admin:create-plan] success plan=${plan.id} file=${file.id}${descriptionSkipped ? ' description_column_missing' : ''}`);
    return res.json({ ok: true, plan, file, description_skipped: descriptionSkipped });
  } finally {
    if (req.file?.path) fs.rmSync(req.file.path, { force: true });
  }
});

app.patch('/api/admin/plans/:id', adminMiddleware, async (req, res) => {
  const id = String(req.params.id);
  const updates: Record<string, string | number> = {};
  if (req.body?.name !== undefined) {
    const name = String(req.body.name).trim();
    if (!name) return res.status(400).json({ error: 'invalid_plan_name' });
    updates.name = name;
  }
  if (req.body?.price_cup !== undefined) {
    const price = Number(req.body.price_cup);
    if (!Number.isFinite(price) || price <= 0) return res.status(400).json({ error: 'invalid_plan_price' });
    updates.price_cup = price;
  }
  if (req.body?.description !== undefined) updates.description = String(req.body.description).trim();
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'no_changes' });
  const { data, error } = await supabase.from('plans').update(updates).eq('id', id).select('*').single();
  if (error || !data) return res.status(404).json({ error: 'plan_update_failed' });
  res.json(data);
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

app.post('/api/admin/test-parser-payment/:ticketId', adminMiddleware, async (req, res) => {
  if (!PARSER_WEBHOOK_SECRET) return res.status(500).json({ error: 'parser_webhook_secret_not_configured' });
  const { data: ticket } = await supabase.from('payment_tickets').select('*').eq('id', req.params.ticketId).single();
  if (!ticket) return res.status(404).json({ error: 'ticket_not_found' });
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const eventId = `TEST-PARSER-${ticket.id}`;
  const body = JSON.stringify({
    schema_version: '1.0',
    event: 'TRANSFER_DETECTED',
    event_id: eventId,
    occurred_at: new Date().toISOString(),
    client: { id: 'TEST', name: 'SynthesisOne Telegram Shop Test' },
    sms: { sender: 'TEST', body: `TEST payment ${ticket.amount_cup} CUP from ${ticket.transfer_number}`, received_at: new Date().toISOString() },
    verification: { is_financial_transfer: true, has_amount: true, has_currency: true, has_counterparty_phone: true },
    transaction: {
      direction: 'RECIBIDO',
      type: 'MONEDERO_MONEDERO',
      network: 'PAGOMOVIL',
      amount: Number(ticket.amount_cup),
      currency: 'CUP',
      sender_phone: ticket.transfer_number,
      receiver_phone: null,
      receiver_account: null,
      transaction_id: `TEST-TX-${ticket.id}`
    }
  });
  const signatureV1 = hmac(PARSER_WEBHOOK_SECRET, body);
  const signatureV2 = hmac(PARSER_WEBHOOK_SECRET, `${timestamp}.${body}`);
  const target = `${BASE}/api/payments/incoming`;
  try {
    const response = await fetch(target, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-webhook-event-id': eventId,
        'x-webhook-timestamp': timestamp,
        'x-webhook-signature': signatureV1,
        'x-webhook-signature-v2': signatureV2
      },
      body
    });
    const json = await response.json();
    res.status(response.status).json(json);
  } catch (error) { res.status(502).json({ error: String(error) }); }
});

app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'file_too_large_max_49mb' : `upload_${err.code}` });
  if (err) return res.status(500).json({ error: 'internal_server_error' });
  next(err);
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
  console.log(`SynthesisOne Telegram shop v${BUILD_VERSION} listening on ${PORT}`);
  console.log(`Public directory: ${PUBLIC_DIR}`);
  console.log(`Webapp: ${BASE}/`);
  console.log(`Admin: ${BASE}/admin`);
});
bot.launch().catch(console.error);
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
