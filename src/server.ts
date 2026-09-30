import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import crypto from 'node:crypto';
import https from 'node:https';
import dns from 'node:dns/promises';
import { createClient } from '@supabase/supabase-js';
import { Markup, Telegraf } from 'telegraf';
import type { Request, Response, NextFunction } from 'express';
import { flowLog } from './flowLog.js';

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
const PARSER_WEBHOOK_SECRET = process.env.PARSER_WEBHOOK_SECRET?.trim() || '';
const ALLOW_TEST_TELEGRAM_ID = process.env.ALLOW_UNVERIFIED_TELEGRAM_ID === 'true';
const ALLOW_PAYMENT_EVENT_WITHOUT_RECIPIENT_DATA = process.env.ALLOW_PAYMENT_EVENT_WITHOUT_RECIPIENT_DATA === 'true';
const MAX_FILE_BYTES = 49 * 1024 * 1024; // Telegram Bot API currently documents 50 MB for sendDocument.
const BUILD_VERSION = '1.4.0';
const TELEGRAM_HTTP_TIMEOUT_MS = Number(process.env.TELEGRAM_HTTP_TIMEOUT_MS || 8000);
const TELEGRAM_API_HOST = 'api.telegram.org';

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
// Telegram transport hardening: avoid stale keep-alive sockets and prefer IPv4.
// This only affects outbound Bot API calls; webhook handling remains unchanged.
const telegramAgent = new https.Agent({
  keepAlive: false,
  maxSockets: 20,
  maxFreeSockets: 0,
  timeout: TELEGRAM_HTTP_TIMEOUT_MS,
  family: 4,
  maxCachedSessions: 0,
});
const bot = new Telegraf(TELEGRAM_BOT_TOKEN, { telegram: { agent: telegramAgent } });

type TelegramApiResult<T> = { ok: true; result: T } | { ok: false; description?: string; error_code?: number };

function requestTelegramApi<T>(method: string, body?: Buffer, contentType?: string): Promise<T> {
  return new Promise(async (resolve, reject) => {
    let addresses: Array<{ address: string; family: number }> = [];
    try {
      addresses = await dns.lookup(TELEGRAM_API_HOST, { all: true, family: 4 });
      addresses = addresses.filter((x) => x.family === 4);
    } catch (error) {
      reject(error);
      return;
    }
    if (!addresses.length) {
      reject(Object.assign(new Error('No IPv4 address resolved for api.telegram.org'), { code: 'ENOTFOUND', syscall: 'dns' }));
      return;
    }

    let lastError: unknown = null;
    for (const target of addresses) {
      try {
        const result = await new Promise<T>((resolveRequest, rejectRequest) => {
          const req = https.request({
            protocol: 'https:',
            hostname: target.address,
            port: 443,
            method: body ? 'POST' : 'GET',
            path: `/bot${TELEGRAM_BOT_TOKEN}/${method}`,
            servername: TELEGRAM_API_HOST,
            family: 4,
            agent: telegramAgent,
            headers: {
              Host: TELEGRAM_API_HOST,
              Accept: 'application/json',
              Connection: 'close',
              ...(contentType ? { 'Content-Type': contentType } : {}),
              ...(body ? { 'Content-Length': String(body.length) } : {}),
            },
          }, response => {
            const chunks: Buffer[] = [];
            response.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
            response.on('end', () => {
              const raw = Buffer.concat(chunks).toString('utf8');
              let parsed: TelegramApiResult<T> | null = null;
              try { parsed = JSON.parse(raw) as TelegramApiResult<T>; } catch {
                parsed = null;
              }
              if (!parsed || parsed.ok !== true) {
                const err = Object.assign(new Error(parsed && 'description' in parsed ? String(parsed.description || `Telegram HTTP ${response.statusCode || 0}`) : `Telegram returned invalid JSON (HTTP ${response.statusCode || 0})`), {
                  code: `TELEGRAM_HTTP_${response.statusCode || 0}`,
                  telegram_error_code: parsed && 'error_code' in parsed ? parsed.error_code : null,
                  telegram_description: parsed && 'description' in parsed ? parsed.description : null,
                  http_status: response.statusCode || 0,
                  response_body: raw.slice(0, 2000),
                  telegram_ip: target.address,
                });
                rejectRequest(err);
                return;
              }
              resolveRequest(parsed.result);
            });
          });

          req.setTimeout(TELEGRAM_HTTP_TIMEOUT_MS, () => {
            req.destroy(Object.assign(new Error(`Telegram API timeout after ${TELEGRAM_HTTP_TIMEOUT_MS}ms`), { code: 'ETIMEDOUT', telegram_ip: target.address }));
          });
          req.on('error', error => {
            const e = error as any;
            if (e && !e.telegram_ip) e.telegram_ip = target.address;
            rejectRequest(error);
          });
          if (body) req.write(body);
          req.end();
        });
        return resolve(result);
      } catch (error) {
        lastError = error;
        const code = String((error as any)?.code || '');
        if (!['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'ENETUNREACH', 'EHOSTUNREACH'].includes(code)) break;
      }
    }
    reject(lastError || new Error('Telegram API request failed'));
  });
}

function makeMultipartDocument(chatId: string, caption: string, filename: string, bytes: Buffer) {
  const boundary = `----SynthesisOne${crypto.randomBytes(12).toString('hex')}`;
  const part = (name: string, value: string) => Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`, 'utf8');
  const fileHeader = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="${filename.replace(/[\r\n\"]/g, '_')}"\r\nContent-Type: application/octet-stream\r\n\r\n`, 'utf8');
  const end = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  const body = Buffer.concat([part('chat_id', chatId), part('caption', caption), fileHeader, bytes, end]);
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}

async function sendTelegramDocument(chatId: string, filename: string, bytes: Buffer, caption: string) {
  const { body, contentType } = makeMultipartDocument(chatId, caption, filename, bytes);
  return requestTelegramApi<any>('sendDocument', body, contentType);
}
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
function normalizeTransferNumber(s: unknown) {
  let value = normalizeDigits(s);
  // Parser-bot may report Cuban mobile numbers as +53XXXXXXXX or 53XXXXXXXX.
  if (value.startsWith('535') && value.length === 11) value = value.slice(3);
  else if (value.startsWith('53') && value.length === 10) value = value.slice(2);
  return value;
}
const validTransferNumber = (s: unknown) => /^[0-9]{6,15}$/.test(normalizeTransferNumber(s));
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
  const raw = (req.rawBody || Buffer.from(JSON.stringify(req.body || {}))).toString('utf8');
  const parserSignature = req.header('x-webhook-signature-v2') || '';
  const parserTimestamp = req.header('x-webhook-timestamp') || '';
  const parserEventId = req.header('x-webhook-event-id') || '';

  if (parserSignature || parserTimestamp || parserEventId) {
    const timestamp = Number(parserTimestamp);
    const eventId = parserEventId || null;
    const signature = parserSignature.replace(/^sha256=/i, '');
    void flowLog({ stage: 'WEBHOOK_RECEIVED', status: 'PARSER_HEADERS', eventId, details: {
      path: req.path, has_signature: Boolean(parserSignature), has_timestamp: Boolean(parserTimestamp), has_event_id: Boolean(parserEventId),
      timestamp, body_bytes: Buffer.byteLength(raw, 'utf8')
    }});

    if (!PARSER_WEBHOOK_SECRET) {
      void flowLog({ level:'ERROR', stage:'WEBHOOK_AUTH', status:'REJECTED_NO_SECRET', eventId, details:{ reason:'PARSER_WEBHOOK_SECRET missing' }});
      return res.status(500).json({ error: 'parser_webhook_secret_missing' });
    }
    if (!parserSignature || !parserTimestamp || !Number.isFinite(timestamp)) {
      void flowLog({ level:'WARN', stage:'WEBHOOK_AUTH', status:'REJECTED_MISSING_HEADERS', eventId, details:{ has_signature:Boolean(parserSignature), has_timestamp:Boolean(parserTimestamp), has_event_id:Boolean(parserEventId) }});
      return res.status(401).json({ error: 'signature_required' });
    }
    if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > WEBHOOK_MAX_SKEW_SEC) {
      void flowLog({ level:'WARN', stage:'WEBHOOK_AUTH', status:'REJECTED_EXPIRED', eventId, details:{ timestamp, skew_seconds:Math.abs(Math.floor(Date.now()/1000)-timestamp), max_skew:WEBHOOK_MAX_SKEW_SEC }});
      return res.status(401).json({ error: 'signature_expired' });
    }
    const expected = hmac(PARSER_WEBHOOK_SECRET, `${parserTimestamp}.${raw}`);
    if (!safeEqual(signature, expected)) {
      void flowLog({ level:'ERROR', stage:'WEBHOOK_AUTH', status:'REJECTED_BAD_SIGNATURE', eventId, details:{ signature_format: parserSignature.startsWith('sha256=') ? 'sha256-prefixed' : 'hex', body_bytes:Buffer.byteLength(raw,'utf8') }});
      return res.status(401).json({ error: 'invalid_signature' });
    }
    (req as any).paymentWebhookProvider = 'parser';
    (req as any).paymentWebhookEventId = eventId;
    void flowLog({ stage:'WEBHOOK_AUTH', status:'ACCEPTED', eventId, details:{ provider:'parser', event:req.body?.event || null }});
    return next();
  }

  // Backward-compatible direct payment webhook used by local/admin tests.
  const secret = process.env.PAYMENT_WEBHOOK_SECRET || SESSION_SECRET;
  const signature = req.header('x-synthesisone-signature') || '';
  const timestamp = req.header('x-synthesisone-timestamp') || '';
  const unix = Number(timestamp);
  if (!signature || !timestamp || !Number.isFinite(unix)) {
    void flowLog({ level:'WARN', stage:'WEBHOOK_AUTH', status:'REJECTED_MISSING_HEADERS', details:{ provider:'legacy' }});
    return res.status(401).json({ error: 'signature_required' });
  }
  if (Math.abs(Math.floor(Date.now() / 1000) - unix) > WEBHOOK_MAX_SKEW_SEC) {
    void flowLog({ level:'WARN', stage:'WEBHOOK_AUTH', status:'REJECTED_EXPIRED', details:{ provider:'legacy', timestamp:unix }});
    return res.status(401).json({ error: 'signature_expired' });
  }
  const expected = `sha256=${hmac(secret, `${timestamp}.${raw}`)}`;
  if (!safeEqual(signature, expected)) {
    void flowLog({ level:'ERROR', stage:'WEBHOOK_AUTH', status:'REJECTED_BAD_SIGNATURE', details:{ provider:'legacy' }});
    return res.status(401).json({ error: 'invalid_signature' });
  }
  (req as any).paymentWebhookProvider = 'legacy';
  void flowLog({ stage:'WEBHOOK_AUTH', status:'ACCEPTED', details:{ provider:'legacy' }});
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

app.get('/health', (_req, res) => res.json({ ok: true, service: 'synthesisone-telegram-shop', version: BUILD_VERSION }));
app.get('/api/version', (_req, res) => res.json({ ok: true, version: BUILD_VERSION }));
app.get('/api/admin/diagnostics', adminMiddleware, async (_req, res) => {
  const result: any = { ok: true, version: BUILD_VERSION, bucket: BUCKET };
  const { error: plansError } = await supabase.from('plans').select('id').limit(1);
  const { error: filesError } = await supabase.from('pool_files').select('id').limit(1);
  result.plans = plansError ? { ok: false, code: plansError.code, message: plansError.message } : { ok: true };
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
  const eventId = String((req as any).paymentWebhookEventId || req.header('x-webhook-event-id') || `legacy-${crypto.randomUUID()}`);
  const provider = String((req as any).paymentWebhookProvider || 'unknown');
  const body = req.body || {};
  const transaction = body.transaction && typeof body.transaction === 'object' ? body.transaction : {};
  const isParserEvent = provider === 'parser' || body.event === 'TRANSFER_DETECTED';
  const transferNumber = normalizeTransferNumber(isParserEvent ? (transaction.sender_phone || body.sender_phone || body.transfer_number) : body.transfer_number);
  const amount = Number(isParserEvent ? transaction.amount : body.amount_cup);
  const providerReference = String(isParserEvent ? (transaction.transaction_id || body.provider_reference || eventId) : (body.provider_reference || '')).trim();
  const recipientCard = normalizeDigits(isParserEvent ? (transaction.receiver_account || body.merchant_accounts?.card1 || '') : (body.recipient_card || ''));
  const confirmationPhone = normalizeDigits(isParserEvent ? (transaction.receiver_phone || '') : (body.confirmation_phone || ''));

  void flowLog({ stage:'WEBHOOK_EVENT', status:'RECEIVED', event:body.event || null, eventId, details:{ provider, is_parser_event:isParserEvent, transfer_number:transferNumber, amount, provider_reference:providerReference || null, recipient_card:recipientCard || null, confirmation_phone:confirmationPhone || null, raw_keys:Object.keys(body).sort() }});

  if (isParserEvent && body.event !== 'TRANSFER_DETECTED') {
    void flowLog({ level:'INFO', stage:'WEBHOOK_EVENT', status:'IGNORED', event:body.event || null, eventId, details:{ reason:'not_transfer_detected' }});
    return res.json({ ok:true, ignored:true, event:body.event || null });
  }

  if (!validTransferNumber(transferNumber) || !Number.isFinite(amount) || amount <= 0) {
    void flowLog({ level:'ERROR', stage:'PAYMENT_VALIDATION', status:'REJECTED', event:body.event || null, eventId, details:{ transfer_number:transferNumber, amount }});
    return res.status(400).json({ error: 'invalid_payment_event' });
  }

  // Recipient validation is kept for legacy/manual calls. Parser-bot events are already
  // tied to the merchant client and carry merchant_accounts metadata when available.
  if (!isParserEvent && !ALLOW_PAYMENT_EVENT_WITHOUT_RECIPIENT_DATA) {
    if (!recipientCard || !confirmationPhone) {
      void flowLog({ level:'WARN', stage:'PAYMENT_VALIDATION', status:'REJECTED_RECIPIENT_DATA', eventId, details:{ reason:'recipient_data_required' }});
      return res.status(400).json({ error: 'recipient_data_required' });
    }
    if (recipientCard !== normalizeDigits(PAYMENT_CARD) || confirmationPhone !== normalizeDigits(PAYMENT_CONFIRMATION_NUMBER)) {
      void flowLog({ level:'WARN', stage:'PAYMENT_VALIDATION', status:'REJECTED_RECIPIENT_MISMATCH', eventId, details:{ recipient_card:recipientCard, confirmation_phone:confirmationPhone }});
      return res.status(400).json({ error: 'recipient_mismatch' });
    }
  }

  if (providerReference) {
    const { data: already, error: idempotencyError } = await supabase.from('payment_tickets')
      .select('id,status,telegram_id,transfer_number,amount_cup')
      .eq('provider_reference', providerReference)
      .maybeSingle();

    if (idempotencyError) {
      void flowLog({ level:'ERROR', stage:'IDEMPOTENCY', status:'DB_ERROR', eventId, details:{ provider_reference:providerReference, error:idempotencyError.message }});
      return res.status(500).json({ error:'idempotency_lookup_failed' });
    }

    if (already) {
      if (already.status === 'paid') {
        void flowLog({ level:'INFO', stage:'IDEMPOTENCY', status:'DUPLICATE_PAID', eventId, ticketId:already.id, telegramId:String(already.telegram_id), details:{ provider_reference:providerReference }});
        return res.json({ ok: true, duplicate: true, ticket_id: already.id, status: already.status });
      }

      if (already.status === 'processing') {
        void flowLog({ level:'INFO', stage:'IDEMPOTENCY', status:'IN_PROGRESS', eventId, ticketId:already.id, telegramId:String(already.telegram_id), details:{ provider_reference:providerReference, existing_status:already.status }});
        return res.json({ ok: true, duplicate: true, processing: true, ticket_id: already.id, status: already.status });
      }

      // A pending ticket may already contain a provider_reference because a previous
      // delivery attempt reached the shop but Telegram failed. In that situation the
      // same provider event must be allowed to re-enter the delivery path.
      if (already.status === 'pending') {
        void flowLog({ level:'INFO', stage:'IDEMPOTENCY', status:'RETRY_ALLOWED', eventId, ticketId:already.id, telegramId:String(already.telegram_id), details:{ provider_reference:providerReference, reason:'previous_delivery_failed_and_ticket_was_reset_to_pending' }});
      } else {
        void flowLog({ level:'WARN', stage:'IDEMPOTENCY', status:'DUPLICATE_NON_RETRYABLE', eventId, ticketId:already.id, telegramId:String(already.telegram_id), details:{ provider_reference:providerReference, existing_status:already.status }});
        return res.json({ ok: true, duplicate: true, ticket_id: already.id, status: already.status });
      }
    }
  }

  const customer = (await supabase.from('customers').select('telegram_id,transfer_number').eq('transfer_number', transferNumber).maybeSingle()).data;
  if (!customer) {
    void flowLog({ level:'WARN', stage:'TICKET_MATCH', status:'CUSTOMER_NOT_FOUND', eventId, details:{ transfer_number:transferNumber, amount }});
    return res.status(404).json({ error: 'transfer_number_unknown' });
  }

  const now = new Date();
  const minDate = new Date(now.getTime() - WINDOW_MIN * 60_000).toISOString();
  const { data: tickets, error: ticketFindError } = await supabase.from('payment_tickets').select('*')
    .eq('status', 'pending').eq('telegram_id', String(customer.telegram_id)).eq('transfer_number', transferNumber).eq('amount_cup', amount)
    .gte('created_at', minDate).gt('expires_at', now.toISOString()).order('created_at', { ascending: true }).limit(1);
  if (ticketFindError) {
    void flowLog({ level:'ERROR', stage:'TICKET_MATCH', status:'DB_ERROR', eventId, details:{ error:ticketFindError.message }});
    return res.status(500).json({ error: 'ticket_lookup_failed' });
  }
  const ticket = tickets?.[0];
  if (!ticket) {
    void flowLog({ level:'WARN', stage:'TICKET_MATCH', status:'NO_PENDING_MATCH', eventId, telegramId:String(customer.telegram_id), details:{ transfer_number:transferNumber, amount, window_minutes:WINDOW_MIN }});
    return res.status(404).json({ error: 'no_matching_pending_ticket' });
  }

  void flowLog({ stage:'TICKET_MATCH', status:'MATCHED', eventId, ticketId:ticket.id, telegramId:String(ticket.telegram_id), details:{ transfer_number:transferNumber, amount, plan_id:ticket.plan_id, ticket_created_at:ticket.created_at }});

  const { data: claimed, error: claimError } = await supabase.from('payment_tickets').update({
    status: 'processing', provider_reference: providerReference || null, delivery_attempts: (ticket.delivery_attempts || 0) + 1
  }).eq('id', ticket.id).eq('status', 'pending').select('*').single();
  if (claimError || !claimed) {
    void flowLog({ level:'WARN', stage:'TICKET_CLAIM', status:'ALREADY_CLAIMED', eventId, ticketId:ticket.id, details:{ error:claimError?.message || 'no_row_updated' }});
    return res.status(409).json({ error: 'ticket_already_claimed' });
  }
  void flowLog({ stage:'TICKET_CLAIM', status:'PROCESSING', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ provider_reference:providerReference }});

  try {
    const { data: files, error: filesError } = await supabase.from('pool_files').select('*').eq('plan_id', claimed.plan_id).eq('active', true).order('created_at');
    if (filesError) throw filesError;
    const available = files || [];
    if (!available.length) throw new Error('No file available for this plan');
    const file = available[Math.floor(Math.random() * available.length)];
    void flowLog({ stage:'FILE_SELECTION', status:'SELECTED', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ file_id:file.id, file_name:file.file_name, storage_path:file.storage_path, available_count:available.length }});

    const { data: blob, error: storageError } = await supabase.storage.from(BUCKET).download(file.storage_path);
    if (storageError || !blob) throw new Error(storageError?.message || 'Pool file unavailable');
    const bytes = Buffer.from(await blob.arrayBuffer());
    void flowLog({ stage:'FILE_DOWNLOAD', status:'READY', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ file_id:file.id, bytes:bytes.length }});

    void flowLog({ stage:'TELEGRAM_SEND', status:'START', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ file_id:file.id, file_name:file.file_name, transport:'node_https_request', timeout_ms:TELEGRAM_HTTP_TIMEOUT_MS }});
    const sent = await sendTelegramDocument(
      String(claimed.telegram_id),
      file.file_name,
      bytes,
      `✅ Pago confirmado · ${Number(claimed.amount_cup).toFixed(2)} CUP\nPlan: ${claimed.plan_id}`
    );

    void flowLog({ stage:'TELEGRAM_SEND', status:'SUCCESS', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ telegram_message_id:sent.message_id, file_id:file.id, transport:'node_https_request' }});

    const { error: paidError } = await supabase.from('payment_tickets').update({
      status: 'paid', paid_at: now.toISOString(), delivered_file_id: file.id, last_error: null
    }).eq('id', claimed.id).eq('status', 'processing');
    if (paidError) {
      void flowLog({ level:'ERROR', stage:'TICKET_FINALIZE', status:'DB_ERROR_AFTER_TELEGRAM', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ error:paidError.message }});
      throw paidError;
    }
    void flowLog({ stage:'TICKET_FINALIZE', status:'PAID', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ delivered_file_id:file.id, telegram_message_id:sent.message_id }});
    return res.json({ ok: true, ticket_id: claimed.id, telegram_message_id: sent.message_id, delivered_file_id: file.id, event_id:eventId });
  } catch (error) {
    const e = error as any;
    const message = e?.message || String(error);
    const transportError = {
      name: e?.name || 'Error',
      message,
      code: e?.code || null,
      errno: e?.errno || null,
      syscall: e?.syscall || null,
      address: e?.address || null,
      port: e?.port || null,
      type: e?.type || null,
      cause: e?.cause ? String(e.cause?.message || e.cause) : null,
      telegram_ip: e?.telegram_ip || null,
      http_status: e?.http_status || null,
      telegram_error_code: e?.telegram_error_code || null,
      telegram_description: e?.telegram_description || null,
    };
    const { error: resetError } = await supabase.from('payment_tickets').update({
      status:'pending',
      provider_reference:null,
      last_error:message
    }).eq('id', claimed.id).eq('status','processing');
    if (resetError) {
      void flowLog({ level:'ERROR', stage:'TICKET_RESET', status:'DB_ERROR_AFTER_DELIVERY_FAILURE', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ error:resetError.message }});
    } else {
      void flowLog({ stage:'TICKET_RESET', status:'PENDING_RETRY', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ provider_reference_cleared:true }});
    }
    void flowLog({ level:'ERROR', stage:'TELEGRAM_SEND', status:'FAILED', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ error:transportError, transport:{ keepAlive:false, family:4 } }});
    void flowLog({ level:'ERROR', stage:'PAYMENT_FLOW', status:'RETRYABLE_FAILURE', eventId, ticketId:claimed.id, telegramId:String(claimed.telegram_id), details:{ error:transportError }});
    return res.status(502).json({ error:'delivery_failed_retryable', event_id:eventId, detail:message });
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
app.get('/api/admin/telegram-diagnostic', adminMiddleware, async (_req, res) => {
  const started = Date.now();
  const details: Record<string, unknown> = {
    api_host: 'api.telegram.org',
    agent: { keepAlive: false, family: 4, timeout_ms: 30000 },
  };
  try {
    const addresses = await dns.lookup('api.telegram.org', { all: true });
    details.resolved_addresses = addresses.map((x) => ({ address: x.address, family: x.family }));
  } catch (e) {
    details.dns_error = e instanceof Error ? e.message : String(e);
  }
  try {
    const me = await requestTelegramApi<any>('getMe');
    details.telegram_status = 'OK';
    details.bot_id = me.id;
    details.bot_username = me.username || null;
    void flowLog({ stage: 'TELEGRAM_DIAGNOSTIC', status: 'GETME_SUCCESS', details: { ...details, elapsed_ms: Date.now() - started } });
    return res.json({ ok: true, elapsed_ms: Date.now() - started, details });
  } catch (error) {
    const e = error as any;
    const err = {
      name: e?.name || 'Error',
      message: e?.message || String(error),
      code: e?.code || null,
      errno: e?.errno || null,
      syscall: e?.syscall || null,
      address: e?.address || null,
      port: e?.port || null,
      type: e?.type || null,
      cause: e?.cause ? String(e.cause?.message || e.cause) : null,
    };
    details.telegram_status = 'ERROR';
    details.error = err;
    void flowLog({ level: 'ERROR', stage: 'TELEGRAM_DIAGNOSTIC', status: 'GETME_FAILED', details: { ...details, elapsed_ms: Date.now() - started } });
    return res.status(502).json({ ok: false, elapsed_ms: Date.now() - started, details });
  }
});

app.get('/api/admin/payment-flow-logs', adminMiddleware, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 200), 1), 500);
  let query = supabase.from('payment_flow_logs').select('*').order('created_at', { ascending:false }).order('id', { ascending:false }).limit(limit);
  if (req.query.ticket_id) query = query.eq('ticket_id', String(req.query.ticket_id));
  if (req.query.event_id) query = query.eq('event_id', String(req.query.event_id));
  const { data, error } = await query;
  if (error) return res.status(500).json({ error:'payment_flow_logs_unavailable', detail:error.message });
  res.json(data || []);
});
app.get('/api/admin/tickets', adminMiddleware, async (_req, res) => {
  const { data, error } = await supabase.from('payment_tickets').select('*,plans(name,price_cup)').order('created_at', { ascending: false }).limit(300);
  if (error) return res.status(500).json({ error: 'tickets_unavailable' }); res.json(data || []);
});
app.get('/api/admin/parser-webhook-status', adminMiddleware, (_req, res) => {
  res.json({
    configured: Boolean(PARSER_WEBHOOK_SECRET),
    mode: 'parser-bot',
    endpoint: '/api/payments/incoming',
    accepted_headers: ['X-Webhook-Event-Id','X-Webhook-Timestamp','X-Webhook-Signature','X-Webhook-Signature-V2']
  });
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
app.post('/api/admin/test-parser/:ticketId', adminMiddleware, async (req, res) => {
  if (!PARSER_WEBHOOK_SECRET) return res.status(500).json({ error:'parser_webhook_secret_missing' });
  const { data: ticket, error: ticketError } = await supabase.from('payment_tickets').select('*').eq('id', req.params.ticketId).single();
  if (ticketError || !ticket) return res.status(404).json({ error:'ticket_not_found' });

  const body = JSON.stringify({
    schema_version:'1.0',
    event:'TRANSFER_DETECTED',
    event_id:`TEST-PARSER-${ticket.id}-${Date.now()}`,
    occurred_at:new Date().toISOString(),
    client:{ id:'test-client', name:'Parser Test', phone_number:null, expires_at:null },
    merchant_accounts:{ card1:PAYMENT_CARD, card2:null, card3:null, wallet:null },
    sms:{ sender:'TEST', body:'TEST TRANSFER', received_at:new Date().toISOString(), message_id:null, log_id:null },
    verification:{ is_financial_transfer:true, has_amount:true, has_currency:true, has_transaction_id:true, has_destination_account:false, has_destination_phone:false, has_counterparty_phone:true },
    transaction:{ direction:'RECIBIDO', type:'TEST', network:'PAGOMOVIL', amount:Number(ticket.amount_cup), currency:'CUP', sender_phone:ticket.transfer_number, receiver_phone:null, receiver_account:PAYMENT_CARD, transaction_id:`TEST-${ticket.id}`, balance_after:null }
  });
  const timestamp=String(Math.floor(Date.now()/1000));
  const signature=hmac(PARSER_WEBHOOK_SECRET, `${timestamp}.${body}`);
  const target=`${BASE}/api/payments/incoming`;
  await flowLog({ stage:'TEST_PARSER', status:'START', eventId:JSON.parse(body).event_id, ticketId:ticket.id, telegramId:String(ticket.telegram_id), details:{ target, transfer_number:ticket.transfer_number, amount:Number(ticket.amount_cup) }});
  try {
    const response=await fetch(target,{ method:'POST', headers:{'Content-Type':'application/json','X-Webhook-Event-Id':JSON.parse(body).event_id,'X-Webhook-Timestamp':timestamp,'X-Webhook-Signature':signature,'X-Webhook-Signature-V2':signature,'User-Agent':'SynthesisOne-Parser-Test/1.0'}, body });
    const text=await response.text();
    await flowLog({ level:response.ok?'INFO':'ERROR', stage:'TEST_PARSER', status:response.ok?'SUCCESS':'HTTP_ERROR', eventId:JSON.parse(body).event_id, ticketId:ticket.id, telegramId:String(ticket.telegram_id), details:{ http_status:response.status, response:text.slice(0,8000) }});
    res.status(response.ok?200:502).json({ ok:response.ok, http_status:response.status, response:text.slice(0,8000) });
  } catch(error) {
    const detail=error instanceof Error?error.message:String(error);
    await flowLog({ level:'ERROR', stage:'TEST_PARSER', status:'FETCH_EXCEPTION', ticketId:ticket.id, telegramId:String(ticket.telegram_id), details:{ error:detail, target }});
    res.status(502).json({ error:'test_parser_failed', detail });
  }
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
