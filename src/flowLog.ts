import { supabase } from './serverDeps.js';

export type FlowLevel = 'INFO' | 'WARN' | 'ERROR';

function safeDetails(details: Record<string, unknown> = {}) {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(details)) {
    if (/secret|token|authorization|signature/i.test(k)) continue;
    if (typeof v === 'string' && v.length > 8000) out[k] = v.slice(0, 8000) + '…';
    else out[k] = v;
  }
  return out;
}

export async function flowLog(input: {
  level?: FlowLevel;
  stage: string;
  status?: string;
  event?: string;
  eventId?: string | null;
  ticketId?: string | null;
  telegramId?: string | null;
  details?: Record<string, unknown>;
}) {
  const level = input.level || 'INFO';
  const entry = {
    ts: new Date().toISOString(),
    service: 'synthesisone-telegram-shop',
    subsystem: 'payment-flow',
    level,
    stage: input.stage,
    status: input.status || null,
    event: input.event || null,
    event_id: input.eventId || null,
    ticket_id: input.ticketId || null,
    telegram_id: input.telegramId || null,
    ...safeDetails(input.details || {}),
  };
  const line = JSON.stringify(entry);
  if (level === 'ERROR') console.error(line);
  else if (level === 'WARN') console.warn(line);
  else console.log(line);

  try {
    const { error } = await supabase.from('payment_flow_logs').insert({
      level,
      stage: input.stage,
      status: input.status || null,
      event: input.event || null,
      event_id: input.eventId || null,
      ticket_id: input.ticketId || null,
      telegram_id: input.telegramId || null,
      details: safeDetails(input.details || {}),
    });
    if (error) console.error(JSON.stringify({ ts: new Date().toISOString(), service: 'synthesisone-telegram-shop', subsystem: 'payment-flow', level: 'ERROR', stage: 'PERSIST_LOG_FAILED', error: error.message }));
  } catch (error) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), service: 'synthesisone-telegram-shop', subsystem: 'payment-flow', level: 'ERROR', stage: 'PERSIST_LOG_EXCEPTION', error: error instanceof Error ? error.message : String(error) }));
  }
}
