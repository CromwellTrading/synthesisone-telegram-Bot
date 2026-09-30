-- Upgrade an existing SynthesisOne Telegram Shop v1.0 database.
alter table payment_tickets drop constraint if exists payment_tickets_status_check;
alter table payment_tickets add constraint payment_tickets_status_check check(status in('pending','processing','paid','rejected','expired'));
alter table payment_tickets add column if not exists delivery_attempts integer not null default 0;
alter table payment_tickets add column if not exists last_error text;
create unique index if not exists payment_tickets_provider_reference_uq on payment_tickets(provider_reference) where provider_reference is not null;
create unique index if not exists customers_transfer_number_uq on customers(transfer_number) where transfer_number is not null;
create index if not exists payment_tickets_telegram_idx on payment_tickets(telegram_id,status,created_at);
