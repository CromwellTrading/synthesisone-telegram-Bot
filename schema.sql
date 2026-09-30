create extension if not exists pgcrypto;

create table if not exists plans(
  id uuid primary key default gen_random_uuid(),
  name text not null,
  price_cup numeric(12,2) not null check(price_cup>0),
  description text default '',
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create table if not exists pool_files(
  id uuid primary key default gen_random_uuid(),
  plan_id uuid not null references plans(id) on delete cascade,
  file_name text not null,
  storage_path text not null unique,
  telegram_file_id text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create table if not exists customers(
  id uuid primary key default gen_random_uuid(),
  telegram_id bigint not null unique,
  transfer_number text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists payment_tickets(
  id uuid primary key default gen_random_uuid(),
  plan_id uuid not null references plans(id),
  telegram_id bigint not null,
  transfer_number text not null,
  amount_cup numeric(12,2) not null,
  status text not null default 'pending' check(status in('pending','processing','paid','rejected','expired')),
  provider_reference text,
  paid_at timestamptz,
  delivered_file_id uuid references pool_files(id),
  delivery_attempts integer not null default 0,
  last_error text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists payment_tickets_match_idx on payment_tickets(transfer_number,amount_cup,status,created_at);
create index if not exists payment_tickets_telegram_idx on payment_tickets(telegram_id,status,created_at);
create unique index if not exists payment_tickets_provider_reference_uq on payment_tickets(provider_reference) where provider_reference is not null;
create unique index if not exists customers_transfer_number_uq on customers(transfer_number) where transfer_number is not null;

alter table plans enable row level security;
alter table pool_files enable row level security;
alter table customers enable row level security;
alter table payment_tickets enable row level security;

insert into plans(name,price_cup,description) select 'Plan 5 CUP',5,'Archivo del pool · 5 CUP' where not exists(select 1 from plans where price_cup=5);
insert into plans(name,price_cup,description) select 'Plan 10 CUP',10,'Archivo del pool · 10 CUP' where not exists(select 1 from plans where price_cup=10);
insert into plans(name,price_cup,description) select 'Plan 20 CUP',20,'Archivo del pool · 20 CUP' where not exists(select 1 from plans where price_cup=20);

-- Crea manualmente en Supabase Storage un bucket PRIVADO llamado telegram-pool.
-- La service-role key solo se utiliza en el backend.
