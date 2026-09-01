create extension if not exists pgcrypto;

create table if not exists projects (
  id text primary key,
  organization_id uuid,
  name text not null,
  created_at timestamptz not null default now()
);

alter table projects
  add column if not exists organization_id uuid;

create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

insert into organizations (id, name)
values ('00000000-0000-0000-0000-000000000001', 'Demo Organization')
on conflict (id) do nothing;

update projects
set organization_id = '00000000-0000-0000-0000-000000000001'
where organization_id is null;

alter table projects
  alter column organization_id set not null;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references organizations(id) on delete cascade,
  email text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists project_memberships (
  id uuid primary key default gen_random_uuid(),
  project_id text not null references projects(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'developer', 'viewer')),
  created_at timestamptz not null default now(),
  unique (project_id, user_id)
);

create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  project_id text not null references projects(id) on delete cascade,
  name text not null,
  key_hash text not null unique,
  prefix text not null,
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create index if not exists api_keys_project_id_idx on api_keys(project_id);

create table if not exists api_events (
  id text primary key,
  trace_id text,
  parent_span_id text,
  project_id text not null,
  service_name text not null,
  environment text not null,
  timestamp timestamptz not null,
  kind text not null,
  method text not null,
  path text not null,
  route text,
  ip text,
  user_agent text,
  request_headers jsonb not null default '{}',
  request_query jsonb not null default '{}',
  request_body jsonb,
  status_code int not null,
  latency_ms int not null,
  body_bytes int,
  auth_present boolean not null default false,
  auth_failed boolean not null default false,
  graphql_operation_name text,
  graphql_operation_type text,
  evm_rpc_method text,
  threat_score int not null default 0,
  threat_severity text not null default 'low',
  threat_signals jsonb not null default '[]',
  created_at timestamptz not null default now()
);

create index if not exists api_events_project_timestamp_idx on api_events(project_id, timestamp desc);
create index if not exists api_events_path_idx on api_events(path);
create index if not exists api_events_ip_idx on api_events(ip);
create index if not exists api_events_threat_idx on api_events(threat_score desc);
create index if not exists api_events_trace_id_idx on api_events(trace_id);

create table if not exists incidents (
  id uuid primary key default gen_random_uuid(),
  event_id text not null unique references api_events(id) on delete cascade,
  incident_key text,
  project_id text not null,
  severity text not null,
  title text not null,
  description text not null,
  signals jsonb not null default '[]',
  affected_endpoint text,
  attacker_ips jsonb not null default '[]',
  request_count int not null default 1,
  started_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  status text not null default 'open',
  created_at timestamptz not null default now()
);

update incidents
set incident_key = 'event:' || event_id
where incident_key is null;

create unique index if not exists incidents_incident_key_idx on incidents(incident_key);

insert into projects (id, organization_id, name)
values ('demo', '00000000-0000-0000-0000-000000000001', 'Demo Project')
on conflict (id) do nothing;

update projects
set organization_id = '00000000-0000-0000-0000-000000000001'
where id = 'demo';
