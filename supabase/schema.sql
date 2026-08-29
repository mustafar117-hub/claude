-- Ops Ledger — Supabase schema
-- Run this once in your Supabase project's SQL editor (Dashboard → SQL Editor → New query → paste → Run).

create extension if not exists pgcrypto;

-- ---------- profiles (one row per login: owner or staff) ----------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  role text not null default 'staff' check (role in ('owner','staff')),
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;

-- Auto-create a profile (defaulting to 'staff') whenever someone signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)), 'staff');
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.is_owner()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'owner');
$$;

create policy "profiles_select_all_authenticated" on public.profiles
  for select using (auth.uid() is not null);
create policy "profiles_update_own_or_owner" on public.profiles
  for update using (auth.uid() = id or public.is_owner());
create policy "profiles_delete_owner_only" on public.profiles
  for delete using (public.is_owner());

-- ---------- settings (single row: company name) ----------
create table public.settings (
  id boolean primary key default true check (id),
  company text not null default 'My Company'
);
insert into public.settings (id, company) values (true, 'My Company');
alter table public.settings enable row level security;
create policy "settings_select_all_authenticated" on public.settings
  for select using (auth.uid() is not null);
create policy "settings_update_owner_only" on public.settings
  for update using (public.is_owner());

-- ---------- tasks (shared: everyone signed in can see all tasks) ----------
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  assignee_id uuid references public.profiles(id) on delete set null,
  due date,
  priority text not null default 'normal' check (priority in ('low','normal','high')),
  status text not null default 'todo' check (status in ('todo','in progress','done')),
  completed_at timestamptz,
  created_at timestamptz not null default now()
);
alter table public.tasks enable row level security;

create policy "tasks_select_all_authenticated" on public.tasks
  for select using (auth.uid() is not null);
create policy "tasks_insert_owner_only" on public.tasks
  for insert with check (public.is_owner());
create policy "tasks_update_owner_or_assignee" on public.tasks
  for update using (public.is_owner() or assignee_id = auth.uid());
create policy "tasks_delete_owner_only" on public.tasks
  for delete using (public.is_owner());

-- Staff can only flip status/completed_at on their own task, never reassign or rewrite it.
create or replace function public.restrict_task_updates()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_owner() then
    if new.title <> old.title
       or new.assignee_id is distinct from old.assignee_id
       or new.due is distinct from old.due
       or new.priority <> old.priority then
      raise exception 'Only the owner can edit task details';
    end if;
  end if;
  return new;
end;
$$;

create trigger tasks_restrict_staff_updates
  before update on public.tasks
  for each row execute function public.restrict_task_updates();

-- ---------- customers / vendors (private to the owner) ----------
create table public.customers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text,
  email text,
  created_at timestamptz not null default now()
);
alter table public.customers enable row level security;
create policy "customers_owner_all" on public.customers
  for all using (public.is_owner()) with check (public.is_owner());

create table public.vendors (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text,
  email text,
  created_at timestamptz not null default now()
);
alter table public.vendors enable row level security;
create policy "vendors_owner_all" on public.vendors
  for all using (public.is_owner()) with check (public.is_owner());

-- ---------- appointments (customers only) ----------
create table public.appointments (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.customers(id) on delete cascade,
  date date not null,
  time text,
  service text,
  notes text,
  created_at timestamptz not null default now()
);
alter table public.appointments enable row level security;
create policy "appointments_owner_all" on public.appointments
  for all using (public.is_owner()) with check (public.is_owner());

-- ---------- ledger (money in/out, optionally tied to a customer or vendor) ----------
create table public.ledger (
  id uuid primary key default gen_random_uuid(),
  description text not null,
  date date not null,
  type text not null check (type in ('credit','debit')),
  amount numeric(12,2) not null check (amount >= 0),
  party_type text check (party_type in ('customer','vendor')),
  party_id uuid,
  created_at timestamptz not null default now()
);
alter table public.ledger enable row level security;
create policy "ledger_owner_all" on public.ledger
  for all using (public.is_owner()) with check (public.is_owner());

-- ---------- party_notes (conversation log on a customer or vendor) ----------
create table public.party_notes (
  id uuid primary key default gen_random_uuid(),
  party_type text not null check (party_type in ('customer','vendor')),
  party_id uuid not null,
  date date not null,
  text text not null,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);
alter table public.party_notes enable row level security;
create policy "party_notes_owner_all" on public.party_notes
  for all using (public.is_owner()) with check (public.is_owner());

-- ---------- after running this file ----------
-- 1. Sign up once from the app itself (as yourself) so a profile row exists for you.
-- 2. Then run this, filling in your email, to make yourself the owner:
--      update public.profiles set role = 'owner' where id = (select id from auth.users where email = 'YOUR-EMAIL-HERE');
-- 3. In Authentication → Providers → Email, turn OFF "Confirm email" so staff can log
--    in immediately after creating their account without needing to click an email link.
