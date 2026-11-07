-- Run once in Supabase: SQL Editor > New query > paste > Run.

-- One profile row per account, created automatically on sign-up (email or Google).
create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  full_name  text,
  email      text,
  provider   text,
  created_at timestamptz not null default now()
);

-- Every sign-up, sign-in, sign-out and password change.
create table if not exists public.audit_log (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references auth.users (id) on delete cascade,
  event      text not null check (event in ('register','login','google_login','logout','reset_done')),
  detail     text,
  created_at timestamptz not null default now()
);
create index if not exists audit_log_user_idx on public.audit_log (user_id, created_at desc);

alter table public.profiles  enable row level security;
alter table public.audit_log enable row level security;

drop policy if exists "profiles: read own"   on public.profiles;
drop policy if exists "profiles: update own" on public.profiles;
drop policy if exists "audit: read own"      on public.audit_log;
drop policy if exists "audit: insert own"    on public.audit_log;

create policy "profiles: read own"   on public.profiles  for select using (auth.uid() = id);
create policy "profiles: update own" on public.profiles  for update using (auth.uid() = id) with check (auth.uid() = id);
create policy "audit: read own"      on public.audit_log for select using (auth.uid() = user_id);
create policy "audit: insert own"    on public.audit_log for insert with check (auth.uid() = user_id);

-- Create the profile when an auth user appears.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name, email, provider)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    new.email,
    coalesce(new.raw_app_meta_data->>'provider', 'email')
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
