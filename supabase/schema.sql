-- =====================================================================
-- Plano Alimentar · estrutura do banco (Supabase)
-- Cole tudo no SQL Editor do Supabase e clique em "Run". Pode rodar de novo sem problema.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Tabelas ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  display_name text not null,
  role text not null check (role in ('nutri','paciente')),
  created_at timestamptz not null default now()
);

create table if not exists public.plans (
  patient_id uuid primary key references public.profiles(id) on delete cascade,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.profiles(id) on delete set null
);

create table if not exists public.logs (
  patient_id uuid not null references public.profiles(id) on delete cascade,
  day date not null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (patient_id, day)
);

-- ---------- Quem é nutricionista ----------
create or replace function public.is_nutri() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'nutri');
$$;

-- ---------- Permissões (RLS) ----------
alter table public.profiles enable row level security;
alter table public.plans    enable row level security;
alter table public.logs     enable row level security;

drop policy if exists "perfil: ver o próprio ou nutri" on public.profiles;
create policy "perfil: ver o próprio ou nutri" on public.profiles
  for select using (id = auth.uid() or public.is_nutri());
drop policy if exists "perfil: nutri edita" on public.profiles;
create policy "perfil: nutri edita" on public.profiles
  for update using (public.is_nutri()) with check (public.is_nutri());

drop policy if exists "plano: ver o próprio ou nutri" on public.plans;
create policy "plano: ver o próprio ou nutri" on public.plans
  for select using (patient_id = auth.uid() or public.is_nutri());
drop policy if exists "plano: nutri cria" on public.plans;
create policy "plano: nutri cria" on public.plans
  for insert with check (public.is_nutri());
drop policy if exists "plano: nutri edita" on public.plans;
create policy "plano: nutri edita" on public.plans
  for update using (public.is_nutri()) with check (public.is_nutri());

drop policy if exists "registro: ver o próprio ou nutri" on public.logs;
create policy "registro: ver o próprio ou nutri" on public.logs
  for select using (patient_id = auth.uid() or public.is_nutri());
drop policy if exists "registro: paciente grava o próprio" on public.logs;
create policy "registro: paciente grava o próprio" on public.logs
  for insert with check (patient_id = auth.uid());
drop policy if exists "registro: paciente atualiza o próprio" on public.logs;
create policy "registro: paciente atualiza o próprio" on public.logs
  for update using (patient_id = auth.uid()) with check (patient_id = auth.uid());

revoke all on public.profiles, public.plans, public.logs from anon;
grant select, update on public.profiles to authenticated;
grant select, insert, update on public.plans to authenticated;
grant select, insert, update on public.logs to authenticated;

-- ---------- Funções internas ----------
create or replace function public._login_email(p_username text) returns text
language sql immutable as $$
  select lower(regexp_replace(trim(p_username), '[^a-zA-Z0-9._-]', '', 'g')) || '@plano-alimentar.local';
$$;

create or replace function public._create_login(p_username text, p_password_hash text) returns uuid
language plpgsql security definer set search_path = public, extensions, auth as $$
declare uid uuid := gen_random_uuid(); em text := public._login_email(p_username);
begin
  insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, email_change, email_change_token_new, recovery_token)
  values ('00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated', em, p_password_hash, now(),
    '{"provider":"email","providers":["email"]}'::jsonb, '{}'::jsonb, now(), now(), '', '', '', '');
  insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), uid, uid::text,
    jsonb_build_object('sub', uid::text, 'email', em, 'email_verified', true), 'email', now(), now(), now());
  return uid;
end $$;
revoke all on function public._create_login(text, text) from public, anon, authenticated;

-- ---------- Ações da nutricionista (chamadas pelo site) ----------
create or replace function public.nutri_create_patient(p_username text, p_password text, p_name text, p_plan jsonb)
returns uuid language plpgsql security definer set search_path = public, extensions, auth as $$
declare uid uuid; uname text := trim(p_username);
begin
  if not public.is_nutri() then raise exception 'Somente a nutricionista pode cadastrar pacientes.'; end if;
  if uname !~ '^[A-Za-z0-9._-]{3,40}$' then raise exception 'Usuário deve ter de 3 a 40 letras, números, ponto, hífen ou sublinhado.'; end if;
  if length(coalesce(p_password,'')) < 6 then raise exception 'A senha precisa ter pelo menos 6 caracteres.'; end if;
  if exists (select 1 from public.profiles where lower(username) = lower(uname)) then raise exception 'Já existe um paciente com esse usuário.'; end if;
  uid := public._create_login(uname, extensions.crypt(p_password, extensions.gen_salt('bf')));
  insert into public.profiles (id, username, display_name, role) values (uid, uname, coalesce(nullif(trim(p_name),''), uname), 'paciente');
  insert into public.plans (patient_id, data, updated_by) values (uid, p_plan, auth.uid());
  return uid;
end $$;

create or replace function public.nutri_set_password(p_patient uuid, p_password text)
returns void language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not public.is_nutri() then raise exception 'Somente a nutricionista pode trocar senhas.'; end if;
  if length(coalesce(p_password,'')) < 6 then raise exception 'A senha precisa ter pelo menos 6 caracteres.'; end if;
  if not exists (select 1 from public.profiles where id = p_patient and role = 'paciente') then raise exception 'Paciente não encontrado.'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')), updated_at = now() where id = p_patient;
end $$;

create or replace function public.nutri_delete_patient(p_patient uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_nutri() then raise exception 'Somente a nutricionista pode excluir pacientes.'; end if;
  if not exists (select 1 from public.profiles where id = p_patient and role = 'paciente') then raise exception 'Paciente não encontrado.'; end if;
  delete from auth.users where id = p_patient;
end $$;

revoke all on function public.nutri_create_patient(text, text, text, jsonb) from public, anon;
revoke all on function public.nutri_set_password(uuid, text) from public, anon;
revoke all on function public.nutri_delete_patient(uuid) from public, anon;
grant execute on function public.nutri_create_patient(text, text, text, jsonb) to authenticated;
grant execute on function public.nutri_set_password(uuid, text) to authenticated;
grant execute on function public.nutri_delete_patient(uuid) to authenticated;
