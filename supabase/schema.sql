-- CyberWatch Africa PRO 7.0 — Supabase schema
-- Apply only to the Supabase project selected for CyberWatch.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create or replace function private.create_profile_for_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $
begin
  insert into public.profiles(user_id,display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name',''))
  on conflict (user_id) do nothing;
  return new;
end;
$;
drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users
for each row execute function private.create_profile_for_new_user();

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 100),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);
create table if not exists public.organization_members (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','admin','analyst','member')),
  created_at timestamptz not null default now(),
  primary key (organization_id,user_id)
);
create table if not exists public.cloud_threat_observations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  ip inet not null, source text not null, kind text not null, label text,
  country text, country_code text, city text, lat double precision, lon double precision,
  first_seen timestamptz, last_seen timestamptz,
  reported_by uuid not null default auth.uid() references auth.users(id),
  origin text not null default 'local_collector',
  verified boolean not null default false,
  created_at timestamptz not null default now(),
  unique (organization_id,ip,source,reported_by)
);
create table if not exists public.cloud_incident_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  local_event_id text not null, ts timestamptz not null,
  severity text not null, category text not null, title text not null, detail text not null,
  ip inet, reported_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  unique (organization_id,local_event_id,reported_by)
);
create table if not exists public.user_preferences (
  user_id uuid primary key references auth.users(id) on delete cascade,
  language text not null default 'fr' check (language in ('fr','en','pt','ar')),
  preferences jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create or replace function private.is_org_member(target_org uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.organization_members m
    where m.organization_id = target_org and m.user_id = (select auth.uid())
  );
$$;
create or replace function private.has_org_role(target_org uuid, allowed_roles text[])
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.organization_members m
    where m.organization_id = target_org
      and m.user_id = (select auth.uid())
      and m.role = any(allowed_roles)
  );
$$;
grant execute on function private.is_org_member(uuid) to authenticated;
grant execute on function private.has_org_role(uuid,text[]) to authenticated;

create or replace function private.add_org_owner()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.organization_members(organization_id,user_id,role)
  values (new.id,new.created_by,'owner');
  return new;
end;
$$;
drop trigger if exists organizations_add_owner on public.organizations;
create trigger organizations_add_owner after insert on public.organizations
for each row execute function private.add_org_owner();

alter table public.profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.cloud_threat_observations enable row level security;
alter table public.cloud_incident_events enable row level security;
alter table public.user_preferences enable row level security;

drop policy if exists profiles_select_self_or_platform_admin on public.profiles;
create policy profiles_select_self_or_platform_admin on public.profiles for select to authenticated
using (user_id = (select auth.uid()) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin');
drop policy if exists profiles_insert_self on public.profiles;
create policy profiles_insert_self on public.profiles for insert to authenticated
with check (user_id = (select auth.uid()));
drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles for update to authenticated
using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

drop policy if exists organizations_select_member on public.organizations;
create policy organizations_select_member on public.organizations for select to authenticated
using (private.is_org_member(id) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin');
drop policy if exists organizations_insert_self on public.organizations;
create policy organizations_insert_self on public.organizations for insert to authenticated
with check (created_by = (select auth.uid()));
drop policy if exists organizations_update_admin on public.organizations;
create policy organizations_update_admin on public.organizations for update to authenticated
using (private.has_org_role(id,array['owner','admin']) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin')
with check (private.has_org_role(id,array['owner','admin']) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin');
drop policy if exists organizations_delete_owner on public.organizations;
create policy organizations_delete_owner on public.organizations for delete to authenticated
using (private.has_org_role(id,array['owner']));

drop policy if exists members_select_same_org on public.organization_members;
create policy members_select_same_org on public.organization_members for select to authenticated
using (user_id = (select auth.uid()) or private.has_org_role(organization_id,array['owner','admin']) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin');
drop policy if exists members_insert_admin on public.organization_members;
create policy members_insert_admin on public.organization_members for insert to authenticated
with check ((private.has_org_role(organization_id,array['owner','admin']) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin') and role in ('analyst','member'));
drop policy if exists members_delete_admin on public.organization_members;
create policy members_delete_admin on public.organization_members for delete to authenticated
using ((private.has_org_role(organization_id,array['owner','admin']) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin') and role <> 'owner');

drop policy if exists cloud_threats_select_member on public.cloud_threat_observations;
create policy cloud_threats_select_member on public.cloud_threat_observations for select to authenticated
using (private.is_org_member(organization_id) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin');
drop policy if exists cloud_threats_insert_member on public.cloud_threat_observations;
create policy cloud_threats_insert_member on public.cloud_threat_observations for insert to authenticated
with check (private.is_org_member(organization_id) and reported_by = (select auth.uid()));
drop policy if exists cloud_threats_update_member on public.cloud_threat_observations;
create policy cloud_threats_update_member on public.cloud_threat_observations for update to authenticated
using (private.is_org_member(organization_id) and reported_by = (select auth.uid()))
with check (private.is_org_member(organization_id) and reported_by = (select auth.uid()));

drop policy if exists cloud_events_select_member on public.cloud_incident_events;
create policy cloud_events_select_member on public.cloud_incident_events for select to authenticated
using (private.is_org_member(organization_id));
drop policy if exists cloud_events_insert_member on public.cloud_incident_events;
create policy cloud_events_insert_member on public.cloud_incident_events for insert to authenticated
with check (private.is_org_member(organization_id) and reported_by = (select auth.uid()));
drop policy if exists cloud_events_update_member on public.cloud_incident_events;
create policy cloud_events_update_member on public.cloud_incident_events for update to authenticated
using (private.is_org_member(organization_id) and reported_by = (select auth.uid()))
with check (private.is_org_member(organization_id) and reported_by = (select auth.uid()));

drop policy if exists preferences_self_all on public.user_preferences;
create policy preferences_self_all on public.user_preferences for all to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

grant select, insert, update on public.profiles to authenticated;
grant select, insert, update, delete on public.organizations to authenticated;
grant select, insert, delete on public.organization_members to authenticated;
grant select, insert, update on public.cloud_threat_observations to authenticated;
grant select, insert, update on public.cloud_incident_events to authenticated;
grant select, insert, update on public.user_preferences to authenticated;
