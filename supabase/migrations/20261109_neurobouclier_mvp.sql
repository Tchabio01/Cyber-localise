-- NeuroBouclier Africa MVP — migration additive pour le cloud multi-organisation.
-- À exécuter dans le SQL Editor du projet Supabase choisi, après le schema.sql existant.
-- Cette migration ne crée aucun utilisateur et ne publie aucune clé secrète.

alter table public.cloud_incident_events
  add column if not exists status text not null default 'open'
    check (status in ('open','in_progress','resolved')),
  add column if not exists assignee text not null default '',
  add column if not exists resolution text not null default '';

drop policy if exists cloud_events_update_member on public.cloud_incident_events;
create policy cloud_events_update_analyst on public.cloud_incident_events
for update to authenticated
using (
  private.has_org_role(organization_id,array['owner','admin','analyst'])
  or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin'
)
with check (
  private.has_org_role(organization_id,array['owner','admin','analyst'])
  or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin'
);

create table if not exists public.cloud_vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  cve text not null check (cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  vendor text not null default '',
  product text not null default '',
  vulnerability_name text not null default '',
  date_added date,
  due_date date,
  ransomware_use text not null default 'Unknown',
  description text not null default '',
  required_action text not null default '',
  source_url text not null,
  reported_by uuid not null references auth.users(id),
  synced_at timestamptz not null default now(),
  unique (organization_id,cve)
);

alter table public.cloud_vulnerabilities enable row level security;
drop policy if exists cloud_vulnerabilities_select_member on public.cloud_vulnerabilities;
create policy cloud_vulnerabilities_select_member on public.cloud_vulnerabilities
for select to authenticated
using (private.is_org_member(organization_id) or (auth.jwt()->'app_metadata'->>'platform_role') = 'admin');
drop policy if exists cloud_vulnerabilities_insert_analyst on public.cloud_vulnerabilities;
create policy cloud_vulnerabilities_insert_analyst on public.cloud_vulnerabilities
for insert to authenticated
with check (
  private.has_org_role(organization_id,array['owner','admin','analyst'])
  and reported_by = (select auth.uid())
);
drop policy if exists cloud_vulnerabilities_update_analyst on public.cloud_vulnerabilities;
create policy cloud_vulnerabilities_update_analyst on public.cloud_vulnerabilities
for update to authenticated
using (private.has_org_role(organization_id,array['owner','admin','analyst']))
with check (private.has_org_role(organization_id,array['owner','admin','analyst']));

revoke all on table public.cloud_vulnerabilities from public,anon,authenticated;
grant select,insert,update on public.cloud_vulnerabilities to authenticated;
