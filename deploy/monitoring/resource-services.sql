-- This is the ONLY projection granted to the resource exporter. Do not add
-- spec/status, email, credential, environment or audit payload columns.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_resource_creator_idx
ON public.outbox_events (aggregate_id, created_at, id)
WHERE topic = 'service-instance.reconcile' AND payload->>'generation' = '1';
CREATE SCHEMA IF NOT EXISTS monitoring;
REVOKE ALL ON SCHEMA monitoring FROM PUBLIC;
CREATE OR REPLACE VIEW monitoring.resource_services WITH (security_barrier = true) AS
SELECT s.id::text AS service_id, s.name AS service_name,
       s.organization_id::text AS organization_id, o.name AS organization_name,
       p.id::text AS creator_principal_id, p.name AS creator_name,
       u.id::text AS creator_user_id, u.display_name AS creator_user_name,
       s.spec->>'task_role' AS task_role_id
FROM public.service_instances s
JOIN public.organizations o ON o.id = s.organization_id
LEFT JOIN LATERAL (
    -- The generation-one event is retained and records the creator, whereas
    -- the latest requester changes on every edit. Never infer from metadata.
    SELECT e.payload->>'principal_id' AS principal_id
    FROM public.outbox_events e
    WHERE e.aggregate_id = s.id AND e.topic = 'service-instance.reconcile'
      AND e.payload->>'generation' = '1'
    ORDER BY e.created_at, e.id LIMIT 1
) creator ON true
LEFT JOIN public.principals p ON p.id::text = creator.principal_id
    AND p.organization_id = s.organization_id
LEFT JOIN public.users u ON u.id = p.user_id
WHERE s.provider = 'flash' AND s.state <> 'deleting';
