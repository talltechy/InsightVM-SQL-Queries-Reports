WITH
   vuln_references AS (
      SELECT dv.vulnerability_id
      ,array_to_string(array_agg(reference), ', ') AS references
      ,fava.age_in_days AS aid
      ,dv.severity AS severity
      FROM dim_vulnerability dv
        JOIN dim_vulnerability_reference USING (vulnerability_id)
        LEFT OUTER JOIN fact_asset_vulnerability_age fava ON fava.vulnerability_id = dv.vulnerability_id
      GROUP BY dv.vulnerability_id, dv.severity, fava.age_in_days
   )
--begin SELECT
SELECT da.ip_address AS "IP"
,da.host_name AS "Hostname"
,da.mac_address AS "MAC"
,dv.title AS "Vulnerability"
,dvs.description AS "Status"
,favi.date AS "Discovered Date"
,vr.aid AS "Age"
,   CASE
        WHEN vr.aid < 30 THEN '<30' 
        WHEN vr.aid > 30 and vr.aid <= 60 THEN '30-60'
        WHEN vr.aid > 60 and vr.aid <= 90 THEN '61-90'
    ELSE '90+'
    END as "Aging"
,vr.severity AS "Severity"
,CASE WHEN favi.port = -1 THEN NULL ELSE favi.port END AS "PORT"
,dp.name AS "Protocol"
,dsvc.name AS "Service"
,proofAsText(dv.description) AS "Vulnerability Description"
,proofAsText(favi.proof) AS "Proof"
,vr.references AS "References"
,dv.exploits AS "Exploits"
,dv.malware_kits AS "Malware Kits"
--end SELECT
--begin FROM/JOIN
FROM fact_asset_vulnerability_instance favi
   JOIN dim_asset da USING (asset_id)
   JOIN dim_vulnerability dv USING (vulnerability_id)
   JOIN dim_site_asset dsa USING (asset_id)
   JOIN dim_site ds USING (site_id)
   JOIN dim_vulnerability_status dvs USING (status_id)
   JOIN dim_protocol dp USING (protocol_id)
   JOIN dim_service dsvc USING (service_id)
   JOIN vuln_references vr USING (vulnerability_id)
--end FROM/JOIN
ORDER BY ds.name, da.ip_address