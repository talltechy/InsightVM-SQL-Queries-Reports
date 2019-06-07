WITH
   vuln_references AS (
      SELECT dv.vulnerability_id, array_to_string(array_agg(reference), ', ') AS references
      ,fava.age_in_days AS aid
      FROM dim_vulnerability dv
        JOIN dim_vulnerability_reference USING (vulnerability_id)
        LEFT OUTER JOIN fact_asset_vulnerability_age fava ON fava.vulnerability_id = dv.vulnerability_id
      GROUP BY dv.vulnerability_id, fava.age_in_days
   )
--begin SELECT
SELECT da.ip_address
,da.host_name
,da.mac_address
,dv.title AS vulnerability
,dvs.description AS status
,favi.date AS discovered_date
,vr.aid AS "Age"
,   CASE
        WHEN vr.aid < 30 THEN '<30' 
        WHEN vr.aid > 30 and vr.aid <= 60 THEN '30-60'
        WHEN vr.aid > 60 and vr.aid <= 90 THEN '61-90'
    ELSE '90+'
    END as "Aging"
,CASE WHEN favi.port = -1 THEN NULL ELSE favi.port END AS port
,dp.name AS protocol
,dsvc.name AS service
,proofAsText(dv.description) AS vulnerability_description
,proofAsText(favi.proof) AS proof
,vr.references
,dv.exploits
,dv.malware_kits
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