WITH
    vuln_references AS (
        SELECT dv.vulnerability_id
        ,array_to_string(array_agg(reference), ', ') AS references
        ,fava.age_in_days AS aid
        ,dv.severity AS severity
        ,to_char(round(dv.riskscore::numeric,0),'999G999G999') AS vulnerability_risk
        FROM dim_vulnerability dv
            JOIN dim_vulnerability_reference USING (vulnerability_id)
            LEFT OUTER JOIN fact_asset_vulnerability_age fava ON fava.vulnerability_id = dv.vulnerability_id
        GROUP BY dv.vulnerability_id, dv.severity, dv.riskscore, fava.age_in_days
    ),
    dfa_assets AS (
        SELECT da.asset_id
        ,to_char(round(fa.riskscore::numeric,0),'999G999G999') AS asset_risk
        ,fa.critical_vulnerabilities AS total_asset_critical
        ,fa.severe_vulnerabilities AS total_asset_severe
        ,fa.moderate_vulnerabilities AS total_asset_moderate
        ,fa.vulnerabilities AS total_asset_vulnerabilities
        FROM dim_asset da
            JOIN fact_asset fa USING (asset_id)
        GROUP BY da.asset_id, fa.riskscore, fa.critical_vulnerabilities, fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.vulnerabilities
    ),
    custom_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS custom_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'CUSTOM'
        GROUP BY asset_id
    ),
    location_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS location_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'LOCATION'
        GROUP BY asset_id
    ),
    owner_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS owner_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'OWNER'
        GROUP BY asset_id
    ),
    criticality_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS criticality_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'CRITICALITY'
        GROUP BY asset_id
    )
--begin SELECT
SELECT da.ip_address AS "IP"
,da.host_name AS "Hostname"
,da.mac_address AS "MAC"
,dfa.asset_risk AS "Total Asset Risk"
,dfa.total_asset_moderate AS "Total Asset Moderate"
,dfa.total_asset_severe AS "Total Asset Severe"
,dfa.total_asset_critical AS "Total Asset Critical"
,dfa.total_asset_vulnerabilities AS "Total Asset Vulnerabilities"
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
,vr.vulnerability_risk AS "Vulnerability Risk"
,   CASE WHEN favi.port = -1 THEN NULL ELSE favi.port
    END AS "PORT"
,dp.name AS "Protocol"
,dsvc.name AS "Service"
,proofAsText(dv.description) AS "Vulnerability Description"
,proofAsText(favi.proof) AS "Proof"
,vr.references AS "References"
,dv.exploits AS "Exploits"
,dv.malware_kits AS "Malware Kits"
,ct.custom_tags AS "Custom Tags"
,lt.location_tags AS "Location Tags"
,ot.owner_tags AS "Owner Tags"
,crt.criticality_tags AS "Criticality Tags"
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
    JOIN dfa_assets dfa USING (asset_id)
    LEFT OUTER JOIN custom_tags ct USING (asset_id)
    LEFT OUTER JOIN location_tags lt USING (asset_id)
    LEFT OUTER JOIN owner_tags ot USING (asset_id)
    LEFT OUTER JOIN criticality_tags crt USING (asset_id)
--end FROM/JOIN
ORDER BY ds.name, da.ip_address