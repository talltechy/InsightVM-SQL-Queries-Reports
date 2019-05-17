WITH
    vuln_references AS (
        SELECT dv.vulnerability_id
        ,array_to_string(array_agg(reference), ', ') AS references
        ,dv.severity AS severity
        ,dv.risk_score AS vulnerability_risk
        ,dv.nexpose_id
		,dv.title
        ,dv.description
        ,dv.exploits
        ,dv.malware_kits
        FROM dim_vulnerability dv
            LEFT JOIN dim_vulnerability_reference USING (vulnerability_id)
        GROUP BY dv.vulnerability_id, dv.severity, dv.risk_score, dv.nexpose_id, dv.title, dv.description, dv.exploits, dv.malware_kits
    ),
    dfa_assets AS (
        SELECT fa.asset_id
		,da.ip_address AS ip
		,da.mac_address AS mac
		,da.host_name AS hostname
		,da.os_description AS os
        ,fa.risk_score AS asset_risk
        ,fa.critical_vulnerabilities AS total_asset_critical
        ,fa.severe_vulnerabilities AS total_asset_severe
        ,fa.moderate_vulnerabilities AS total_asset_moderate
        ,fa.vulnerabilities AS total_asset_vulnerabilities
        ,daga.asset_group_id
        FROM fact_asset fa
            LEFT JOIN dim_asset da ON fa.asset_id = da.asset_id
            LEFT JOIN dim_asset_group_asset daga ON fa.asset_id = daga.asset_id
        GROUP BY fa.asset_id, da.ip_address, da.mac_address, da.host_name, da.os_description, fa.risk_score, fa.critical_vulnerabilities, fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.vulnerabilities, daga.asset_group_id
    )
--begin SELECT
SELECT dfa.asset_id
,dfa.ip
,dfa.mac
,regexp_replace(dfa.hostname, '([\.][\w\.]+)', '', 'g') AS "Hostname"
,dfa.os
,dfa.asset_group_id AS "Asset Group ID"
,round(dfa.asset_risk::numeric, 0) AS "Total Asset Risk"
,dfa.total_asset_moderate AS "Total Asset Moderate"
,dfa.total_asset_severe AS "Total Asset Severe"
,dfa.total_asset_critical AS "Total Asset Critical"
,dfa.total_asset_vulnerabilities AS "Total Asset Vulnerabilities"
,vr.title AS "Vulnerability Title"
,favi.date AS "Vulnerability Test Date"
,vr.severity AS "Severity"
,round(vr.vulnerability_risk::numeric, 0) AS "Vulnerability Risk"
,   CASE WHEN favi.port = -1 THEN NULL ELSE favi.port
    END AS "PORT"
,vr.description AS "Vulnerability Description"
,htmltotext(favi.proof) AS "Proof"
,favi.port AS "Port"
,vr.references AS "References"
,vr.exploits AS "Exploits"
,vr.malware_kits AS "Malware Kits"
--end SELECT
--begin FROM/JOIN
FROM fact_asset_vulnerability_instance favi
    JOIN vuln_references vr USING (vulnerability_id)
    JOIN dfa_assets dfa USING (asset_id)
--end FROM/JOIN
WHERE dfa.asset_group_id = 2
ORDER BY dfa.asset_id, dfa.ip, vr.severity DESC;
