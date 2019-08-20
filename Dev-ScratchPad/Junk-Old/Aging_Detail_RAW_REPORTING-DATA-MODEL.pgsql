WITH
-- Needs to be tested, probably broken
-- Created by Matt Wyen
    vuln_references AS (
        SELECT dv.vulnerability_id
        ,dv.severity AS severity
        ,dv.risk_score AS vulnerability_risk
        ,dv.nexpose_id AS nexpose_id
		,dv.title AS title
        ,dv.description AS description
        ,dv.exploits
        ,dv.malware_kits
        FROM dim_vulnerability dv
        GROUP BY dv.vulnerability_id, dv.severity, dv.risk_score, dv.nexpose_id, dv.title, dv.description, dv.exploits, dv.malware_kits
    ),
    dfa_assets AS (
        SELECT da.asset_id
        ,da.ip_address AS ip_address
        ,da.mac_address AS mac_address
        ,da.host_name AS host_name
        ,fa.risk_score AS asset_risk
        ,fa.critical_vulnerabilities AS total_asset_critical
        ,fa.severe_vulnerabilities AS total_asset_severe
        ,fa.moderate_vulnerabilities AS total_asset_moderate
        ,fa.vulnerabilities AS total_asset_vulnerabilities
        ,daga.asset_group_id AS asset_group_id
        FROM fact_asset fa
            LEFT JOIN dim_asset da ON da.asset_id = fa.asset_id
            LEFT JOIN dim_asset_group_asset daga ON da.asset_id = daga.asset_id
        GROUP BY da.asset_id, da.ip_address,da.mac_address,da.host_name, fa.risk_score, fa.critical_vulnerabilities, fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.vulnerabilities, daga.asset_group_id
    )
--begin SELECT
SELECT dfa.ip_address AS "IP"
,dfa.mac_address AS "MAC"
,dfa.host_name AS "Hostname"
,dfa.asset_group_id AS "Asset Group ID"
,to_char(round(dfa.asset_risk::numeric,0),'999G999G999') AS "Total Asset Risk"
,dfa.total_asset_moderate AS "Total Asset Moderate"
,dfa.total_asset_severe AS "Total Asset Severe"
,dfa.total_asset_critical AS "Total Asset Critical"
,dfa.total_asset_vulnerabilities AS "Total Asset Vulnerabilities"
,vr.nexpose_id AS "Nexpose ID"
,favi.status AS "Vulnerability Status"
,vr.title AS "Vulnerability"
,favi.date AS "Discovered Date"
,vr.severity AS "Vulnerability Severity"
,to_char(round(vr.vulnerability_risk::numeric,0),'999G999G999') AS "Vulnerability Risk"
,   CASE WHEN favi.port = -1 THEN NULL ELSE favi.port
    END AS "PORT"
,favi.protocol AS "Protocol"
,vr.exploits AS "Exploits"
,vr.malware_kits AS "Malware Kits"
--,vr.description AS "Vulnerability Description"
--,favi.proof AS "Proof"
--end SELECT
--begin FROM/JOIN
FROM fact_asset_vulnerability_instance favi
    JOIN vuln_references vr ON vr.vulnerability_id = favi.vulnerability_id
    JOIN dfa_assets dfa ON dfa.asset_id = favi.asset_id
--end FROM/JOIN
WHERE dfa.asset_group_id = 2 AND vr.severity = 'Critical'
ORDER BY dfa.host_name, dfa.ip_address