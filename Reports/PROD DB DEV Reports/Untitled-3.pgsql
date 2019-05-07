WITH
    vuln_references AS (
        SELECT dv.vulnerability_id
        ,dv.severity
        ,dv.riskscore AS vulnerability_risk
        ,dv.nexpose_id
		,dv.title
        ,dv.description
        ,dv.exploits
        ,dv.malware_kits
        FROM dim_vulnerability dv
        GROUP BY dv.vulnerability_id, dv.severity, dv.riskscore, dv.nexpose_id, dv.title, dv.description, dv.exploits, dv.malware_kits
    ),
    dfa_assets AS (
        SELECT DISTINCT ON (fa.asset_id) fa.asset_id
        ,fa.riskscore AS asset_risk
        ,fa.critical_vulnerabilities AS total_asset_critical
        ,fa.severe_vulnerabilities AS total_asset_severe
        ,fa.moderate_vulnerabilities AS total_asset_moderate
        ,fa.vulnerabilities AS total_asset_vulnerabilities
        ,daga.asset_group_id
    	,dag.name AS asset_group_name
        ,da.ip_address AS IP
        ,da.mac_address AS MAC
        ,da.host_name AS Hostname

        FROM fact_asset fa
            LEFT JOIN dim_asset da ON da.asset_id = fa.asset_id
            LEFT JOIN dim_asset_group_asset daga ON fa.asset_id = daga.asset_id
			LEFT JOIN dim_asset_group dag ON daga.asset_group_id = dag.asset_group_id
        GROUP BY fa.asset_id, da.ip_address,da.mac_address,da.host_name, fa.riskscore, fa.critical_vulnerabilities, fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.vulnerabilities, daga.asset_group_id, dag.name
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
SELECT DISTINCT ON (favi.asset_id, favi.vulnerability_id, dfa.asset_group_id) favi.asset_id
,dfa.IP
,dfa.MAC
,regexp_replace(dfa.Hostname, '([\.][\w\.]+)', '', 'g') AS "Hostname"
,dfa.asset_group_id AS "Asset Group ID"
,dfa.asset_group_name AS "Asset Group Name"
,round(dfa.asset_risk::numeric, 0) AS "Total Asset Risk"
,dfa.total_asset_moderate AS "Total Asset Moderate"
,dfa.total_asset_severe AS "Total Asset Severe"
,dfa.total_asset_critical AS "Total Asset Critical"
,dfa.total_asset_vulnerabilities AS "Total Asset Vulnerabilities"
,favi.vulnerability_id AS "Vulnerability ID"
,vr.nexpose_id AS "Nexpose ID"
,vr.title AS "Vulnerability Title"
,round(fava.age_in_days::numeric, 0) AS "fava-Age In Days"
,   (CASE
		WHEN round(fava.age_in_days::numeric, 0) < 30 THEN '<30' 
        WHEN round(fava.age_in_days::numeric, 0) > 30 and round(fava.age_in_days::numeric, 0) <= 60 THEN '30-60'
        WHEN round(fava.age_in_days::numeric, 0) > 60 and round(fava.age_in_days::numeric, 0) <= 90 THEN '61-90'
    ELSE '90+'
    END) favaAging
,round(age(favi.date, 'days')::numeric, 0) AS "favi-Age In Days"
,   (CASE
		WHEN round(age(favi.date, 'days')::numeric, 0) < 30 THEN '<30' 
        WHEN round(age(favi.date, 'days')::numeric, 0) > 30 and round(age(favi.date, 'days')::numeric, 0) <= 60 THEN '30-60'
        WHEN round(age(favi.date, 'days')::numeric, 0) > 60 and round(age(favi.date, 'days')::numeric, 0) <= 90 THEN '61-90'
    ELSE '90+'
    END) favidate
,fava.first_discovered AS "fava-first_discovered"
,fava.most_recently_discovered AS "fava-most_recently_discovered"
,vr.severity AS "Vulnerability Severity"
,round(vr.vulnerability_risk::numeric, 0) AS "Vulnerability Risk"
,   CASE WHEN favi.protocol_id = -1 THEN NULL ELSE favi.protocol_id
    END AS "Protocol"
,   CASE WHEN favi.port = -1 THEN NULL ELSE favi.port
    END AS "PORT"
,vr.exploits AS "Exploits"
,vr.malware_kits AS "Malware Kits"
,htmltotext(vr.description) AS "Vulnerability Description"
,htmltotext(favi.proof) AS "Proof"
,ct.custom_tags AS "Custom Tags"
,lt.location_tags AS "Location Tags"
,ot.owner_tags AS "Owner Tags"
,crt.criticality_tags AS "Criticality Tags"
--end SELECT
--begin FROM/JOIN
FROM fact_asset_vulnerability_instance favi
    LEFT JOIN fact_asset_vulnerability_age fava ON favi.vulnerability_id = fava.vulnerability_id AND favi.asset_id = fava.asset_id
    LEFT JOIN vuln_references vr ON vr.vulnerability_id = favi.vulnerability_id
    LEFT JOIN dfa_assets dfa ON favi.asset_id = dfa.asset_id
    LEFT OUTER JOIN custom_tags ct ON favi.asset_id = ct.asset_id
    LEFT OUTER JOIN location_tags lt ON favi.asset_id = lt.asset_id
    LEFT OUTER JOIN owner_tags ot ON favi.asset_id = ot.asset_id
    LEFT OUTER JOIN criticality_tags crt ON favi.asset_id = crt.asset_id
WHERE dfa.asset_group_id = 2
--end FROM/JOIN
ORDER BY favi.asset_id, favi.vulnerability_id, dfa.asset_group_id, dfa.Hostname, dfa.IP, vr.nexpose_id