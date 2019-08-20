WITH
    asset_vuln_age AS (
        SELECT favi.asset_id
            ,favi.vulnerability_id
            ,date_part('days', (CURRENT_DATE - MIN(fasvi.date)) + INTERVAL '1 day') AS age
        FROM fact_asset_scan_vulnerability_instance fasvi
        JOIN fact_asset_vulnerability_instance favi ON fasvi.asset_id = favi.asset_id AND fasvi.vulnerability_id = favi.vulnerability_id
        GROUP BY favi.asset_id, favi.vulnerability_id
    ),
    asset_metadata AS (
        SELECT da.asset_id
            ,da.ip_address AS ip_address
            ,da.host_name
            ,da.sites
        FROM dim_asset da
    )
SELECT vfa.asset_id
        ,am.sites AS "All Sites"
        ,am.ip_address
        ,regexp_replace(am.host_name, '([\.][\w\.]+)', '', 'g') AS "Hostname"
        ,vfa.vulnerability_title
        ,vfa.severity AS "RAW Severity"
        ,CASE
            WHEN vfa.severity = 0 THEN 'None/Moderate' 
            WHEN vfa.severity BETWEEN 1 and 3 THEN 'Moderate'
            WHEN vfa.severity BETWEEN 4 and 7 THEN 'Severe'
            WHEN vfa.severity BETWEEN 8 and 10 THEN 'Critical'
            ELSE '?'
            END as "Severity"
        ,vfa.vuln_count AS "Vulnerability Count"
        ,vfa.age AS "Vulnerability Age-in-Days"
        ,   CASE
                WHEN vfa.age < 30 THEN '<30' 
                WHEN vfa.age > 30 and vfa.age <= 60 THEN '30-60'
                WHEN vfa.age > 60 and vfa.age <= 90 THEN '61-90'
            ELSE '90+'
            END as "Aging"
FROM (
    -- List the age of vuln findings in scope, along with their title, site/asset information, and instance count
    SELECT avd.asset_id, dv.title AS vulnerability_title
        ,dv.severity_score AS severity
        ,avd.vuln_count
        ,avd.age
    FROM (
        SELECT favi.asset_id
            ,favi.vulnerability_id
            ,1 AS vuln_count
            ,ava.age
        FROM asset_vuln_age ava
        JOIN fact_asset_vulnerability_finding favi ON favi.asset_id = ava.asset_id AND favi.vulnerability_id = ava.vulnerability_id
        GROUP BY favi.asset_id, favi.vulnerability_id, ava.age
    ) avd
    JOIN dim_vulnerability dv ON dv.vulnerability_id = avd.vulnerability_id
) vfa
JOIN asset_metadata am ON vfa.asset_id = am.asset_id
ORDER BY asset_id, vulnerability_title