WITH
    vulnerability_count AS (
        SELECT COUNT(*) FROM (SELECT DISTINCT vulnerability_id FROM fact_asset_vulnerability_instance) AS vcount;
    ),
    vulnerability_raw AS (
        SELECT vulnerability_id
        FROM fact_asset_vulnerability_instance
        GROUP BY favi.asset_id, favi.vulnerability_id
    )
SELECT 
FROM (
    -- List the age of vuln findings in scope, along with their title, site/asset information, and instance count
    SELECT avd.asset_id, dv.title AS vulnerability_title
        ,dv.severity_score AS severity
    FROM (
        SELECT favi.asset_id
            ,favi.vulnerability_id
            ,ava.age
        FROM asset_vuln_age ava
        JOIN fact_asset_vulnerability_finding favi ON favi.asset_id = ava.asset_id AND favi.vulnerability_id = ava.vulnerability_id
        GROUP BY favi.asset_id, favi.vulnerability_id, ava.age
    ) avd
    JOIN dim_vulnerability dv ON dv.vulnerability_id = avd.vulnerability_id
) vfa
JOIN asset_metadata am ON vfa.asset_id = am.asset_id
ORDER BY asset_id, vulnerability_title

SELECT DISTINCT ON (vulnerability_id)
FROM fact_asset_vulnerability_instance