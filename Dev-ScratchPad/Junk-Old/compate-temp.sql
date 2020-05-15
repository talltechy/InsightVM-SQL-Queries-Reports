WITH
    asset_vuln_age AS (
                        SELECT favi.asset_id
                                ,favi.vulnerability_id
                                ,date_part('days', (CURRENT_DATE - MIN(fasvi.date)) + INTERVAL '1 day') AS age
                        FROM fact_asset_scan_vulnerability_instance fasvi
                        JOIN fact_asset_vulnerability_instance favi ON fasvi.asset_id = favi.asset_id AND fasvi.vulnerability_id = favi.vulnerability_id
                        GROUP BY favi.asset_id
                                ,favi.vulnerability_id
    ),
    asset_metadata AS (
                        SELECT da.asset_id
                                ,da.ip_address
                                -- UPPER wraps the Regex and formats as uppercase
                                -- regexp_replace takes the hostname and removes all the DNS extras such as .exampledomain.tld and leaves only  regular asset names
                                ,UPPER(regexp_replace(da.host_name, '([\.][\w\.]+)', '', 'g')) AS hostname
                                -- This is an aggregate of all sites this asset belongs to, dont be surprised if you see more than what you filtered on via the console
                                ,da.sites
                        FROM dim_asset da
    )
SELECT vfa.asset_id
    -- Reference of the all sites aggregate from asset metadata
    ,am.sites AS "All Sites"
    ,am.ip_address
    ,am.hostname
    -- This calls the already formatted hostname from asset_metadata and runs a CASE statement to replace blank values with the word blank for formatting/sorting purposes
    ,CASE
        WHEN am.hostname = ' ' THEN vfa.asset_id::TEXT
        WHEN am.hostname IS NULL THEN vfa.asset_id::TEXT
        WHEN am.hostname IS NOT NULL THEN am.hostname
        ELSE vfa.asset_id::TEXT
        END as "Hostname Replace Blank"
    ,vfa.vulnerability_title
    -- Preformated severity
    ,vfa.severity
    -- Legible riskscore
    ,vfa.risk
    ,vfa.exploits
    ,vfa.malware_kits
    ,vfa.age AS "Age-in-Days"
    ,CASE
        WHEN vfa.age < 30 THEN '<30'
        WHEN vfa.age > 30 and vfa.age <= 60 THEN '30-60'
        WHEN vfa.age > 60 and vfa.age <= 90 THEN '61-90'
        ELSE '90+'
        END as "Aging"
    FROM (
            -- List the age of vuln findings in scope, along with their title, site/asset information, and instance count
            SELECT avd.asset_id
                    ,dv.title AS vulnerability_title
                    -- Preformated severity
                    ,dv.severity
                    -- This makes the risk score legible and gets rid of extra decimal places
                    ,round(dv.riskscore::numeric, 0) AS risk
                    ,dv.exploits
                    ,dv.malware_kits
                    ,avd.age
            FROM (
                    SELECT favf.asset_id
                            ,favf.vulnerability_id
                            ,ava.age
                    FROM asset_vuln_age ava
                    JOIN fact_asset_vulnerability_finding favf ON favf.asset_id = ava.asset_id AND favf.vulnerability_id = ava.vulnerability_id
                    GROUP BY favf.asset_id
                            ,favf.vulnerability_id
                            ,ava.age
            ) avd
            JOIN dim_vulnerability dv ON dv.vulnerability_id = avd.vulnerability_id
    ) vfa
    JOIN asset_metadata am ON vfa.asset_id = am.asset_id
-- Note there is no WHERE clause on purpose, you have to filter assets via the InsightVM console SQL report - You select an Asset, Site or Asset Group
ORDER BY asset_id
        ,vulnerability_title