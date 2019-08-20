WITH
    asset_metadata AS (
                        SELECT fa.asset_id
                                ,da.ip_address
                                -- UPPER wraps the Regex and formats as uppercase
                                -- regexp_replace takes the hostname and removes all the DNS extras such as .forchtgroup.us and leaves only FG00001111 regular asset names
                                ,UPPER(regexp_replace(da.host_name, '([\.][\w\.]+)', '', 'g')) AS hostname
                                ,da.mac_address
                                ,dos.description
                                ,fa.critical_vulnerabilities AS total_critical
                                ,fa.severe_vulnerabilities AS total_severe
                                ,fa.moderate_vulnerabilities AS total_moderate
                                ,fa.vulnerabilities AS total_vulnerabilities
                                ,da.last_assessed_for_vulnerabilities AS last_assessed
                                -- This is an aggregate of all sites this asset belongs to, dont be surprised if you see more than what you filtered on via the console
                                ,da.sites
                        FROM fact_asset fa
                        LEFT JOIN dim_asset da ON fa.asset_id = da.asset_id
                        LEFT JOIN dim_operating_system dos ON dos.operating_system_id = da.operating_system_id
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
    ,am.mac_address AS "MAC"
    ,am.description AS "Operating System"
    ,am.last_assessed AS "Last Assessed"
    ,am.total_critical AS "Critical"
    ,am.total_severe AS "Severe"
    ,am.total_moderate AS "Moderate"
    ,am.total_vulnerabilities AS "Total"
    ,vfa.vulnerability_title
    -- Preformated severity
    ,vfa.severity
    -- Legible riskscore
    ,vfa.risk
    ,vfa.exploits
    ,vfa.malware_kits
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
            FROM (
                    SELECT favf.asset_id
                            ,favf.vulnerability_id
                    FROM fact_asset_vulnerability_finding favf
                    GROUP BY favf.asset_id
                            ,favf.vulnerability_id
                            -- ,ava.age
            ) avd
            JOIN dim_vulnerability dv ON dv.vulnerability_id = avd.vulnerability_id
    ) vfa
    JOIN asset_metadata am ON vfa.asset_id = am.asset_id
-- Note there is no WHERE clause on purpose, you have to filter assets via the InsightVM console SQL report - You select an Asset, Site or Asset Group
ORDER BY asset_id
        ,vulnerability_title