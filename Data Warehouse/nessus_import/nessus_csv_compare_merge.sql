/*
 * @Author: matt.wyen 
 * @Date: 2020-04-29 12:02:05 
 * @Last Modified by: matt.wyen
 * @Last Modified time: 2020-04-29 12:03:33
 * Version: 2.9.1
 * Moderate revision change, 2.5.1 caused issues with the sub-query, causing a 600MB CSV file to generate
 * Moderate revision change, 2.7.1 speed optimization with WHERE statements
 * Moderate revision change, 2.9.1 stripped out data for cve reports that wasnt needed
 */
WITH
        asset_metadata AS (
                        SELECT fa.asset_id
                                ,da.ip_address
                                -- UPPER wraps the Regex and formats as uppercase
                                -- regexp_replace takes the hostname and removes all the DNS extras such as .exampledomain.tld and leaves only  regular asset names
                                ,UPPER(regexp_replace(da.host_name, '([\.][\w\.]+)','','g')) AS hostname
                                -- This is an aggregate of all sites this asset belongs to, dont be surprised if you see more than what you filtered on via the console
                                ,round(fa.riskscore::numeric,0) AS total_asset_risk
                        FROM fact_asset fa 
                        LEFT JOIN dim_asset da ON fa.asset_id = da.asset_id
                        WHERE fa.asset_id IS NOT NULL
        ),
        -- Level of Grain: A vulnerability on an asset.
        --  * Fact Type: accumulating snapshot
        --  * Description: This fact table provides an accumulating snapshot for vulnerability age and occurrence information on an asset.
        --  * For every vulnerability to which an asset is currently vulnerable, there will be one fact record.
        --  * The record indicates when the vulnerability was first found, last found, and its current age.
        --  * The age is computed as the difference between the time the vulnerability was first discovered on the asset, and the current time.
        --  * If the vulnerability was temporarily remediated, but rediscovered, the age will be from the first discovery time.
        --  * If a vulnerability was found on a service, remediated and discovered on another service,
        --  * the age is still computed as the first time the vulnerability was found on any service on the asset.
        r7_aging AS (
                        SELECT asset_id
                                ,vulnerability_id
                                ,first_discovered
                                ,most_recently_discovered
                        FROM fact_asset_vulnerability_age
        )
SELECT vfa.asset_id
        -- Reference of the all sites aggregate from asset metadata
        ,am.ip_address
        -- This calls the already formatted hostname from asset_metadata and runs a CASE statement to replace blank values with the word blank for formatting/sorting purposes
        ,CASE
                WHEN am.hostname = ' ' THEN am.ip_address::TEXT
                WHEN am.hostname IS NULL THEN am.ip_address::TEXT
                WHEN am.hostname IS NOT NULL THEN am.hostname
                ELSE am.ip_address::TEXT
        END as "Hostname"
        ,vfa.nexpose_id
        -- Legible riskscore
        ,vfa.risk AS "Vulnerability: Risk"
        ,am.total_asset_risk AS "Asset: Risk"
        ,vfa.r7a_first_discovered AS "Asset: First Discovered"
        ,vfa.r7a_most_recently_discovered AS "Asset: Most Receently Discovered"
        ,vfa.vulnerability_date_published AS "Vulnerability: Published"
        ,vfa.vulnerability_date_added AS "Vulnerability: Added"
        ,vfa.vulnerability_date_modified AS "Vulnerability: Modified"
FROM ( -- List the age of vuln findings in scope, along with their title, site/asset information, and instance count
        SELECT avd.asset_id
                ,dv.nexpose_id
                -- This makes the risk score legible and gets rid of extra decimal places
                -- This specific riskscore is only for individual vulnerability risk NOT total asset risk
                ,round(dv.riskscore::numeric, 0) AS risk
                ,dv.date_published AS vulnerability_date_published
                ,dv.date_added AS vulnerability_date_added
                ,dv.date_modified AS vulnerability_date_modified
                ,avd.r7a_first_discovered
                ,avd.r7a_most_recently_discovered
        FROM (
                SELECT favf.asset_id
                        ,favf.vulnerability_id
                        ,r7a.first_discovered AS r7a_first_discovered
                        ,r7a.most_recently_discovered AS r7a_most_recently_discovered
                FROM fact_asset_vulnerability_finding favf
                LEFT JOIN r7_aging r7a ON favf.asset_id = r7a.asset_id AND favf.vulnerability_id = r7a.vulnerability_id
                WHERE favf.asset_id IS NOT NULL
        ) avd
        LEFT JOIN dim_vulnerability dv ON avd.vulnerability_id = dv.vulnerability_id
        WHERE avd.vulnerability_id IS NOT NULL
) vfa
LEFT JOIN asset_metadata am ON vfa.asset_id = am.asset_id
WHERE vfa.asset_id IS NOT NULL
AND vfa.nexpose_id in ('msft-cve-2019-0887')
ORDER BY asset_id
        ,nexpose_id