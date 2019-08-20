WITH
    vulnerability_raw AS (
        -- This is where the FACT table lists all currently KNOWN vulnerabilities
                SELECT favi.asset_id
                ,favi.vulnerability_id AS vulnerability_id
                FROM fact_asset_vulnerability_instance favi
                GROUP BY favi.asset_id, favi.vulnerability_id
    ),
    asset_metadata AS (
        -- This is where the assets metadata comes form, such as hostname, ip etc.
                SELECT da.asset_id
                    ,da.ip_address
                    ,da.host_name
                FROM dim_asset da
                GROUP BY da.asset_id, da.ip_address, da.host_name
    )
SELECT vfa.asset_id
    ,am.ip_address
    -- This first grabs the hostname from dim_asset, runs a regex against it to remove any DNS junk like .forchtgroup.us
    -- Then it uses the UPPER command to make the entire hostname uppercase for easier sorting and comparing
    ,UPPER(regexp_replace(am.host_name, '([\.][\w\.]+)', '', 'g')) AS "Hostname"
    ,vfa.vulnerability_id
    ,vfa.nexpose_id
    ,vfa.vulnerability_title
    ,vfa.severity
    ,vfa.risk
    ,vfa.exploits
    ,vfa.malware_kits
FROM (
        --This is where vulnerability_raw (fact table for known vulnerabilities) and the dim_vulnerability (vulnerability metadata) are joined so that we know the details of the vulnerabilites
        SELECT vraw.asset_id
            ,vraw.vulnerability_id
            ,dv.nexpose_id
            ,dv.title AS vulnerability_title
            ,dv.severity
            -- This makes the risk score legible and gets rid of extra decimal places
            ,round(dv.riskscore::numeric, 0) AS risk
            ,dv.exploits
            ,dv.malware_kits
        FROM vulnerability_raw AS vraw
        JOIN dim_vulnerability dv ON dv.vulnerability_id = vraw.vulnerability_id
) vfa
JOIN asset_metadata am ON vfa.asset_id = am.asset_id
-- Note there is no WHERE clause on purpose, you have to filter assets via the InsightVM console SQL report - You select an Asset, Site or Asset Group
ORDER BY asset_id, vulnerability_title