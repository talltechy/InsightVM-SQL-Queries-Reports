WITH
    vulnerability_raw AS (
                SELECT favi.asset_id
                ,favi.vulnerability_id AS vulnerability_id
                FROM fact_asset_vulnerability_instance favi
                GROUP BY favi.asset_id, favi.vulnerability_id
    ),
    asset_metadata AS (
                SELECT da.asset_id
                    ,da.ip_address AS ip_address
                    ,da.host_name
                FROM dim_asset da
                GROUP BY da.asset_id, da.ip_address, da.host_name
    )
SELECT vfa.asset_id
    ,am.ip_address
    ,regexp_replace(am.host_name, '([\.][\w\.]+)', '', 'g') AS "Hostname"
    ,vfa.vulnerability_id
    ,vfa.nexpose_id
    ,vfa.vulnerability_title
    ,vfa.severity
    ,vfa.risk
    ,vfa.exploits
    ,vfa.malware_kits
FROM (
        SELECT vraw.asset_id
            ,vraw.vulnerability_id
            ,dv.nexpose_id
            ,dv.title AS vulnerability_title
            ,dv.severity
            ,round(dv.riskscore::numeric, 0) AS risk
            ,dv.exploits
            ,dv.malware_kits
        FROM vulnerability_raw AS vraw
        JOIN dim_vulnerability dv ON dv.vulnerability_id = vraw.vulnerability_id
) vfa
JOIN asset_metadata am ON vfa.asset_id = am.asset_id
ORDER BY asset_id, vulnerability_title