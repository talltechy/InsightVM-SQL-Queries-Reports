WITH
    vulnerability_raw AS (
        SELECT
            favi.asset_id,
            favi.vulnerability_id
        FROM fact_asset_vulnerability_instance favi
    ),
    asset_metadata AS (
        SELECT
            da.asset_id,
            da.ip_address,
            da.host_name
        FROM dim_asset da
    )
SELECT
    vfa.asset_id,
    am.ip_address,
    UPPER(regexp_replace(am.host_name, '([\.][\w\.]+)', '', 'g')) AS hostname,
    vfa.vulnerability_id,
    vfa.nexpose_id,
    vfa.vulnerability_title,
    vfa.severity,
    round(vfa.riskscore::numeric, 0) AS risk,
    vfa.exploits,
    vfa.malware_kits
FROM (
    SELECT
        vraw.asset_id,
        vraw.vulnerability_id,
        dv.nexpose_id,
        dv.title AS vulnerability_title,
        dv.severity,
        dv.riskscore,
        dv.exploits,
        dv.malware_kits
    FROM vulnerability_raw vraw
    JOIN dim_vulnerability dv ON dv.vulnerability_id = vraw.vulnerability_id
) vfa
JOIN asset_metadata am ON vfa.asset_id = am.asset_id
WHERE 1=1 -- No filtering is being done in this query
ORDER BY vfa.asset_id, vfa.vulnerability_title;
