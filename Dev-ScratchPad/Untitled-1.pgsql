WITH assets_vulns AS (
SELECT
fasv.asset_id,
fasv.vulnerability_id,
FROM
fact_asset_scan_vulnerability_instance fasv
JOIN (
SELECT
asset_id,
FROM
dim_asset
) s ON s.asset_id = fasv.asset_id
AND (
fasv.scan_id = s.current_scan
)
GROUP BY
fasv.asset_id,
fasv.vulnerability_id,
--END assets_vulns
new_vulns AS (
SELECT
av.asset_id,
av.vulnerability_id,
COUNT (av.vulnerability_id) AS new_vulns
FROM
assets_vulns AS av
GROUP BY
av.asset_id,
av.vulnerability_id
),
--END new_vulns
JOIN dim_asset AS da2 ON da2.asset_id = nv.asset_id
JOIN dim_vulnerability dv2 ON dv2.vulnerability_id = nv.vulnerability_id
LEFT JOIN vuln_exploit_count vec ON vec.vulnerability_id = nv.vulnerability_id
ORDER BY status DESC, ip_address, hostname, title