with assets_vulns as (
SELECT
fasv.asset_id,
fasv.vulnerability_id,
baselineComparison (fasv.scan_id, current_scan) AS baseline,
s.baseline_scan,
s.current_scan
FROM
fact_asset_scan_vulnerability_instance fasv
JOIN (
SELECT
asset_id,
previousScan (asset_id) AS baseline_scan,
lastScan (asset_id) AS current_scan
FROM
dim_asset
) s ON s.asset_id = fasv.asset_id
AND (
fasv.scan_id = s.baseline_scan
OR fasv.scan_id = s.current_scan
)
GROUP BY
fasv.asset_id,
fasv.vulnerability_id,
s.baseline_scan,
s.current_scan
HAVING
(
baselineComparison (fasv.scan_id, current_scan) = 'Same'
)
OR (
baselineComparison (fasv.scan_id, current_scan) = 'New'
)
OR (
baselineComparison (fasv.scan_id, current_scan) = 'Old'
)
),
--END assets_vulns