current_scan_date as (
SELECT
av.asset_id,
finished
FROM assets_vulns av
LEFT JOIN dim_scan ds ON ds.scan_id = av.current_scan
GROUP BY av.asset_id, finished
),
--END current_scan_date