WITH
  assets_vulns as (
    SELECT
    fasv.asset_id,
    fasv.vulnerability_id,
    baselineComparison (fasv.scan_id, current_scan) AS baseline,
    s.baseline_scan,
    s.current_scan
    FROM
    fact_asset_scan_vulnerability_instance fasv
    JOIN 
      (SELECT  
        asset_id, 
        scanasofdate (asset_id, ('2018-05-17')) AS baseline_scan, 
        lastScan (asset_id) AS current_scan 
        FROM dim_asset
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
    (baselineComparison (fasv.scan_id, current_scan) = 'Same')
    OR 
    (baselineComparison (fasv.scan_id, current_scan) = 'New')
    OR 
    (baselineComparison (fasv.scan_id, current_scan) = 'Old')
  ),

  baseline_scan_date as (

    SELECT
    av.asset_id,
    finished
    FROM assets_vulns av
    LEFT JOIN dim_scan ds ON ds.scan_id = av.baseline_scan
    GROUP BY av.asset_id, finished
  ),

  current_scan_date as (
    SELECT
    av.asset_id,
    finished
    FROM assets_vulns av
    LEFT JOIN dim_scan ds ON ds.scan_id = av.current_scan
    GROUP BY av.asset_id, finished
  ),

  same_vulns as (
    SELECT
    av.asset_id,
    av.vulnerability_id,
    COUNT (av.vulnerability_id) AS same_vulns
    FROM
    assets_vulns AS av
    WHERE
    av.baseline = 'Same'
    GROUP BY
    av.asset_id,
    av.vulnerability_id
  )

SELECT
  'unchanged' as status,
  dv3.vulnerability_id AS "id",
  da3.ip_address AS "ip_address",
  da3.host_name AS "asset_name",
  dv3.description AS "vuln_description", 
  dv3.title AS "vuln_title",
  ds.fix AS "solution", 
  ds.solution_type AS "solution_type", 
  ds.estimate AS "remediation_time", 
  ds.summary AS "solution_summary"
  FROM same_vulns sv
  JOIN dim_asset da3 ON da3.asset_id = sv.asset_id
  LEFT JOIN baseline_scan_date bsd ON bsd.asset_id = da3.asset_id
  LEFT JOIN current_scan_date csd ON csd.asset_id = da3.asset_id
  JOIN dim_vulnerability dv3 ON dv3.vulnerability_id = sv.vulnerability_id
  JOIN dim_asset_vulnerability_solution davs ON davs.asset_id = da3.asset_id
  JOIN dim_solution ds ON ds.solution_id = davs.solution_id
