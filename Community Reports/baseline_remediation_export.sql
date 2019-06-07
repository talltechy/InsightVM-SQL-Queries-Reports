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
        scanasof (last_assessed_for _vulnerabilities, ('2018-05-01')) AS baseline_scan, --EXTRACT(MONTH FROM dim_asset and make it = 05)
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

  new_vulns as (
    SELECT
    av.asset_id,
    av.vulnerability_id,
    COUNT (av.vulnerability_id) AS new_vulns
    FROM
    assets_vulns AS av
    WHERE
    av.baseline = 'New'
    GROUP BY
    av.asset_id,
    av.vulnerability_id 
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
  ),

  remediated_vulns AS (
    SELECT
    av.asset_id,
    av.vulnerability_id,
    COUNT (av.vulnerability_id) AS remediated_vulns
    FROM
    assets_vulns AS av
    WHERE
    av.baseline = 'Old'
    GROUP BY
    av.asset_id,
    av.vulnerability_id
  )


SELECT
  'Remediated' as status,
  --(SELECT COUNT(*) FROM (SELECT DISTINCT dv1.vulnerability_id FROM dim_vulnerability)) AS instance_count,
  COUNT(dv1.vulnerability_id) AS instance_count,
  --(SELECT COUNT(*) FROM (SELECT DISTINCT dv1.vulnerability_id) AS unique_1) AS unique
  COUNT(DISTINCT dv1.vulnerability_id)AS unique
  FROM remediated_vulns rv
  --JOIN remediated_unique ru USING (vulnerability_id)
  JOIN dim_asset da1 ON da1.asset_id = rv.asset_id
  LEFT JOIN baseline_scan_date bsd ON bsd.asset_id = da1.asset_id
  LEFT JOIN current_scan_date csd ON csd.asset_id = da1.asset_id
  JOIN dim_vulnerability dv1 ON dv1.vulnerability_id = rv.vulnerability_id
  UNION ALL

SELECT
  'New' as status,
  --(SELECT COUNT(*) FROM (SELECT DISTINCT dv2.vulnerability_id FROM dim_vulnerability)) AS instance_count,
  COUNT(dv2.vulnerability_id) AS instance_count,
  --(SELECT COUNT(*) FROM (SELECT DISTINCT dv2.vulnerability_id) AS unique_1) AS unique
  COUNT(DISTINCT dv2.vulnerability_id)AS unique
  FROM new_vulns nv
  --JOIN new_unique nu USING (vulnerability_id)
  JOIN dim_asset as da2 ON da2.asset_id = nv.asset_id
  LEFT JOIN baseline_scan_date bsd ON bsd.asset_id = da2.asset_id
  LEFT JOIN current_scan_date csd ON csd.asset_id = da2.asset_id
  JOIN dim_vulnerability dv2 ON dv2.vulnerability_id = nv.vulnerability_id
  UNION ALL

SELECT
  'Same' as status,
  --(SELECT COUNT(*) FROM (SELECT DISTINCT dv2.vulnerability_id FROM dim_vulnerability)) AS instance_count,
  COUNT(dv3.vulnerability_id) AS instance_count,
  --(SELECT COUNT(*) FROM (SELECT DISTINCT dv3.vulnerability_id) AS unique_1) AS unique
  COUNT(DISTINCT dv3.vulnerability_id)AS unique
  FROM same_vulns sv
  --JOIN same_unique su USING (vulnerability_id)
  JOIN dim_asset da3 ON da3.asset_id = sv.asset_id
  LEFT JOIN baseline_scan_date bsd ON bsd.asset_id = da3.asset_id
  LEFT JOIN current_scan_date csd ON csd.asset_id = da3.asset_id
  JOIN dim_vulnerability dv3 ON dv3.vulnerability_id = sv.vulnerability_id
