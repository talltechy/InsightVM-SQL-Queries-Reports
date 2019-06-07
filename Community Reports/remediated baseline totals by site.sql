WITH

  site_last_scan AS (

   SELECT site_id,
   (SELECT scan_id AS last_scan, finished
    FROM dim_site_scan
    JOIN dim_scan USING (scan_id)
    WHERE site_id = ds.site_id
    ORDER BY finished DESC
    LIMIT 1) AS last_scan
    FROM dim_site ds
  ),

  site_baseline_scan AS (

   SELECT site_id, finished, 
    (SELECT finished AS last_scan
      FROM dim_site_scan
      JOIN dim_scan USING (scan_id)
      WHERE site_id = ds.site_id AND finished LIKE '2018-05-16'
      ORDER BY finished DESC
      LIMIT 1) AS baseline_scan
    FROM dim_site ds
  ),

last_vuln_count AS (SELECT sls.site_id, count(fasv.vulnerability_id) AS last_vuln_count

FROM site_last_scan AS sls
LEFT OUTER JOIN fact_asset_scan_vulnerability_finding AS fasv ON sls.last_scan = fasv.scan_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = fasv.vulnerability_id
GROUP BY sls.site_id),


previous_vuln_count AS (SELECT sps.site_id, count(fasv.vulnerability_id) AS previous_vuln_count

FROM site_previous_scan AS sps
LEFT OUTER JOIN fact_asset_scan_vulnerability_finding AS fasv ON sps.previous_scan = fasv.scan_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = fasv.vulnerability_id
GROUP BY sps.site_id)


SELECT 
ds.site_id, 
ds.name, 
fs.assets AS "Total Assets",
ds2.started AS "Last Scan Date", 
fs.vulnerabilities AS "Total Current Vulnerabilities Discovered(last_scan)",
lvc.last_vuln_count AS "Total New Vulnerabilities Discovered(last_scan)",
pvc.previous_vuln_count AS "Total Unaddressed Vulnerabilities",

FROM dim_site ds
JOIN fact_site fs ON fs.site_id = ds.site_id
JOIN dim_scan ds2 ON ds2.scan_id = ds.last_scan_id
LEFT OUTER JOIN last_vuln_count AS lvc ON lvc.site_id = ds.site_id
LEFT OUTER JOIN previous_vuln_count AS pvc ON pvc.site_id = lvc.site_id