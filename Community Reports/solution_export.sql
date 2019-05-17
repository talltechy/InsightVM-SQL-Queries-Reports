SELECT  
da.ip_address AS "ip_address",
da.host_name AS "asset_name",
dv.description AS "vuln_description", 
dv.title AS "vuln_title", 
dv.severity_score AS "severity_score", 
dv.severity AS "vuln_severity", 
dv.exploits AS "vuln_exploit_count", 
ds.fix AS "solution", 
ds.solution_type AS "solution_type", 
ds.estimate AS "remediation_time", 
ds.summary AS "solution_summary"
FROM fact_asset_scan_vulnerability_instance AS favi
JOIN dim_vulnerability dv ON dv.vulnerability_id = favi.vulnerability_id
JOIN dim_asset da ON da.asset_id = favi.asset_id
JOIN dim_asset_vulnerability_solution davs ON davs.asset_id = da.asset_id
JOIN dim_solution ds ON ds.solution_id = davs.solution_id
--WHERE dv.severity = 'Critical'