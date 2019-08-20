SELECT
    csv(DISTINCT dv.title) AS "Vulnerability Title",
    dv.description AS "Vulnerability Description",
    to_char(round(dv.riskscore::numeric,0),'999G999G999') AS "Vulnerability Risk",
    fav.age AS "Age",
    fav.age_in_days AS "Age in Days",
    fav.first_discovered AS "First Discovered",
    fav.most_recently_discovered AS "Most Recently Discovered",
    dv.nexpose_id AS "ID / CVE",
    asset_id AS "Asset ID",
    host_name AS "Hostname",
    ip_address AS "IP",
    last_assessed_for_vulnerabilities AS "Last Assessed",
    to_char(round(fa.riskscore::numeric,0),'999G999G999') AS "Asset Risk",
    summary AS "Solution",
    dos.description AS "Operating System",
    fa.critical_vulnerabilities AS "Critical",
    fa.severe_vulnerabilities AS "Severe",
    fa.moderate_vulnerabilities AS "Moderate",
    fa.vulnerabilities AS "Total",
    sites AS "Sites",
    ct.custom_tags AS "Custom Tags",
    lt.location_tags AS "Location Tags",
    ot.owner_tags AS "Owner Tags",
    crt.criticality_tags AS "Criticality Tags",
    fix as "Fix"
FROM remediations r
    JOIN dim_asset_vulnerability_solution dvs USING (solution_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    JOIN assets USING (asset_id)
    JOIN dim_asset_operating_system USING (asset_id)
    JOIN dim_operating_system dos USING (operating_system_id)
    JOIN dim_tag_asset dta USING (asset_id)
    JOIN dim_tag dt ON dta.tag_id = dt.tag_id
    JOIN fact_asset fa USING (asset_id)
    LEFT OUTER JOIN custom_tags ct USING (asset_id)
    LEFT OUTER JOIN location_tags lt USING (asset_id)
    LEFT OUTER JOIN owner_tags ot USING (asset_id)
    LEFT OUTER JOIN criticality_tags crt USING (asset_id)
    LEFT OUTER JOIN fact_asset_vulnerability_age fav USING (asset_id)
GROUP BY dv.nexpose_id, dv.title, dv.description, summary, fix, to_char(round(dv.riskscore::numeric,0),'999G999G999'), fav.age, fav.age_in_days, fav.first_discovered, fav.most_recently_discovered, dv.severity, to_char(round(fa.riskscore::numeric,0),'999G999G999'), host_name, dos.description, ip_address, asset_id, last_assessed_for_vulnerabilities, fa.critical_vulnerabilities, fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.vulnerabilities, sites, ct.custom_tags, lt.location_tags, ot.owner_tags, crt.criticality_tags
ORDER BY "Hostname" DESC