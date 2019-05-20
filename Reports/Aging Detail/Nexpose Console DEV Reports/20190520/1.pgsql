WITH new_vulnerability_findings AS (
SELECT asset_id, vulnerability_id, age_in_days, first_discovered
FROM fact_asset_vulnerability_age
)
SELECT asset_id, vulnerability_id, age_in_days, first_discovered
FROM new_vulnerability_findings
JOIN dim_vulnerability USING (vulnerability_id)
ORDER BY age_in_days DESC;