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
),
--END remediated_vulns