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
--END new_vulns