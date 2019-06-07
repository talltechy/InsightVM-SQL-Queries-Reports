WITH
/*
    Created by Matt Wyen 4/15/19
    Last Commited 4/24/19
    https://help.rapid7.com/nexpose/en-us/warehouse/warehouse-schema.html
*/
/*
    custom_tags
    location_tags
    owner_tags
    criticality_tags
    remediations
    assets
*/
    custom_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS custom_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'CUSTOM'
        GROUP BY asset_id
    ),
    location_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS location_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'LOCATION'
        GROUP BY asset_id
    ),
    owner_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS owner_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'OWNER'
        GROUP BY asset_id
    ),
    criticality_tags AS (
        SELECT asset_id, CSV(tag_name ORDER BY tag_name) AS criticality_tags
        FROM dim_tag
            JOIN dim_tag_asset USING (tag_id)
        WHERE tag_type = 'CRITICALITY'
        GROUP BY asset_id
    ),
    remediations AS (
        SELECT DISTINCT fr.solution_id AS ultimate_soln_id, summary, fix, estimate, dshs.solution_id AS solution_id
        FROM fact_remediation(10,'riskscore DESC') fr
            JOIN dim_solution ds USING (solution_id)
            JOIN dim_solution_highest_supercedence dshs ON (fr.solution_id = dshs.superceding_solution_id AND ds.solution_id = dshs.superceding_solution_id)
    ),
    assets AS (
        SELECT DISTINCT asset_id, host_name, sites, ip_address, mac_address, last_assessed_for_vulnerabilities
        FROM dim_asset da
        GROUP BY asset_id, host_name, sites, ip_address, mac_address, last_assessed_for_vulnerabilities
    )
/* begin SELECT
Need to get away from DISTINCT statements as it might be cuasing wonky */
SELECT
    asset_id AS "Asset ID"
    ,host_name AS "Hostname"
    ,ip_address AS "IP"
    ,dos.description AS "Operating System"
    ,to_char(round(fa.riskscore::numeric,0),'999G999G999') AS "Asset Risk"
    ,csv(DISTINCT dv.title) AS "Vulnerability Title"
    ,dv.nexpose_id AS "ID / CVE"
    ,dv.description AS "Vulnerability Description"
    ,to_char(round(dv.riskscore::numeric,0),'999G999G999') AS "Vulnerability Risk"
    ,fav.age_in_days AS "Age in Days"
    ,CASE WHEN  fav.age_in_days < 30 THEN '<30' 
        WHEN fav.age_in_days > 30 and fav.age_in_days <= 60 THEN '30-60'
        WHEN fav.age_in_days > 60 and fav.age_in_days <= 90 THEN '61-90'
    ELSE '90+'
    END as "Vulnerability Aging"
    ,fav.first_discovered AS "First Discovered"
    ,fav.most_recently_discovered AS "Most Recently Discovered"
    ,last_assessed_for_vulnerabilities AS "Last Assessed"
    ,summary AS "Solution"
    ,fix as "Fix"
    ,fa.critical_vulnerabilities AS "Total Asset Critical"
    ,fa.severe_vulnerabilities AS "Total Asset Severe"
    ,fa.moderate_vulnerabilities AS "Total Asset Moderate"
    ,fa.vulnerabilities AS "Total Asset Vulnerabilities"
    ,sites AS "Sites"
    ,ct.custom_tags AS "Custom Tags"
    ,lt.location_tags AS "Location Tags"
    ,ot.owner_tags AS "Owner Tags"
    ,crt.criticality_tags AS "Criticality Tags"
/* end SELECT
begin FROM / JOIN */
FROM remediations r
    JOIN dim_asset_vulnerability_solution dvs USING (solution_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    JOIN assets USING (asset_id)
    JOIN dim_asset_operating_system USING (asset_id)
    JOIN dim_operating_system dos USING (operating_system_id)
    JOIN dim_tag_asset dta USING (asset_id)
    JOIN dim_tag dt ON dta.tag_id = dt.tag_id
    --fact_asset table is where total counts of vulnerabilities come from
    JOIN fact_asset fa USING (asset_id)
    --this is where the WHEN statement tags come from
    LEFT OUTER JOIN custom_tags ct USING (asset_id)
    LEFT OUTER JOIN location_tags lt USING (asset_id)
    LEFT OUTER JOIN owner_tags ot USING (asset_id)
    LEFT OUTER JOIN criticality_tags crt USING (asset_id)
    --this is where the age_in_days column is joined to calculate the CASE statement to display aging of vulnerabilities
    LEFT OUTER JOIN fact_asset_vulnerability_age fav USING (asset_id)
--end FROM / JOIN
--begin GROUP BY
GROUP BY dv.nexpose_id
,dv.title
,dv.description
,summary
,fix
,to_char(round(dv.riskscore::numeric,0),'999G999G999')
,fav.age
,fav.age_in_days
,fav.first_discovered
,fav.most_recently_discovered
,dv.severity
,to_char(round(fa.riskscore::numeric,0),'999G999G999')
,host_name, dos.description
,ip_address
,asset_id
,last_assessed_for_vulnerabilities
,fa.critical_vulnerabilities
,fa.severe_vulnerabilities
,fa.moderate_vulnerabilities
,fa.vulnerabilities
,sites
,ct.custom_tags
,lt.location_tags
,ot.owner_tags
,crt.criticality_tags
--end GROUP BY
--begin ORDER BY
ORDER BY "Hostname" DESC
