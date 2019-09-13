WITH
/* Created by Matt Wyen
   https://help.rapid7.com/nexpose/en-us/warehouse/warehouse-schema.html
   fact_asset table is where counts of vulnerabilities come from */
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
    )

Select DISTINCT da.ip_address AS "IP", da.host_name AS "Hostname", da.mac_address AS "MAC", dos.description AS "Operating System", da.last_assessed_for_vulnerabilities AS "Last Assessed", fa.critical_vulnerabilities AS "Critical", fa.severe_vulnerabilities AS "Severe", fa.moderate_vulnerabilities AS "Moderate", fa.vulnerabilities AS "Total", to_char(round(fa.riskscore::numeric,0),'999G999G999') AS "Risk", ct.custom_tags AS "Custom Tags", lt.location_tags AS "Location Tags", ot.owner_tags AS "Owner Tags", crt.criticality_tags AS "Criticality Tags"

FROM dim_asset AS da
    JOIN dim_operating_system dos USING (operating_system_id)
    JOIN dim_tag_asset AS dta USING (asset_id)
    JOIN dim_tag AS dt ON dta.tag_id = dt.tag_id
    JOIN fact_asset as fa USING (asset_id)
    LEFT OUTER JOIN custom_tags ct USING (asset_id)
    LEFT OUTER JOIN location_tags lt USING (asset_id)
    LEFT OUTER JOIN owner_tags ot USING (asset_id)
    LEFT OUTER JOIN criticality_tags crt USING (asset_id)

/* Add all SELECT arguments here - this adds the column to the output */
GROUP BY da.ip_address, da.host_name, da.mac_address, dos.description, da.last_assessed_for_vulnerabilities, fa.critical_vulnerabilities, fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.vulnerabilities, to_char(round(fa.riskscore::numeric,0),'999G999G999'), ct.custom_tags, lt.location_tags, ot.owner_tags, crt.criticality_tags

ORDER BY "Hostname", "IP"