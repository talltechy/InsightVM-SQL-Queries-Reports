SELECT da.ip_address AS "IP", da.host_name AS "Hostname", dos.description as "OS", da.last_assessed_for_vulnerabilities AS "Last Assessed", fa.risk_score AS risk, fa.critical_vulnerabilities AS "Critical", fa.severe_vulnerabilities AS "Severe", fa.moderate_vulnerabilities AS "Moderate"

/* Required to output fa.risk_score */
/* (CASE risk WHEN 0 THEN NULL ELSE risk END) / (CASE assets WHEN 0 THEN NULL ELSE assets END) AS "RiskPerAsset" */
CAST(fa.risk_score as decimal(10,0)) as risk,

/* Created by Matt Wyen 4/15/19
   Last Commited at 2:44 PM EST
   https://help.rapid7.com/nexpose/en-us/warehouse/warehouse-schema.html
   fact_asset table is where counts of vulnerabilities come from */
FROM fact_asset AS fa

   JOIN dim_asset da ON da.asset_id = fa.asset_id

   JOIN dim_operating_system as dos

      ON da.operating_system_id = dos.operating_system_id

   JOIN dim_site_asset as dsa

      ON fa.asset_id = dsa.asset_id

/* I'm not sure if dim_site is required at this point - possible remove in DEV to test speed of report generation */
   JOIN dim_site as dsite

      ON dsa.site_id = dsite.site_id

/* Add all SELECT arguments here - this adds the column to the output */
GROUP BY da.host_name, da.ip_address, dos.description, da.last_assessed_for_vulnerabilities, fa.critical_vulnerabilities, fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.risk_score

ORDER BY "Hostname", "IP"