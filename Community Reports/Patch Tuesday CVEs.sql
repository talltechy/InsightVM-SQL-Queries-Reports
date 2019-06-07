SELECT ds.name AS site, da.ip_address, da.host_name, dv.title AS vulnerability_title, dos.description AS operating_system, dos.cpe

FROM fact_asset_vulnerability_finding favf

JOIN dim_asset da USING (asset_id)

JOIN dim_operating_system dos USING (operating_system_id)

JOIN dim_vulnerability dv USING (vulnerability_id)

JOIN dim_site_asset dsa USING (asset_id)

JOIN dim_site ds USING (site_id)

WHERE dv.title LIKE 'Microsoft CVE%'

AND dv.date_published BETWEEN '2018-10-01 00:00:00' AND '2018-10-30 11:59:59'

ORDER BY da.ip_address ASC, dv.title ASC