SELECT ds.name "Site", da.ip_address as "IP Address", da.host_name as "Host Name", dacs.aggregated_credential_status_description "Access Level"

FROM dim_asset da

JOIN fact_asset fa using (asset_id)

JOIN dim_site_asset dsa using (asset_id)

JOIN dim_site ds using (site_id)

JOIN dim_aggregated_credential_status dacs using (aggregated_credential_status_id)

GROUP BY ds.name, da.ip_address, da.host_name, dacs.aggregated_credential_status_description

ORDER BY da.ip_address DESC