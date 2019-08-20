SELECT dsite.name "Site", da.ip_address as "IP Address", da.host_name as "Host Name", ds.name as "Service", dp.description as "Protocol", dcs.credential_status_description "Access Level"

FROM dim_asset da

JOIN fact_asset_scan_service fass using (asset_id)

JOIN fact_asset fa using (asset_id)

JOIN dim_site_asset dsa using (asset_id)

JOIN dim_site dsite using (site_id)

JOIN dim_service ds using (service_id)

JOIN dim_protocol dp using (protocol_id)

JOIN dim_credential_status dcs using (credential_status_id)

GROUP BY dsite.name, da.ip_address, da.host_name, ds.name, dp.description, dcs.credential_status_description

ORDER BY da.ip_address DESC