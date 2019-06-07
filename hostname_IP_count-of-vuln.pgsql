SELECT da.host_name AS Hostname, da.ip_address AS IP, fa.critical_vulnerabilities AS Critical, fa.severe_vulnerabilities AS Severe, fa.moderate_vulnerabilities AS Moderate

FROM dim_asset da

    JOIN fact_asset fa USING (asset_id)

ORDER BY da.host_name ASC