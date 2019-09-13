SELECT dss.site_id AS "Site ID", da.host_name, da.ip_address, dos.description AS "Operating System", 
fa.scan_started AS "Last Scan Date", ds.name AS "Software Name", ds.version AS "Software Version"
FROM dim_asset da
JOIN dim_operating_system dos ON dos.operating_system_id = da.operating_system_id
JOIN fact_asset fa ON fa.asset_id = da.asset_id
JOIN dim_asset_software das ON das.asset_id = da.asset_id
JOIN dim_software ds ON ds.software_id = das.software_id
JOIN dim_scan ds2 ON ds2.scan_id = fa.last_scan_id
JOIN dim_site_scan dss ON dss.scan_id = ds2.scan_id