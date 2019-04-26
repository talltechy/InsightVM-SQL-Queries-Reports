WITH
vuln_urls AS (
    SELECT vulnerability_id, array_to_string(array_agg(reference), ' , ') AS references
    FROM dim_vulnerability_reference 
    GROUP BY vulnerability_id),
category AS (
	SELECT vulnerability_id, category_name, category_id  
	FROM dim_vulnerability_category
	GROUP BY vulnerability_id, category_name, category_id),
hostname AS (
	SELECT asset_id, host_name AS hostname
	FROM dim_asset_host_name
	GROUP BY asset_id, host_name)

SELECT 
da.ip_address, 
da.host_name as asset,
h.hostname as hostname, 
--dos.description as operating_system,
dv.nexpose_id as vuln_id,
dv.title as vuln_title, 
round(dv.riskscore::numeric,0) as vuln_riskscore, 
proofastext(dv.description) as vuln_description,
--s.solution as solution,
c.category_name as category,

--parent_category = 
CASE
WHEN c.category_id in (5,6,10,14,22,25,29,37,38,40,41,47,49,52,53,56,60,61,63,66,67,68,69,71,72,73,74,77,78,84,85,86,90,92,93,94,95,96,97,99,100,101,103,105,106,107,109,110,111,113,118,119,120,122,124,125,129,130,131,134,136,137,138,139,140,144,145,146,149,150,151,152,155,156,157,158,159,160,161,163,167,168,169,171,172,173,174,176,177,178,179,181,182,183,184,185,186,187,189,191,192,193,194,197,200,202,203,204,206,209,211,212,213,214,215,217,218,219,220,221,226,227,228,229,230,231,235,236,239,240,241,242)
 THEN '3rd Party'
WHEN c.category_id in (2,13,21,42,64,70,76,83,87,135,148,164,180)
 THEN 'Exploit Method'
WHEN c.category_id in (3,9,11,16,18,20,23,24,27,28,31,32,33,36,39,43,44,50,51,54,55,59,79,80,81,82,88,89,91,102,108,116,121,123,132,133,142,143,153,154,166,170,188,190,195,196,198,199,201,207,208,216,222,224,232,233,234,237,238,243,244)
 THEN 'OS'
WHEN c.category_id in (17,26,128)
 THEN 'Exploit Result'
WHEN c.category_id in (1,8,15,34,35,48,58,112,147,162)
 THEN 'OS & 3rd Party'
WHEN c.category_id in (4,7,12,19,30,45,46,57,62,65,75,98,104,114,115,117,126,127,141,165,175,210,223,225)
 THEN 'Technology'
ELSE 'n/a'
END AS parent_category,

--c.category_id as cid,

--classification = 
CASE
WHEN c.category_id in (2,13,17,21,26,42,64,83,87,128)
 THEN 'Attack Type'
WHEN c.category_id in (76,180,188)
 THEN 'Config'
WHEN c.category_id in (63,90,95,97,99,139,183)
 THEN 'DB'
WHEN c.category_id in (12,19,30,45,46,57,62,65,75,98,104,114,115,117,126,141,165,175,210,223)
 THEN 'Generic Tech'
WHEN c.category_id in (5,101,118,127,169,203)
 THEN 'Mail'
WHEN c.category_id in (70,135,148,164)
 THEN 'Malware'
WHEN c.category_id in (1,8,15,23,27,32,34,35,43,48,55,58,88,91,112,147,153,159,162,171,176,178,190,191,196,240)
 THEN 'Mixed'
WHEN c.category_id in (14,22,37,38,40,41,53,61,68,69,72,73,74,78,93,100,103,109,113,136,150,157,163,181,182,197,206,213,218,219,225,226,231,242)
 THEN 'Non-Runtime'
WHEN c.category_id in (3,9,11,16,18,20,24,28,31,33,36,39,44,50,51,54,59,79,80,81,82,89,102,108,116,121,123,132,133,142,143,154,166,170,195,198,199,201,207,208,216,222,224,232,233,234,237,238,243,244)
 THEN 'OS'
WHEN c.category_id in (47,49,52,66,67,71,77,84,85,86,92,94,96,105,107,110,111,120,122,124,129,130,131,134,140,144,146,151,155,156,158,160,161,167,173,174,177,179,184,185,186,187,200,202,204,209,211,212,214,215,217,220,221,229,230,235,241)
 THEN 'Runitme'
WHEN c.category_id in (4,6,7,10,25,29,56,60,106,119,125,137,138,145,149,152,168,172,189,192,193,194,227,228,236,239)
 THEN 'Web'
ELSE 'n/a'
END AS classification,

proofastext(f.proof) as vuln_proof, 
vu.references, 
-- f.port as "port# (-1 = n/a)", 
dv.date_added as vuln_date_into_nexpose, 
to_char(f.date, 'YYYY-mm-dd') as asset_last_scan

FROM fact_asset_vulnerability_instance f
JOIN dim_vulnerability dv USING (vulnerability_id)
JOIN dim_asset da USING (asset_id)
JOIN hostname h USING (asset_id)
--JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
JOIN vuln_urls vu USING (vulnerability_id)
JOIN category c USING (vulnerability_id)
--JOIN dim_vulnerability_solution USING (vulnerability_id)
--JOIN dim_asset_vulnerability_finding_rollup_solution davfrs USING (vulnerability_id)

--JOIN dim_solution s USING (solution_id)

--ORDER BY dv.riskscore DESC