SELECT a.site_id, a.name, a.description, string_agg(b.target, ' , '), b.scope
FROM dim_site AS a
left join dim_site_target AS b
on a.site_id = b.site_id
GROUP BY a.site_id, a.name, a.description, b.scope
ORDER BY a.site_id ASC