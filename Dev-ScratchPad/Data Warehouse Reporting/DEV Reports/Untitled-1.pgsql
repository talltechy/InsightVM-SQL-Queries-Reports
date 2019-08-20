SELECT dve.vulnerability_exception_id
,dve.vulnerability_id
,dv.title
,dv.severity
,round(dv.riskscore::numeric, 0) AS risk
,dve.scope_id
,dve.reason_id
,dve.status_id
,dve.group_id
,dve.additional_comments
,dve.review_comment
,dve.submitted_date
,dve.review_date
,dve.expiration_date
,dve.submitted_by
,dve.reviewed_by
FROM dim_vulnerability_exception dve
JOIN dim_vulnerability dv ON dv.vulnerability_id = dve.vulnerability_id