WITH
    the_whole_report AS (
        SELECT dve.vulnerability_exception_id
                ,dve.vulnerability_id
                ,dv.nexpose_id
                ,dv.title
                ,round(dv.risk_score::numeric, 0) AS risk
                ,dv.severity
                ,dv.severity_score
                ,dve.scope
                ,dve.scope_description
                ,dve.group_id
                ,dag.asset_group_id
                ,dag.name
                ,dag.description
                ,dag.dynamic_membership
                ,dve.reason
                ,dve.additional_comments
                ,dve.review_comment
                ,dve.submitted_date
                ,dve.review_date
                ,dve.expiration_date
                ,dve.submitted_by
                ,dve.reviewed_by
                ,dve.status
        FROM dim_vulnerability_exception dve
        JOIN dim_vulnerability dv ON dv.vulnerability_id = dve.vulnerability_id
        JOIN dim_asset_group dag ON dag.asset_group_id = dve.group_id
        -- removes any vulnerability exceptions with the status of Recalled
        WHERE dve.status NOT LIKE 'Recalled'
        -- removed any vulnerability exceptions that expired before NOW aka when you ran the report
        AND dve.expiration_date > now();
    )
