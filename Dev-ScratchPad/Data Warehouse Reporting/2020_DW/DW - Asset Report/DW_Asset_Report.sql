with
-- 2020/06/04 - Written by Matt Wyen
-- Version: 1.0.0
    asset_metadata   as (
        select
            fa.asset_id
            , da.ip_address
            -- UPPER wraps the Regex and formats as uppercase
            -- regexp_replace takes the hostname and removes all the DNS extras such as .exampledomain.tld and leaves only regular asset names
            , UPPER(regexp_replace(da.host_name, '([.][\w.]+)', '', 'g')) as hostname
            , da.host_name as hostname_full
            -- This is an aggregate of all sites this asset belongs to, don't be surprised if you see more than what you filtered on via the console
            , round(fa.risk_score::numeric, 0) as total_asset_risk
            from
                fact_asset fa
                    left join dim_asset da on fa.asset_id = da.asset_id
            where
                fa.asset_id is not null
    )
    , asset_software as (
    select
        das.asset_id
        , vendor
        , family
        , name
        , version
        , type
        from
            dim_asset_software das
)
/*Level of Grain: A vulnerability on an asset.
Fact Type: accumulating snapshot
Description: This fact table provides an accumulating snapshot for vulnerability age and occurrence information on an asset.
For every vulnerability to which an asset is currently vulnerable, there will be one fact record.
The record indicates when the vulnerability was first found, last found, and its current age.
The age is computed as the difference between the time the vulnerability was first discovered on the asset, and the current time.
If the vulnerability was temporarily remediated, but rediscovered, the age will be from the first discovery time.
If a vulnerability was found on a service, remediated and discovered on another service,
the age is still computed as the first time the vulnerability was found on any service on the asset.*/
select
    am.asset_id
    -- Reference of the all sites aggregate from asset metadata
    , am.ip_address
    -- This calls the already formatted hostname from asset_metadata and runs a CASE statement to replace blank values with the word blank for formatting/sorting purposes
    , case
    when am.hostname = ' ' then am.ip_address::TEXT
    when am.hostname is null then am.ip_address::TEXT
    when am.hostname is not null then am.hostname
    else am.ip_address::TEXT
    end as "Hostname"
    , am.hostname_full
    -- Legible risk_score
    , am.total_asset_risk as "Asset: Risk"
    from
        asset_metadata am
    where
        am.asset_id is not null
    order by
        asset_id
