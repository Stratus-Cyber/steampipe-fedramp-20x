# KSI-PIY: Policy and Inventory Queries - AWS


query "ksi_piy_01_aws_check" {
  sql = <<-EOQ
    -- Check RDS cluster tag inventory (foundational_security_rds_16)
    -- Ensures RDS DB clusters are tagged for inventory tracking
    select
      arn as resource,
      case
        when tags is null or tags = '{}' then 'alarm'
        else 'ok'
      end as status,
      case
        when tags is null or tags = '{}' then db_cluster_identifier || ' has no tags for inventory tracking.'
        else db_cluster_identifier || ' is properly tagged for inventory.'
      end as reason,
      region,
      account_id
    from
      aws_rds_db_cluster

    union all

    -- Check RDS instance tag inventory (foundational_security_rds_17)
    -- Ensures RDS DB instances are tagged for inventory tracking
    select
      arn as resource,
      case
        when tags is null or tags = '{}' then 'alarm'
        else 'ok'
      end as status,
      case
        when tags is null or tags = '{}' then db_instance_identifier || ' has no tags for inventory tracking.'
        else db_instance_identifier || ' is properly tagged for inventory.'
      end as reason,
      region,
      account_id
    from
      aws_rds_db_instance
  EOQ
}
