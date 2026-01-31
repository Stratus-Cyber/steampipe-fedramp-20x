# KSI-CNA: Cloud Native Architecture Queries - AWS

query "ksi_cna_01_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-01: Restrict Network Traffic
    -- Limit inbound and outbound network traffic to only what is required

    -- Check for overly permissive inbound security group rules (0.0.0.0/0)
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':security-group-rule/' || security_group_rule_id as resource,
      case
        when cidr_ipv4 = '0.0.0.0/0' and is_egress = false then 'alarm'
        else 'ok'
      end as status,
      case
        when cidr_ipv4 = '0.0.0.0/0' and is_egress = false
          then 'Security group rule ' || security_group_rule_id || ' allows unrestricted inbound access from 0.0.0.0/0 on ' ||
            coalesce(ip_protocol || ' port ' || from_port::text, 'all protocols') || '.'
        else 'Security group rule ' || security_group_rule_id || ' has appropriate inbound restrictions.'
      end as reason,
      account_id
    from
      aws_vpc_security_group_rule
    where
      cidr_ipv4 = '0.0.0.0/0' and is_egress = false

    union all

    -- Check for unrestricted outbound rules (all protocols to 0.0.0.0/0)
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':security-group-rule/' || security_group_rule_id as resource,
      case
        when cidr_ipv4 = '0.0.0.0/0' and is_egress = true and ip_protocol = '-1' then 'alarm'
        else 'ok'
      end as status,
      case
        when cidr_ipv4 = '0.0.0.0/0' and is_egress = true and ip_protocol = '-1'
          then 'Security group rule ' || security_group_rule_id || ' allows unrestricted outbound traffic (all protocols to 0.0.0.0/0).'
        else 'Security group rule ' || security_group_rule_id || ' has appropriate outbound restrictions.'
      end as reason,
      account_id
    from
      aws_vpc_security_group_rule
    where
      cidr_ipv4 = '0.0.0.0/0' and is_egress = true and ip_protocol = '-1'

    union all

    -- Check for default NACLs (may be overly permissive)
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':network-acl/' || network_acl_id as resource,
      case
        when is_default = true then 'info'
        else 'ok'
      end as status,
      case
        when is_default = true then 'VPC ' || vpc_id || ' is using default NACL which may be overly permissive (review recommended).'
        else 'VPC ' || vpc_id || ' uses custom NACL (appropriate network controls).'
      end as reason,
      account_id
    from
      aws_vpc_network_acl
    where
      is_default = true

    union all

    -- Check sensitive ports (SSH/RDP/DB/Cache/Search) open to 0.0.0.0/0
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':security-group-rule/' || security_group_rule_id as resource,
      case
        when cidr_ipv4 = '0.0.0.0/0' and is_egress = false
          and from_port in (22, 3389, 3306, 5432, 1433, 27017, 5439, 6379, 11211, 9200, 9300) then 'alarm'
        else 'ok'
      end as status,
      case
        when cidr_ipv4 = '0.0.0.0/0' and is_egress = false
          and from_port in (22, 3389, 3306, 5432, 1433, 27017, 5439, 6379, 11211, 9200, 9300)
          then 'CRITICAL: Security group rule ' || security_group_rule_id || ' exposes sensitive port ' || from_port ||
            ' (' ||
            case from_port
              when 22 then 'SSH'
              when 3389 then 'RDP'
              when 3306 then 'MySQL'
              when 5432 then 'PostgreSQL'
              when 1433 then 'SQL Server'
              when 27017 then 'MongoDB'
              when 5439 then 'Redshift'
              when 6379 then 'Redis'
              when 11211 then 'Memcached'
              when 9200 then 'Elasticsearch'
              when 9300 then 'Elasticsearch'
            end ||
            ') to 0.0.0.0/0.'
        else 'Security group rule ' || security_group_rule_id || ' does not expose sensitive ports to internet.'
      end as reason,
      account_id
    from
      aws_vpc_security_group_rule
    where
      cidr_ipv4 = '0.0.0.0/0'
      and is_egress = false
      and from_port in (22, 3389, 3306, 5432, 1433, 27017, 5439, 6379, 11211, 9200, 9300)
  EOQ
}

query "ksi_cna_02_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-02: Attack Surface
    -- Minimize exposed services and lateral movement paths

    -- Check EC2 instances with public IP addresses
    select
      arn as resource,
      case
        when public_ip_address is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when public_ip_address is not null then instance_id || ' has public IP ' || public_ip_address || ' (expands attack surface).'
        else instance_id || ' does not have a public IP.'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check for non-standard ports open inbound from 0.0.0.0/0
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':security-group/' || group_id as resource,
      case
        when is_egress = false and cidr_ipv4 = '0.0.0.0/0' and from_port not in (443, 80) then 'alarm'
        else 'ok'
      end as status,
      case
        when is_egress = false and cidr_ipv4 = '0.0.0.0/0' and from_port not in (443, 80)
          then 'Security group ' || group_id || ' allows non-standard port ' || from_port || ' from 0.0.0.0/0 (expands attack surface).'
        else 'Security group ' || group_id || ' appropriately restricts non-HTTP/S ports.'
      end as reason,
      account_id
    from
      aws_vpc_security_group_rule
    where
      is_egress = false and cidr_ipv4 = '0.0.0.0/0' and from_port not in (443, 80)

    union all

    -- Check EC2 instances enforce IMDSv2 (prevents SSRF credential theft)
    select
      arn as resource,
      case
        when coalesce(metadata_options ->> 'HttpTokens', 'optional') != 'required' then 'alarm'
        else 'ok'
      end as status,
      case
        when coalesce(metadata_options ->> 'HttpTokens', 'optional') != 'required'
          then instance_id || ' does NOT enforce IMDSv2 (vulnerable to SSRF credential theft).'
        else instance_id || ' enforces IMDSv2 (protected against SSRF).'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

    union all

    -- Check S3 buckets with public policies
    select
      arn as resource,
      case
        when bucket_policy_is_public = true then 'alarm'
        else 'ok'
      end as status,
      case
        when bucket_policy_is_public = true then name || ' has a public bucket policy (expands attack surface).'
        else name || ' bucket policy is not public.'
      end as reason,
      account_id
    from
      aws_s3_bucket

    union all

    -- Check RDS instances publicly accessible
    select
      arn as resource,
      case
        when publicly_accessible = true then 'alarm'
        else 'ok'
      end as status,
      case
        when publicly_accessible = true
          then db_instance_identifier || ' is publicly accessible at ' || coalesce(endpoint_address, 'pending') || ' (CRITICAL attack surface).'
        else db_instance_identifier || ' is not publicly accessible.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check for internet-facing ALBs (need WAF verification)
    select
      arn as resource,
      case
        when scheme = 'internet-facing' then 'info'
        else 'ok'
      end as status,
      case
        when scheme = 'internet-facing' then name || ' is internet-facing (verify WAF association for protection).'
        else name || ' is internal (reduced attack surface).'
      end as reason,
      account_id
    from
      aws_ec2_application_load_balancer
  EOQ
}

query "ksi_cna_03_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-03: Enforce Traffic Flow
    -- Control where network traffic can flow using segmentation and routing

    -- Check VPCs have flow logs enabled
    select
      v.arn as resource,
      case
        when f.flow_log_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when f.flow_log_id is not null then v.vpc_id || ' has flow logs enabled for traffic visibility.'
        else v.vpc_id || ' does NOT have flow logs enabled.'
      end as reason,
      v.account_id
    from
      aws_vpc as v
      left join aws_vpc_flow_log as f on v.vpc_id = f.resource_id

    union all

    -- Check subnets don't auto-assign public IPs (bypass traffic controls)
    select
      subnet_arn as resource,
      case
        when map_public_ip_on_launch = true then 'alarm'
        else 'ok'
      end as status,
      case
        when map_public_ip_on_launch = true
          then subnet_id || ' auto-assigns public IPs (may bypass traffic controls, disable except for public subnets).'
        else subnet_id || ' does not auto-assign public IPs.'
      end as reason,
      account_id
    from
      aws_vpc_subnet

    union all

    -- Check route tables with internet gateway routes (identify internet-facing paths)
    select
      'arn:aws:ec2:' || region || ':' || account_id || ':route-table/' || route_table_id as resource,
      'info' as status,
      route_table_id || ' in VPC ' || vpc_id || ' has internet gateway route (verify appropriate for subnet tier).' as reason,
      account_id
    from
      aws_vpc_route_table
    where
      routes::text like '%igw-%'

    union all

    -- Check VPCs have sufficient VPC endpoints (S3/KMS/SSM minimum for private traffic)
    select
      'arn:aws:ec2:' || region || ':' || vpc_id || ':vpc-endpoint-summary' as resource,
      case
        when count(*) >= 3 then 'ok'
        else 'info'
      end as status,
      case
        when count(*) >= 3 then vpc_id || ' has ' || count(*) || ' VPC endpoints (sufficient private traffic routing).'
        else vpc_id || ' has only ' || count(*) || ' VPC endpoints (recommend S3/KMS/SSM minimum for private traffic).'
      end as reason,
      max(account_id) as account_id
    from
      aws_vpc_endpoint
    group by
      vpc_id, region
  EOQ
}

query "ksi_cna_04_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-04: Immutable Infrastructure
    -- Deploy infrastructure that is replaced rather than modified

    -- Check instances have SSH keys configured (excludes static-tagged instances)
    select
      arn as resource,
      case
        when key_name is not null and coalesce(tags ->> 'Lifecycle', '') != 'static' then 'info'
        else 'ok'
      end as status,
      case
        when key_name is not null and coalesce(tags ->> 'Lifecycle', '') != 'static'
          then instance_id || ' has SSH key "' || key_name || '" configured (immutable infrastructure should not have SSH access).'
        when key_name is not null and tags ->> 'Lifecycle' = 'static'
          then instance_id || ' has SSH key but is tagged as static/persistent.'
        else instance_id || ' does not have SSH keys (follows immutable pattern).'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'

  EOQ
}

query "ksi_cna_05_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-05: Unwanted Activity Protection
    -- Protect against DDoS and application-layer attacks

    -- Check WAF Web ACLs have rules configured
    select
      arn as resource,
      case
        when rules is null or jsonb_array_length(rules) = 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when rules is null or jsonb_array_length(rules) = 0
          then name || ' (' || scope || ') has NO rules configured (provides no protection).'
        else name || ' (' || scope || ') has ' || jsonb_array_length(rules) || ' rules configured.'
      end as reason,
      account_id
    from
      aws_wafv2_web_acl

    union all

    -- Check internet-facing ALBs have Shield protection
    select
      r.arn as resource,
      case
        when s.id is null and r.scheme = 'internet-facing' then 'alarm'
        else 'ok'
      end as status,
      case
        when s.id is null and r.scheme = 'internet-facing'
          then r.name || ' is internet-facing but does NOT have Shield protection (vulnerable to DDoS).'
        when s.id is not null
          then r.name || ' has Shield protection enabled.'
        else r.name || ' is internal (Shield not required).'
      end as reason,
      r.account_id
    from
      aws_ec2_application_load_balancer r
      left join aws_shield_protection s on r.arn = s.resource_arn
    where
      r.scheme = 'internet-facing'

    union all

    -- Check GuardDuty enabled for automated threat detection
    select
      'arn:aws:guardduty:' || region || ':' || account_id || ':detector/' || detector_id as resource,
      case
        when status = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when status = 'ENABLED' then 'GuardDuty detector ' || detector_id || ' is enabled (automated threat detection active).'
        else 'GuardDuty detector ' || detector_id || ' is NOT enabled.'
      end as reason,
      account_id
    from
      aws_guardduty_detector

    union all

    -- Check CloudWatch alarms have actions enabled for automated response
    select
      alarm_arn as resource,
      case
        when actions_enabled = false and (namespace = 'AWS/EC2' or namespace = 'AWS/ApplicationELB') then 'alarm'
        else 'ok'
      end as status,
      case
        when actions_enabled = false and (namespace = 'AWS/EC2' or namespace = 'AWS/ApplicationELB')
          then alarm_name || ' has actions DISABLED (no automated response).'
        else alarm_name || ' has actions enabled.'
      end as reason,
      account_id
    from
      aws_cloudwatch_alarm
    where
      namespace in ('AWS/EC2', 'AWS/ApplicationELB')
  EOQ
}

query "ksi_cna_06_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-06: High Availability
    -- Optimize infrastructure for availability and rapid recovery

    -- Check Auto Scaling Groups deployed across multiple AZs
    select
      autoscaling_group_arn as resource,
      case
        when jsonb_array_length(availability_zones) < 2 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(availability_zones) < 2
          then autoscaling_group_name || ' is deployed in only ' || jsonb_array_length(availability_zones) || ' AZ (single point of failure).'
        else autoscaling_group_name || ' is deployed across ' || jsonb_array_length(availability_zones) || ' AZs (HA enabled).'
      end as reason,
      account_id
    from
      aws_ec2_autoscaling_group

    union all

    -- Check ElastiCache replication groups have HA configuration
    select
      arn as resource,
      case
        when automatic_failover != 'enabled' or multi_az != 'enabled' then 'alarm'
        else 'ok'
      end as status,
      case
        when automatic_failover != 'enabled' or multi_az != 'enabled'
          then replication_group_id || ' does NOT have full HA: ' ||
            case when automatic_failover != 'enabled' then 'NO automatic failover ' else '' end ||
            case when multi_az != 'enabled' then 'NO multi-AZ' else '' end
        else replication_group_id || ' has automatic failover and multi-AZ enabled (HA configured).'
      end as reason,
      account_id
    from
      aws_elasticache_replication_group

    union all

    -- Check ALBs deployed across multiple AZs
    select
      arn as resource,
      case
        when jsonb_array_length(availability_zones) < 2 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(availability_zones) < 2
          then name || ' is deployed in only ' || jsonb_array_length(availability_zones) || ' AZ (single point of failure).'
        else name || ' is deployed across ' || jsonb_array_length(availability_zones) || ' AZs (HA enabled).'
      end as reason,
      account_id
    from
      aws_ec2_application_load_balancer

    union all

    -- Check RDS instances have Multi-AZ enabled
    select
      arn as resource,
      case
        when multi_az = false then 'alarm'
        else 'ok'
      end as status,
      case
        when multi_az = false then db_instance_identifier || ' does NOT have Multi-AZ enabled (no automatic failover).'
        else db_instance_identifier || ' has Multi-AZ enabled (database HA configured).'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check ECS services have desired count >= 2 for HA
    select
      'arn:aws:ecs:' || region || ':' || account_id || ':service/' || service_name as resource,
      case
        when desired_count < 2 then 'alarm'
        else 'ok'
      end as status,
      case
        when desired_count < 2
          then service_name || ' has desired count of ' || desired_count || ' (single task = no HA).'
        else service_name || ' has desired count of ' || desired_count || ' (HA enabled).'
      end as reason,
      account_id
    from
      aws_ecs_service
  EOQ
}

query "ksi_cna_07_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-07: Cloud Provider Best Practices
    -- Follow cloud provider security benchmarks and recommendations

    -- Check AWS managed Config rules compliance (CIS/AWS best practices)
    select
      arn as resource,
      case
        when compliance_status = 'NON_COMPLIANT' and source ->> 'Owner' = 'AWS' then 'alarm'
        else 'ok'
      end as status,
      case
        when compliance_status = 'NON_COMPLIANT' and source ->> 'Owner' = 'AWS'
          then 'AWS managed Config rule ' || name || ' is NON_COMPLIANT (violates AWS best practices).'
        else 'AWS managed Config rule ' || name || ' is compliant.'
      end as reason,
      account_id
    from
      aws_config_rule
    where
      source ->> 'Owner' = 'AWS'

    union all

    -- Check all Config rules compliance (aggregate view)
    select
      arn as resource,
      case
        when compliance_status = 'NON_COMPLIANT' then 'alarm'
        else 'ok'
      end as status,
      case
        when compliance_status = 'NON_COMPLIANT' then 'Config rule ' || name || ' is NON_COMPLIANT.'
        else 'Config rule ' || name || ' is compliant.'
      end as reason,
      account_id
    from
      aws_config_rule
  EOQ
}

query "ksi_cna_08_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-08: Automated Enforcement
    -- Automatically assess and enforce security posture

    -- Check Config rules detecting drift from desired state
    select
      arn as resource,
      case
        when compliance_status = 'NON_COMPLIANT' then 'alarm'
        else 'ok'
      end as status,
      case
        when compliance_status = 'NON_COMPLIANT'
          then 'Config rule ' || name || ' detects drift (NON_COMPLIANT): ' || coalesce(compliance_status, 'unknown') || '.'
        else 'Config rule ' || name || ' shows no drift (compliant).'
      end as reason,
      account_id
    from
      aws_config_rule

    union all

    -- Check SSM associations status (State Manager enforces configuration)
    select
      'arn:aws:ssm:' || region || ':' || account_id || ':association/' || association_id as resource,
      case
        when status ->> 'Name' != 'Success' then 'alarm'
        else 'ok'
      end as status,
      case
        when status ->> 'Name' != 'Success'
          then 'SSM association ' || name || ' status is ' || coalesce(status ->> 'Name', 'unknown') || ' (not enforcing configuration).'
        else 'SSM association ' || name || ' status is Success (enforcing desired configuration).'
      end as reason,
      account_id
    from
      aws_ssm_association

    union all

    -- Check non-compliant Config rules have auto-remediation configured
    select
      c.arn as resource,
      case
        when c.compliance_status = 'NON_COMPLIANT' and r.config_rule_name is null then 'alarm'
        else 'ok'
      end as status,
      case
        when c.compliance_status = 'NON_COMPLIANT' and r.config_rule_name is null
          then 'Config rule ' || c.name || ' is NON_COMPLIANT but has NO auto-remediation (detection only, not enforcement).'
        when c.compliance_status = 'NON_COMPLIANT' and r.config_rule_name is not null
          then 'Config rule ' || c.name || ' is NON_COMPLIANT but has auto-remediation configured.'
        else 'Config rule ' || c.name || ' is compliant.'
      end as reason,
      c.account_id
    from
      aws_config_rule c
      left join aws_config_remediation_configuration r on c.name = r.config_rule_name
    where
      c.compliance_status = 'NON_COMPLIANT'
  EOQ
}
