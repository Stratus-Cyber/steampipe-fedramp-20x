# KSI-CNA: Cloud Native Architecture Queries - AWS

query "ksi_cna_01_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-01: Restrict Network Traffic
        -- Limit inbound and outbound network traffic to only what is required
    
        with exempt_sgs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-01.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:security-group/%'
        ),
        expired_sgs as (
          select arn from exempt_sgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for overly permissive inbound security group rules (0.0.0.0/0)
        select
          'arn:aws:ec2:' || r.region || ':' || r.account_id || ':security-group-rule/' || r.security_group_rule_id as resource,
          case
            when esg.arn is not null then 'alarm'
            when e.arn is not null and esg.arn is null then 'skip'
            when r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = false then 'alarm'
            else 'ok'
          end as status,
          case
            when esg.arn is not null
              then 'Security group rule ' || r.security_group_rule_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Security group rule ' || r.security_group_rule_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = false
              then 'Security group rule ' || r.security_group_rule_id || ' allows unrestricted inbound access from 0.0.0.0/0 on ' ||
                coalesce(r.ip_protocol || ' port ' || r.from_port::text, 'all protocols') || '.'
            else 'Security group rule ' || r.security_group_rule_id || ' has appropriate inbound restrictions.'
          end as reason,
          r.account_id
        from
          aws_vpc_security_group_rule as r
          left join aws_vpc_security_group as sg on r.group_id = sg.group_id
          left join exempt_sgs as e on sg.arn = e.arn
          left join expired_sgs as esg on sg.arn = esg.arn
        where
          r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = false
  EOQ
}

query "ksi_cna_01_2_aws_check" {
  sql = <<-EOQ
        with exempt_sgs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-01.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:security-group/%'
        ),
        expired_sgs as (
          select arn from exempt_sgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for unrestricted outbound rules (all protocols to 0.0.0.0/0)
        select
          'arn:aws:ec2:' || r.region || ':' || r.account_id || ':security-group-rule/' || r.security_group_rule_id as resource,
          case
            when esg.arn is not null then 'alarm'
            when e.arn is not null and esg.arn is null then 'skip'
            when r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = true and r.ip_protocol = '-1' then 'alarm'
            else 'ok'
          end as status,
          case
            when esg.arn is not null
              then 'Security group rule ' || r.security_group_rule_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Security group rule ' || r.security_group_rule_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = true and r.ip_protocol = '-1'
              then 'Security group rule ' || r.security_group_rule_id || ' allows unrestricted outbound traffic (all protocols to 0.0.0.0/0).'
            else 'Security group rule ' || r.security_group_rule_id || ' has appropriate outbound restrictions.'
          end as reason,
          r.account_id
        from
          aws_vpc_security_group_rule as r
          left join aws_vpc_security_group as sg on r.group_id = sg.group_id
          left join exempt_sgs as e on sg.arn = e.arn
          left join expired_sgs as esg on sg.arn = esg.arn
        where
          r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = true and r.ip_protocol = '-1'
  EOQ
}

query "ksi_cna_01_3_aws_check" {
  sql = <<-EOQ
        with exempt_nacls as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-01.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:network-acl/%'
        ),
        expired_nacls as (
          select arn from exempt_nacls
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for default NACLs (may be overly permissive)
        select
          'arn:aws:ec2:' || n.region || ':' || n.account_id || ':network-acl/' || n.network_acl_id as resource,
          case
            when en.arn is not null then 'alarm'
            when e.arn is not null and en.arn is null then 'skip'
            when n.is_default = true then 'info'
            else 'ok'
          end as status,
          case
            when en.arn is not null
              then 'NACL ' || n.network_acl_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'NACL ' || n.network_acl_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when n.is_default = true then 'VPC ' || n.vpc_id || ' is using default NACL which may be overly permissive (review recommended).'
            else 'VPC ' || n.vpc_id || ' uses custom NACL (appropriate network controls).'
          end as reason,
          n.account_id
        from
          aws_vpc_network_acl as n
          left join exempt_nacls as e on ('arn:aws:ec2:' || n.region || ':' || n.account_id || ':network-acl/' || n.network_acl_id) = e.arn
          left join expired_nacls as en on ('arn:aws:ec2:' || n.region || ':' || n.account_id || ':network-acl/' || n.network_acl_id) = en.arn
        where
          n.is_default = true
  EOQ
}

query "ksi_cna_01_4_aws_check" {
  sql = <<-EOQ
        with exempt_sgs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-01.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:security-group/%'
        ),
        expired_sgs as (
          select arn from exempt_sgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check sensitive ports (SSH/RDP/DB/Cache/Search) open to 0.0.0.0/0
        select
          'arn:aws:ec2:' || r.region || ':' || r.account_id || ':security-group-rule/' || r.security_group_rule_id as resource,
          case
            when esg.arn is not null then 'alarm'
            when e.arn is not null and esg.arn is null then 'skip'
            when r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = false
              and r.from_port in (22, 3389, 3306, 5432, 1433, 27017, 5439, 6379, 11211, 9200, 9300) then 'alarm'
            else 'ok'
          end as status,
          case
            when esg.arn is not null
              then 'Security group rule ' || r.security_group_rule_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Security group rule ' || r.security_group_rule_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.cidr_ipv4 = '0.0.0.0/0' and r.is_egress = false
              and r.from_port in (22, 3389, 3306, 5432, 1433, 27017, 5439, 6379, 11211, 9200, 9300)
              then 'CRITICAL: Security group rule ' || r.security_group_rule_id || ' exposes sensitive port ' || r.from_port ||
                ' (' ||
                case r.from_port
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
            else 'Security group rule ' || r.security_group_rule_id || ' does not expose sensitive ports to internet.'
          end as reason,
          r.account_id
        from
          aws_vpc_security_group_rule as r
          left join aws_vpc_security_group as sg on r.group_id = sg.group_id
          left join exempt_sgs as e on sg.arn = e.arn
          left join expired_sgs as esg on sg.arn = esg.arn
        where
          r.cidr_ipv4 = '0.0.0.0/0'
          and r.is_egress = false
          and r.from_port in (22, 3389, 3306, 5432, 1433, 27017, 5439, 6379, 11211, 9200, 9300)
  EOQ
}

query "ksi_cna_02_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-02: Attack Surface
        -- Minimize exposed services and lateral movement paths
    
        with exempt_instances as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-02.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:instance/%'
        ),
        expired_instances as (
          select arn from exempt_instances
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check EC2 instances with public IP addresses
        select
          i.arn as resource,
          case
            when ei.arn is not null then 'alarm'
            when e.arn is not null and ei.arn is null then 'skip'
            when i.public_ip_address is not null then 'alarm'
            else 'ok'
          end as status,
          case
            when ei.arn is not null
              then i.instance_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then i.instance_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when i.public_ip_address is not null then i.instance_id || ' has public IP ' || i.public_ip_address || ' (expands attack surface).'
            else i.instance_id || ' does not have a public IP.'
          end as reason,
          i.account_id
        from
          aws_ec2_instance as i
          left join exempt_instances as e on i.arn = e.arn
          left join expired_instances as ei on i.arn = ei.arn
        where
          i.instance_state = 'running'
  EOQ
}

query "ksi_cna_02_2_aws_check" {
  sql = <<-EOQ
        with exempt_sgs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-02.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:security-group/%'
        ),
        expired_sgs as (
          select arn from exempt_sgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for non-standard ports open inbound from 0.0.0.0/0
        select
          'arn:aws:ec2:' || r.region || ':' || r.account_id || ':security-group/' || r.group_id as resource,
          case
            when esg.arn is not null then 'alarm'
            when e.arn is not null and esg.arn is null then 'skip'
            when r.is_egress = false and r.cidr_ipv4 = '0.0.0.0/0' and r.from_port not in (443, 80) then 'alarm'
            else 'ok'
          end as status,
          case
            when esg.arn is not null
              then 'Security group ' || r.group_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then 'Security group ' || r.group_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.is_egress = false and r.cidr_ipv4 = '0.0.0.0/0' and r.from_port not in (443, 80)
              then 'Security group ' || r.group_id || ' allows non-standard port ' || r.from_port || ' from 0.0.0.0/0 (expands attack surface).'
            else 'Security group ' || r.group_id || ' appropriately restricts non-HTTP/S ports.'
          end as reason,
          r.account_id
        from
          aws_vpc_security_group_rule as r
          left join aws_vpc_security_group as sg on r.group_id = sg.group_id
          left join exempt_sgs as e on sg.arn = e.arn
          left join expired_sgs as esg on sg.arn = esg.arn
        where
          r.is_egress = false and r.cidr_ipv4 = '0.0.0.0/0' and r.from_port not in (443, 80)
  EOQ
}

query "ksi_cna_02_3_aws_check" {
  sql = <<-EOQ
        with exempt_instances as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-02.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:instance/%'
        ),
        expired_instances as (
          select arn from exempt_instances
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check EC2 instances enforce IMDSv2 (prevents SSRF credential theft)
        select
          i.arn as resource,
          case
            when ei.arn is not null then 'alarm'
            when e.arn is not null and ei.arn is null then 'skip'
            when coalesce(i.metadata_options ->> 'HttpTokens', 'optional') != 'required' then 'alarm'
            else 'ok'
          end as status,
          case
            when ei.arn is not null
              then i.instance_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then i.instance_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when coalesce(i.metadata_options ->> 'HttpTokens', 'optional') != 'required'
              then i.instance_id || ' does NOT enforce IMDSv2 (vulnerable to SSRF credential theft).'
            else i.instance_id || ' enforces IMDSv2 (protected against SSRF).'
          end as reason,
          i.account_id
        from
          aws_ec2_instance as i
          left join exempt_instances as e on i.arn = e.arn
          left join expired_instances as ei on i.arn = ei.arn
        where
          i.instance_state = 'running'
  EOQ
}

query "ksi_cna_02_4_aws_check" {
  sql = <<-EOQ
        with exempt_buckets as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-02.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:s3:::%'
        ),
        expired_buckets as (
          select arn from exempt_buckets
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check S3 buckets with public policies
        select
          b.arn as resource,
          case
            when eb.arn is not null then 'alarm'
            when e.arn is not null and eb.arn is null then 'skip'
            when b.bucket_policy_is_public = true then 'alarm'
            else 'ok'
          end as status,
          case
            when eb.arn is not null
              then b.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then b.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when b.bucket_policy_is_public = true then b.name || ' has a public bucket policy (expands attack surface).'
            else b.name || ' bucket policy is not public.'
          end as reason,
          b.account_id
        from
          aws_s3_bucket as b
          left join exempt_buckets as e on b.arn = e.arn
          left join expired_buckets as eb on b.arn = eb.arn
  EOQ
}

query "ksi_cna_02_5_aws_check" {
  sql = <<-EOQ
        with exempt_rds as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-02.5' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:rds:%:db:%'
        ),
        expired_rds as (
          select arn from exempt_rds
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check RDS instances publicly accessible
        select
          r.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when r.publicly_accessible = true then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then r.db_instance_identifier || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then r.db_instance_identifier || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.publicly_accessible = true
              then r.db_instance_identifier || ' is publicly accessible at ' || coalesce(r.endpoint_address, 'pending') || ' (CRITICAL attack surface).'
            else r.db_instance_identifier || ' is not publicly accessible.'
          end as reason,
          r.account_id
        from
          aws_rds_db_instance as r
          left join exempt_rds as e on r.arn = e.arn
          left join expired_rds as er on r.arn = er.arn
  EOQ
}

query "ksi_cna_02_6_aws_check" {
  sql = <<-EOQ
        with exempt_albs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-02.6' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:elasticloadbalancing:%:loadbalancer/%'
        ),
        expired_albs as (
          select arn from exempt_albs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check for internet-facing ALBs (need WAF verification)
        select
          a.arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when a.scheme = 'internet-facing' then 'info'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then a.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then a.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when a.scheme = 'internet-facing' then a.name || ' is internet-facing (verify WAF association for protection).'
            else a.name || ' is internal (reduced attack surface).'
          end as reason,
          a.account_id
        from
          aws_ec2_application_load_balancer as a
          left join exempt_albs as e on a.arn = e.arn
          left join expired_albs as ea on a.arn = ea.arn
  EOQ
}

query "ksi_cna_03_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-03: Enforce Traffic Flow
        -- Control where network traffic can flow using segmentation and routing
    
        with exempt_vpcs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-03.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:vpc/%'
        ),
        expired_vpcs as (
          select arn from exempt_vpcs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check VPCs have flow logs enabled
        select
          v.arn as resource,
          case
            when ev.arn is not null then 'alarm'
            when e.arn is not null and ev.arn is null then 'skip'
            when f.flow_log_id is not null then 'ok'
            else 'alarm'
          end as status,
          case
            when ev.arn is not null
              then v.vpc_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then v.vpc_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when f.flow_log_id is not null then v.vpc_id || ' has flow logs enabled for traffic visibility.'
            else v.vpc_id || ' does NOT have flow logs enabled.'
          end as reason,
          v.account_id
        from
          aws_vpc as v
          left join aws_vpc_flow_log as f on v.vpc_id = f.resource_id
          left join exempt_vpcs as e on v.arn = e.arn
          left join expired_vpcs as ev on v.arn = ev.arn
  EOQ
}

query "ksi_cna_03_2_aws_check" {
  sql = <<-EOQ
        with exempt_subnets as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-03.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:subnet/%'
        ),
        expired_subnets as (
          select arn from exempt_subnets
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check subnets don't auto-assign public IPs (bypass traffic controls)
        select
          s.subnet_arn as resource,
          case
            when es.arn is not null then 'alarm'
            when e.arn is not null and es.arn is null then 'skip'
            when s.map_public_ip_on_launch = true then 'alarm'
            else 'ok'
          end as status,
          case
            when es.arn is not null
              then s.subnet_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then s.subnet_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when s.map_public_ip_on_launch = true
              then s.subnet_id || ' auto-assigns public IPs (may bypass traffic controls, disable except for public subnets).'
            else s.subnet_id || ' does not auto-assign public IPs.'
          end as reason,
          s.account_id
        from
          aws_vpc_subnet as s
          left join exempt_subnets as e on s.subnet_arn = e.arn
          left join expired_subnets as es on s.subnet_arn = es.arn
  EOQ
}

query "ksi_cna_03_3_aws_check" {
  sql = <<-EOQ
        with exempt_route_tables as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-03.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:route-table/%'
        ),
        expired_route_tables as (
          select arn from exempt_route_tables
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check route tables with internet gateway routes (identify internet-facing paths)
        select
          'arn:aws:ec2:' || rt.region || ':' || rt.account_id || ':route-table/' || rt.route_table_id as resource,
          case
            when ert.arn is not null then 'alarm'
            when e.arn is not null and ert.arn is null then 'skip'
            else 'info'
          end as status,
          case
            when ert.arn is not null
              then rt.route_table_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then rt.route_table_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            else rt.route_table_id || ' in VPC ' || rt.vpc_id || ' has internet gateway route (verify appropriate for subnet tier).'
          end as reason,
          rt.account_id
        from
          aws_vpc_route_table as rt
          left join exempt_route_tables as e on ('arn:aws:ec2:' || rt.region || ':' || rt.account_id || ':route-table/' || rt.route_table_id) = e.arn
          left join expired_route_tables as ert on ('arn:aws:ec2:' || rt.region || ':' || rt.account_id || ':route-table/' || rt.route_table_id) = ert.arn
        where
          rt.routes::text like '%igw-%'
  EOQ
}

query "ksi_cna_03_4_aws_check" {
  sql = <<-EOQ
        with exempt_vpcs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-03.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:ec2:%:vpc/%'
        ),
        expired_vpcs as (
          select arn from exempt_vpcs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check VPCs have sufficient VPC endpoints (S3/KMS/SSM minimum for private traffic)
        -- Note: VPC endpoints aggregate by VPC, exemption applies at VPC level
        select
          'arn:aws:ec2:' || ep.region || ':' || ep.vpc_id || ':vpc-endpoint-summary' as resource,
          case
            when ev.arn is not null then 'alarm'
            when e.arn is not null and ev.arn is null then 'skip'
            when count(*) >= 3 then 'ok'
            else 'info'
          end as status,
          case
            when ev.arn is not null
              then ep.vpc_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then ep.vpc_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when count(*) >= 3 then ep.vpc_id || ' has ' || count(*) || ' VPC endpoints (sufficient private traffic routing).'
            else ep.vpc_id || ' has only ' || count(*) || ' VPC endpoints (recommend S3/KMS/SSM minimum for private traffic).'
          end as reason,
          max(ep.account_id) as account_id
        from
          aws_vpc_endpoint as ep
          left join aws_vpc as v on ep.vpc_id = v.vpc_id
          left join exempt_vpcs as e on v.arn = e.arn
          left join expired_vpcs as ev on v.arn = ev.arn
        group by
          ep.vpc_id, ep.region, ev.arn, e.arn, e.exemption_expiry, e.exemption_reason
  EOQ
}

query "ksi_cna_04_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-04: Immutable Infrastructure
    -- Deploy infrastructure that is replaced rather than modified

    with exempt_instances as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
        tags->>'${var.exemption_reason_key}' as exemption_reason
      from
        aws_tagging_resource
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-CNA-04' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
        and arn like 'arn:aws:ec2:%:instance/%'
    ),
    expired_exemptions as (
      select arn from exempt_instances
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check instances have SSH keys configured (excludes static-tagged instances)
    select
      i.arn as resource,
      case
        when ee.arn is not null then 'alarm'
        when e.arn is not null and ee.arn is null then 'skip'
        when i.key_name is not null and coalesce(i.tags ->> 'Lifecycle', '') != 'static' then 'info'
        else 'ok'
      end as status,
      case
        when ee.arn is not null
          then i.instance_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when e.arn is not null
          then i.instance_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
        when i.key_name is not null and coalesce(i.tags ->> 'Lifecycle', '') != 'static'
          then i.instance_id || ' has SSH key "' || i.key_name || '" configured (immutable infrastructure should not have SSH access).'
        when i.key_name is not null and i.tags ->> 'Lifecycle' = 'static'
          then i.instance_id || ' has SSH key but is tagged as static/persistent.'
        else i.instance_id || ' does not have SSH keys (follows immutable pattern).'
      end as reason,
      i.account_id
    from
      aws_ec2_instance as i
      left join exempt_instances as e on i.arn = e.arn
      left join expired_exemptions as ee on i.arn = ee.arn
    where
      i.instance_state = 'running'

  EOQ
}

query "ksi_cna_05_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-05: Unwanted Activity Protection
        -- Protect against DDoS and application-layer attacks
    
        with exempt_waf as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-05.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:wafv2:%:webacl/%'
        ),
        expired_waf as (
          select arn from exempt_waf
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check WAF Web ACLs have rules configured
        select
          w.arn as resource,
          case
            when ew.arn is not null then 'alarm'
            when e.arn is not null and ew.arn is null then 'skip'
            when w.rules is null or jsonb_array_length(w.rules) = 0 then 'alarm'
            else 'ok'
          end as status,
          case
            when ew.arn is not null
              then w.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then w.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when w.rules is null or jsonb_array_length(w.rules) = 0
              then w.name || ' (' || w.scope || ') has NO rules configured (provides no protection).'
            else w.name || ' (' || w.scope || ') has ' || jsonb_array_length(w.rules) || ' rules configured.'
          end as reason,
          w.account_id
        from
          aws_wafv2_web_acl as w
          left join exempt_waf as e on w.arn = e.arn
          left join expired_waf as ew on w.arn = ew.arn
  EOQ
}

query "ksi_cna_05_2_aws_check" {
  sql = <<-EOQ
        with exempt_albs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-05.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:elasticloadbalancing:%:loadbalancer/%'
        ),
        expired_albs as (
          select arn from exempt_albs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check internet-facing ALBs have Shield protection
        select
          r.arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when s.id is null and r.scheme = 'internet-facing' then 'alarm'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then r.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then r.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
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
          left join exempt_albs as e on r.arn = e.arn
          left join expired_albs as ea on r.arn = ea.arn
        where
          r.scheme = 'internet-facing'
  EOQ
}

query "ksi_cna_05_3_aws_check" {
  sql = <<-EOQ
    -- Check GuardDuty enabled for automated threat detection
        -- Note: GuardDuty detectors are account-level resources, no resource-level exemptions
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
  EOQ
}

query "ksi_cna_05_4_aws_check" {
  sql = <<-EOQ
    -- Check CloudWatch alarms have actions enabled for automated response
        -- Note: CloudWatch alarms don't support tagging for exemptions, skipping exemption logic
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

query "ksi_cna_06_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-06: High Availability
        -- Optimize infrastructure for availability and rapid recovery
    
        with exempt_asgs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-06.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:autoscaling:%:autoScalingGroup:%'
        ),
        expired_asgs as (
          select arn from exempt_asgs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Auto Scaling Groups deployed across multiple AZs
        select
          a.autoscaling_group_arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when jsonb_array_length(a.availability_zones) < 2 then 'alarm'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then a.autoscaling_group_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then a.autoscaling_group_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when jsonb_array_length(a.availability_zones) < 2
              then a.autoscaling_group_name || ' is deployed in only ' || jsonb_array_length(a.availability_zones) || ' AZ (single point of failure).'
            else a.autoscaling_group_name || ' is deployed across ' || jsonb_array_length(a.availability_zones) || ' AZs (HA enabled).'
          end as reason,
          a.account_id
        from
          aws_ec2_autoscaling_group as a
          left join exempt_asgs as e on a.autoscaling_group_arn = e.arn
          left join expired_asgs as ea on a.autoscaling_group_arn = ea.arn
  EOQ
}

query "ksi_cna_06_2_aws_check" {
  sql = <<-EOQ
        with exempt_elasticache as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-06.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:elasticache:%:replicationgroup:%'
        ),
        expired_elasticache as (
          select arn from exempt_elasticache
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check ElastiCache replication groups have HA configuration
        select
          c.arn as resource,
          case
            when ec.arn is not null then 'alarm'
            when e.arn is not null and ec.arn is null then 'skip'
            when c.automatic_failover != 'enabled' or c.multi_az != 'enabled' then 'alarm'
            else 'ok'
          end as status,
          case
            when ec.arn is not null
              then c.replication_group_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.replication_group_id || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.automatic_failover != 'enabled' or c.multi_az != 'enabled'
              then c.replication_group_id || ' does NOT have full HA: ' ||
                case when c.automatic_failover != 'enabled' then 'NO automatic failover ' else '' end ||
                case when c.multi_az != 'enabled' then 'NO multi-AZ' else '' end
            else c.replication_group_id || ' has automatic failover and multi-AZ enabled (HA configured).'
          end as reason,
          c.account_id
        from
          aws_elasticache_replication_group as c
          left join exempt_elasticache as e on c.arn = e.arn
          left join expired_elasticache as ec on c.arn = ec.arn
  EOQ
}

query "ksi_cna_06_3_aws_check" {
  sql = <<-EOQ
        with exempt_albs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-06.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:elasticloadbalancing:%:loadbalancer/%'
        ),
        expired_albs as (
          select arn from exempt_albs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check ALBs deployed across multiple AZs
        select
          a.arn as resource,
          case
            when ea.arn is not null then 'alarm'
            when e.arn is not null and ea.arn is null then 'skip'
            when jsonb_array_length(a.availability_zones) < 2 then 'alarm'
            else 'ok'
          end as status,
          case
            when ea.arn is not null
              then a.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then a.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when jsonb_array_length(a.availability_zones) < 2
              then a.name || ' is deployed in only ' || jsonb_array_length(a.availability_zones) || ' AZ (single point of failure).'
            else a.name || ' is deployed across ' || jsonb_array_length(a.availability_zones) || ' AZs (HA enabled).'
          end as reason,
          a.account_id
        from
          aws_ec2_application_load_balancer as a
          left join exempt_albs as e on a.arn = e.arn
          left join expired_albs as ea on a.arn = ea.arn
  EOQ
}

query "ksi_cna_06_4_aws_check" {
  sql = <<-EOQ
        with exempt_rds as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-06.4' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and arn like 'arn:aws:rds:%:db:%'
        ),
        expired_rds as (
          select arn from exempt_rds
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check RDS instances have Multi-AZ enabled
        select
          r.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when r.multi_az = false then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then r.db_instance_identifier || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then r.db_instance_identifier || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when r.multi_az = false then r.db_instance_identifier || ' does NOT have Multi-AZ enabled (no automatic failover).'
            else r.db_instance_identifier || ' has Multi-AZ enabled (database HA configured).'
          end as reason,
          r.account_id
        from
          aws_rds_db_instance as r
          left join exempt_rds as e on r.arn = e.arn
          left join expired_rds as er on r.arn = er.arn
  EOQ
}

query "ksi_cna_06_5_aws_check" {
  sql = <<-EOQ
        with exempt_ecs as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_tagging_resource
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-06' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-06.5' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
            and resource_type = 'ecs:service'
        ),
        expired_ecs as (
          select arn from exempt_ecs
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check ECS services have desired count >= 2 for HA
        select
          'arn:aws:ecs:' || s.region || ':' || s.account_id || ':service/' || s.service_name as resource,
          case
            when es.arn is not null then 'alarm'
            when e.arn is not null and es.arn is null then 'skip'
            when s.desired_count < 2 then 'alarm'
            else 'ok'
          end as status,
          case
            when es.arn is not null
              then s.service_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then s.service_name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when s.desired_count < 2
              then s.service_name || ' has desired count of ' || s.desired_count || ' (single task = no HA).'
            else s.service_name || ' has desired count of ' || s.desired_count || ' (HA enabled).'
          end as reason,
          s.account_id
        from
          aws_ecs_service as s
          left join exempt_ecs as e on ('arn:aws:ecs:' || s.region || ':' || s.account_id || ':service/' || s.service_name) = e.arn
          left join expired_ecs as es on ('arn:aws:ecs:' || s.region || ':' || s.account_id || ':service/' || s.service_name) = es.arn
  EOQ
}

query "ksi_cna_07_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-07: Cloud Provider Best Practices
        -- Follow cloud provider security benchmarks and recommendations

        with exempt_rules as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_config_rule
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-07' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-07.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rules as (
          select arn from exempt_rules
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check AWS managed Config rules compliance (CIS/AWS best practices)
        select
          c.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' and c.source ->> 'Owner' = 'AWS' then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then c.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' and c.source ->> 'Owner' = 'AWS'
              then 'AWS managed Config rule ' || c.name || ' is NON_COMPLIANT (violates AWS best practices).'
            else 'AWS managed Config rule ' || c.name || ' is compliant.'
          end as reason,
          c.account_id
        from
          aws_config_rule as c
          left join exempt_rules as e on c.arn = e.arn
          left join expired_rules as er on c.arn = er.arn
        where
          c.source ->> 'Owner' = 'AWS'
  EOQ
}

query "ksi_cna_07_2_aws_check" {
  sql = <<-EOQ
        with exempt_rules as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_config_rule
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-07' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-07.2' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rules as (
          select arn from exempt_rules
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check all Config rules compliance (aggregate view)
        select
          c.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then c.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' then 'Config rule ' || c.name || ' is NON_COMPLIANT.'
            else 'Config rule ' || c.name || ' is compliant.'
          end as reason,
          c.account_id
        from
          aws_config_rule as c
          left join exempt_rules as e on c.arn = e.arn
          left join expired_rules as er on c.arn = er.arn
  EOQ
}

query "ksi_cna_08_1_aws_check" {
  sql = <<-EOQ
    -- KSI-CNA-08: Automated Enforcement
        -- Automatically assess and enforce security posture

        with exempt_rules as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_config_rule
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-08.1' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rules as (
          select arn from exempt_rules
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check Config rules detecting drift from desired state
        select
          c.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then c.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT'
              then 'Config rule ' || c.name || ' detects drift (NON_COMPLIANT): ' || coalesce(c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType', 'unknown') || '.'
            else 'Config rule ' || c.name || ' shows no drift (compliant).'
          end as reason,
          c.account_id
        from
          aws_config_rule as c
          left join exempt_rules as e on c.arn = e.arn
          left join expired_rules as er on c.arn = er.arn
  EOQ
}

query "ksi_cna_08_2_aws_check" {
  sql = <<-EOQ
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
  EOQ
}

query "ksi_cna_08_3_aws_check" {
  sql = <<-EOQ
        with exempt_rules as (
          select
            arn,
            tags->>'${var.exemption_expiry_tag}' as exemption_expiry,
            tags->>'${var.exemption_reason_key}' as exemption_reason
          from
            aws_config_rule
          where
            tags->>'${var.exemption_tag_key}' is not null
              and ('KSI-CNA-08' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
                OR 'KSI-CNA-08.3' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':')))
        ),
        expired_rules as (
          select arn from exempt_rules
          where exemption_expiry is not null and exemption_expiry::date < current_date
        )
    -- Check non-compliant Config rules have auto-remediation configured
        select
          c.arn as resource,
          case
            when er.arn is not null then 'alarm'
            when e.arn is not null and er.arn is null then 'skip'
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' and r.config_rule_name is null then 'alarm'
            else 'ok'
          end as status,
          case
            when er.arn is not null
              then c.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when e.arn is not null
              then c.name || ' is exempt.' || coalesce(' Reason: ' || e.exemption_reason || '.', '')
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' and r.config_rule_name is null
              then 'Config rule ' || c.name || ' is NON_COMPLIANT but has NO auto-remediation (detection only, not enforcement).'
            when c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT' and r.config_rule_name is not null
              then 'Config rule ' || c.name || ' is NON_COMPLIANT but has auto-remediation configured.'
            else 'Config rule ' || c.name || ' is compliant.'
          end as reason,
          c.account_id
        from
          aws_config_rule as c
          left join aws_config_remediation_configuration r on c.name = r.config_rule_name
          left join exempt_rules as e on c.arn = e.arn
          left join expired_rules as er on c.arn = er.arn
        where
          c.compliance_by_config_rule -> 'Compliance' ->> 'ComplianceType' = 'NON_COMPLIANT'
  EOQ
}
