# KSI-IAM: Identity and Access Management Queries - AWS

query "ksi_iam_01_aws_check" {
  sql = <<-EOQ
    -- Check MFA enabled for root account (cis_v150_1_1)
    select
      'arn:aws:iam::' || account_id || ':root' as resource,
      case
        when account_mfa_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when account_mfa_enabled then 'Root account has MFA enabled.'
        else 'Root account does not have MFA enabled.'
      end as reason,
      account_id
    from
      aws_iam_account_summary

    union all

    -- Check MFA enabled for console users (cis_v150_1_4)
    -- Note: Using login_profile IS NOT NULL instead of password_enabled (Steampipe compatibility)
    select
      arn as resource,
      case
        when login_profile is not null and not mfa_enabled then 'alarm'
        when login_profile is not null and mfa_enabled then 'ok'
        else 'ok'
      end as status,
      case
        when login_profile is not null and not mfa_enabled then name || ' has console access but MFA is not enabled.'
        when login_profile is not null and mfa_enabled then name || ' has MFA enabled.'
        else name || ' does not have console access.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check RDS IAM authentication enabled (foundational_security_rds_25)
    select
      arn as resource,
      case
        when iam_database_authentication_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when iam_database_authentication_enabled then title || ' has IAM database authentication enabled.'
        else title || ' does not have IAM database authentication enabled.'
      end as reason,
      account_id
    from
      aws_rds_db_instance
  EOQ
}

query "ksi_iam_02_aws_check" {
  sql = <<-EOQ
    -- Check IAM password policy minimum length (cis_v150_1_5)
    select
      'arn:aws:iam::' || account_id || ':account' as resource,
      case
        when minimum_password_length >= 14 then 'ok'
        when minimum_password_length >= 8 then 'info'
        else 'alarm'
      end as status,
      case
        when minimum_password_length >= 14 then 'Password policy requires minimum ' || minimum_password_length || ' characters.'
        when minimum_password_length >= 8 then 'Password policy requires minimum ' || minimum_password_length || ' characters (recommend 14+).'
        else 'Password policy requires only ' || coalesce(minimum_password_length::text, '0') || ' characters.'
      end as reason,
      account_id
    from
      aws_iam_account_password_policy

    union all

    -- Check IAM password reuse prevention (cis_v150_1_6)
    select
      'arn:aws:iam::' || account_id || ':account' as resource,
      case
        when password_reuse_prevention >= 24 then 'ok'
        when password_reuse_prevention > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when password_reuse_prevention >= 24 then 'Password policy prevents reuse of last ' || password_reuse_prevention || ' passwords.'
        when password_reuse_prevention > 0 then 'Password policy prevents reuse of last ' || password_reuse_prevention || ' passwords (recommend 24).'
        else 'Password policy does not prevent password reuse.'
      end as reason,
      account_id
    from
      aws_iam_account_password_policy

    union all

    -- Check no IAM users with password age > 90 days (cis_v150_1_10)
    -- Note: Using login_profile and password_last_used for Steampipe compatibility
    select
      arn as resource,
      case
        when login_profile is null then 'ok'
        when password_last_used > (current_date - interval '90 days') then 'ok'
        else 'alarm'
      end as status,
      case
        when login_profile is null then name || ' does not have a password.'
        when password_last_used > (current_date - interval '90 days') then name || ' password is within 90-day rotation.'
        else name || ' password is over 90 days old.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check IAM users with inactive credentials (foundational_security_iam_4)
    select
      arn as resource,
      case
        when login_profile is not null and password_last_used < (current_date - interval '45 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when login_profile is not null and password_last_used < (current_date - interval '45 days') then name || ' has not used password in over 45 days.'
        else name || ' credentials are active.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check ElastiCache Redis AUTH enabled (foundational_security_elasticache_6)
    select
      arn as resource,
      case
        when auth_token_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when auth_token_enabled then title || ' has Redis AUTH enabled.'
        else title || ' does not have Redis AUTH enabled.'
      end as reason,
      account_id
    from
      aws_elasticache_replication_group
  EOQ
}

query "ksi_iam_03_aws_check" {
  sql = <<-EOQ
    -- Check no root access keys (cis_v150_1_4)
    select
      'arn:aws:iam::' || account_id || ':root' as resource,
      case
        when account_access_keys_present = 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when account_access_keys_present = 0 then 'Root account has no access keys.'
        else 'Root account has ' || account_access_keys_present || ' access key(s).'
      end as reason,
      account_id
    from
      aws_iam_account_summary

    union all

    -- Check access key rotation (cis_v150_1_7)
    select
      u.arn as resource,
      case
        when k.access_key_id is null then 'ok'
        when k.create_date <= (current_date - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when k.access_key_id is null then u.name || ' has no access keys.'
        when k.create_date <= (current_date - interval '90 days') then u.name || ' access key ' || k.access_key_id || ' is over 90 days old.'
        else u.name || ' access key ' || k.access_key_id || ' is within rotation period.'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join aws_iam_access_key as k on u.name = k.user_name

    union all

    -- Check RDS master username is not default (foundational_security_rds_10)
    select
      arn as resource,
      case
        when master_user_name not in ('admin', 'postgres', 'root', 'master') then 'ok'
        else 'alarm'
      end as status,
      case
        when master_user_name not in ('admin', 'postgres', 'root', 'master') then title || ' uses non-default master username.'
        else title || ' uses default master username: ' || master_user_name || '.'
      end as reason,
      account_id
    from
      aws_rds_db_instance

    union all

    -- Check RDS IAM authentication (foundational_security_rds_12)
    select
      arn as resource,
      case
        when iam_database_authentication_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when iam_database_authentication_enabled then title || ' has IAM database authentication enabled.'
        else title || ' does not have IAM database authentication enabled.'
      end as reason,
      account_id
    from
      aws_rds_db_instance
  EOQ
}

query "ksi_iam_05_aws_check" {
  sql = <<-EOQ
    -- Check for unused IAM credentials (cis_v150_1_12)
    select
      arn as resource,
      case
        when login_profile is not null and password_last_used < (current_date - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when login_profile is not null and password_last_used < (current_date - interval '90 days') then name || ' has unused credentials for over 90 days.'
        else name || ' credentials are actively used.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check for full admin policies attached to users (cis_v150_1_13)
    select
      arn as resource,
      case
        when attached_policy_arns @> '["arn:aws:iam::aws:policy/AdministratorAccess"]' then 'alarm'
        else 'ok'
      end as status,
      case
        when attached_policy_arns @> '["arn:aws:iam::aws:policy/AdministratorAccess"]' then name || ' has direct AdministratorAccess policy.'
        else name || ' does not have direct AdministratorAccess.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check access key rotation (cis_v150_1_14)
    select
      u.arn as resource,
      case
        when k.access_key_id is null then 'ok'
        when k.create_date <= (current_date - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when k.access_key_id is null then u.name || ' has no access keys.'
        when k.create_date <= (current_date - interval '90 days') then u.name || ' access key ' || k.access_key_id || ' needs rotation.'
        else u.name || ' access keys are rotated within 90 days.'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join aws_iam_access_key as k on u.name = k.user_name

    union all

    -- Check IAM users have policies via groups (foundational_security_iam_3)
    select
      arn as resource,
      case
        when jsonb_array_length(inline_policies) > 0 or jsonb_array_length(attached_policy_arns) > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(inline_policies) > 0 or jsonb_array_length(attached_policy_arns) > 0 then name || ' has direct policies attached (use groups instead).'
        else name || ' has no direct policies attached.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check no overly permissive policies (foundational_security_iam_22)
    select
      arn as resource,
      case
        when policy_std -> 'Statement' @> '[{"Effect": "Allow", "Action": "*", "Resource": "*"}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when policy_std -> 'Statement' @> '[{"Effect": "Allow", "Action": "*", "Resource": "*"}]' then name || ' has overly permissive policy (Allow * on *).'
        else name || ' does not have overly permissive policy.'
      end as reason,
      account_id
    from
      aws_iam_policy
    where
      is_aws_managed = false
  EOQ
}
