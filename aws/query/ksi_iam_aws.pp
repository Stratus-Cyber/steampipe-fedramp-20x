# KSI-IAM: Identity and Access Management Queries - AWS

query "ksi_iam_01_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-01: Phishing-Resistant MFA
    -- Require MFA using phishing-resistant methods (FIDO2, hardware tokens)
    -- Note: Virtual MFA (TOTP) is NOT phishing-resistant per FedRAMP 20x

    with exempt_users as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_user
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-01' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_exemptions as (
      select arn from exempt_users
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check IAM users without any MFA enabled
    select
      u.arn as resource,
      case
        when ee.arn is not null then 'alarm'
        when e.arn is not null and ee.arn is null then 'skip'
        when u.mfa_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when ee.arn is not null
          then u.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || '). MFA required.'
        when e.arn is not null
          then u.name || ' is exempt from MFA requirement.'
        when u.mfa_enabled = false then u.name || ' does NOT have MFA enabled (high risk).'
        else u.name || ' has MFA enabled.'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join exempt_users as e on u.arn = e.arn
      left join expired_exemptions as ee on u.arn = ee.arn

    union all

    -- Check users with virtual MFA (NOT phishing-resistant)
    -- Virtual MFA (TOTP) is vulnerable to phishing; FIDO2/WebAuthn hardware tokens required
    select
      u.arn as resource,
      'info' as status,
      u.name || ' uses virtual MFA which is NOT phishing-resistant (FedRAMP 20x requires FIDO2/WebAuthn hardware tokens).' as reason,
      u.account_id
    from
      aws_iam_user u
      join aws_iam_virtual_mfa_device m on m.user ->> 'UserName' = u.name
    where
      u.mfa_enabled = true

    union all

    -- Check console users without MFA from credential report
    select
      'arn:aws:iam::' || account_id || ':user/' || user_name as resource,
      case
        when password_enabled = true and mfa_active = false then 'alarm'
        else 'ok'
      end as status,
      case
        when password_enabled = true and mfa_active = false
          then user_name || ' has console access but MFA is NOT active (critical risk).'
        else user_name || ' has appropriate MFA configuration.'
      end as reason,
      account_id
    from
      aws_iam_credential_report
    where
      password_enabled = true
  EOQ
}

query "ksi_iam_02_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-02: Strong Password Policies
    -- Use secure passwordless methods when feasible, otherwise enforce strong passwords with MFA
    -- Note: AWS best practice is to use SSO/federated identities instead of IAM user passwords

    with exempt_users as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_user
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-02' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_exemptions as (
      select arn from exempt_users
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check IAM password policy minimum length
    -- Note: Account-level policy, no exemptions
    select
      'arn:aws:iam::' || account_id || ':account-password-policy' as resource,
      case
        when minimum_password_length >= 14 then 'ok'
        when minimum_password_length >= 8 then 'info'
        else 'alarm'
      end as status,
      case
        when minimum_password_length >= 14
          then 'Password policy requires minimum ' || minimum_password_length || ' characters (meets strong password requirement).'
        when minimum_password_length >= 8
          then 'Password policy requires minimum ' || minimum_password_length || ' characters (recommend 14+ for FedRAMP 20x).'
        else 'Password policy requires only ' || coalesce(minimum_password_length::text, '0') || ' characters (too weak).'
      end as reason,
      account_id
    from
      aws_iam_account_password_policy

    union all

    -- Check IAM password reuse prevention
    -- Note: Account-level policy, no exemptions
    select
      'arn:aws:iam::' || account_id || ':account-password-policy' as resource,
      case
        when password_reuse_prevention >= 24 then 'ok'
        when password_reuse_prevention > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when password_reuse_prevention >= 24
          then 'Password policy prevents reuse of last ' || password_reuse_prevention || ' passwords (meets strong password requirement).'
        when password_reuse_prevention > 0
          then 'Password policy prevents reuse of last ' || password_reuse_prevention || ' passwords (recommend 24 for FedRAMP 20x).'
        else 'Password policy does NOT prevent password reuse (critical weakness).'
      end as reason,
      account_id
    from
      aws_iam_account_password_policy

    union all

    -- Check for users with passwords over 90 days old
    select
      u.arn as resource,
      case
        when ee.arn is not null then 'alarm'
        when e.arn is not null and ee.arn is null then 'skip'
        when u.login_profile is null then 'ok'
        when u.password_last_used > (current_date - interval '90 days') then 'ok'
        else 'alarm'
      end as status,
      case
        when ee.arn is not null
          then u.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then u.name || ' is exempt.'
        when u.login_profile is null
          then u.name || ' does not have a password (uses SSO/federation, preferred method).'
        when u.password_last_used > (current_date - interval '90 days')
          then u.name || ' password is within 90-day rotation period.'
        else u.name || ' password is over 90 days old (should be rotated).'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join exempt_users as e on u.arn = e.arn
      left join expired_exemptions as ee on u.arn = ee.arn
  EOQ
}

query "ksi_iam_03_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-03: Non-User Account Security
    -- Secure service accounts and machine identities

    with exempt_roles as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_role
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_roles as (
      select arn from exempt_roles
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_users as (
      select
        arn,
        name,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_user
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_users as (
      select arn from exempt_users
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_instances as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_ec2_instance
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-03' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_instances as (
      select arn from exempt_instances
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check IAM roles without condition constraints on assume role
    select
      r.arn as resource,
      case
        when er.arn is not null then 'alarm'
        when e.arn is not null and er.arn is null then 'skip'
        when r.path not like '/aws-service-role/%'
          and r.assume_role_policy_document::text like '%sts:AssumeRole%'
          and r.assume_role_policy_document::text not like '%Condition%' then 'alarm'
        else 'ok'
      end as status,
      case
        when er.arn is not null
          then r.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then r.name || ' is exempt.'
        when r.path not like '/aws-service-role/%'
          and r.assume_role_policy_document::text like '%sts:AssumeRole%'
          and r.assume_role_policy_document::text not like '%Condition%'
          then r.name || ' has assume role policy WITHOUT condition constraints (overly permissive).'
        else r.name || ' has appropriate assume role constraints.'
      end as reason,
      r.account_id
    from
      aws_iam_role as r
      left join exempt_roles as e on r.arn = e.arn
      left join expired_roles as er on r.arn = er.arn
    where
      r.path not like '/aws-service-role/%'

    union all

    -- Check active access keys older than 90 days (long-lived keys = risk)
    select
      'arn:aws:iam::' || k.account_id || ':user/' || k.user_name || '/access-key/' || k.access_key_id as resource,
      case
        when eu.arn is not null then 'alarm'
        when e.arn is not null and eu.arn is null then 'skip'
        when k.status = 'Active' and k.create_date < now() - interval '90 days' then 'alarm'
        else 'ok'
      end as status,
      case
        when eu.arn is not null
          then k.user_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then k.user_name || ' access key is exempt.'
        when k.status = 'Active' and k.create_date < now() - interval '90 days'
          then k.user_name || ' access key ' || k.access_key_id || ' is ' ||
            extract(day from now() - k.create_date)::int || ' days old (exceeds 90 days, should be rotated or replaced with roles).'
        else k.user_name || ' access key ' || k.access_key_id || ' is within rotation period.'
      end as reason,
      k.account_id
    from
      aws_iam_access_key as k
      left join exempt_users as e on e.name = k.user_name
      left join expired_users as eu on eu.arn = e.arn
    where
      k.status = 'Active'

    union all

    -- Check for unused instance profiles (should be cleaned up)
    -- Note: Instance profiles not taggable, no exemptions
    select
      ip.arn as resource,
      'info' as status,
      ip.instance_profile_name || ' is NOT attached to any EC2 instances (unused, consider cleanup).' as reason,
      ip.account_id
    from
      aws_iam_instance_profile ip
    where
      not exists (
        select 1 from aws_ec2_instance e
        where e.iam_instance_profile_arn = ip.arn
      )

    union all

    -- Check EC2 instances without managed identity (may use embedded credentials)
    select
      i.arn as resource,
      case
        when ei.arn is not null then 'alarm'
        when e.arn is not null and ei.arn is null then 'skip'
        when i.iam_instance_profile_arn is null then 'alarm'
        else 'ok'
      end as status,
      case
        when ei.arn is not null
          then i.instance_id || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then i.instance_id || ' is exempt.'
        when i.iam_instance_profile_arn is null
          then i.instance_id || ' does NOT have instance profile (may be using embedded credentials).'
        else i.instance_id || ' has instance profile ' || i.iam_instance_profile_arn || ' (using managed identity).'
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

query "ksi_iam_05_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-05: Least Privilege
    -- Ensure permissions are scoped to minimum necessary

    with exempt_policies as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_policy
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_policies as (
      select arn from exempt_policies
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_users as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_user
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_users as (
      select arn from exempt_users
      where exemption_expiry is not null and exemption_expiry::date < current_date
    ),
    exempt_roles as (
      select
        arn,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_role
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-05' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_roles as (
      select arn from exempt_roles
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check customer-managed policies with wildcard actions
    select
      p.arn as resource,
      case
        when ep.arn is not null then 'alarm'
        when e.arn is not null and ep.arn is null then 'skip'
        when p.is_aws_managed = false and p.policy_std::text like '%"Action": "*"%' then 'alarm'
        else 'ok'
      end as status,
      case
        when ep.arn is not null
          then p.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then p.name || ' is exempt.'
        when p.is_aws_managed = false and p.policy_std::text like '%"Action": "*"%'
          then p.name || ' is a customer-managed policy with wildcard actions (violates least privilege).'
        else p.name || ' follows least privilege principles.'
      end as reason,
      p.account_id
    from
      aws_iam_policy as p
      left join exempt_policies as e on p.arn = e.arn
      left join expired_policies as ep on p.arn = ep.arn
    where
      p.is_aws_managed = false and p.attachment_count > 0

    union all

    -- Check users with AdministratorAccess policy
    select
      u.arn as resource,
      case
        when eu.arn is not null then 'alarm'
        when e.arn is not null and eu.arn is null then 'skip'
        when u.attached_policy_arns::text like '%AdministratorAccess%' then 'alarm'
        else 'ok'
      end as status,
      case
        when eu.arn is not null
          then u.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then u.name || ' is exempt.'
        when u.attached_policy_arns::text like '%AdministratorAccess%'
          then u.name || ' has AdministratorAccess policy attached (should be restricted to break-glass accounts only).'
        else u.name || ' does not have administrator access.'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join exempt_users as e on u.arn = e.arn
      left join expired_users as eu on u.arn = eu.arn

    union all

    -- Check roles with AdministratorAccess (excluding AWS service roles)
    select
      r.arn as resource,
      case
        when er.arn is not null then 'alarm'
        when e.arn is not null and er.arn is null then 'skip'
        when r.attached_policy_arns::text like '%AdministratorAccess%' and r.path not like '/aws-service-role/%' then 'alarm'
        else 'ok'
      end as status,
      case
        when er.arn is not null
          then r.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then r.name || ' is exempt.'
        when r.attached_policy_arns::text like '%AdministratorAccess%' and r.path not like '/aws-service-role/%'
          then r.name || ' has AdministratorAccess policy (admin roles should be limited and justified).'
        else r.name || ' does not have administrator access.'
      end as reason,
      r.account_id
    from
      aws_iam_role as r
      left join exempt_roles as e on r.arn = e.arn
      left join expired_roles as er on r.arn = er.arn
    where
      r.path not like '/aws-service-role/%'
  EOQ
}

query "ksi_iam_06_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-06: Suspicious Activity Response
    -- Detect and respond to suspicious authentication activity

    -- Check GuardDuty enabled for suspicious activity detection
    -- Note: Access may be denied if GuardDuty is not enabled
    select
      'arn:aws:guardduty:' || region || ':' || account_id || ':detector/' || detector_id as resource,
      case
        when status = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when status = 'ENABLED'
          then 'GuardDuty detector ' || detector_id || ' is enabled (detects suspicious activity).'
        else 'GuardDuty detector ' || detector_id || ' is NOT enabled (verify via AWS Console if access denied).'
      end as reason,
      account_id
    from
      aws_guardduty_detector

    union all

    -- Check IAM-related CloudWatch alarms have actions enabled
    select
      alarm_arn as resource,
      case
        when (namespace = 'AWS/IAM' or metric_name like '%Login%' or metric_name like '%Auth%')
          and actions_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when (namespace = 'AWS/IAM' or metric_name like '%Login%' or metric_name like '%Auth%')
          and actions_enabled = false
          then alarm_name || ' monitors IAM/auth but has actions DISABLED (no automated response).'
        else alarm_name || ' has actions enabled for automated response.'
      end as reason,
      account_id
    from
      aws_cloudwatch_alarm
    where
      namespace = 'AWS/IAM' or metric_name like '%Login%' or metric_name like '%Auth%'
  EOQ
}

query "ksi_iam_07_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-07: Automated Account Management
    -- Automate account lifecycle management

    with exempt_users as (
      select
        arn,
        name,
        tags->>'${var.exemption_expiry_tag}' as exemption_expiry
      from
        aws_iam_user
      where
        tags->>'${var.exemption_tag_key}' is not null
          and 'KSI-IAM-07' = any(string_to_array(tags->>'${var.exemption_tag_key}', ':'))
    ),
    expired_users as (
      select arn from exempt_users
      where exemption_expiry is not null and exemption_expiry::date < current_date
    )
    -- Check for stale users not logged in for 90+ days
    select
      u.arn as resource,
      case
        when eu.arn is not null then 'alarm'
        when e.arn is not null and eu.arn is null then 'skip'
        when u.password_last_used < now() - interval '90 days' or u.password_last_used is null then 'alarm'
        else 'ok'
      end as status,
      case
        when eu.arn is not null
          then u.name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then u.name || ' is exempt.'
        when u.password_last_used < now() - interval '90 days'
          then u.name || ' has not logged in for ' || extract(day from now() - u.password_last_used)::int ||
            ' days (stale account, should be disabled automatically).'
        when u.password_last_used is null
          then u.name || ' has NEVER logged in (stale account, should be disabled automatically).'
        else u.name || ' account is active.'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join exempt_users as e on u.arn = e.arn
      left join expired_users as eu on u.arn = eu.arn

    union all

    -- Check access keys not rotated in 90+ days
    select
      'arn:aws:iam::' || k.account_id || ':user/' || k.user_name || '/access-key/' || k.access_key_id as resource,
      case
        when eu.arn is not null then 'alarm'
        when e.arn is not null and eu.arn is null then 'skip'
        when k.status = 'Active' and k.create_date < now() - interval '90 days' then 'alarm'
        else 'ok'
      end as status,
      case
        when eu.arn is not null
          then k.user_name || ' has EXPIRED exemption (expired: ' || e.exemption_expiry || ').'
        when e.arn is not null
          then k.user_name || ' access key is exempt.'
        when k.status = 'Active' and k.create_date < now() - interval '90 days'
          then k.user_name || ' access key ' || k.access_key_id || ' has not been rotated in ' ||
            extract(day from now() - k.create_date)::int || ' days (key rotation should be automated).'
        else k.user_name || ' access key ' || k.access_key_id || ' is within rotation period.'
      end as reason,
      k.account_id
    from
      aws_iam_access_key as k
      left join exempt_users as e on e.name = k.user_name
      left join expired_users as eu on eu.arn = e.arn
    where
      k.status = 'Active'

    union all

    -- Check SSO instances have identity store configured (enables automated provisioning/deprovisioning)
    -- Note: SSO instances are account-level, no exemptions
    select
      instance_arn as resource,
      case
        when identity_store_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when identity_store_id is null
          then 'SSO instance ' || instance_arn || ' does NOT have identity store configured (automated provisioning unavailable).'
        else 'SSO instance ' || instance_arn || ' has identity store configured (enables automated account management).'
      end as reason,
      account_id
    from
      aws_ssoadmin_instance
  EOQ
}
