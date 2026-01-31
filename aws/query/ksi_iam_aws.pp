# KSI-IAM: Identity and Access Management Queries - AWS

query "ksi_iam_01_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-01: Phishing-Resistant MFA
    -- Require MFA using phishing-resistant methods (FIDO2, hardware tokens)
    -- Note: Virtual MFA (TOTP) is NOT phishing-resistant per FedRAMP 20x

    -- Check IAM users without any MFA enabled
    select
      arn as resource,
      case
        when mfa_enabled = false then 'alarm'
        else 'ok'
      end as status,
      case
        when mfa_enabled = false then name || ' does NOT have MFA enabled (high risk).'
        else name || ' has MFA enabled.'
      end as reason,
      account_id
    from
      aws_iam_user

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

    -- Check IAM password policy minimum length
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
      arn as resource,
      case
        when login_profile is null then 'ok'
        when password_last_used > (current_date - interval '90 days') then 'ok'
        else 'alarm'
      end as status,
      case
        when login_profile is null
          then name || ' does not have a password (uses SSO/federation, preferred method).'
        when password_last_used > (current_date - interval '90 days')
          then name || ' password is within 90-day rotation period.'
        else name || ' password is over 90 days old (should be rotated).'
      end as reason,
      account_id
    from
      aws_iam_user
  EOQ
}

query "ksi_iam_03_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-03: Non-User Account Security
    -- Secure service accounts and machine identities

    -- Check IAM roles without condition constraints on assume role
    select
      arn as resource,
      case
        when path not like '/aws-service-role/%'
          and assume_role_policy_document::text like '%sts:AssumeRole%'
          and assume_role_policy_document::text not like '%Condition%' then 'alarm'
        else 'ok'
      end as status,
      case
        when path not like '/aws-service-role/%'
          and assume_role_policy_document::text like '%sts:AssumeRole%'
          and assume_role_policy_document::text not like '%Condition%'
          then name || ' has assume role policy WITHOUT condition constraints (overly permissive).'
        else name || ' has appropriate assume role constraints.'
      end as reason,
      account_id
    from
      aws_iam_role
    where
      path not like '/aws-service-role/%'

    union all

    -- Check active access keys older than 90 days (long-lived keys = risk)
    select
      'arn:aws:iam::' || account_id || ':user/' || user_name || '/access-key/' || access_key_id as resource,
      case
        when status = 'Active' and create_date < now() - interval '90 days' then 'alarm'
        else 'ok'
      end as status,
      case
        when status = 'Active' and create_date < now() - interval '90 days'
          then user_name || ' access key ' || access_key_id || ' is ' ||
            extract(day from now() - create_date)::int || ' days old (exceeds 90 days, should be rotated or replaced with roles).'
        else user_name || ' access key ' || access_key_id || ' is within rotation period.'
      end as reason,
      account_id
    from
      aws_iam_access_key
    where
      status = 'Active'

    union all

    -- Check for unused instance profiles (should be cleaned up)
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
      arn as resource,
      case
        when iam_instance_profile_arn is null then 'alarm'
        else 'ok'
      end as status,
      case
        when iam_instance_profile_arn is null
          then instance_id || ' does NOT have instance profile (may be using embedded credentials).'
        else instance_id || ' has instance profile ' || iam_instance_profile_arn || ' (using managed identity).'
      end as reason,
      account_id
    from
      aws_ec2_instance
    where
      instance_state = 'running'
  EOQ
}

query "ksi_iam_05_aws_check" {
  sql = <<-EOQ
    -- KSI-IAM-05: Least Privilege
    -- Ensure permissions are scoped to minimum necessary

    -- Check customer-managed policies with wildcard actions
    select
      arn as resource,
      case
        when is_aws_managed = false and policy_std::text like '%"Action": "*"%' then 'alarm'
        else 'ok'
      end as status,
      case
        when is_aws_managed = false and policy_std::text like '%"Action": "*"%'
          then name || ' is a customer-managed policy with wildcard actions (violates least privilege).'
        else name || ' follows least privilege principles.'
      end as reason,
      account_id
    from
      aws_iam_policy
    where
      is_aws_managed = false and attachment_count > 0

    union all

    -- Check users with AdministratorAccess policy
    select
      arn as resource,
      case
        when attached_policy_arns::text like '%AdministratorAccess%' then 'alarm'
        else 'ok'
      end as status,
      case
        when attached_policy_arns::text like '%AdministratorAccess%'
          then name || ' has AdministratorAccess policy attached (should be restricted to break-glass accounts only).'
        else name || ' does not have administrator access.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check roles with AdministratorAccess (excluding AWS service roles)
    select
      arn as resource,
      case
        when attached_policy_arns::text like '%AdministratorAccess%' and path not like '/aws-service-role/%' then 'alarm'
        else 'ok'
      end as status,
      case
        when attached_policy_arns::text like '%AdministratorAccess%' and path not like '/aws-service-role/%'
          then name || ' has AdministratorAccess policy (admin roles should be limited and justified).'
        else name || ' does not have administrator access.'
      end as reason,
      account_id
    from
      aws_iam_role
    where
      path not like '/aws-service-role/%'
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

    -- Check for stale users not logged in for 90+ days
    select
      arn as resource,
      case
        when password_last_used < now() - interval '90 days' or password_last_used is null then 'alarm'
        else 'ok'
      end as status,
      case
        when password_last_used < now() - interval '90 days'
          then name || ' has not logged in for ' || extract(day from now() - password_last_used)::int ||
            ' days (stale account, should be disabled automatically).'
        when password_last_used is null
          then name || ' has NEVER logged in (stale account, should be disabled automatically).'
        else name || ' account is active.'
      end as reason,
      account_id
    from
      aws_iam_user

    union all

    -- Check access keys not rotated in 90+ days
    select
      'arn:aws:iam::' || account_id || ':user/' || user_name || '/access-key/' || access_key_id as resource,
      case
        when status = 'Active' and create_date < now() - interval '90 days' then 'alarm'
        else 'ok'
      end as status,
      case
        when status = 'Active' and create_date < now() - interval '90 days'
          then user_name || ' access key ' || access_key_id || ' has not been rotated in ' ||
            extract(day from now() - create_date)::int || ' days (key rotation should be automated).'
        else user_name || ' access key ' || access_key_id || ' is within rotation period.'
      end as reason,
      account_id
    from
      aws_iam_access_key
    where
      status = 'Active'

    union all

    -- Check SSO instances have identity store configured (enables automated provisioning/deprovisioning)
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
