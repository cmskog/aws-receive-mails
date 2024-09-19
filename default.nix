{ coreutils, jq, terraform, writeShellScriptBin } :
  let
    terraformwithPlugins = terraform.withPlugins (p: [ p.aws p.cloudflare ]);
  in
    writeShellScriptBin "tj"
      ''
      set \
        -o errexit \
        -o nounset \
        -o pipefail

      if [[ ! -e terraform.tfvars.json ]]
      then
        echo "$0: The configuration file 'terraform.tfvars.json' must exist in this directory"
        exit 1
      fi

      ${coreutils}/bin/cat <<END >terraform.tf
      terraform {
        required_providers {
          aws = {
            source = "hashicorp/aws"
          }
          cloudflare = {
            source = "cloudflare/cloudflare"
          }
        }
      }
      END

      ${coreutils}/bin/cat <<END >variables.tf
      variable "domain_name" {
        type = string
      }
      variable "aws_email_receiving_ses_regions" {
        type = list(string)
      }
      variable "aws_ses_dkim_domain_exception" {
        type = map(string)
        description = "Exceptions for the normal DKIM domain suffix(dkim.amazonses.com)"
      }
      variable "email_bucket" {
        type = string
      }
      variable "aws_s3_bucket_region" {
        type = string
      }
      variable "ses_receipt_rule_set_name" {
        type = string
      }
      variable "ses_receipt_rule_name" {
        type = string
      }
      variable "aws_access_key_id" {
        type = string
      }
      variable "aws_secret_access_key" {
        type = string
      }
      # Log in to the account where you plan to create the zone for the domain
      # Go to "Account Home" in the rightmost menu
      # The account id for the account is the last part of the URL(ignore any query)
      variable "cloudflare_account_id" {
        type = string
      }

      # If a unchanged setup is expected, create an api token with Zone.Zone and Zone.DNS
      # permissions for the zone to be checked
      variable "cloudflare_api_token" {
        type = string
      }
      END

      ${coreutils}/bin/cat <<END >cloudflare.tf
      provider "cloudflare" {
        api_token = var.cloudflare_api_token
      }

      resource "cloudflare_zone" "dns_zone" {
        account_id = var.cloudflare_account_id
        zone = var.domain_name
      }
      END

      # Create providers for each of the AWS regions to be used to receive
      # mail plus the region of the mail bucket
      #
      ${jq}/bin/jq '
      [ .aws_email_receiving_ses_regions + [ .aws_s3_bucket_region ] | unique | .[] | {
        "provider":
          {
            "aws":
              {
                "alias": .,

                "region": .,
                "access_key": "''${var.aws_access_key_id}",
                "secret_key": "''${var.aws_secret_access_key}"
              }
          }
      } ]' <terraform.tfvars.json >providers.tf.json

      # Create the bucket for emails in its region
      #
      ${jq}/bin/jq '
      {
        "resource":
          {
            "aws_s3_bucket":
              {
                "bucket_for_email":
                  {
                    "provider": ( "aws." + .aws_s3_bucket_region ),

                     "bucket": .email_bucket
                  }
              }
          }
      }
      ' <terraform.tfvars.json >bucket_for_email.tf.json

      # Create the policy for the email bucket, so AWS SES can drop email
      # files there
      #
      ${jq}/bin/jq --argjson policy \
      '
      {
        "Version":"2012-10-17",
        "Statement":[
          {
            "Effect":"Allow",
            "Principal":{
              "Service":"ses.amazonaws.com"
            },
            "Action":"s3:PutObject",
            "Resource":"arn:aws:s3:::''${aws_s3_bucket.bucket_for_email.id}/*",
            "Condition":{
              "StringEquals":{
                "AWS:SourceAccount":"''${data.aws_caller_identity.current.account_id}"
              }
            }
          }
        ]
      }
      ' \
      '
      {
        "resource":
          {
            "aws_s3_bucket_policy":
              {
                "bucket_for_email_policy":
                  {
                    "provider": ( "aws." + .aws_s3_bucket_region ),

                    "bucket":   "''${aws_s3_bucket.bucket_for_email.id}",
                    "policy":   ( $policy | tojson )
                  }
              }
          }
      }
      ' < terraform.tfvars.json >bucket_for_email_policy.tf.json

      # Create a aws_caller_identity data source in the email bucket
      # region(which we know exist) for picking the account id
      #
      ${jq}/bin/jq '
      .aws_s3_bucket_region |
      {
        "data":
          {
            "aws_caller_identity":
              {
                "current":
                  {
                    "provider": ("aws." + .)
                  }
              }
          }
      }
      ' <terraform.tfvars.json >data_aws_caller_identity.tf.json

      # Create a aws_ses_domain_identity(start setting up a domain for
      # verification) for all AWS regions where we are to receive email
      #
      ${jq}/bin/jq '[ .aws_email_receiving_ses_regions[] | {
        "resource":
          {
            "aws_ses_domain_identity":
              {
                ("domain_identity_" + .):
                  {
                    "provider": ("aws." + .),
                    "domain": "''${var.domain_name}"
                  }
              }
          }
      } ]' <terraform.tfvars.json >aws_ses_domain_identity.tf.json

      # Setup DKIM for the domain in each of the AWS regions where we are
      # to receive email
      #
      ${jq}/bin/jq '[ .aws_email_receiving_ses_regions[] | {
        "resource":
          {
            "aws_ses_domain_dkim":
              {
                ("domain_dkim_" + .):
                  {
                    "provider": ( "aws." + . ),
                    "domain": ( "''${resource.aws_ses_domain_identity.domain_identity_" + . + ".domain}" )
                  }
              }
          }
      } ]' <terraform.tfvars.json >aws_ses_domain_dkim.tf.json

      # Create 3 DKIM Cloudflare DNS records for each of the AWS regions
      # where we are to receive email
      #
      ${jq}/bin/jq '[ .aws_ses_dkim_domain_exception as $dkim_domain_exception | .aws_email_receiving_ses_regions[] | {
        "resource":
          {
            "cloudflare_record":
              {
                ("ses_dkim_record_" + .):
                  {
                    "zone_id": "''${resource.cloudflare_zone.dns_zone.id}",
                    "count": 3,
                    "name": ("''${resource.aws_ses_domain_dkim.domain_dkim_" + . + ".dkim_tokens[count.index]}._domainkey"),
                    "content": ("''${resource.aws_ses_domain_dkim.domain_dkim_" + . + ".dkim_tokens[count.index]}." + (if $dkim_domain_exception[.] then $dkim_domain_exception[.] else "dkim.amazonses.com" end)),
                    "type":"CNAME",
                    "ttl": 3600,
                    "proxied": false
                  }
              }
          }
      } ]' <terraform.tfvars.json >cloudflare_record.tf.json

      # Setup a aws_ses_domain_identity_verification(a structure for
      # checking that the domain is verified; takes a minute or so. We
      # want to wait for this so that we don't add MX posts for a domain
      # that is not ready to recieve emails) for the domain in each of the
      # AWS regions where we are to receive email
      #
      ${jq}/bin/jq '
      [
        .aws_email_receiving_ses_regions[]
        |
        {
          "resource":
            {
              "aws_ses_domain_identity_verification":
                {
                  ( "domain_identity_verification_" + . ):
                    {
                      "provider":
                        ( "aws." + . ),
                      "domain":
                        ( "''${resource.aws_ses_domain_identity.domain_identity_" + . + ".id}" ),
                      "depends_on":
                        [
                          ( "resource.cloudflare_record.ses_dkim_record_" + . )
                        ]
                    }
                }
            }
        }
      ]
      ' <terraform.tfvars.json >aws_ses_domain_identity_verification.tf.json

      # Set up a receipt rule set for each of the AWS regions where we are
      # to receive email
      #
      ${jq}/bin/jq '[ .aws_email_receiving_ses_regions[] | {
        "resource":
          {
            "aws_ses_receipt_rule_set":
              {
                ( "default_" + . ):
                  {
                    "provider":      ("aws." + .),
                    "rule_set_name": "''${var.ses_receipt_rule_set_name}"
                  }
              }
          }
      } ]' <terraform.tfvars.json >aws_ses_receipt_rule_set.tf.json

      # Set the receipt rule set as the active rule set(only one per region)
      # for each of the AWS regions where we are to receive email
      #
      ${jq}/bin/jq '[ .aws_email_receiving_ses_regions[] | {
        "resource":
          {
            "aws_ses_active_receipt_rule_set":
              {
                ( "default_" + . ):
                  {
                    "provider":      ("aws." + .),
                    "rule_set_name": ("''${resource.aws_ses_receipt_rule_set.default_" + . + ".id}")
                  }
              }
          }
      } ]' <terraform.tfvars.json >aws_ses_active_receipt_rule_set.tf.json

      # Add a rule in the active rule set that drops the email files in a
      # specific S3 bucket for each email sent to an address in the domain
      #
      ${jq}/bin/jq '[ .aws_email_receiving_ses_regions[] | {
        "resource":
          {
            "aws_ses_receipt_rule":
              {
                ("receipt_rule_" + .):
                  {
                    "provider": ( "aws." + . ),

                    "name":
                      "''${var.ses_receipt_rule_name}",
                    "rule_set_name":
                      ("''${aws_ses_active_receipt_rule_set.default_" + . + ".id}"),
                    "recipients":
                      ["''${var.domain_name}"],
                    "enabled":
                      true,
                    "scan_enabled":
                      false,
                    "tls_policy":
                      "Optional",
                    "s3_action":
                      {
                        "bucket_name": "''${aws_s3_bucket_policy.bucket_for_email_policy.id}",
                        "position": 1
                      }
                  }
              }
          }
      } ]' <terraform.tfvars.json >aws_ses_receipt_rule.tf.json

      # And, finally, add a MX record for each region that have been set up
      # to receive mail
      #
      ${jq}/bin/jq '
      [ .aws_email_receiving_ses_regions[] |
      {
        "resource":
          {
            "cloudflare_record":
              {
                ("mx-record_" + .):
                  {
                    "zone_id": "''${resource.cloudflare_zone.dns_zone.id}",
                    "name": "''${var.domain_name}",
                    "ttl": 3600,
                    "proxied": false,
                    "content": ( "inbound-smtp." + . + ".amazonaws.com" ),
                    "type": "MX",
                    "priority": 10,

                    "depends_on":
                      [
                        ( "resource.aws_ses_receipt_rule.receipt_rule_" + . )
                      ]
                }
              }
          }
      }
      ]
      ' <terraform.tfvars.json >mx-records.tf.json


      declare -A ALIASES
      ALIASES=(
        a apply
        p plan
        v validate
      )

      if [[ $# -lt 1 ]]
      then
        echo "Usage: $0 <terraform operation>" >&2
        exit 1
      fi

      TERRAFORM_OPERATION="''${ALIASES[$1]:-$1}"
      shift

      echo "Performing terraform operation: '$TERRAFORM_OPERATION'"

      echo "terraform output start:"
      ${terraformwithPlugins}/bin/terraform "$TERRAFORM_OPERATION" "$@"
      echo "terraform output end:"
      ''
