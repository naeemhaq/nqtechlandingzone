# Centralize SecurityHub

Enabling this add-on in the Security account will allow the customers to see a centralized (cross-account) view of both their compliance with the security standards and their high priority AWS security alerts, or findings.

This is done by deploying a SecurityHub Enabler lambda function in the master account. It runs periodically and checks each account/region to ensure that they have been invited into the central SecurityHub account and that SecurityHub is enabled.

The original code for automating SecurityHub enablement in AWS accounts is present [here](https://code.amazon.com/packages/ProServe-SecurityHubCentralized/trees/mainline). This has been extended to work with Landing Zones.

## Instructions

* Upload the zip (code/securityhub_enabler.zip) in an S3 bucket in master account. The default bucket name defined in user-input.yaml is not public.
* Copy this directory into the landing zone configuration add-on directory.
* Update the S3 bucket name in user-input.yaml
* If the customer wants to use an account other than Security for SecurityHub aggregation, then change the user-input.yaml to reflect the desired account ID.
