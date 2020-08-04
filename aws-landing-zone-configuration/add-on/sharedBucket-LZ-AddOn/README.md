# Created by NRCAN Federal Geo Spatial Platform Team. 

### Shared Bucket Dependency

This AddOn depends on Shared Bucket in the Shared Services account, which is done through main This bucket is used to hosts Lambda function which is referenced by all organizational accounts when the below task of integration is executed.

# Import AWS Config Findings into AWS Security Hub
Run the cloud formation template explained in this blog: https://aws.amazon.com/blogs/security/how-to-import-aws-config-rules-evaluations-findings-security-hub/ in all organizational accounts, this template creates Lamda, Cloud Watch Alarms and roles to import findings and evaluations from AWS Config to Security Hub.

This repository contains the following.

- **Template** contains the cloudformation template to deploy the solution for integrating AWS Config with AWS Security Hub
- **Code** contains the python lambda code file that integrates AWS Config with AWS Security Hub

At the momement there is an error while running this: Figuring it out. 
```
    "ca-central-1": "ResourceLogicalId:ConfigurationAggregator, ResourceType:AWS::Config::ConfigurationAggregator, ResourceStatusReason:You do not have permission to call the EnableAWSServiceAccess API. Use the credentials that allow the action. (Service: AmazonConfig; Status Code: 400; Error Code: OrganizationAccessDeniedException; Request ID: 957ba254-a252-480f-9864-2e5a2ac10f1b)."

```

## Instructions

* Upload the zip (code/sechubconfig_int.zip) in an S3 bucket in master account. The default bucket name defined in user-input.yaml is not public.
* Copy this directory into the landing zone configuration add-on directory.
* Update the S3 bucket name in user-input.yaml
* If the customer wants to use an account other than Security for SecurityHub aggregation, then change the user-input.yaml to reflect the desired account ID.


## License Summary

This sample code is made available under the MIT-0 license. See the LICENSE file.