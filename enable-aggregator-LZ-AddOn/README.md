# Import AWS Config Findings into AWS Security Hub

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