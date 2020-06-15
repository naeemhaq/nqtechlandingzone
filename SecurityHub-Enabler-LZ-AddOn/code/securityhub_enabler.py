"""
Copyright 2019 Amazon Web Services, Inc. or its affiliates.
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License").
You may not use this file except in compliance with the License.
A copy of the License is located at
   http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file.

This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

This script orchestrates the enablement and centralization of SecurityHub
across an enterprise of AWS accounts.
It takes in a list of AWS Account Numbers, iterates through each account and
region to enable SecurityHub.
It creates each account as a Member in the SecurityHub Master account.
It invites and accepts the invite for each Member account.
"""

import boto3
import json
import os
import logging
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

session = boto3.Session()


def get_enabled_regions(session, regions):
    """
    With the introduction of regions that can be disabled,
    it is necessary to test to see if a region can be used
    and not just assume we can enable it.
    """
    enabled_regions = []
    for region in regions:
        sts_client = session.client('sts', region_name=region)
        try:
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except ClientError as e:
            if e.response['Error']['Code'] == "InvalidClientTokenId":
                LOGGER.info("{} region is disabled.".format(region))
            else:
                # LOGGER.debug("Error %s %s" % (e.response['Error'],region))
                err = e.response['Error']
                LOGGER.error(
                    "Error {} occurred testing region {}".format(err, region))
    return enabled_regions


def get_account_list():
    """
    Gets a list of Active AWS Accounts in the Organization.
    This is called if the function is not executed by an SNS trigger and
    used to periodically ensure all accounts are correctly configured, and
    prevent gaps in security from activities like new regions being added and
    SecurityHub being disabled.
    """
    aws_accounts_dict = dict()
    # Get list of accounts in org
    orgclient = session.client('organizations', region_name='us-east-1')
    accounts = orgclient.list_accounts()
    while 'NextToken' in accounts:
        moreaccounts = orgclient.list_accounts(NextToken=accounts['NextToken'])
        for acct in accounts['Accounts']:
            moreaccounts['Accounts'].append(acct)
        accounts = moreaccounts
    LOGGER.debug(accounts)
    LOGGER.info('Total accounts: {}'.format(len(accounts['Accounts'])))
    for account in accounts['Accounts']:
        # Store active accounts in a dict
        if account['Status'] == 'ACTIVE':
            accountid = account['Id']
            email = account['Email']
            aws_accounts_dict.update({accountid: email})
    LOGGER.info('Active accounts count: {}, Active accounts: {}'.format(
        len(aws_accounts_dict.keys()), json.dumps(aws_accounts_dict)))
    return aws_accounts_dict


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    """

    sts_client = boto3.client('sts')
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition, aws_account_number, role_name),
        RoleSessionName='EnableSecurityHub'
    )
    sts_session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    LOGGER.info("Assumed session for {}.".format(aws_account_number))
    return sts_session


def get_master_members(master_session, aws_region):
    """
    Returns a list of current members of the SecurityHub master account
    :param aws_region: AWS Region of the SecurityHub master account
    :return: dict of AwsAccountId:MemberStatus
    """
    member_dict = dict()
    sh_client = master_session.client('securityhub', region_name=aws_region)
    # Need to paginate and iterate over results
    paginator = sh_client.get_paginator('list_members')
    operation_parameters = {
        'OnlyAssociated': False
    }
    page_iterator = paginator.paginate(**operation_parameters)
    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update(
                    {
                        member['AccountId']: member['MemberStatus']
                    }
                )
    return member_dict


def enable_cis_benchmark(sh_client, partition):
    CIS_BENCHMARK_ARN = (
        'arn:{}:securityhub:::ruleset/'
        'cis-aws-foundations-benchmark/v/1.2.0'.format(partition))
    enabled_standards = sh_client.get_enabled_standards()
    if len(enabled_standards['StandardsSubscriptions']) > 0:
        LOGGER.info(
            "Standards are already enabled: {}".format(
                enabled_standards['StandardsSubscriptions']))
        return None
    sh_client.batch_enable_standards(
        StandardsSubscriptionRequests=[
            {
                'StandardsArn': CIS_BENCHMARK_ARN
            }
        ]
    )


def lambda_handler(event, context):
    LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))
    partition = context.invoked_function_arn.split(":")[1]
    session = boto3.session.Session()
    securityhub_regions = get_enabled_regions(
        session, session.get_available_regions('securityhub'))
    LOGGER.info(
        "Enabling SecurityHub in regions {}".format(securityhub_regions))
    aws_account_dict = dict()
    # Checks if function was called SNS
    if 'Records' in event:
        message = event['Records'][0]['Sns']['Message']
        jsonmessage = json.loads(message)
        LOGGER.info('SNS message: {}'.format(
            json.dumps(jsonmessage, default=str)))
        accountid = jsonmessage['AccountId']
        email = jsonmessage['Email']
        aws_account_dict.update({accountid: email})
    else:
        # Not called by SNS, iterates through list of Organization accounts
        # and recursively calls the function itself via SNS. SNS is used to
        # fan out the requests to avoid function timeout if too many accounts
        aws_account_dict = get_account_list()
        snsclient = session.client('sns', region_name=os.environ['AWS_REGION'])
        for accountid, email in aws_account_dict.items():
            sns_message = {
                'AccountId': accountid,
                'Email': email
            }
            LOGGER.info("Publishing to configure account {}".format(accountid))
            snsclient.publish(
                TopicArn=os.environ['topic'], Message=json.dumps(sns_message))
        return
    master_account_id = os.environ['master_account']
    master_session = assume_role(master_account_id, os.environ['assume_role'])
    for region in securityhub_regions:
        sh_master_client = master_session.client(
            'securityhub', region_name=region)

        # Making sure SecurityHub is enabled in the Master Account
        try:
            sh_master_client.get_findings()
        except Exception:
            LOGGER.info("SecurityHub not currently enabled on Master account "
                        "in {region}. Enabling it.".format(region=region))
            sh_master_client.enable_security_hub()
        else:
            # Security Hub already enabled
            LOGGER.info('SecurityHub already enabled in Master Account in '
                        '{}'.format(region))
        LOGGER.info(
            'Enabling CIS Benchmark in Master Account in {}'.format(region))
        enable_cis_benchmark(sh_master_client, partition)

    LOGGER.info('Processing: {}'.format(json.dumps(aws_account_dict)))
    for account in aws_account_dict.keys():
        email_address = aws_account_dict[account]
        if account == master_account_id:
            LOGGER.info("{} cannot become a member of itself".format(account))
            continue
        failed_invitations = []
        try:
            LOGGER.debug(
                "Enabling SecurityHub on account {} in regions {}".format(
                    securityhub_regions, account))
            member_session = assume_role(account, os.environ['assume_role'])
            for aws_region in securityhub_regions:
                sh_member_client = member_session.client(
                    'securityhub', region_name=aws_region)
                sh_master_client = master_session.client(
                    'securityhub', region_name=aws_region)
                master_members = get_master_members(master_session, aws_region)
                LOGGER.info('Beginning {account} in {region}'.format(
                    account=account, region=aws_region))
                if account in master_members:
                    if master_members[account] == 'Associated':
                        LOGGER.info(
                            "{} is already associated with {} in {}".format(
                                account, master_account_id, aws_region))
                        continue
                    else:
                        LOGGER.warning(
                            "{} exists, but not associated to {} in {}".format(
                                account, master_account_id, aws_region))
                        LOGGER.info(
                            "Disassociating {} from {} in {}".format(
                                account, master_account_id, aws_region))
                        sh_master_client.disassociate_members(
                            AccountIds=[account])
                        sh_master_client.delete_members(
                            AccountIds=[account])

                try:
                    sh_member_client.get_findings()
                except Exception as e:
                    LOGGER.debug(str(e))
                    LOGGER.info(
                        "SecurityHub not currently enabled on {} in {}".format(
                            account, aws_region))
                    LOGGER.info("Enabling SecurityHub on {} in {}".format(
                        account, aws_region))
                    sh_member_client.enable_security_hub()
                else:
                    # Security Hub already enabled
                    LOGGER.info(
                        'SecurityHub already enabled in {} in {}'.format(
                            account, aws_region))

                LOGGER.info('Enabling CIS Benchmark in {} in {}'.format(
                    account, aws_region))
                enable_cis_benchmark(sh_member_client, partition)

                LOGGER.info("Creating member for {} and {} in {}".format(
                    account, email_address, aws_region))
                member_response = sh_master_client.create_members(
                    AccountDetails=[{
                        'AccountId': account,
                        'Email': email_address
                    }])

                if len(member_response['UnprocessedAccounts']) > 0:
                    LOGGER.warning("Could not create member {} in {}".format(
                        account, aws_region))
                    failed_invitations.append({
                        'AccountId': account, 'Region': aws_region
                    })
                    continue
                LOGGER.info("Inviting {} in {}".format(
                    account, aws_region))
                sh_master_client.invite_members(AccountIds=[account])

                # go through each invitation (hopefully only 1)
                # and pull the one matching the Security Master Account ID
                try:
                    paginator = sh_member_client.get_paginator(
                        'list_invitations')
                    invitation_iterator = paginator.paginate()
                    for invitation in invitation_iterator:
                        master_invitation = next(
                            item for item in invitation['Invitations'] if
                            item["AccountId"] == master_account_id)

                    LOGGER.info(
                        "Accepting invitation on {} from {} in {}".format(
                            account, master_account_id, aws_region))

                    sh_member_client.accept_invitation(
                        MasterId=master_account_id,
                        InvitationId=master_invitation['InvitationId'])
                except Exception as e:
                    LOGGER.warning(
                        "{} could not accept invitation from {} in {}".format(
                            account, master_account_id, aws_region))
                    LOGGER.warning(e)

        except ClientError as e:
            LOGGER.error(
                "Error Processing {}. Error: {}".format(account, str(e)))

        if len(failed_invitations) > 0:
            LOGGER.warning("Error Processing following accounts: {}".format(
                json.dumps(failed_invitations, sort_keys=True, default=str)))

        # retries = 10
        # counter = 0
        # while counter < retries:
        #     sleep(60)
        #     if is_securityhub_setup(
        #             master_account_id=master_account_id,
        #             member_account_id=account_id):
        #         return True
        #     counter += 1
        # logger.error("Unable to setup SecurityHub with {master}"
        #             .format(master=master_account_id))
        # logger.error("Make sure Email address provided is the root user's")
        # raise Exception("Could not setup SecurityHub with {}"
        #                 .format(master_account_id))
