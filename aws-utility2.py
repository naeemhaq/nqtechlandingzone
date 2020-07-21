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

role_to_assume = 'AWSCloudFormationStackSetExecutionRole'

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
    return aws_accounts_dict, accounts


def assume_role(session, aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    """

    sts_client = session.client('sts')
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition, aws_account_number, role_name),
        RoleSessionName='boto3-utility'
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

def check_awsconfig(session):
    awsconfig_regions =  get_enabled_regions(
        session, session.get_available_regions('config'))
    LOGGER.info(
        "Enabling SecurityHub in regions {}".format(awsconfig_regions))
    
    aws_account_dict = get_account_list()
    try:
        outputfile = open("outputfile.txt", "a")
        for account in aws_account_dict[1]['Accounts']:
            # Store active accounts in a dict
            LOGGER.debug('printing full account dict: {}'.format(account))
            if account['Status'] == 'ACTIVE':
                LOGGER.debug('printing name of the account {} and account id: {}'.format(account['Name'], account['Id']))
                master_session = assume_role(session, account['Id'], role_to_assume)

                for aws_region in awsconfig_regions:
                    sh_master_client = master_session.client('config', region_name=aws_region)
                    recorder = sh_master_client.describe_configuration_recorders()
                    if not recorder.get('ConfigurationRecorders'):
                        print ('not found in account: ' + account['Name'] + ' region ' + aws_region)
                        continue
                    else:
                        print (recorder.get('ConfigurationRecorders')[0]['name'], file=outputfile)
                        sh_master_client.delete_configuration_recorders(ConfigurationRecorderName=recorder.get('ConfigurationRecorders')[0]['name'])
                        print ('config recorder deleted in region: ' + aws_region + ' account: ' + account['Name'])
                    
        outputfile.close()    
    except Exception as e:
        LOGGER.error('found error', exce_info=True)


def handler():
    LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps('from manual print', default=str)))
    session = boto3.session.Session(profile_name='nqtech')
    check_awsconfig(session)

handler()