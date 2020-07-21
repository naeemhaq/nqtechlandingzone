
import boto3
import json
import os
import logging
from botocore.exceptions import ClientError

logging.basicConfig()
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
region_name = 'ca-central-1'
session = boto3.Session(profile_name='nqtech')

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
    try:
        sts_client = session.client('sts')
        try:
            partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
            LOGGER.info('Caller identity {}'.format(partition))
        except Exception as e:
            LOGGER.info(str(e))

        LOGGER.info('partition object created: {}'.format(partition))
        response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition, aws_account_number, role_name),
            RoleSessionName='boto3'
        )
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        LOGGER.info("Assumed session for {}.".format(aws_account_number))
    except Exception as e:
        LOGGER.error('{} ' + str(e))
    return sts_session

#arn:aws:iam::217083334892:role/AWSLandingZoneAdminExecutionRole


def security_account_session(aws_account_dict, session):
    try:
        for account in aws_account_dict[1]['Accounts']:
            # Store active accounts in a dict
            LOGGER.info('printing full account dict: {}'.format(account))
            if account['Status'] == 'ACTIVE' and account['Name'] == 'security':
                LOGGER.info('printing name of the account {} and account id: {}'.format(account['Name'], account['Id']))
                master_session = assume_role(session, account['Id'], 'AWSCloudFormationStackSetExecutionRole')
                break
        return master_session, account['Name']
    except Exception as e:
        LOGGER.error('found error in returning session for security account:  ' + str(e))


def enable_config_aggregator(master_session):
    org_aggregation_source = {
        "AllAwsRegions": True,
        "RoleArn": "arn:aws:iam::104731561022:role/service-role/aws-config-aggregator-role"
    }
    try:
        response = master_session[0].client('config', region_name).get_discovered_resource_counts()
        LOGGER.info('discovered resource counts: {}'.format(response))
        response1 = master_session[0].client('config', region_name).put_configuration_aggregator(ConfigurationAggregatorName='boto3_aggregator', OrganizationAggregationSource=org_aggregation_source)
    except Exception as e:
        LOGGER.info("there is an exception while enabling aggregator: {} in the account{}".format(response1, master_session[1]))


def config_sh_integration(master_session):

    try:
        response = master_session[0].client('cloudformation', region_name).list_stacks(StackStatusFilter=['CREATE_COMPLETE'])
        LOGGER.info('response {}'.format(response))
        for stack in response['StackSummaries']:
            if 'config-sechub-integration' in stack.values():
                LOGGER.info("the stack exists StackId {}".format(stack['StackId']))
            else:
                LOGGER.info("stack not found in {}, about to create a new one".format(master_session[1]))
                break
    except Exception as e:
        LOGGER.error('cluster fuck ' + str(e))
        LOGGER.info("Stack creation failed in {}. Enabling it.".format(master_session[1]))


def handler():
    LOGGER.debug('REQUEST RECEIVED: {}'.format(json.dumps('from manual print', default=str)))
    session = boto3.session.Session(profile_name='nqtech')
    aws_account_dict = dict()
    aws_account_dict = get_account_list()
    LOGGER.info('dump the account dict: {}'.format(aws_account_dict))
    master_session = security_account_session(aws_account_dict, session)
    config_sh_integration(master_session)
    enable_config_aggregator(master_session)

handler()
