import hashlib
import ipaddress
import json
import time
from datetime import datetime, timedelta, timezone
import boto3
import botocore
import requests
import yaml


with open('config.yaml') as f:
    config = yaml.safe_load(f)

MANAGED_ACCOUNT_ID = config['managedAccount']['id']
MANAGED_ACCOUNT_REGION = config['managedAccount']['region']

IOC_FEED_URL = config['feed']['url']

BUCKET_NAME = config['managedAccount']['bucketName']
BUCKET_PREFIX = config['managedAccount']['bucketPrefix']

LAMBDA_NAME = config['managedAccount']['lambdaName']

SCHEDULER_NAME = config['managedAccount']['schedulerName']
SCHEDULER_RATE = config['managedAccount']['schedulerRate']
SCHEDULER_ROLE_NAME = config['managedAccount']['schedulerRoleName']

TARGET_ACCOUNT_ID = config['targetAccount']['id']
TARGET_ACCOUNT_REGION = config['targetAccount']['region']

ROLE_NAME = config['targetAccount']['roleName']

GUARDDUTY_DETECTOR = config['targetAccount']['gdDetector']
GUARDDUTY_MAX_IOCS = config['targetAccount']['gdMaxIocs']
GUARDDUTY_THREAT_INTEL_SET = config['targetAccount']['gdThreatIntelSet']


def lambda_handler(event, context):
    start = time.time()

    if event.get('source') != 'aws.scheduler':
        init()

    try:
        response = requests.get(url=IOC_FEED_URL, timeout=60)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'Failed to fetch IOCs from the feed URL. ({type(e).__name__})')
        raise

    # TODO: use response.json() if your feed returns JSON
    data = response.text
    # data = response.json()

    iocs, count = normalize(data)

    # skip upload if the feed hash is unchanged
    s3 = boto3.client('s3', region_name=MANAGED_ACCOUNT_REGION)

    try:
        original = s3.get_object(
            Bucket=BUCKET_NAME,
            Key=f'{BUCKET_PREFIX}.sha256'
        )['Body'].read().decode('utf-8')
    except s3.exceptions.NoSuchKey:
        print(f'Hash file not found: s3://{BUCKET_NAME}/{BUCKET_PREFIX}.sha256')
        raise

    new = hashlib.sha256(iocs.encode('utf-8')).hexdigest()

    if original == new:
        duration = int((time.time() - start) * 1000)
        print(f'No changes, skipped update. GuardDuty Threat IP List has {count:,} indicators. (duration: {duration} ms)')

        return {
            'statusCode': 200,
            'body': json.dumps('No changes, skipped update.')
        }

    try:
        s3.put_object(Bucket=BUCKET_NAME, Key=BUCKET_PREFIX, Body=iocs)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        print(e)
        raise

    guardduty = assume_role(service='guardduty')

    try:
        threat_intel_sets = guardduty.list_threat_intel_sets(DetectorId=GUARDDUTY_DETECTOR)

        exists = False
        for threat_intel_set_id in threat_intel_sets['ThreatIntelSetIds']:
            threat_intel_set = guardduty.get_threat_intel_set(
                DetectorId=GUARDDUTY_DETECTOR,
                ThreatIntelSetId=threat_intel_set_id
            )
            if threat_intel_set['Name'] == GUARDDUTY_THREAT_INTEL_SET:
                exists = True
                guardduty.update_threat_intel_set(
                    DetectorId=GUARDDUTY_DETECTOR,
                    ThreatIntelSetId=threat_intel_set_id,
                    Location=f's3://{BUCKET_NAME}/{BUCKET_PREFIX}',
                    Activate=True
                )
                break

        if not exists:
            guardduty.create_threat_intel_set(
                DetectorId=GUARDDUTY_DETECTOR,
                Name=GUARDDUTY_THREAT_INTEL_SET,
                Format="TXT",
                Location=f"s3://{BUCKET_NAME}/{BUCKET_PREFIX}",
                Activate=True
            )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        print(f'Failed to update ThreatIntelSet "{GUARDDUTY_THREAT_INTEL_SET}". {e}')
        raise

    s3.put_object(Bucket=BUCKET_NAME, Key=f'{BUCKET_PREFIX}.sha256', Body=new)

    duration = int((time.time() - start) * 1000)
    print(f'Changes detected, updated. GuardDuty Threat IP List has {count:,} indicators. (duration: {duration} ms)')

    return {
        'statusCode': 200,
        'body': json.dumps('Changes detected, updated.')
    }


def normalize(data: str | dict ):
    """dedupe and sort IPv4 addresses/CIDRs"""
    # TODO: adapt to your feed format (CSV, JSON, STIX) and the target service's requirements
    data = {line.strip() for line in data.splitlines() if line.strip()}
    data = sorted(data, key=lambda ip: ipaddress.IPv4Network(ip, strict=False))[:GUARDDUTY_MAX_IOCS]
    return '\n'.join(data), len(data)


def init():
    # create EventBridge Scheduler schedule if it does not exist
    scheduler = boto3.client('scheduler', region_name=MANAGED_ACCOUNT_REGION)

    rate = int(SCHEDULER_RATE)
    expression = f"rate({rate} {'minute' if rate == 1 else 'minutes'})"

    schedule = {
        'Name': SCHEDULER_NAME,
        'ScheduleExpression': expression,
        'StartDate': datetime.now(timezone.utc) + timedelta(minutes=10),
        'FlexibleTimeWindow': {'Mode': 'OFF'},
        'Target': {
            'Arn': f'arn:aws:lambda:{MANAGED_ACCOUNT_REGION}:{MANAGED_ACCOUNT_ID}:function:{LAMBDA_NAME}',
            'RoleArn': f'arn:aws:iam::{MANAGED_ACCOUNT_ID}:role/{SCHEDULER_ROLE_NAME}'
        },
        'State': 'ENABLED'
    }

    try:
        scheduler.get_schedule(Name=SCHEDULER_NAME)
    except scheduler.exceptions.ResourceNotFoundException:
        try:
            scheduler.create_schedule(**schedule)
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            print(f'Failed to create schedule "{SCHEDULER_NAME}". {e}')
            raise
        print(f'Schedule "{SCHEDULER_NAME}" created with {expression}.')

    # create empty hash file in S3 if it does not exist
    s3 = boto3.client('s3', region_name=MANAGED_ACCOUNT_REGION)

    try:
        s3.head_object(Bucket=BUCKET_NAME, Key=f"{BUCKET_PREFIX}.sha256")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '404':
            s3.put_object(Bucket=BUCKET_NAME, Key=f"{BUCKET_PREFIX}.sha256", Body=b'')
            print(f'Hash file "s3://{BUCKET_NAME}/{BUCKET_PREFIX}.sha256" created.')
        else:
            print(f'Failed to check hash file. {e}')
            raise


def assume_role(service: str):
    try:
        sts_client = boto3.client('sts')
        assumed_role_object = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{TARGET_ACCOUNT_ID}:role/{ROLE_NAME}',
            RoleSessionName='socThreatIntel'
        )
        credentials = assumed_role_object['Credentials']
        return boto3.client(
            service,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=TARGET_ACCOUNT_REGION
        )
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        print(f'Failed to assume role for {service}. {e}')
        raise
