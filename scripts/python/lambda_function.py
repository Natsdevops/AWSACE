from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
)
from jwt.utils import get_int_from_datetime
from datetime import datetime, timedelta, timezone
import os
import json
import boto3
import requests
from simple_salesforce import Salesforce
from simple_salesforce.exceptions import SalesforceAuthenticationFailed

#session from iam access keys
#access keys for Partner IAM user. Partner will created them in their AWS account
session = boto3.Session(
    aws_access_key_id='AKIATLWDDB6MMTUNP3WJ',
    aws_secret_access_key='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',
)
s3_client = session.client('s3')
# s3_client = boto3.client('s3')
session.client('sts').get_caller_identity().get('Account')

def lambda_handler(event, context):
    print(session.client('sts').get_caller_identity().get('Account'))

    bucket_name = 'ace-apn-1450-beta-us-west-2'
    prefix = 'opportunity-outbound/'
    # object_key = 'lead-outbound/Leads_Outbound.json'
    # s3_object_response = s3_client.get_object(
    #     Bucket=bucket_name,
    #     Key=object_key
    # )
    # print(s3_object_response)
    # print(s3_object_response.get('ContentLength')) # Size of the body in bytes.
    # print(s3_object_response['Body'].read().decode('utf-8'))
    
    objects_summary = s3_client.list_objects_v2(
        Bucket=bucket_name,
        Prefix = prefix
    )
    print(type(objects_summary))

    if objects_summary['KeyCount'] > 0:
        print(objects_summary['Contents'])
        
        for object_detail in objects_summary['Contents']:	   
            print(object_detail)
            if(object_detail['Size'] > 0):    
            
                object_key = object_detail['Key']
                tags_res = s3_client.get_object_tagging(
                    Bucket=bucket_name,
                    Key=object_key
                )
                is_previously_read = False
                tags = tags_res['TagSet']
                print('tags', tags)
                for tag in tags:
                    print(tag)
                    if (tag['Key'] == 'partner_processed') and ( tag['Value'] == 'true'):
                        print('Already READ')
                        is_previously_read = True
                    print('is_previously_read', is_previously_read)
                if is_previously_read is True:
                    print(object_key)
                    s3_object_response = s3_client.delete_object(
                        Bucket=bucket_name,
                        Key=object_key
                    )
                    print(s3_object_response)
                if is_previously_read is False:
                	print(object_key)
                	s3_object_response = s3_client.get_object(
                    	Bucket=bucket_name,
                    	Key=object_key
                	)
                	print(s3_object_response)
                	print(s3_object_response.get('ContentLength')) # Size of the body in bytes.
                	body_data = s3_object_response['Body'].read().decode('utf-8')               
                	print(body_data)
                	#send body data to target system               
                
                	sf = jwt_login('3MVG9HoFrxrSzmIyvUKkKbAdXMeUx7sekjwntxJrV2iJVrLRVS0NQlbqdMAf.XlZQo8cvn4g9.1gTpV9OZmJA', 'a854599@atos.net.indirect', True)
                	print('making sfdc api request...')
                	result = sf.apexecute('/partnerIntegration/api/v1/read', method='PUT', data=body_data)
                               
                	# partner can tag object as processed
                	response = s3_client.put_object_tagging(
                    	Bucket=bucket_name,
                    	Key=object_key,
                    	Tagging={
                        	'TagSet': [
                            	{
                                	'Key': 'partner_processed',
                                	'Value': 'true'
                            	},
                        	]
                    	}
                	)
                	print(response)
        return {
            'statusCode': 200,
            'body': json.dumps('success')
        }
    
def jwt_login(consumer_id, username, sandbox=False):
    endpoint = 'https://test.salesforce.com' if sandbox is True else 'https://myatos--indirect.sandbox.my.salesforce.com'
    print('generating jwt request...')
    instance = JWT()

    message = {
        'aud': endpoint,
        'sub': username,
        'iat': get_int_from_datetime(datetime.now(timezone.utc)),
        'exp': get_int_from_datetime(
            datetime.now(timezone.utc) + timedelta(hours=1)),
        'iss': consumer_id,
    }

    """
    Encode the message to JWT(JWS).
    """
    with open('server.key', 'rb') as fh:
        signing_key = jwk_from_pem(fh.read())
    
    compact_jws = instance.encode(message, signing_key, alg='RS256')
        
    print('requesting token...')
    result = requests.post(
        endpoint + '/services/oauth2/token',
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': compact_jws
        }
    )
    body = result.json()

    if result.status_code != 200:
        print('sfdc request error')
        raise SalesforceAuthenticationFailed(body['error'], body['error_description'])
    
    return Salesforce(instance_url=body['instance_url'], session_id=body['access_token'])
