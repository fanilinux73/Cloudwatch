import os
import boto3
import json
from base64 import b64decode
from botocore.vendored import requests

client = boto3.client('cloudwatch')



def lambda_handler(event, lambda_context):
   
    k = 0
    zenoss = []
    paginator = client.get_paginator('describe_alarms')
    for response in paginator.paginate():
        print(response['MetricAlarms'])
    # Do something with the alarm
   
        for i in response['MetricAlarms']:
            # print(i['AlarmName'],i['StateValue'],i['StateReason'])
            statevalue = i.get('StateValue')
            alarmname = i.get('AlarmName')
            # print(statevalue)
            # print(alarmname)
        
            if statevalue == 'ALARM':
                # print(alarmname,'this has been in alarm state')
                k += 1
                zenoss.append(alarmname)
    # print(k)
    # print(zenoss)
    for l in range(len(zenoss)):
        var = 'this cloudwatch alarm is in alarm state' +"            "+ zenoss[l-1]
        
        strZenossURL = 'https://siriusxm.saas.zenoss.com:443/zport/dmd/evconsole_router'
        strZenossData = {'action':'EventsRouter', 'method':'add_event', 'data':[{'summary':'', 'device':'258115232967', 'component':'Devops AWS Test', 'severity':'Critical', 'evclasskey':'', 'evclass':'/App/Aws/Test1'}], 'type':'rpc', 'tid':1}
        
        # strZenossUser = 's-zenawsitops'
        # strZenossPass = 'Awssxmitops1'
        
        ENCRYPTEDUSER = os.environ['username']
        strZenossUser = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTEDUSER))['Plaintext'].decode('utf-8')
        print(strZenossUser)
        ENCRYPTEDPASSWD = os.environ['password']
        strZenossPass = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTEDPASSWD))['Plaintext'].decode('utf-8')
        print(strZenossPass)
        
        strZenossData['data'][0]['summary'] = var

        resultPost = requests.post(strZenossURL, json=strZenossData, auth=(strZenossUser, strZenossPass))
        print(resultPost)
        print('Zenoss HTTP Status Code: {} ' .format(resultPost.status_code))
        
        
        print(strZenossData,'AFTER')
