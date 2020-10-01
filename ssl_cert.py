import boto3
import datetime
from botocore.vendored import requests
import json
acm_client = boto3.client('acm')
sns_client = boto3.client('sns')
import os
from base64 import b64decode


def sns_Alert(dName, eDays, sslStatus):
    sslStat1 = dName + ' SSL certificate will be expired in ' + eDays +' days!! '
    snsSub = dName + ' SSL Certificate Expiry ' + sslStatus + ' alert'
    sslStat = sslStat1 + "            " + snsSub + "\n"
    print(sslStat)
    return sslStat

def sns_Alert_send_response(sslStat):
    sns_Alert_Sub = 'PROD SSL Certificate Expiry Summary List'
    # if len(sslStat)>0:
    #     response = sns_client.publish(
    #     TargetArn="arn:aws:sns:us-west-2:Accountnumber:Alert_SSL_ExpiryCheck_InEligibleCert",
    #     Message= sslStat,
    #     Subject= sns_Alert_Sub
    #     )
        
    ENCRYPTEDusername = os.environ['username'] 
    # strZenossUser = boto3.client('kms',region_name='us-west-2').decrypt(CiphertextBlob=b64decode(ENCRYPTEDusername))['Plaintext'].decode('utf-8')
    strZenossUser = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTEDusername),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')
    ENCRYPTEDpassword = os.environ['password'] 
    # strZenossPass = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTEDpassword))['Plaintext'].decode('utf-8')
    strZenossPass=boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTEDpassword),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')
    strZenossURL = '#########################'

    strZenossData = {'action':'EventsRouter', 'method':'add_event', 'data':[{'summary':'', 'device':'Accountnumber', 'component':'Prod Account Accountnumber', 'severity':'Critical', 'evclasskey':'', 'evclass':'/App/AWS/SSLExpiry'}], 'type':'rpc', 'tid':1}
    strZenossData['data'][0]['summary'] = sslStat
    print(strZenossData)

    if len(sslStat)>0:
        
        response = sns_client.publish(
        TargetArn="arn:aws:sns:us-west-2:Accountnumber:Alert_SSL_ExpiryCheck_InEligibleCert",
        Message= sslStat,
        Subject= sns_Alert_Sub
        )
        headers = {}
        resultPost = requests.post(strZenossURL, json=strZenossData, auth=(strZenossUser, strZenossPass), headers=headers)
        type(resultPost)
        print('Zenoss HTTP Status Code: ' + str(resultPost.status_code))
        
def lambda_handler(event,context):
    sslStat=''
    list_response = acm_client.list_certificates(
        CertificateStatuses=[
            'ISSUED'
            ]
            )
    print(list_response)
    

    if len(list_response['CertificateSummaryList'])>0:
        for i in list_response['CertificateSummaryList']:
            certificate_arn = i['CertificateArn']
            print(certificate_arn)
            
        
            describe_cert = acm_client.describe_certificate(
                CertificateArn=certificate_arn
            )
            if str(describe_cert['Certificate']['RenewalEligibility']).upper()=='INELIGIBLE':
                expiry_date = describe_cert['Certificate']['NotAfter']
                expiry_domainname = describe_cert['Certificate']['DomainName']
                

                today = datetime.date.today()
                exp_date_fmt = expiry_date.date()
                days_left = exp_date_fmt - today
                days_left=days_left.days
                if int(days_left) < 10:
                    sslStat += sns_Alert(expiry_domainname, str(days_left), 'Critical')
            # Frist critical alert on 20 th day      
                elif int(days_left) == 20:
                    sns_Alert(expiry_domainname, str(days_left), 'Critical')
            #third warning alert on 30th day      
                elif int(days_left) == 30:
                    sns_Alert(expiry_domainname, str(days_left), 'Warning')
            #second warning alert on 40th day
                elif int(days_left) == 40:
                    sns_Alert(expiry_domainname, str(days_left), 'Warning')
            #First warning alert on 50th day      
                elif int(days_left) == 60:
                    sns_Alert(expiry_domainname, str(days_left), 'Warning')
                else:
                    print('Everything is fine...No Action Required')
    # print(f"{sslStat} response")
    
    sns_Alert_send_response(sslStat)
