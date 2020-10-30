# i-0796d6d94492924db
from getpass import getpass
import boto3
import botocore
import pprint

InstanceID = 'i-0796d6d94492924db'
region = 'us-east-1'

session = boto3.Session(region_name=region)
iam = session.client('iam')
kms = session.client('kms')
ssm = session.client('ssm')
ec2 = session.client('ec2')
pretty = pprint.PrettyPrinter(width=30)


def getInstanceID():
    answer = input("Do you need to attach provided Instance Role to the your instance(y/n)?")
    if answer == 'y':
        response = ec2.describe_instances()
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                # This sample print will output entire Dictionary object
                print('Instances info:')
                pretty.pprint(instance)
                # This will print will output the value of the Dictionary key 'InstanceId'
                print('Intances IDs:')
                pretty.pprint(instance["InstanceId"])
        InstanceID = input('To attach new Instance Role please enter instance ID:')
        response = ec2.describe_iam_instance_profile_associations(
            Filters=[
                {"Name": "instance-id", "Values": [InstanceID]}
            ]
        )

        assotiation = response['IamInstanceProfileAssociations']
        print("Assotiation:")
        pretty.pprint(assotiation)
        if assotiation != []:
            print('Your instance has a role. Exiting')
        else:
            response = ec2.associate_iam_instance_profile(
                IamInstanceProfile={
                    'Arn': InstanceProfileArn,
                    'Name': InstanceProfile
                },
                InstanceId=InstanceID
            )
            print(response)


getInstanceID()
