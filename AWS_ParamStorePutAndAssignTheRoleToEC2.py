from getpass import getpass
# import disassociate_role_with_instance as ds
import boto3
import botocore
import pprint

global ProjectName
global IAMPolicyNameForTheKMS
global IAMPolicyDescriptionForTheKMS
global KMSKeyDescription
global IAMPolicyNameForTheEC2
global IAMPolicyDescriptionForTheEC2
global InstanceProfile
global EC2GetSSMRole
global KMSAliasName
global AssumeRolePolicyDocument
global IAMPolicyEC2arn
global IAMPolicyEC2

# List AWS regions
ec2 = boto3.client('ec2')
# select Regions' Names only
regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
print('AWS regions list:')
pprint.pprint(regions)

pretty = pprint.PrettyPrinter(width=30)
# Ask for a region
region = input('\nAWS region (or skip, the default region is us-east-1):')

# Fix empty value of the region
while len(region) > 0:
    if region in regions:
        break
    else:
        print('The region name is incorrect: ', region)
        region = input('\nPlease, enter AWS region (or skip, the default region is us-east-1):')

if len(region) == 0:
    region = 'us-east-1'
    print('Will use default region us-east-1...')

session = boto3.Session(region_name=region)
iam = session.client('iam')
kms = session.client('kms')
ssm = session.client('ssm')
ec2 = session.client('ec2')


def create_aliasForKmsKey():
    # #Create the KMS Alias:
    try:
        response = kms.create_alias(AliasName=KMSAliasName, TargetKeyId=KeyIDis)
        print("Created an alias for your new KMS Key. Status code: ", response['ResponseMetadata']['HTTPStatusCode'])
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    put_parameter()


def create_iam_policy_for_kms():
    global IAMPolicyKMS
    # JSON data:
    IAMPolicyKMS = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "IAMPolicyKMS",
          "Action": [
            "kms:Decrypt",
            "kms:Encrypt"
          ],
          "Effect": "Allow",
          "Resource": """ + "\"" + KeyARNis + "\"" + """
        }
      ]
    }"""
    print('IAM Policy for KMS', IAMPolicyKMS)

    # Create the IAM Policy:
    try:
        response = iam.create_policy(
            PolicyName=IAMPolicyNameForTheKMS,
            PolicyDocument=IAMPolicyKMS,
            Description=IAMPolicyDescriptionForTheKMS
        )
        print("Created IAM Policy arn: ", response['Policy']['Arn'])
        # print("Description: ", response['Policy']['Description'])
        print("Policy Name: ", response['Policy']['PolicyName'])
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass
    # arn:aws:iam::0123456789012:policy/nda-kms-policy
    create_aliasForKmsKey()


def createCMK():
    global KeyARNis
    global KeyIDis
    response = kms.create_key(
        Description=KMSKeyDescription,
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS',
        BypassPolicyLockoutSafetyCheck=False,
        Tags=[{'TagKey': 'Name', 'TagValue': KMSKeyDescription}]
    )
    KeyARNis = response['KeyMetadata']['Arn']
    KeyIDis = response['KeyMetadata']['KeyId']
    print("Key ARN:", KeyARNis)
    create_iam_policy_for_kms()


# Get Arn for EC2 Policy with * (all access)
# cut suffix from a secret name to receive path
def rchop(string, suffix):
    if suffix and string.endswith(suffix):
        return string[:-len(suffix)]
    return string


def ParametersPath():
    global ParametersPath
    ParametersPath = rchop(ParameterARNis, secretName) + '*'
    print('Resource ARN for EC2 IAM Policy:', ParameterARNis)
    return ParametersPath


def getVar():
    ProjectName = input('Enter your project name:')
    IAMPolicyNameForTheKMS = input('IAM Policy Name For The KMS (for ex. <project>-KMS)): ')
    IAMPolicyDescriptionForTheKMS = 'Project:' \
                                    + ProjectName + '- Grants Encrypt\Decrypt permissions for the KMS Key ussage'
    KMSKeyDescription = ProjectName + ' Key'
    IAMPolicyNameForTheEC2 = input('IAM Policy Name For The EC2(for ex. <project>-EC2)): ')
    IAMPolicyDescriptionForTheEC2 = 'Project:' + ProjectName + '- Grants GetParameter and Decrypt permissions'
    InstanceProfile = input('EC2InstanceProfile: ')
    EC2GetSSMRole = ProjectName + 'EC2InstanceSSMrole'
    KMSAliasName = 'alias/' + ProjectName + '/ec2/kms'
    createCMK()


# Grant Permissions to Instance Profile:
# Now we will create a policy that can only decrypt and
# read values from SSM that matches the path: '/nda/mysql/mysql_*. '
# This policy will be associated to a instance profile role,
# which will be used by EC2, where our application will read the values from.

def create_ec2_policy():
    # The policy grants GetParameter and Decrypt
    # permissions and will be used for EC2 instance profile
    # Create a Policy
    IAMPolicyEC2 = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "EC2DecryptKeyPolicy",
          "Action": [
            "kms:Decrypt"
          ],
          "Effect": "Allow",
          "Resource": """ + "\"" + KeyARNis + "\"" + """
        },
        {
          "Sid": "GetSSMPolicy",
          "Action": [
            "ssm:GetParameter"
          ],
          "Effect": "Allow",
          "Resource": """ + "\"" + ParametersPath() + "\"" + """
        }
      ]
    }"""

    # Create a policy
    AssumeRolePolicyDocument = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EC2AssumeRole",
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }"""
    try:
        response = iam.create_policy(PolicyName=IAMPolicyNameForTheEC2, PolicyDocument=IAMPolicyEC2,
                                     Description=IAMPolicyDescriptionForTheEC2)
        print("Created IAM Policy arn:", response['Policy']['Arn'])
        IAMPolicyEC2arn = response['Policy']['Arn']
        # print("Description: ", response['Policy']['Description'])
        print("Policy Name:", response['Policy']['PolicyName'])
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


def add_param_question():
    answer = input('Parameter has been created/updated. '
                   '\nDo you want to add one more parameter(y/n)?')
    if answer == 'y' or answer == 'Y':
        put_parameter()
    # return tu menu
    elif menuAnswer == '2':
        menu()
    elif menuAnswer == '1':
        create_ec2_policy()


# Publish the Secrets to SSM:
# As the administrator, write the secret values to the parameter store in SSM.
# We will publish a secret with the Parameter: /nda/mysql/mysql_hostname and the Value: db01.us-east-1.mycompany.com:
def put_parameter():
    global secretPath
    global secretName
    global secretValue
    global secretDescription
    global secretNameFull
    global ParameterARNis
    secretPath = input('secret Path (for ex. /nda/ or leave it empty):')
    secretName = input('secret Name (for ex. MySQLPassword):')
    secretValue = getpass('secret Value (hidden):')
    secretDescription = input('secret Description (for ex. MySQL Password):')
    secretNameFull = secretPath + secretName
    ssm.put_parameter(
        Name=secretNameFull,
        Description=secretDescription,
        Value=secretValue,
        Type='SecureString',
        KeyId=KeyIDis,
        Overwrite=True
    )
    # Read the Parameter value from SSM with using decryption via KMS:
    response = ssm.get_parameter(Name=secretNameFull, WithDecryption=False)
    print('Encrypted', secretNameFull, 'Value:', response['Parameter']['Value'])
    ParameterARNis = response['Parameter']['ARN']
    print('Parameter', secretNameFull, 'ARN:', response['Parameter']['ARN'])
    add_param_question()


def find_active_kms_keys(KeyArn):
    response = kms.describe_key(KeyId=KeyArn)['KeyMetadata']['KeyState']
    return response


def listKeysArns():
    global kmsKeys
    print('Getting data. May take a while...')
    try:
        kmsKeys = [region['KeyArn'] for region in kms.list_keys(Limit=1000)['Keys']]
    except:
        print('There are no Keys...')
        pass
    enabledKeysArns = []
    for KeyArn in kmsKeys:
        if find_active_kms_keys(KeyArn) == 'Enabled':
            print("Key Arn (state:enabled): ", KeyArn)
            enabledKeysArns.append(KeyArn)
            try:
                AliasArn = kms.list_aliases(KeyId=KeyArn, Limit=1000)['Aliases'][0]['AliasArn']
                print('Its Alias Arn: ', AliasArn)
            except:
                print('Its Alias Arn: None')


def menu():
    global KeyIDis
    global menuAnswer
    print("""
    '1'="Create a new Parameter store with encryption Key, Key Policy, EC2 role attached to the instance"
    '2'="Add/update parameter in ParamStore. KeyArn, ParamStore path are required"
    '3'="List KMS keys aliases ARNs (limit 1000)"
    '4'="Exit"
    """)
    menuAnswer = input("Please Select:")
    if menuAnswer == '1':
        getVar()
    elif menuAnswer == '2':
        listKeysArns()
        KeyIDis = input(
            'secret Key Alias ARN (for ex. arn:aws:kms:us-east-1:4...2:key/1...3-9):')
        put_parameter()
    elif menuAnswer == '3':
        listKeysArns()
        menu()
    elif menuAnswer == '4':
        exit(0)
    else:
        print("Unknown Option Selected!")
        menu()


menu()


# Create instance profile:
def create_instance_profile():
    global InstanceProfileArn
    try:
        response = iam.create_instance_profile(InstanceProfileName=InstanceProfile)
        print("Created instance profile:", InstanceProfile)
        pprint.pprint(response)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass
    try:
        response = iam.get_instance_profile(
            InstanceProfileName=InstanceProfile
        )
        InstanceProfileArn = response["InstanceProfile"]["Arn"]
        print("Created instance profile ARN:", InstanceProfileArn)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


create_instance_profile()


# Create a Role:
def create_role():
    try:
        response = iam.create_role(RoleName=EC2GetSSMRole,
                                   AssumeRolePolicyDocument=AssumeRolePolicyDocument)
        print("Create a Role:", response)
        print("Created EC2 role:", EC2GetSSMRole)
        response = iam.attach_role_policy(
            RoleName=EC2GetSSMRole, PolicyArn=IAMPolicyEC2arn)
        print('Attach the role: ', response)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


create_role()


# Associate this Role and Instance Profile:
def associate_role():
    print('Associating created Role...')
    try:
        response = iam.add_role_to_instance_profile(InstanceProfileName=InstanceProfile, RoleName=EC2GetSSMRole)
        print('get response associateRole func')
        print(response)
        print("Added EC2 role", EC2GetSSMRole, 'to the Instance profile', InstanceProfile)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


associate_role()


# Attach the Policy to the Role:
def attach_policy():
    try:
        response = iam.put_role_policy(RoleName=EC2GetSSMRole, PolicyName=IAMPolicyNameForTheEC2,
                                       PolicyDocument=IAMPolicyEC2)
        print(response)
        print('Attached Policy', IAMPolicyNameForTheEC2, 'to the EC2 get ssm parameter role', EC2GetSSMRole,
              'the following Policy Document:', InstanceProfile)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


def disassociate_role_with_instance():
    answer = input("Do you want to remove the association(y)?")
    if answer == 'y' or answer == 'Y':
        response = ec2.disassociate_iam_instance_profile(
            AssociationId=associationID
        )
        print('The role has been disassociated with Instance Profile of your EC2 instance. Exiting...')
        print('State: ', response['IamInstanceProfileAssociation']['State'])
        handle_associations()
    else:
        print('Exiting...')
        menu()


def associate_iam_instance_profile():
    response = ec2.associate_iam_instance_profile(
        IamInstanceProfile={
            'Arn': InstanceProfileArn,
            'Name': InstanceProfile
        },
        InstanceId=InstanceID
    )
    NewAssociationId = response['IamInstanceProfileAssociation']['AssociationId']
    IamInstanceProfile = response['IamInstanceProfileAssociation']['IamInstanceProfile']
    NewState = response['IamInstanceProfileAssociation']['State']
    print('The role has been associated with the Instance Profile of your EC2 instance. Exiting...')
    print(
        'Instance ID: ', InstanceID,
        '\nThe new Association Id: ', NewAssociationId,
        '\nIamInstanceProfile: ', IamInstanceProfile,
        '\nAssociation state: ', NewState)
    menu()


# associate created Role with read SSM and KMS Decrypt ParamStore Policy with your Instance
# aws ec2 describe-iam-instance-profile-associations --filters "Name=instance-id,Values=i-0796d6d94492924db" --output text
# arn:aws:ssm:us-east-1:461181574132:parameter/nda/sql
def handle_associations():
    global associationID
    global InstanceID
    associationID = '[]'
    associationState = ''
    answer = input(
        "Do you want to attach the created role with SSM ParamStore access policy to your instance(y)?"
    )
    if answer == 'y' or answer == 'Y':
        response = ec2.describe_instances()
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                # This sample print will output entire Dictionary object
                print('Instances info: ')
                pretty.pprint(instance)
                # This will print will output the value of the Dictionary key 'InstanceId'
                print('Intances IDs: ')
                print(instance["InstanceId"])
        InstanceID = input(
            'To attach the new role to the Instance Profile of your EC2 instance please enter instance ID: '
        )
        try:
            listOfassociations = ec2.describe_iam_instance_profile_associations(
                Filters=[
                    {"Name": "instance-id", "Values": [InstanceID]}
                ]
            )
            if listOfassociations['IamInstanceProfileAssociations'] != '[]':
                associationID = listOfassociations['IamInstanceProfileAssociations'][0]['AssociationId']
                associationState = listOfassociations['IamInstanceProfileAssociations'][0]['State']
                print("Association ID: ", associationID, '\nAssociation state: ', associationState)
        except:
            pass
        if associationID != [] and associationState == 'associated' or associationState == 'associating':
            print('Your instance has the association with ID: ', associationID,
                  '\nOnly one is allowed. Disassociate it and try again...')
            disassociate_role_with_instance()
        else:
            associate_iam_instance_profile()
    else:
        print('Exiting...')
        menu()


handle_associations()
