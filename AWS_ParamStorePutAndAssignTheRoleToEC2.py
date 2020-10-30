from getpass import getpass
import logging
import boto3
import botocore
import pprint

logger = logging.getLogger(__name__)



welcome = "Welcome to the AWS SSM ParamStore. The app may put secrets to ParamStore, create related policies, roles, and instance profile"
print('-' * len(welcome))
print(welcome)
print('-' * len(welcome))


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


def create_alias_for_kms_key():
    # global kms_id_is
    # global kms_alias_name
    # #Create the KMS Alias:
    try:
        response = kms.create_alias(AliasName=kms_alias_name, TargetKeyId=key_id_is)
        print("Created an alias for your new KMS Key. Status code: ", response['ResponseMetadata']['HTTPStatusCode'])
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))



def create_iam_policy_for_kms():
    # JSON data:
    iam_policy_kms = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "IAMPolicyKMS",
          "Action": [
            "kms:Decrypt",
            "kms:Encrypt"
          ],
          "Effect": "Allow",
          "Resource": """ + "\"" + key_arn_is + "\"" + """
        }
      ]
    }"""
    print('IAM Policy for KMS', iam_policy_kms)

    # Create the IAM Policy:
    try:
        response = iam.create_policy(
            PolicyName=iam_policy_name_for_the_kms,
            PolicyDocument=iam_policy_kms,
            Description=iam_policy_description_for_the_kms
        )
        print("Created IAM Policy arn: ", response['Policy']['Arn'])
        # print("Description: ", response['Policy']['Description'])
        print("Policy Name: ", response['Policy']['PolicyName'])
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass



def create_cmk():
    global key_arn_is
    global key_id_is
    response = kms.create_key(
        Description=kms_key_description,
        KeyUsage='ENCRYPT_DECRYPT',
        Origin='AWS_KMS',
        BypassPolicyLockoutSafetyCheck=False,
        Tags=[{'TagKey': 'Name', 'TagValue': kms_key_description}]
    )
    key_arn_is = response['KeyMetadata']['Arn']
    key_id_is = response['KeyMetadata']['KeyId']
    print("Key ARN:", key_arn_is)
    print("Key ID:", key_id_is)



# Get Arn for EC2 Policy with * (all access)
# cut suffix from a secret name to receive path
def rchop(string, suffix):
    if suffix and string.endswith(suffix):
        return string[:-len(suffix)]
    return string


def get_parameters_path():
    parameters_path = rchop(parameter_arn_is, secret_name) + '*'
    print('Resource ARN for EC2 IAM Policy:', parameter_arn_is)
    return parameters_path


def get_var():
    global kms_key_description
    global iam_policy_name_for_the_kms
    global iam_policy_description_for_the_kms
    global iam_policy_name_for_the_ec2
    global iam_policy_description_for_the_kms
    global instance_profile
    global ec2_get_ssm_role
    global kms_alias_name
    project_name = input('Enter your project name:')
    iam_policy_name_for_the_kms = input('IAM Policy Name For The KMS (for ex. <project>-KMS)): ')
    iam_policy_description_for_the_kms = 'Project:' \
                                         + project_name + '. Grants Encrypt\Decrypt permissions for the KMS Key usage'
    kms_key_description = project_name + ' Key'
    iam_policy_name_for_the_ec2 = input('IAM Policy Name For The EC2(for ex. <project>-EC2)): ')
    iam_policy_description_for_the_kms = 'Project:' + project_name + '- Grants GetParameter and Decrypt permissions'
    instance_profile = input('EC2InstanceProfile: ')
    ec2_get_ssm_role = project_name + 'EC2InstanceSSMrole'
    kms_alias_name = 'alias/' + project_name + '/ec2/kms'



# Grant Permissions to Instance Profile:
# Now we will create a policy that can only decrypt and
# read values from SSM that matches the path: '/nda/mysql/mysql_*. '
# This policy will be associated to a instance profile role,
# which will be used by EC2, where our application will read the values from.

def create_ec2_policy():
    global assume_role_policy_document
    global iam_policy_ec2
    # The policy grants GetParameter and Decrypt
    # permissions and will be used for EC2 instance profile
    # Create a Policy
    iam_policy_ec2 = """{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "EC2DecryptKeyPolicy",
          "Action": [
            "kms:Decrypt"
          ],
          "Effect": "Allow",
          "Resource": """ + "\"" + key_arn_is + "\"" + """
        },
        {
          "Sid": "GetSSMPolicy",
          "Action": [
            "ssm:GetParameter"
          ],
          "Effect": "Allow",
          "Resource": """ + "\"" + get_parameters_path() + "\"" + """
        }
      ]
    }"""

    # Create a policy
    assume_role_policy_document = """{
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
        response = iam.create_policy(PolicyName=iam_policy_name_for_the_ec2, PolicyDocument=iam_policy_ec2,
                                     Description=iam_policy_name_for_the_ec2)
        print("Created IAM Policy ARN:", response['Policy']['Arn'])
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
    elif menu_answer == '1':
        create_ec2_policy()
    # return to menu
    elif menu_answer == '2':
        menu()



# Publish the Secrets to SSM:
# As the administrator, write the secret values to the parameter store in SSM.
# We will publish a secret with the Parameter: /nda/mysql/mysql_hostname and the Value: db01.us-east-1.mycompany.com:

def put_parameter():
    global key_id_is
    if menu_answer == '2' and key_id_is == '':
        key_id_is = input('Secret Key Alias ARN (for ex. arn:aws:kms:us-east-1:4...2:key/1...3-9): ')
    secret_path = input('secret Path (for ex. /nda/ or leave it empty):')
    secret_name = input('secret Name (for ex. MySQLPassword):')
    secret_value = getpass('secret Value (hidden):')
    secret_description = input('secret Description (for ex. MySQL Password):')
    secret_name_full = secret_path + secret_name
    ssm.put_parameter(
        Name=secret_name_full,
        Description=secret_description,
        Value=secret_value,
        Type='SecureString',
        KeyId=key_id_is,
        Overwrite=True
    )
    # Read the Parameter value from SSM with using decryption via KMS:
    response = ssm.get_parameter(Name=secret_name_full, WithDecryption=False)
    print('Encrypted', secret_name_full, 'Value:', response['Parameter']['Value'])
    parameter_arn_is = response['Parameter']['ARN']
    print('Parameter', secret_name_full, 'ARN:', response['Parameter']['ARN'])
    if menu_answer == '2':
        add_param_question()




def find_active_kms_keys(key_arn):
    response = kms.describe_key(KeyId=key_arn)['KeyMetadata']['KeyState']
    return response


def list_keys_arns():
    kms_keys = []
    print('Getting data. May take a while...')
    try:
        kms_keys = [region['KeyArn'] for region in kms.list_keys(Limit=1000)['Keys']]
    except:
        print('There are no Keys...')
        pass
    for key_arn in kms_keys:
        if find_active_kms_keys(key_arn) == 'Enabled':
            print("Key Arn (state:enabled): ", key_arn)
            try:
                alias_arn = kms.list_aliases(KeyId=key_arn, Limit=1000)['Aliases'][0]['AliasArn']
                print('Its Alias Arn: ', alias_arn)
            except:
                print('Its Alias Arn: None')


# Create instance profile:
def create_instance_profile():
    try:
        response = iam.create_instance_profile(InstanceProfileName=instance_profile)
        print("Created instance profile:", instance_profile)
        pprint.pprint(response)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass
    try:
        response = iam.get_instance_profile(
            InstanceProfileName=instance_profile
        )
        instance_profile_arn = response["InstanceProfile"]["Arn"]
        print("Created instance profile ARN:", instance_profile_arn)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


# create_instance_profile()


# Create a Role:
def create_role():
    try:
        response = iam.create_role(RoleName=ec2_get_ssm_role,
                                   AssumeRolePolicyDocument=assume_role_policy_document)
        print("Create a Role:", response)
        print("Created EC2 role:", ec2_get_ssm_role)
        response = iam.attach_role_policy(
            RoleName=ec2_get_ssm_role, PolicyArn=iam_policy_ec2arn)
        print('Attach the role: ', response)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


# create_role()


# Associate this Role and Instance Profile:
def associate_role():
    print('Associating created Role...')
    try:
        response = iam.add_role_to_instance_profile(InstanceProfileName=instance_profile, RoleName=ec2_get_ssm_role)
        print('get response associateRole func')
        print(response)
        print("Added EC2 role", ec2_get_ssm_role, 'to the Instance profile', instance_profile)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


# associate_role()


# Attach the Policy to the Role:
def attach_policy():
    try:
        response = iam.put_role_policy(RoleName=ec2_get_ssm_role, PolicyName=iam_policy_name_for_the_ec2,
                                       PolicyDocument=iam_policy_ec2)
        print(response)
        print('Attached Policy', iam_policy_name_for_the_ec2, 'to the EC2 get ssm parameter role', ec2_get_ssm_role,
              'the following Policy Document:', instance_profile)
    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    else:
        pass


def disassociate_role_with_instance():
    answer = input("Do you want to remove the association(y)?")
    if answer == 'y' or answer == 'Y':
        response = ec2.disassociate_iam_instance_profile(
            AssociationId=association_id
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
            'Arn': instance_profile_arn,
            'Name': instance_profile
        },
        InstanceId=instance_id
    )
    new_association_id = response['IamInstanceProfileAssociation']['AssociationId']
    iam_instance_profile = response['IamInstanceProfileAssociation']['IamInstanceProfile']
    new_state = response['IamInstanceProfileAssociation']['State']
    print('The role has been associated with the Instance Profile of your EC2 instance. Exiting...')
    print(
        'Instance ID: ', instance_id,
        '\nThe new Association Id: ', new_association_id,
        '\nIamInstanceProfile: ', iam_instance_profile,
        '\nAssociation state: ', new_state)
    menu()


# associate created Role with read SSM and KMS Decrypt ParamStore Policy with your Instance
# aws ec2 describe-iam-instance-profile-associations
# --filters "Name=instance-id,Values=i-0796d6d94492924db" --output text
# arn:aws:ssm:us-east-1:461181574132:parameter/nda/sql
def handle_associations():
    association_id = '[]'
    association_state = ''
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
                print('Instances IDs: ')
                print(instance["InstanceId"])
        instance_id = input(
            'To attach the new role to the Instance Profile of your EC2 instance please enter instance ID: '
        )
        try:
            list_of_associations = ec2.describe_iam_instance_profile_associations(
                Filters=[
                    {"Name": "instance-id", "Values": [instance_id]}
                ]
            )
            if list_of_associations['IamInstanceProfileAssociations'] != '[]':
                association_id = list_of_associations['IamInstanceProfileAssociations'][0]['AssociationId']
                association_state = list_of_associations['IamInstanceProfileAssociations'][0]['State']
                print("Association ID: ", association_id, '\nAssociation state: ', association_state)
        except botocore.exceptions.ParamValidationError as error:
            raise ValueError('The parameters you provided are incorrect: {}'.format(error))
        if association_id != [] and association_state == 'associated' or association_state == 'associating':
            print('Your instance has the association with ID: ', association_id,
                  '\nOnly one is allowed. Disassociate it and try again...')
            disassociate_role_with_instance()
        else:
            associate_iam_instance_profile()
    else:
        print('Exiting...')
        menu()

# handle_associations()

def menu():



    global key_id_is

    global iam_policy_ec2arn
    global iam_policy_ec2
    global iamPolicyKMS
    global menu_answer
    global parametersPath
    global key_arn_is
    global association_id
    global instance_id
    global instance_profile_arn
    global secret_path
    global secret_name
    global secret_value
    global secret_description
    global secret_name_full
    global parameter_arn_is
    global kms_keys
    print("""
    '1'="Create a new Parameter store with encryption Key, Key Policy, EC2 role attached to the instance"
    '2'="Add/update parameter in ParamStore. KeyArn, ParamStore path are required"
    '3'="List KMS keys aliases ARNs (limit 1000)"
    '4'="Exit"
    """)
    menu_answer = input("Please Select:")
    if menu_answer == '1':
        get_var()
        create_cmk()
        create_iam_policy_for_kms()
        create_alias_for_kms_key()
        put_parameter()
        add_param_question()
        create_instance_profile()
        create_role()
        associate_role()
        attach_policy()
        handle_associations()
    elif menu_answer == '2':
        key_id_is = ''
        list_keys_arns()
        put_parameter()
    elif menu_answer == '3':
        list_keys_arns()
        menu()
    elif menu_answer == '4':
        exit(0)
    else:
        print("Unknown option selected!")
        menu()

if __name__ == '__main__':
    menu()
