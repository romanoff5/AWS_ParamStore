from getpass import getpass
# import disassociateRoleWithInstance as ds
import boto3
import botocore
import pprint
import json

region = 'us-east-1'
print('Will use default region us-east-1...')

session = boto3.Session(region_name=region)
iam = session.client('iam')
kms = session.client('kms')
ssm = session.client('ssm')
ec2 = session.client('ec2')

roles = iam.list_roles()


# using the in operator
def count(dict):
    count = 0
    for x in dict:
        if isinstance(dict[x], list):
            count += len(dict[x])
    return count


RoleNames = []
InstanceProfiles = []
for i in range(0, count(roles)):
    # print(roles['Roles'][i]['RoleName'])
    RoleName = roles['Roles'][i]['RoleName']
    if RoleName.find('QuickSetup') and RoleName.find('AWS') and RoleName.find('Amazon') == -1:
        RoleNames.append(roles['Roles'][i]['RoleName'])
        profiles = iam.list_instance_profiles_for_role(RoleName=RoleName)
        # print(str(profiles))
        if str(profiles).find('[]') == -1:
            profileName = dict(profiles)['InstanceProfiles'][0]['InstanceProfileName']
            print(profileName)
            InstanceProfiles.append(profileName)
            removeRoleFromInstanceProfile = iam.remove_role_from_instance_profile(InstanceProfileName=profileName,
                                                                                  RoleName=RoleName)
            print(removeRoleFromInstanceProfile)
            removeInstanceProfile = iam.delete_instance_profile(InstanceProfileName=profileName)
            print(removeInstanceProfile)
# find all instance profiles
response = iam.list_instance_profiles()
pprint.pprint(response)
for i in range(0, count(response)):
    itemFromInstanceProfilesList = dict(response)['InstanceProfiles'][i]['InstanceProfileName']
    if itemFromInstanceProfilesList.find('AWS') or itemFromInstanceProfilesList.find('Amazon') == -1:
        try:
            deleteInstanceProfile = iam.delete_instance_profile(InstanceProfileName=itemFromInstanceProfilesList)
            pprint.pprint(deleteInstanceProfile)
        except:
            print('Cannot delete entity ', itemFromInstanceProfilesList,
                  ', must remove roles from instance profile first.')
            pass

#
#
policiesNames = dict(iam.list_policies(Scope='Local'))
# pprint.pprint(response)
# policiesNames=dict(response)#[0]['PolicyName']
pprint.pprint(policiesNames)
policiesNamesList = []
policiesARNsList = []
policiesARNs = []
for i in range(0, count(policiesNames)):
    PolicyARN = policiesNames['Policies'][i]['Arn']
    PolicyName = policiesNames['Policies'][i]['PolicyName']
    policiesNamesList.append(PolicyName)
    try:
        removePolicy = iam.delete_policy(PolicyArn=PolicyARN)
        policiesARNs.append(PolicyARN)
        print('removePolicy')
        pprint.pprint(removePolicy)
    except:
        print('Cannot delete a policy with ARN #:', PolicyARN, ' attached to entities.')
        pass
# policiesARNs=dict(response)['Policies']#[0]['Arn']
print('policiesNamesList')
pprint.pprint(policiesNamesList)
print('policiesARNs')
pprint.pprint(policiesARNs)
#
# for PolicyARN in policiesARNs:
#     try:
#         removePolicy = iam.delete_policy(PolicyArn=PolicyARN)
#     except:
#         print('')
# for role in RoleNames:
#     removeRole = iam.delete_role(RoleName=role)
print('RoleNames')
pprint.pprint(RoleNames)
print('InstanceProfiles')
pprint.pprint(InstanceProfiles)

for i in InstanceProfiles:
    try:
        deleteInstancePolicy = iam.delete_policy(PolicyArn=i)
        print(deleteInstancePolicy)
    except:
        print('Cannot delete entity', i, '.')
        pass

# response = iam.list_
listAttachedRolePol = []
for i in RoleNames:
    print('i: ', i)
    # try:
    listAttachedRolePolicies = iam.list_attached_role_policies(RoleName=i)

    listAttachedRolePolicies = dict(listAttachedRolePolicies)['AttachedPolicies']  # [0]#['PolicyArn']
    listAttachedRolePol.append(listAttachedRolePolicies)
    print('listAttachedRolePolicies', listAttachedRolePolicies)
    try:
        response = iam.delete_role(RoleName=i)
        print(response)
    except:
        print('Cannot delete entity', i, 'must delete policies first.')
        pass
print('listAttachedRolePol', listAttachedRolePol)

# for secondItem in listAttachedRolePolicies:
#     try:
#         deleteInstancePolicy = iam.delete_policy(PolicyArn=i)
#         print(deleteInstancePolicy)
#     except:
#         print('Cannot delete entity', i, '.')
#         pass
# deleteRoles = iam.delete_role(RoleName=i)
# print('deleteRoles')
# pprint.pprint(deleteRoles)
# #except:
# print('Cannot delete entity', i,', must delete policies first.')
# pass

listOfassociations = ec2.describe_iam_instance_profile_associations(
    Filters=[
        {"Name": "instance-id", "Values": [InstanceID]}
    ]
)
print('listOfassociations: ', listOfassociations)
if listOfassociations['IamInstanceProfileAssociations'] != '[]':
    associationID = listOfassociations['IamInstanceProfileAssociations'][0]['AssociationId']
    associationState = listOfassociations['IamInstanceProfileAssociations'][0]['State']
    print("Association ID: ", associationID, '\nAssociation state: ', associationState)
