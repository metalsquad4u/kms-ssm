import { Stack, StackProps } from 'aws-cdk-lib';
import { CdkCommand } from 'aws-cdk-lib/cloud-assembly-schema';
import { Construct } from 'constructs';
// import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cdk from '@aws-cdk/core';
import * as iam from '@aws-cdk/aws-iam';
import * as kms from '@aws-cdk/aws-kms';

import { PolicyStatement } from '@aws-cdk/aws-iam';
import { Effect } from '@aws-cdk/aws-iam';
import { ManagedPolicy } from '@aws-cdk/aws-iam';


export class sessionManagerStackAndKey extends cdk.Stack {

  public readonly kmskey: kms.Key;

  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    //Create Session Manager KMS Key Custom Policy in IT Account.
    const SessionManagerKeyPolicy = new iam.PolicyDocument({
      statements:[
        new PolicyStatement({
          sid: 'EnableIAMPoliciesInITAccount',
          effect: Effect.ALLOW,           
          actions:[
            'kms:*',
          ],
          principals: [
            new iam.AccountRootPrincipal(), 
            ],            
          resources: ['*'],
        }),

        new PolicyStatement({
          sid: 'AllowAccessForKeyAdministratorsInITAccount',
          effect: Effect.ALLOW,           
          actions:[
          'kms:Create*',
          'kms:Describe*',
          'kms:Enable*',
          'kms:List*',
          'kms:Put*',
          'kms:Update*',
          'kms:Revoke*',
          'kms:Disable*',
          'kms:Get*',
          'kms:Delete*',
          'kms:TagResource',
          'kms:UntagResource',
          'kms:ScheduleKeyDeletion',
          'kms:CancelKeyDeletion'
          ],
          principals: [
            //new iam.ArnPrincipal('arn:aws:iam::683578897984:user/iam-user'), 
            new iam.AnyPrincipal(),
            ],            
          resources: ['*'],
          
        }),

        new PolicyStatement({
          sid: 'AllowUseOfTheKeyByInternalAndExternalAccounts',
          effect: Effect.ALLOW,           
          actions:[
            'kms:Encrypt',
            'kms:Decrypt',
            'kms:ReEncrypt*',
            'kms:GenerateDataKey*',
            'kms:DescribeKey'
          ],
          principals: [
            new iam.AnyPrincipal()
            //new iam.ArnPrincipal('arn:aws:iam::127148144263:user/test-user'), 
            //new iam.ArnPrincipal('arn:aws:iam::127148144263:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_c5fd3c7b185f2316'),
            ],            
          resources: ['*'],
        }),

        new PolicyStatement({
          sid: 'AllowAttachmentOfPersistentResources',
          effect: Effect.ALLOW,           
          actions:[
            'kms:CreateGrant',
            'kms:ListGrants',
            'kms:RevokeGrant'
          ],
          principals: [
            new iam.AnyPrincipal()
            //new iam.ArnPrincipal('arn:aws:iam::127148144263:user/test-user'), 
            //new iam.ArnPrincipal('arn:aws:iam::127148144263:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_c5fd3c7b185f2316'),
            ],            
          resources: ['*'],
          conditions: {
            'Bool': {
                'kms:GrantIsForAWSResource': true
              }
          },
        }),
        
      ]
       
    });

    

    //Create Session Manager KMS Key in IT Account.
    this.kmskey = new kms.Key(this, 'SSMSessionKey', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pendingWindow: cdk.Duration.days(7),
      alias: 'alias/SSMSessionKey',
        description: 'KMS key for Session Manager Session Encryption',
        enableKeyRotation: false,
        //trustAccountIdentities: true, //Allow KMS key to trust IAM Policies
        //admins: [myTrustedAdminRole],
        policy: SessionManagerKeyPolicy,      
      });

      const ssmintancerolePolicy = new ManagedPolicy(this, 'SSMInstanceRolePolicy', {
        statements:[
          new PolicyStatement({
            sid: 'SSMManagedInstanceCoreS3CloudWatchLogsKMSKey',
            effect: Effect.ALLOW,
            actions: ['ssm:DescribeAssociation',
            'ssm:GetDeployablePatchSnapshotForInstance',
            'ssm:GetDocument',
            'ssm:DescribeDocument',
            'ssm:GetManifest',
            'ssm:GetParameters',
            'ssm:ListAssociations',
            'ssm:ListInstanceAssociations',
            'ssm:PutInventory',
            'ssm:PutComplianceItems',
            'ssm:PutConfigurePackageResult',
            'ssm:UpdateAssociationStatus',
            'ssm:UpdateInstanceAssociationStatus',
            'ssm:UpdateInstanceInformation',
            'ssmmessages:CreateControlChannel',
            'ssmmessages:CreateDataChannel',
            'ssmmessages:OpenControlChannel',
            'ssmmessages:OpenDataChannel',
            'ec2messages:AcknowledgeMessage',
            'ec2messages:DeleteMessage',
            'ec2messages:FailMessage',
            'ec2messages:GetEndpoint',
            'ec2messages:GetMessages',
            'ec2messages:SendReply',
            'ec2:DescribeInstanceStatus',
            'cloudwatch:PutMetricData',
            'ds:CreateComputer',
            'ds:DescribeDirectories',
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:DescribeLogGroups',
            'logs:DescribeLogStreams',
            'logs:PutLogEvents',
            's3:GetBucketLocation',
            's3:PutObject',
            's3:PutObjectAcl',
            's3:GetObject',
            's3:GetEncryptionConfiguration',
            's3:AbortMultipartUpload',
            's3:ListMultipartUploadParts',
            's3:ListBucket',
            's3:ListBucketMultipartUploads',
            'kms:GenerateDataKey'],
            resources: ['*'],
            
          }),
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['kms:Decrypt'],
            resources: [this.kmskey.keyArn],
            }),    
        ],
      });
      const role = new iam.Role(this, 'ec2SessionManagerRole', {
        assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
        description: 'EC2 Instance Role for Session Manager',
      });
      //Attach EC2 Instance Role Policy to Instance Role.
      role.addManagedPolicy(ssmintancerolePolicy);
  }
}

interface SsmStackProps extends cdk.StackProps {
  kmskey: kms.Key;
}

export class sessionManagerStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: SsmStackProps) {
    super(scope, id, props);

    const {kmskey} = props;

    const KEY_ARN = kmskey.keyArn;

    //const acctId = cdk.Stack.of(this).account;
    //const regionId = cdk.Stack.of(this).region;

    //Create EC2 Instance Role Policy for Session Manager.
    const ssmintancerolePolicy = new ManagedPolicy(this, 'SSMInstanceRolePolicy', {
      statements:[
        new PolicyStatement({
          sid: 'SSMManagedInstanceCoreS3CloudWatchLogsKMSKey',
          effect: Effect.ALLOW,
          actions: ['ssm:DescribeAssociation',
          'ssm:GetDeployablePatchSnapshotForInstance',
          'ssm:GetDocument',
          'ssm:DescribeDocument',
          'ssm:GetManifest',
          'ssm:GetParameters',
          'ssm:ListAssociations',
          'ssm:ListInstanceAssociations',
          'ssm:PutInventory',
          'ssm:PutComplianceItems',
          'ssm:PutConfigurePackageResult',
          'ssm:UpdateAssociationStatus',
          'ssm:UpdateInstanceAssociationStatus',
          'ssm:UpdateInstanceInformation',
          'ssmmessages:CreateControlChannel',
          'ssmmessages:CreateDataChannel',
          'ssmmessages:OpenControlChannel',
          'ssmmessages:OpenDataChannel',
          'ec2messages:AcknowledgeMessage',
          'ec2messages:DeleteMessage',
          'ec2messages:FailMessage',
          'ec2messages:GetEndpoint',
          'ec2messages:GetMessages',
          'ec2messages:SendReply',
          'ec2:DescribeInstanceStatus',
          'cloudwatch:PutMetricData',
          'ds:CreateComputer',
          'ds:DescribeDirectories',
          'logs:CreateLogGroup',
          'logs:CreateLogStream',
          'logs:DescribeLogGroups',
          'logs:DescribeLogStreams',
          'logs:PutLogEvents',
          's3:GetBucketLocation',
          's3:PutObject',
          's3:PutObjectAcl',
          's3:GetObject',
          's3:GetEncryptionConfiguration',
          's3:AbortMultipartUpload',
          's3:ListMultipartUploadParts',
          's3:ListBucket',
          's3:ListBucketMultipartUploads',
          'kms:GenerateDataKey'],
          resources: ['*'],
          
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt'],
          resources: [KEY_ARN],
          }),    
      ],
    });

    //Create Instance Role for Session Manager.
    const role = new iam.Role(this, 'ec2SessionManagerRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'EC2 Instance Role for Session Manager',
    });
    //Attach EC2 Instance Role Policy to Instance Role.
    role.addManagedPolicy(ssmintancerolePolicy);

    //Create policy to Allow External Account Users and Roles to Use Session Manager KMS Key in IT Account.
    const resourcePolicytoAllowexternalusers = new ManagedPolicy(this, 'ResourcePolicyToAllowExternalUsers', {
      statements:[
        new PolicyStatement({
          sid: 'AllowUseOfKMSKeyInITAccount',
          effect: Effect.ALLOW,
          actions:[
            'kms:Encrypt',
            'kms:Decrypt',
            'kms:ReEncrypt*',
            'kms:GenerateDataKey*',
            'kms:DescribeKey'
          ],
          //Remember to add the right resource
          resources: [KEY_ARN],
        }),

        new PolicyStatement({
          sid: 'AllowAttachmentOfPersistentResources',
          effect: Effect.ALLOW,
          actions: ['kms:CreateGrant',
          'kms:ListGrants',
          'kms:RevokeGrant'],
          //Remember to add the right resource
          resources: [KEY_ARN],
          conditions: {
            'Bool': {
                'kms:GrantIsForAWSResource': true
              }
          },
        }),       

      ]
       
    });

    //Create Users Policy to Use Session Manager Sessions.
   /* const ssmuserPermission = new ManagedPolicy(this, 'SSMUserPermission', {
      statements:[ 
        new PolicyStatement({
          sid: 'UserPermissionToUseSSM',
          effect: Effect.ALLOW,
          actions:[
            'ssm:StartSession',
            'ssm:SendCommand'
          ],
          resources:['arn:aws:ec2:*:*:instance/*',
          'arn:aws:ssm:' + cdk.Stack.of(this).region +':*:document/SSM-SessionManagerRunShell',
          'arn:aws:ssm:*:*:document/AWS-StartPortForwardingSession'],
          conditions: {
            'Bool': {
              'ssm:SessionDocumentAccessCheck': true
            }
          },
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions:[
            'ssm:DescribeSessions',
            'ssm:GetConnectionStatus',
            'ssm:DescribeInstanceInformation',
            'ssm:DescribeInstanceProperties',
            'ec2:DescribeInstances'
          ],
          resources:['*'],
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions:[
            'ssm:TerminateSession',
            'ssm:ResumeSession'
          ],
          //Confirm the username variable is working.
          resources:['arn:aws:ssm:*:*:session/${aws:username}-*'],
        }),
        new PolicyStatement({
          sid: '',
          effect: Effect.ALLOW,
          actions:[
            'kms:GenerateDataKey' 
          ],
          resources:[KEY_ARN],
        }),
        
        
      ]
    });

    //Create Admin Policy to delegate Session Manager Administration.
    const adminssmuserPermission = new ManagedPolicy(this, 'AdminSSMUserPermission', {
      statements:[ 
        new PolicyStatement({
          sid: 'AdminPermissionToConfigureSSM',
          effect: Effect.ALLOW,
          actions:[
            'ssm:StartSession',
            'ssm:SendCommand' 
          ],
          resources:[
            'arn:aws:ec2:' + cdk.Stack.of(this).region + ':' + cdk.Stack.of(this).account + ':instance/*'
          ],
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions:[
            'ssm:DescribeSessions',
            'ssm:GetConnectionStatus',
            'ssm:DescribeInstanceInformation',
            'ssm:DescribeInstanceProperties',
            'ec2:DescribeInstances'
          ],
          resources:['*'],
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions:[
            'ssm:CreateDocument',
            'ssm:UpdateDocument',
            'ssm:GetDocument',
            'ssm:DeleteDocument'
          ],
          resources:['arn:aws:ssm:'+ cdk.Stack.of(this).region + ':' + cdk.Stack.of(this).account + ':document/SSM-SessionManagerRunShell'],
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions:[
            'ssm:TerminateSession',
            'ssm:ResumeSession'
          ],
          //Confirm the username variable is working.
          resources:['arn:aws:ssm:*:*:session/${aws:username}-'],
        }),
      ]
    });*/
  }
}