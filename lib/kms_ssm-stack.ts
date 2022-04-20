
// import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cdk from '@aws-cdk/core';
import * as iam from '@aws-cdk/aws-iam';
import * as kms from '@aws-cdk/aws-kms';
import * as logs from '@aws-cdk/aws-logs';


import { PolicyStatement } from '@aws-cdk/aws-iam';
import { Effect } from '@aws-cdk/aws-iam';
import { ManagedPolicy } from '@aws-cdk/aws-iam';
import { ArnPrincipal } from '@aws-cdk/aws-iam';
import { RemovalPolicy } from '@aws-cdk/core';
import { AccountPrincipal } from '@aws-cdk/aws-iam';
import { AnyPrincipal } from '@aws-cdk/aws-iam';
import { publicEncrypt } from 'crypto';
import { assert } from 'console';


//===========================1st Stack for deployment into Master Accounts ====================//

export class sessionManagerStackAndKey extends cdk.Stack {

  public readonly kmskey: kms.Key; //

  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    //Create Encrypted LogGroup for Session Logs
    const logGroup = new logs.LogGroup(this, 'SMLogGroup', {
      logGroupName: 'SMLogGroup',     
      retention: logs.RetentionDays.ONE_DAY,
      //encryptionKey: this.kmskey,
      removalPolicy: RemovalPolicy.DESTROY
    });
    logGroup.grantWrite(new iam.ServicePrincipal('ssm.amazonaws.com'));
    

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
          sid: 'GrantAccessToKeyAdministratorsinITAccount',
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
            new ArnPrincipal('arn:aws:iam::AWS_ACCCOUNT:user/iam-user'),
            new ArnPrincipal('arn:aws:iam::AWS_ACCCOUNT:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_c7dj6xxxxxxxxxxxxx')
            ],            
          resources: ['*'],
        }),

        new PolicyStatement({
          sid: 'AllowUseOfThisKeyByLogsAndSSMInAllAccounts',
          effect: Effect.ALLOW,           
          actions:[
            'kms:Encrypt',
            'kms:Decrypt',
            'kms:ReEncrypt*',
            'kms:GenerateDataKey*',
            'kms:DescribeKey'
          ],
          principals: [
            new iam.ServicePrincipal('logs.amazonaws.com'),
            new iam.ServicePrincipal('ssm.amazonaws.com'),
            
          ],            
          resources: ['*'],
           conditions: {          
            ArnEquals : {
              "kms:EncryptionContext:aws:logs:arn": logGroup.logGroupArn
          }
          },
        }),      
      ]       
    });

    
    //Create Session Manager KMS Key in IT Account.
    this.kmskey = new kms.Key(this, 'SessionManagerKMSKey', {
      //const kmskey = new kms.Key(this, 'SessionManagerKMSKey', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pendingWindow: cdk.Duration.days(7),
      alias: 'alias/SessionManagerKMSKey',
      description: 'KMS key for Session Manager Session and Session Logs Encryption',
      enableKeyRotation: false,
      policy: SessionManagerKeyPolicy,      
    });


    const sessionManagerRolePolicy = new ManagedPolicy(this, 'SessionManagerRolePolicy', {
      description: 'Custom Policy to Grant EC2 Instances Permission to Use Session Manager.',
      managedPolicyName: 'SessionManagerRolePolicy',
      statements:[
        new PolicyStatement({
          sid: 'SSMManagedInstanceCoreS3CloudWatchLogsKMSKey',
          effect: Effect.ALLOW,
          actions: [
          'ssm:DescribeAssociation',
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
          'kms:GenerateDataKey'
        ],
          resources: ['*'], 
        }),
        new PolicyStatement({
          sid: 'ForEC2InstanceToDecryptSessionData',
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt'],
          resources: [this.kmskey.keyArn],
          }),    
      ],
    });
      //
      const role = new iam.Role(this, 'SessionManagerRole', {
        roleName: 'SessionManagerRole',
        assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
        description: 'EC2 Instance Role for Session Manager',
        maxSessionDuration: cdk.Duration.hours(4),
      });
      //Attach EC2 Instance Role Policy to Instance Role.
      role.addManagedPolicy(sessionManagerRolePolicy);

      //Create Session Manager Role Instance Profile
      const sessionManagerRoleInstanceProfile = new iam.CfnInstanceProfile(this, 'SessionManagerRoleInstanceProfile', 
      {
        roles: ['SessionManagerRole'],
        instanceProfileName: 'SessionManagerRoleInstanceProfile',
      });
          
  }
}

interface SsmStackProps extends cdk.StackProps {
  kmskey: kms.Key;
}


//===========================2nd Stack for deployment into Other Accounts====================//
export class sessionManagerStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: SsmStackProps) {
    super(scope, id, props);

    const {kmskey} = props;

    const KEY_ARN = kmskey.keyArn;

     //Create Encrypted LogGroup for Session Logs
     const logGroup = new logs.LogGroup(this, 'SMLogGroup', {
      logGroupName: 'SMLogGroup',     
      retention: logs.RetentionDays.ONE_DAY,
      encryptionKey: kmskey,
      removalPolicy: RemovalPolicy.DESTROY
    });
    logGroup.grantWrite(new iam.ServicePrincipal('ssm.amazonaws.com'));

    //Create EC2 Instance Role Policy for Session Manager.
    const sessionManagerRolePolicy = new ManagedPolicy(this, 'SessionManagerRolePolicy', {
      description: 'Custom Policy to Grant EC2 Instances Permission to Use Session Manager.',
      managedPolicyName: 'SessionManagerRolePolicy',
      statements:[
        new PolicyStatement({
          sid: 'SSMManagedInstanceCoreS3CloudWatchLogsKMSKey',
          effect: Effect.ALLOW,
          actions: [
          'ssm:DescribeAssociation',
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
          sid: 'ForEC2InstanceToDecryptSessionData',
          effect: Effect.ALLOW,
          actions: ['kms:Decrypt'],
          resources: [KEY_ARN],
          }),    
      ],
    });

    //Create Instance Role for Session Manager.
    const role = new iam.Role(this, 'SessionManagerRole', {
      roleName: 'SessionManagerRole',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'EC2 Instance Role for Session Manager',
      maxSessionDuration: cdk.Duration.hours(4),
    });
    
    //Attach EC2 Instance Role Policy to Instance Role.
    role.addManagedPolicy(sessionManagerRolePolicy);
    
  }
}
