#!/usr/bin/env node
import 'source-map-support/register';
//import * as cdk from 'aws-cdk-lib';
import * as cdk from '@aws-cdk/core';
import { sessionManagerStackAndKey, sessionManagerStack } from '../lib/ssm_stack-stack';

const app = new cdk.App();

//IT Account Stack to deploy Session Manager, Policies, and KMS Key.
const smkmsStack = new sessionManagerStackAndKey(app, 'SessionManagerStackAndKey', { //KMStoITAccount
  stackName: 'SessionManagerStackAndKey',
  description: 'This stack is used to deploy Session Manager and KMS Key to encrypt sessions.',
  env: {
    region: process.env.CDK_DEFAULT_REGION,
    account: process.env.CDK_DEFAULT_ACCOUNT,
  },
});

//Other Accounts Stack to deploy Session Manager and Policies.
const prodAcct = { account: 'AWS_ACCOUNT_ID', region: 'us-east-1'};

new sessionManagerStack(app, 'SessionManagerStack', {
  kmskey : smkmsStack.kmskey,
  stackName: 'SessionManagerStack',
  description: 'This stack is used to deploy Session Manager and policies for using Session Manager.',
  env:prodAcct,
});


