#!/usr/bin/env node
import 'source-map-support/register';
//import * as cdk from 'aws-cdk-lib';
import * as cdk from '@aws-cdk/core';
import { sessionManagerStackAndKey, sessionManagerStack } from '../lib/kms_ssm-stack';

const app = new cdk.App();

//IT Account Stack to deploy Session Manager, Policies, and KMS Key.
const smkmsStack = new sessionManagerStackAndKey(app, 'SessionManagerStackAndKey', { //KMStoITAccount
  stackName: 'SessionManagerStackAndKey',
  description: 'This stack is used to deploy Session Manager and KMS Key to encrypt sessions.',
  env: {
    region: 'us-east-1',
    account: '683578897984',
  },
});

//Other Accounts Stack to deploy Session Manager and Policies.
const prodAcct = { account: '683578897984', region: 'us-east-1'};

new sessionManagerStack(app, 'SessionManagerStack', {
  kmskey : smkmsStack.kmskey,
  stackName: 'SessionManagerStack',
  description: 'This stack is used to deploy Session Manager and policies for using Session Manager.',
  env:prodAcct,
});


