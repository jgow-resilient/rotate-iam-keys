// A simple lambda function to revoke IAM roles of groups periodically
// By @dvdtoth

'use strict';

const aws = require('aws-sdk');
const iam = new aws.IAM();

// Update an access key by id
function updateAccessKey(id, username) {

  let params = {
    AccessKeyId: id,
    Status: "Inactive",
    UserName: username
  };

  return iam.updateAccessKey(params).promise()
    .catch(err => {
      // Key might have been deleted already if user is in multiple groups
      if (err.code == "NoSuchEntity") {
        Promise.resolve();
      }
      else {
        throw err;
      }
    })
}

// Update access keys of username
function updateByUser(username) {

  let params = {
    UserName: username
  };

  return iam.listAccessKeys(params).promise()
    .then(data => {
      return Promise.all(data.AccessKeyMetadata.map(metadata => {
        console.log('Deactivating access key ' + metadata.AccessKeyId + ' for user ' + username);
        return updateAccessKey(metadata.AccessKeyId, username);
      }))
    })
}

// Update all keys for users in group
function updateKeysInGroup(group) {

  let params = {
    GroupName: group,
  };

  return iam.getGroup(params).promise()
    .then(group_data => {
      let group_users = group_data.Users;
      return Promise.all(group_data.Users.map(user => {
        return updateByUser(user.UserName);
      }))
    })
}

// AWS Lambda handler
module.exports.revoke = (event, context, callback) => {

  // clear whitespaces, split by comma
  let groups = process.env.GROUPS.replace(/\s/g, '').split(',');

  // Update access keys asynchronously from groups
  Promise.all(groups.map(updateKeysInGroup))
    .then(data => {
      callback(null, {
        message: 'Keys successfully deactivated',
        event
      });
    })

    .catch(err => {
      callback(err, {
        message: 'Failed to deactivate keys',
        event
      });
    })
}