# Multi-emission

Functionality for multi-issuance of platform tokens Atomyze.

## TOC

- [Multi-emission](#-multi-emission)
  - [TOC](#-toc)
  - [Description](#-description)
    - [API Spec](#-api-spec)
    - [Storage](#-storage)
      - [Accounts](#-accounts)
      - [AccountRights](#-accountrights)
      - [HaveRight](#-haveright)
  - [Links](#-links)

## Description

The current implementation of the foundation library and ACL chaincode allows for the installation of only one issuer for each token. The introduction of multi-issuance functionality will enable the creation of multiple issuances for a single token, owned by different issuers. This functionality is implemented in the ACL chaincode through an access matrix, which is a list of user roles and access for specific operations in a specific chaincode and channel.

### API Spec

The API within the multi-issuance functionality is extended with the following functions:

1. Adding permission for a user:  
  `addRights(args []string)`
  - args:  
    - channelName    - channel name
    - chaincodeName  - chaincode name
    - roleName       - role
    - operationName  - operation name, can be empty
    - addressEncoded - user address  
  - return value:  
    - nil - if the operation is successful
    - error - if there is an error
2. Removing permission for a user  
  `removeRights(args []string)`
  - args:  
    - channelName    - channel name
    - chaincodeName  - chaincode name
    - roleName       - role
    - operationName  - operation name, can be empty
    - addressEncoded - user address  
  - return value:  
    - nil - if the operation is successful
    - error - if there is an error
3. Checking the availability of permission to execute an operation for a role in a channel and chaincode at a user address 
  `getAccountOperationRight(args []string)`
  - args:  
    - channelName    - channel name
    - chaincodeName  - chaincode name
    - roleName       - role
    - operationName  - operation name, can be empty
    - addressEncoded - user address
  - return value:  
    - proto-message [HaveRight](#haveright) - if the operation is successful
    - error - if there is an error
4. Getting a list of existing user rights  
  `getAccountAllRights(args []string)`
  - args:  
    - addressEncoded - user address
  - return value:
    - proto-message [AccountRights](#accountrights) - if the operation is successful
    - error - if there is an error
5. Getting a list of addresses for which there is permission for an operation with a role in a channel and chaincode  
  `getOperationAllRights(args []string)`
  - args:  
    - channelName    - channel name
    - chaincodeName  - chaincode name
    - roleName       - role
    - operationName  - operation name, can be empty
  - return value:
    - proto-message [Accounts](#accounts) - if the operation is successful
    - error - if there is an error

### Storage

The functionality is implemented based on the ACL chaincode, and the data in the ledger is stored as follows:
- Under the key *acl_access_matrix_operation**, a list of addresses is stored in the format of the proto-message [Accounts](#accounts), which have permission to perform an operation with a specific role in a specific channel in a specific chaincode.
  `*` is the continuation of the key, which consists of: `"channel name" + "chaincode name" + "role" + "operation name"`, and the operation name can be empty.  
  Examples:
    - `acl_access_matrix_operationBAIVT.BARissuer` - list of allowed addresses for channel `BA`, chaincode `IVT.BAR`, role `issuer`, operation not specified;
    - `acl_access_matrix_operationnmmmultiNMMMULTIissuercreateEmissionApp` - list of allowed addresses for channel `nmmmulti`, chaincode `NMMMULTI`, role `issuer`, operation `createEmissionApp`;
- Under the key *acl_access_matrix_address**, a list of permissions is stored in the format of the proto-message [AccountRights](#accountrights).
  `*` is the continuation of the key, which consists of `"user address"`.  
  Examples:
    - `acl_access_matrix_address2datxk5TmB1spSNn9enVo11dcpgmUoSBSqCx5cCGoWq8qTbZog` - list of permissions for the user with the address `2datxk5TmB1spSNn9enVo11dcpgmUoSBSqCx5cCGoWq8qTbZog`

#### Accounts

```protobuf
syntax = "proto3";

message Accounts {
  repeated Address addresses = 1;
}

message Address {
  string userID     = 1;
  bytes address     = 2;
  bool isIndustrial = 3;
  bool isMultisig   = 4;
}
```

#### AccountRights

```protobuf
syntax = "proto3";

message AccountRights {
  Address address       = 1;
  repeated Right rights = 2;
}

message Right {
  string channelName   = 1;
  string chaincodeName = 2;
  string roleName      = 3;
  string operationName = 4;
  Address address      = 5;
  HaveRight haveRight  = 6;
}

message Address {
  string userID     = 1;
  bytes address     = 2;
  bool isIndustrial = 3;
  bool isMultisig   = 4;
}

message HaveRight {
  bool haveRight = 1;
}
```

#### HaveRight

```protobuf
syntax = "proto3";

message HaveRight {
  bool haveRight = 1;
}
```

All existing messages are stored in `foundation, proto/batch.proto`

## Links

* No
