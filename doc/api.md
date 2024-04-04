# ACL API

ACL API

## TOC

- [ACL API](#acl-api)
  - [TOC](#toc)
  - [Description](#description)
  - [API](#api)
  - [Links](#links)
  - [License](#license)

## Description

## API

### Init chaincode

**Args:**

```
-c '{"Args":[adminSKI,validatorBase58Ed25519PublicKey1, ..., validatorBase58Ed25519PublicKeyN]}'
```

**Args:**

    [0]   adminSKI                           - SKI of administrator
    [1]   validatorsCount                    - number of validators (n)
    [2]   validatorBase58Ed25519PublicKey1   - validator 1   
    [n]   validatorBase58Ed25519PublicKeyN   - validator n   

#### User Management

- **AddUser** - adds user by public key to the platform
  - Not batch tx
  - **Args**:
    - args[0] - encoded base58 user publicKey
    - args[1] - Know Your Client (KYC) hash
    - args[2] - user identifier
    - args[3] - user can do industrial operation or not (boolean)
- **ChangePublicKey** - changes public key for user
  - Not batch tx
  - **Args**:
    - arg[0] - user's address (base58check)
    - arg[1] - reason (string)А
    - arg[2] - reason ID (string)
    - arg[3] - new key (base58)
    - arg[4] - nonce
    - arg[5:] - public keys and signatures of validators
- **ChangePublicKeyWithBase58Signature** - 
  - Not batch tx
  - **Args**:
    - arg[0] - Request ID
    - arg[1] - Chaincode name
    - arg[2] - Channel ID
    - arg[3] - User's address (base58check)
    - arg[4] - Reason (string)
    - arg[5] - Reason ID (string)
    - arg[6] - New key (base58)
    - arg[7] - Nonce
    - arg[8 and onwards] - List of validators' public keys and their corresponding signatures
- **Setkyc** - updates KYC for address
  - Not batch tx
  - **Args**:
    - arg[0] - address
    - arg[1] - KYC hash
    - arg[2] - nonce
    - arg[3:] - public keys and signatures of validators
- **SetAccountInfo** - sets account info (KYC hash, graylist and blacklist attributes) for address
  - Not batch tx
  - **Args**:
    - arg[0] - address
    - arg[1] - KYC hash
    - arg[2] - is address gray listed? ("true" or "false")
    - arg[3] - is address black listed? ("true" or "false")
- **GetAccountInfo** - returns json-serialized account info (KYC hash, graylist and blacklist attributes) for address
  - Not batch tx
  - **Args**:
    - arg[0] - address
- **CheckKeys** - returns AclResponse with account indo fetched by public keys
  - Not batch tx
  - **Args**:
    - args[0] - base58 encoded public key. if multisign is used, then public keys separated by `/`
- **CheckAddress** - checks if the address is graylisted
  - Not batch tx
  - **Args**:
    - args[0] - base58-encoded address
- **GetAddresses** - fetch all user addresses in json-serialized format with pagination
  - Not batch tx
  - **Args**:
    - args[0] - page size of pagination
    - args[1] - bookmark

#### Access Matrix

- **AddRights** - adds rights to the access matrix
  - Not batch tx
  - **Args**:
    - args[0] -> channelName
    - args[1] -GetOperationAllRights> chaincodeName
    - args[2] -> roleName
    - args[3] -> operationName
    - args[4] -> addressEncoded
- **RemoveRights** - removes rights from the access matrix
  - Not batch tx
  - **Args**:
    - args[0] -> channelName
    - args[1] -GetOperationAllRights> chaincodeName
    - args[2] -> roleName
    - args[3] -> operationName
    - args[4] -> addressEncoded
- **GetAccountOperationRight** - checks address have rights for the operation 
  - Not batch tx
  - **Args**:
    - args[0] -> channelName
    - args[1] -GetOperationAllRights> chaincodeName
    - args[2] -> roleName
    - args[3] -> operationName
    - args[4] -> addressEncoded
- **GetAccountAllRights** - returns all operations specified account have right to execute
  - Not batch tx
  - **Args**:
    - args[0] -> addressEncoded
- **GetOperationAllRights** - returns all accounts having right to execute specified operation
  - Not batch tx
  - **Args**:
    - args[0] -> channelName
    - args[1] -GetOperationAllRights> chaincodeName
    - args[2] -> roleName
    - args[3] -> operationName

#### Black/Gray lists management

- **AddToList** - sets address to gray list or black list
  - Not batch tx
  - **Args**:
    // arg[0] - address
    // arg[1] - "gray" of "black"
- **DelFromList** - removes address from gray list or 'black list
  - Not batch tx
  - **Args**:
    // arg[0] - address
    // arg[1] - "gray" of "black"

#### Multi Signature
- AddMultisig - creates multi-signature address which operates when N of M signatures is present
  - Not batch tx
  - **Args**:
    - args[0] request id
    - args[1] chaincodeName acl
    - args[2] channelID acl
    - args[3] N number of signature policy (number of sufficient signatures), M part is derived from number of public keys
    - args[4] nonce
    - args[5:] are the public keys and signatures base58 of all participants in the multi-wallet
    - and signatures confirming the agreement of all participants with the signature policy
- ChangeMultisigPublicKey - changes public key of multisig member
  - Not batch tx
  - **Args**:
    - arg[0] - multisig address (base58check)
    - arg[1] - old key (base58)
    - arg[2] - new key (base58)
    - arg[3] - reason (string)
    - arg[4] - reason ID (string)
    - arg[5] - nonce
    - arg[6:] - public keys and signatures of validators

## Links

* [legacy documentation](https://nwty.atlassian.net/wiki/spaces/ATMCORE/pages/3704182/ACL)

## License

Apache-2.0