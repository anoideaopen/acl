# Chaincode init

ACL chaincode initialization

## TOC

- [Chaincode init](#-chaincode-init)
  - [TOC](#-toc)
  - [Description](#-description)
    - [Init parameters](#-init-parameters)
    - [Examples](#-examples)
  - [Links](#-links)

## Description

Stores information about ACL init and it's details

### Init parameters

| Parameter position | Parameter Name          | Parameter type | Parameter description                            |
|--------------------|-------------------------| -------------- |--------------------------------------------------|
| 1                  | AminSKI                 | string         | Subject Key Identifier (SKI) of chaincode        |
| 2                  | ValidatorsCount         | string         | Validators count                                 |
| 3                  | Validator base58-pubkey | string         | public key is ed25519 type, base58 encoded       |

NOTE: If validators count set to "3" you should set 3 validators base58-pubkey.

### Examples

Example, 1 validator:
```json
{
  "Args":[
    "f0197c42ce7a178073de4a2075be04331f79c73db54495252bdddcb26d598125",
    "1",
    "5DgC8ewcTMqJ33AJjiiqQ2h3r6VNEXU96fJB8vHHLAwF"
  ]
}
```

Example, 2 validators:
```json
{
  "Args":[
    "f0197c42ce7a178073de4a2075be04331f79c73db54495252bdddcb26d598125",
    "2",
    "5DgC8ewcTMqJ33AJjiiqQ2h3r6VNEXU96fJB8vHHLAwF",
    "4YB5nQ4zYcZSuKHqzzmc2BQdbDgcXLSWKbstaxf8SjPt"
  ]
}
```

## Links

* No