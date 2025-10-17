package cc

import (
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

type AddUserRequest struct {
	PublicKey
	KYCHash      string
	UserID       string
	IsIndustrial bool
}

func addUser(stub shim.ChaincodeStubInterface, request AddUserRequest) error {
	if err := saveSignedAddress(
		stub,
		&pb.SignedAddress{
			Address: &pb.Address{
				UserID:       request.UserID,
				Address:      request.Hash,
				IsIndustrial: request.IsIndustrial,
				IsMultisig:   false,
			},
		},
		request.HashInHex,
		failIfExists,
	); err != nil {
		return fmt.Errorf("failed saving signed address: %w", err)
	}

	if err := savePublicKey(stub, request.PublicKey, newAddress); err != nil {
		return fmt.Errorf("failed saving public key: %w", err)
	}

	if err := saveAccountInfo(
		stub,
		&pb.AccountInfo{
			KycHash: request.KYCHash,
		},
		request.HashInBase58Check,
	); err != nil {
		return fmt.Errorf("failed saving account info: %w", err)
	}

	return nil
}

func addUserRequestFromArguments(args []string, withPublicKeyType bool) (AddUserRequest, error) {
	const (
		indexPublicKey = iota
		indexKYCHash
		indexUserID
		indexIsIndustrial
		indexPublicKeyType
	)

	const (
		requiredArgumentsCountWithoutKeyType = iota + indexPublicKeyType
		requiredArgumentsCountWithKeyType
	)

	const True = "true"

	requiredArgumentsCount := requiredArgumentsCountWithoutKeyType
	if withPublicKeyType {
		requiredArgumentsCount = requiredArgumentsCountWithKeyType
	}

	argsNum := len(args)
	if argsNum != requiredArgumentsCount {
		return AddUserRequest{}, fmt.Errorf(
			"incorrect number of arguments: %d, expected %d",
			argsNum, requiredArgumentsCount,
		)
	}

	publicKey, err := PublicKeyFromBase58String(args[indexPublicKey])
	if err != nil {
		return AddUserRequest{}, fmt.Errorf("failed decoding public key: %w", err)
	}

	kycHash := args[indexKYCHash]
	if len(kycHash) == 0 {
		return AddUserRequest{}, errors.New("empty kyc hash")
	}

	userID := args[indexUserID]
	if len(userID) == 0 {
		return AddUserRequest{}, errors.New("empty userID")
	}

	isIndustrial := args[indexIsIndustrial] == True

	if withPublicKeyType {
		publicKey.Type = args[indexPublicKeyType]
		if !helpers.ValidatePublicKeyType(publicKey.Type) {
			return AddUserRequest{}, fmt.Errorf("unknow public key type %s", args[indexPublicKeyType])
		}
	}

	if err = publicKey.validateLength(); err != nil {
		return AddUserRequest{}, fmt.Errorf("failed validating key length: %w", err)
	}

	return AddUserRequest{
		PublicKey:    publicKey,
		KYCHash:      kycHash,
		UserID:       userID,
		IsIndustrial: isIndustrial,
	}, nil
}
