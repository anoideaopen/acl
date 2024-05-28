package cc

import (
	"errors"
	"fmt"

	"github.com/anoideaopen/acl/helpers"
	pb "github.com/anoideaopen/foundation/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
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
				Address:      request.PublicKey.Hash,
				IsIndustrial: request.IsIndustrial,
				IsMultisig:   false,
			},
		},
		request.PublicKey.HashInHex,
		FailIfExists,
	); err != nil {
		return fmt.Errorf("failed saving signed address: %w", err)
	}

	if err := savePublicKey(stub, request.PublicKey); err != nil {
		return fmt.Errorf("failed saving public key: %w", err)
	}

	if err := saveAccountInfo(
		stub,
		&pb.AccountInfo{
			KycHash: request.KYCHash,
		},
		request.PublicKey.HashInBase58Check,
	); err != nil {
		return fmt.Errorf("failed saving account info: %w", err)
	}

	return nil
}

func addUserRequestFromArguments(args []string) (AddUserRequest, error) {
	const (
		publicKeyPosition = iota
		kycHashPosition
		userIDPosition
		isIndustrialPosition
		publicKeyTypePosition
	)

	const (
		requiredArgumentsCount = iota + publicKeyTypePosition
		requiredArgumentsCountWithKeyType
	)

	argsNum := len(args)
	if argsNum != requiredArgumentsCount && argsNum != requiredArgumentsCountWithKeyType {
		return AddUserRequest{}, fmt.Errorf(
			"incorrect number of arguments: %d, expected %d or %d",
			argsNum, requiredArgumentsCount, requiredArgumentsCountWithKeyType,
		)
	}

	publicKey, err := publicKeyFromBase58String(args[publicKeyPosition])
	if err != nil {
		return AddUserRequest{}, fmt.Errorf("failed decoding public key: %w", err)
	}

	kycHash := args[kycHashPosition]
	if len(kycHash) == 0 {
		return AddUserRequest{}, errors.New("empty kyc hash")
	}

	userID := args[userIDPosition]
	if len(userID) == 0 {
		return AddUserRequest{}, errors.New("empty userID")
	}

	isIndustrial := helpers.ParseBool(args[isIndustrialPosition])

	if argsNum == requiredArgumentsCountWithKeyType {
		var ok bool
		publicKey.Type, ok = textToKeyType[args[publicKeyTypePosition]]
		if !ok {
			return AddUserRequest{}, fmt.Errorf("unknow public key type %s", args[publicKeyTypePosition])
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
