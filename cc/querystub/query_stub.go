package querystub

import (
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
)

type queryStub struct {
	shim.ChaincodeStubInterface
	args [][]byte
}

func NewQueryStub(stub shim.ChaincodeStubInterface, args ...string) shim.ChaincodeStubInterface {
	qs := &queryStub{
		ChaincodeStubInterface: stub,
		args:                   make([][]byte, 0, len(args)),
	}
	for _, arg := range args {
		qs.args = append(qs.args, []byte(arg))
	}

	return qs
}

func (qs *queryStub) PutState(_ string, _ []byte) error {
	return nil
}

func (qs *queryStub) DelState(_ string) error {
	return nil
}

func (qs *queryStub) SetStateValidationParameter(_ string, _ []byte) error {
	return nil
}

func (qs *queryStub) PutPrivateData(_ string, _ string, _ []byte) error {
	return nil
}

func (qs *queryStub) DelPrivateData(_, _ string) error {
	return nil
}

func (qs *queryStub) PurgePrivateData(_, _ string) error {
	return nil
}

func (qs *queryStub) SetPrivateDataValidationParameter(_, _ string, _ []byte) error {
	return nil
}

func (qs *queryStub) SetEvent(_ string, _ []byte) error {
	return nil
}

func (qs *queryStub) GetArgs() [][]byte {
	return qs.args
}

func (qs *queryStub) GetStringArgs() []string {
	args := qs.GetArgs()
	strargs := make([]string, 0, len(args))
	for _, barg := range args {
		strargs = append(strargs, string(barg))
	}
	return strargs
}

func (qs *queryStub) GetFunctionAndParameters() (function string, params []string) {
	allargs := qs.GetStringArgs()
	function = ""
	params = []string{}
	if len(allargs) >= 1 {
		function = allargs[0]
		params = allargs[1:]
	}
	return function, params
}

func (qs *queryStub) GetArgsSlice() ([]byte, error) {
	args := qs.GetArgs()
	res := []byte{} //nolint:prealloc
	for _, barg := range args {
		res = append(res, barg...)
	}
	return res, nil
}
