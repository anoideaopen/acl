package unit

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/anoideaopen/acl/cc"
	aclproto "github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/acl/tests/common"
	"github.com/anoideaopen/acl/tests/unit/mock"
	"github.com/anoideaopen/foundation/core/telemetry"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestTelemetry(t *testing.T) {
	mockStub := newMockStub(t)

	t.Run("invoke without tracing", func(t *testing.T) {
		mockStub.GetFunctionAndParametersReturns(
			common.FnAddUser,
			[]string{common.TestUsers[0].PublicKey, kycHash, testUserID, stateTrue},
		)

		response := cc.New().Invoke(mockStub)
		require.Equal(t, shim.OK, int(response.GetStatus()))
	})

	t.Run("invoke with tracing", func(t *testing.T) {
		mockStub = addTelemetryToMockStub(t, mockStub)

		mockStub.GetFunctionAndParametersReturns(
			common.FnAddUser,
			[]string{common.TestUsers[1].PublicKey, kycHash, testUserID, stateTrue},
		)

		response := cc.New().Invoke(mockStub)
		require.Equal(t, shim.OK, int(response.GetStatus()))
	})
}

func newMockStub(t *testing.T) *mock.ChaincodeStub {
	const txID = "0"

	mockStub := new(mock.ChaincodeStub)

	mockStub.GetTxIDReturns(txID)

	cfgBytes, err := protojson.Marshal(common.TestInitConfig)
	require.NoError(t, err)

	mockStub.GetStateCalls(func(s string) ([]byte, error) {
		switch s {
		case "__config":
			return cfgBytes, nil
		}

		return nil, nil
	})

	mockStub.GetSignedProposalReturns(&peer.SignedProposal{}, nil)
	pCert, _ := pem.Decode([]byte(common.AdminCert))
	parsed, err := x509.ParseCertificate(pCert.Bytes)
	require.NoError(t, err)

	marshaledIdentity, err := common.MarshalIdentity(common.TestCreatorMSP, parsed.Raw)
	require.NoError(t, err)

	mockStub.GetCreatorReturns(marshaledIdentity, nil)

	return mockStub
}

func addTelemetryToMockStub(t *testing.T, mockStub *mock.ChaincodeStub) *mock.ChaincodeStub {
	const collectorEndpoint = "172.23.0.6:4318"

	var testInitConfigWithTelemetry = &aclproto.ACLConfig{
		AdminSKIEncoded: common.TestInitConfig.GetAdminSKIEncoded(),
		Validators:      common.TestInitConfig.GetValidators(),
		TracingCollectorEndpoint: &aclproto.TracingCollectorEndpoint{
			Endpoint: collectorEndpoint,
		},
	}

	cfgBytes, err := protojson.Marshal(testInitConfigWithTelemetry)
	require.NoError(t, err)

	mockStub.GetStateCalls(func(s string) ([]byte, error) {
		switch s {
		case "__config":
			return cfgBytes, nil
		}

		return nil, nil
	})

	tracerProvider := sdktrace.NewTracerProvider()
	tr := tracerProvider.Tracer("test")
	ctx, _ := tr.Start(context.Background(), "top-test")

	carrier := propagation.MapCarrier{}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.GetTextMapPropagator().Inject(ctx, carrier)

	mockStub.GetTransientReturns(telemetry.PackToTransientMap(carrier))

	return mockStub
}
