package common

import (
	"context"
	"testing"

	"github.com/anoideaopen/acl/cc"
	aclproto "github.com/anoideaopen/acl/proto"
	"github.com/anoideaopen/foundation/core/telemetry"
	"github.com/anoideaopen/foundation/mock/stub"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/protobuf/encoding/protojson"
)

type StubWithTrace struct {
	*stub.Stub

	t   *testing.T
	ctx context.Context
}

const collectorEndpoint = "172.23.0.6:4318"

var TestInitConfigWithTelemetry = &aclproto.ACLConfig{
	AdminSKIEncoded: TestInitConfig.AdminSKIEncoded,
	Validators:      TestInitConfig.Validators,
	TracingCollectorEndpoint: &aclproto.TracingCollectorEndpoint{
		Endpoint: collectorEndpoint,
	},
}

func StubCreateAndInitWithTelemetry(t *testing.T) *StubWithTrace {
	aclStub := &StubWithTrace{
		Stub: stub.NewMockStub(cc.ACLChaincodeName, cc.New()),
		t:    t,
	}
	err := aclStub.SetAdminCreatorCert(TestCreatorMSP)
	require.NoError(t, err)

	cfgBytes, err := protojson.Marshal(TestInitConfigWithTelemetry)
	require.NoError(t, err)

	args := [][]byte{cfgBytes}
	rsp := aclStub.MockInit("0", args)
	require.Equal(t, shim.OK, int(rsp.GetStatus()))

	return aclStub
}

func (s *StubWithTrace) SetTraceContext(ctx context.Context) {
	s.ctx = ctx
}

func (s *StubWithTrace) MockInvokeTraced(uuid string, args ...[]byte) pb.Response {
	if s.ctx == nil {
		return s.MockInvoke(uuid, args)
	}

	input, err := proto.Marshal(&peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			ChaincodeId: &peer.ChaincodeID{
				Name: cc.ACLChaincodeName,
			},
			Input: &peer.ChaincodeInput{
				Args: args,
			},
		},
	})
	require.NoError(s.t, err)

	carrier := propagation.MapCarrier{}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.GetTextMapPropagator().Inject(s.ctx, carrier)

	transientMap, err := telemetry.PackToTransientMap(carrier)
	require.NoError(s.t, err)

	payload, err := proto.Marshal(&peer.ChaincodeProposalPayload{
		Input:        input,
		TransientMap: transientMap,
	})
	require.NoError(s.t, err)

	proposal, err := proto.Marshal(&peer.Proposal{Payload: payload})
	require.NoError(s.t, err)

	return s.MockInvokeWithSignedProposal(uuid, args, &peer.SignedProposal{
		ProposalBytes: proposal,
	})
}
