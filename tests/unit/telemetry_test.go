package unit

import (
	"context"
	"testing"

	"github.com/anoideaopen/acl/tests/common"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestTelemetry(t *testing.T) {
	const txID = "0"

	stub := common.StubCreateAndInitWithTelemetry(t)

	t.Run("invoke with tracing", func(t *testing.T) {
		tracerProvider := sdktrace.NewTracerProvider()
		tr := tracerProvider.Tracer("test")
		ctx, _ := tr.Start(context.Background(), "top-test")

		stub.SetTraceContext(ctx)

		resp := stub.MockInvokeTraced(
			txID,
			[]byte(common.FnAddUser), []byte(common.TestUsers[0].PublicKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue),
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	})

	t.Run("invoke without tracing", func(t *testing.T) {
		resp := stub.MockInvoke(
			txID,
			[][]byte{[]byte(common.FnAddUser), []byte(common.TestUsers[1].PublicKey), []byte(kycHash), []byte(testUserID), []byte(stateTrue)},
		)
		require.Equal(t, int32(shim.OK), resp.Status)
	})
}
