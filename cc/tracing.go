package cc

import (
	"os"

	"github.com/anoideaopen/foundation/core/telemetry"
	pbfound "github.com/anoideaopen/foundation/proto"
	"go.opentelemetry.io/otel"
)

func (c *ACL) tracingHandler() *telemetry.TracingHandler {
	var th *telemetry.TracingHandler

	c.lockTH.RLock()
	if c.trHandler != nil {
		th = c.trHandler
	}
	c.lockTH.RUnlock()

	if th != nil {
		return th
	}

	c.lockTH.Lock()
	defer c.lockTH.Unlock()

	if c.trHandler != nil {
		return c.trHandler
	}

	c.setupTracing()

	return c.trHandler
}

func (c *ACL) setupTracing() {
	serviceName := "chaincode-" + ACLChaincodeName

	endpointFromEnv, ok := os.LookupEnv(telemetry.TracingCollectorEndpointEnv)

	traceConfig := c.traceConfigFromConfig()

	if c.isService && ok {
		traceConfig = &pbfound.CollectorEndpoint{
			Endpoint:                 endpointFromEnv,
			AuthorizationHeaderKey:   os.Getenv(telemetry.TracingCollectorAuthHeaderKey),
			AuthorizationHeaderValue: os.Getenv(telemetry.TracingCollectorAuthHeaderValue),
			TlsCa:                    os.Getenv(telemetry.TracingCollectorCaPem),
		}
	}

	telemetry.InstallTraceProvider(traceConfig, serviceName)

	th := &telemetry.TracingHandler{
		Tracer:      otel.Tracer(serviceName),
		Propagators: otel.GetTextMapPropagator(),
	}
	th.TracingInit()

	c.trHandler = th
}

func (c *ACL) traceConfigFromConfig() *pbfound.CollectorEndpoint {
	aclTraceConfig := c.config.GetTracingCollectorEndpoint()

	return &pbfound.CollectorEndpoint{
		Endpoint:                 aclTraceConfig.GetEndpoint(),
		AuthorizationHeaderKey:   aclTraceConfig.GetAuthorizationHeaderKey(),
		AuthorizationHeaderValue: aclTraceConfig.GetAuthorizationHeaderValue(),
		TlsCa:                    aclTraceConfig.GetTlsCa(),
	}
}
