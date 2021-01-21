package yoorqueztendpoint
import (
	"context"
	"time"

	"golang.org/x/time/rate"

	stdopentracing "github.com/opentracing/opentracing-go"
	stdzipkin "github.com/openzipkin/zipkin-go"
	"github.com/sony/gobreaker"

	"github.com/go-kit/kit/circuitbreaker"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/ratelimit"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/tracing/zipkin"

	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztservice"
)

// Set collects all of the endpoints that compose an add service. It's meant to
// be used as a helper struct, to collect all of the endpoints into a single
// parameter.
type Set struct {
	SignupEndpoint endpoint.Endpoint
	ConcatEndpoint endpoint.Endpoint
}

// New returns a Set that wraps the provided server, and wires in all of the
// expected endpoint middlewares via the various parameters.
func New(svc yoorqueztservice.Service, logger log.Logger, duration metrics.Histogram, otTracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer) Set {
	var signupEndpoint endpoint.Endpoint
	{
		signupEndpoint = MakeSignupEndpoint(svc)
		// Signup is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		signupEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), 1))(signupEndpoint)
		signupEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(signupEndpoint)
		signupEndpoint = opentracing.TraceServer(otTracer, "Signup")(signupEndpoint)
		if zipkinTracer != nil {
			signupEndpoint = zipkin.TraceEndpoint(zipkinTracer, "Signup")(signupEndpoint)
		}
		signupEndpoint = LoggingMiddleware(log.With(logger, "method", "Signup"))(signupEndpoint)
		signupEndpoint = InstrumentingMiddleware(duration.With("method", "Signup"))(signupEndpoint)
	}
	var concatEndpoint endpoint.Endpoint
	{
		concatEndpoint = MakeConcatEndpoint(svc)
		// Concat is limited to 1 request per second with burst of 100 requests.
		// Note, rate is defined as a number of requests per second.
		concatEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(concatEndpoint)
		concatEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(concatEndpoint)
		concatEndpoint = opentracing.TraceServer(otTracer, "Concat")(concatEndpoint)
		if zipkinTracer != nil {
			concatEndpoint = zipkin.TraceEndpoint(zipkinTracer, "Concat")(concatEndpoint)
		}
		concatEndpoint = LoggingMiddleware(log.With(logger, "method", "Concat"))(concatEndpoint)
		concatEndpoint = InstrumentingMiddleware(duration.With("method", "Concat"))(concatEndpoint)
	}
	return Set{
		SignupEndpoint: signupEndpoint,
		ConcatEndpoint: concatEndpoint,
	}
}

// Signup implements the service interface, so Set may be used as a service.
// This is primarily useful in the context of a client library.
func (s Set) Signup(ctx context.Context, a, b int) (int, error) {
	resp, err := s.SignupEndpoint(ctx, SignupRequest{A: a, B: b})
	if err != nil {
		return 0, err
	}
	response := resp.(SignupResponse)
	return response.V, response.Err
}

// Concat implements the service interface, so Set may be used as a
// service. This is primarily useful in the context of a client library.
func (s Set) Concat(ctx context.Context, a, b string) (string, error) {
	resp, err := s.ConcatEndpoint(ctx, ConcatRequest{A: a, B: b})
	if err != nil {
		return "", err
	}
	response := resp.(ConcatResponse)
	return response.V, response.Err
}

// MakeSignupEndpoint constructs a Signup endpoint wrapping the service.
func MakeSignupEndpoint(s yoorqueztservice.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(SignupRequest)
		v, err := s.Signup(ctx, req.A, req.B)
		return SignupResponse{V: v, Err: err}, nil
	}
}

// MakeConcatEndpoint constructs a Concat endpoint wrapping the service.
func MakeConcatEndpoint(s yoorqueztservice.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ConcatRequest)
		v, err := s.Concat(ctx, req.A, req.B)
		return ConcatResponse{V: v, Err: err}, nil
	}
}

// compile time assertions for our response types implementing endpoint.Failer.
var (
	_ endpoint.Failer = SignupResponse{}
	_ endpoint.Failer = ConcatResponse{}
)

// SignupRequest collects the request parameters for the Signup method.
type SignupRequest struct {
	A, B int
}

// SignupResponse collects the response values for the Signup method.
type SignupResponse struct {
	V   int   `json:"v"`
	Err error `json:"-"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r SignupResponse) Failed() error { return r.Err }

// ConcatRequest collects the request parameters for the Concat method.
type ConcatRequest struct {
	A, B string
}

// ConcatResponse collects the response values for the Concat method.
type ConcatResponse struct {
	V   string `json:"v"`
	Err error  `json:"-"`
}

// Failed implements endpoint.Failer.
func (r ConcatResponse) Failed() error { return r.Err }
