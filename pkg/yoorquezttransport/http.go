package yoorquezttransport

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/tracing/zipkin"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztendpoint"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztservice"
	stdopentracing "github.com/opentracing/opentracing-go"
	stdzipkin "github.com/openzipkin/zipkin-go"
	"net/http"
)

// NewHTTPHandler returns an HTTP handler that makes a set of endpoints
// available on predefined paths.
func NewHTTPHandler(endpoints yoorqueztendpoint.Set, otTracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer, logger log.Logger) http.Handler {
	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(errorEncoder),
		httptransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
	}

	if zipkinTracer != nil {
		// Zipkin HTTP Server Trace can either be instantiated per endpoint with a
		// provided operation name or a global tracing service can be instantiated
		// without an operation name and fed to each Go kit endpoint as ServerOption.
		// In the latter case, the operation name will be the endpoint's http method.
		// We demonstrate a global tracing service here.
		options = append(options, zipkin.HTTPServerTrace(zipkinTracer))
	}

	mux := http.NewServeMux()
	mux.Handle("/signup", httptransport.NewServer(
		endpoints.SignupEndpoint,
		decodeHTTPSignupRequest,
		encodeHTTPGenericResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Signup", logger)))...,
	))
	mux.Handle("/login", httptransport.NewServer(
		endpoints.LoginEndpoint,
		decodeHTTPLoginRequest,
		encodeHTTPGenericResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "Login", logger)))...,
	))
	return mux
}

func errorEncoder(_ context.Context, err error, w http.ResponseWriter) {
	w.WriteHeader(err2code(err))
	json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})
}

func err2code(err error) int {
	switch err {
	case yoorqueztservice.ErrTwoZeroes, yoorqueztservice.ErrMaxSizeExceeded, yoorqueztservice.ErrIntOverflow:
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

type errorWrapper struct {
	Error string `json:"error"`
}

var (
	ErrBadRouting = errors.New("Error bad routing")
	ErrNotFound   = errors.New("Asset not found\n")
	ErrBadRequest = errors.New("Bad Request")
)

// decodeHTTPSignupRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded signup request from the HTTP request body. Primarily useful in a
// server.
func decodeHTTPSignupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var user data.User

	if r.Body == nil {
		return nil, ErrBadRequest
	}

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		return nil, errors.New(err.Error())
	} else {
		return user, nil
	}
}

// decodeHTTPLoginRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded signup request from the HTTP request body. Primarily useful in a
// server.
func decodeHTTPLoginRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var user data.User

	if r.Body == nil {
		return nil, ErrBadRequest
	}

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		return nil, errors.New(err.Error())
	} else {
		return user, nil
	}
}

// encodeHTTPGenericResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer. Primarily useful in a server.
func encodeHTTPGenericResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if f, ok := response.(endpoint.Failer); ok && f.Failed() != nil {
		errorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}
