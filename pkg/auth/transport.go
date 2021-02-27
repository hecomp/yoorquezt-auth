package auth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	"net/http"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/tracing/zipkin"
	"github.com/go-kit/kit/transport"
	kithttp "github.com/go-kit/kit/transport/http"
	stdopentracing "github.com/opentracing/opentracing-go"
	stdzipkin "github.com/openzipkin/zipkin-go"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/pkg/helper"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
)

var (
	ErrBadRouting = errors.New("Error bad routing")
	ErrNotFound   = errors.New("Asset not found\n")
	ErrBadRequest = errors.New("Bad Request")
)

func MakeHandler(endpoints Set, otTracer stdopentracing.Tracer, validator *data.Validation, repo signup.Repository, zipkinTracer *stdzipkin.Tracer, logger kitlog.Logger, configs *utils.Configurations) http.Handler {
	options := []kithttp.ServerOption{
		kithttp.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		kithttp.ServerErrorEncoder(encodeError),
	}

	if zipkinTracer != nil {
		// Zipkin HTTP Server Trace can either be instantiated per endpoint with a
		// provided operation name or a global tracing service can be instantiated
		// without an operation name and fed to each Go kit endpoint as ServerOption.
		// In the latter case, the operation name will be the endpoint's http method.
		// We demonstrate a global tracing service here.
		options = append(options, zipkin.HTTPServerTrace(zipkinTracer))
	}

	authHelper := helper.NewHelper(logger, nil, validator, repo, configs)

	mux := http.NewServeMux()

	mux2 := http.NewServeMux()

	signupHandler := kithttp.NewServer(
		MiddlewareValidateUser(logger, authHelper)(endpoints.SignupEndpoint),
		decodeHTTPSignupRequest,
		encodeResponse,
		append(options, kithttp.ServerBefore(opentracing.HTTPToContext(otTracer, "Signup", logger), kithttp.PopulateRequestContext))...,
	)
	loginHandler := kithttp.NewServer(
		MiddlewareValidateUser(logger, authHelper)(endpoints.LoginEndpoint),
		decodeHTTPLoginRequest,
		encodeResponse,
		append(options, kithttp.ServerBefore(opentracing.HTTPToContext(otTracer, "Login", logger), kithttp.PopulateRequestContext))...,
	)
	verifyMailHandler := kithttp.NewServer(
		MiddlewareValidateVerificationData(logger, validator)(endpoints.VerifyMailEndpoint),
		decodeHTTPVerifyMailRequest,
		encodeResponse,
		append(options, kithttp.ServerBefore(opentracing.HTTPToContext(otTracer, "Verify", logger), kithttp.PopulateRequestContext))...,
	)
	passwordResetHandler := kithttp.NewServer(
		MiddlewareValidateVerificationData(logger, validator)(endpoints.VerifyPasswordResetEndpoint),
		decodeHTTPVerifyPasswordResetRequest,
		encodeResponse,
		append(options, kithttp.ServerBefore(opentracing.HTTPToContext(otTracer, "PasswordReset", logger), kithttp.PopulateRequestContext))...,
	)
	refreshTokenHandler := kithttp.NewServer(
		MiddlewareValidateRefreshToken(logger, authHelper, repo)(endpoints.RefreshTokenEndpoint),
		decodeHTTPRefreshTokenRequest,
		encodeResponse,
		append(options, kithttp.ServerBefore(opentracing.HTTPToContext(otTracer, "RefreshToken", logger), kithttp.PopulateRequestContext))...,
	)

	mux.Handle("/signup", signupHandler)
	mux.Handle("/login", loginHandler)
	mux.Handle("/verify/mail", verifyMailHandler)
	mux.Handle("/verify/password-reset", passwordResetHandler)
	mux.Handle("/refresh-token", refreshTokenHandler)

	mux2.Handle("/api/auth/v1/", http.StripPrefix("/api/auth/v1", mux))

	http.Handle("/", accessControl(mux2))

	return mux2
}

func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}

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

// decodeHTTPVerifyMailRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded signup request from the HTTP request body. Primarily useful in a
// server.
func decodeHTTPVerifyMailRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var verificationData data.VerificationData

	if r.Body == nil {
		return nil, ErrBadRequest
	}

	err := json.NewDecoder(r.Body).Decode(&verificationData)
	if err != nil {
		return nil, errors.New(err.Error())
	} else {
		return verificationData, nil
	}
}

// decodeHTTPVerifyPasswordResetMailRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded signup request from the HTTP request body. Primarily useful in a
// server.
func decodeHTTPVerifyPasswordResetRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var verificationData data.VerificationData

	if r.Body == nil {
		return nil, ErrBadRequest
	}

	err := json.NewDecoder(r.Body).Decode(&verificationData)
	if err != nil {
		return nil, errors.New(err.Error())
	} else {
		return verificationData, nil
	}
}

// decodeHTTPRefreshTokenRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded signup request from the HTTP request body. Primarily useful in a
// server.
func decodeHTTPRefreshTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
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


func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

type errorer interface {
	error() error
}

// encode errors from business-logic
func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch err {
	case signup.ErrUnknown:
		w.WriteHeader(http.StatusNotFound)
	case ErrInvalidArgument:
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}
