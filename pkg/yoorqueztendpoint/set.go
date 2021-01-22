package yoorqueztendpoint

import (
	"context"
	"fmt"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztrepository"
	"strings"
	"time"

	stdopentracing "github.com/opentracing/opentracing-go"
	stdzipkin "github.com/openzipkin/zipkin-go"
	"github.com/sony/gobreaker"
	"golang.org/x/time/rate"

	"github.com/go-kit/kit/circuitbreaker"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/ratelimit"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/tracing/zipkin"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztservice"
)

// Set collects all of the endpoints that compose an add service. It's meant to
// be used as a helper struct, to collect all of the endpoints into a single
// parameter.
type Set struct {
	SignupEndpoint endpoint.Endpoint
	ConcatEndpoint endpoint.Endpoint
}

var (
	authHelper IAuthHelper
)

// New returns a Set that wraps the provided server, and wires in all of the
// expected endpoint middlewares via the various parameters.
func New(svc yoorqueztservice.Authentication, logger log.Logger, mailService yoorqueztservice.MailService, validator *data.Validation, repository *yoorqueztrepository.PostgresRepository, configs *utils.Configurations, duration metrics.Histogram, otTracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer) Set {

	authHelper = NewHelper(logger, mailService, validator, repository, configs)

	var signupEndpoint endpoint.Endpoint
	{
		signupEndpoint = MakeSignupEndpoint(svc)
		// Signup is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		signupEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(signupEndpoint)
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
func (s Set) Signup(ctx context.Context, user *data.User) error {
	resp, err := s.SignupEndpoint(ctx, user)
	if err != nil {
		return err
	}
	response := resp.(SignupResponse)
	return response.Err
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
func MakeSignupEndpoint(authService yoorqueztservice.Authentication) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		user := request.(data.User)

		// Validate user
		errs := authHelper.ValidateUser(&user)
		if len(errs) != 0 {
			return SignupResponse{Status: false, Message: strings.Join(errs.Errors(), ","), Err: err}, nil
		}

		hashedPass, err := authHelper.HashPassword(user.Password)
		if err != nil {
			return SignupResponse{Status: false, Message: UserCreationFailed}, nil
		}
		user.Password = hashedPass
		user.TokenHash = utils.GenerateRandomString(15)

		err = authService.Signup(ctx, &user)
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, PgDuplicateKeyMsg) {
				return SignupResponse{Status: false, Message: ErrUserAlreadyExists}, nil
			} else {
				return SignupResponse{Status: false, Message: UserCreationFailed}, nil
			}
		}

		// Send verification mail
		from := "hebercomp@yahoo.com"
		to := []string{user.Email}
		subject := "Email Verification for hecomp"
		mailType := yoorqueztservice.MailConfirmation
		mailData := &yoorqueztservice.MailData{
			Username: user.Username,
			Code: 	utils.GenerateRandomString(8),
		}

		err = authHelper.SenMail(from, to, subject, mailType, mailData)
		if err != nil {
			return SignupResponse{Status: false, Message: UserCreationFailed, Err: err}, err
		}

		verificationData := authHelper.BuildVerificationData(&user, mailData)
		err = authHelper.StoreVerificationData(ctx, verificationData)
		if err != nil {
			return SignupResponse{Status: false, Message: UserCreationFailed, Err: err}, err
		}

		return SignupResponse{Status: true, Message: UserCreationSuccess}, nil
	}
}

// MakeConcatEndpoint constructs a Concat endpoint wrapping the service.
func MakeConcatEndpoint(s yoorqueztservice.Authentication) endpoint.Endpoint {
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

// ValidationError is a collection of validation error messages
type ValidationError struct {
	Errors []string `json:"errors"`
}

// Below data types are used for encoding and decoding b/t go types and json
type TokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type AuthResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	Username     string `json:"username"`
}

type UsernameUpdate struct {
	Username string `json:"username"`
}

type CodeVerificationReq struct {
	Code string `json: "code"`
	Type string `json" "type"`
}

type PasswordResetReq struct {
	Password string `json: "password"`
	PasswordRe string `json: "password_re"`
	Code 		string `json: "code"`
}

var ErrUserAlreadyExists = fmt.Sprintf("User already exists with the given email")
var ErrUserNotFound = fmt.Sprintf("No user account exists with given email. Please sign in first")
var UserCreationFailed = fmt.Sprintf("Unable to create user.Please try again later")
var UserCreationSuccess = fmt.Sprintf("Please verify your email account using the confirmation code send to your mail")

var PgDuplicateKeyMsg = "duplicate key value violates unique constraint"
var PgNoRowsMsg = "no rows in result set"

type SignupRequest struct {
	ID         string
	Email      string
	Password   string
	Username   string
	TokenHash  string
	IsVerified bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// SignupResponse collects the response values for the Signup method.
type SignupResponse struct {
	Status  bool        `json:"status"`
	Message   string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err       error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
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
