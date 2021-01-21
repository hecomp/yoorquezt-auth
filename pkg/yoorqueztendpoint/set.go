package yoorqueztendpoint
import (
	"context"
	"fmt"
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

// New returns a Set that wraps the provided server, and wires in all of the
// expected endpoint middlewares via the various parameters.
func New(svc yoorqueztservice.Authentication, mailSvc yoorqueztservice.MailService, logger log.Logger, conf *utils.Configurations, validator *data.Validation, duration metrics.Histogram, otTracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer) Set {
	var signupEndpoint endpoint.Endpoint
	{
		signupEndpoint = MakeSignupEndpoint(svc, mailSvc, conf, validator)
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
func (s Set) Signup(ctx context.Context, user *data.User) error {
	resp, err := s.SignupEndpoint(ctx, user)
	if err != nil {
		return err
	}
	response := resp.(SignupResponse)
	return response.Err
}

func (s Set) StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error {
	panic("implement me")
}

func (s Set) HashPassword(password string) (string, error) {
	panic("implement me")
}

func (s Set) Authenticate(reqUser *data.User, user *data.User) bool {
	panic("implement me")
}

func (s Set) GenerateAccessToken(user *data.User) (string, error) {
	panic("implement me")
}

func (s Set) GenerateRefreshToken(user *data.User) (string, error) {
	panic("implement me")
}

func (s Set) GenerateCustomKey(userID string, password string) string {
	panic("implement me")
}

func (s Set) ValidateAccessToken(token string) (string, error) {
	panic("implement me")
}

func (s Set) ValidateRefreshToken(token string) (string, string, error) {
	panic("implement me")
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
func MakeSignupEndpoint(s yoorqueztservice.Authentication, mailSvc yoorqueztservice.MailService, configs *utils.Configurations, validator *data.Validation) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		user := request.(data.User)

		hashedPass, err := s.HashPassword(user.Password)
		if err != nil {
			return GenericResponse{Status: false, Message: UserCreationFailed}, nil
		}
		user.Password = hashedPass
		user.TokenHash = utils.GenerateRandomString(15)

		err = s.Signup(ctx, &user)
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, PgDuplicateKeyMsg) {
				return GenericResponse{Status: false, Message: ErrUserAlreadyExists}, nil
			} else {
				return GenericResponse{Status: false, Message: UserCreationFailed}, nil
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

		mailReq := mailSvc.NewMail(from, to, subject, mailType, mailData)
		err = mailSvc.SendMail(mailReq)
		if err != nil {
			return GenericResponse{Status: false, Message: UserCreationFailed}, nil
		}

		verificationData := &data.VerificationData{
			Email: user.Email,
			Code : mailData.Code,
			Type : data.MailConfirmation,
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(configs.MailVerifCodeExpiration)),
		}
		err = s.StoreVerificationData(ctx, verificationData)
		if err != nil {
			return GenericResponse{Status: false, Message: UserCreationFailed}, nil
		}

		return GenericResponse{Status: true, Message: UserCreationSuccess}, nil
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

// GenericResponse is the format of our response
type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

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

// SignupResponse collects the response values for the Signup method.
type SignupResponse struct {
	Message   string   `json:",omitempty"`
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
