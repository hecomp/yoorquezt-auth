package auth

import (
	"context"
	"fmt"
	stdopentracing "github.com/opentracing/opentracing-go"
	stdzipkin "github.com/openzipkin/zipkin-go"

	"github.com/go-kit/kit/circuitbreaker"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/ratelimit"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/tracing/zipkin"

	"github.com/sony/gobreaker"
	"golang.org/x/time/rate"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	"github.com/hecomp/yoorquezt-auth/pkg/helper"
	mail2 "github.com/hecomp/yoorquezt-auth/pkg/mail"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
)

// SignupResponse collects the response values for the Signup method.
type SignupResponse struct {
	Status  bool        `json:"status"`
	Message   string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err       error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r SignupResponse) Failed() error { return r.Err }

// Set collects all of the endpoints that compose an add service. It's meant to
// be used as a helper struct, to collect all of the endpoints into a single
// parameter.
type Set struct {
	SignupEndpoint endpoint.Endpoint
	LoginEndpoint endpoint.Endpoint
	VerifyMailEndpoint endpoint.Endpoint
	VerifyPasswordResetEndpoint endpoint.Endpoint
	RefreshTokenEndpoint endpoint.Endpoint
	GeneratePassResetCodeEndpoint endpoint.Endpoint
	UpdateUsernameEndpoint endpoint.Endpoint
	ResetPasswordEndpoint endpoint.Endpoint
}

// Signup for grcp
func (s Set) Signup(ctx context.Context, user *data.User) (*SignupResponse, error) {
		resp, err := s.SignupEndpoint(ctx, user)
		if err != nil {
			return nil, err
		}
		response := resp.(SignupResponse)
		return &response, response.Err
}

// Login for grcp
func (s Set) Login(ctx context.Context, user *data.User) (*LoginResponse, error) {
		resp, err := s.LoginEndpoint(ctx, user)
		if err != nil {
			return nil, err
		}
		response := resp.(LoginResponse)
		userReq := response.Data.(LoginResponse)
		return &userReq, response.Err
}

// VerifyMail for grcp
func (s Set) VerifyMail(ctx context.Context, verificationData *data.VerificationData) (*VerifyMailResponse, error) {
		resp, err := s.VerifyMailEndpoint(ctx, verificationData)
		if err != nil {
			return nil, err
		}
		response := resp.(VerifyMailResponse)
		verificationDataReq := response.Data.(VerifyMailResponse)
		return &verificationDataReq, response.Err
}

// VerifyPasswordReset for grcp
func (s Set) VerifyPasswordReset(ctx context.Context, verificationData *data.VerificationData) (*VerifyPasswordResetResponse, error) {
	resp, err := s.VerifyMailEndpoint(ctx, verificationData)
	if err != nil {
		return nil, err
	}
	response := resp.(VerifyMailResponse)
	verificationDataReq := response.Data.(VerifyPasswordResetResponse)
	return &verificationDataReq, response.Err
}

// RefreshToken for grcp
func (s Set) RefreshToken(ctx context.Context, user *data.User) (*RefreshTokenResponse, error) {
	resp, err := s.RefreshTokenEndpoint(ctx, user)
	if err != nil {
		return nil, err
	}
	response := resp.(RefreshTokenResponse)
	verificationDataReq := response.Data.(RefreshTokenResponse)
	return &verificationDataReq, response.Err
}

// GeneratePassResetCode for grcp
func (s Set) GeneratePassResetCode(ctx context.Context, user *data.User) (*GeneratePassResetCodeResponse, error) {
	resp, err := s.GeneratePassResetCodeEndpoint(ctx, user)
	if err != nil {
		return nil, err
	}
	response := resp.(GeneratePassResetCodeResponse)
	verificationDataReq := response.Data.(GeneratePassResetCodeResponse)
	return &verificationDataReq, response.Err
}

var (
	authServiceHelper helper.IAuthHelper
)

// New returns a Set that wraps the provided server, and wires in all of the
// expected endpoint middlewares via the various parameters.
func New(svc Service, logger log.Logger, mailService mail2.MailService, validator *data.Validation, repository signup.Repository, configs *utils.Configurations, otTracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer) Set {

	authServiceHelper = helper.NewHelper(logger, mailService, validator, repository, configs)

	var signupEndpoint endpoint.Endpoint
	{
		signupEndpoint = makeSignupEndpoint(svc)
		// Signup is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		signupEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(signupEndpoint)
		signupEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(signupEndpoint)
		signupEndpoint = opentracing.TraceServer(otTracer, "Signup")(signupEndpoint)
		if zipkinTracer != nil {
			signupEndpoint = zipkin.TraceEndpoint(zipkinTracer, "Signup")(signupEndpoint)
		}
	}
	var loginEndpoint endpoint.Endpoint
	{
		loginEndpoint = makeLoginEndpoint(svc)
		// Login is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		loginEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(loginEndpoint)
		loginEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(loginEndpoint)
		loginEndpoint = opentracing.TraceServer(otTracer, "Login")(loginEndpoint)
		if zipkinTracer != nil {
			loginEndpoint = zipkin.TraceEndpoint(zipkinTracer, "Login")(loginEndpoint)
		}
	}
	var verifyMailEndpoint endpoint.Endpoint
	{
		verifyMailEndpoint = makeVerifyMailEndpoint(svc)
		// VerifyMai is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		verifyMailEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(verifyMailEndpoint)
		verifyMailEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(verifyMailEndpoint)
		verifyMailEndpoint = opentracing.TraceServer(otTracer, "VerifyMail")(verifyMailEndpoint)
		if zipkinTracer != nil {
			verifyMailEndpoint = zipkin.TraceEndpoint(zipkinTracer, "VerifyMail")(verifyMailEndpoint)
		}
	}
	var verifyPasswordResetEndpoint endpoint.Endpoint
	{
		verifyPasswordResetEndpoint = makeVerifyPasswordResetEndpoint(svc)
		// VerifyPasswordReset is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		verifyPasswordResetEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(verifyPasswordResetEndpoint)
		verifyPasswordResetEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(verifyPasswordResetEndpoint)
		verifyPasswordResetEndpoint = opentracing.TraceServer(otTracer, "VerifyPasswordReset")(verifyPasswordResetEndpoint)
		if zipkinTracer != nil {
			verifyPasswordResetEndpoint = zipkin.TraceEndpoint(zipkinTracer, "VerifyPasswordReset")(verifyPasswordResetEndpoint)
		}
	}
	var refreshTokenEndpoint endpoint.Endpoint
	{
		refreshTokenEndpoint = makeRefreshTokenEndpoint(svc)
		// RefreshToken is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		refreshTokenEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(refreshTokenEndpoint)
		refreshTokenEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(refreshTokenEndpoint)
		refreshTokenEndpoint = opentracing.TraceServer(otTracer, "RefreshToken")(refreshTokenEndpoint)
		if zipkinTracer != nil {
			refreshTokenEndpoint = zipkin.TraceEndpoint(zipkinTracer, "RefreshToken")(refreshTokenEndpoint)
		}
	}
	var generatePassResetCodeEndpoint endpoint.Endpoint
	{
		generatePassResetCodeEndpoint = makeGeneratePassResetCodeEndpoint(svc)
		// GeneratePassResetCode is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		generatePassResetCodeEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(generatePassResetCodeEndpoint)
		generatePassResetCodeEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(generatePassResetCodeEndpoint)
		generatePassResetCodeEndpoint = opentracing.TraceServer(otTracer, "GeneratePassResetCode")(generatePassResetCodeEndpoint)
		if zipkinTracer != nil {
			generatePassResetCodeEndpoint = zipkin.TraceEndpoint(zipkinTracer, "GeneratePassResetCode")(generatePassResetCodeEndpoint)
		}
	}
	var updateUsernameEndpoint endpoint.Endpoint
	{
		updateUsernameEndpoint = makeUpdateUsernameEndpoint(svc)
		// UpdateUsername is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		updateUsernameEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(updateUsernameEndpoint)
		updateUsernameEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(updateUsernameEndpoint)
		updateUsernameEndpoint = opentracing.TraceServer(otTracer, "UpdateUsername")(updateUsernameEndpoint)
		if zipkinTracer != nil {
			updateUsernameEndpoint = zipkin.TraceEndpoint(zipkinTracer, "UpdateUsername")(updateUsernameEndpoint)
		}
	}
	var resetPasswordEndpoint endpoint.Endpoint
	{
		resetPasswordEndpoint = makeResetPasswordEndpoint(svc)
		// ResetPassword is limited to 1 request per second with burst of 1 request.
		// Note, rate is defined as a time interval between requests.
		resetPasswordEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(resetPasswordEndpoint)
		resetPasswordEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(resetPasswordEndpoint)
		resetPasswordEndpoint = opentracing.TraceServer(otTracer, "ResetPassword")(resetPasswordEndpoint)
		if zipkinTracer != nil {
			resetPasswordEndpoint = zipkin.TraceEndpoint(zipkinTracer, "ResetPassword")(resetPasswordEndpoint)
		}
	}
	return Set{
		SignupEndpoint: signupEndpoint,
		LoginEndpoint: loginEndpoint,
		VerifyMailEndpoint: verifyMailEndpoint,
		VerifyPasswordResetEndpoint: verifyPasswordResetEndpoint,
		RefreshTokenEndpoint: refreshTokenEndpoint,
		GeneratePassResetCodeEndpoint: generatePassResetCodeEndpoint,
		UpdateUsernameEndpoint: updateUsernameEndpoint,
		ResetPasswordEndpoint: resetPasswordEndpoint,
	}
}

// MakeSignupEndpoint constructs a Signup endpoint wrapping the service.
func makeSignupEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		user := request.(data.User)

		resp, erro := authService.Signup(ctx, &user)
		if erro != nil {
			return SignupResponse{ Status: resp.Status, Message: resp.Message, Err: resp.Err, }, nil
		}

		return SignupResponse{ Status: resp.Status, Message: resp.Message, }, nil
	}
}

// LoginResponse collects the response values for the Signup method.
type LoginResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

type AuthResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	Username     string `json:"username"`
}

// Failed implements endpoint.Failer.
func (r LoginResponse) Failed() error { return r.Err }

// makeLoginEndpoint constructs a Login endpoint wrapping the service.
func makeLoginEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		reqUser := request.(data.User)

		resp, err := authService.Login(ctx, &reqUser)
		if err != nil {
			return LoginResponse{ Status:  resp.Status, Message: resp.Message, Data:    resp.Data, Err: err, }, nil
		}

		return LoginResponse{ Status:  resp.Status, Message: resp.Message, Data:    resp.Data, }, nil
	}
}

// VerifyMailResponse collects the response values for the Signup method.
type VerifyMailResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r VerifyMailResponse) Failed() error { return r.Err }

// makeVerifyMailEndpoint constructs a VerifyMail endpoint wrapping the service.
func makeVerifyMailEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		verificationData := request.(data.VerificationData)

		resp, err := authService.VerifyMail(ctx, &verificationData)
		if err != nil {
			return VerifyMailResponse{Status: resp.Status, Message: resp.Message, Err: resp.Err, }, nil
		}

		return VerifyMailResponse{Status: resp.Status, Message: resp.Message}, nil
	}
}

// VerifyPasswordResetResponse collects the response values for the Signup method.
type VerifyPasswordResetResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r VerifyPasswordResetResponse) Failed() error { return r.Err }

// makeVerifyPasswordResetEndpoint constructs a VerifyMail endpoint wrapping the service.
func makeVerifyPasswordResetEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		verificationData := request.(data.VerificationData)

		resp, err := authService.VerifyPasswordReset(ctx, &verificationData)
		if err != nil {
			return VerifyPasswordResetResponse{Status: resp.Status, Message: resp.Message, Err: resp.Err, }, nil
		}

		return VerifyPasswordResetResponse{Status: resp.Status, Message: resp.Message}, nil
	}
}

// RefreshTokenResponse collects the response values for the Signup method.
type RefreshTokenResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Below data types are used for encoding and decoding b/t go types and json
type TokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

// Failed implements endpoint.Failer.
func (r RefreshTokenResponse) Failed() error { return r.Err }

// makeRefreshTokenEndpoint constructs a RefreshToken endpoint wrapping the service.
func makeRefreshTokenEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		user := request.(data.User)

		resp, err := authService.RefreshToken(ctx, &user)
		if err != nil {
			return &RefreshTokenResponse{ Status: resp.Status, Message: resp.Message, Err: resp.Err}, nil
		}

		return &RefreshTokenResponse{ Status: resp.Status,Message: resp.Message, Data: resp.Data }, nil
	}
}

// GeneratePassResetCodeResponse collects the response values for the Signup method.
type GeneratePassResetCodeResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r GeneratePassResetCodeResponse) Failed() error { return r.Err }

// makeGeneratePassResetCodeEndpoint constructs a GeneratePassResetCode endpoint wrapping the service.
func makeGeneratePassResetCodeEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		user := request.(data.User)

		resp, err := authService.GeneratePassResetCode(ctx, &user)
		if err != nil {
			return &GeneratePassResetCodeResponse{ Status: resp.Status, Message: resp.Message, Err: resp.Err}, nil
		}

		return &GeneratePassResetCodeResponse{ Status: resp.Status,Message: resp.Message, Data: resp.Data }, nil
	}
}

// GeneratePassResetCodeResponse collects the response values for the Signup method.
type UpdateUsernameResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r UpdateUsernameResponse) Failed() error { return r.Err }

// makeUpdateUsernameEndpoint constructs a UpdateUsername endpoint wrapping the service.
func makeUpdateUsernameEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		user := request.(data.User)

		resp, err := authService.UpdateUsername(ctx, &user)
		if err != nil {
			return &UpdateUsernameResponse{ Status: resp.Status, Message: resp.Message, Err: resp.Err}, nil
		}

		return &UpdateUsernameResponse{ Status: resp.Status,Message: resp.Message, Data: resp.Data }, nil
	}
}

// ResetPasswordResponse collects the response values for the Signup method.
type ResetPasswordResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r ResetPasswordResponse) Failed() error { return r.Err }

// makeResetPasswordEndpoint constructs a UpdateUsername endpoint wrapping the service.
func makeResetPasswordEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		passResetReq := request.(data.PasswordResetReq)

		resp, err := authService.ResetPassword(ctx, &passResetReq)
		if err != nil {
			return &ResetPasswordResponse{ Status: resp.Status, Message: resp.Message, Err: resp.Err}, nil
		}

		return &ResetPasswordResponse{ Status: resp.Status,Message: resp.Message, Data: resp.Data }, nil
	}
}

var ErrUserAlreadyExists = fmt.Sprintf("User already exists with the given email")
var ErrUserNotFound = fmt.Sprintf("No user account exists with given email. Please sign in first")
var ErrRetrieveUser = fmt.Sprintf("Unable to retrieve user from database.Please try again later")
var ErrUnableToLogin = fmt.Sprintf("Unable to login the user. Please try again later")
var UserCreationFailed = fmt.Sprintf("Unable to create user.Please try again later")
var UserCreationSuccess = fmt.Sprintf("Please verify your email account using the confirmation code send to your mail")
var VerifyEmail = fmt.Sprintf("Please verify your mail address before login")
var IncorrectPassword = fmt.Sprintf("Incorrect password")
var ResetPassCodeSuccess = fmt.Sprintf("Please check your mail for password reset code")
var ResetPassCodeFailed = fmt.Sprintf("Unable to send password reset code. Please try again later")
var UpdateUsernameFailed = fmt.Sprintf("Unable to update username. Please try again later")
var UpdateUsernameSuccess =fmt.Sprintf("Successfully updated username")
var ResetPasswordFailed = fmt.Sprintf("Unable to reset password. Please try again later")
var DuplicatePassword = fmt.Sprintf("Password and re-entered Password are not same")
var UpdatePasswordFailed = fmt.Sprintf("Unable to update user password in db")
var UpadatePasswordSuccess = fmt.Sprintf("Password Reset Successfully")

var PgDuplicateKeyMsg = "duplicate key value violates unique constraint"
var PgNoRowsMsg = "no rows in result set"
