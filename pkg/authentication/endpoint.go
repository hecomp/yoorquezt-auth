package authentication

import (
	"context"
	"fmt"

	"github.com/hecomp/yoorquezt-auth/pkg/helper"
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
	"strings"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	mail2 "github.com/hecomp/yoorquezt-auth/pkg/mail"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztservice"
)

// signupResponse collects the response values for the Signup method.
type signupResponse struct {
	Status  bool        `json:"status"`
	Message   string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err       error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r signupResponse) Failed() error { return r.Err }

// Set collects all of the endpoints that compose an add service. It's meant to
// be used as a helper struct, to collect all of the endpoints into a single
// parameter.
type Set struct {
	SignupEndpoint endpoint.Endpoint
	LoginEndpoint endpoint.Endpoint
	VerifyMailEndpoint endpoint.Endpoint
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
		verifyMailEndpoint = opentracing.TraceServer(otTracer, "VerifyMai")(verifyMailEndpoint)
		if zipkinTracer != nil {
			verifyMailEndpoint = zipkin.TraceEndpoint(zipkinTracer, "VerifyMai")(verifyMailEndpoint)
		}
	}
	return Set{
		SignupEndpoint: signupEndpoint,
		LoginEndpoint: loginEndpoint,
		VerifyMailEndpoint: verifyMailEndpoint,
	}
}

// MakeSignupEndpoint constructs a Signup endpoint wrapping the service.
func makeSignupEndpoint(authService Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		user := request.(data.User)

		// Validate user
		errs := authServiceHelper.Validate(&user)
		if len(errs) != 0 {
			return signupResponse{Status: false, Message: strings.Join(errs.Errors(), ","), Err: err}, nil
		}

		hashedPass, err := authServiceHelper.HashPassword(user.Password)
		if err != nil {
			return signupResponse{Status: false, Message: UserCreationFailed}, nil
		}
		user.Password = hashedPass
		user.TokenHash = utils.GenerateRandomString(15)

		err = authService.Signup(ctx, &user)
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, PgDuplicateKeyMsg) {
				return signupResponse{Status: false, Message: ErrUserAlreadyExists}, nil
			} else {
				return signupResponse{Status: false, Message: UserCreationFailed}, nil
			}
		}

		// Send verification mail
		from := "heber.luiz.cunha@gmail.com"
		to := []string{user.Email}
		subject := "Email Verification for yoorquezt"
		mailType := mail2.MailConfirmation
		mailData := &mail2.MailData{
			Username: user.Username,
			Code: 	utils.GenerateRandomString(8),
		}

		err = authServiceHelper.SenMail(from, to, subject, mailType, mailData)
		if err != nil {
			return signupResponse{Status: false, Message: UserCreationFailed, Err: err}, nil
		}

		verificationData := authServiceHelper.BuildVerificationData(&user, mailData)
		err = authServiceHelper.StoreVerificationData(ctx, verificationData)
		if err != nil {
			return signupResponse{Status: false, Message: UserCreationFailed, Err: err}, nil
		}

		return signupResponse{Status: true, Message: UserCreationSuccess}, nil
	}
}

// SignupResponse collects the response values for the Signup method.
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
func makeLoginEndpoint(authService yoorqueztservice.Authentication) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		reqUser := request.(data.User)

		// Validate user
		errs := authServiceHelper.Validate(&reqUser)
		if len(errs) != 0 {
			return LoginResponse{Status: false, Message: strings.Join(errs.Errors(), ","), Err: err}, nil
		}

		user, err := authService.Login(ctx, &reqUser)
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, PgNoRowsMsg) {
				return LoginResponse{Status: true, Message: ErrUserNotFound, Err: err}, nil
			} else {
				return LoginResponse{Status: true, Message: ErrRetrieveUser, Err: err}, nil
			}
		}

		if !user.IsVerified {
			authServiceHelper.Log("unverified user")
			return LoginResponse{Status: false, Message: VerifyEmail, Err: nil}, nil
		}

		if valid := authServiceHelper.Authenticate(&reqUser, user); !valid {
			authServiceHelper.Log("Authetication of user failed")
			return LoginResponse{Status: false, Message: IncorrectPassword, Err: nil}, nil
		}

		accessToken, err := authServiceHelper.GenerateAccessToken(user)
		if err != nil {
			authServiceHelper.ErrorMsgs("unable to generate access token", "error", err.Error())
			return LoginResponse{Status: false, Message: ErrUnableToLogin, Err: err}, nil
		}
		refreshToken, err := authServiceHelper.GenerateRefreshToken(user)
		if err != nil {
			authServiceHelper.ErrorMsgs("unable to generate refresh token", "error", err.Error())
			return LoginResponse{Status: false, Message: ErrUnableToLogin, Err: err}, nil
		}

		authServiceHelper.Debug("successfully generated token", "accesstoken", accessToken, "refreshtoken", refreshToken)

		return LoginResponse{
			Status:  true,
			Message: "Successfully logged in",
			Data:    &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, Username: user.Username},
		}, nil
	}
}

// SignupResponse collects the response values for the Signup method.
type VerifyMailResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// Failed implements endpoint.Failer.
func (r VerifyMailResponse) Failed() error { return r.Err }

// makeVerifyMailEndpoint constructs a VerifyMail endpoint wrapping the service.
func makeVerifyMailEndpoint(authService yoorqueztservice.Authentication) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		verificationData := request.(data.VerificationData)

		authServiceHelper.Log("validating verification data")

		errs := authServiceHelper.Validate(verificationData)
		if len(errs) != 0 {
			authServiceHelper.ErrorMsgs("validation of verification data json failed", "error", strings.Join(errs.Errors(), ","))
			return VerifyMailResponse{Status: false, Message: strings.Join(errs.Errors(), ",")}, nil
		}

		authServiceHelper.Log("verifying the confimation code")
		verificationData.Type = data.MailConfirmation

		actualVerificationData, err := authService.VerifyMail(ctx, &verificationData)
		if err != nil {
			if strings.Contains(err.Error(), PgNoRowsMsg) {
				return VerifyMailResponse{Status: false, Message: ErrUserNotFound}, nil
			}
			return VerifyMailResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, nil
		}

		valid, err := authServiceHelper.Verify(actualVerificationData, &verificationData)
		if !valid {
			return VerifyMailResponse{Status: false, Message: err.Error()}, nil
		}

		// correct code, update user status to verified.
		err = authServiceHelper.UpdateUserVerificationStatus(context.Background(), verificationData.Email, true)
		if err != nil {
			return VerifyMailResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, nil
		}

		// delete the VerificationData from db
		err = authServiceHelper.DeleteVerificationData(context.Background(), verificationData.Email, verificationData.Type)
		if err != nil {
			authServiceHelper.ErrorMsgs("unable to delete the verification data", "error", err.Error())
		}

		authServiceHelper.Log("user mail verification succeeded")

		return VerifyMailResponse{Status: true, Message: "Mail Verification succeeded"}, nil
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

var PgDuplicateKeyMsg = "duplicate key value violates unique constraint"
var PgNoRowsMsg = "no rows in result set"
