package yoorqueztendpoint
//
//import (
//	"context"
//	"fmt"
//	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztrepository"
//	"strings"
//	"time"
//
//	stdopentracing "github.com/opentracing/opentracing-go"
//	stdzipkin "github.com/openzipkin/zipkin-go"
//	"github.com/sony/gobreaker"
//	"golang.org/x/time/rate"
//
//	"github.com/go-kit/kit/circuitbreaker"
//	"github.com/go-kit/kit/endpoint"
//	"github.com/go-kit/kit/log"
//	"github.com/go-kit/kit/metrics"
//	"github.com/go-kit/kit/ratelimit"
//	"github.com/go-kit/kit/tracing/opentracing"
//	"github.com/go-kit/kit/tracing/zipkin"
//
//	"github.com/hecomp/yoorquezt-auth/internal/data"
//	"github.com/hecomp/yoorquezt-auth/internal/utils"
//	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztservice"
//)
//
//// Set collects all of the endpoints that compose an add service. It's meant to
//// be used as a helper struct, to collect all of the endpoints into a single
//// parameter.
//type Set struct {
//	SignupEndpoint endpoint.Endpoint
//	LoginEndpoint endpoint.Endpoint
//	VerifyMailEndpoint endpoint.Endpoint
//}
//
//var (
//	authServiceHelper yoorqueztservice.IAuthHelper
//)
//
//// New returns a Set that wraps the provided server, and wires in all of the
//// expected endpoint middlewares via the various parameters.
//func New(svc yoorqueztservice.Authentication, logger log.Logger, mailService yoorqueztservice.MailService, validator *data.Validation, repository *yoorqueztrepository.PostgresRepository, configs *utils.Configurations, duration metrics.Histogram, otTracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer) Set {
//
//	authServiceHelper = yoorqueztservice.NewHelper(logger, mailService, validator, repository, configs)
//
//	var signupEndpoint endpoint.Endpoint
//	{
//		signupEndpoint = MakeSignupEndpoint(svc)
//		// Signup is limited to 1 request per second with burst of 1 request.
//		// Note, rate is defined as a time interval between requests.
//		signupEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(signupEndpoint)
//		signupEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(signupEndpoint)
//		signupEndpoint = opentracing.TraceServer(otTracer, "Signup")(signupEndpoint)
//		if zipkinTracer != nil {
//			signupEndpoint = zipkin.TraceEndpoint(zipkinTracer, "Signup")(signupEndpoint)
//		}
//		signupEndpoint = LoggingMiddleware(log.With(logger, "method", "Signup"))(signupEndpoint)
//		signupEndpoint = InstrumentingMiddleware(duration.With("method", "Signup"))(signupEndpoint)
//	}
//	var loginEndpoint endpoint.Endpoint
//	{
//		loginEndpoint = MakeLoginEndpoint(svc)
//		// Login is limited to 1 request per second with burst of 1 request.
//		// Note, rate is defined as a time interval between requests.
//		loginEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(loginEndpoint)
//		loginEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(loginEndpoint)
//		loginEndpoint = opentracing.TraceServer(otTracer, "Login")(loginEndpoint)
//		if zipkinTracer != nil {
//			loginEndpoint = zipkin.TraceEndpoint(zipkinTracer, "Login")(loginEndpoint)
//		}
//		loginEndpoint = LoggingMiddleware(log.With(logger, "method", "Login"))(loginEndpoint)
//		loginEndpoint = InstrumentingMiddleware(duration.With("method", "Login"))(loginEndpoint)
//	}
//	var verifyMailEndpoint endpoint.Endpoint
//	{
//		verifyMailEndpoint = MakeVerifyMailEndpoint(svc)
//		// VerifyMai is limited to 1 request per second with burst of 1 request.
//		// Note, rate is defined as a time interval between requests.
//		verifyMailEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Limit(1), 100))(verifyMailEndpoint)
//		verifyMailEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(verifyMailEndpoint)
//		verifyMailEndpoint = opentracing.TraceServer(otTracer, "VerifyMai")(verifyMailEndpoint)
//		if zipkinTracer != nil {
//			verifyMailEndpoint = zipkin.TraceEndpoint(zipkinTracer, "VerifyMai")(verifyMailEndpoint)
//		}
//		verifyMailEndpoint = LoggingMiddleware(log.With(logger, "method", "VerifyMai"))(loginEndpoint)
//		verifyMailEndpoint = InstrumentingMiddleware(duration.With("method", "VerifyMai"))(verifyMailEndpoint)
//	}
//	return Set{
//		SignupEndpoint: signupEndpoint,
//		LoginEndpoint: loginEndpoint,
//		VerifyMailEndpoint: verifyMailEndpoint,
//	}
//}
//
//// Signup implements the service interface, so Set may be used as a service.
//// This is primarily useful in the context of a client library.
//func (s Set) Signup(ctx context.Context, user *data.User) error {
//	resp, err := s.SignupEndpoint(ctx, user)
//	if err != nil {
//		return err
//	}
//	response := resp.(SignupResponse)
//	return response.Err
//}
//
//// Login implements the service interface, so Set may be used as a service.
//// This is primarily useful in the context of a client library.
//func (s Set) Login(ctx context.Context, user *data.User) (*data.User, error) {
//	resp, err := s.LoginEndpoint(ctx, user)
//	if err != nil {
//		return nil, err
//	}
//	response := resp.(GenericResponse)
//	userReq := response.Data.(data.User)
//	return &userReq, response.Err
//}
//
//// VerifyMail implements the service interface, so Set may be used as a service.
//// This is primarily useful in the context of a client library.
//func (s Set) VerifyMail(ctx context.Context, verificationData *data.VerificationData) (*data.VerificationData, error) {
//	resp, err := s.VerifyMailEndpoint(ctx, verificationData)
//	if err != nil {
//		return nil, err
//	}
//	response := resp.(GenericResponse)
//	verificationDataReq := response.Data.(data.VerificationData)
//	return &verificationDataReq, response.Err
//}
//
//// MakeSignupEndpoint constructs a Signup endpoint wrapping the service.
//func MakeSignupEndpoint(authService yoorqueztservice.Authentication) endpoint.Endpoint {
//	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
//		user := request.(data.User)
//
//		// Validate user
//		errs := authServiceHelper.Validate(&user)
//		if len(errs) != 0 {
//			return GenericResponse{Status: false, Message: strings.Join(errs.Errors(), ","), Err: err}, nil
//		}
//
//		hashedPass, err := authServiceHelper.HashPassword(user.Password)
//		if err != nil {
//			return GenericResponse{Status: false, Message: UserCreationFailed}, nil
//		}
//		user.Password = hashedPass
//		user.TokenHash = utils.GenerateRandomString(15)
//
//		err = authService.Signup(ctx, &user)
//		if err != nil {
//			errMsg := err.Error()
//			if strings.Contains(errMsg, PgDuplicateKeyMsg) {
//				return GenericResponse{Status: false, Message: ErrUserAlreadyExists}, nil
//			} else {
//				return GenericResponse{Status: false, Message: UserCreationFailed}, nil
//			}
//		}
//
//		// Send verification mail
//		from := "heber.luiz.cunha@gmail.com"
//		to := []string{user.Email}
//		subject := "Email Verification for yoorquezt"
//		mailType := yoorqueztservice.MailConfirmation
//		mailData := &yoorqueztservice.MailData{
//			Username: user.Username,
//			Code: 	utils.GenerateRandomString(8),
//		}
//
//		err = authServiceHelper.SenMail(from, to, subject, mailType, mailData)
//		if err != nil {
//			return GenericResponse{Status: false, Message: UserCreationFailed, Err: err}, nil
//		}
//
//		verificationData := authServiceHelper.BuildVerificationData(&user, mailData)
//		err = authServiceHelper.StoreVerificationData(ctx, verificationData)
//		if err != nil {
//			return GenericResponse{Status: false, Message: UserCreationFailed, Err: err}, nil
//		}
//
//		return GenericResponse{Status: true, Message: UserCreationSuccess}, nil
//	}
//}
//
//// MakeLoginEndpoint constructs a Login endpoint wrapping the service.
//func MakeLoginEndpoint(authService yoorqueztservice.Authentication) endpoint.Endpoint {
//	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
//		reqUser := request.(data.User)
//
//		// Validate user
//		errs := authServiceHelper.Validate(&reqUser)
//		if len(errs) != 0 {
//			return GenericResponse{Status: false, Message: strings.Join(errs.Errors(), ","), Err: err}, nil
//		}
//
//		user, err := authService.Login(ctx, &reqUser)
//		if err != nil {
//			errMsg := err.Error()
//			if strings.Contains(errMsg, PgNoRowsMsg) {
//				return GenericResponse{Status: true, Message: ErrUserNotFound, Err: err}, nil
//			} else {
//				return GenericResponse{Status: true, Message: ErrRetrieveUser, Err: err}, nil
//			}
//		}
//
//		if !user.IsVerified {
//			authServiceHelper.Log("unverified user")
//			return GenericResponse{Status: false, Message: VerifyEmail, Err: nil}, nil
//		}
//
//		if valid := authServiceHelper.Authenticate(&reqUser, user); !valid {
//			authServiceHelper.Log("Authetication of user failed")
//			return GenericResponse{Status: false, Message: IncorrectPassword, Err: nil}, nil
//		}
//
//		accessToken, err := authServiceHelper.GenerateAccessToken(user)
//		if err != nil {
//			authServiceHelper.ErrorMsgs("unable to generate access token", "error", err.Error())
//			return GenericResponse{Status: false, Message: ErrUnableToLogin, Err: err}, nil
//		}
//		refreshToken, err := authServiceHelper.GenerateRefreshToken(user)
//		if err != nil {
//			authServiceHelper.ErrorMsgs("unable to generate refresh token", "error", err.Error())
//			return GenericResponse{Status: false, Message: ErrUnableToLogin, Err: err}, nil
//		}
//
//		authServiceHelper.Debug("successfully generated token", "accesstoken", accessToken, "refreshtoken", refreshToken)
//
//		return GenericResponse{
//			Status:  true,
//			Message: "Successfully logged in",
//			Data:    &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, Username: user.Username},
//		}, nil
//	}
//}
//
//// MakeVerifyMailEndpoint constructs a VerifyMail endpoint wrapping the service.
//func MakeVerifyMailEndpoint(authService yoorqueztservice.Authentication) endpoint.Endpoint {
//	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
//		verificationData := request.(data.VerificationData)
//
//		authServiceHelper.Log("validating verification data")
//
//		errs := authServiceHelper.Validate(verificationData)
//		if len(errs) != 0 {
//			authServiceHelper.ErrorMsgs("validation of verification data json failed", "error", strings.Join(errs.Errors(), ","))
//			return GenericResponse{Status: false, Message: strings.Join(errs.Errors(), ",")}, nil
//		}
//
//		authServiceHelper.Log("verifying the confimation code")
//		verificationData.Type = data.MailConfirmation
//
//		actualVerificationData, err := authService.VerifyMail(ctx, &verificationData)
//		if err != nil {
//			if strings.Contains(err.Error(), PgNoRowsMsg) {
//				return GenericResponse{Status: false, Message: ErrUserNotFound}, nil
//			}
//			return GenericResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, nil
//		}
//
//		valid, err := authServiceHelper.Verify(actualVerificationData, &verificationData)
//		if !valid {
//			return GenericResponse{Status: false, Message: err.Error()}, nil
//		}
//
//
//		return nil, nil
//	}
//}
//
//// compile time assertions for our response types implementing endpoint.Failer.
//var (
//	_ endpoint.Failer = SignupResponse{}
//	_ endpoint.Failer = LoginResponse{}
//)
//
//var ErrUserAlreadyExists = fmt.Sprintf("User already exists with the given email")
//var ErrUserNotFound = fmt.Sprintf("No user account exists with given email. Please sign in first")
//var ErrRetrieveUser = fmt.Sprintf("Unable to retrieve user from database.Please try again later")
//var ErrUnableToLogin = fmt.Sprintf("Unable to login the user. Please try again later")
//var UserCreationFailed = fmt.Sprintf("Unable to create user.Please try again later")
//var UserCreationSuccess = fmt.Sprintf("Please verify your email account using the confirmation code send to your mail")
//var VerifyEmail = fmt.Sprintf("Please verify your mail address before login")
//var IncorrectPassword = fmt.Sprintf("Incorrect password")
//
//var PgDuplicateKeyMsg = "duplicate key value violates unique constraint"
//var PgNoRowsMsg = "no rows in result set"
//
//type SignupRequest struct {
//	ID         string
//	Email      string
//	Password   string
//	Username   string
//	TokenHash  string
//	IsVerified bool
//	CreatedAt  time.Time
//	UpdatedAt  time.Time
//}
//
//// Failed implements endpoint.Failer.
//func (r SignupResponse) Failed() error { return r.Err }
//
//// Failed implements endpoint.Failer.
//func (r LoginResponse) Failed() error { return r.Err }
