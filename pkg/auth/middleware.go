package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	kithttp "github.com/go-kit/kit/transport/http"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/pkg/helper"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
)

type Adapter func(http.Handler) http.Handler

// GenericResponse is the format of our response
type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
	Err     error       `json:"err,omitempty"`
}

func (g GenericResponse) Error() string {
	return g.Err.Error()
}

// UserKey is used as a key for storing the User object in context at middleware
type UserKey struct{}

// UserIDKey is used as a key for storing the UserID in context at middleware
type UserIDKey struct{}

// VerificationDataKey is used as the key for storing the VerificationData in context at middleware
type VerificationDataKey struct{}

// MiddlewareValidateUser validates the user in the request
func MiddlewareValidateUser(logger log.Logger, authHelper *helper.AuthHelper) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{})(interface{}, error) {
			user := request.(data.User)

			logger.Log("user json", user)

			token, ok := ctx.Value(kithttp.ContextKeyRequestAuthorization).(string)
			if !ok {
				logger.Log("token not provided or malformed")
				errMsg := "Authentication failed. Token not provided or malformed"
				return &GenericResponse{Status: false, Message: errMsg}, errors.New(errMsg)
			}
			logger.Log("token present in header", token)

			// validate the user
			errs := authHelper.Validator.Validate(user)
			if len(errs) != 0 {
				logger.Log("validation of user json failed", "error", errs)
				err := strings.Join(errs.Errors(), ",")
				return &GenericResponse{Status: false, Message: err, Err: errors.New(err)}, errors.New(err)
			}

			// call the next handler
			return next(ctx, request)
		}
	}
}

// MiddlewareValidateAccessToken validates whether the request contains a bearer token
// it also decodes and authenticates the given token
func MiddlewareValidateAccessToken(logger log.Logger, authHelper *helper.AuthHelper) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{})(interface{}, error) {

			logger.Log("validating access token")

			token, ok := ctx.Value(kithttp.ContextKeyRequestAuthorization).(string)
			if !ok {
				logger.Log("token not provided or malformed")
				errMsg := "Authentication failed. Token not provided or malformed"
				return &GenericResponse{Status: false, Message: errMsg}, errors.New(errMsg)
			}
			logger.Log("token present in header", token)

			userID, err := authHelper.ValidateAccessToken(token)
			if err != nil {
				logger.Log("token validation failed", "error", err)
				errMgs := "Authentication failed. Invalid token"
				return &GenericResponse{Status: false, Message: errMgs}, errors.New(errMgs)
			}
			logger.Log("access token validated")

			ctx = context.WithValue(ctx, UserIDKey{}, userID)
			return next(ctx, request)
		}
	}
}

// MiddlewareValidateRefreshToken validates whether the request contains a bearer token
// it also decodes and authenticates the given token
func MiddlewareValidateRefreshToken(logger log.Logger, authHelper *helper.AuthHelper, repo signup.Repository) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{})(interface{}, error) {


			logger.Log("validating refresh token")

			token, ok := ctx.Value(kithttp.ContextKeyRequestAuthorization).(string)
			if !ok {
				logger.Log("token not provided or malformed")
				errMsg := "Authentication failed. Token not provided or malformed"
				return &GenericResponse{Status: false, Message: errMsg}, errors.New(errMsg)
			}
			logger.Log("token present in header", token)

			userID, customKey, err := authHelper.ValidateRefreshToken(token)
			if err != nil {
				logger.Log("token validation failed", "error", err)
				errMsg := "Authentication failed. Invalid token"
				return &GenericResponse{Status: false, Message: "Authentication failed. Invalid token"}, errors.New(errMsg)
			}
			logger.Log("refresh token validated")

			user, err := repo.GetUserByID(context.Background(), userID)
			if err != nil {
				logger.Log("invalid token: wrong userID while parsing", err)
				errMsg := "Unable to fetch corresponding user"
				return &GenericResponse{Status: false, Message: errMsg}, errors.New(errMsg)
			}

			actualCustomKey := authHelper.GenerateCustomKey(user.ID, user.TokenHash)
			if customKey != actualCustomKey {
				logger.Log("wrong token: authetincation failed")
				errMsg := "Authentication failed. Invalid token"
				return &GenericResponse{Status: false, Message: "Authentication failed. Invalid token"}, errors.New(errMsg)
			}

			ctx = context.WithValue(ctx, UserKey{}, *user)
			return next(ctx, request)
		}
	}
}

// MiddlerwareValidateVerificationData validates whether the request contains the email
// and confirmation code that are required for the verification
func MiddlewareValidateVerificationData(logger log.Logger, validator *data.Validation) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{})(interface{}, error) {

			logger.Log("validating verification data")

			verificationData := request.(data.VerificationData)

			errs := validator.Validate(verificationData)
			if len(errs) != 0 {
				logger.Log("validation of verification data json failed", "error", errs)
				errMsg := "validation of verification data json failed"
				return &GenericResponse{Status: false, Message: strings.Join(errs.Errors(), ",")}, errors.New(errMsg)
			}

			// add the ValidationData to context
			ctx = context.WithValue(ctx, VerificationDataKey{}, verificationData)
			return next(ctx, request)
		}
	}
}
