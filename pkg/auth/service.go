package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/go-kit/kit/log"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	mail2 "github.com/hecomp/yoorquezt-auth/pkg/mail"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
)

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// Service is the interface that provides signup methods.
type Service interface {
	Signup(ctx context.Context, user *data.User) (*SignupResponse, error)
	Login(ctx context.Context, user *data.User) (*LoginResponse, error)
	VerifyMail(_ context.Context, verificationData *data.VerificationData) (*VerifyMailResponse, error)
}

type service struct {
	logger      log.Logger
	signupRepo signup.Repository
}

func NewService(signup signup.Repository, logger log.Logger) Service {
	return service{signupRepo: signup, logger: logger}
}

func (s service) Signup(ctx context.Context, user *data.User) (sig *SignupResponse, err error) {

	hashedPass, err := authServiceHelper.HashPassword(user.Password)
	if err != nil {
		return &SignupResponse{Status: false, Message: UserCreationFailed}, nil
	}
	user.Password = hashedPass
	user.TokenHash = utils.GenerateRandomString(15)

	err = s.signupRepo.Signup(context.Background(), user)
	if err != nil {
		s.logger.Log("unable to insert user to database", "error", err)
		errMsg := err.Error()
		if strings.Contains(errMsg, PgDuplicateKeyMsg) {
			return &SignupResponse{Status: false, Message: ErrUserAlreadyExists}, nil
		} else {
			return &SignupResponse{Status: false, Message: UserCreationFailed}, nil
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
		return &SignupResponse{Status: false, Message: UserCreationFailed, Err: err}, nil
	}

	verificationData := authServiceHelper.BuildVerificationData(user, mailData)
	err = authServiceHelper.StoreVerificationData(ctx, verificationData)
	if err != nil {
		return &SignupResponse{Status: false, Message: UserCreationFailed, Err: err}, nil
	}

	return &SignupResponse{Status: true, Message: UserCreationSuccess}, nil
}

func (s service) Login(_ context.Context, reqUser *data.User) (l *LoginResponse, err error) {
	user, err := s.signupRepo.GetUserByEmail(context.Background(), reqUser.Email)
	if err != nil {
		s.logger.Log("error fetching the user", "error", err)
		errMsg := err.Error()
		if strings.Contains(errMsg, PgNoRowsMsg) {
			return &LoginResponse{Status: false, Message: ErrUserNotFound, Err: err}, err
		} else {
			return &LoginResponse{Status: false, Message: ErrRetrieveUser, Err: err}, err
		}
	}

	if !user.IsVerified {
		s.logger.Log("unverified user")
		return &LoginResponse{Status: false, Message: VerifyEmail, Err: nil}, err
	}

	if valid := authServiceHelper.Authenticate(reqUser, user); !valid {
		s.logger.Log("Authetication of user failed")
		return &LoginResponse{Status: false, Message: IncorrectPassword, Err: nil}, err
	}

	accessToken, err := authServiceHelper.GenerateAccessToken(user)
	if err != nil {
		s.logger.Log("unable to generate access token", "error", err.Error())
		return &LoginResponse{Status: false, Message: ErrUnableToLogin, Err: err}, err
	}
	refreshToken, err := authServiceHelper.GenerateRefreshToken(user)
	if err != nil {
		authServiceHelper.ErrorMsgs("unable to generate refresh token", "error", err.Error())
		return &LoginResponse{Status: false, Message: ErrUnableToLogin, Err: err}, err
	}

	s.logger.Log("successfully generated token", "accesstoken", accessToken, "refreshtoken", refreshToken)

	return &LoginResponse{
		Status:  true,
		Message: "Successfully logged in",
		Data:    &AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken, Username: user.Username},
	}, nil
}

func (s service) VerifyMail(_ context.Context, verificationData *data.VerificationData) (*VerifyMailResponse, error) {
	s.logger.Log("verifying the confimation code")
	verificationData.Type = data.MailConfirmation

	actualVerificationData, err := s.signupRepo.GetVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		s.logger.Log("unable to fetch verification data", "error", err)
		if strings.Contains(err.Error(), PgNoRowsMsg) {
			return &VerifyMailResponse{Status: false, Message: ErrUserNotFound}, nil
		}
		return &VerifyMailResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, nil
	}

	valid, err := authServiceHelper.Verify(actualVerificationData, verificationData)
	if !valid {
		return &VerifyMailResponse{Status: false, Message: err.Error()}, nil
	}

	// correct code, update user status to verified.
	err = authServiceHelper.UpdateUserVerificationStatus(context.Background(), verificationData.Email, true)
	if err != nil {
		return &VerifyMailResponse{Status: false, Message: "Unable to verify mail. Please try again later"}, nil
	}

	// delete the VerificationData from db
	err = authServiceHelper.DeleteVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		authServiceHelper.ErrorMsgs("unable to delete the verification data", "error", err.Error())
	}

	s.logger.Log("user mail verification succeeded")

	return &VerifyMailResponse{Status: true, Message: "Mail Verification succeeded"}, nil
}