package auth

import (
	"context"
	"errors"
	"github.com/go-kit/kit/log"
	"strings"

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
	VerifyPasswordReset(_ context.Context, verificationData *data.VerificationData) (*VerifyPasswordResetResponse, error)
	RefreshToken(_ context.Context, user *data.User) (*RefreshTokenResponse, error)
	GeneratePassResetCode(_ context.Context, user *data.User) (*GeneratePassResetCodeResponse, error)
	UpdateUsername(_ context.Context, user *data.User) (*UpdateUsernameResponse, error)
	ResetPassword(ctx context.Context, user *data.PasswordResetReq) (*ResetPasswordResponse, error)
}

//service
type service struct {
	logger log.Logger
	repo   signup.Repository
}

//NewService
func NewService(signup signup.Repository, logger log.Logger) Service {
	return &service{repo: signup, logger: logger}
}

//Signup
func (s *service) Signup(ctx context.Context, user *data.User) (sig *SignupResponse, err error) {

	hashedPass, err := authServiceHelper.HashPassword(user.Password)
	if err != nil {
		return &SignupResponse{Status: false, Message: UserCreationFailed}, nil
	}
	user.Password = hashedPass
	user.TokenHash = utils.GenerateRandomString(15)

	err = s.repo.Signup(context.Background(), user)
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

//Login
func (s *service) Login(_ context.Context, reqUser *data.User) (l *LoginResponse, err error) {
	user, err := s.repo.GetUserByEmail(context.Background(), reqUser.Email)
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

//VerifyMail
func (s *service) VerifyMail(_ context.Context, verificationData *data.VerificationData) (*VerifyMailResponse, error) {
	s.logger.Log("verifying the confimation code")
	verificationData.Type = data.MailConfirmation

	actualVerificationData, err := s.repo.GetVerificationData(context.Background(), verificationData.Email, verificationData.Type)
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

//VerifyPasswordReset
func (s *service) VerifyPasswordReset(_ context.Context, verificationData *data.VerificationData) (*VerifyPasswordResetResponse, error) {
	s.logger.Log("verifying the confimation code")
	verificationData.Type = data.MailConfirmation

	actualVerificationData, err := s.repo.GetVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		s.logger.Log("unable to fetch verification data", "error", err)
		if strings.Contains(err.Error(), PgNoRowsMsg) {
			return &VerifyPasswordResetResponse{Status: false, Message: ErrUserNotFound}, nil
		}
		return &VerifyPasswordResetResponse{Status: false, Message: "Unable to reset password. Please try again later"}, nil
	}

	valid, err := authServiceHelper.Verify(actualVerificationData, verificationData)
	if !valid {
		return &VerifyPasswordResetResponse{Status: false, Message: err.Error()}, nil
	}

	respData := struct{
		Code string
	}{
		Code: verificationData.Code,
	}

	s.logger.Log("password reset code verification succeeded")

	return &VerifyPasswordResetResponse{Status: true, Message: "Password Reset code verification succeeded", Data: respData}, nil
}

//RefreshToken
func (s *service) RefreshToken(_ context.Context, user *data.User) (*RefreshTokenResponse, error) {
	accessToken, err := authServiceHelper.GenerateAccessToken(user)
	if err != nil {
		s.logger.Log("unable to generate access token", "error", err)
		return &RefreshTokenResponse{Status: false, Message: "Unable to generate access token.Please try again later", Err: err}, err
	}
	return &RefreshTokenResponse{
		Status:  true,
		Message: "Successfully generated new access token",
		Data:    &TokenResponse{AccessToken: accessToken},
	}, nil
}

//GeneratePassResetCode
func (s *service) GeneratePassResetCode(ctx context.Context, user *data.User) (*GeneratePassResetCodeResponse, error) {
	user, err := s.repo.GetUserByID(context.Background(), user.ID)
	if err != nil {
		s.logger.Log("unable to get user to generate secret code for password reset", "error", err)
		return &GeneratePassResetCodeResponse{Status: false, Message: "Unable to send password reset code. Please try again later"}, err
	}

	// Send verification mail
	from := "heber.luiz.cunha@gmail.com"
	to := []string{user.Email}
	subject := "Password Reset for yoorquezt"
	mailType := mail2.PassReset
	mailData := &mail2.MailData{
		Username: user.Username,
		Code: 	utils.GenerateRandomString(8),
	}

	err = authServiceHelper.SenMail(from, to, subject, mailType, mailData)
	if err != nil {
		return &GeneratePassResetCodeResponse{Status: false, Message: ResetPassCodeFailed, Err: err}, err
	}

	verificationData := authServiceHelper.BuildVerificationDataREsetPassCode(user, mailData)
	err = authServiceHelper.StoreVerificationData(ctx, verificationData)
	if err != nil {
		return &GeneratePassResetCodeResponse{Status: false, Message: ResetPassCodeFailed, Err: err}, err
	}


	s.logger.Log("successfully mailed password reset code")

	return &GeneratePassResetCodeResponse{
		Status:  true,
		Message: ResetPassCodeSuccess,
	}, nil
}

//UpdateUsername
func (s *service) UpdateUsername(ctx context.Context, user *data.User) (*UpdateUsernameResponse, error) {
	err := s.repo.UpdateUsername(ctx, user)
	if err != nil {
		s.logger.Log("unable to update username", "error", err)
		return &UpdateUsernameResponse{Status: false, Message: UpdateUsernameFailed, Err: err}, err
	}
	return &UpdateUsernameResponse{Status: true, Message: UpdateUsernameSuccess, Data: &data.UsernameUpdate{Username: user.Username}}, nil
}

//ResetPassword
func (s *service) ResetPassword(ctx context.Context, passResetReq *data.PasswordResetReq) (*ResetPasswordResponse, error) {
	userID := ctx.Value(UserIDKey{}).(string)
	user, err := s.repo.GetUserByID(context.Background(), userID)
	if err != nil {
		s.logger.Log("unable to retrieve the user from db", "error", err)
		return &ResetPasswordResponse{Status: false, Message: ErrRetrieveUser, Err: err}, err
	}

	verificationData, err := s.repo.GetVerificationData(context.Background(), user.Email, data.PassReset)
	if err != nil {
		s.logger.Log("unable to retrieve the verification data from db", "error", err)
		return &ResetPasswordResponse{Status: false, Message: ResetPasswordFailed, Err: err}, err
	}

	if verificationData.Code != passResetReq.Code {
		// we should never be here.
		s.logger.Log("verification code did not match even after verifying PassReset")
		return &ResetPasswordResponse{Status: false, Message: ResetPasswordFailed, Err: err}, err
	}

	if passResetReq.Password != passResetReq.PasswordRe {
		s.logger.Log("password and password re-enter did not match")
		return &ResetPasswordResponse{Status: false, Message: DuplicatePassword, Err: err}, err
	}

	hashedPass, err := authServiceHelper.HashPassword(passResetReq.Password)
	if err != nil {
		s.logger.Log(UserCreationFailed)
		return &ResetPasswordResponse{Status: false, Message: UserCreationFailed, Err: err}, err
	}

	tokenHash := utils.GenerateRandomString(15)
	err = s.repo.UpdatePassword(context.Background(), userID, hashedPass, tokenHash)
	if err != nil {
		s.logger.Log("unable to update user password in db", "error", err)
		return &ResetPasswordResponse{Status: false, Message: UpdatePasswordFailed, Err: err}, err
	}

	// delete the VerificationData from db
	err = s.repo.DeleteVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		s.logger.Log("unable to delete the verification data", "error", err)
	}

	return &ResetPasswordResponse{
		Status:  false,
		Message: UpadatePasswordSuccess,
	}, nil
}