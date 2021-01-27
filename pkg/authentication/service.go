package authentication

import (
	"context"
	"errors"

	"github.com/go-kit/kit/log"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
)

// ErrInvalidArgument is returned when one or more arguments are invalid.
var ErrInvalidArgument = errors.New("invalid argument")

// Service is the interface that provides signup methods.
type Service interface {
	Signup(ctx context.Context, user *data.User) error
	Login(ctx context.Context, user *data.User) (*data.User, error)
	VerifyMail(_ context.Context, verificationData *data.VerificationData) (*data.VerificationData, error)
}

type service struct {
	logger      log.Logger
	signupRepo signup.Repository
}

func NewService(signup signup.Repository, logger log.Logger) Service {
	return service{signupRepo: signup, logger: logger}
}

func (s service) Signup(_ context.Context, user *data.User) error {
	err := s.signupRepo.Signup(context.Background(), user)
	if err != nil {
		s.logger.Log("unable to insert user to database", "error", err)
		return err
	}
	return nil
}

func (s service) Login(ctx context.Context, user *data.User) (*data.User, error) {
	user, err := s.signupRepo.GetUserByEmail(context.Background(), user.Email)
	if err != nil {
		s.logger.Log("error fetching the user", "error", err)
		return nil, err
	}
	return user, nil
}

func (s service) VerifyMail(_ context.Context, verificationData *data.VerificationData) (*data.VerificationData, error) {
	actualVerificationData, err := s.signupRepo.GetVerificationData(context.Background(), verificationData.Email, verificationData.Type)
	if err != nil {
		s.logger.Log("unable to fetch verification data", "error", err)
		return nil, err
	}
	return actualVerificationData, nil
}