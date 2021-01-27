package authentication

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"

	"github.com/hecomp/yoorquezt-auth/internal/data"
)

type loggingService struct {
	logger log.Logger
	Service
}

func NewLoggingService(logger log.Logger, s Service) Service {
	return &loggingService{logger: logger, Service: s}
}

func (s *loggingService) Signup(ctx context.Context, user *data.User) (err error)  {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "signup",
			"user", user,
			"took", time.Since(begin),
			"err", err,
			)
	}(time.Now())
	return s.Service.Signup(ctx, user)
}

func (s *loggingService) Login(ctx context.Context, user *data.User) (userReq *data.User, err error)  {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "Login",
			"user", user,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.Service.Login(ctx, user)
}

func (s *loggingService) VerifyMail(ctx context.Context, verificationData *data.VerificationData) (ver *data.VerificationData, err error)  {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "VerifyMail",
			"user", verificationData,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return s.Service.VerifyMail(ctx, verificationData)
}
