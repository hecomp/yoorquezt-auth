package yoorqueztservice

import (
	"context"
	"errors"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztrepository"
)

// Authentication describes a service that adds things together.
type Authentication interface {
	Signup(ctx context.Context, user *data.User) error
	Concat(ctx context.Context, a, b string) (string, error)
}

// New returns a basic Authentication with all of the expected middlewares wired in.
func New(logger log.Logger, configs *utils.Configurations, repository *yoorqueztrepository.PostgresRepository, ints, chars metrics.Counter) Authentication {
	var svc Authentication
	{
		svc = NewAuthService(logger, configs, repository)
		svc = LoggingMiddleware(logger)(svc)
		svc = InstrumentingMiddleware(ints, chars)(svc)
	}
	return svc
}

var (
	// ErrTwoZeroes is an arbitrary business rule for the Signup method.
	ErrTwoZeroes = errors.New("can't signup zeroes")

	// ErrIntOverflow protects the Add method. We've decided that this error
	// indicates a misbehaving service and should count against e.g. circuit
	// breakers. So, we return it directly in endpoints, to illustrate the
	// difference. In a real service, this probably wouldn't be the case.
	ErrIntOverflow = errors.New("integer overflow")

	// ErrMaxSizeExceeded protects the Concat method.
	ErrMaxSizeExceeded = errors.New("result exceeds maximum size")
)

// AuthService is the implementation of our Authentication
type AuthService struct{
	logger      log.Logger
	configs     *utils.Configurations
	repo        *yoorqueztrepository.PostgresRepository
}

// NewAuthService returns a naïve, stateless implementation of Authentication.
func NewAuthService(logger log.Logger, configs *utils.Configurations, repository *yoorqueztrepository.PostgresRepository) *AuthService {
	return &AuthService{
		logger: logger,
		configs: configs,
		repo: repository,
	}
}

const (
	intMax = 1<<31 - 1
	intMin = -(intMax + 1)
	maxLen = 10
)

func (auth *AuthService) Signup(_ context.Context, user *data.User) error {
	err := auth.repo.Create(context.Background(), user)
	if err != nil {
		auth.logger.Log("unable to insert user to database", "error", err)
		return err
	}
	return nil
}


// Concat implements Authentication.
func (auth AuthService) Concat(_ context.Context, a, b string) (string, error) {
	if len(a)+len(b) > maxLen {
		return "", ErrMaxSizeExceeded
	}
	return a + b, nil
}


