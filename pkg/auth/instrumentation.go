package auth

import (
	"context"
	"time"

	"github.com/go-kit/kit/metrics"

	"github.com/hecomp/yoorquezt-auth/internal/data"
)

type instrumentingService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	Service
}

// NewInstrumentingService returns an instance of an instrumenting Service.
func NewInstrumentingService(counter metrics.Counter, latency metrics.Histogram, s Service) Service {
	return &instrumentingService{
		requestCount:   counter,
		requestLatency: latency,
		Service:        s,
	}
}

func (i instrumentingService) Signup(ctx context.Context, user *data.User) (l *SignupResponse, err error) {
	defer func(begin time.Time) {
		i.requestCount.With("method", "signup").Add(1)
		i.requestLatency.With("method", "signup").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return i.Service.Signup(ctx, user)
}

func (i instrumentingService) Login(ctx context.Context, user *data.User) (*LoginResponse, error) {
	defer func(begin time.Time) {
		i.requestCount.With("method", "Login").Add(1)
		i.requestLatency.With("method", "Login").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return i.Service.Login(ctx, user)
}

func (i instrumentingService) VerifyMail(ctx context.Context, verificationData *data.VerificationData) (*VerifyMailResponse, error) {
	defer func(begin time.Time) {
		i.requestCount.With("method", "VerifyMail").Add(1)
		i.requestLatency.With("method", "VerifyMail").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return i.Service.VerifyMail(ctx, verificationData)
}
