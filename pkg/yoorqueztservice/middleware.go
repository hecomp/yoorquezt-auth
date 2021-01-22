package yoorqueztservice
import (
	"context"
	"github.com/hecomp/yoorquezt-auth/internal/data"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
)

// Middleware describes a service (as opposed to endpoint) middleware.
type Middleware func(Authentication) Authentication

// MailMiddleware describes a service (as opposed to endpoint) middleware.
type MailMiddleware func(MailService) MailService

// LoggingMiddleware takes a logger as a dependency
// and returns a service Middleware.
func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next Authentication) Authentication {
		return loggingMiddleware{logger, next}
	}
}

func LoggingMailMiddleware(logger log.Logger) MailMiddleware {
	return func(next MailService) MailService {
		return loggingMailMiddleware{logger, next}
	}
}

type loggingMiddleware struct {
	logger log.Logger
	next   Authentication
}

type loggingMailMiddleware struct {
	logger log.Logger
	next   MailService
}

func (mw loggingMailMiddleware) CreateMail(mailReq *Mail) []byte {
	defer func() {
		mw.logger.Log("method", "CreateMail")
	}()
	return mw.next.CreateMail(mailReq)
}

func (mw loggingMailMiddleware) SendMail(mailReq *Mail) error {
	defer func() {
		mw.logger.Log("method", "SendMail")
	}()
	return mw.next.SendMail(mailReq)
}

func (mw loggingMailMiddleware) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	defer func() {
		mw.logger.Log("method", "NewMail")
	}()
	return mw.next.NewMail(from, to, subject, mailType, data)
}

func (mw loggingMiddleware) Signup(ctx context.Context, user *data.User) (err error) {
	defer func() {
		mw.logger.Log("method", "Signup", "ID", user.ID, "Email", user.Email, "err", err)
	}()
	return mw.next.Signup(ctx, user)
}

func (mw loggingMiddleware) Concat(ctx context.Context, a, b string) (v string, err error) {
	defer func() {
		mw.logger.Log("method", "Concat", "a", a, "b", b, "v", v, "err", err)
	}()
	return mw.next.Concat(ctx, a, b)
}

// InstrumentingMiddleware returns a service middleware that instruments
// the number of integers summed and characters concatenated over the lifetime of
// the service.
func InstrumentingMiddleware(ints, chars metrics.Counter) Middleware {
	return func(next Authentication) Authentication {
		return instrumentingMiddleware{
			ints:  ints,
			chars: chars,
			next:  next,
		}
	}
}

type instrumentingMiddleware struct {
	ints  metrics.Counter
	chars metrics.Counter
	next  Authentication
}

func (mw instrumentingMiddleware) Signup(ctx context.Context, user *data.User) error {
	err := mw.next.Signup(ctx, user)
	mw.chars.Add(float64(len(user.ID)))
	return err
}

func (mw instrumentingMiddleware) Concat(ctx context.Context, a, b string) (string, error) {
	v, err := mw.next.Concat(ctx, a, b)
	mw.chars.Add(float64(len(v)))
	return v, err
}

// InstrumentingMailMiddleware returns a service middleware that instruments
// the number of integers summed and characters concatenated over the lifetime of
// the service.
func InstrumentingMailMiddleware(ints, chars metrics.Counter) MailMiddleware {
	return func(next MailService) MailService {
		return instrumentingMailMiddleware{
			ints:  ints,
			chars: chars,
			next:  next,
		}
	}
}

type instrumentingMailMiddleware struct {
	ints  metrics.Counter
	chars metrics.Counter
	next  MailService
}

func (i instrumentingMailMiddleware) CreateMail(mailReq *Mail) []byte {
	err := i.next.CreateMail(mailReq)
	i.chars.Add(float64(len(mailReq.from)))
	return err
}

func (i instrumentingMailMiddleware) SendMail(mailReq *Mail) error {
	err := i.next.SendMail(mailReq)
	i.chars.Add(float64(len(mailReq.from)))
	return err
}

func (i instrumentingMailMiddleware) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	err := i.next.NewMail(from, to, subject, mailType, data)
	i.chars.Add(float64(len(from)))
	return err
}

