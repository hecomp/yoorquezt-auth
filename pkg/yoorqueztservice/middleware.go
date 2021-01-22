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

func (mw loggingMiddleware) HashPassword(password string) (string, error) {
	defer func() {
		mw.logger.Log("method", "HashPassword")
	}()
	return mw.next.HashPassword(password)
}

func (mw loggingMiddleware) Authenticate(reqUser *data.User, user *data.User) bool {
	defer func() {
		mw.logger.Log("method", "Authenticate")
	}()
	return mw.next.Authenticate(reqUser, user)
}

func (mw loggingMiddleware) GenerateAccessToken(user *data.User) (string, error) {
	defer func() {
		mw.logger.Log("method", "GenerateAccessToken")
	}()
	return mw.next.GenerateAccessToken(user)
}

func (mw loggingMiddleware) GenerateRefreshToken(user *data.User) (string, error) {
	defer func() {
		mw.logger.Log("method", "GenerateRefreshToken")
	}()
	return mw.next.GenerateRefreshToken(user)
}

func (mw loggingMiddleware) GenerateCustomKey(userID string, password string) string {
	defer func() {
		mw.logger.Log("method", "GenerateCustomKey")
	}()
	return mw.next.GenerateCustomKey(userID, password)
}

func (mw loggingMiddleware) ValidateAccessToken(token string) (string, error) {
	defer func() {
		mw.logger.Log("method", "ValidateAccessToken")
	}()
	return mw.next.ValidateAccessToken(token)
}

func (mw loggingMiddleware) ValidateRefreshToken(token string) (string, string, error) {
	defer func() {
		mw.logger.Log("method", "ValidateRefreshToken")
	}()
	return mw.next.ValidateRefreshToken(token)
}

func (mw loggingMiddleware) ValidateUser(user *data.User) data.ValidationErrors {
	defer func() {
		mw.logger.Log("method", "ValidateUser")
	}()
	return mw.next.ValidateUser(user)
}

func (mw loggingMiddleware) SenMail(from string, to []string, subject string, mailType MailType, mailData *MailData) error {
	defer func() {
		mw.logger.Log("method", "SenMail")
	}()
	return mw.next.SenMail(from, to, subject, mailType,  mailData)
}

func (mw loggingMiddleware) BuildVerificationData(user *data.User, mailData *MailData) *data.VerificationData {
	defer func() {
		mw.logger.Log("method", "BuildVerificationData")
	}()
	return mw.next.BuildVerificationData(user, mailData)
}

func (mw loggingMiddleware) StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error {
	defer func() {
		mw.logger.Log("method", "StoreVerificationData")
	}()
	return mw.next.StoreVerificationData(ctx, verificationData)
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

func (mw instrumentingMiddleware) ValidateUser(user *data.User) data.ValidationErrors {
	err := mw.next.ValidateUser(user)
	mw.chars.Add(float64(len(err)))
	return err
}

func (mw instrumentingMiddleware) SenMail(from string, to []string, subject string, mailType MailType, mailData *MailData) error {
	err := mw.next.SenMail(from, to, subject, mailType, mailData)
	mw.chars.Add(float64(len(err.Error())))
	return err
}

func (mw instrumentingMiddleware) BuildVerificationData(user *data.User, mailData *MailData) *data.VerificationData {
	verificationData := mw.next.BuildVerificationData(user, mailData)
	mw.chars.Add(float64(len(verificationData.Email)))
	return verificationData
}

func (mw instrumentingMiddleware) StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error {
	err := mw.next.StoreVerificationData(ctx, verificationData)
	mw.chars.Add(float64(len(verificationData.Email)))
	return err
}

func (mw instrumentingMiddleware) HashPassword(password string) (string, error) {
	hash, err := mw.next.HashPassword(password)
	mw.chars.Add(float64(len(hash)))
	return hash, err
}

func (mw instrumentingMiddleware) Authenticate(reqUser *data.User, user *data.User) bool {
	isAuth := mw.next.Authenticate(reqUser, user)
	mw.chars.Add(float64(len(reqUser.ID)))
	return isAuth
}

func (mw instrumentingMiddleware) GenerateAccessToken(user *data.User) (string, error) {
	token, err := mw.next.GenerateAccessToken(user)
	mw.chars.Add(float64(len(token)))
	return token, err
}

func (mw instrumentingMiddleware) GenerateRefreshToken(user *data.User) (string, error) {
	token, err := mw.next.GenerateRefreshToken(user)
	mw.chars.Add(float64(len(token)))
	return token, err
}

func (mw instrumentingMiddleware) GenerateCustomKey(userID string, password string) string {
	token := mw.next.GenerateCustomKey(userID, password)
	mw.chars.Add(float64(len(token)))
	return token
}

func (mw instrumentingMiddleware) ValidateAccessToken(token string) (string, error) {
	token, err := mw.next.ValidateAccessToken(token)
	mw.chars.Add(float64(len(token)))
	return token, err
}

func (mw instrumentingMiddleware) ValidateRefreshToken(token string) (string, string, error) {
	userId, customKey, err := mw.next.ValidateRefreshToken(token)
	mw.chars.Add(float64(len(userId)))
	return userId, customKey, err
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

