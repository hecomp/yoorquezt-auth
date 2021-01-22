package yoorqueztservice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	"github.com/hecomp/yoorquezt-auth/pkg/yoorqueztrepository"
)

// Authentication describes a service that adds things together.
type Authentication interface {
	Signup(ctx context.Context, user *data.User) error
	StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error
	HashPassword(password string) (string, error)
	Concat(ctx context.Context, a, b string) (string, error)
	Authenticate(reqUser *data.User, user *data.User) bool
	GenerateAccessToken(user *data.User) (string, error)
	GenerateRefreshToken(user *data.User) (string, error)
	GenerateCustomKey(userID string, password string) string
	ValidateAccessToken(token string) (string, error)
	ValidateRefreshToken(token string) (string, string, error)
	ValidateUser(user *data.User) data.ValidationErrors
	SenMail(from string, to []string, subject string, mailType MailType, mailData *MailData) error
	BuildVerificationData(user *data.User, mailData *MailData) *data.VerificationData
}

// RefreshTokenCustomClaims specifies the claims for refresh token
type RefreshTokenCustomClaims struct {
	UserID    string
	CustomKey string
	KeyType   string
	jwt.StandardClaims
}

// AccessTokenCustomClaims specifies the claims for access token
type AccessTokenCustomClaims struct {
	UserID  string
	KeyType string
	jwt.StandardClaims
}

// New returns a basic Authentication with all of the expected middlewares wired in.
func New(logger log.Logger, configs *utils.Configurations, repository *yoorqueztrepository.PostgresRepository, mailService MailService, validator *data.Validation, ints, chars metrics.Counter) Authentication {
	var svc Authentication
	{
		svc = NewAuthService(logger, configs, repository, mailService, validator)
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
	mailService MailService
	validator   *data.Validation
}

// NewAuthService returns a naïve, stateless implementation of Authentication.
func NewAuthService(logger log.Logger, configs *utils.Configurations, repository *yoorqueztrepository.PostgresRepository, mailService MailService, validator *data.Validation) *AuthService {
	return &AuthService{
		logger: logger,
		configs: configs,
		repo: repository,
		mailService: mailService,
		validator: validator,
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


func (auth *AuthService) StoreVerificationData(_ context.Context, verificationData *data.VerificationData) error {
	err := auth.repo.StoreVerificationData(context.Background(), verificationData)
	if err != nil {
		auth.logger.Log("unable to store mail verification data", "error", err)
		return err
	}
	auth.logger.Log("User created successfully")
	return nil
}

// Authenticate checks the user credentials in request against the db and authenticates the request
func (auth *AuthService) Authenticate(reqUser *data.User, user *data.User) bool {

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqUser.Password)); err != nil {
		auth.logger.Log("password hashes are not same")
		return false
	}
	return true
}

// GenerateRefreshToken generate a new refresh token for the given user
func (auth *AuthService) GenerateRefreshToken(user *data.User) (string, error) {

	cusKey := auth.GenerateCustomKey(user.ID, user.TokenHash)
	tokenType := "refresh"

	claims := RefreshTokenCustomClaims{
		user.ID,
		cusKey,
		tokenType,
		jwt.StandardClaims{
			Issuer: "bookite.auth.service",
		},
	}

	signBytes, err := ioutil.ReadFile(auth.configs.RefreshTokenPrivateKeyPath)
	if err != nil {
		auth.logger.Log("unable to read private key", "error", err)
		return "", errors.New("could not generate refresh token. please try again later")
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		auth.logger.Log("unable to parse private key", "error", err)
		return "", errors.New("could not generate refresh token. please try again later")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

// GenerateAccessToken generates a new access token for the given user
func (auth *AuthService) GenerateAccessToken(user *data.User) (string, error) {

	userID := user.ID
	tokenType := "access"

	claims := AccessTokenCustomClaims{
		userID,
		tokenType,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(auth.configs.JwtExpiration)).Unix(),
			Issuer:    "bookite.auth.service",
		},
	}

	signBytes, err := ioutil.ReadFile(auth.configs.AccessTokenPrivateKeyPath)
	if err != nil {
		auth.logger.Log("unable to read private key", "error", err)
		return "", errors.New("could not generate access token. please try again later")
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		auth.logger.Log("unable to parse private key", "error", err)
		return "", errors.New("could not generate access token. please try again later")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(signKey)
}

// GenerateCustomKey creates a new key for our jwt payload
// the key is a hashed combination of the userID and user tokenhash
func (auth *AuthService) GenerateCustomKey(userID string, tokenHash string) string {

	// data := userID + tokenHash
	h := hmac.New(sha256.New, []byte(tokenHash))
	h.Write([]byte(userID))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

// ValidateAccessToken parses and validates the given access token
// returns the userId present in the token payload
func (auth *AuthService) ValidateAccessToken(tokenString string) (string, error) {

	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			auth.logger.Log("Unexpected signing method in auth token")
			return nil, errors.New("Unexpected signing method in auth token")
		}
		verifyBytes, err := ioutil.ReadFile(auth.configs.AccessTokenPublicKeyPath)
		if err != nil {
			auth.logger.Log("unable to read public key", "error", err)
			return nil, err
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			auth.logger.Log("unable to parse public key", "error", err)
			return nil, err
		}

		return verifyKey, nil
	})

	if err != nil {
		auth.logger.Log("unable to parse claims", "error", err)
		return "", err
	}

	claims, ok := token.Claims.(*AccessTokenCustomClaims)
	if !ok || !token.Valid || claims.UserID == "" || claims.KeyType != "access" {
		return "", errors.New("invalid token: authentication failed")
	}
	return claims.UserID, nil
}

// ValidateRefreshToken parses and validates the given refresh token
// returns the userId and customkey present in the token payload
func (auth *AuthService) ValidateRefreshToken(tokenString string) (string, string, error) {

	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			auth.logger.Log("Unexpected signing method in auth token")
			return nil, errors.New("Unexpected signing method in auth token")
		}
		verifyBytes, err := ioutil.ReadFile(auth.configs.RefreshTokenPublicKeyPath)
		if err != nil {
			auth.logger.Log("unable to read public key", "error", err)
			return nil, err
		}

		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			auth.logger.Log("unable to parse public key", "error", err)
			return nil, err
		}

		return verifyKey, nil
	})

	if err != nil {
		auth.logger.Log("unable to parse claims", "error", err)
		return "", "", err
	}

	claims, ok := token.Claims.(*RefreshTokenCustomClaims)
	auth.logger.Log("ok", ok)
	if !ok || !token.Valid || claims.UserID == "" || claims.KeyType != "refresh" {
		auth.logger.Log("could not extract claims from token")
		return "", "", errors.New("invalid token: authentication failed")
	}
	return claims.UserID, claims.CustomKey, nil
}

func (auth *AuthService) HashPassword(password string) (string, error) {

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		auth.logger.Log("unable to hash password", "error", err)
		return "", err
	}

	return string(hashedPass), nil
}

func (auth *AuthService) ValidateUser(user *data.User) data.ValidationErrors {
	err:= auth.validator.Validate(user)
	if len(err) != 0 {
		auth.logger.Log("validation of user json failed", "error", err)
		return err
	}
	return err
}

func (auth *AuthService) SenMail(from string, to []string, subject string, mailType MailType, mailData *MailData) error {
	mailReq := auth.mailService.NewMail(from, to, subject, mailType, mailData)
	err := auth.mailService.SendMail(mailReq)
	if err != nil {
		auth.logger.Log("sending mail to user failed", "error", err)
		return err
	}
	return nil
}

func (auth *AuthService) BuildVerificationData(user *data.User, mailData *MailData) *data.VerificationData {
	return &data.VerificationData{
		Email: user.Email,
		Code : mailData.Code,
		Type : data.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(auth.configs.MailVerifCodeExpiration)),
	}
}

// Concat implements Authentication.
func (auth AuthService) Concat(_ context.Context, a, b string) (string, error) {
	if len(a)+len(b) > maxLen {
		return "", ErrMaxSizeExceeded
	}
	return a + b, nil
}


