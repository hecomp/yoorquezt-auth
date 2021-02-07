package helper

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"

	"golang.org/x/crypto/bcrypt"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	mail2 "github.com/hecomp/yoorquezt-auth/pkg/mail"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
)

type IAuthHelper interface {
	StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error
	HashPassword(password string) (string, error)
	Validate(i interface{}) data.ValidationErrors
	SenMail(from string, to []string, subject string, mailType mail2.MailType, mailData *mail2.MailData) error
	BuildVerificationData(user *data.User, mailData *mail2.MailData) *data.VerificationData
	Authenticate(reqUser *data.User, user *data.User) bool
	GenerateAccessToken(user *data.User) (string, error)
	GenerateRefreshToken(user *data.User) (string, error)
	Verify(actualVerificationData *data.VerificationData, verificationData *data.VerificationData) (bool, error)
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error
	DeleteVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) error
	ErrorMsgs(message, msg, err string)
	ErrorMsg(message, err string)
	Error(message string)
	Log(message string)
	Debug(msg1, msg2, msg3, msg4, msg5 string)
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

type AuthHelper struct {
	logger      log.Logger
	mailService mail2.MailService
	validator   *data.Validation
	repo        signup.Repository
	configs     *utils.Configurations
}

func NewHelper(logger log.Logger, mailService mail2.MailService, validator *data.Validation, repository signup.Repository, configs *utils.Configurations) *AuthHelper {
	return &AuthHelper{
		logger: logger,
		mailService: mailService,
		validator: validator,
		repo: repository,
		configs: configs,
	}
}


func (auth *AuthHelper) StoreVerificationData(_ context.Context, verificationData *data.VerificationData) error {
	err := auth.repo.StoreVerificationData(context.Background(), verificationData)
	if err != nil {
		auth.logger.Log("unable to store mail verification data", "error", err)
		return err
	}
	auth.logger.Log("User created successfully")
	return nil
}

// Authenticate checks the user credentials in request against the db and authenticates the request
func (auth *AuthHelper) Authenticate(reqUser *data.User, user *data.User) bool {

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqUser.Password)); err != nil {
		auth.logger.Log("password hashes are not same")
		return false
	}
	return true
}

// GenerateRefreshToken generate a new refresh token for the given user
func (auth *AuthHelper) GenerateRefreshToken(user *data.User) (string, error) {

	cusKey := auth.GenerateCustomKey(user.ID, user.TokenHash)
	tokenType := "refresh"

	claims := RefreshTokenCustomClaims{
		user.ID,
		cusKey,
		tokenType,
		jwt.StandardClaims{
			Issuer: "yoorquezt.auth.service",
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
func (auth *AuthHelper) GenerateAccessToken(user *data.User) (string, error) {

	userID := user.ID
	tokenType := "access"

	claims := AccessTokenCustomClaims{
		userID,
		tokenType,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(auth.configs.JwtExpiration)).Unix(),
			Issuer:    "yoorquezt.auth.service",
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
func (auth *AuthHelper) GenerateCustomKey(userID string, tokenHash string) string {

	// data := userID + tokenHash
	h := hmac.New(sha256.New, []byte(tokenHash))
	h.Write([]byte(userID))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

// ValidateAccessToken parses and validates the given access token
// returns the userId present in the token payload
func (auth *AuthHelper) ValidateAccessToken(tokenString string) (string, error) {

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
		return "", errors.New("invalid token: auth failed")
	}
	return claims.UserID, nil
}

// ValidateRefreshToken parses and validates the given refresh token
// returns the userId and customkey present in the token payload
func (auth *AuthHelper) ValidateRefreshToken(tokenString string) (string, string, error) {

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
		return "", "", errors.New("invalid token: auth failed")
	}
	return claims.UserID, claims.CustomKey, nil
}

func (auth *AuthHelper) HashPassword(password string) (string, error) {

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		auth.logger.Log("unable to hash password", "error", err)
		return "", err
	}

	return string(hashedPass), nil
}

func (auth *AuthHelper) Validate(i interface{}) data.ValidationErrors {
	err:= auth.validator.Validate(i)
	if len(err) != 0 {
		auth.logger.Log("validation of user json failed", "error", err)
		return err
	}
	return err
}

func (auth *AuthHelper) SenMail(from string, to []string, subject string, mailType mail2.MailType, mailData *mail2.MailData) error {
	mailReq := auth.mailService.NewMail(from, to, subject, mailType, mailData)
	err := auth.mailService.SendMail(mailReq)
	if err != nil {
		auth.logger.Log("sending mail to user failed", "error", err)
		return err
	}
	return nil
}

func (auth *AuthHelper) BuildVerificationData(user *data.User, mailData *mail2.MailData) *data.VerificationData {
	return &data.VerificationData{
		Email: user.Email,
		Code : mailData.Code,
		Type : data.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(auth.configs.MailVerifCodeExpiration)),
	}
}

func (auth *AuthHelper) Verify(actualVerificationData *data.VerificationData, verificationData *data.VerificationData) (bool, error) {

	// check for expiration
	if actualVerificationData.ExpiresAt.Before(time.Now()) {
		auth.logger.Log("verification data provided is expired")
		err := auth.repo.DeleteVerificationData(context.Background(), actualVerificationData.Email, actualVerificationData.Type)
		auth.logger.Log("unable to delete verification data from db", "error", err)
		return false, errors.New("Confirmation code has expired. Please try generating a new code")
	}

	if actualVerificationData.Code != verificationData.Code {
		auth.logger.Log("verification of mail failed. Invalid verification code provided")
		return false, errors.New("Verification code provided is Invalid. Please look in your mail for the code")
	}

	return true, nil
}

func (auth *AuthHelper) UpdateUserVerificationStatus(_ context.Context, email string, status bool) error  {
	err := auth.repo.UpdateUserVerificationStatus(context.Background(), email, status)
	if err != nil {
		auth.logger.Log("unable to set user verification status to true")
		return err
	}
	return nil
}

func (auth *AuthHelper) DeleteVerificationData(_ context.Context, email string, verificationDataType data.VerificationDataType) error  {
	err := auth.repo.DeleteVerificationData(context.Background(), email, verificationDataType)
	if err != nil {
		auth.logger.Log("unable to delete the verification data", "error")
		return err
	}
	return nil
}

func (auth *AuthHelper) ErrorMsg(message, err string) {
	auth.logger.Log(message, err)
}

func (auth *AuthHelper) ErrorMsgs(message, msg, err string) {
	auth.logger.Log(message, msg, err)
}

func (auth *AuthHelper) Error(message string)  {
	auth.logger.Log(message)
}

func (auth *AuthHelper) Log(message string)  {
	auth.logger.Log(message)
}

func (auth *AuthHelper) Debug(msg1, msg2, msg3, msg4, msg5 string)  {
	auth.logger.Log(msg1, msg2, msg3, msg4, msg5)
}