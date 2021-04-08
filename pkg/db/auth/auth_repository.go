package auth

import (
	"context"
	"github.com/go-kit/kit/log"
	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/pkg/signup"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/jmoiron/sqlx"
)

// AuthRepository has the implementation of the db methods.
type AuthRepository struct {
	db     *sqlx.DB
	logger log.Logger
}

// signupRepository has the implementation of the db methods.
type signupRepository struct {
	db     *sqlx.DB
	logger log.Logger
}

func NewSignupRepository(db *sqlx.DB, logger log.Logger)  signup.Repository{
	return &signupRepository{db, logger}
}

// Create inserts the given user into the database
func (r *signupRepository) Signup(ctx context.Context, user *data.User) error {
	user.ID = uuid.Must(uuid.NewRandom()).String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	r.logger.Log("creating user", hclog.Fmt("%v", user))
	query := "insert into users (id, email, username, password, tokenhash, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err := r.db.ExecContext(ctx, query, user.ID, user.Email, user.Username, user.Password, user.TokenHash, user.CreatedAt, user.UpdatedAt)
	return err
}

// Create inserts the given user into the database
func (repo *AuthRepository) Create(ctx context.Context, user *data.User) (err error) {
	user.ID = uuid.Must(uuid.NewRandom()).String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	repo.logger.Log("creating user", hclog.Fmt("%v", user))
	query := "insert into users (id, email, username, password, tokenhash, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err = repo.db.ExecContext(ctx, query, user.ID, user.Email, user.Username, user.Password, user.TokenHash, user.CreatedAt, user.UpdatedAt)
	return err
}

// GetUserByEmail retrieves the user object having the given email, else returns error
func (repo *signupRepository) GetUserByEmail(ctx context.Context, email string) (*data.User, error) {
	repo.logger.Log("querying for user with email", email)
	query := "select * from users where email = $1"
	var user data.User
	if err := repo.db.GetContext(ctx, &user, query, email); err != nil {
		return nil, err
	}
	repo.logger.Log("read users", hclog.Fmt("%#v", user))
	return &user, nil
}

// GetUserByID retrieves the user object having the given ID, else returns error
func (repo *signupRepository) GetUserByID(ctx context.Context, userID string) (*data.User, error) {
	repo.logger.Log("querying for user with id", userID)
	query := "select * from users where id = $1"
	var user data.User
	if err := repo.db.GetContext(ctx, &user, query, userID); err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUsername updates the username of the given user
func (repo *AuthRepository) UpdateUsername(ctx context.Context, user *data.User) error {
	user.UpdatedAt = time.Now()

	query := "update users set username = $1, updatedat = $2 where id = $3"
	if _, err := repo.db.ExecContext(ctx, query, user.Username, user.UpdatedAt, user.ID); err != nil {
		return err
	}
	return nil
}

// UpdateUserVerificationStatus updates user verification status to true
func (repo *signupRepository) UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error {

	query := "update users set isverified = $1 where email = $2"
	if _, err := repo.db.ExecContext(ctx, query, status, email); err != nil {
		return err
	}
	return nil
}

// StoreMailVerificationData adds a mail verification data to db
func (repo *signupRepository) StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error {

	query := "insert into verifications(email, code, expiresat, type) values($1, $2, $3, $4)"
	_, err := repo.db.ExecContext(ctx, query, verificationData.Email, verificationData.Code, verificationData.ExpiresAt, verificationData.Type)
	return err
}

// GetMailVerificationCode retrieves the stored verification code.
func (repo *signupRepository) GetVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) (*data.VerificationData, error) {

	query := "select * from verifications where email = $1 and type = $2"

	var verificationData data.VerificationData
	if err := repo.db.GetContext(ctx, &verificationData, query, email, verificationDataType); err != nil {
		return nil, err
	}
	return &verificationData, nil
}

// DeleteMailVerificationData deletes a used verification data
func (repo *signupRepository) DeleteVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) error {

	query := "delete from verifications where email = $1 and type = $2"
	_, err := repo.db.ExecContext(ctx, query, email, verificationDataType)
	return err
}


// UpdatePassword updates the user password
func (repo *AuthRepository) UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error {

	query := "update users set password = $1, tokenhash = $2 where id = $3"
	_, err := repo.db.ExecContext(ctx, query, password, tokenHash, userID)
	return err
}

//UpdateUsername
func (repo *signupRepository) UpdateUsername(ctx context.Context, user *data.User) error {
	user.UpdatedAt = time.Now()

	query := "update users set username = $1, updatedat = $2 where id = $3"
	if _, err := repo.db.ExecContext(ctx, query, user.Username, user.UpdatedAt, user.ID); err != nil {
		return err
	}
	return nil
}

//UpdatePassword
func (repo *signupRepository) UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error {
	query := "update users set password = $1, tokenhash = $2 where id = $3"
	_, err := repo.db.ExecContext(ctx, query, password, tokenHash, userID)
	return err
}