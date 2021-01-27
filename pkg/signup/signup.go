package signup

import (
	"context"
	"errors"
	"github.com/hecomp/yoorquezt-auth/internal/data"
)

type Repository interface {
	Signup(ctx context.Context, user *data.User) error
	StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error
	DeleteVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) error
	GetUserByEmail(ctx context.Context, email string) (*data.User, error)
	GetVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) (*data.VerificationData, error)
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error


	//GetUserByID(ctx context.Context, userID string) (*data.User, error)
	//UpdateUsername(ctx context.Context, user *data.User) error
	//UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error
}

// ErrUnknown is used when a user could not be found.
var ErrUnknown = errors.New("unknown user")
