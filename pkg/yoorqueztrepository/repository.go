package yoorqueztrepository

import (
	"context"
	"github.com/hecomp/yoorquezt-auth/internal/data"
)

// Repository is an interface for the storage implementation of the auth service
type Repository interface {
	Create(ctx context.Context, user *data.User) error
	GetUserByEmail(ctx context.Context, email string) (*data.User, error)
	GetUserByID(ctx context.Context, userID string) (*data.User, error)
	UpdateUsername(ctx context.Context, user *data.User) error
	StoreVerificationData(ctx context.Context, verificationData *data.VerificationData) error
	GetVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) (*data.VerificationData, error)
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error
	DeleteVerificationData(ctx context.Context, email string, verificationDataType data.VerificationDataType) error
	UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error
}