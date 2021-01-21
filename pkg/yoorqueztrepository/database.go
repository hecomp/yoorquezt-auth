package yoorqueztrepository

import (
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/hecomp/yoorquezt-auth/internal/utils"

)

// NewConnection creates the connection to the database
func NewConnection(config *utils.Configurations, logger log.Logger) (*sqlx.DB, error) {

	var conn string

	if config.DBConn != "" {
		conn = config.DBConn
	} else {
		host := config.DBHost
		port := config.DBPort
		user := config.DBUser
		dbName := config.DBName
		password := config.DBPass
		conn = fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", host, port, user, dbName, password)
	}
	logger.Log("connection string", conn)

	db, err := sqlx.Connect("postgres", conn)
	if err != nil {
		return nil, err
	}
	return db, nil
}