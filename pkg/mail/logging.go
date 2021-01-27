package yoorqueztservice

import (
	"time"

	"github.com/go-kit/kit/log"

)

type loggingService struct {
	logger log.Logger
	MailService
}

func NewLoggingService(logger log.Logger, m MailService) MailService {
	return &loggingService{logger: logger, MailService: m}
}

func (s loggingService) CreateMail(mailReq *Mail) []byte {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "CreateMail",
			"mail", mailReq,
			"took", time.Since(begin),
		)
	}(time.Now())
	return s.MailService.CreateMail(mailReq)
}

func (s loggingService) SendMail(mailReq *Mail) error {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "SendMail",
			"mail", mailReq,
			"took", time.Since(begin),
		)
	}(time.Now())
	return s.MailService.SendMail(mailReq)
}

func (s loggingService) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	defer func(begin time.Time) {
		s.logger.Log(
			"method", "SendMail",
			"mail", data,
			"took", time.Since(begin),
		)
	}(time.Now())
	return s.MailService.NewMail(from, to, subject, mailType, data)
}
