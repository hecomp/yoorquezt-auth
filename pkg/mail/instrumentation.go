package yoorqueztservice

import (
	"time"

	"github.com/go-kit/kit/metrics"
	)

type instrumentingService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	MailService
}

// NewInstrumentingService returns an instance of an instrumenting Service.
func NewInstrumentingService(counter metrics.Counter, latency metrics.Histogram, s MailService) MailService {
	return &instrumentingService{
		requestCount:   counter,
		requestLatency: latency,
		MailService:        s,
	}
}

func (i instrumentingService) CreateMail(mailReq *Mail) []byte {
	defer func(begin time.Time) {
		i.requestCount.With("method", "CreateMail").Add(1)
		i.requestLatency.With("method", "CreateMail").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return i.MailService.CreateMail(mailReq)
}

func (i instrumentingService) SendMail(mailReq *Mail) error {
	defer func(begin time.Time) {
		i.requestCount.With("method", "SendMail").Add(1)
		i.requestLatency.With("method", "SendMail").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return i.MailService.SendMail(mailReq)
}

func (i instrumentingService) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	defer func(begin time.Time) {
		i.requestCount.With("method", "SendMail").Add(1)
		i.requestLatency.With("method", "SendMail").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return i.MailService.NewMail(from, to, subject, mailType, data)
}

