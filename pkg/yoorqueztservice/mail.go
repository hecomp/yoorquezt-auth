package yoorqueztservice

import (
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	"github.com/hecomp/yoorquezt-auth/internal/utils"
)

// MailService represents the interface for our mail service.
type MailService interface {
	CreateMail(mailReq *Mail) []byte
	SendMail(mailReq *Mail) error
	NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail
}

type MailType int

// List of Mail Types we are going to send.
const (
	MailConfirmation MailType = iota + 1
	PassReset
)

// MailData represents the data to be sent to the template of the mail.
type MailData struct {
	Username string
	Code	 string
}

// Mail represents a email request
type Mail struct {
	from  string
	to    []string
	subject string
	body string
	mtype MailType
	data *MailData
}

// SGMailService is the sendgrid implementation of our MailService.
type SGMailService struct {
	logger log.Logger
	configs *utils.Configurations
}

func NewMailService(logger log.Logger, configs *utils.Configurations, ints, chars metrics.Counter) MailService {
	var svc MailService
	{
		svc = NewSGMailService(logger, configs)
		svc = LoggingMailMiddleware(logger)(svc)
		svc = InstrumentingMailMiddleware(ints, chars)(svc)
	}
	return svc
}

// NewSGMailService returns a new instance of SGMailService
func NewSGMailService(logger log.Logger, configs *utils.Configurations) *SGMailService {
	return &SGMailService{logger, configs}
}


// CreateMail takes in a mail request and constructs a sendgrid mail type.
func (ms *SGMailService) CreateMail(mailReq *Mail) []byte {

	m := mail.NewV3Mail()

	from := mail.NewEmail("yoorquezt", mailReq.from)
	m.SetFrom(from)

	if mailReq.mtype == MailConfirmation {
		m.SetTemplateID(ms.configs.MailVerifTemplateID)
	} else if mailReq.mtype == PassReset {
		m.SetTemplateID(ms.configs.PassResetTemplateID)
	}

	p := mail.NewPersonalization()

	tos := make([]*mail.Email, 0)
	for _, to := range mailReq.to {
		tos = append(tos, mail.NewEmail("user", to))
	}

	p.AddTos(tos...)

	p.SetDynamicTemplateData("Username", mailReq.data.Username)
	p.SetDynamicTemplateData("Code", mailReq.data.Code)

	m.AddPersonalizations(p)
	return mail.GetRequestBody(m)
}

// SendMail creates a sendgrid mail from the given mail request and sends it.
func (ms *SGMailService) SendMail(mailReq *Mail) error {

	request := sendgrid.GetRequest(ms.configs.SendGridApiKey, "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	var Body = ms.CreateMail(mailReq)
	request.Body = Body
	response, err := sendgrid.API(request)
	if err != nil {
		ms.logger.Log("unable to send mail", "error", err)
		return err
	}
	ms.logger.Log("mail sent successfully", "sent status code", response.StatusCode)
	return nil
}

// NewMail returns a new mail request.
func (ms *SGMailService) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	return &Mail{
		from: 	 from,
		to:  	 to,
		subject: subject,
		mtype: 	 mailType,
		data: 	 data,
	}
}
