package grpc

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	"github.com/go-kit/kit/tracing/zipkin"
	"github.com/go-kit/kit/transport"
	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/pkg/auth"
	stdopentracing "github.com/opentracing/opentracing-go"
	stdzipkin "github.com/openzipkin/zipkin-go"

	"github.com/hecomp/yoorquezt-auth/pb"
)

type grpcServer struct {
	signup     grpctransport.Handler
	login      grpctransport.Handler
	verifyMail grpctransport.Handler
}

// NewGRPCServer makes a set of endpoints available as a gRPC AddServer.
func NewGRPCServer(endpoints auth.Set, otTracer stdopentracing.Tracer, zipkinTracer *stdzipkin.Tracer, logger log.Logger) pb.AuthServer {
	options := []grpctransport.ServerOption{
		grpctransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
	}

	if zipkinTracer != nil {

		// Zipkin GRPC Server Trace can either be instantiated per gRPC method with a
		// provided operation name or a global tracing service can be instantiated
		// without an operation name and fed to each Go kit gRPC server as a
		// ServerOption.
		// In the latter case, the operation name will be the endpoint's grpc method
		// path if used in combination with the Go kit gRPC Interceptor.
		//
		// In this example, we demonstrate a global Zipkin tracing service with
		// Go kit gRPC Interceptor.
		options = append(options, zipkin.GRPCServerTrace(zipkinTracer))
	}

	return &grpcServer{
		signup: grpctransport.NewServer(
			endpoints.SignupEndpoint,
			decodeGRPCSignupRequest,
			encodeGRPCSignupResponse,
			append(options, grpctransport.ServerBefore(opentracing.GRPCToContext(otTracer, "Signup", logger)))...,
		),
		login: grpctransport.NewServer(
			endpoints.LoginEndpoint,
			decodeGRPCLoginRequest,
			encodeGRPCLoginResponse,
			append(options, grpctransport.ServerBefore(opentracing.GRPCToContext(otTracer, "Login", logger)))...,
		),
		verifyMail: grpctransport.NewServer(
			endpoints.VerifyMailEndpoint,
			decodeGRPCVerifyMailRequest,
			encodeGRPCVerifyMailResponse,
			append(options, grpctransport.ServerBefore(opentracing.GRPCToContext(otTracer, "VerifyMail", logger)))...,
		),
	}
}

func (s *grpcServer) Signup(ctx context.Context, req *pb.SignupRequest) (*pb.SignupReply, error) {
	_, rep, err := s.signup.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.SignupReply), nil
}

func (s *grpcServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginReply, error) {
	_, rep, err := s.login.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.LoginReply), nil
}

func (s *grpcServer) VerifyMail(ctx context.Context, req *pb.VerifyMailRequest) (*pb.VerifyMailReply, error) {
	_, rep, err := s.verifyMail.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.VerifyMailReply), nil
}

// decodeGRPCSignupRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC signup request to a user-domain signup request. Primarily useful in a server.
func decodeGRPCSignupRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*pb.SignupRequest)
	return data.User{
		ID: req.ID,
		Email: req.Email,
		Password: req.Password,
		Username: req.Username,
		TokenHash: req.TokenHash,
		IsVerified: req.IsVerified,
	}, nil
}

// decodeGRPCLoginRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC login request to a user-domain signup request. Primarily useful in a server.
func decodeGRPCLoginRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*pb.SignupRequest)
	return data.User{
		ID: req.ID,
		Email: req.Email,
		Password: req.Password,
		Username: req.Username,
		TokenHash: req.TokenHash,
		IsVerified: req.IsVerified,
	}, nil
}

// decodeGRPCVerifyMailRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC verify mail request to a user-domain signup request. Primarily useful in a server.
func decodeGRPCVerifyMailRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*pb.VerifyMailRequest)
	return data.VerificationData{
		Email: req.Email,
		Code: req.Code ,
		Type: data.VerificationDataType(req.Type),
	}, nil
}

// encodeGRPCSignupResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain signup response to a gRPC signup reply. Primarily useful in a server.
func encodeGRPCSignupResponse(_ context.Context, response interface{}) (interface{}, error) {
	resp := response.(auth.SignupResponse)
	return &pb.SignupReply{
		Status: resp.Status,
		Message: resp.Message,
		Data: fmt.Sprintf("%v", resp.Data),
		Err: resp.Err.Error(),
	}, nil
}

// encodeGRPCSignupResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain signup response to a gRPC signup reply. Primarily useful in a server.
func encodeGRPCLoginResponse(_ context.Context, response interface{}) (interface{}, error) {
	resp := response.(auth.LoginResponse)
	return &pb.LoginReply{
		Status: resp.Status,
		Message: resp.Message,
		Data: fmt.Sprintf("%v", resp.Data),
		Err: resp.Err.Error(),
	}, nil
}

// encodeGRPCVerifyMailResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain verify mail response to a gRPC signup reply. Primarily useful in a server.
func encodeGRPCVerifyMailResponse(_ context.Context, response interface{}) (interface{}, error) {
	resp := response.(auth.VerifyMailResponse)
	return &pb.VerifyMailReply{
		Status: resp.Status,
		Message: resp.Message,
		Data: fmt.Sprintf("%v", resp.Data),
		Err: resp.Err.Error(),
	}, nil
}

// These annoying helper functions are required to translate Go error types to
// and from strings, which is the type we use in our IDLs to represent errors.
// There is special casing to treat empty strings as nil errors.

func str2err(s string) error {
	if s == "" {
		return nil
	}
	return errors.New(s)
}

func err2str(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
