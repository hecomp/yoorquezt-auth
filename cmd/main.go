package main

import (
	"flag"
	"fmt"
	grpc2 "github.com/hecomp/yoorquezt-auth/pkg/grpc"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/go-kit/kit/log"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-kit/kit/sd/consul"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/hashicorp/consul/api"
	"github.com/jmoiron/sqlx"
	"github.com/lightstep/lightstep-tracer-go"
	"github.com/oklog/oklog/pkg/group"
	stdopentracing "github.com/opentracing/opentracing-go"
	zipkinot "github.com/openzipkin-contrib/zipkin-go-opentracing"
	"github.com/openzipkin/zipkin-go"
	zipkinhttp "github.com/openzipkin/zipkin-go/reporter/http"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"google.golang.org/grpc"

	"sourcegraph.com/sourcegraph/appdash"
	appdashot "sourcegraph.com/sourcegraph/appdash/opentracing"

	"github.com/hecomp/yoorquezt-auth/internal/data"
	"github.com/hecomp/yoorquezt-auth/internal/utils"
	yoorqueztpb "github.com/hecomp/yoorquezt-auth/pb"
	authentication2 "github.com/hecomp/yoorquezt-auth/pkg/auth"
	db2 "github.com/hecomp/yoorquezt-auth/pkg/db"
	"github.com/hecomp/yoorquezt-auth/pkg/db/auth"
	mail2 "github.com/hecomp/yoorquezt-auth/pkg/mail"
)

func main()  {
	// Define our flags. Your service probably won't need to bind listeners for
	// *all* supported transports, or support both Zipkin and LightStep, and so
	// on, but we do it here for demonstration purposes.
	fs := flag.NewFlagSet("yoorqueztauthsvc", flag.ExitOnError)
	var (
		httpAddr       = fs.String("http-addr", ":8081", "HTTP listen address")
		grpcAddr       = fs.String("grpc-addr", ":8082", "gRPC listen address")
		zipkinURL      = fs.String("zipkin-url", "", "Enable Zipkin tracing via HTTP reporter URL e.g. http://localhost:9411/api/v2/spans")
		zipkinBridge   = fs.Bool("zipkin-ot-bridge", false, "Use Zipkin OpenTracing bridge instead of native implementation")
		lightstepToken = fs.String("lightstep-token", "", "Enable LightStep tracing via a LightStep access token")
		appdashAddr    = fs.String("appdash-addr", "", "Enable Appdash tracing via an Appdash server host:port")
		consulServer   = fs.String("consul.addr", ":8500", "consulServer")
		serviceName    = fs.String("SERVICE", "yoorqueztauthsvc", "yoorqueztauthsvc")
		prefix         = fs.String("PREFIX", "/yoorqueztauthsvc", "prefix yoorqueztauthsvc")
	)
	fs.Usage = usageFor(fs, os.Args[0]+" [flags]")
	fs.Parse(os.Args[1:])

	// Create a single logger, which we'll use and give to other components.
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	// Specify the information of an instance.
	asr := api.AgentServiceRegistration{
		// Every service instance must have an unique ID.
		ID:      fmt.Sprintf("%v%v/%v", "localhost", httpAddr, prefix),
		Name:    *serviceName,
		// These two values are the location of an instance.
		Address: "localhost",
		Port:    8081,
	}
	consulConfig := api.DefaultConfig()
	// We can get the address of consul server from environment variale or a config file.
	if len(*consulServer) > 0 {
		consulConfig.Address = *consulServer
	}
	consulClient, errs := api.NewClient(consulConfig)
	if errs != nil {
		logger.Log("errs", errs)
		os.Exit(1)
	}
	sdClient := consul.NewClient(consulClient)
	registar := consul.NewRegistrar(sdClient, &asr, logger)
	registar.Register()
	// According to the official doc of Go kit,
	// it's important to call registar.Deregister() before the program exits.
	defer registar.Deregister()

	var configs *utils.Configurations
	{
		configs = utils.NewConfigurations(logger)
	}

	// validator contains all the methods that are need to validate the user json in request
	var validator *data.Validation
	{
		validator = data.NewValidation()

	}

	var db *sqlx.DB
	var err error
	{
		// create a new connection to the postgres db store
		db, err = db2.NewConnection(configs, logger)
		if err != nil {
			logger.Log("unable to connect to db", "error", err)
			panic(err)
		}
		defer db.Close()
	}

	var zipkinTracer *zipkin.Tracer
	{
		if *zipkinURL != "" {
			var (
				err         error
				hostPort    = "localhost:80"
				serviceName = "yoorqueztauthsvc"
				reporter    = zipkinhttp.NewReporter(*zipkinURL)
			)
			defer reporter.Close()
			zEP, _ := zipkin.NewEndpoint(serviceName, hostPort)
			zipkinTracer, err = zipkin.NewTracer(reporter, zipkin.WithLocalEndpoint(zEP))
			if err != nil {
				logger.Log("err", err)
				os.Exit(1)
			}
			if !(*zipkinBridge) {
				logger.Log("tracer", "Zipkin", "type", "Native", "URL", *zipkinURL)
			}
		}
	}

	// Determine which OpenTracing tracer to use. We'll pass the tracer to all the
	// components that use it, as a dependency.
	var tracer stdopentracing.Tracer
	{
		if *zipkinBridge && zipkinTracer != nil {
			logger.Log("tracer", "Zipkin", "type", "OpenTracing", "URL", *zipkinURL)
			tracer = zipkinot.Wrap(zipkinTracer)
			zipkinTracer = nil // do not instrument with both native tracer and opentracing bridge
		} else if *lightstepToken != "" {
			logger.Log("tracer", "LightStep") // probably don't want to print out the token :)
			tracer = lightstep.NewTracer(lightstep.Options{
				AccessToken: *lightstepToken,
			})
			defer lightstep.FlushLightStepTracer(tracer)
		} else if *appdashAddr != "" {
			logger.Log("tracer", "Appdash", "addr", *appdashAddr)
			tracer = appdashot.NewTracer(appdash.NewRemoteCollector(*appdashAddr))
		} else {
			tracer = stdopentracing.GlobalTracer() // no-op
		}
	}

	var (
		signup = auth.NewSignupRepository(db, logger)
	)

	fieldKeys := []string{"method"}

	var as authentication2.Service
	{
		as = authentication2.NewService(signup, logger)
		as = authentication2.NewLoggingService(log.With(logger, "component", "auth"), as)
		as = authentication2.NewInstrumentingService(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "api",
				Subsystem: "auth_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "api",
				Subsystem: "auth_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
			as,
		)
	}
	var ms mail2.MailService
	{
		ms = mail2.NewService(logger, configs)
		ms = mail2.NewLoggingService(log.With(logger, "component", "mail"), ms)
		ms = mail2.NewInstrumentingService(
			kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
				Namespace: "api",
				Subsystem: "mail_service",
				Name:      "request_count",
				Help:      "Number of requests received.",
			}, fieldKeys),
			kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
				Namespace: "api",
				Subsystem: "mail_service",
				Name:      "request_latency_microseconds",
				Help:      "Total duration of requests in microseconds.",
			}, fieldKeys),
			ms,
			)
	}
	http.DefaultServeMux.Handle("/metrics", promhttp.Handler())

	httpLogger := log.With(logger, "component", "http")

	var (
		endpoints   = authentication2.New(as, logger, ms, validator, signup, configs, tracer, zipkinTracer)
		httpHandler = authentication2.MakeHandler(endpoints, tracer, zipkinTracer, httpLogger)
		grpcServer  = grpc2.NewGRPCServer(endpoints, tracer, zipkinTracer, logger)
	)
	//mux := http.NewServeMux()
	//
	//mux.Handle("/auth/v1/", authentication2.MakeHandler(as, tracer, zipkinTracer, httpLogger))

	// Now we're to the part of the func main where we want to start actually
	// running things, like servers bound to listeners to receive connections.
	//
	// The method is the same for each component: add a new actor to the group
	// struct, which is a combination of 2 anonymous functions: the first
	// function actually runs the component, and the second function should
	// interrupt the first function and cause it to return. It's in these
	// functions that we actually bind the Go kit server/handler structs to the
	// concrete transports and run them.
	//
	// Putting each component into its own block is mostly for aesthetics: it
	// clearly demarcates the scope in which each listener/socket may be used.
	var g group.Group
	{
		// The HTTP listener mounts the Go kit HTTP handler we created.
		httpListener, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			logger.Log("transport", "HTTP", "during", "Listen", "err", err)
			os.Exit(1)
		}
		g.Add(func() error {
			logger.Log("transport", "HTTP", "addr", *httpAddr)
			return http.Serve(httpListener, httpHandler)
		}, func(error) {
			httpListener.Close()
		})
	}
	{
		// The gRPC listener mounts the Go kit gRPC server we created.
		grpcListener, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			logger.Log("transport", "gRPC", "during", "Listen", "err", err)
			os.Exit(1)
		}
		g.Add(func() error {
			logger.Log("transport", "gRPC", "addr", *grpcAddr)
			// we add the Go Kit gRPC Interceptor to our gRPC service as it is used by
			// the here demonstrated zipkin tracing middleware.
			baseServer := grpc.NewServer(grpc.UnaryInterceptor(kitgrpc.Interceptor))
			yoorqueztpb.RegisterAuthServer(baseServer, grpcServer)
			return baseServer.Serve(grpcListener)
		}, func(error) {
			grpcListener.Close()
		})
	}
	{
		// This function just sits and waits for ctrl-C.
		cancelInterrupt := make(chan struct{})
		g.Add(func() error {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
			select {
			case sig := <-c:
				return fmt.Errorf("received signal %s", sig)
			case <-cancelInterrupt:
				return nil
			}
		}, func(error) {
			close(cancelInterrupt)
		})
	}
	logger.Log("exit", g.Run())
}

func usageFor(fs *flag.FlagSet, short string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "USAGE\n")
		fmt.Fprintf(os.Stderr, "  %s\n", short)
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		w := tabwriter.NewWriter(os.Stderr, 0, 2, 2, ' ', 0)
		fs.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(w, "\t-%s %s\t%s\n", f.Name, f.DefValue, f.Usage)
		})
		w.Flush()
		fmt.Fprintf(os.Stderr, "\n")
	}
}