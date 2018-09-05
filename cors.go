package goacors

import (
	"github.com/goadesign/goa"
)

// New return middleware implements checking cors with default config
func New(service *goa.Service) goa.Middleware {
	return WithConfig(service, &DefaultGoaCORSConfig)
}

// WithConfig create middleware with configure for this
func WithConfig(service *goa.Service, conf *GoaCORSConfig) goa.Middleware {
	if conf == nil {
		conf = &DefaultGoaCORSConfig
	}
	if conf.Skipper == nil {
		conf.Skipper = DefaultGoaCORSConfig.Skipper
	}
	if len(conf.AllowOrigins) == 0 {
		conf.AllowOrigins = DefaultGoaCORSConfig.AllowOrigins
	}
	if len(conf.AllowMethods) == 0 {
		conf.AllowMethods = DefaultGoaCORSConfig.AllowMethods
	}
	if conf.DomainStrategy != AllowIntermediateMatch {
		conf.DomainStrategy = AllowStrict
	}
	factory := NewFactory()
	return factory.Produce(service, conf)
}
