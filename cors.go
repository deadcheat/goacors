package goacors

import (
	"github.com/goadesign/goa"
)

// GoaCORSConfig CORSチェック用のConfig
type GoaCORSConfig struct {
	Skipper          Skipper
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	AllowCredentials bool
	ExposeHeaders    []string
	MaxAge           int
}

// DefaultGoaCORSConfig is the default CORS middleware config.
var DefaultGoaCORSConfig = GoaCORSConfig{
	Skipper:      defaultSkipper,
	AllowOrigins: []string{"*"},
	AllowMethods: []string{GET, HEAD, PUT, PATCH, POST, DELETE},
}

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
	b := NewDefaultHandlerBuilder(service, conf)
	return b.Build
}
