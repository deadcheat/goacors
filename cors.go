package goacors

import (
	"net/http"
	"strconv"
	"strings"

	"context"

	"github.com/goadesign/goa"
)

type (
	// GoaCORSConfig CORSチェック用のConfig
	GoaCORSConfig struct {
		Skipper          Skipper
		AllowOrigins     []string
		AllowMethods     []string
		AllowHeaders     []string
		AllowCredentials bool
		ExposeHeaders    []string
		MaxAge           int
	}
)

var (
	// DefaultGoaCORSConfig is the default CORS middleware config.
	DefaultGoaCORSConfig = GoaCORSConfig{
		Skipper:      defaultSkipper,
		AllowOrigins: []string{"*"},
		AllowMethods: []string{GET, HEAD, PUT, PATCH, POST, DELETE},
	}
)

const (
	// DELETE HTTP Methods
	DELETE = "DELETE"
	// GET HTTP Methods
	GET = "GET"
	// HEAD HTTP Methods
	HEAD = "HEAD"
	// OPTIONS HTTP Methods
	OPTIONS = "OPTIONS"
	// PATCH HTTP Methods
	PATCH = "PATCH"
	// POST HTTP Methods
	POST = "POST"
	// PUT HTTP Methods
	PUT = "PUT"
)

const (
	// HeaderVary "Vary"
	HeaderVary = "Vary"
	// HeaderOrigin "Origin"
	HeaderOrigin = "Origin"
	// HeaderAccessControlRequestMethod "Access-Control-Request-Method"
	HeaderAccessControlRequestMethod = "Access-Control-Request-Method"
	// HeaderAccessControlRequestHeaders "Access-Control-Request-Headers"
	HeaderAccessControlRequestHeaders = "Access-Control-Request-Headers"
	// HeaderAccessControlAllowOrigin Access-Control-Allow-Origin"
	HeaderAccessControlAllowOrigin = "Access-Control-Allow-Origin"
	// HeaderAccessControlAllowMethods "Access-Control-Allow-Methods"
	HeaderAccessControlAllowMethods = "Access-Control-Allow-Methods"
	// HeaderAccessControlAllowHeaders "Access-Control-Allow-Headers"
	HeaderAccessControlAllowHeaders = "Access-Control-Allow-Headers"
	// HeaderAccessControlAllowCredentials "Access-Control-Allow-Credentials"
	HeaderAccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	// HeaderAccessControlExposeHeaders "Access-Control-Expose-Headers"
	HeaderAccessControlExposeHeaders = "Access-Control-Expose-Headers"
	// HeaderAccessControlMaxAge "Access-Control-Max-Age"
	HeaderAccessControlMaxAge = "Access-Control-Max-Age"
	// HeaderContentType "Content-Type"
	HeaderContentType = "Content-Type"
)

// New serviceとDefaultConfigを利用してCORSヘッダチェックを行う
func New(service *goa.Service) goa.Middleware {
	return WithConfig(service, &DefaultGoaCORSConfig)
}

// WithConfig Configを用いてCORSヘッダチェックを行う
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
	allowMethods := strings.Join(conf.AllowMethods, ",")
	allowHeaders := strings.Join(conf.AllowHeaders, ",")
	exposeHeaders := strings.Join(conf.ExposeHeaders, ",")
	maxAge := strconv.Itoa(conf.MaxAge)
	return func(h goa.Handler) goa.Handler {
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
			// Skipper
			if conf.Skipper(c, rw, req) {
				return h(c, rw, req)
			}
			origin := req.Header.Get(HeaderOrigin)
			// Check allowed origins
			allowedOrigin := ""
			for _, o := range conf.AllowOrigins {
				if o == "*" || o == origin {
					allowedOrigin = o
					break
				}
			}

			// Simple request
			if req.Method != OPTIONS {
				rw.Header().Add(HeaderVary, HeaderOrigin)
				rw.Header().Set(HeaderAccessControlAllowOrigin, allowedOrigin)
				if conf.AllowCredentials {
					rw.Header().Set(HeaderAccessControlAllowCredentials, "true")
				}
				if exposeHeaders != "" {
					rw.Header().Set(HeaderAccessControlExposeHeaders, exposeHeaders)
				}
				return h(c, rw, req)
			}
			// Preflight request
			rw.Header().Add(HeaderVary, HeaderOrigin)
			rw.Header().Add(HeaderVary, HeaderAccessControlRequestMethod)
			rw.Header().Add(HeaderVary, HeaderAccessControlRequestHeaders)
			rw.Header().Set(HeaderAccessControlAllowOrigin, allowedOrigin)
			rw.Header().Set(HeaderAccessControlAllowMethods, allowMethods)
			if conf.AllowCredentials {
				rw.Header().Set(HeaderAccessControlAllowCredentials, "true")
			}
			if allowHeaders != "" {
				rw.Header().Set(HeaderAccessControlAllowHeaders, allowHeaders)
			} else {
				h := req.Header.Get(HeaderAccessControlRequestHeaders)
				if h != "" {
					rw.Header().Set(HeaderAccessControlAllowHeaders, h)
				}
			}

			if conf.MaxAge > 0 {
				rw.Header().Set(HeaderAccessControlMaxAge, maxAge)
			}
			return service.Send(c, http.StatusNoContent, http.StatusText(http.StatusNoContent))
		}
	}
}
