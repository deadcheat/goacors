package goacors

import (
	"context"
	"net/http"
	"strconv"
	"strings"

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
	allowMethods := strings.Join(conf.AllowMethods, ",")
	allowHeaders := strings.Join(conf.AllowHeaders, ",")
	exposeHeaders := strings.Join(conf.ExposeHeaders, ",")
	maxAge := strconv.Itoa(conf.MaxAge)

	var om OriginMatcher
	switch conf.DomainStrategy {
	case AllowIntermediateMatch:
		om = newInterMediateMatcher(conf)
	default:
		om = newStrictOriginMatcher(conf)
	}
	return func(next goa.Handler) goa.Handler {
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
			// Skipper
			if conf.Skipper(c, rw, req) {
				return next(c, rw, req)
			}
			origin := req.Header.Get(HeaderOrigin)
			// Check allowed origins
			allowedOrigin, _ := om.FindMatchedOrigin(conf.AllowOrigins, origin)

			// Simple request
			if req.Method == http.MethodGet || req.Method == http.MethodPost || req.Method == http.MethodHead {
				rw.Header().Add(HeaderVary, HeaderOrigin)
				rw.Header().Set(HeaderAccessControlAllowOrigin, allowedOrigin)
				if conf.AllowCredentials && allowedOrigin != "*" && allowedOrigin != "" {
					rw.Header().Set(HeaderAccessControlAllowCredentials, "true")
				}
				if exposeHeaders != "" {
					rw.Header().Set(HeaderAccessControlExposeHeaders, exposeHeaders)
				}
				return next(c, rw, req)
			}
			// Preflight request
			rw.Header().Add(HeaderVary, HeaderOrigin)
			rw.Header().Add(HeaderVary, HeaderAccessControlRequestMethod)
			rw.Header().Add(HeaderVary, HeaderAccessControlRequestHeaders)
			rw.Header().Set(HeaderAccessControlAllowOrigin, allowedOrigin)
			rw.Header().Set(HeaderAccessControlAllowMethods, allowMethods)
			if conf.AllowCredentials && allowedOrigin != "*" && allowedOrigin != "" {
				rw.Header().Set(HeaderAccessControlAllowCredentials, "true")
			}
			if allowHeaders != "" {
				rw.Header().Set(HeaderAccessControlAllowHeaders, allowHeaders)
			} else {
				header := req.Header.Get(HeaderAccessControlRequestHeaders)
				if header != "" {
					rw.Header().Set(HeaderAccessControlAllowHeaders, header)
				}
			}

			if conf.MaxAge > 0 {
				rw.Header().Set(HeaderAccessControlMaxAge, maxAge)
			}
			return service.Send(c, http.StatusNoContent, http.StatusText(http.StatusNoContent))
		}
	}

}
