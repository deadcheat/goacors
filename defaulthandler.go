package goacors

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/goadesign/goa"
)

type DefaultHandlerBuilder struct {
	s *goa.Service
	c *GoaCORSConfig
}

func NewDefaultHandlerBuilder(service *goa.Service, conf *GoaCORSConfig) HandlerBuilder {
	return &DefaultHandlerBuilder{
		s: service,
		c: conf,
	}
}

func (d *DefaultHandlerBuilder) Build(h goa.Handler) goa.Handler {
	allowMethods := strings.Join(d.c.AllowMethods, ",")
	allowHeaders := strings.Join(d.c.AllowHeaders, ",")
	exposeHeaders := strings.Join(d.c.ExposeHeaders, ",")
	maxAge := strconv.Itoa(d.c.MaxAge)
	return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
		// Skipper
		if d.c.Skipper(c, rw, req) {
			return h(c, rw, req)
		}
		origin := req.Header.Get(HeaderOrigin)
		// Check allowed origins
		allowedOrigin := ""
		for _, o := range d.c.AllowOrigins {
			if o == "*" || o == origin {
				allowedOrigin = o
				break
			}
		}

		// Simple request
		if req.Method != OPTIONS {
			rw.Header().Add(HeaderVary, HeaderOrigin)
			rw.Header().Set(HeaderAccessControlAllowOrigin, allowedOrigin)
			if d.c.AllowCredentials {
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
		if d.c.AllowCredentials {
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

		if d.c.MaxAge > 0 {
			rw.Header().Set(HeaderAccessControlMaxAge, maxAge)
		}
		return d.s.Send(c, http.StatusNoContent, http.StatusText(http.StatusNoContent))
	}
}
