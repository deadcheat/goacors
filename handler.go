package goacors

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/goadesign/goa"
)

// Handler defines behavior building handler
type Handler interface {
	Func(handler goa.Handler) goa.Handler
}

type CorsHandler struct {
	h             goa.Handler
	s             *goa.Service
	c             *GoaCORSConfig
	om            OriginMatcher
	allowMethods  string
	allowHeaders  string
	exposeHeaders string
	maxAge        string
}

func newCorsHandler(service *goa.Service, config *GoaCORSConfig, mb MatcherBuilder) Handler {
	return &CorsHandler{
		s:  service,
		c:  config,
		om: mb(config),
	}
}

func (h *CorsHandler) handle(c context.Context, rw http.ResponseWriter, req *http.Request) error {
	// Skipper
	if h.c.Skipper(c, rw, req) {
		return h.h(c, rw, req)
	}
	origin := req.Header.Get(HeaderOrigin)
	// Check allowed origins
	allowedOrigin, _ := h.om.FindMatchedOrigin(h.c.AllowOrigins, origin)

	// Simple request
	if req.Method == http.MethodGet || req.Method == http.MethodPost || req.Method == http.MethodHead {
		rw.Header().Add(HeaderVary, HeaderOrigin)
		rw.Header().Set(HeaderAccessControlAllowOrigin, allowedOrigin)
		if h.c.AllowCredentials && allowedOrigin != "*" && allowedOrigin != "" {
			rw.Header().Set(HeaderAccessControlAllowCredentials, "true")
		}
		if h.exposeHeaders != "" {
			rw.Header().Set(HeaderAccessControlExposeHeaders, h.exposeHeaders)
		}
		return h.h(c, rw, req)
	}
	// Preflight request
	rw.Header().Add(HeaderVary, HeaderOrigin)
	rw.Header().Add(HeaderVary, HeaderAccessControlRequestMethod)
	rw.Header().Add(HeaderVary, HeaderAccessControlRequestHeaders)
	rw.Header().Set(HeaderAccessControlAllowOrigin, allowedOrigin)
	rw.Header().Set(HeaderAccessControlAllowMethods, h.allowMethods)
	if h.c.AllowCredentials && allowedOrigin != "*" && allowedOrigin != "" {
		rw.Header().Set(HeaderAccessControlAllowCredentials, "true")
	}
	if h.allowHeaders != "" {
		rw.Header().Set(HeaderAccessControlAllowHeaders, h.allowHeaders)
	} else {
		header := req.Header.Get(HeaderAccessControlRequestHeaders)
		if header != "" {
			rw.Header().Set(HeaderAccessControlAllowHeaders, header)
		}
	}

	if h.c.MaxAge > 0 {
		rw.Header().Set(HeaderAccessControlMaxAge, h.maxAge)
	}
	return h.s.Send(c, http.StatusNoContent, http.StatusText(http.StatusNoContent))
}

func (h *CorsHandler) Func(handler goa.Handler) goa.Handler {
	h.allowMethods = strings.Join(h.c.AllowMethods, ",")
	h.allowHeaders = strings.Join(h.c.AllowHeaders, ",")
	h.exposeHeaders = strings.Join(h.c.ExposeHeaders, ",")
	h.maxAge = strconv.Itoa(h.c.MaxAge)
	h.h = handler
	return h.handle
}
