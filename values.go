package goacors

import (
	"net/http"
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

// DomainStrategy defined identify how handle (judge match with origin or not) domain
type DomainStrategy int

const (
	// AllowStrict strict mode (completely same origin or wild card or null)
	AllowStrict DomainStrategy = iota
	// AllowIntermediateMatch intermediate-match (such as subdomain like '*.example.com')
	AllowIntermediateMatch
)

// GoaCORSConfig CORSチェック用のConfig
type GoaCORSConfig struct {
	Skipper
	DomainStrategy
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	AllowCredentials bool
	ExposeHeaders    []string
	MaxAge           int
}

// DefaultGoaCORSConfig is the default CORS middleware config.
var DefaultGoaCORSConfig = GoaCORSConfig{
	Skipper:        defaultSkipper,
	AllowOrigins:   []string{"*"},
	AllowMethods:   []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	DomainStrategy: AllowStrict,
}
