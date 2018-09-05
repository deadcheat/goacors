package goacors

import (
	"github.com/goadesign/goa"
)

type Factory interface {
	Produce(service *goa.Service, conf *GoaCORSConfig) func(goa.Handler) goa.Handler
}

// CorsHandlerFactory hold strategy id
type CorsHandlerFactory struct {
}

// New returns new factory
func NewFactory() Factory {
	return &CorsHandlerFactory{}
}

// Produce create func(goa.Handler) goa.Handler with inject their match-strategy
func (f *CorsHandlerFactory) Produce(service *goa.Service, config *GoaCORSConfig) func(goa.Handler) goa.Handler {
	var matcherBuilder MatcherBuilder
	switch config.DomainStrategy {
	case AllowIntermediateMatch:
		matcherBuilder = newInterMediateMatcher
	default:
		matcherBuilder = newStrictOriginMatcher
	}
	h := newCorsHandler(service, config, matcherBuilder)
	return h.Func
}
