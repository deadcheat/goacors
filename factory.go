package goacors

import (
	"github.com/goadesign/goa"
)

type Factory interface {
	Produce(service *goa.Service, conf *GoaCORSConfig) func(goa.Handler) goa.Handler
}

// CorsHandlerFactory hold strategy id
type CorsHandlerFactory struct {
	strategy DomainStrategy
}

// New returns new factory
func NewFactory(s DomainStrategy) Factory {
	return &CorsHandlerFactory{s}
}

// Produce create func(goa.Handler) goa.Handler with inject their match-strategy
func (f *CorsHandlerFactory) Produce(service *goa.Service, conf *GoaCORSConfig) func(goa.Handler) goa.Handler {
	h := newCorsHandler(service, conf)
	return h.Func
}
