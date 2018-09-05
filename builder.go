package goacors

import "github.com/goadesign/goa"

// HandlerBuilder defines behavior building handler
type HandlerBuilder interface {
	Build(goa.Handler) goa.Handler
}
