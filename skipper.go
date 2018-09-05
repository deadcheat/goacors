package goacors

import (
	"net/http"

	"context"
)

// Skipper スキップ条件を記述するためのもの
type Skipper func(c context.Context, rw http.ResponseWriter, req *http.Request) bool

// defaultSkipper skipper always return false, check cors every time
func defaultSkipper(c context.Context, rw http.ResponseWriter, req *http.Request) bool {
	return false
}
