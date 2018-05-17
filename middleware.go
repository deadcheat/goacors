package goacors

import (
	"net/http"

	"context"
)

type (
	// Skipper スキップ条件を記述するためのもの
	Skipper func(c context.Context, rw http.ResponseWriter, req *http.Request) bool
)

// defaultSkipper 常にFalseを返すSkipper
func defaultSkipper(c context.Context, rw http.ResponseWriter, req *http.Request) bool {
	return false
}
