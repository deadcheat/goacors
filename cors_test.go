package goacors_test

import (
	"net/http"

	. "github.com/deadcheat/goacors"

	"golang.org/x/net/context"

	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CORS-Middleware for goa", func() {
	var (
		ctx     context.Context
		req     *http.Request
		rw      http.ResponseWriter
		service *goa.Service
	)
	Context("when no origin header given ", func() {
		It("will return empty 'Access-Control-Allow-Origin' Header", func() {
			service = newService(nil)
			req, _ = http.NewRequest(GET, "/", nil)
			rw = newTestResponseWriter()
			ctx = newContext(service, rw, req, nil)
			var newCtx context.Context

			h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
				newCtx = ctx
				return service.Send(ctx, http.StatusOK, "ok")
			}
			t := WithConfig(service, &GoaCORSConfig{
				AllowCredentials: true,
			})(h)
			err := t(ctx, rw, req)
			Expect(err).Should(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowOrigin)).Should(Equal(""))
		})
	})
	Context("when origin header is empty and allow wildcard", func() {
		It("will return '*' for 'Access-Control-Allow-Origin' Header", func() {
			service = newService(nil)
			req, _ = http.NewRequest(GET, "/", nil)
			req.Header.Set(HeaderOrigin, "")
			rw = newTestResponseWriter()
			ctx = newContext(service, rw, req, nil)
			var newCtx context.Context

			h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
				newCtx = ctx
				return service.Send(ctx, http.StatusOK, "ok")
			}
			t := WithConfig(service, &GoaCORSConfig{
				AllowCredentials: true,
			})(h)
			err := t(ctx, rw, req)
			Expect(err).Should(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowOrigin)).Should(Equal("*"))
		})
	})
	Context("when origin header is empty and allow some host", func() {
		It("will return '*' for 'Access-Control-Allow-Origin' Header", func() {
			service = newService(nil)
			req, _ = http.NewRequest(GET, "/", nil)
			req.Header.Set(HeaderOrigin, "")
			rw = newTestResponseWriter()
			ctx = newContext(service, rw, req, nil)
			var newCtx context.Context

			h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
				newCtx = ctx
				return service.Send(ctx, http.StatusOK, "ok")
			}
			t := WithConfig(service, &GoaCORSConfig{
				AllowOrigins:     []string{"http://example.com"},
				AllowCredentials: true,
			})(h)
			err := t(ctx, rw, req)
			Expect(err).Should(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowOrigin)).Should(Equal(""))
		})
	})
	Context("when origin allowed by wildcard", func() {
		It("will return '*' for 'Access-Control-Allow-Origin' Header", func() {
			service = newService(nil)
			req, _ = http.NewRequest(GET, "/", nil)
			req.Header.Set(HeaderOrigin, "http://someorigin.com")
			rw = newTestResponseWriter()
			ctx = newContext(service, rw, req, nil)
			var newCtx context.Context

			h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
				newCtx = ctx
				return service.Send(ctx, http.StatusOK, "ok")
			}
			t := WithConfig(service, &GoaCORSConfig{
				AllowOrigins:     []string{"*"},
				AllowCredentials: true,
			})(h)
			err := t(ctx, rw, req)
			Expect(err).Should(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowOrigin)).Should(Equal("*"))
		})
	})
	Context("when origin allowed by fixied origin", func() {
		It("will return origin string for 'Access-Control-Allow-Origin' Header", func() {
			service = newService(nil)
			fixedOrigin := "http://someorigin.com"
			req, _ = http.NewRequest(GET, "/", nil)
			req.Header.Set(HeaderOrigin, fixedOrigin)
			rw = newTestResponseWriter()
			ctx = newContext(service, rw, req, nil)
			var newCtx context.Context

			h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
				newCtx = ctx
				return service.Send(ctx, http.StatusOK, "ok")
			}
			t := WithConfig(service, &GoaCORSConfig{
				AllowOrigins:     []string{fixedOrigin},
				AllowCredentials: true,
			})(h)
			err := t(ctx, rw, req)
			Expect(err).Should(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowOrigin)).Should(Equal(fixedOrigin))
		})
	})
	Context("when Preflight Request", func() {
		It("will return valid headers", func() {
			service = newService(nil)
			req, _ = http.NewRequest(OPTIONS, "/", nil)
			req.Header.Set(HeaderOrigin, "localhost")
			req.Header.Set(HeaderContentType, "application/json")
			rw = newTestResponseWriter()
			ctx = newContext(service, rw, req, nil)
			var newCtx context.Context

			h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
				newCtx = ctx
				return service.Send(ctx, http.StatusOK, "ok")
			}
			testee := WithConfig(service, &GoaCORSConfig{
				AllowCredentials: true,
				AllowOrigins:     []string{"localhost"},
				MaxAge:           3600,
			})(h)
			err := testee(ctx, rw, req)
			Expect(err).Should(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowOrigin)).Should(Equal("localhost"))
			Expect(rw.Header().Get(HeaderAccessControlAllowMethods)).ShouldNot(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowCredentials)).Should(Equal("true"))
			Expect(rw.Header().Get(HeaderAccessControlMaxAge)).Should(Equal("3600"))
		})
	})
	Context("when given not allowed header on Request", func() {
		It("will return '*' for 'Access-Control-Allow-Origin' Header", func() {
			service = newService(nil)
			req, _ = http.NewRequest(GET, "/", nil)
			req.Header.Set(HeaderOrigin, "localhost")
			rw = newTestResponseWriter()
			ctx = newContext(service, rw, req, nil)
			var newCtx context.Context

			h := func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
				newCtx = ctx
				return service.Send(ctx, http.StatusOK, "ok")
			}
			testee := WithConfig(service, &GoaCORSConfig{
				AllowCredentials: true,
				AllowOrigins:     []string{"example.com"},
			})(h)
			err := testee(ctx, rw, req)
			Expect(err).Should(BeNil())
			Expect(rw.Header().Get(HeaderAccessControlAllowOrigin)).Should(Equal(""))
		})
	})
})
