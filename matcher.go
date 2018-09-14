package goacors

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/goadesign/goa"
)

// OriginMatcher define behavior domain and origin matcher
type OriginMatcher interface {
	FindMatchedOrigin(allowedOrigins []string, origin string) (foundOne string, found bool)
}

// StrictOriginMatcher marker for doing strict check
type StrictOriginMatcher struct {
	config *GoaCORSConfig
}

// newStrictOriginMatcher create new OriginMatcher implement
func newStrictOriginMatcher(config *GoaCORSConfig) OriginMatcher {
	return &StrictOriginMatcher{config}
}

// Filter check if allowedOrigins contain * or completely same origin
func (s *StrictOriginMatcher) FindMatchedOrigin(allowedOrigins []string, origin string) (foundOne string, found bool) {
	fmt.Println("fuga", allowedOrigins, origin)
	for _, o := range allowedOrigins {
		if foundOne, found = innerMatcher(o, origin, s.config.AllowCredentials); found {
			return
		}
	}
	return
}

type baseMatcher func(allowedOrigin string, origin string, allowCredentials bool) (filteredOrigin string, ok bool)

var innerMatcher = func(allowedOrigin string, origin string, allowCredentials bool) (filteredOrigin string, ok bool) {
	if allowedOrigin == "*" && allowCredentials && origin != "" {
		return origin, true
	}
	if allowedOrigin == "*" || allowedOrigin == origin {
		return allowedOrigin, true
	}
	return
}

// InterMediateMatcher allows subdomain wildcard
type InterMediateMatcher struct {
	baseMatcher
	config *GoaCORSConfig
}

// newInterMediateMatcher create new OriginMatcher implement
func newInterMediateMatcher(config *GoaCORSConfig) OriginMatcher {
	// notify this matcher has weakness for security
	goa.LogInfo(context.Background(), "!!!warning!!! you'll use intermediate match mode! note that using this mode is not recommended for production!")
	return &InterMediateMatcher{
		baseMatcher: innerMatcher,
		config:      config,
	}
}

// Filter returns ok and found one if wildcard matched with subdomain or completely same origin or entirely wildcard
// ** Note **
// first of all, this method will be panic when couldn't parse pre-set allowed origin url.
// second, wild card is enabled only in their host name
func (i *InterMediateMatcher) FindMatchedOrigin(allowedOrigins []string, origin string) (foundOne string, found bool) {

	originUrl, err := url.Parse(origin)
	if err != nil {
		return "", false
	}

	for _, o := range allowedOrigins {
		if foundOne, found = i.baseMatcher(o, origin, i.config.AllowCredentials); found {
			return
		}

		allowedURL, err := url.Parse(o)
		if err != nil {
			panic(err)
		}
		if !strings.Contains(allowedURL.Host, "*") {
			continue
		}
		parts := strings.SplitN(allowedURL.Host, "*", 2)
		if !strings.HasPrefix(originUrl.Host, parts[0]) ||
			!strings.HasSuffix(origin, parts[1]) ||
			originUrl.Scheme != allowedURL.Scheme ||
			originUrl.Path != allowedURL.Path ||
			originUrl.RawQuery != allowedURL.RawQuery {
			continue
		}
		// return origin, true
		return origin, true
	}
	return
}
