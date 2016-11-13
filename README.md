[![Build Status](https://travis-ci.org/deadcheat/goacors.svg?branch=master)](https://travis-ci.org/deadcheat/goacors)
[![Coverage Status](https://coveralls.io/repos/github/deadcheat/goacors/badge.svg?branch=master)](https://coveralls.io/github/deadcheat/goacors?branch=master)

# goacors
a cors-header middleware for goa(https://github.com/goadesign/goa)

# how to use
1. first, import this from glide, or `go get github.com/deadcheat/goacors`
2. write your main.go generated automatically from goagen.
	```
	service.Use(cors.GoaCORSWithConfig(service, cors.DefaultGoaCORSConfig))
	```
	or
	```
	service.Use(goacors.GoaCORSWithConfig(service, &goacors.GoaCORSConfig{
		AllowOrigins: []string{"http://example.com"},
		AllowMethods: []string{goacors.GET},
	}))
	```