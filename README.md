serviceberry-cors
=================

[![CircleCI](https://circleci.com/gh/bob-gray/serviceberry-cors.svg?style=svg)](https://circleci.com/gh/bob-gray/serviceberry-cors)
[![Test Coverage](https://api.codeclimate.com/v1/badges/5a4fc498c6e90455f103/test_coverage)](https://codeclimate.com/github/bob-gray/serviceberry-cors/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/5a4fc498c6e90455f103/maintainability)](https://codeclimate.com/github/bob-gray/serviceberry-cors/maintainability)
[![npm version](https://badge.fury.io/js/serviceberry-cors.svg)](https://badge.fury.io/js/serviceberry-cors)

CORS plugin for [Serviceberry](https://serviceberry.js.org). For information on
Cross-Origin Resource Sharing check out this [article](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
on MDN.

Install
-------

```shell-script
npm install serviceberry-cors
```

Usage
-----

This plugin sets `Access-Control-` response headers describing what is
allowed when cross-origin requests are made. Forbidden cross-origin requests
are denied with a `403 Forbidden` response.

*without options*
```javascript
const cors = require("serviceberry-cors");

trunk.use(cors());                      // Access-Control-Allow-Origin: *
```

*with origin*
```javascript
const cors = require("serviceberry-cors");

trunk.use(cors("https://example.com")); // Access-Control-Allow-Origin: https://example.com
```

*with options*
```javascript
const cors = require("serviceberry-cors");

trunk.use(cors({
    origins: "https://*example.com",    // includes all subdomains and apex domain
    maxAge: 86400,                      // cache the preflight request for a day
    credentials: true,                  // requests can be made with credentials
    requestHeaders: [                   // requests can be made with these headers
        "X-Foo"
    ],
    responseHeaders: [                  // responses can include these headers
        "X-Baz"
    ],
    methods: [                          // requests can be made with these methods
        "GET",
        "PUT"
    ]
}))
```

Options
-------
  - **origins** *array or string*

	`Access-Control-Allow-Origin`

    A whitelist of origins or a single origin. Can be an asterisk `*` to be sent
	literally telling the client all origins. Can optionally include an asterisk
	`*` within an origin to mean *any* subdomain and/or *any* protocol.

      - `*.foo.com` matches `http` or `https` and any subdomain of `foo.com` but
        not `foo.com` as an apex (bare) domain.

      - `https://*foo.com` matches only `https` and any subdomains of `foo.com`
        including the apex (bare) domain. **notice there is no dot `.` after the
        asterisk `*`**

      - `*://foo.com` matches `http` or `https` and only the apex (bare) domain
        without a subdomain.

	Defaults to `*`

  - **maxAge** *number* [optional]

    `Access-Control-Max-Age`

    Number of seconds the result of the preflight request may be cached.

    By default this header will not be sent.

  - **credentials** *boolean* [optional]

    `Access-Control-Allow-Credentials`

    Whether the request is allowed to be made with credentials. *Cookies and
	Authorization header*

	By default this header will not be sent.

  - **requestHeaders** *array* [optional]

    `Access-Control-Allow-Headers`

    Whitelist of request headers that may be used beyond the CORS safe list.

	By default this header will not be sent.

  - **responseHeaders** *array* [optional]

    `Access-Control-Expose-Headers`

    Whitelist of response headers that are safe for use by the requesting origin.

	By default this header will not be sent.

  - **methods** *array* [optional]

    `Access-Control-Allow-Methods`

    Whitelist of request methods that may be used to make a request.

	Defaults to all implemented methods.

AccessControl
-------------

`serviceberry-cors` exports a static factory method for creating an instance of
the `AccessControl` class that serves as the Serviceberry handler. The class
can be accessed directly at `cors.AccessControl` if you wish to extend it. One
use case for extending `AccessControl` could be for dynamic header values beyond
`Access-Control-Allow-Origin`. Some methods of interest are listed below.

### constructor ([origins])

  - **origins** *array or string*

    *See above*

### constructor (options)

  - **options** *object*

    *See above*

### use (request, response)

Serviceberry handler method.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

  - **response** *object*

    Serviceberry [response](https://serviceberry.js.org/docs/response.html) object.

### getAllowOrigin (request)

Returns the value to be used for the `Access-Control-Allow-Origin` header. This
value will be used to determine whether Access-Controls headers are needed.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

### getMaxAge (request)

Returns the value to be used for the `Access-Control-Max-Age` header.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

### getAllowCredentials (request)

Returns the value to be used for the `Access-Control-Allow-Credentials`.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

### getAllowHeaders (request)

Returns the value to be used for the `Access-Control-Allow-Headers`.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

### getExposeHeaders (request)

Returns the value to be used for the `Access-Control-Expose-Headers`.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

### getAllowMethods (request)

Returns the value to be used for the `Access-Control-Allow-Methods`.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

### setAccessControlHeaders (allowOrigin, request, response)

Determines what headers to set and their values and sets them.

  - **allowOrigin** *string*

    `Access-Control-Allow-Origin` header value.

  - **request** *object*

    Serviceberry [request](https://serviceberry.js.org/docs/request.html) object.

  - **response** *object*

    Serviceberry [response](https://serviceberry.js.org/docs/response.html) object.
