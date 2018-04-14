serviceberry-cors
=================

CORS plugin for [Serviceberry](https://serviceberry.js.org).

Install
-------

```shell-script
npm install serviceberry-cors
```

Usage
-----

This plugin sets `Access-Control-` response headers telling browsers what is
allowed when cross origin requests are made.

**without options**
```javascript
const cors = require("serviceberry-cors");

trunk.use(cors());                      // Access-Control-Allow-Origin: *
```

**with origin**
```javascript
const cors = require("serviceberry-cors");

trunk.use(cors("https://example.com")); // Access-Control-Allow-Origin: https://example.com
```

**with options**
```javascript
const cors = require("serviceberry-cors");

trunk.use(cors({
    origins: "https://*example.com",    // includes all subdomains including none
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
	`*` with an origin to mean *any* subdomain and/or *any* protocol.

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

  - **requestHeaders** *array*

    Whitelist of request headers that may be used beyond the CORS safe list.

	By default this header will not be sent.

  - **responseHeaders** *array*

    Whitelist of response headers that are safe for use by the requesting origin.

	By default this header will not be sent.

  - **methods** *array*

    Whitelist of request methods that may be used to make a request.

	Defaults to all implemented methods.

AccessControl
-------------

`serviceberry-cors` exports a static factory method for creating an instance of
the `AccessControl` class that serves as the Serviceberry handlers. The class
can be accessed directly at `cors.AccessControl` if you wish to extend it. Some
methods of interest are listed below.

### constructor ([origins])

  - **origins** *array or string*

    *See above*

### constructor (options)

  - **options** *object*

    *See above*

### use (request, response)

Serviceberry handler method.

  - **request** *object*

    Serviceberry request object.

  - **response** *object*

    Serviceberry resposne object.

### getAllowOrigin (request)

Returns the value to be used for the `Access-Control-Allow-Origin` header. This
value will be used to determine whether Access-Controls headers are needed.

  - **request** *object*

    Serviceberry request object.

### getMaxAge (request)

Returns the value to be used for the `Access-Control-Max-Age` header.

  - **request** *object*

    Serviceberry request object.

### getAllowCredentials (request)

Returns the value to be used for the `Access-Control-Allow-Credentials`.

  - **request** *object*

    Serviceberry request object.

### getAllowHeaders (request)

Returns the value to be used for the `Access-Control-Allow-Headers`.

  - **request** *object*

    Serviceberry request object.

### getExposeHeaders (request)

Returns the value to be used for the `Access-Control-Expose-Headers`.

  - **request** *object*

    Serviceberry request object

### getAllowMethods (request)

Returns the value to be used for the `Access-Control-Allow-Methods`.

  - **request** *object*

    Serviceberry request object.

### setAccessControlHeaders (allowOrigin, request, response)

Determines what headers to set and their values and sets them. 

  - **allowOrigin** *string*

    `Access-Control-Allow-Origin` header value.

  - **request** *object*

    Serviceberry request object.

  - **response** *object*

    Serviceberry resposne object.
