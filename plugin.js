"use strict";

const vary = require("vary"),
	escape = require("escape-string-regexp"),
	{HttpError} = require("serviceberry"),
	wildcard = "*",
	wildcardDot = /\*\./,
	protocol = /^https?:\/\//,
	defaultOptions = {
		origins: wildcard,
		maxAge: NaN,
		credentials: false,
		methods: [],
		requestHeaders: [],
		responseHeaders: []
	};

class AccessControl {
	static create () {
		return new AccessControl(...arguments);
	}

	constructor (options = wildcard) {
		this.setOptions(options);

		if (this.options.origins[0] !== wildcard) {
			this.createOriginMatcher();
		}

		this.allowHeaders = this.options.requestHeaders.join(", ");
		this.exposeHeaders = this.options.responseHeaders.join(", ");
		this.allowMethods = this.options.methods.join(", ");
	}

	use (request, response) {
		const host = request.getHost(),
			origin = request.getHeader("Origin"),
			allowOrigin = this.getAllowOrigin(request);

		if (origin && !allowOrigin && host !== origin.replace(protocol, "")) {
			throw new HttpError("Cross-origin access denied.", "Forbidden");
		}

		this.setAccessControlHeaders(allowOrigin, request, response);
		request.proceed();
	}

	setOptions (options) {
		if (typeof options === "string" || Array.isArray(options)) {
			options = {
				origins: options.slice()
			};
		}

		if (typeof options.origins === "string") {
			options.origins = [options.origins];
		}

		this.options = {...defaultOptions, ...options};
	}

	createOriginMatcher () {
		const pattern = this.options.origins.map(toPatterns).join("|");

		this.originMatcher = new RegExp("^(?:" + pattern + ")$");
	}

	getAllowOrigin (request) {
		var origin = request.getHeader("Origin"),
			allowOrigin,
			match;

		if (this.originMatcher) {
			match = origin.match(this.originMatcher);
		} else if (this.options.credentials) {
			allowOrigin = origin;
		} else {
			allowOrigin = wildcard;
		}

		if (match) {
			allowOrigin = match[0];
		}

		return allowOrigin;
	}

	setAccessControlHeaders (allowOrigin, request, response) {
		const preflight = request.getMethod() === "OPTIONS";

		response.setHeader("Access-Control-Allow-Origin", allowOrigin);

		if (allowOrigin !== "*") {
			vary(response, "Origin");
		}

		this.setAllowCredentialsHeader(request, response);
		this.setExposeHeadersHeader(request, response);

		if (preflight) {
			this.setMaxAgeHeader(request, response);
			this.setAllowHeadersHeader(request, response);
			this.setAllowMethodsHeader(request, response);
		}
	}

	getMaxAge () {
		return this.options.maxAge;
	}

	getAllowCredentials () {
		return this.options.credentials;
	}

	getAllowHeaders () {
		return this.allowHeaders;
	}

	getExposeHeaders () {
		return this.exposeHeaders;
	}

	getAllowMethods (request) {
		return this.allowMethods || request.getAllowedMethods();
	}

	setMaxAgeHeader (request, response) {
		const maxAge = this.getMaxAge(request);

		if (!isNaN(maxAge)) {
			response.setHeader("Access-Control-Max-Age", maxAge);
		}
	}

	setAllowCredentialsHeader (request, response) {
		const allowCredentials = this.getAllowCredentials(request);

		if (allowCredentials) {
			response.setHeader("Access-Control-Allow-Credentials", allowCredentials);
		}
	}

	setAllowHeadersHeader (request, response) {
		const allowHeaders = this.getAllowHeaders(request);

		if (allowHeaders) {
			response.setHeader("Access-Control-Allow-Headers", allowHeaders);
		}
	}

	setExposeHeadersHeader (request, response) {
		const exposeHeaders = this.getExposeHeaders(request);

		if (exposeHeaders) {
			response.setHeader("Access-Control-Expose-Headers", exposeHeaders);
		}
	}

	setAllowMethodsHeader (request, response) {
		const allowMethods = this.getAllowMethods(request);

		if (allowMethods) {
			response.setHeader("Access-Control-Allow-Methods", allowMethods);
		}
	}
}

function toPatterns (origin) {
	var pattern;

	if (origin.match(wildcardDot)) {
		pattern = origin.split(wildcardDot).map(escape).join(".+");
	} else {
		pattern = origin.split(wildcard).map(escape).join("(?:.+\\.)?");
	}

	return pattern;
}

module.exports = AccessControl.create;
module.exports.AccessControl = AccessControl;
