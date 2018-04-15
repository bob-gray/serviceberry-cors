"use strict";

const vary = require("vary"),
	escape = require("escape-string-regexp"),
	{HttpError} = require("serviceberry"),
	wildcard = "*",
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

		if (this.options.origins !== wildcard) {
			this.createOriginMatcher();
		}

		if (this.options.requestHeaders) {
			this.allowHeaders = this.options.requestHeaders.join(", ");
		}

		if (this.options.responseHeaders) {
			this.exposeHeaders = this.options.responseHeaders.join(", ");
		}

		if (this.options.methods) {
			this.allowMethods = this.options.methods.join(", ");
		}
	}

	use (request, response) {
		const origin = request.getHeader("Origin"),
			allowOrigin = this.getAllowOrigin(request);

		if (origin && !allowOrigin) {
			throw new HttpError("Cross-origin access denied.", "Forbidden");
		}

		this.setAccessControlHeaders(allowOrigin, request, response);
		request.proceed();
	}

	setOptions (options) {
		if (options === wildcard || Array.isArray(options)) {
			options = {
				origins: options.slice()
			};
		} else if (typeof options === "string") {
			options = {
				origins: [options]
			};
		}

		Object.assign(this, {...defaultOptions, ...options});
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
			match = this.originMatcher(origin);
		} else if (this.options.credentials) {
			allowOrigin = origin;
		} else {
			allowOrigin = wildcard;
		}

		if (match) {
			allowOrigin = match.unshift();
		}

		return allowOrigin;
	}

	// eslint-disable-next-line complexity
	setAccessControlHeaders (allowOrigin, request, response) {
		const preflight = request.getMethod() === "OPTIONS",
			maxAge = this.getMaxAge(request),
			allowCredentials = this.getAllowCredentials(request),
			allowHeaders = this.getAllowHeaders(request),
			exposeHeaders = this.getExposeHeaders(request),
			allowMethods = this.getAllowMethods(request);

		response.setHeader("Access-Control-Allow-Origin", allowOrigin);

		if (allowOrigin !== "*") {
			vary(response, "Origin");
		}

		if (preflight && !isNaN(maxAge)) {
			response.setHeader("Access-Control-Max-Age", maxAge);
		}

		if (allowCredentials) {
			response.setHeader("Access-Control-Allow-Credentials", allowCredentials);
		}

		if (preflight && allowHeaders) {
			response.setHeader("Access-Control-Allow-Headers", allowHeaders);
		}

		if (exposeHeaders) {
			response.setHeader("Access-Control-Expose-Headers", exposeHeaders);
		}

		if (preflight && allowMethods) {
			response.setHeader("Access-Control-Allow-Methods", allowMethods);
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
		return this.allowMethods || request.getAllowMethods();
	}
}

function toPatterns (origin) {
	return origin.split(wildcard).map(escape).join(".*\\b");
}

module.exports = AccessControl.create;
module.exports.AccessControl = AccessControl;
