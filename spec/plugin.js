"use strict";

const cors = require("../plugin"),
	Request = require("serviceberry/src/Request"),
	{HttpError} = require("serviceberry"),
	httpMocks = require("node-mocks-http");

describe("serviceberry-cors", () => {
	var handler,
		request,
		response;

	beforeEach(() => {
		handler = cors();
		request = createRequest();
		response = createResponse();
	});

	it("should create a handler instance with a use() method", () => {
		expect(typeof handler.use).toBe("function");
	});

	it("should export cors.AccessControl class", () => {
		expect(handler instanceof cors.AccessControl).toBe(true);
	});

	it("should set Access-Control-Allow-Origin: * by default", () => {
		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Origin", "*");
	});

	it("should set Access-Control-Allow-Origin with origin string as options", () => {
		handler = cors("https://www.foo.com");

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Origin", "https://www.foo.com");
	});

	it("should set Vary header with origin is not *", () => {
		handler = cors("https://www.foo.com");

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Vary", "Origin");
	});

	it("should set Access-Control-Allow-Origin with origin array as options and wildcard", () => {
		handler = cors(["https://*.foo.com", "https://other.io"]);

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Origin", "https://www.foo.com");
	});

	it("should set Access-Control-Allow-Origin with options object and wildcard for domain and protocol", () => {
		handler = cors({
			origins: "*.foo.com",
			maxAge: 60
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Origin", "https://www.foo.com");
	});

	it("should set Access-Control-Allow-Origin with origin as options and wildcard for protocol", () => {
		request = createRequest("GET", {
			Origin: "http://foo.com"
		});

		handler = cors("*://foo.com");

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Origin", "http://foo.com");
	});

	it("should set Access-Control-Allow-Origin with apex domain and wildcard", () => {
		request = createRequest("GET", {
			Origin: "https://foo.com"
		});

		handler = cors({
			origins: "https://*foo.com",
			maxAge: 60
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Origin", "https://foo.com");
	});

	it("should throw with an apex domain and a dot after wildcard", () => {
		request = createRequest("GET", {
			Origin: "https://foo.com"
		});

		handler = cors({
			origins: [
				"https://*.foo.com",
				"*example.com"
			]
		});

		expect(handler.use.bind(handler, request, response)).toThrowError(HttpError, "Cross-origin access denied.");
	});

	it("should throw with an origin that is similar to allowd origin with wildcard", () => {
		request = createRequest("GET", {
			Origin: "https://evil-foo.com"
		});

		handler = cors({
			origins: "*foo.com"
		});

		expect(handler.use.bind(handler, request, response)).toThrowError(HttpError, "Cross-origin access denied.");
	});

	it("should throw with an origin that is similar to allowd origin with wildcard", () => {
		request = createRequest("GET", {
			Origin: "https://evil-foo.com"
		});

		handler = cors({
			origins: "*.foo.com"
		});

		expect(handler.use.bind(handler, request, response)).toThrowError(HttpError, "Cross-origin access denied.");
	});

	it("should throw 403 if origin is not host and is not allowed", () => {
		handler = cors("https://other.io");

		expect(handler.use.bind(handler, request, response)).toThrowError(HttpError, "Cross-origin access denied.");
	});

	it("should set Access-Control-Max-Age", () => {
		handler = cors({
			maxAge: 86400
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Max-Age", 86400);
	});

	it("should set Access-Control-Allow-Credentials", () => {
		handler = cors({
			credentials: true
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Credentials", true);
	});

	it("should set Access-Control-Allow-Origin actual origin and not * when credentials is true", () => {
		handler = cors({
			credentials: true
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Origin", "https://www.foo.com");
	});

	it("should set Access-Control-Allow-Headers", () => {
		handler = cors({
			requestHeaders: [
				"X-Foo",
				"Something-Awesome"
			]
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Headers", "X-Foo, Something-Awesome");
	});

	it("should set Access-Control-Expose-Headers", () => {
		handler = cors({
			responseHeaders: [
				"X-Foo",
				"Something-Awesome"
			]
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Expose-Headers", "X-Foo, Something-Awesome");
	});

	it("should set Access-Control-Allow-Methods", () => {
		handler = cors({
			methods: [
				"GET",
				"OPTIONS"
			]
		});

		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Methods", "GET, OPTIONS");
	});

	it("should set implemented methods as Access-Control-Allow-Methods", () => {
		const allowed = "GET, HEAD, PUT, DELETE, OPTIONS";

		handler = cors();
		request.setAllowedMethods(allowed);
		handler.use(request, response);

		expect(response.setHeader).toHaveBeenCalledWith("Access-Control-Allow-Methods", allowed);
	});

	it("should not set preflight headers for a non preflight (OPTONS) request", () => {
		request = createRequest("GET");

		handler = cors({
			maxAge: 3600,
			requestHeaders: [
				"X-Baz"
			],
			allowMethods: [
				"GET",
				"HEAD",
				"PUT",
				"DELETE",
				"OPTIONS"
			]
		});

		handler.use(request, response);

		expect(response.setHeader).not.toHaveBeenCalledWith("Access-Control-Max-Age", 3600);
		expect(response.setHeader).not.toHaveBeenCalledWith("Access-Control-Allow-Headers", "X-Baz");
		expect(response.setHeader).not.toHaveBeenCalledWith("Access-Control-Allow-Methods", "GET, HEAD, PUT, DELETE, OPTIONS");
	});
});

function createRequest (
	method = "OPTIONS",
	headers = {
		host: "www.example.com",
		origin: "https://www.foo.com"
	}) {
	var incomingMessage = httpMocks.createRequest({
			method: method,
			url: "/",
			headers: headers
		}),
		request;


	incomingMessage.setEncoding = Function.prototype;
	request = new Request(incomingMessage);
	request.proceed = jasmine.createSpy("request.proceed");

	return request;
}

function createResponse () {
	var response = jasmine.createSpyObj("Response", [
		"setHeader",
		"getHeader"
	]);

	return response;
}
