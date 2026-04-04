# HTML / HTTP Documentation & Cheatsheet

This document provides a quick reference for HTTP methods (commands), status code groups, and common status codes.

## HTTP Methods (Commands)

HTTP methods indicate the desired action to be performed for a given resource.

| Method | Description | Safe | Idempotent |
|---|---|---|---|
| **GET** | Retrieves a representation of the specified resource. Requests using GET should only retrieve data. | Yes | Yes |
| **POST** | Submits an entity to the specified resource, often causing a change in state or side effects on the server. | No | No |
| **PUT** | Replaces all current representations of the target resource with the request payload. | No | Yes |
| **DELETE** | Deletes the specified resource. | No | Yes |
| **PATCH** | Applies partial modifications to a resource. | No | No |
| **HEAD** | Asks for a response identical to a GET request, but without the response body. | Yes | Yes |
| **OPTIONS**| Describes the communication options for the target resource. | Yes | Yes |
| **TRACE** | Performs a message loop-back test along the path to the target resource. | Yes | Yes |
| **CONNECT**| Establishes a tunnel to the server identified by the target resource. | No | No |

## HTTP Status Code Groups

Status codes are grouped by their first digit, which defines the class of response.

| Group | Category | Description |
|---|---|---|
| **1xx** | Informational | The request was received, continuing process. |
| **2xx** | Successful | The request was successfully received, understood, and accepted. |
| **3xx** | Redirection | Further action needs to be taken in order to complete the request. |
| **4xx** | Client Error | The request contains bad syntax or cannot be fulfilled. |
| **5xx** | Server Error | The server failed to fulfill an apparently valid request. |

## Common HTTP Status Codes

Here are the most frequently encountered status codes:

### 2xx Success
* **200 OK**: The request succeeded. The result meaning depends on the HTTP method.
* **201 Created**: The request succeeded, and a new resource was created as a result.
* **204 No Content**: There is no content to send for this request, but the headers may be useful.

### 3xx Redirection
* **301 Moved Permanently**: The URL of the requested resource has been changed permanently.
* **302 Found**: The URI of the requested resource has been changed temporarily.
* **304 Not Modified**: Tells the client that the response has not been modified, so the client can continue to use the same cached version of the response.

### 4xx Client Error
* **400 Bad Request**: The server could not understand the request due to invalid syntax.
* **401 Unauthorized**: The client must authenticate itself to get the requested response.
* **403 Forbidden**: The client does not have access rights to the content.
* **404 Not Found**: The server can not find the requested resource.
* **405 Method Not Allowed**: The request method is known by the server but is not supported by the target resource.

### 5xx Server Error
* **500 Internal Server Error**: The server has encountered a situation it does not know how to handle.
* **502 Bad Gateway**: The server, while acting as a gateway or proxy, got an invalid response.
* **503 Service Unavailable**: The server is not ready to handle the request (e.g., it is down for maintenance or overloaded).
* **504 Gateway Timeout**: The server is acting as a gateway and cannot get a response in time.

## HTTP Cookies & Security Flags

Cookies are used for state management, tracking, and personalization. Security flags are vital to protect cookies from attacks like XSS and CSRF.

**Syntax using the semicolon (`;`):**
When a server sends a cookie to the client, it uses the `Set-Cookie` header. The cookie's name-value pair and its attributes are separated by a semicolon `;` followed by a space.
*Example:* `Set-Cookie: session_id=abc1234; Secure; HttpOnly; SameSite=Strict`

| Attribute / Flag | Description | Security Implication |
|---|---|---|
| **Secure** | Cookie is only sent over encrypted connections (HTTPS). | Prevents the cookie from being observed in plaintext over HTTP (protects against MitM). |
| **HttpOnly** | Cookie cannot be accessed via client-side scripts (e.g., JavaScript `document.cookie`). | Mitigates the risk of Cross-Site Scripting (XSS) stealing the cookie. |
| **SameSite** | Controls whether cookies are sent with cross-site requests. Values: `Strict`, `Lax`, `None`. | Mitigates Cross-Site Request Forgery (CSRF) attacks. |
| **Domain** | Specifies the hosts to which the cookie will be sent. | If too broad (e.g., `.example.com`), subdomains can dangerously access the cookie. |
| **Path** | Indicates the URL path that must exist in the requested URL to send the Cookie header. | Can be used to restrict cookie scope. |
| **Expires / Max-Age** | Determines the cookie's lifespan. | Short expiration limits the window of opportunity for stolen session cookies. |

## Common HTTP Security Headers

In addition to cookies, security headers are critical for hardening web applications. Since this repository relates to cyber writups, these headers are an excellent addition to check during security assessments:

| Header | Purpose | Security Benefit |
|---|---|---|
| **Strict-Transport-Security (HSTS)** | Forces the browser to only communicate over HTTPS. | Mitigates SSL stripping and Downgrade attacks. |
| **Content-Security-Policy (CSP)** | Defines approved sources of content that the browser may load. | Strongly mitigates XSS and data injection attacks. |
| **X-Content-Type-Options** | Set to `nosniff` to prevent the browser from MIME-sniffing the content type. | Mitigates drive-by download attacks and improper content interpretation. |
| **X-Frame-Options** | Restricts if a browser can render the page in a `<frame>`, `<iframe>`, or `<object>`. | Prevents clickjacking attacks. |
| **Referrer-Policy** | Controls how much referrer information is sent with requests. | Protects sensitive information that might be embedded in the URL. |
| **CORS Headers** | `Access-Control-Allow-Origin`, etc. control how resources are shared across origins. | Prevents unauthorized domains from accessing sensitive API responses via the browser. |
