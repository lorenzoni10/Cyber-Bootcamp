# HTTP Requests and Responses Reference

**Table of Contents**

<!-- TOC -->

- [HTTP Requests and Responses Reference](#http-requests-and-responses-reference)
  - [Client-Server Architecture](#client-server-architecture)
  - [HTTP](#http)
    - [The HTTP Exchange](#the-http-exchange)
    - [The HTTP Client](#the-http-client)
    - [The HTTP Server](#the-http-server)
    - [Example of an HTTP Request](#example-of-an-http-request)
    - [Example of an HTTP Response](#example-of-an-http-response)
  - [HTTP Requests](#http-requests)
    - [HTTP Request Methods](#http-request-methods)
    - [Common HTTP Request Headers](#common-http-request-headers)
    - [HTTP Request Bodies](#http-request-bodies)
  - [HTTP Responses](#http-responses)
    - [HTTP Response Status Codes](#http-response-status-codes)
    - [HTTP Response Headers](#http-response-headers)

<!-- /TOC -->

---

## Client-Server Architecture

An example of the typical web client and server architecture:

![HTTP Web Client Server](../../../Images/HTTP_web_client_server.png)

---

## HTTP

- The Hypertext Transfer Protocol (HTTP) is an application-level protocol for distributed, collaborative, hypermedia information systems. This is the foundation for data communication for the World Wide Web (i.e. internet) since 1990. HTTP is a generic and stateless protocol that can be used for other purposes as well using extensions of its request methods, error codes, and headers. ([Source](https://www.tutorialspoint.com/http/http_overview.htm))

### The HTTP Exchange

- The HTTP protocol is a request/response protocol based on the client/server based architecture where web browsers, robots and search engines, etc. act like HTTP clients, and the Web server acts as a server. ([Source](https://www.tutorialspoint.com/http/http_overview.htm))

- HTTP is based on the client-server architecture model and a stateless request/response protocol that operates by exchanging messages across a reliable TCP/IP connection. ([Source](https://www.tutorialspoint.com/http/http_messages.htm))

### The HTTP Client

- An HTTP "client" is a program (Web browser or any other client) that establishes a connection to a server for the purpose of sending one or more HTTP request messages. ([Source](https://www.tutorialspoint.com/http/http_messages.htm))

### The HTTP Server

- An HTTP "server" is a program ( generally a web server like Apache Web Server ) that accepts connections in order to serve HTTP requests by sending HTTP response messages. ([Source](https://www.tutorialspoint.com/http/http_messages.htm))

### Example of an HTTP Request

An example HTTP GET request for the web page (h</div>ttp://www.example.com/hello.html):

> Example Request Header

```HTTP
GET /hello.html HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Host: www.example.com
Accept-Language: en-us
Accept-Encoding: gzip, deflate
Connection: Keep-Alive
```

    (this example has no request body)

### Example of an HTTP Response

An example HTTP 200 response to the request example above:

> Example Response Header

```HTTP
HTTP/1.1 200 OK
Date: Mon, 27 Jul 2009 12:28:53 GMT
Server: Apache/2.2.14 (Win32)
Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT
Content-Length: 88
Content-Type: text/html
Connection: Closed
```

> Example Response Body (HTML or HyperText Markup Language)

```HTML
<html>
    <body>
    <h1>Hello, World!</h1>
    </body>
</html>
```

---

## HTTP Requests

### HTTP Request Methods

<!-- prettier-ignore -->
| HTTP Method | Description                                                                                                                           |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| GET         | Requests data *from* a server. Requests using GET should only retrieve data.                     |
| HEAD        | The HEAD method is identical to GET except that the server does not send the response body.|
| POST        | Sends data *to* the specified resource, often changing or updating the server. |
| PUT         | Replaces all current representations of the specified resource with the request payload (the requested data).                                  |
| DELETE      | Deletes the specified resource.                                                                                     |
| CONNECT     | Establishes a tunnel to the server identified by the target resource.                                              |
| OPTIONS     | Describes the communication options for the target resource.                                             |
| TRACE       | Performs a message loop-back test along the path to the target resource.                                             |
| PATCH       | Applies partial modifications to a resource.                                                                |

---

### Common HTTP Request Headers

<!-- prettier-ignore -->
| **Header**  | **Usage and Parameters**   | **Description**                                                                                                                                                                                                                                                                                           |
| ------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Authorization | {type} {credentials}         | Contains the credentials to authenticate a user with a server, usually after the server has responded with a 401 Unauthorized status and the WWW-Authenticate header.                                                                     |
| Referer       | {url}                        | Contains the address of the previous webpage that linked to the currently requested page. Allows servers to identify where people are visiting from and may use that data for analytics, logging, or optimized caching. |
| Cookie        | {Cookie_Name}={Cookie_Value} | Contains stored HTTP cookies previously sent by the server with the Set-Cookie header.                                                                                                                                                                                       |
| User-Agent    | {product}                    | A string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent.                                                                                                               |

### HTTP Request Bodies

---

## HTTP Responses

### HTTP Response Status Codes

<!-- prettier-ignore -->
| Status Codes               | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **200 Codes**           | **Successful Responses**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 200 OK                    | The request succeeded. The meaning of the success depends on the HTTP method.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **300 Codes**           | **Redirects**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 301 Moved Permanently     | The URL of the requested resource has been changed permanently. The new URL is given in the response.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **400 Codes**           | **Client Errors**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 400 Bad Request           | The server could not understand the request due to invalid syntax.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 401 Unauthorized          | Although the HTTP standard specifies "unauthorized," semantically this response means "unauthenticated." That is, the client must authenticate itself to get the requested response.                                                                                                                                                                                                                                                                                                                                                                                                          |
| 403 Forbidden             | The client does not have access rights to the content. That is, it is unauthorized, so the server is refusing to give the requested resource. Unlike 401, the client's identity is known to the server.                                                                                                                                                                                                                                                                                                                                                                                      |
| 404 Not Found             | The server can not find the requested resource. In the browser, this means the URL is not recognized. In an API, this can mean that the endpoint is valid but the resource itself does not exist. Servers may also send this response instead of 403 to hide the existence of a resource from an unauthorized client.                                                                                                                                                                     |
| 429 Too Many Requests     | The user has sent too many requests in a given amount of time ("rate limiting").                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **500 Codes**           | **Server Errors**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 500 Internal Server Error | The server has encountered a situation that it doesn't know how to handle.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 502 Bad Gateway           | The server, while working as a gateway to get a response needed to handle a request, got an invalid response.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 503 Service Unavailable   | The server is not ready to handle the request. Common causes are a server that is down for maintenance or overloaded. This response should be accompanied by a page explaining the problem. This response should be used for temporary conditions and the Retry-After HTTP header should, if possible, contain the estimated time before the recovery of the service. These temporary condition responses should usually not be cached. |

---

### HTTP Response Headers

HTTP response headers let the client and the server pass additional information with an HTTP request or response. An HTTP header consists of its case-insensitive name followed by a colon `:`, then its value. Whitespace before the value is ignored.


- **Connection**: `keep-alive` Indicates that the client would like to keep the connection open. Having a persistent connection is the default on HTTP/1.1 requests.
- **Set-Cookie**:  The Set-Cookie HTTP response header is used to send cookies from the server to the user agent, so the user agent can send them back to the server later. 
- **X-XSS-Protection**: The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
