# `curl` References

## The cURL Syntax

`curl` is a tool to transfer data from or to a server, using one of the supported protocols, without user interaction.

```bash
# Fetch HTML
curl example.com
```

  - This fetches the HTML for a webpage using a GET request.

```bash
# Views the request/response text
curl -v example.com
```

  - This views the request/response text by adding the `-v` option. 

    - `-v`: (*verbose*) Shows more detailed output.


```bash
# View the response headers
curl -I example.com
```

- This views the response headers only, using the `-I` option.

  - `-I`: only sees the response headers.

```bash
# Setting a request type and URL
curl --request GET --url example.com
```

- This explicitly sets a request type and URL with the `--request` and `--url` options.

  - `--request`: Sets the request type.
  - `--url`: Sets the URL.

```bash
# Viewing available options
curl --help
```

- This views all available options for `curl` command.

  - `--help`: Shows the help file.


```bash
# Send a GET request with parameters
curl --request https://example.com/get?parameter=value
```

- This sends a GET request to the `/get` endpoint with the following parameters: name, location.

  -  `--request`: Set the request type.
  -  `name`: Your name.
  -  `location`: Your current city.


```bash
# Send a GET request with parameters and show both request and response headers
curl -v --request https://example.com/get?name=rodric&location=atlanta
```
- This sends a GET request to the `/get` endpoint with the following parameters: name, location, but also prints out both request and response headers.

  -  `-v`: (*verbose*) Shows more detailed output (e.g. request and response headers).
  - `--request`: Sets the request type.
  - `name`: Your name.
  - `location`: Your current city.

```bash
# Send a POST request with parameters
curl -v --request POST --url https://postman-echo.com/post --data 'name=<yourname>&location=<yourlocation>'
```

- This sends a POST request to the `/post` endpoint using the same data as previous query parameters, but uses `curl`'s `--data` option instead.

  - `-v`: (*verbose*) Shows more detailed output.    <li><code>--request</code> set the request type
  - `--url`: Specific custom URL.
  - `--data`:` Specifies parameters.

```bash
# Send a GET request with request headers
curl -X --url https://httpbin.org/bearer -H 'authorization: {Type} {Credential}'
```

- This sends a GET request to the `bearer` endpoint for httpbin.org. You need to set the `type` of authorization and also the `credential`.
  - `-H`</code>`: Sets a request header.

--- 
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
