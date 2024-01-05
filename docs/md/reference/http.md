## _class_ __PdefHeader__
Some Predefined HTTP Headers.
	
### CONTENT_XWFU
Header for URL Encoded Content-Type.
	
### CONTENT_JSON
Header for JSON Content-Type.
	
### ACCEPT_JSON
Header for JSON Accept.

## _class_ __ContentType__
Some HTTP Content Types.

### html
HTML Content Type
	
### plain
Plain Text Content Type
	
### label
The header key for Content Type.
	
### json
JSON Content Type
	
### xwfu
URL Encoded Content Type

## _class_ __Response__
Represents an HTTP Response.

### Response.__\_\_bool\_\___()
Whether or not it's a successful response.
	
### Response.__\_\_str\_\___()
Returns a formatted string containing all the public [1] properties of the
response instance. The formatting utilizes the `pprint.pformat()` method.
	
### Response.__\_\_repr\_\___()
Returns a formatted string containing all properties, including both
public [1] and private [1] ones, of the response. The formatting utilizes the
`pprint.pformat()` method.
	
### Response.__\_\_iter\_\___()
This method returns an iterator object, enabling iteration through the
public [1] variables of the response instance.
	

### _property_ Response.__content_type__
The content type of the response.
	
### _property_ Response.__length__
The length of the returned content.
	
### _property_ Response.__is_json__
Whether or not the returned content is in JSON format.

### _property_ Response.__json__
Returns dict containing parsed json content.
	
### _property_ Response.__content__
Returns the content in the format defined by the `"Content-Type"`
header.

If Content-Type is JSON, the parsed JSON is returned. If it's plain
text or HTML, the ASCII-decoded string is returned.

### _property_ Response.__error__
If any Error is encountered, it is returned as an AuthEngineError
instance.

[1] Public and Private variables are defined here:
https://docs.python.org/3/tutorial/classes.html#private-variables

## _class_ __Request__
This class make HTTP/HTTPS requests by employing
`http.client.HTTPConnection/http.client.HTTPSConnection` and returns the
response as an instance of Response.
	
### Request.__con_url__(url)
Returns a tuple consisting of an HTTPConnection/HTTPSConnection
instance and the URL to be used by that connection.
	
### Request.__make_body__(headers, body)
Constructs an appropriate body for HTTP/HTTPS requests based on the
`"Content-Type"` header. If the `"Content-Type"` header is not present, the
content is formatted in URL encoding media type and the `"Content-Type"`
header is set to `"application/x-www-form-urlencoded"`. Returns the body.

### Request.__\_get__(url, headers = {})
Makes an HTTP `GET` request and returns the response as a Response
instance.
	
### Request.__\_post__(url, headers = {}, body = None)
Makes an HTTP `POST` request and returns the response as a Response
instance.

### Request.__\_patch__(url, headers ={}, body = None)
Makes an HTTP `PATCH` request and returns the response as a Response
instance.

### staticmethod Request.__get__(url, headers = {})
An Alias staticmethod for `Request._get()` that creates the Request itself.

### staticmethod Request.__post__(url, headers = {}, body = None)
An Alias staticmethod for `Request._post()` that creates the Request itself.

### staticmethod  Request.__patch__(url, headers = {}, body = None)
An Alias staticmethod for `Request._patch()` that creates the Request itself.