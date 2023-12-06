# _class_ AuthEngineError()
# _class_ AuthEngineError(error)
# _class_ AuthEngineError(auth0_error)
# _class_ AuthEngineError(error, description)
# _class_ AuthEngineError(error, description, /, **kwarg)
Custom exception class raised by different methods of the AuthEngine class. It encapsulates information about the error encountered during the authentication process. error is a string representing the name of the error. description is short explanation of the error.

Each instance has five propery.

### AuthEngineError.__error__
This holds the error argument.

### AuthEngineError.__description__
This holds the description argument.

### AuthEngineError.__message__
It looks up the kwargs and try to find a value with key "message". If one such pair exists, it holds the value. In case of auth0_error, it looks for propery named "message".
	
### AuthEngineError.__additional_error__
Nested error information, stored if both error and an object with an error key are provided. Sometimes both the error and some other object with a key "error" can be passed as argument. In those cases, AuthEngineError.error holds the value of error and additional_error holds the value of the error key in that object.

### AuthEngineError.__additional_description__
Nested description information, similar to additional_error.

Any additional keyword arguments passed to the constructor are accessible as properties.

These are the methods available in a user object:

### AuthEngineError.__\_\_str\_\___()
Returns a formatted string with detailed information about the error using pprint.pformat().
	
### AuthEngineError.__\_\_repr\_\___()
Returns a string summarizing the error in the format "error: description/message".
	
### AuthEngineError.__\_\_bool\_\___()
Always returns False.

	
Example Usage:

```
try:
	user = AuthEngine().signin(
		request,
		username="johndoe",
		password="secret"
	)
except AuthEngineError as e:
	print(f"Error: {e.error}")
	print(f"Description: {e.description}")
	print(f"Message: {e.message}")

```