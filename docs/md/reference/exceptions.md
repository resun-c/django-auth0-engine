# _class_ AuthEngineError()
# _class_ AuthEngineError(error)
# _class_ AuthEngineError(auth0_error)
# _class_ AuthEngineError(error, description)
# _class_ AuthEngineError(error, description, /, **kwarg)
This is a custom exception class used by various methods in this module. It
encapsulates information about the error encountered during the
authentication process and other processes.

##  Args:

	error (str, optional): A string representing the name of the error.
		
	description (str, optional): A short explanation of the error.

	**kwarg: keyword argument containing additional information about the error.


Each object has five property.

### AuthEngineError.__error__
This holds the error argument.

### AuthEngineError.__description__
This holds the description argument.

### AuthEngineError.__message__
This property captures the value of the "message" keyword argument, if
supplied, for cases where applicable Auth0 endpoints return a message.

Any additional keyword arguments passed to the constructor are accessible
as properties.

These are the methods available in a user object:

### AuthEngineError.__\_\_str\_\___()
Returns a formatted string containing all properties of the error. The
formatting utilizes the `pprint.pformat()` method.
	
### AuthEngineError.__\_\_repr\_\___()
Returns a string summarizing the error in the format
"error: description/message".
	
### AuthEngineError.__\_\_bool\_\___()
Always returns False.


Example Usage:

```
from django_auth0_engine import AuthEngine, AuthEngineError

try:
	user = AuthEngine().signin(request, username="johndoe", password="secret")
except AuthEngineError as e:
	print(f"Error: {e.error}")
	print(f"Description: {e.description}")
	print(f"Message: {e.message}")
```