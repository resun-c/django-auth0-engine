# _class_ AuthEngineResponse(**kwarg):

AuthEngineResponse serves as a base class for various response objects
returned by different methods of this module. It provides a standardized
way to access response data and check for successful operations.

Args:

	**kwarg: keyword argument containing information of the  response.

These are the property available in a AuthEngineResponse object:

### AuthEngineResponse.__access_token__
Access token received from the operation (if available).

### AuthEngineResponse.__refresh_token__
Refresh token received from the operation (if available).
		
### AuthEngineResponse.__id_token__
ID token received from the operation (if available).

### AuthEngineResponse.__token_type__
Type of the access token (if available).

### AuthEngineResponse.__expires_in__
Expiration time of the access token (if available).

### AuthEngineResponse.__message__
Message received from the Auth0 endpoint (if applicable).

These are the methods available in a AuthEngineResponse object:
	
### AuthEngineResponse.__\_\_bool\_\___()
Returns the value of the private<sup>[1]</sup> variable _bool. Various subclasses
determine the value of _bool based on the outcome of an operation. Upon
successful operation, _bool must be set to True; otherwise, it remains
False. By default, _bool is initialized as False.

### AuthEngineResponse.__\_\_str\_\___()
Returns a formatted string containing all the public<sup>[1]</sup>  properties of the
response object. The formatting utilizes the pprint.pformat() method.
	
### AuthEngineResponse.__\_\_repr\_\___()
Returns a formatted string containing all properties, including both
public<sup>[1]</sup>  and private<sup>[1]</sup>  ones, of the response. The formatting utilizes the
pprint.pformat() method.
	
### AuthEngineResponse.__\_\_iter\_\___()
This method returns an iterator object, enabling iteration through the
public<sup>[1]</sup> variables of the response object.

### Inheritance:

- User:

	Represents a successful authentication and provides OIDC
	information of the authenticated user.

- AuthEngineError:

	Represents an error encountered during an operation
	and contains detailed information of the error.
	
Example:

```
response = auth_engine.signin(request, username="johndoe", password="secret")
if response:
	user = response
	print(f"User ID: {user.id}")
else:
	print(f"Error: {response.error}")

```

[1] Public and Private variables are defined here:
[Python3 / tutorial / 9.6. Private Variables](https://docs.python.org/3/tutorial/classes.html#private-variables)
