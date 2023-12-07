# _class_ AuthEngineResponse(**kwarg):
AuthEngineResponse serves as a base class for various response objects returned by methods within the AuthEngine and the ManagementEngine class. It provides a standardized way to access response data and check for successful operations.

These are the property available in a user object:

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

These are the methods available in a user object:
	
### AuthEngineResponse.__\_\_bool\_\___()
Returns the value of the private variable _bool. It's subclasses defines the value of _bool depending on the result of an operation.
	
### AuthEngineResponse.__\_\_str\_\___()
Returns a formatted string representing the response object. The string is formatted using pprint.pformat().
	
AuthEngineResponse.__\_\_repr\_\___()
Returns a formatted string representing all key-value pairs of the response. The string is formatted using pprint.pformat().
	
### AuthEngineResponse.__\_\_iter\_\___()
Allows iterating over publicly accessible variables of the response object. (Public variables: https://docs.python.org/3/tutorial/classes.html#private-variables)

Inheritance:

User: Represents a successful authentication and provides user information.

AuthEngineError: Represents an error encountered during an operation and contains detailed error information.
	
Example Usage:

```
# Successful authentication
response = auth_engine.signin(request,username="johndoe", password="secret")
if response:
	user = response
	print(f"User ID: {user.id}")
else:
	print(f"Error: {response.error}")

# Refreshing access token
response = auth_engine.refresh_access_toke(refresh_token="refresh_token")
if response:
	print(f"Access token refreshed: {response.access_token}")
else:
	print(f"Error: {response.error}")

```