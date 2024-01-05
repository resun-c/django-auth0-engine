The AuthEngine: Support for user authentication using Auth0 Auth API.

Most methods accept a HttpRequest instance as the first argument. This instance
is used to store authentication-related session data for subsequent requests.

The methods rely on a set of constants that are fetched from settings.py (see
apps.py).

## __verify_id_token__(token)
Validates a token and returns the payload. If the token is invalid, an
exception is raised.

### token
token to be validated.

## __parse_response__(response, request)
## __parse_response__(response_dict, request)
Parses the response received from various Auth0 endpoints or
authentication session data and returns an instance of AuthEngineResponse
or its subclass.

If an id_token is present in the response, it is validated using
`verify_id_token()`. If the token is valid, a User instance constructed from
the payload is returned. In case, the token is expired and a `refresh_token`
is present the tokens are refreshed and a User instance is returned. If the
token is invalid an AuthEngineError instance with proper information is
returned.

The presence of an `_id` key in the response indicates sign-up. In this case,
an AuthEngineResponse instance constructed from the response is returned.

### response
typically response from Auth0 endpoints or auth session data from
request.

## __to_session__(user)
Returns a dictionary containing authentication session data constructed
from User instance.

### response
User instance to acquire data from.
	
## __set_session__(request, response)
Sets authentication session data in the HttpRequest instance. The data
is received from `to_session()`. The modification in the HttpRequest
instance's session applies only if the new session data differs from the
current session data.

### request
The HttpRequest instance to set the session cookie to.

### response
AuthEngineResponse to acquire the data from.

## __signin__(request, username, password [, scope = cfg.Provider.Scopes.DEFAULT, realm = cfg.Provider.USERNAME_PASSWORD_REALM, audience = None, keep_signed_in = False])
Signs in a user with username, and password.

Upon authentication, it sets the auth session in the request and
returns a User instance. Otherwise, an AuthEngineError instance with
error information is returned; the request session is unchanged.

### request
Django HttpRequest.

### username
Resource owner's identifier.

### password
resource owner's Secret.

### scope
The string value of the different scopes the application is asking for.
Multiple scopes are separated with whitespace. The default value is
`cfg.Provider.Scopes.DEFAULT`.

### realm
The string value of the realm the user belongs to. Set this if you want to add
realm support at this grant. By default, it uses the
`"Username-Password-Authentication"` connection.

### audience
The unique identifier of the target API you want to access. For
authentication purpose, it's the Auth0 application's `client_id`.

### keep_signed_in
Whether or not to fetch a refresh token for refreshing the access token
next time.

## __signin_code__(request, code, redirect_uri)
Signs in a user using the authorization code grant received
from various identity providers (IdPs), including social networks
(Google, Facebook, Twitter, LinkedIn), enterprise systems (Microsoft
Active Directory), and others.

Upon parsing the response, it sets the auth session in the request and
returns a User instance. Otherwise, an AuthEngineError instance with error
information is returned; the request session is unchanged.

### request
Django HttpRequest

### code
authorization code grant provided by IdP

### redirect_uri
the URL for which the code was intended.

## __signup__(request, email, password, username = None, connection = cfg.Provider.USERNAME_PASSWORD_REALM, user_metadata = None, given_name = None, family_name = None, name = None, nickname = None, picture = None, keep_signed_in = False)

Registers a user with Auth0 application using email address, password,
and additional information.

Upon successful registration, it sets the auth session in the request
and returns a User instance. Otherwise, an AuthEngineError instance with
error information is returned.

### request
Django HttpRequest.

### email
The user's email address.

### password
The user's desired password.

### username
The user's username, if required by the database connection.

### connection
The name of the database connection where this user should be created.
By default, it uses the `"Username-Password-Authentication"` connection.

### user_metadata
Additional key-value information to store for the user. Some
limitations apply, see:
https://auth0.com/docs/metadata#metadata-restrictions

### given_name
The user's given name(s).

### family_name
The user's family name(s).

### name
The user's full name.

### nickname
The user's nickname.

### picture
A URI pointing to the user's picture.

### keep_signed_in
Whether or not to fetch a refresh token for refreshing the access token
next time.

## __change_password__(email, connection = cfg.Provider.USERNAME_PASSWORD_REALM, organization = None)
	
Sends a password change email to the email address if a user with that
email exists. 

### email
email address of the user.

### connection
The name of the database connection where the user was created. By
default, it uses the `"Username-Password-Authentication"` connection.

## __refresh_access_token__(request, refresh_token, scope = cfg.Provider.Scopes.DEFAULT)
Refreshes an access token using the provided `refresh_token`.
	 
Upon refreshment returns a User instance; an AuthEngineError instance with
error information is returned otherwise. It sets the `_token_refreshed` flag
in the response which is used by other functions to decide whether or not
to update the request session.

### refresh_token
the refresh token.

### scope
Used to limit the scopes of the new access token. Multiple scopes are
separated with whitespace. The default value is
`cfg.Provider.Scopes.DEFAULT`.

## __authenticate__(request)
Authenticates a HttpRequest instance.

The authentication session data is retrieved from the request session and
passed to `parse_response()`. If `parse_response()` refreshes the tokens, the
session data is updated in HttpRequest. It returns the same instance as the
`parse_response()`.
	
### request
Django HttpRequest.

## __authenticate_header__(request)
Functions similarly to `authenticate()`, except that the tokens are parsed
from the request header instead of the request session. Returns the return
value of `parse_response()`.

### request
Django HttpRequest.

## __get_user__(request, access_token)
Exchanges an `access_token` for a User instance. Returns User if successful;
AuthEngineError otherwise.

### request
Django HttpRequest.
		
### access_token
The access token.
