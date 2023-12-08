# _class_ AuthVerifierEngine(issuer, jwks_url, audience, algorithms)
A wrapper of auth0.authentication.token_verifier.TokenVerifier. The
auth0.authentication.token_verifier.TokenVerifier.verify function is used
to validate id tokens.

# _class_ AuthEngine
AuthEngine class facilitate with user authentication using Auth0 Python
SDK. It interacts with Auth0 endpoints to perform user authentication and
is compatible with various Django built-in modules and objects, including
the HttpRequest object. Most methods accept an optional HttpRequest object.
Successful authentication updates or creates session cookies in the
HttpRequest for future requests.

AuthEngine relies on several key pieces of information from the Django
project's settings to function: the Auth0 application's client ID and
client secret, the tenant domain, and the API audience. If any of these
required pieces of information are missing, an error will be raised.

Each AuthEngine object has these attributes:

### AuthEngine.BACKEND_NAME.
String representing the name of the backend. Default is,

```
"django_auth0_engine.engine.AuthEngine"
```

### AuthEngine.USERNAME_PASSWORD_REALM
String representing the Username-Password-Authentication realm of auth0.

## class AuthEngine.Scopes:
OpenID Connect Scopes.

### Scopes.REFRESH_TOKEN
Scope for refresh token.

### Scopes.OPENID
Scope for OpenID Information.

### Scopes.PROFILE
Scope for Profile Information.

### Scopes.EMAIL
Scope for Email address.
			
### Scopes.DEFAULT
Scope used as default if no scopes are provided.

### cached_property AuthEngine.issuer
Returns the issuer URL or None if the instance is unusable.

### cached_property AuthEngine.jwks_url
Returns the JWKS URL or None if the instance is unusable.

### cached_property AuthEngine.token_endpoint
Returns an instance of auth0.authentication.GetToken.

### cached_property AuthEngine.database_endpoint
Returns an instance of auth0.authentication.Database.

### cached_property AuthEngine.passwordless_endpoint
Returns an instance of auth0.authentication.Passwordless.

### cached_property AuthEngine.user_endpoint
Returns an instance of auth0.authentication.Users.

### cached_property AuthEngine.verifier
Returns an instance of AuthVerifierEngine initialized with issuer,
jwks_url, and audience.

These are all the methods AuthEngine object has:

### AuthEngine.__bool__()
Determines if the instance is usable based on the availability of
required information.

### AuthEngine.parse_response(response: str)
### AuthEngine.parse_response(response: dict[str, Any])
This method parses response data received from various Auth0 endpoints
and returns different types of AuthEngineResponse objects, including
User and AuthEngineError. It also parses auth session data from the
request object.

If the response includes an id_token, the function validates it using
AuthVerifierEngine.verify(). If valid, a User object is constructed
from the token's information and returned. If the token is expired and
a refresh_token exists, the function refreshes it using
AuthEngine.refresh_token() and returns the received response. In case
of an invalid token, an AuthEngineError object is returned. If the
response contains an _id key (indicating sign up), a corresponding
AuthEngineResponse object is constructed and returned. If the response
has an error key, a corresponding AuthEngineError object is constructed
and returned.

#### Args:

	response (str | dict): typically response from Auth0 endpoints or
		auth session data from request. If string is passed, it is
		first parsed as json.

#### Returns:
	AuthEngineResponse or User or AuthEngineError

### AuthEngine.to_session(response)
This method constructs a dictionary containing essential authentication
information (access_token, refresh_token, id_token, token_type, and
expires_in) from a User object. This dictionary is stored in the
request session cookie, which is later used by
AuthEngine.parse_response() to facilitate authentication for subsequent
requests.

#### Args:
	response (User): User object to acquire data from.

#### Returns:
	dict

### AuthEngine.set_session(request, response)
This method sets/updates the authentication session data stored in the
HttpRequest object with the dict returned by AuthEngine.to_session().
This modification only applies if the provided dictionary differs from
the current session data associated with the request.

#### Args:
	request (HttpRequest): The HttpRequest whose session cookie is
		set/updated.

	response (User): User object to acquire data from.

### AuthEngine.signin(request, username, password, [scope, realm, audience, grant_type, forwarded_for, keep_signed_in])
Signs in a user with username, password.

Upon authentication, it sets the auth session in the request and
returns a User object. Otherwise, an AuthEngineError object with
error information is returned; the request session is unchanged.

#### Args:
	request (HttpRequest): Django HttpRequest

	username (str): Resource owner's identifier

	password (str): resource owner's Secret

	scope(str, optional): String value of the different scopes the
		client is asking for. Multiple scopes are separated with
		whitespace.

	realm (str, optional): String value of the realm the user belongs.
		Set this if you want to add realm support at this grant.

	audience (str, optional): The unique identifier of the target API
		you want to access.

	grant_type (str, optional): Denotes the flow you're using. For
		password realm use
		http://auth0.com/oauth/grant-type/password-realm

	forwarded_for (str, optional): End-user IP as a string value. Set
		this if you want brute-force protection to work in server-side
		scenarios. See
		https://auth0.com/docs/get-started/authentication-and-authorization-flow/avoid-common-issues-with-resource-owner-password-flow-and-attack-protection

	keep_signed_in (bool): Whether or not to fetch refresh token for
		refreshing access token next time.
		
#### Returns:
	User or AuthEngineError

Example:

```
from django_auth0_engine import AuthEngine

user = AuthEngine().signin(
	request,
	username="user@company.com",
	password="pas$w4rd",
	realm=AuthEngine.USERNAME_PASSWORD_REALM,
	keep_signed_in=True,
)
if user:
	...
else:
	...
```

### AuthEngine.signin_code(request, code, redirect_uri)
This method signs in a user using the authorization code grant received
from various identity providers (IdPs), including social networks
(Google, Facebook, Twitter, LinkedIn), enterprise systems (Microsoft
Active Directory), and others.

Upon parsing the response, it sets the auth session in the request and
returns a User object. Otherwise, an AuthEngineError object with error
information is returned; the request session is unchanged.

#### Args:
	request (HttpRequest): Django HttpRequest

	code (str): authorization code grant provided by IdP

	redirect_uri (str): the url for which the code was intended for.
		
#### Returns:
	User or AuthEngineError

### AuthEngine.signup(request, email, password, [connection, username, user_metadata, given_name, family_name, name, nickname, picture, keep_signed_in])
This method allows to register a user with Auth0 application using
email address, password, and any additional information.
		
Upon successful sign up, it sets the auth session in the request and
returns a User object. Otherwise, an AuthEngineError object with error
information is returned; the request session is unchanged. A
verification mail is also sent to the email address.

#### Args:
	request (HttpRequest): Django HttpRequest

	email (str): The user's email address.

	password (str): The user's desired password.

	connection (str): The name of the database connection where
		this user should be created. By default it uses the
		"Username-Password-Authentication" connection.

	username (str, optional): The user's username, if required by the
		database connection.

	user_metadata (dict, optional): Additional key-value information to
		store for the user. Some limitations apply, see:
		https://auth0.com/docs/metadata#metadata-restrictions

	given_name (str, optional): The user's given name(s).

	family_name (str, optional): The user's family name(s).

	name (str, optional): The user's full name.

	nickname (str, optional): The user's nickname.

	picture (str, optional): A URI pointing to the user's picture.

	keep_signed_in (bool): Whether or not to fetch refresh token for
		refreshing access token next time.

#### Returns:
	User or AuthEngineError

#### Example:
		
```
from django_auth0_engine import AuthEngine

created_user = AuthEngine().signup(
	request,
	email="user@company.com",
	password="pas$w4rd",
	connection=AuthEngine.USERNAME_PASSWORD_REALM,
)
	
if created_user:
	...
else:
	...
```

### AuthEngine.change_password(email, connection)
This method sends a password change email to the email address if a
user with that email exists. 

#### Args:
	email (str): email address of the user.

	connection (str): The name of the database connection where the
		user was created. By default it uses the
		"Username-Password-Authentication" connection.

#### Returns:
	AuthEngineResponse object with an appropriate message.

### AuthEngine.refresh_access_token(refresh_token, scope)
This method refreshes an access token using the refresh_token. Upon
success, return a User object; an AuthEngineError object with error
information is returned otherwise. It sets the token_refreshed flag in
the response which is used by other functions to decide whether or not
to update the request session.

#### Args:
	refresh_token (str): the refresh token.

	scope (str): Used to limit the scopes of the new access token.
		Multiple scopes are separated with whitespace.

#### Returns:
	User or AuthEngineError

### AuthEngine.authenticate(request)
This method authenticates a request using the id_token. The id_token is
retrieved from the request session. Upon successful authentication, it
returns a User object; AuthEngineError otherwise. If the token is
expired and a refresh token exists in the request session, this method
fetches a new ID token and access token and updates the session cookie
automatically.

#### Args:
	request (HttpRequest): Django HttpRequest
		
#### Returns:
	User or AuthEngineError

### AuthEngine.authenticate_header(request)
This method functions similarly to the AuthEngine.authenticate()
method, except that the access_token is parsed from the request header
instead of the request session. Returns User object upon successful
authentication; AuthEngineError otherwise.

#### Args:
	request (HttpRequest): Django HttpRequest
		
#### Returns:
	User or AuthEngineError

### AuthEngine.get_user(access_token)
This method exchanges an access_token for a User object. Returns User
if successful; AuthEngineError otherwise.

#### Args:
	access_token (str): access_token

#### Returns:
	User or AuthEngineError