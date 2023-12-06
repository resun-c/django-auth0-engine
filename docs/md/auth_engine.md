# _class_ AuthVerifierEngine(issuer, jwks_url, audience, algorithms)
A wrapper of auth0.authentication.token_verifier.TokenVerifier. The auth0.authentication.token_verifier.TokenVerifier.verify  function is used to validate id tokens.

# _class_ AuthEngine
AuthEngine class facilitate with user authentication using Auth0 Python SDK. It interacts with Auth0 endpoints to perform user authentication and is compatible with various Django built-in modules and objects, including the HttpRequest object. Most methods accept an optional HttpRequest object. Successful authentication updates or creates session cookies in the HttpRequest for future requests.

AuthEngine relies on several key pieces of information from the Django project's settings to function: the Auth0 application's client ID and client secret, the tenant domain, and the API audience. If any of these required pieces of information are missing, an error will be raised.

Each AuthEngine object has these attributes:

### AuthEngine.__BACKEND_NAME__.
String representing the name of the backend. Default is, "django_auth0_engine.engine.AuthEngine"

### AuthEngine.__USERNAME_PASSWORD_REALM__
String representing the Username-Password-Authentication realm of auth0.

## _class_ AuthEngine.__Scopes__:
OpenID Connect Scopes.

### Scopes.__REFRESH_TOKEN__
Scope for refresh token.

### Scopes.__OPENID__
Scope for OpenID Information.

### Scopes.__PROFILE__
Scope for Profile Information.

### Scopes.__EMAIL__
Scope for Email address.
			
### Scopes.__DEFAULT__
Scope used as default if no scopes are provided.

### _cached_property_ AuthEngine.__issuer__
Returns the issuer URL or None if the instance is unusable.

### _cached_property_ AuthEngine.__jwks_url__
Returns the JWKS URL or None if the instance is unusable.

### _cached_property_ AuthEngine.__token_endpoint__
Returns an instance of auth0.authentication.GetToken.

### _cached_property_ AuthEngine.__database_endpoint__
Returns an instance of auth0.authentication.Database.

### _cached_property_ AuthEngine.__passwordless_endpoint__
Returns an instance of auth0.authentication.Passwordless.

### _cached_property_ AuthEngine.__user_endpoint__
Returns an instance of auth0.authentication.Users.

### _cached_property_ AuthEngine.__verifier__
Returns an instance of AuthVerifierEngine initialized with issuer, jwks_url, and audience.

These are all the methods AuthEngine object has:

### AuthEngine.__\_\_bool\_\___()
Determines if the instance is usable based on the availability of required information.

### AuthEngine.__parse_response__(response: str)AuthEngine.__parse_response__(response: dict[str, Any])
Parse response received from different auth0 endpoints and return different types of AuthEngineResponse instances including User and AuthEngineError. It also parse auth data stored in request's session cookies.
		
If an id_token is present in response, it validates that using AuthVerifierEngine.verify. If the token is valid, an User instance is constructed from the informations of the id_token and returned. If thetoken is expired and a refresh_token exists in response, it refreshes the token by calling AuthEngine.refresh_token and return the response received from it. In case, the token is invalid and AuthEngineError is returned.

### AuthEngine.__to_session__(response)
Converts a parsed response to a dictionary containing information including access_token, refresh_token, id_token, token_type, and expires_in for session storage.

The dict is stored in auth session, which is parsed by AuthEngine.parse_response for authenticating subsequent requests.


### AuthEngine.__set_session__(request, response)
Sets the authorization session in the HttpRequest object from dict returned by AuthEngine.to_session. The session is modified only if it's not the same as the existing session in the request.


### AuthEngine.__signin__(request, username, password, [scope, realm, audience, grant_type, forwarded_for, keep_signed_in])
Signs in a user with username, password, belonging to realm. grant_type denotes the flow being used. Default is http://auth0.com/oauth/grant-type/password-realm (from auth0 sdk). forwarded_for is the End-user IP as a string value. It is used for brute-force protection to work in server-side scenarios. keep_signed_in defines whether or not to fetch a refresh token.

Upon authentication, it sets session in the request object and return a User instance. Otherwise, an AuthEngineError instance with error information is returned, request session is unchanged.

Example:

```
user = AUTH0_ENGINE_INSTANCE.signin(
	request,
	username="user@company.com",
	password="pas$w4rd",
	realm=AUTH0_ENGINE_INSTANCEUSERNAME_PASSWORD_EALM,
	keep_signed_in=True,
)

if user:
    ...
else:
    ...

```

### AuthEngine.__signin_code__(request, code, redirect_uri)
Signs in a user using the authorization code grant received from the identity providers such as Google, Facebook, X, and Microsoft.

Upon parsing the response, it sets session in request and return a User instance. Otherwise, an AuthEngineError instance with error information is returned, request session is unchanged.

### AuthEngine.__signup__(request, email, password, [connection, username, user_metadata, given_name, family_name, name, nickname, picture, signin, keep_signed_in])
Sign up a user using email, password, and other provided information. picture is a URL representing the profile picture. If signin is set, a session cookie is set in the request. keep_signed_in defines whether or not to fetch a refresh token and is only used if signin is set.

If the user is successfully signed up, session is set in request and return a User instance. Otherwise, an AuthEngineError instance with error information is returned, request session is unchanged.

Example:
		
```
created_user = AUTH0_ENGINE_INSTANCE.signup(
	request,
	email="user@company.com",
	password="pas$w4rd",
	connection=AUTH0_ENGINE_INSTANCE.USERNAME_PASSWORD_REALM,
)

if created_user:
	...
else:
	...

```

### AuthEngine.__change_password__(email, connection)
Sends a password change email to the email address if a user with that email exists. An AuthEngineResponse instance is returned with an appropriate message.

### AuthEngine.__refresh_access_token__(refresh_token, scope)
Refreshes an access token using the refresh_token. Upon success, return a User instance; an AuthEngineError instance with error information is returned otherwise. It sets the token_refreshed flag in the response which is used by other function to decide wheather or not to update session.

### AuthEngine.__authenticate__(request)
Authenticates a request using the id_token. The id_token is acquire from the session cookie. Returns User on successful authorization; AuthEngineError otherwise. If token is refreshed, updates session cookie.

### AuthEngine.__authenticate_header__(request)
Functions similarly to AuthEngine.authenticate, except that the access_token is parsed from the request header instead of the session cookie. Returns User on successful authorization; AuthEngineError otherwise.

### AuthEngine.__get_user__(access_token)
Exchanges the access_token for a User instance. Returns User if successful; AuthEngineError otherwise.