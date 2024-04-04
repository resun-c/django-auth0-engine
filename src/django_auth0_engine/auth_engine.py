"""The AuthEngine: Support for user authentication using Auth0 Auth API.

Most methods accept a HttpRequest instance as the first argument. This instance
is used to store authentication-related session data for subsequent requests.

The methods rely on a set of constants that are fetched from settings.py (see
apps.py).
"""
import jwt
from jwt import PyJWKClient
from typing import Any
from django.http import HttpRequest
from functools import singledispatch

from . import cfg
from .exceptions import *
from .error import AuthEngineError
from .response import AuthEngineResponse
from .http import Request, Response, PdefHeader
from .user import User, NoUser

def verify_id_token(token: str) -> dict:
	"""Validates a token and returns the payload. If the token is invalid, an
	exception is raised.

	token (str):
		token to be validated.
	"""
	unverified_header = jwt.get_unverified_header(token)
	alg = unverified_header["alg"]
	jwks_client = PyJWKClient(cfg._AUTH0_JWKS_URL)
	signing_key = jwks_client.get_signing_key_from_jwt(token)
	
	try:
		claims = jwt.decode(
			token,
			signing_key.key,
			algorithms=[alg],
			issuer=cfg._AUTH0_ISSUER,
			audience=cfg._AUTH0_AUDIENCE)
		return claims
	except:
		raise

@singledispatch
def _parse_response(
		response_dict: dict[str, Any],
		request: HttpRequest
	) -> AuthEngineResponse | User | AuthEngineError:
	"""Parses the response received from various Auth0 endpoints or
	authentication session data and returns an instance of AuthEngineResponse
	or its subclass.

	If an id_token is present in the response, it is validated using
	verify_id_token(). If the token is valid, a User instance constructed from
	the payload is returned. In case, the token is expired and a refresh_token
	is present the tokens are refreshed and a User instance is returned. If the
	token is invalid an AuthEngineError instance with proper information is
	returned.

	The presence of an _id key in the response indicates sign-up. In this case,
	an AuthEngineResponse instance constructed from the response is returned.

	response (Response | dict):
		typically response from Auth0 endpoints or auth session data from
		request.
	"""
	
	# check configuration
	cfg._bool()

	return_response = AuthEngineError(
		loc="AuthEngine._parse_response()",
		error="Unknown"
	)

	if response_dict:
		# response from token endpoint or auth session.
		if "id_token" in response_dict:
			# parse payload from id_token
			try:
				id_token_payload = verify_id_token(response_dict["id_token"])
				# instantiate an User with id_token_payload and data
				# received in response (i.e. access_token,
				# refresh_token, expires_in)
				return_response = User(**(id_token_payload | response_dict))
				return_response._request = request
			# if invalid token try to refresh token
			except jwt.ExpiredSignatureError as err:
				if "refresh_token" in response_dict:
					refreshed = refresh_access_token(
						request,
						response_dict["refresh_token"],
						scope=response_dict.get("scope", None)
					)
					return refreshed
				else:
					return AuthEngineError(
						error = "Expired Session!",
						loc = "AuthEngine._parse_response()",
						description = "The given token has been expired."
					)
			except Exception as err:
				return AuthEngineError(exception=err)
		# sign-up
		elif "_id" in response_dict:
			return_response = AuthEngineResponse(**response_dict)
		# error
		elif "error" in response_dict:
			return AuthEngineError(**response_dict)
		else:
			return_response = AuthEngineResponse(**response_dict)
	return return_response

@_parse_response.register
def _(response: Response, request: HttpRequest) -> AuthEngineResponse:
	"""A dispatch of _parse_response that takes .http.Response as the response.
	"""
	return_response = AuthEngineError(
		loc="AuthEngine._parse_response",
		error="Unknown"
	)
	if response:
		if response.is_json:
			return_response = _parse_response(response.json, request)
		else:
			return_response = AuthEngineResponse(message = response.content)
	else:
		return_response = response.error
		return_response.prepend_loc("AuthEngine._parse_response()")
	
	return return_response

def to_session(user: User) -> dict[str, Any]:
	"""Returns a dictionary containing authentication session data constructed
	from User instance.

	response (User):
		User instance to acquire data from.
	"""
	if user:
		data = {
			"access_token":			user.__dict__.get("access_token", None),
			"refresh_token":		user.__dict__.get("refresh_token", None),
			"id_token":				user.__dict__.get("id_token", None),
			"token_type":			user.__dict__.get("token_type", None),
			"expires_in":			user.__dict__.get("expires_in", None)
		}
		return data
	return {}
	
def set_session(request: HttpRequest, response: User) -> None:
	"""Sets authentication session data in the HttpRequest instance. The data
	is received from to_session(). The modification in the HttpRequest
	instance's session applies only if the new session data differs from the
	current session data.

	request (HttpRequest):
		The HttpRequest instance to set the session cookie to.

	response (AuthEngineResponse):
		AuthEngineResponse to acquire the data from.
	"""
	if response:
		existing_auth = request.session.get(cfg._SESSION_KEY)
		new_auth = to_session(response)
		# session is updated only if auth is updated to prevent unnecessary database access
		if existing_auth != new_auth:
			request.session[cfg._SESSION_KEY] = new_auth
			request.session.modified = True

def signin(
	request: HttpRequest | None,
	username: str,
	password: str,
	scope: str = cfg.Provider.Scopes.DEFAULT,
	realm: str = cfg.Provider.USERNAME_PASSWORD_REALM,
	audience: str | None = None,
	keep_signed_in: bool = False
) -> User | AuthEngineError:
	"""Signs in a user with username, and password.

	Upon authentication, it sets the auth session in the request and
	returns a User instance. Otherwise, an AuthEngineError instance with
	error information is returned; the request session is unchanged.

	request (HttpRequest):
		Django HttpRequest.

	username (str):
		Resource owner's identifier.

	password (str):
		resource owner's Secret.

	scope (str, optional):
		The string value of the different scopes the application is asking for.
		Multiple scopes are separated with whitespace. The default value is
		cfg.Provider.Scopes.DEFAULT.

	realm (str, optional):
		The string value of the realm the user belongs to. Set this if you want
		to add realm support at this grant. By default, it uses the
		"Username-Password-Authentication" connection.

	audience (str, optional):
		The unique identifier of the target API you want to access. For
		authentication purpose, it's the Auth0 application's client_id.

	keep_signed_in (bool):
		Whether or not to fetch a refresh token for refreshing the access token
		next time.
	"""
	
	# check configuration
	cfg._bool()

	# if keep_signed_in is set add offline_access in scope
	if keep_signed_in:
		scope += cfg.Provider.Scopes.REFRESH_TOKEN
	
	body = {
		"grant_type": cfg.Provider.Grant.password,
		"client_id": cfg._AUTH0_CLIENT_ID,
		"client_secret": cfg._AUTH0_CLIENT_SECRET,
		"username": username,
		"password": password,
		"scope": scope,
		"realm": realm,
	}
	
	# optional parameters
	if audience:
		body["audience"] = audience
	
	signin_request = Request.post(cfg.Provider.URL.Auth.token, headers=PdefHeader.CONTENT_XWFU, body=body)
	response = _parse_response(signin_request, request=request)
	
	# if response isn't User, then it's an error
	if not isinstance(response, User):
		response = AuthEngineError(**response.__dict__)
		response.prepend_loc("AuthEngine.signin()")				# prepend the current location
	
	# if response is true (User) add session cookies in request
	if request and response:
		set_session(request, response)		# type: ignore
	
	return response

def signin_code(
		request: HttpRequest | None,
		code: str,
		redirect_uri: str
) -> User | AuthEngineError:
	"""Signs in a user using the authorization code grant received
	from various identity providers (IdPs), including social networks
	(Google, Facebook, Twitter, LinkedIn), enterprise systems (Microsoft
	Active Directory), and others.

	Upon parsing the response, it sets the auth session in the request and
	returns a User instance. Otherwise, an AuthEngineError instance with error
	information is returned; the request session is unchanged.

	request (HttpRequest):
		Django HttpRequest

	code (str):
		authorization code grant provided by IdP

	redirect_uri (str):
		the URL for which the code was intended.
	"""
	
	# check configuration
	cfg._bool()
	
	body = {
		"grant_type": cfg.Provider.Grant.authorization_code,
		"client_id": cfg._AUTH0_CLIENT_ID,
		"client_secret": cfg._AUTH0_CLIENT_SECRET,
		"code": code,
	}

	# optional parameters
	if redirect_uri:
		body["redirect_uri"] = redirect_uri

	code_request = Request.post(cfg.Provider.URL.Auth.token, headers=PdefHeader.CONTENT_XWFU, body=body)
	response = _parse_response(code_request, request=request)
	
	# if response isn't User, then it's an error
	if not isinstance(response, User):
		response = AuthEngineError(**response.__dict__)
		response.prepend_loc("AuthEngine.signin_code()")		# prepend the current location
	
	# if response is true add session cookies in request
	if request and response:
		set_session(request, response)		# type: ignore

	return response

def signup(
	request: HttpRequest | None,
	email: str,
	password: str,
	username: str | None = None,
	connection: str = cfg.Provider.USERNAME_PASSWORD_REALM,
	user_metadata: dict[str, Any] | None = None,
	given_name: str | None = None,
	family_name: str | None = None,
	name: str | None = None,
	nickname: str | None = None,
	picture: str | None = None,
	keep_signed_in: bool = False
) -> User | AuthEngineError:
	"""Registers a user with Auth0 application using email address, password,
	and additional information.
		
	Upon successful registration, it sets the auth session in the request
	and returns a User instance. Otherwise, an AuthEngineError instance with
	error information is returned.

	request (HttpRequest):
		Django HttpRequest.

	email (str):
		The user's email address.

	password (str):
		The user's desired password.

	username (str, optional):
		The user's username, if required by the database connection.

	connection (str, optional):
		The name of the database connection where this user should be created.
		By default, it uses the "Username-Password-Authentication" connection.

	user_metadata (dict, optional):
		Additional key-value information to store for the user. Some
		limitations apply, see:
		https://auth0.com/docs/metadata#metadata-restrictions

	given_name (str, optional):
		The user's given name(s).

	family_name (str, optional):
		The user's family name(s).

	name (str, optional):
		The user's full name.

	nickname (str, optional):
		The user's nickname.

	picture (str, optional):
		A URI pointing to the user's picture.

	keep_signed_in (bool):
		Whether or not to fetch a refresh token for refreshing the access token
		next time.
	"""
	
	# check configuration
	cfg._bool()

	body = {
		"client_id": cfg._AUTH0_CLIENT_ID,
		"email": email,
		"password": password,
		"connection": connection,
	}

	# optional parameters
	if username:
		body["username"] = username
	if given_name:
		body["given_name"] = given_name
	if family_name:
		body["family_name"] = family_name
	if name:
		body["name"] = name
	if nickname:
		body["nickname"] = nickname
	if picture:
		body["picture"] = picture
	if user_metadata:
		body["user_metadata"] = user_metadata # type: ignore
	
	signup_request = Request.post(cfg.Provider.URL.Auth.dbcon_signup, headers=PdefHeader.CONTENT_JSON, body=body)
	response = _parse_response(signup_request, request=request)

	if response:
		response = signin(
			request,
			email,
			password,
			realm=cfg.Provider.USERNAME_PASSWORD_REALM,		# signed up users are stored in username-password realm
			keep_signed_in=keep_signed_in
		)

	return response							# type: ignore

def change_password_email(
	email: str,
	connection: str = cfg.Provider.USERNAME_PASSWORD_REALM,
	organization:str | None = None
) -> AuthEngineResponse | AuthEngineError:
	"""Sends a password change email to the email address if a user with that
	email exists. 
	
	email (str):
		email address of the user.
	
	connection (str):
		The name of the database connection where the user was created. By
		default, it uses the "Username-Password-Authentication" connection.
	"""
	
	# check configuration
	cfg._bool()
	
	if not connection:
		connection = cfg.Provider.USERNAME_PASSWORD_REALM
	
	body = {
		"client_id": cfg._AUTH0_CLIENT_ID,
		"email": email,
		"connection": connection,
	}

	# optional parameters
	if organization:
		body["organization"] = organization

	change_request = Request.post(cfg.Provider.URL.Auth.dbcon_change_password, headers=PdefHeader.CONTENT_JSON, body=body)
	response = _parse_response(change_request, None)
	
	return response

def refresh_access_token(
		request:HttpRequest | None,
		refresh_token:str,
		scope: str = cfg.Provider.Scopes.DEFAULT
	) -> User | AuthEngineError:
	"""Refreshes an access token using the provided refresh_token.
	
	Upon refreshment returns a User instance; an AuthEngineError instance with
	error information is returned otherwise. It sets the _token_refreshed flag
	in the response which is used by other functions to decide whether or not
	to update the request session.

	refresh_token (str):
		the refresh token.

	scope (str):
		Used to limit the scopes of the new access token. Multiple scopes are
		separated with whitespace. The default value is
		cfg.Provider.Scopes.DEFAULT.
	"""
	
	# check configuration
	cfg._bool()
	
	body = {
		"grant_type": cfg.Provider.Grant.refresh_token,
		"client_id": cfg._AUTH0_CLIENT_ID,
		"client_secret": cfg._AUTH0_CLIENT_SECRET,
		"refresh_token": refresh_token,
		"scope": scope,
	}
	
	refresh_request = Request.post(cfg.Provider.URL.Auth.token, headers=PdefHeader.CONTENT_XWFU, body=body)
	response = _parse_response(refresh_request, request=request)
	
	# if response isn't User, then it's an error
	if not isinstance(response, User):
		response = AuthEngineError(**response.__dict__)
		response.prepend_loc("AuthEngine.refresh_access_token()")		# prepend the current location
	
	# if successfully refreshed token set _token_refreshed flag
	if response and response:
		set_session(request, response) 							# type: ignore
		response._token_refreshed = True
	
	return response

def authenticate(request: HttpRequest) -> User | AuthEngineError:
	"""Authenticates a HttpRequest instance.

	The authentication session data is retrieved from the request session and
	passed to _parse_response(). If _parse_response() refreshes the tokens, the
	session data is updated in HttpRequest. It returns the same instance as the
	_parse_response().
	
	request (HttpRequest):
		Django HttpRequest.
	"""
	
	# check configuration
	cfg._bool()
	
	auth_session = request.session.get(cfg._SESSION_KEY)
	response = _parse_response(auth_session, request=request)
	
	# if response isn't User, then it's an error
	if not isinstance(response, User):
		response = AuthEngineError(**response.__dict__)
		response.prepend_loc("AuthEngine.authenticate()")		# prepend the current location
	
	# if _token_refreshed flag is set update session
	if response and response._token_refreshed:
		set_session(request, response)			# type: ignore
		
	return response

def authenticate_header(request: HttpRequest) -> User | AuthEngineError:
	"""Functions similarly to authenticate(), except that the tokens are parsed
	from the request header instead of the request session. Returns the return
	value of _parse_response().

	request (HttpRequest):
		Django HttpRequest.
	"""
	
	# check configuration
	cfg._bool()
	
	authorization = request.headers.get("Authorization", "")
	splited_authorization = authorization.split()
	if len(splited_authorization) == 2 and splited_authorization[0].lower() == "bearer":
		token = splited_authorization[1]
		response = _parse_response({"access_token": token }, request=request)
	else:
		response = AuthEngineResponse(loc="AuthEngine.refresh_access_token")
		response.error = AuthEngineError(loc="AuthEngine.authenticate_header", error="invalid_request", description="missing access_token parameter")
	
	# if response isn't User, then it's an error
	if not isinstance(response, User):
		response = AuthEngineError(**response.__dict__)
		response.prepend_loc("AuthEngine.authenticate_header()")		# prepend the current location
		
	return response
