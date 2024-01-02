"""The AuthEngine: Support for user authentication using Auth0.

Most methods accept a HttpRequest instance as the first argument. This instance
is used to store authentication-related session data for subsequent requests.

The methods rely on a set of constants that are fetched from settings.py (see
apps.py).
"""

from . import cfg
from .user import User
from .exceptions import AuthEngineError
from .response import AuthEngineResponse
from .http import Request, Response, PdefHeader
from typing import Any
from django.http import HttpRequest
from functools import singledispatch
import jwt
from jwt import PyJWKClient
from pprint import pprint

def verify_id_token(token:str):
	"""Validates a token and returns the payload. If the token is invalid, an
	exception is raised.

	token (str)
		token to be validated.
	"""
	unverified_header = jwt.get_unverified_header(token)
	alg = unverified_header["alg"]
	jwks_client = PyJWKClient(cfg.Provider.jwks_url())
	signing_key = jwks_client.get_signing_key_from_jwt(token)
	
	try:
		claims = jwt.decode(
			token,
			signing_key.key,
			algorithms=[alg],
			issuer=cfg.Provider.issuer(),
			audience=cfg._AUTH0_AUDIENCE)
	except:
		raise

	return claims

@singledispatch
def parse_response(response:dict[str, Any], request:HttpRequest) -> AuthEngineResponse:
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

	return_response:AuthEngineResponse = AuthEngineError(
		loc="AuthEngine.parse_response"
	)

	if cfg._BOOL and response:
		if "id_token" in response:
			# parse payload from id_token
			try:
				id_token_payload = verify_id_token(response["id_token"])
				# instantiate an User with id_token_payload and data
				# received in response (i.e. access_token,
				# refresh_token, expires_in)
				return_response = User(**(id_token_payload | response))
				return_response._request = request
			# if invalid token try to refresh token
			except jwt.ExpiredSignatureError as err:
				if "refresh_token" in response:
					refreshed = refresh_access_token(
						request,
						response["refresh_token"],
						scope=response.get("scope", None)
					)
					return refreshed
			except Exception as err:
				print(err.__dict__)
				return_response = AuthEngineError(loc="AuthEngine.parse_response", **(err.__dict__), **response)
		# sign-up
		elif "_id" in response:
			return_response = AuthEngineResponse(loc="AuthEngine.parse_response", **response)
			return_response._bool = True
		# error
		elif "error" in response:
			return_response = AuthEngineError(loc="AuthEngine.parse_response", **response)
		else:
			return_response = AuthEngineResponse(**response)
	return return_response

@parse_response.register
def _(response:Response, request:HttpRequest) -> AuthEngineResponse:
	"""A dispatch of parse_response that takes .http.Response as the response.
	"""
	return_response:AuthEngineResponse = AuthEngineError(loc="AuthEngine.parse_response")
	if response:
		if response.is_json:
			return_response = parse_response(response.json, request)
		elif response.length < 512:		# content of small length are treated as message
			return_response = AuthEngineResponse(message=response.content)
			return_response._bool = True
		else:
			return_response = AuthEngineResponse(large_text = response.content, loc = "AuthEngine.parse_response")
			return_response._bool = True
	else:
		return_response = AuthEngineError(loc = "AuthEngine.parse_response", **response.json)
	
	return return_response

def to_session(user: User) -> dict[str, Any]:
	"""Returns a dictionary containing authentication session data constructed
	from User instance.

	response (User):
		User object to acquire data from.
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
	
def set_session(request: HttpRequest, user: AuthEngineResponse) -> None:
	"""Sets authentication session data in the HttpRequest instance. The data
	is received from to_session(). The modification in the HttpRequest
	instance's session applies only if the new session data differs from the
	current session data.

	request (HttpRequest):
		The HttpRequest instance to set the session cookie to.

	user (AuthEngineResponse):
		User object to acquire the data from.
	"""
	if user and isinstance(user, User):
		existing_auth = request.session.get(cfg._SESSION_KEY)
		new_auth = to_session(user)
		# session is updated only if auth is updated to prevent unnecessary database access
		if existing_auth != new_auth:
			request.session[cfg._SESSION_KEY] = new_auth
			request.session.modified = True

def signin(
	request: HttpRequest | None,
	username: str,
	password: str,
	scope: str | None = None,
	realm: str | None = None,
	audience: str | None = None,
	keep_signed_in: bool = False
) -> AuthEngineResponse | User | None:
	"""Signs in a user with username, password.

	Upon authentication, it sets the auth session in the request and
	returns a User object. Otherwise, an AuthEngineError object with
	error information is returned; the request session is unchanged.

	request (HttpRequest):
		Django HttpRequest.

	username (str):
		Resource owner's identifier.

	password (str):
		resource owner's Secret.

	scope(str, optional):
		String value of the different scopes the client is asking for. Multiple
		scopes are separated with whitespace.

	realm (str, optional):
		String value of the realm the user belongs. Set this if you want to add
		realm support at this grant.By default it uses the
		"Username-Password-Authentication" connection.

	audience (str, optional):
		The unique identifier of the target API you want to access. For
		authentication purpose, it's the Auth0 application's client_id.

	keep_signed_in (bool):
		Whether or not to fetch refresh token for refreshing access token next
		time.
	"""
	if not cfg._BOOL():
		return
		
	scope = scope if scope else cfg.Provider.Scopes.DEFAULT
	realm = realm if realm else cfg.Provider.USERNAME_PASSWORD_REALM

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

	try:
		signin_request = Request.post(cfg.Provider.URL.Auth.token(), headers=PdefHeader.CONTENT_XWFU, body=body)
		response = parse_response(signin_request, request=request)
	except Exception as err:
		response = AuthEngineError(loc="AuthEngine.signin", **(err.__dict__))
		
	# if response is true add session cookies in request
	if request and response:
		set_session(request, response)
	
	return response

def signin_code(
		request: HttpRequest | None,
		code: str,
		redirect_uri: str
) -> AuthEngineResponse | User | None:
	"""Signs in a user using the authorization code grant received
	from various identity providers (IdPs), including social networks
	(Google, Facebook, Twitter, LinkedIn), enterprise systems (Microsoft
	Active Directory), and others.

	Upon parsing the response, it sets the auth session in the request and
	returns a User object. Otherwise, an AuthEngineError object with error
	information is returned; the request session is unchanged.

	request (HttpRequest):
		Django HttpRequest

	code (str):
		authorization code grant provided by IdP

	redirect_uri (str):
		the url for which the code was intended for.
	"""
	if not cfg._BOOL():
		return
	
	body = {
		"grant_type": cfg.Provider.Grant.authorization_code,
		"client_id": cfg._AUTH0_CLIENT_ID,
		"client_secret": cfg._AUTH0_CLIENT_SECRET,
		"code": code,
	}

	# optional parameters
	if redirect_uri:
		body["redirect_uri"] = redirect_uri

	try:
		code_request = Request.post(cfg.Provider.URL.Auth.token(), headers=PdefHeader.CONTENT_XWFU, body=body)
		response = parse_response(code_request, request=request)
	except Exception as err:
		response = AuthEngineError(loc="AuthEngine.signin_code", **(err.__dict__))

	if request and response:
		set_session(request, response)

	return response

def signup(
	request: HttpRequest | None,
	email: str,
	password: str,
	username: str | None = None,
	connection: str | None = None,
	user_metadata: dict[str, Any] | None = None,
	given_name: str | None = None,
	family_name: str | None = None,
	name: str | None = None,
	nickname: str | None = None,
	picture: str | None = None,
	keep_signed_in: bool = False
) -> AuthEngineResponse | User | None:
	"""Registers a user with Auth0 application using email address, password,
	and additional informations.
		
	Upon successful registeration up, it sets the auth session in the request
	and returns a User object. Otherwise, an AuthEngineError object with error
	information is returned.

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
		By default it uses the "Username-Password-Authentication" connection.

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
		Whether or not to fetch refresh token for refreshing access token next
		time.
	"""
	if not cfg._BOOL():
		return
	
	if not connection:
		connection = cfg.Provider.USERNAME_PASSWORD_REALM

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

	try:
		signup_request = Request.post(cfg.Provider.URL.Auth.dbcon_signup(), headers=PdefHeader.CONTENT_JSON, body=body)
		response = parse_response(signup_request, request=request)
	except Exception as err:
		response = AuthEngineError(loc="AuthEngine.signup", **(err.__dict__))

	if response:
		response = signin(
			request,
			email,
			password,
			realm=cfg.Provider.USERNAME_PASSWORD_REALM,				# signed up users are stored in username-password realm
			keep_signed_in=keep_signed_in
		)

	return response

def change_password(email: str, connection: str, organization:str | None = None) -> AuthEngineResponse | None:
	"""Sends a password change email to the email address if a user with that
	email exists. 

	email (str):
		email address of the user.

	connection (str):
		The name of the database connection where the user was created. By
		default it uses the "Username-Password-Authentication" connection.
	"""
	if not cfg._BOOL():
		return

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

	try:
		change_request = Request.post(cfg.Provider.URL.Auth.dbcon_change_password(), headers=PdefHeader.CONTENT_JSON, body=body)
		response = parse_response(change_request, None)
	except Exception as err:
		response = AuthEngineError(loc="AuthEngine.change_password", **(err.__dict__))
		
	return response

def refresh_access_token(
		request:HttpRequest | None,
		refresh_token:str,
		scope: str | None = None
	) -> AuthEngineResponse:
	"""Refreshes an access token using the provided refresh_token.
	 
	Upon refreshment returns a User object; an AuthEngineError object with
	error information is returned otherwise. It sets the _token_refreshed flag
	in the response which is used by other functions to decide whether or not
	to update the request session.

	refresh_token (str):
		the refresh token.

	scope (str):
		Used to limit the scopes of the new access token. Multiple scopes are
		separated with whitespace.
	"""
	if not cfg._BOOL():
		return # type: ignore
	
	scope = scope if scope else cfg.Provider.Scopes.DEFAULT

	body = {
		"grant_type": cfg.Provider.Grant.refresh_token,
		"client_id": cfg._AUTH0_CLIENT_ID,
		"client_secret": cfg._AUTH0_CLIENT_SECRET,
		"refresh_token": refresh_token,
		"scope": scope,
	}

	try:
		refresh_request = Request.post(cfg.Provider.URL.Auth.token(), headers=PdefHeader.CONTENT_XWFU, body=body)
		response = parse_response(refresh_request, request=request)
		# if successfully refreshed token set _token_refreshed flag
		if response and response:
			set_session(request, response) 							# type: ignore
			response._token_refreshed = True
			
	except Exception as err:
		response = AuthEngineError(loc="AuthEngine.refresh_access_token", **(err.__dict__))
	return response

def authenticate(request: HttpRequest) -> AuthEngineResponse | None:
	"""Authenticates a HttpRequest instance.

	The authentication session data is retrieved from the request session and
	passed to parse_response(). If parse_response() refreshes the tokens, the
	session data is updated in HttpRequest. It returns the same instance as the
	parse_response().
	
	request (HttpRequest):
		Django HttpRequest.
	"""
	if not cfg._BOOL():
		return
	auth_session:dict = request.session.get(cfg._SESSION_KEY) # type: ignore
	response = parse_response(auth_session, request=request)
	# if _token_refreshed flag is set update session
	if response and response._token_refreshed:
		set_session(request, response)
	return response

def authenticate_header(request: HttpRequest) -> AuthEngineResponse | None:
	"""Functions similarly to authenticate(), except that the tokens are parsed
	from the request header instead of the request session. Returns the return
	value of parse_response().

	request (HttpRequest):
		Django HttpRequest.
	"""
	if not cfg._BOOL():
		return
	authorization = request.headers.get("Authorization", "")
	splited_authorization = authorization.split()
	if len(splited_authorization) == 2 and splited_authorization[0].lower() == "bearer":
		token = splited_authorization[1]
		response = parse_response({"access_token": token }, request=request)
	else:
		response = AuthEngineError(loc="AuthEngine.authenticate_header", error="invalid_request", description="missing access_token parameter")
	return response

def get_user(request:HttpRequest | None, access_token: str | None) -> AuthEngineResponse | User | None:
	"""Exchanges an access_token for a User object. Returns User if successful;
	AuthEngineError otherwise.

	request (HttpRequest):
		Django HttpRequest.
		
	access_token (str):
		access_token.
	"""
	if not cfg._BOOL():
		return
	response = None

	headers = {
		"Authorization": f"Bearer {access_token}"
	}

	if access_token:
		try:
			userinfo_request = Request.get(cfg.Provider.URL.Auth.userinfo(), headers=headers)
			json = userinfo_request.json
			if json and "sub" in json:
				response = User(**json)
				response._request = request
		except Exception as err:
			response = AuthEngineError(loc="AuthEngine.get_user", **(err.__dict__))
	return response
