from . import cfg
from .user import User
from .exceptions import AuthEngineError
from .response import AuthEngineResponse
import json
from typing import overload, Any
from django.utils.functional import cached_property
from django.http import HttpRequest
from auth0 import authentication
from auth0.authentication.token_verifier import AsymmetricSignatureVerifier
from auth0.authentication.token_verifier import SymmetricSignatureVerifier
from auth0.authentication.token_verifier import TokenVerifier
from auth0.authentication.token_verifier import TokenValidationError

class AuthVerifierEngine(TokenVerifier):
	def __init__(self, issuer, jwks_url, audience, algorithms:list = ["RS256"]):
		if "RS256" in algorithms:
			signature_verifier = AsymmetricSignatureVerifier(jwks_url=jwks_url, algorithm="RS256")
			super().__init__(
				signature_verifier=signature_verifier,
				issuer=issuer,
				audience=audience,
			)
		elif "HS256" in algorithms:
			signature_verifier = SymmetricSignatureVerifier(shared_secret=audience, algorithm="HS256")
			super().__init__(
				signature_verifier=signature_verifier,
				issuer=issuer,
				audience=audience,
			)

class AuthEngine:
	"""AuthEngine class facilitate with user authentication using Auth0 Python
	SDK. It interacts with Auth0 endpoints to perform user authentication and
	is compatible with various Django built-in modules and objects, including
	the HttpRequest object. Most methods accept an optional HttpRequest object.
	Successful authentication updates or creates session cookies in the
	HttpRequest for future requests.

	AuthEngine relies on several key pieces of information from the Django
	project's settings to function: the Auth0 application's client ID and
	client secret, the tenant domain, and the API audience. If any of these
	required pieces of information are missing, an error will be raised.
	"""

	# String representing the name of the backend.
	BACKEND_NAME			: str	= "django_auth0_engine.engine.AuthEngine"

	# String representing the Username-Password-Authentication realm of auth0.
	USERNAME_PASSWORD_REALM	: str	= "Username-Password-Authentication"

	class Scopes:
		"""OpenID Connect Scopes.
		"""

		REFRESH_TOKEN		: str	=	" offline_access "		# Scope for refresh token.
		OPENID				: str	=	" openid "				# Scope for OpenID Information.
		PROFILE				: str	=	" profile "				# Scope for Profile Information.
		EMAIL				: str	=	" email "				# Scope for Email address.

		# Scope used as default if no scopes are provided.
		DEFAULT				: str	=	OPENID + PROFILE + EMAIL

	def __bool__(self):
		"""Determines if the instance is usable based on the availability of
		required information.
		"""
		if cfg._AUTH0_CLIENT_ID and cfg._AUTH0_CLIENT_SECRET and cfg._AUTH0_DOMAIN and cfg._AUTH0_AUDIENCE:
			return True
		
		raise AuthEngineError(
			"AuthEngine Not Configured Correctly",
			"""Either of client_id, client_secret or domain is missing."""
		)
		
	@cached_property
	def issuer(self) -> str | None:
		"""Returns the issuer URL or None if the instance is unusable.
		"""
		if self:
			return f"https://{cfg._AUTH0_DOMAIN}/"
		return None
	
	@cached_property
	def jwks_url(self) -> str | None:
		"""Returns the JWKS URL or None if the instance is unusable.
		"""
		if self:
			return f"{self.issuer}.well-known/jwks.json"
		return None

	@cached_property
	def token_endpoint(self) -> authentication.GetToken:
		"""Returns an instance of auth0.authentication.GetToken.
		"""
		return authentication.GetToken(
			domain			=	cfg._AUTH0_DOMAIN,
			client_id		=	cfg._AUTH0_CLIENT_ID,
			client_secret	=	cfg._AUTH0_CLIENT_SECRET,
		)

	@cached_property
	def database_endpoint(self) -> authentication.Database:
		"""Returns an instance of auth0.authentication.Database.
		"""
		return authentication.Database(
			domain			=	cfg._AUTH0_DOMAIN,
			client_id		=	cfg._AUTH0_CLIENT_ID,
			client_secret	=	cfg._AUTH0_CLIENT_SECRET,
		)

	@cached_property
	def passwordless_endpoint(self) -> authentication.Passwordless:
		"""Returns an instance of auth0.authentication.Passwordless.
		"""
		return authentication.Passwordless(
			domain			=	cfg._AUTH0_DOMAIN,
			client_id		=	cfg._AUTH0_CLIENT_ID,
			client_secret	=	cfg._AUTH0_CLIENT_SECRET,
		)

	@cached_property
	def user_endpoint(self) -> authentication.Users:
		"""Returns an instance of auth0.authentication.Users.
		"""
		return authentication.Users(
			domain			=	cfg._AUTH0_DOMAIN,
		)

	@cached_property
	def verifier(self) -> AuthVerifierEngine:
		"""Returns an instance of AuthVerifierEngine initialized with issuer,
		jwks_url, and audience.
		"""
		return AuthVerifierEngine(self.issuer, self.jwks_url, cfg._AUTH0_AUDIENCE)

	@overload
	def parse_response(self, response: str) -> AuthEngineResponse:
		return_response:AuthEngineResponse = AuthEngineError(error="Unknown error at AuthEngine.parse_response")
		try:
			response_dict = json.loads(response)
			return_response = self.parse_response(response_dict)
		except json.JSONDecodeError:
			if response.find("error") > 0:
				return_response = AuthEngineError(response)
			else:
				self._bool = True
				self.message = response
				return_response = AuthEngineResponse(message = response)
		return return_response

	@overload
	def parse_response(self, response: dict[str, Any]) -> AuthEngineResponse:...

	@overload
	def parse_response(self, response:Any) -> AuthEngineResponse:
		if isinstance(response, dict):
			return self.parse_response(response)
		else:
			return AuthEngineError(**response)

	def parse_response(self, response = None) -> AuthEngineResponse:
		"""
		Parse response received from different auth0 endpoints and return
		different types of AuthEngineResponse instances including User and
		AuthEngineError. It also parse auth data stored in request's session
		cookies.

		Args:
			response (dict): response received from different auth0 endpoints

		Return:
			Instance of any Subclasses of AuthEngineResponse or instance of
			AuthEngineResponse itself.

		If an id_token is present in response, it validates that using
		AuthVerifierEngine.verify. If the token is valid, an User instance is
		constructed from the informations of the id_token and returned. If the
		token is expired and a refresh_token exists in response, it refreshes
		the token by calling AuthEngine.refresh_token and return the response
		received from it. In case, the token is invalid and AuthEngineError is
		returned.
		"""
		return_response:AuthEngineResponse = AuthEngineError(error="Unknown error at AuthEngine.parse_response")
		if self and response:
			if "id_token" in response:
				# parse payload from id_token
				try:
					id_token_payload = self.verifier.verify(response["id_token"])
					# instantiate an User with id_token_payload and data
					# received in response (i.e. access_token,
					# refresh_token, expires_in)
					return User(**(id_token_payload | response))
				# if invalid token try to refresh token
				except TokenValidationError as err:
					if "refresh_token" in response:
						refreshed = self.refresh_access_token(
							response["refresh_token"],
							scope=response.get("scope", None)
						)
						return refreshed
				except Exception as err:
					print(err.__dict__)
					return_response = AuthEngineError(**(err.__dict__), **response)
			elif "_id" in response:
				return_response = AuthEngineResponse(**response)
				return_response._bool = True
			elif "error" in response:
				return_response = AuthEngineError(**response)
			else:
				return_response = AuthEngineResponse(**response)
		return return_response

	def to_session(self, response: AuthEngineResponse) -> dict[str, Any]:
		"""Converts a parsed response to a dictionary containing information
		including access_token, refresh_token, id_token, token_type, and
		expires_in for session storage.

		The dict is stored in auth session, which is parsed by
		AuthEngine.parse_response for authenticating subsequent requests.

		Args:
			response (AuthEngineResponse): response received from
			AuthEngine.parse_response or session cookie

		Return:
			dict
		"""
		
		if response:
			data = {
				"access_token":			response.__dict__.get("access_token", None),
				"refresh_token":		response.__dict__.get("refresh_token", None),
				"id_token":				response.__dict__.get("id_token", None),
				"token_type":			response.__dict__.get("token_type", None),
				"expires_in":			response.__dict__.get("expires_in", None)
			}
			return data
		return {}
	
	def set_session(self, request: HttpRequest, response: AuthEngineResponse) -> None:
		"""Sets the authorization session in the HttpRequest object from dict
		returned by AuthEngine.to_session. The session is modified only if
		it's not the same as the existing session in the request.

		Args:
			request (HttpRequest): Django HttpRequest
		"""
		if response:
			existing_auth = request.session.get(cfg._SESSION_KEY)
			new_auth = self.to_session(response)
			# session is updated only if auth is updated to prevent unnecessary database access
			if existing_auth != new_auth:
				request.session[cfg._SESSION_KEY] = new_auth
				request.session.modified = True

	def signin(
		self,
		request: HttpRequest | None,
		username: str,
		password: str,
		scope: str | None = None,
		realm: str | None = None,
		audience: str | None = None,
		grant_type: str = "http://auth0.com/oauth/grant-type/password-realm",
		forwarded_for: str | None = None,
		keep_signed_in: bool = False
	) -> AuthEngineResponse | User | None:
		"""Signs in a user with username, password, belonging to realm. grant_type
		denotes the flow being used. Default is
		http://auth0.com/oauth/grant-type/password-realm (from auth0 sdk).
		forwarded_for is the End-user IP as a string value. It is used for
		brute-force protection to work in server-side scenarios. keep_signed_in
		defines whether or not to fetch a refresh token.

		Upon authentication, it sets session in the request object and return a
		User instance. Otherwise, an AuthEngineError instance with error
		information is returned, request session is unchanged.

		Args:
			request (HttpRequest): Django HttpRequest

			username (str): Resource owner's identifier

			password (str): resource owner's Secret

			scope(str, optional): String value of the different scopes the client is asking for.
				Multiple scopes are separated with whitespace.

			realm (str, optional): String value of the realm the user belongs.
				Set this if you want to add realm support at this grant.

			audience (str, optional): The unique identifier of the target API you want to access.

			grant_type (str, optional): Denotes the flow you're using. For password realm
				use http://auth0.com/oauth/grant-type/password-realm

			forwarded_for (str, optional): End-user IP as a string value. Set this if you want
				brute-force protection to work in server-side scenarios.
				See https://auth0.com/docs/get-started/authentication-and-authorization-flow/avoid-common-issues-with-resource-owner-password-flow-and-attack-protection

			keep_signed_in (bool): Wheather or not to fetch refresh token for refereshing access token next time.

		Returns:
			User or AuthEngineError
		"""
		if not self:
			return
		
		if not scope:
			scope = self.Scopes.DEFAULT

		# if keep_signed_in is set add offline_access in scope
		if keep_signed_in:
			scope += self.Scopes.REFRESH_TOKEN

		try:
			login_request = self.token_endpoint.login(
				username=username,
				password=password,
				scope=scope,
				realm=realm,
				audience=audience,
				grant_type=grant_type,
				forwarded_for=forwarded_for
			)
			response = self.parse_response(login_request)
		except Exception as err:
			response = AuthEngineError(**(err.__dict__))
		
		# if response is true add session cookies in request
		if request and response:
			self.set_session(request, response)
		
		return response

	def signin_code(
			self,
			request: HttpRequest | None,
			code: str,
			redirect_uri: str
	) -> AuthEngineResponse | User | None:
		"""Signs in a user using the authorization code grant received from the
		identity providers such as Google, Facebook, X, and Microsoft.

		Upon parsing the response, it sets session in request and return a User
		instance. Otherwise, an AuthEngineError instance with error
		information is returned, request session is unchanged.

		Args:
			request (HttpRequest): Django HttpRequest

			refresh_token (str): The refresh token returned from the initial token request.

			scope (str): Use this to limit the scopes of the new access token.
			Multiple scopes are separated with whitespace.

			grant_type (str): Denotes the flow you're using. For refresh token
				use refresh_token

		Returns:
			User or AuthEngineError
		"""
		if not self:
			return
		
		try:
			code_request = self.token_endpoint.authorization_code(code, redirect_uri)
			response = self.parse_response(code_request)
		except Exception as err:
			response = AuthEngineError(**(err.__dict__))

		if request and response:
			self.set_session(request, response)

		return response

	def signup(
		self,
		request: HttpRequest | None,
		email: str,
		password: str,
		connection: str | None = None,
		username: str | None = None,
		user_metadata: dict[str, Any] | None = None,
		given_name: str | None = None,
		family_name: str | None = None,
		name: str | None = None,
		nickname: str | None = None,
		picture: str | None = None,
		signin: bool = False,
		keep_signed_in: bool = False
	) -> AuthEngineResponse | User | None:
		"""Sign up a user using email, password, and other provided information.
		picture is a URL representing the profile picture. If signin is set, a
		a session cookie is set in the request. keep_signed_in defines whether
		or not to fetch a refresh token and is only used if signin is set.

		If the user is successfully signed up, session is set in request and
		return a User instance. Otherwise, an AuthEngineError instance with
		error information is returned, request session is unchanged.

		Args:
			request (HttpRequest): Django HttpRequest

			email (str): The user's email address.

			password (str): The user's desired password.

			connection (str): The name of the database connection where this user should be created.
				By default it uses the "Username-Password-Authentication" connection.

			username (str, optional): The user's username, if required by the database connection.

			user_metadata (dict, optional): Additional key-value information to store for the user.
				Some limitations apply, see: https://auth0.com/docs/metadata#metadata-restrictions

			given_name (str, optional): The user's given name(s).

			family_name (str, optional): The user's family name(s).

			name (str, optional): The user's full name.

			nickname (str, optional): The user's nickname.

			picture (str, optional): A URI pointing to the user's picture.

			signin (bool, optional): Wheather to keep the user signed in or not.

			keep_signed_in (bool): Wheather or not to fetch refresh token for refereshing access token next time.
				Has no effect if signin is not set.

		Returns:
			User or AuthEngineError
		"""
		if not self:
			return
		
		if not connection:
			connection = self.USERNAME_PASSWORD_REALM

		try:
			signup_request = self.database_endpoint.signup(
				email=email,
				password=password,
				connection=connection,
				username=username,
				user_metadata=user_metadata,
				given_name=given_name,
				family_name=family_name,
				name=name,
				nickname=nickname,
				picture=picture,
			)
			response = self.parse_response(signup_request)
		except Exception as err:
			response = AuthEngineError(**(err.__dict__))

		# if signin is set add session cookies in request

		if response and signin:
			response = self.signin(
				request,
				email,
				password,
				realm=self.USERNAME_PASSWORD_REALM,
				keep_signed_in=keep_signed_in
			)

		return response

	def change_password(self, email: str, connection: str) -> AuthEngineResponse | None:
		"""Sends a password change email to the email address if a user with that
		email exists. An AuthEngineResponse instance is returned with an
		appropriate message.

		Args:
			email (str): The user's email address.

			connection (str): The name of the database connection where this user should be created.

		Returns:
			AuthEngineResponse
		"""
		if not self:
			return

		if not connection:
			connection = self.USERNAME_PASSWORD_REALM

		try:
			change_request = self.database_endpoint.change_password(
				email=email,
				connection=connection
			)
			response = self.parse_response(change_request)
		except Exception as err:
			response = AuthEngineError(**(err.__dict__))
		
		return response

	def refresh_access_token(self, refresh_token:str, scope: str | None = None) -> AuthEngineResponse:
		"""Refreshes an access token using the refresh_token. Upon success, return
		a User instance; an AuthEngineError instance with error information is
		returned otherwise. It sets the token_refreshed flag in the response
		which is used by other function to decide wheather or not to update
		session.

		Args:
			request (HttpRequest): Django HttpRequest

			refresh_token (str): The refresh token returned from the initial token request.

			scope (str): Use this to limit the scopes of the new access token.
			Multiple scopes are separated with whitespace.

		Returns:
			User or AuthEngineError
		"""
		if not self:
			return # type: ignore
		
		scope = scope or self.Scopes.DEFAULT
		try:
			refresh_request	= self.token_endpoint.refresh_token(
				refresh_token=refresh_token,
				scope=scope
			)
			response = self.parse_response(refresh_request)
			# if successfully refreshed token set token_refreshed flag
			if response:
				response.token_refreshed = True
		except Exception as err:
			response = AuthEngineError(**(err.__dict__))
			
		return response

	def authenticate(self, request: HttpRequest) -> AuthEngineResponse | None:
		"""Authenticates a request using the id_token. The id_token is
		acquire from the session cookie. Returns User on successful
		authorization; AuthEngineError otherwise. If token is refreshed,
		updates session cookie.

		Args:
			request (HttpRequest): Django HttpRequest

		Returns:
			User or AuthEngineError
		"""
		if not self:
			return
		
		auth_session = request.session.get(cfg._SESSION_KEY)
		response = self.parse_response(auth_session)
		# if token_refreshed flag is set update session
		if response and response.token_refreshed:
			self.set_session(request, response)
		
		return response

	def authenticate_header(self, request: HttpRequest) -> AuthEngineResponse | None:
		"""Functions similarly to AuthEngine.authenticate, except that the
		access_token is parsed from the request header instead of the session
		cookie. Returns User on successful authorization; AuthEngineError
		otherwise.

		Args:
			request (HttpRequest): Django HttpRequest

		Returns:
			User or AuthEngineError
		"""
		if not self:
			return

		authorization = request.headers.get("Authorization", "")
		splited_authorization = authorization.split()

		if len(splited_authorization) == 2 and splited_authorization[0].lower() == "bearer":
			token = splited_authorization[1]
			response = self.parse_response({"access_token": token })
		else:
			response = AuthEngineError(error="invalid_request", description="missing access_token parameter")

		return response

	def get_user(self, access_token: str | None) -> AuthEngineResponse | User | None:
		"""Exchanges the access_token for a User instance. Returns User if
		successful; AuthEngineError otherwise.

		Args:
			access_token (str, None): access_token received during authorization

		Returns:
			User instance
		"""
		if not self:
			return
		
		response = None
		if access_token:
			try:
				userinfo_request = self.user_endpoint.userinfo(access_token=access_token)
				if "sub" in userinfo_request:
					response = User(**userinfo_request)
			except Exception as err:
				response = AuthEngineError(**(err.__dict__))
		return response

