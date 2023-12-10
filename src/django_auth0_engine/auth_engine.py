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
	"""A wrapper of auth0.authentication.token_verifier.TokenVerifier. The
	auth0.authentication.token_verifier.TokenVerifier.verify function is used
	to validate id tokens.
	"""
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
		"""This method parses response data received from various Auth0 endpoints
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

		Args:
			response (str | dict): typically response from Auth0 endpoints or
				auth session data from request. If string is passed, it is
				first parsed as json.

		Returns:
			AuthEngineResponse or User or AuthEngineError
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
		"""This method constructs a dictionary containing essential authentication
		information (access_token, refresh_token, id_token, token_type, and
		expires_in) from a User object. This dictionary is stored in the
		request session cookie, which is later used by
		AuthEngine.parse_response() to facilitate authentication for subsequent
		requests.

		Args:
			response (User): User object to acquire data from.

		Returns:
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
		"""This method sets/updates the authentication session data stored in the
		HttpRequest object with the dict returned by AuthEngine.to_session().
		This modification only applies if the provided dictionary differs from
		the current session data associated with the request.

		Args:
			request (HttpRequest): The HttpRequest whose session cookie is
				set/updated.

			response (User): User object to acquire data from.
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
		"""Signs in a user with username, password.

		Upon authentication, it sets the auth session in the request and
		returns a User object. Otherwise, an AuthEngineError object with
		error information is returned; the request session is unchanged.

		Args:
			request (HttpRequest): Django HttpRequest

			username (str): Resource owner's identifier

			password (str): resource owner's Secret

			scope(str, optional): String value of the different scopes the
				client is asking for. Multiple scopes are separated with
				whitespace.

			realm (str, optional): String value of the realm the user belongs.
				Set this if you want to add realm support at this grant.By
				default it uses the
				"Username-Password-Authentication" connection.

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
		
		Returns:
			User or AuthEngineError
		"""
		if not self:
			return
		
		if not scope:
			scope = self.Scopes.DEFAULT

		if not realm:
			realm = self.USERNAME_PASSWORD_REALM

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
		"""This method signs in a user using the authorization code grant received
		from various identity providers (IdPs), including social networks
		(Google, Facebook, Twitter, LinkedIn), enterprise systems (Microsoft
		Active Directory), and others.

		Upon parsing the response, it sets the auth session in the request and
		returns a User object. Otherwise, an AuthEngineError object with error
		information is returned; the request session is unchanged.

		Args:
			request (HttpRequest): Django HttpRequest

			code (str): authorization code grant provided by IdP

			redirect_uri (str): the url for which the code was intended for.
		
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
		keep_signed_in: bool = False
	) -> AuthEngineResponse | User | None:
		"""This method allows to register a user with Auth0 application using
		email address, password, and any additional information.
		
		Upon successful sign up, it sets the auth session in the request and
		returns a User object. Otherwise, an AuthEngineError object with error
		information is returned; the request session is unchanged. A
		verification mail is also sent to the email address.

		Args:
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

		if response:
			response = self.signin(
				request,
				email,
				password,
				realm=self.USERNAME_PASSWORD_REALM,
				keep_signed_in=keep_signed_in
			)

		return response

	def change_password(self, email: str, connection: str) -> AuthEngineResponse | None:
		"""This method sends a password change email to the email address if a
		user with that email exists. 

		Args:
			email (str): email address of the user.

			connection (str): The name of the database connection where the
				user was created. By default it uses the
				"Username-Password-Authentication" connection.

		Returns:
			AuthEngineResponse object with an appropriate message.
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
		"""This method refreshes an access token using the refresh_token. Upon
		success, return a User object; an AuthEngineError object with error
		information is returned otherwise. It sets the token_refreshed flag in
		the response which is used by other functions to decide whether or not
		to update the request session.

		Args:
			refresh_token (str): the refresh token.

			scope (str): Used to limit the scopes of the new access token.
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
		"""This method authenticates a request using the id_token. The id_token is
		retrieved from the request session. Upon successful authentication, it
		returns a User object; AuthEngineError otherwise. If the token is
		expired and a refresh token exists in the request session, this method
		fetches a new ID token and access token and updates the session cookie
		automatically.

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
		"""This method functions similarly to the AuthEngine.authenticate()
		method, except that the access_token is parsed from the request header
		instead of the request session. Returns User object upon successful
		authentication; AuthEngineError otherwise.

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
		"""This method exchanges an access_token for a User object. Returns User
		if successful; AuthEngineError otherwise.

		Args:
			access_token (str): access_token

		Returns:
			User or AuthEngineError
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

