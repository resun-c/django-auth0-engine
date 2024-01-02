from typing import Any
from .exceptions import AuthEngineError
"""A module to share information among other modules.
"""

# String representing the name of the backend.
BACKEND_NAME			: str	= "django_auth0_engine.engine.AuthEngine"


# Upon fetching the Auth0 application's client ID and client secret, tenant
# domain, and API audience from settings, the acquired values are stored in
# these variables. Other modules, including the auth_engine and
# management_engine, rely on these variables to perform operations.
_AUTH0_CLIENT_ID		:str	=	None # type: ignore
_AUTH0_CLIENT_SECRET	:str	=	None # type: ignore
_AUTH0_DOMAIN			:str	=	None # type: ignore
_AUTH0_AUDIENCE			:str	=	None # type: ignore
_DEFAULT_SCOPES			:str	=	None # type: ignore
_MANAGEMENT_AUDIENCE	:str	= 	None # type: ignore

# Database Backend class name for User.db
_USER_DB_BACKEND		:Any	=   None

# This is used as the key to access authentication session.
_SESSION_KEY			:str	=	"_auth"

# Tells whether of the the engine is properly configured. Must be set in apps.py

_m_access_token			:str	= ""
_m_access_token_exp		:int	= 0
_m_access_token_type	:str	= ""

def _BOOL():
	if _AUTH0_CLIENT_ID and _AUTH0_CLIENT_SECRET and _AUTH0_DOMAIN:
		return True
	raise AuthEngineError(
		loc="cfg", 
		error="AuthEngine Not Configured Correctly",
	)
	
class Provider:
	# String representing the Username-Password-Authentication realm of auth0.
	USERNAME_PASSWORD_REALM	: str	= "Username-Password-Authentication"
	@staticmethod
	def issuer() -> str | None:
		"""Returns the issuer URL or None if the instance is unusable.
		"""
		if _BOOL():
			return f"https://{_AUTH0_DOMAIN}/"
		raise

	@staticmethod
	def jwks_url() -> str:
		"""Returns the JWKS URL or None if the instance is unusable.
		"""
		if _BOOL():
			return f"{Provider.issuer()}.well-known/jwks.json"
		raise

	class Scopes:
		"""OpenID Connect Scopes.
		"""
		REFRESH_TOKEN		: str	=	" offline_access "		# Scope for refresh token.
		OPENID				: str	=	" openid "				# Scope for OpenID Information.
		PROFILE				: str	=	" profile "				# Scope for Profile Information.
		EMAIL				: str	=	" email "				# Scope for Email address.
		# Scope used as default if no scopes are provided.
		DEFAULT				: str	=	OPENID + PROFILE + EMAIL

	class URL:
		class Auth:
			@staticmethod
			def token() -> str:
				return f"https://{_AUTH0_DOMAIN}/oauth/token"
			@staticmethod
			def dbcon_signup() -> str:
				return f"https://{_AUTH0_DOMAIN}/dbconnections/signup"
			@staticmethod
			def dbcon_change_password() -> str:
				return f"https://{_AUTH0_DOMAIN}/dbconnections/change_password"
			@staticmethod
			def userinfo() -> str:
				return f"https://{_AUTH0_DOMAIN}/userinfo"
			
		class Management:
			@staticmethod
			def user(id) -> str:
				return f"https://{_AUTH0_DOMAIN}/api/v2/users/{id}"
		
	class Grant:
		authorization_code = "authorization_code"
		password = "password"
		password_realm = "http://auth0.com/oauth/grant-type/password-realm"
		client_credentials = "client_credentials"
		refresh_token = "refresh_token"
