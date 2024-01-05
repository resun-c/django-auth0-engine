"""A module to share information among other modules.
"""
from typing import Any
from .exceptions import AuthEngineError

# String representation of the name of the backend.
BACKEND_NAME			: str	= "django_auth0_engine.engine.AuthEngine"

# Constant variables that are fetched from settings.
_AUTH0_CLIENT_ID		:str	=	""
_AUTH0_CLIENT_SECRET	:str	=	""
_AUTH0_DOMAIN			:str	=	""
_AUTH0_AUDIENCE			:str	=	""
_DEFAULT_SCOPES			:str	=	""
_AUTH0_ISSUER			:str	=	"https://{}/"
_AUTH0_JWKS_URL			:str	=	"https://{}/.well-known/jwks.json"
_MANAGEMENT_AUDIENCE	:str	=	"https://{}/api/v2/"

# Database Backend class name for User.db
_USER_DB_BACKEND		:Any	=   None

# Key to access authentication session from request session.
_SESSION_KEY			:str	=	"_auth"

# variables used my management_engine.py to store management access_token
_m_access_token			:str	= ""
_m_access_token_exp		:int	= 0
_m_access_token_type	:str	= ""

def _bool():
	"""Tells whether or not the engine is properly configured."""
	if _AUTH0_CLIENT_ID and _AUTH0_CLIENT_SECRET and _AUTH0_DOMAIN:
		return True
	raise AuthEngineError(
		loc="cfg", 
		error="DjangoAuth0Engine Is Not Configured Correctly",
	)
	
class Provider:
	"""A class holding Provider specific information."""

	# String representing the Username-Password-Authentication realm of auth0.
	USERNAME_PASSWORD_REALM	: str	= "Username-Password-Authentication"

	class Scopes:
		"""OpenID Connect Scopes."""

		REFRESH_TOKEN		: str	=	" offline_access "		# Scope for refresh token.
		OPENID				: str	=	" openid "				# Scope for OpenID Information.
		PROFILE				: str	=	" profile "				# Scope for Profile Information.
		EMAIL				: str	=	" email "				# Scope for Email address.
		# Scopes that are used when AuthEngine functions are invoked without any scope.
		DEFAULT				: str	=	OPENID + PROFILE + EMAIL

	class URL:
		"""A class holding provider-specific URLs."""

		class Auth:
			"""A class holding Auth endpoints."""
			token					:str	=	"https://{}/oauth/token"
			dbcon_signup			:str	=	"https://{}/dbconnections/signup"
			dbcon_change_password	:str	=	"https://{}/dbconnections/change_password"
			userinfo				:str	=	"https://{}/userinfo"
			
		class Management:
			"""A class holding Management endpoints."""
			
			users_endpoint			:str	=	"https://{}/api/v2/users/"

			@staticmethod
			def user(id:str) -> str:
				"""Returns a specific user's management endpoint."""
				return Provider.URL.Management.users_endpoint + id
		
	class Grant:
		"""OAuth Grants."""
		
		authorization_code = "authorization_code"
		password = "password"
		password_realm = "http://auth0.com/oauth/grant-type/password-realm"
		client_credentials = "client_credentials"
		refresh_token = "refresh_token"
