"""A module to share information among other modules.
"""
from typing import Any
from django_auth0_engine.exceptions import AuthEngineException
from urllib.parse import urlencode, quote

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

# variables used my management_engine.py to store management access token
_m_access_token			:str	= ""
_m_access_token_exp		:int	= 0
_m_access_token_type	:str	= ""

def _bool():
	"""Tells whether or not the engine is properly configured."""
	if _AUTH0_CLIENT_ID and _AUTH0_CLIENT_SECRET and _AUTH0_DOMAIN:
		return True
	
	if not _AUTH0_CLIENT_ID:
		raise AuthEngineException.MisconfiguredEngine("AUTH0_CLIENT_ID")
	
	if not _AUTH0_CLIENT_SECRET:
		raise AuthEngineException.MisconfiguredEngine("AUTH0_CLIENT_SECRET")
	
	if not _AUTH0_DOMAIN:
		raise AuthEngineException.MisconfiguredEngine("AUTH0_DOMAIN")
	
class Provider:
	"""A class holding Provider specific information."""

	# String representing the Username-Password-Authentication realm of auth0.
	USERNAME_PASSWORD_REALM	: str	= "Username-Password-Authentication"
	
	class Connections:
		USERNAME_PASSWORD	:str	=	"Username-Password-Authentication"
		GOOGLE				:str	=	"google-oauth2"
		FACEBOOK			:str	=	"facebook"
		FACEBOOK			:str	=	"facebook"
		WINDOWSLIVE			:str	=	"windowslive"
		APPLE				:str	=	"apple"
		APPLE				:str	=	"apple"
		GITHUB				:str	=	"github"
		TWITTER				:str	=	"twitter"
	
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
			class ResponseType:
				code = "code"
				token = "token"
				
			token					:str	=	"https://{}/oauth/token"
			dbcon_signup			:str	=	"https://{}/dbconnections/signup"
			dbcon_change_password	:str	=	"https://{}/dbconnections/change_password"
			userinfo				:str	=	"https://{}/userinfo"
			social					:str	=	"https://{}/authorize?response_type={}&client_id={}&connection={}&redirect_uri={}&scope={}"
			
			
			@staticmethod
			def social_provider(
					connection:str,
					redirect_uri:str,
					scope:str = "",
					response_type:str = ResponseType.code,
					state:str = "",
					additional_parameters:dict = {}
				) -> str:
				
				scope = Provider.Scopes.DEFAULT if not scope else scope
				
				s = Provider.URL.Auth.social.format(
					_AUTH0_DOMAIN,
					response_type,
					_AUTH0_CLIENT_ID,
					connection,
					redirect_uri,
					scope
				)
				
				if state:
					s = f"{s}&state={state}"
					
				if additional_parameters:
					s = f"{s}&{urlencode(additional_parameters, quote_via=quote)}"
				
				return s
			
		class Management:
			"""A class holding Management endpoints."""
			
			users_endpoint			:str	=	"https://{}/api/v2/users"

			@staticmethod
			def user(id:str) -> str:
				"""Returns a specific user's management endpoint."""
				return f"{Provider.URL.Management.users_endpoint}/{id}"
			
			@staticmethod
			def users(query):
				"""Returns a query url for management endpoint."""
				return f"{Provider.URL.Management.users_endpoint}?q={query}"
				
	class Grant:
		"""OAuth Grants."""
		
		authorization_code = "authorization_code"
		password = "password"
		password_realm = "http://auth0.com/oauth/grant-type/password-realm"
		client_credentials = "client_credentials"
		refresh_token = "refresh_token"
