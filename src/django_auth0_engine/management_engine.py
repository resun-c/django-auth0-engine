from .response import AuthEngineResponse
from .exceptions import AuthEngineError
from . import cfg
import time
from django.utils.functional import cached_property
from auth0.management import Auth0, Users
from auth0 import authentication

class ManagementEngine:
	"""ManagementEngine facilitates administrative tasks on the Auth0 platform,
	specifically focusing on updating user information.

	ManagementEngine relies on the same pieces of information that AuthEngine
	relies on to. If any of these required pieces of information are missing,
	an error will be raised.

	The ManagementEngine class only serves one purpose: updating user
	information. The update_user method is typically called by the User class
	after changing a user's attributes.
	"""
	def __init__(self) -> None:
		self.audience				:str			= "https://{}/api/v2/".format(cfg._AUTH0_DOMAIN)
		self._access_token			:str | None		= None
		self._exp					:int			= 0
		self._token_type			:str | None		= None
		self._auth0_object			:Auth0 | None	= None
		self._auth0_object_user		:Users | None	= None

	def __bool__(self):
		if cfg._AUTH0_CLIENT_SECRET and cfg._AUTH0_CLIENT_SECRET and cfg._AUTH0_DOMAIN:
			return True
		
		raise AuthEngineError(
			"ManagementEngine Not Configured Correctly",
			"""Either of client_id, client_secret or domain is missing."""
		)

	@cached_property
	def _auth0(self) -> Auth0 | None:
		"""An instance of the Auth0 class from the Auth0 SDK.
		"""
		return Auth0(cfg._AUTH0_DOMAIN, self.access_token) # type: ignore

	@cached_property
	def token_endpoint(self) -> authentication.GetToken:
		"""Returns an instance of auth0.authentication.GetToken.
		"""
		return authentication.GetToken(
			domain			=	cfg._AUTH0_DOMAIN,
			client_id		=	cfg._AUTH0_CLIENT_ID,
			client_secret	=	cfg._AUTH0_CLIENT_SECRET,
		)
	
	@property
	def access_token(self) -> str | None:
		"""Return a access toeken for the Management API. It automatically
		refreshes the token if expired and raises an AuthEngineError if the
		refresh fails.
		"""
		if not self:
			return None
		
		now = time.time() + 120				# added 120s with the time so that the
											# token is usable for the next 2 minutes

		if self._access_token is None or (self._exp > 0 and self._exp < now):
			self.fetch_management_token()
		
		if self._access_token:
			return self._access_token
		else:
			raise AuthEngineError(error="Can't fetch Access Token for ManagementEngine!")

	def fetch_management_token(self) -> bool:
		"""Retrieves a Management API token using the token endpoint. Returns True
		upon success; False otherwise.
		"""
		if not self:
			return False
		
		try:
			payload = self.token_endpoint.client_credentials(self.audience)
		except:
			payload = {}

		if "access_token" in payload:
			self._access_token		= payload["access_token"]
			self._exp				= payload["expires_in"]
			self._token_type		= payload["token_type"]
			return True
		else:
			self._access_token		= None
			self._exp				= 0
			self._token_type		= None

		return False

	def update_user(self, id, body) -> AuthEngineResponse:
		"""Updates a user's information based on the provided id and body data. On
		successful update, returns an AuthEngineResponse object containing the
		updated information.
		"""
		return_response:AuthEngineResponse = AuthEngineError()
		try:
			update_user_response = self._auth0.users.update(id, body) # type: ignore
			return_response = AuthEngineResponse(**update_user_response)
			return_response._bool = True
		except Exception as err:
			print(err.__dict__)
			return_response = AuthEngineError(**err.__dict__)

		return return_response
