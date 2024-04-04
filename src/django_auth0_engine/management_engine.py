"""The ManagementEngine: Support for management using Auth0 Management API.

Here it primarily focuses on updating user information.

The methods rely on the same set of constants that are fetched from settings.py
(see apps.py).
"""

import time
from urllib.parse import quote
from . import cfg
from .exceptions import *
from .response import AuthEngineResponse
from .error import AuthEngineError
from .http import Request, PdefHeader
from .user import User, NoUser

def _access_token() -> str | None:
	"""Returns an access token for the Management API. It automatically
	refreshes the token if no access token exists or the existing one is
	expired. It raises an AuthEngineError if unable to fetch a token.
	"""
	
	# check configuration
	cfg._bool()
	
	now = time.time() + 120				# added 120s with the time so that the
										# token is usable for the next 2 minutes
	if (not cfg._m_access_token) or (cfg._m_access_token_exp > 0 and cfg._m_access_token_exp < now):
		if _fetch_management_token():
			return cfg._m_access_token
	else:
		return cfg._m_access_token

def _fetch_management_token() -> bool:
	"""Fetches a Management API access token using the token endpoint.
	Returns True upon success; an AuthEngineError instance otherwise.
	"""
	if not cfg._bool():
		return False
	
	body = {
		"grant_type": cfg.Provider.Grant.client_credentials,
		"client_id": cfg._AUTH0_CLIENT_ID,
		"client_secret": cfg._AUTH0_CLIENT_SECRET,
		"audience": cfg._MANAGEMENT_AUDIENCE
	}

	payload = {}

	code_response = Request.post(cfg.Provider.URL.Auth.token, headers=PdefHeader.CONTENT_JSON, body=body)
	if code_response:
		payload = code_response.json

	if payload and "access_token" in payload:
		cfg._m_access_token			= payload["access_token"]
		cfg._m_access_token_exp		= payload["expires_in"]
		cfg._m_access_token_type	= payload["token_type"]
		return True
	else:
		cfg._m_access_token			= ""
		cfg._m_access_token_exp		= 0
		cfg._m_access_token_type	= ""
		
		raise ManagementEngineException.NoAccessTokenReceived(
			"ManagementEngine._fetch_management_token",
			payload
		)


def _authorize_header(header):
	"""Adds Authorization header to the header."""
	if "Authorization" not in header and (token := _access_token()):
			header["Authorization"] = f"Bearer {token}"

def get_user(
		sub:str = "",
		query:str = "",
		body:dict = {}
	) -> User | list[User] | AuthEngineError | NoUser:
	"""If sub is defined gets a specific user. if query is defined, perform
	searches based on the quesry string (https://auth0.com/docs/manage-users/user-search/user-search-query-syntax).

	Upon success returns an AuthEngineResponse instance containing the
	attributes. Otherwise, an AuthEngineError instance is returned.
	
	sub (str):
		sub of the user whose attributes to get.

	body (dict):
		a dict containing the attributes to get.
	"""
	return_response = NoUser("ManagementEngine.get_user()")

	if sub:
		url = cfg.Provider.URL.Management.user(sub)
	elif query:
		url = cfg.Provider.URL.Management.users(quote(query))
	else:
		raise ManagementEngineException(
			error = "Missing Required Parameter",
			loc = "ManagementEngine.update_user",
			description = "Either of sub or url is required."
			)
	
	headers = PdefHeader.CONTENT_JSON | PdefHeader.ACCEPT_JSON
	_authorize_header(headers)
	
	try:
		user_response = Request.get(url, headers=headers, body=body)
		if user_response:
			json_response = user_response.json
			if isinstance(json_response, list):
				return_response = list(map(lambda u: User(**u), json_response))
			else:
				return_response = User(**user_response.json)
		else:
			raise ManagementEngineException(user_response.error, f"ManagementEngine.get_user()")
	except ManagementEngineException:			# ignore the ManagementEngineException from try
		raise
	except Exception as err:
		raise ManagementEngineException("Unable to get User", f"ManagementEngine.get_user()") from err
	
	return return_response

def update_user(sub, body) -> AuthEngineResponse | AuthEngineError:
	"""Updates the attributes of the user, defined in body.

	Upon successful update, it returns an AuthEngineResponse instance
	containing the updated attributes. Otherwise, an AuthEngineError instance
	is returned.
	
	sub (str):
		sub of the user whose attributes to update.

	body (dict):
		a dict containing the attributes to update.
	"""
	return_response:AuthEngineResponse = AuthEngineError(loc="ManagementEngine.update_user()")

	url = cfg.Provider.URL.Management.user(sub)
	headers = PdefHeader.CONTENT_JSON | PdefHeader.ACCEPT_JSON
	_authorize_header(headers)
	
	try:
		update_response = Request.patch(url, headers=headers, body=body)
		if update_response:
			return_response = AuthEngineResponse(**update_response.json)
			return_response._bool = True
		else:
			raise ManagementEngineException(update_response.error, f"ManagementEngine.update_user()")
	except ManagementEngineException:			# ignore the ManagementEngineException from try
		raise
	except Exception as err:
		raise ManagementEngineException("Unable to update User", f"ManagementEngine.update_user()") from err
	
	return return_response
