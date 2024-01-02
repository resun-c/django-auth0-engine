from .response import AuthEngineResponse
from .exceptions import AuthEngineError
from .http import Request, PdefHeader
from . import cfg
import time

from pprint import pprint

"""This class facilitates administrative tasks on the Auth0 platform,
specifically focusing on updating user information.
ManagementEngine relies on the same pieces of information that AuthEngine
relies on. If any of these required pieces of information is missing, an
AuthEngineError is raised.
"""

def access_token() -> str | None:
	"""Return an access token for the Management API. It automatically
	refreshes the token if it's expired and raises an AuthEngineError if
	it's unable to do so.
	"""
	if not cfg._BOOL():
		return None
	
	now = time.time() + 120				# added 120s with the time so that the
										# token is usable for the next 2 minutes
	if (not cfg._m_access_token) or (cfg._m_access_token_exp > 0 and cfg._m_access_token_exp < now):
		fetch = fetch_management_token()
		if fetch:
			return cfg._m_access_token
		else:
			raise fetch 				# type: ignore
	else:
		return cfg._m_access_token

def fetch_management_token() -> bool | AuthEngineError:
	"""Fetch a Management API token using the token endpoint. Returns True
	upon success; False otherwise.
	"""
	if not cfg._BOOL():
		return False
	
	body = {
		"grant_type": cfg.Provider.Grant.client_credentials,
		"client_id": cfg._AUTH0_CLIENT_ID,
		"client_secret": cfg._AUTH0_CLIENT_SECRET,
		"audience": cfg._MANAGEMENT_AUDIENCE
	}

	payload = {}

	try:
		code_response = Request.post(cfg.Provider.URL.Auth.token(), headers=PdefHeader.CONTENT_JSON, body=body)
		if code_response:
			payload = code_response.json
	except:
		pass

	if "access_token" in payload:
		cfg._m_access_token			= payload["access_token"]
		cfg._m_access_token_exp		= payload["expires_in"]
		cfg._m_access_token_type	= payload["token_type"]
		return True
	else:
		error = AuthEngineError(loc="ManagementEngine.fetch_management_token", **payload)
		cfg._m_access_token			= ""
		cfg._m_access_token_exp		= 0
		cfg._m_access_token_type	= ""
	return error


def authorize_header(header):
	if "Authorization" not in header and (token := access_token()):
			header["Authorization"] = f"Bearer {token}"

def update_user(id, body) -> AuthEngineResponse:
	"""This method updates the attributes of the user.
	Args:
		id (str): sub (a.k.a id) of the user whose attributes to update.
		body (dict): a dict containing the attributes to update.
	Upon successful update, it returns an AuthEngineResponse object
	containing the updated attributes. Otherwise, an AuthEngineError object
	is returned.
	"""
	return_response:AuthEngineResponse = AuthEngineError(loc="ManagementEngine.update_user")

	url = cfg.Provider.URL.Management.user(id)
	headers = PdefHeader.CONTENT_JSON | PdefHeader.ACCEPT_JSON
	authorize_header(headers)
	
	try:
		update_response = Request.patch(url, headers=headers, body=body)
		if update_response:
			return_response = AuthEngineResponse(**update_response.json)
			return_response._bool = True
		else:
			return_response = AuthEngineError(loc="ManagementEngine.update_user", **update_response.json)
	except Exception as err:
		print(err.__dict__)
		return_response = AuthEngineError(loc="ManagementEngine.update_user", **err.__dict__)
	return return_response
