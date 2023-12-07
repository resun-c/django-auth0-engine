# _class_ ManagementEngine(domain, auth_engine)
ManagementEngine facilitates administrative tasks on the Auth0 platform, specifically focusing on updating user information.

ManagementEngine relies on the same pieces of information that AuthEngine relies on to. If any of these required pieces of information are missing, an error will be raised.

Each AuthEngine object has these attributes:

### _cached_property_ ManagementEngine.__\_auth0__
An instance of the Auth0 class from the Auth0 SDK.

### _cached_property_ ManagementEngine.__token_endpoint__
Returns an instance of auth0.authentication.GetToken.

### _property_ ManagementEngine.__access_token__
Return a access token for the Management API. It automatically refreshes the token if expired and raises an AuthEngineError if the refresh fails.

These are the methods available in a user object:

### ManagementEngine.__fetch_management_token__()
Retrieves a Management API token using the token endpoint. Returns True upon success; False otherwise.

### ManagementEngine.__update_user__(id, body)
Updates a user's information based on the provided id and body data. On successful update, returns an AuthEngineResponse object containing the updated information.

The ManagementEngine class only serves one purpose: updating user information. The update_user method is typically called by the User class after changing a user's attributes.