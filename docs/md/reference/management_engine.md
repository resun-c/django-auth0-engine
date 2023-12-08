# _class_ ManagementEngine(domain, auth_engine)
This class facilitates administrative tasks on the Auth0 platform,
specifically focusing on updating user information.

ManagementEngine relies on the same pieces of information that AuthEngine
relies on. If any of these required pieces of information is missing, an
AuthEngineError is raised.

Each AuthEngine object has these attributes:

### _cached\_property_ ManagementEngine.__\_auth0__
An instance of the Auth0 class from the Auth0 SDK.

### _cached\_property_ ManagementEngine.__token_endpoint__
An instance of auth0.authentication.GetToken.

### _property_ ManagementEngine.__access_token__
Return an access token for the Management API. It automatically
refreshes the token if it's expired and raises an AuthEngineError if
it's unable to do so.

These are the methods available in a user object:

### ManagementEngine.__\_\_bool\_\___()
Determines if the instance is usable based on the availability of
required information.

### ManagementEngine.__fetch_management_token__()
Fetch a Management API token using the token endpoint. Returns True
upon success; False otherwise.

### ManagementEngine.__update_user__(id, body)
This method updates the attributes of the user.

### Args:

    id (str): sub (a.k.a id) of the user whose attributes to update.

    body (dict): a dict containing the attributes to update.

Upon successful update, it returns an AuthEngineResponse object
containing the updated attributes. Otherwise, an AuthEngineError object
is returned.

The ManagementEngine class only serves one purpose: updating user
information. The update_user() method is typically called by the User class
after changing a user's attributes.