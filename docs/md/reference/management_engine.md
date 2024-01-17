The ManagementEngine: Support for management using Auth0 Management API.

Here it primarily focuses on updating user information.

The methods rely on the same set of constants that are fetched from settings.py
(see apps.py).

## __\_access_token__()
Returns an access token for the Management API. It automatically
refreshes the token if no access token exists or the existing one is
expired. It raises an AuthEngineError if unable to fetch a token.

## __\_fetch_management_token__()
Fetches a Management API access token using the token endpoint.
Returns True upon success; an AuthEngineError instance otherwise.


## __\_authorize_header__(header)
Adds Authorization header to the header.

## __get_user__(sub, body)
Get the attributes of the user, defined in body.

Upon success returns an AuthEngineResponse instance containing the
attributes. Otherwise, an AuthEngineError instance is returned.
	
### sub (str):
sub of the user whose attributes to get.

### body (dict):
a dict containing the attributes to get.
        
## __update_user__(id, body)
Updates the attributes of the user, defined in body.

Upon successful update, it returns an AuthEngineResponse instance
containing the updated attributes. Otherwise, an AuthEngineError instance
is returned.
	
### id
sub (a.k.a id) of the user whose attributes to update.

### body
a dict containing the attributes to update.
	