A module to share information among other modules.

### BACKEND_NAME
String representation of the name of the backend.

Constant variables that are fetched from settings:

	_AUTH0_CLIENT_ID
	_AUTH0_CLIENT_SECRET
	_AUTH0_DOMAIN
	_AUTH0_AUDIENCE
	_DEFAULT_SCOPES
	_AUTH0_ISSUER
	_AUTH0_JWKS_URL
	_MANAGEMENT_AUDIENCE

### _USER_DB_BACKEND
Database Backend class name for User.db

### _SESSION_KEY
Key to access authentication session from request session.

### ___bool__()
Tells whether or not the engine is properly configured.

## _class_ __Provider__
A class holding Provider specific information.

### USERNAME_PASSWORD_REALM
String representing the Username-Password-Authentication realm of
auth0.

## _class_ Provider.__Scopes__
OpenID Connect Scopes.

### REFRESH_TOKEN
Scope for refresh token.

### OPENID
Scope for OpenID Information.

### PROFILE
Scope for Profile Information.
		
### EMAIL
Scope for Email address.

### DEFAULT
Scopes that are used when AuthEngine functions are invoked without
any scope.

## _class_ Provider.__URL__
A class holding provider-specific URLs.

## _class_ Provider.URL.__Auth__
A class holding Auth endpoints

### token
The token endpoint.

### dbcon_signup
dbconnections signup endpoint.

### dbcon_change_password
dbconnections change password endpoint.

### userinfo
userinfo endpoint.
			
## _class_ Provider.URL.__Management__
A class holding Management endpoints.
			
### users_endpoint
users endpoint.

### staticmethod user(id)
Returns a specific user's management endpoint.
		
## _class_ Provider.__Grant__
OAuth Grants.

### authorization_code
Authorization Code grant.
		
### password
Password grant.
		
### password_realm
Password Realm grant.
"http://auth0.com/oauth/grant-type/password-realm"
		
### client_credentials
Client Credentials grant.
		
### refresh_token
Refresh Token grant.
