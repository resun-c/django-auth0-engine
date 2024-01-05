## _class_ __DjangoAuth0EngineConfig__
Configuration for Django app.

### DjangoAuth0EngineConfig.__ready__()
Fetches package-specific constant values from settings. It looks
for the following variables:

	AUTH0_CLIENT_ID
		Auth0 application's client_id
	
	AUTH0_CLIENT_SECRET
		Auth0 application's client_secret
	
	AUTH0_DOMAIN
		Tenant domain
	
	AUTH0_AUDIENCE (optional)
		API audience
	
	AUTH0_DEFAULT_SCOPES (optional)
		Scopes that are used when AuthEngine functions are invoked
		without any scope.
	
	USER_DB_BACKEND (optional)
		Database backend class used by User class.
			
If any of the above information is missing, an AuthEngineError is raised.