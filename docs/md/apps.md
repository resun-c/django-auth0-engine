# _class_ DjangoAuth0Engine

Configuration for Django app.

## DjangoAuth0Engine.__ready__()

This method fetches different values from settings to be used by the AuthEngine and ManagementEngine. It looks for the following variables in settings:

### AUTH0_CLIENT_ID
Auth0 application's client_id

### AUTH0_CLIENT_SECRET
Auth0 application's client_secret

### AUTH0_DOMAIN
Tenant domain

### AUTH0_AUDIENCE
API audience

### AUTH0_DEFAULT_SCOPES (optional)
String containing scopes that are used when requesting for access_token.

### USER_DB_BACKEND (optional)
Databse backend class used by User class.


If any of the above information is missing, an AuthEngineError is raised.