A module to share information among other modules.

### _AUTH0_CLIENT_ID, _AUTH0_CLIENT_SECRET, _AUTH0_DOMAIN, _AUTH0_AUDIENCE, _DEFAULT_SCOPES

Upon fetching the Auth0 application's client ID and client secret, tenant domain, and API audience from settings, the acquired values are stored in these variables. Other modules, including the auth_engine and management_engine, rely on these variables to perform operations.


### _USER_DB_BACKEND
Database Backend class name for User.db

### _SESSION_KEY
This is used as the key to access authentication session.