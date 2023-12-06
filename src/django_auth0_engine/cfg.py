from typing import Any

"""A module to share information among other modules.
"""


# Upon fetching the Auth0 application's client ID and client secret, tenant
# domain, and API audience from settings, the acquired values are stored in
# these variables. Other modules, including the auth_engine and
# management_engine, rely on these variables to perform operations.
_AUTH0_CLIENT_ID		:str    =	None # type: ignore
_AUTH0_CLIENT_SECRET	:str    =	None # type: ignore
_AUTH0_DOMAIN			:str    =	None # type: ignore
_AUTH0_AUDIENCE			:str    =	None # type: ignore
_DEFAULT_SCOPES			:str    =	None # type: ignore

# Database Backend class name for User.db
_USER_DB_BACKEND        :Any    =   None

# This is used as the key to access authentication session.
_SESSION_KEY			:str	=	"_auth"