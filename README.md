# Django Auth0 Engine
Django Auth0 Engine is a simple Django Authentication Backend that utilizes OAuth, OIDC, and Auth0 technology to perform authentication and authorization securely. It focuses on empowering developers to build secure and user-friendly applications with simplified authentication and resource management.

# Install

```
py -m pip install --index-url https://test.pypi.org/simple/ --no-deps django-auth0-engine
```

# Setup

## Configuration

1. Create an Auth0 application and set it up first.

2. Collect the `client_id` and `client_secret` of the application, tenant `domain` name and API `audience` (for only authentication purposes it is the client_id)

3. Add the `"django_auth0_engine"` app to the `INSTALLED_APPS` list in settings.

4. In settings define these attributes with `client_id`, `client_secret`, tenant `domain` and API `audience`:

```
AUTH0_CLIENT_ID		=	"client_id"

AUTH0_CLIENT_SECRET	=	"client_secret"

AUTH0_DOMAIN		=	"tenant domain"

AUTH0_AUDIENCE		=	"API audience"
```

You can set the `AUTH0_AUDIENCE` to `AUTH0_CLIENT_ID` or ignore it if you are not intending to use anything other than authentication.

## Adding the middlewares

Django Auth0 Engine comes with two middleware to make the authentication process easy and resource-effective.

### SessionAuthMiddleware

This middleware authenticates the requests made from the browser using the ID tokens from the session.

To use it, add this to your `MIDDLEWARE` list:

```
'django_auth0_engine.middleware.SessionAuthMiddleware'
```

See the [SessionAuthMiddleware](docs/reference/md/middleware.md#class-sessionauthmiddleware) documentation for details.

### HeaderAuthMiddleware

To authenticate the requests of your API, use this middleware. It is like `SessionAuthMiddleware`, but instead of using sessions, it uses the Bearer token from the Authorization header for authentication.

To use it, add this to your `MIDDLEWARE` list:

```
'django_auth0_engine.middleware.HeaderAuthMiddleware'
```

See the [SessionAuthMiddleware](docs/reference/md/middleware.md#class-headerauthmiddleware) documentation for details.

You can use both of these middleware in the same project, and they're compatible with Django's built-in authentication middleware.

## Setting User Database Backend
To integrate a database for users, assign a custom database backend class to the  `USER_DB_BACKEND` attribute in settings. Then you can access the user's database record through the `User.db` property directly from your code.

```
USER_DB_BACKEND = UserDB			# UserDB is a class with database control
```

See the [User Database](#user-database) section for more details.

# Usage

Django Auth0 Engine provides a comprehensive set of tools for managing user authentication, authorization, and resources within your Django application. The `AuthEngine` class facilitates user authentication and user registration. The `ManagementEngine` aims at resource management.

## Authentication

### 1. Signing up:

The `AuthEngine.signup()` method helps you register users with Auth0. To use it, simply provide a Django `HttpRequest` object, the user's email address, password, and any other information needed by your specific Auth0 setup (see the [AuthEngine.signup()](docs/reference/md/auth_engine.md#authenginesignuprequest-email-password-connection-username-user_metadata-given_name-family_name-name-nickname-picture-signin-keep_signed_in) documentation for more details).

Upon successful signup, it sets the session cookie in the request object and returns a `User` object. Otherwise, an `AuthEngineError` object with error information is returned; the request session is unchanged. A verification mail is also sent to the email address.

Example:

```
from django_auth0_engine import AuthEngine

def signup_user(request):
	username = request.POST["username"]
	email = request.POST["email"]
	password = request.POST["password"]

	user = AuthEngine().signup(
		request = request,
		email = email,
		password = password,
		username = username
	)

	if user:
		# successful user creation
		...
	else:
		# unsuccessful user creation
		...

```

It has other functionality for finer control over the signup process. See the [AuthEngine.signup()](docs/reference/md/auth_engine.md#authenginesignuprequest-email-password-connection-username-user_metadata-given_name-family_name-name-nickname-picture-signin-keep_signed_in) documentation for details.

### 2. Signup/Signin with provider

The `AuthEngine.signin_code()` method allows sign-in using various identity providers (IdPs), including social networks (Google, Facebook, Twitter, LinkedIn), enterprise systems (Microsoft Active Directory), and others.

This method takes a Django `HttpRequest` object and the grant code received from the selected IdP as argument.

Upon authentication, it sets the session cookie in the request object and returns a `User` object. Otherwise, an `AuthEngineError` object with error information is returned; the request session is unchanged.

Example

```
from django_auth0_engine import AuthEngine

def callback(request):
	code = request.GET["code"]

	user = AuthEngine().signin_code(request, code)
	if user:
		# successfully signed in
	    ...
	else:
		# unsuccessful to sign in
	    ...
```

### 3. Signing in:
The sign-in process is done by the `AuthEngine.signin()` method. This method takes a Django `HttpRequest` object, the user's email address as username, password, and any additional information required by Auth0 (see the [AuthEngine.signin()](docs/reference/md/auth_engine.md#authenginesigninrequest-username-password-scope-realm-audience-grant_type-forwarded_for-keep_signed_in) documentation for details).

Upon successful signin, it sets the session cookie in the request object and returns a `User` object. Otherwise, an `AuthEngineError` object with error information is returned; the request session is unchanged.

Example:

```
from django_auth0_engine import AuthEngine

def signin_user(request):
	email = request.POST["email"]
	password = request.POST["password"]

	user = AuthEngine().signin(
		request,
		username = email,
		password = password,
	)
	if user:
		# successfully signed in
	    ...
	else:
		# unsuccessful to sign in
	    ...
```

To prolonged user sessions without requiring manual intervention you can set the `keep_signed_in` parameter to True. It fetches a refresh token. So when the user session expires, other methods of `AuthEngine` automatically exchange the refresh token with a new ID token to keep the user signed in.

Example:

```
from django_auth0_engine import AuthEngine

def signin_user(request):
	email = request.POST["email"]
	password = request.POST["password"]

	user = AuthEngine().signin(
		request,
		username = email,
		password = password,
		keep_signed_in = True,
	)
	if user:
		# successfully signed in
	    ...
	else:
		# unsuccessful to sign in
	    ...
```

### 4. Authenticate request:
If you have added the `SessionAuthMiddleware` the user authentication happens automatically. Access the authenticated user directly through the `request.user` property in your Django views.

Example:

```

def home(request):
	user = request.user
	if user:
		# successfully authentication
		...
	else:
		# unsuccessful authentication
		...
```

However, manual authentication can be done by the `AuthEngine.authenticate()` method. This method authenticates a Django `HttpRequest` object and upon successful authentication, it returns a `User` object; `AuthEngineError` otherwise. See the [AuthEngine.authenticate()](docs/reference/md/auth_engine.md#authengineauthenticaterequest) documentation for details.

Example:

```
from django_auth0_engine import AuthEngine

def aview(request):
	user = AuthEngine().authenticate(request)

	if user:
		# successful authentication
		...
	else:
		# unsuccessful authentication
		...
```

## User object

The User object is a fundamental element of the Django Auth0 Engine and plays a critical role in user management within your application. It resembles the standard Django User object but extends its capabilities by specifically leveraging OIDC and Auth0 technologies.

### User Database
The `User` object in Django Auth0 Engine is built using OpenID Connect (OIDC) information obtained from Auth0 ID tokens. This allows for a lightweight representation of the user without requiring database interaction by default. However, the `User` object provides functionalities for seamlessly integrating with your chosen database backend.

To utilize database interaction, configure `USER_DB_BACKEND` with your method or class. Access the user's database entry through the `User.db` property in your code.

Backend configuration:

- Method: Set `USER_DB_BACKEND` to a function that receives the user's OIDC attributes as keyword arguments and returns the database entry.

- Class: Set `USER_DB_BACKEND` to a class that can be initialized with the user's OIDC attributes and provides methods for accessing and manipulating the user's database representation.

Here's an example:

```
def home(request):
	user = request.user
	if user:
		user_db = user.db
		...
	else:
		# unauthorized
		...
```

See the [examples / user_db_backends.md](docs/examples/user_db_backends.md) documentation for details.

User object has other functionality including multiple database backends. See the [User](docs/reference/md/user.md#class-userkwarg) documentation for details.
