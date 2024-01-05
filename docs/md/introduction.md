# Django Auth0 Engine

Django Auth0 Engine is a simple Django Authentication Backend that utilizes
OAuth, OIDC, and Auth0 technology to perform authentication and
authorization. For user management, it provides an interface similar to the
standard Django User Model.

Getting Started:

- Install and Configure the engine

- Add middleware

- Access request.user to perform the authentication process.

## 1. Setup

### 1.1 Installation

```
py -m pip install --index-url https://test.pypi.org/simple/ \
--no-deps django-auth0-engine
```

### 1.1 Configuration

- Create and set up an Auth0 application first.
		
- Add `django_auth0_engine` to the `INSTALLED_APPS` list in
	settings.

- Collect the `client_id` and `client_secret` of the Auth0 application,
	tenant `domain` name and API `audience` (for authentication
	purposes it is the client_id)

- In settings define these variables:

```
AUTH0_CLIENT_ID		=	"client_id"

AUTH0_CLIENT_SECRET	=	"client_secret"

AUTH0_DOMAIN		=	"tenant domain"

AUTH0_AUDIENCE		=	"API audience"
```

You can set the `AUTH0_AUDIENCE` to `AUTH0_CLIENT_ID` or ignore it
if you are not intending to use anything other than authentication.

### 1.2 Adding the middleware

Django Auth0 Engine comes with two middleware to make the
authentication process easy and resource-effective.

### 1.2.1. SessionAuthMiddleware

This middleware authenticates the requests made from the browser, using
the ID token from the session.

To use it, add this to your `MIDDLEWARE` list:

```
'django_auth0_engine.middleware.SessionAuthMiddleware'
```

See the [middleware](docs/txt/reference/middleware.md) documentation for details.

### 1.2.2. HeaderAuthMiddleware

To authenticate the requests of your APIs, use this middleware. It is
like `SessionAuthMiddleware`, but instead of using sessions, it uses
the Bearer token from the Authorization header for authentication.

To use it, add this to your `MIDDLEWARE` list:

```
'django_auth0_engine.middleware.HeaderAuthMiddleware'
```

See the [middleware](docs/txt/reference/middleware.md) documentation for details.

You can use both of these middleware in the same project, and they're
compatible with Django's built-in authentication middleware.

### 1.3 Setting User Database Backend

To integrate a database for users, assign a custom database backend
class/function to the `USER_DB_BACKEND` variable in settings. Then you
can access the user's database record through the User.db property
directly from your code.

in settings.py

```
USER_DB_BACKEND = UserDB			# UserDB is a class with database
									# control
```

in views.py

```
def home(request):
	user = request.user
	if user:
		user_record = user.db		# user_record is an instance of
									# UserFirestore that represents the
									# document of the user in Firestore
		...
	else:
		# unauthorized
		...

```

See the Writing User Database Backend section in
[user_class](docs/txt/user_class.md) documentation for details on making a User
Database Backend.

## 2. Usage

Django Auth0 Engine provides a comprehensive set of tools for managing
user authentication, authorization, and resource management.

### 2.1. Signing up:

To register a new user, call the `AuthEngine.signup()` function with the
user's email address, password, and any other information needed by
your specific Auth0 setup.

Upon signing up, it sets an authentication session cookie in the
request and returns a User instance. If it fails to sign up the user,
an AuthEngineError with proper error information is returned.

Example:

```
from django_auth0_engine import AuthEngine

def signup_user(request):
	username = request.POST["username"]
	email = request.POST["email"]
	password = request.POST["password"]

	user = AuthEngine.signup(
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

It has other functionality for finer control over the signup process.
See the [auth_engine](docs/txt/reference/auth_engine.md) documentation for details.

### 2.2. Sign up/Sign in with provider

The `AuthEngine.signin_code()` function allows sign-in using various
identity providers (IdPs), including social networks (Google, Facebook,
Twitter, LinkedIn), enterprise systems (Microsoft Active Directory),
and others.

Call this function with the request, the grant code received from the
selected IdP, and the redirect URL that was sent to the IdP. The values
must match.

Upon authentication, this function sets an authentication session
cookie in the request and returns a User instance. If it fails to
authenticate the user, an AuthEngineError with proper error information
is returned.

Example

```
from django_auth0_engine import AuthEngine

def callback(request):
	code = request.GET["code"]

	user = AuthEngine.signin_code(request, code)
	if user:
		# successfully signed in
	    ...
	else:
		# unsuccessful to sign in
	    ...
```

### 2.3. Signing in:

Call the `AuthEngine.signin()` function with the user's email address as
username, password, and any additional information required by Auth0 to
sign in a user.

Upon sign-in, it sets an authentication session cookie in the request
and returns a User instance. If it fails to sign in the user, an
AuthEngineError is returned with proper error information.

Example:

```
from django_auth0_engine import AuthEngine

def signin_user(request):
	email = request.POST["email"]
	password = request.POST["password"]

	user = AuthEngine.signin(
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

To keep the user signed in without requiring manual sign-in after the
sign-in session ends, set the `keep_signed_in` parameter to True. When
the sign-in session ends other functions of AuthEngine automatically
fetch a new access token and ID token to keep the user signed in.

Example:

```
from django_auth0_engine import AuthEngine

def signin_user(request):
	email = request.POST["email"]
	password = request.POST["password"]

	user = AuthEngine.signin(
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

See the [auth_engine](docs/txt/reference/auth_engine.md) documentation for details.

### 2.4. Authenticate request:

If you have added the `SessionAuthMiddleware`, the user authentication
happens automatically. You can access the authenticated user directly
through the request.user property in your Django views.

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

However, to manually authentication a request call the
`AuthEngine.authenticate()` function with the request object. Upon
successful authentication, it returns a User instance; `AuthEngineError`
otherwise. It sets an authentication session cookie in the request.

Example:

```
from django_auth0_engine import AuthEngine

def aview(request):
	user = AuthEngine.authenticate(request)

	if user:
		# successful authentication
		...
	else:
		# unsuccessful authentication
		...

```
		
See the [auth_engine](docs/txt/reference/auth_engine.md) documentation for details.

### 2.5 Update User Information

To update a user's information on the Auth0 end call the `User.update()`
method with an optional dict containing the key-value pairs to update.

```
def update_nickname(request):
user = request.user
if user:
	user.update({"nickname": "new_nickname"})
	...
```

You can also update the attribute in the User instance and call the
update method without passing any arguments. It will automatically
detect the changed attributes and update them on the Auth0 end.

```
def update_nickname(request):
user = request.user
if user:
	user.nickname = "new_nickname"
	user.update()
	...
```