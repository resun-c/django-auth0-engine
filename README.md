# Django Auth0 Engine

Django Auth0 Engine is a simple Django Authentication Backend that utilizes
OAuth, OIDC, and Auth0 technology to perform authentication and
authorization securely. It focuses on empowering developers to build secure
and user-friendly applications with simplified authentication and resource
management.

## 1. Advantages:

- Secured authentication system employing OAuth, OIDC, and Auth0
	technology.

- Automatic user authentication through middleware; authenticated user
	readily available in `request.user` as `User` object.

- Comprehensive and flexible User object with directly accessible
	database records and functionality for resource management.

## 2. Getting Started:

1. Install and Configure the engine
   
2. Add middleware
   
3. Access `request.user` to perform the authentication process.

## 3. Setup

### 3.1 Installation

```
py -m pip install --index-url https://test.pypi.org/simple/ \
--no-deps django-auth0-engine
```

### 3.2 Configuration

1. Add the `"django_auth0_engine"` app to the `INSTALLED_APPS` list in
	settings.

2. Create an Auth0 application and set it up first.

3. Collect the `client_id` and `client_secret` of the application,
	tenant `domain` name and API `audience` (for only authentication
	purposes it is the `client_id`)

4. In settings define these attributes with `client_id`,
	`client_secret`, tenant `domain` and API `audience`:

```
AUTH0_CLIENT_ID		=	"client_id"

AUTH0_CLIENT_SECRET	=	"client_secret"

AUTH0_DOMAIN		=	"tenant domain"

AUTH0_AUDIENCE		=	"API audience"
```

You can set the `AUTH0_AUDIENCE` to `AUTH0_CLIENT_ID` or ignore it
if you are not intending to use anything other than authentication.

### 3.3 Adding the middlewares

Django Auth0 Engine comes with two middleware to make the
authentication process easy and resource-effective.

#### 3.3.1. SessionAuthMiddleware

This middleware authenticates the requests made from the browser using
the ID tokens from the session.

To use it, add this to your `MIDDLEWARE` list:

```
'django_auth0_engine.middleware.SessionAuthMiddleware'
```

See the [SessionAuthMiddleware](docs/reference/md/middleware.md#class-sessionauthmiddleware) documentation for details.

#### 3.3.2. HeaderAuthMiddleware

To authenticate the requests of your API, use this middleware. It is
like `SessionAuthMiddleware`, but instead of using sessions, it uses
the `Bearer` token from the `Authorization` header for authentication.

To use it, add this to your `MIDDLEWARE` list:

```
'django_auth0_engine.middleware.HeaderAuthMiddleware'
```

See the [SessionAuthMiddleware](docs/reference/md/middleware.md#class-headerauthmiddleware) documentation for details.

You can use both of these middleware in the same project, and they're
compatible with Django's built-in authentication middleware.

### 3.4 Setting User Database Backend

To integrate a database for users, assign a custom database backend
class to the `USER_DB_BACKEND` attribute in settings. Then you can
access the user's database record through the `User.db` property
directly from your code.

```
USER_DB_BACKEND = UserDB			# UserDB is a class with database
									# control
```

See the [User Database Backend](#user-database) section bellow for more details.

## 4. Usage

Django Auth0 Engine provides a comprehensive set of tools for managing
user authentication, authorization, and resource management within your
Django application. The `AuthEngine` class facilitates user
authentication and user registration. The `ManagementEngine` aims at
resource management.

### 4.1. Signing up:

To register a new user, call the `AuthEngine.signup()` method with the
user's email address, password, and any other information needed by
your specific Auth0 setup.

Upon signing up the user, this method sets the session cookie in the
request and returns a `User` object. If it fails to sign up the user, an
`AuthEngineError` is returned with proper error information.

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

It has other functionality for finer control over the sign up process.
See the [AuthEngine.signup()](docs/reference/md/auth_engine.md#authenginesignuprequest-email-password-connection-username-user_metadata-given_name-family_name-name-nickname-picture-signin-keep_signed_in) documentation for details.


### 4.2. Sign up/Sign in with provider

The `AuthEngine.signin_code()` method allows sign-in using various
identity providers (IdPs), including social networks (Google, Facebook,
Twitter, LinkedIn), enterprise systems (Microsoft Active Directory),
and others.

Call this method with the request, the grant code received from the
selected IdP, and the redirect URL that was sent to the IdP. The values
must match.

Upon authentication, this method sets the session cookie in the request
and returns a `User` object. If it fails to authentication the user, an
`AuthEngineError` is returned with proper error information.

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

### 4.3. Signing in:

Call the `AuthEngine.signin()` method with the user's email address as
username, password, and any additional information required by Auth0 to
sign in a user.

Upon sign in, this method sets the session cookie in the request and
returns a `User` object. If it fails to sign in the user, an
`AuthEngineError` is returned with proper error information.

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

To keep the user signed in without requiring manual sign-in after the
sign-in session ends, set the `keep_signed_in` parameter to True. When
the sign-in session ends other methods of AuthEngine automatically
fetch a new access token and ID token to keep the user signed in.

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

See the [AuthEngine.signup()](docs/reference/md/auth_engine.md#authenginesignuprequest-email-password-connection-username-user_metadata-given_name-family_name-name-nickname-picture-signin-keep_signed_in) documentation for details.

### 4.4. Authenticate request:

If you have added the `SessionAuthMiddleware` the user authentication
happens automatically. Access the authenticated user directly through
the `request.user` property in your Django views.

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
`AuthEngine.authenticate()` method with the request object. Upon
successful authentication, it returns a `User` object; `AuthEngineError`
otherwise.

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

See the [AuthEngine.signup()](docs/reference/md/auth_engine.md#authenginesignuprequest-email-password-connection-username-user_metadata-given_name-family_name-name-nickname-picture-signin-keep_signed_in) documentation for details.

## 5. User object

The `User` object is a crucial element of this module and plays a
critical role in user management within your application. It' just like
the standard Django `User` object but it has capabilities to leveraging
OIDC and Auth0 technologies.

### 5.1 User Database Backend

The `User` object in Django Auth0 Engine is constructed using OpenID
Connect (OIDC) information for a lightweight representation of the
user. It doesn't have database interaction by default. However, it
provides functionalities for integrating your chosen database backend.

To enable database interaction, configure `USER_DB_BACKEND` with your
User Database Backend. Then you can access the user's database record
through the `User.db` property in your code.

See the [Writing User Database Backend](docs/md/user_object.md#writing-user-database-backend) documentation for details on making a User Database Backend.

Here's an example:

in `settings.py`

```
USER_DB_BACKEND = UserFirestore		# see the Writing User Database
									# Backend section bellow
```

in `views.py`

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

`User` object has other functionality including multiple database
backends. See the [User](docs/md/user_object.md) documentation for details.
