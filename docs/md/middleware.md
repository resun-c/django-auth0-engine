# _class_ SessionAuthMiddleware()
This middleware authenticates users based on session cookies. When included  in the settings.MIDDLEWARE list, it automatically performs user  authentication for each request. Accessing request.user within your views triggers the authentication process:

If a valid session cookie exists, a wrapped lambda function calls the authenticate method from the AuthEngine, retrieving the user information.

If successful, the SimpleLazyObject returns a User instance, making it readily available within your view logic.

If authentication fails or no session cookie is present, the SimpleLazyObject returns an AuthEngineError.

Here's an example of authenticating a request after an user has been successfully signed in:

```
def home(request: HttpRequest):
	user = request.user
	if user:
		...
	else:
		...

```

# _class_ HeaderAuthMiddleware()
This middleware operates similarly to SessionAuthMiddleware, but it relies on access tokens provided in the request header instead of session cookies. The wrapped lambda function calls the authenticate_header method from the AuthEngine, performing authentication based on the provided token.