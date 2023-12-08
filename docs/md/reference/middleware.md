# _class_ SessionAuthMiddleware()
This middleware authenticates the user by passing each `request` object to
the `AuthEngine.authenticate()` method. The `authenticate()` method retrieves
the ID token from the session data in the request and verifies it. Upon
validation, it returns either a User object or an AuthEngineError object.
This middleware assigns the returned object to the `request.user` attribute.

The `AuthEngine.authenticate()` method is wrapped into a lambda function and
passed to SimpleLazyObject, and then the `SimpleLazyObject` is assigned to
the `request.user` attribute. This mechanism allows the `authenticate()` method
to only get invoked when the user property of the request is accessed. This
saves both resources and time.

If no session cookie is present, noting is done.

Here's an example of authenticating a request after an user has been
successfully signed in:

```
def home(request: HttpRequest):
	user = request.user
	if user:
		# successful authentication
		...
	else:
		# unsuccessful authentication
		...
```

# _class_ HeaderAuthMiddleware()

This middleware functions similarly to `SessionAuthMiddleware`, but it
employs the `AuthEngine.authenticate_header()` method. The
`authenticate_header()` method functions similarly to the
`AuthEngine.authenticate()` method, except that the ID token is parsed from
the `Authorization` header of the `request` object, rather than from the
session data.

Just like `SessionAuthMiddleware` it also uses the `SimpleLazyObject` as a
wrapper for the `request.user` attribute. This middleware is suitable for API
applications.

For example, if a request is made to your API by setting the `Authorization`
header with `Bearer` token like this:

```
curl --request GET \
	--url http://your-domain.com/api_path \
	--header 'authorization: Bearer ACCESS_TOKEN'
```

In you views you can access the user in the following way:


```
def aview(request: HttpRequest):
	user = request.user
	if user:
		# successful authentication
		...
	else:
		# unsuccessful authentication
		...
```