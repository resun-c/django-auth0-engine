from . import cfg
from . import AuthEngine
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject


class SessionAuthMiddleware(MiddlewareMixin):
    """This middleware authenticates the user by passing each request object to
	the AuthEngine.authenticate() method. The authenticate() method retrieves
	the ID token from the session data in the request and verifies it. Upon
	validation, it returns either a User object or an AuthEngineError object.
	This middleware assigns the returned object to the request.user attribute.

	The AuthEngine.authenticate() method is wrapped into a lambda function and
	passed to SimpleLazyObject, and then the SimpleLazyObject is assigned to
	the request.user attribute. This mechanism allows the authenticate() method
	to only get invoked when the user property of the request is accessed. This
	saves both resources and time.

	If no session cookie is present, noting is done.
    """
    def process_request(self, request):
        if hasattr(request, "session") and cfg._SESSION_KEY in request.session:
            request.user = SimpleLazyObject(lambda: AuthEngine().authenticate(request))

class HeaderAuthMiddleware(MiddlewareMixin):
    """This middleware functions similarly to SessionAuthMiddleware, but it
	employs the AuthEngine.authenticate_header() method. The
	authenticate_header() method functions similarly to the
	AuthEngine.authenticate() method, except that the ID token is parsed from
	the Authorization header of the request object, rather than from the
	session data.

	Just like SessionAuthMiddleware it also uses the SimpleLazyObject as a
	wrapper for the request.user attribute. This middleware is suitable for API
	applications.
    """
    def process_request(self, request):
        if "Authorization" in request.headers:
            request.user = SimpleLazyObject(lambda: AuthEngine().authenticate_header(request))