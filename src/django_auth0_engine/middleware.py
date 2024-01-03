from . import cfg
from . import auth_engine as AuthEngine
from .response import AuthEngineResponse
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject

class SessionAuthMiddleware(MiddlewareMixin):
	"""Authenticates a django.http.HttpRequest using the
	AuthEngine.authenticate() function. It authenticates the request only if
	the request doesn't already have a user property or if a
	django.contrib.auth.models.AnonymousUser instance is assigned to the user
	property.

	The returned value of AuthEngine.authenticate(), is assigned to
	request.user as a SimpleLazyObject.
	"""
	def process_request(self, request):
		# if the request is not already authenticated only them proceed
		# str(django.contrib.auth.models.AnonymousUser) returns "AnonymousUser"
		if (not hasattr(request, "user")) or (not request.user) or str(request.user) == "AnonymousUser":
			if hasattr(request, "session") and cfg._SESSION_KEY in request.session:
				request.user = SimpleLazyObject(lambda: AuthEngine.authenticate(request))
			else:
				request.user = AuthEngineResponse(message="No user")
				request.user._bool = False

class HeaderAuthMiddleware(MiddlewareMixin):
	"""This middleware functions similarly to SessionAuthMiddleware, except that it
	employs the AuthEngine.authenticate_header() function to perform the
	authentication.
	"""
	def process_request(self, request):
		# if the request is not already authenticated only them proceed
		# str(django.contrib.auth.models.AnonymousUser) returns "AnonymousUser"
		if (not hasattr(request, "user")) or (not request.user) or str(request.user) == "AnonymousUser":
			if "Authorization" in request.headers:
				request.user = SimpleLazyObject(lambda: AuthEngine.authenticate_header(request))
			else:
				request.user = AuthEngineResponse(message="No user")
				request.user._bool = False