from . import cfg
from .exceptions import AuthEngineError
from django.apps import AppConfig
from django.conf import settings

class DjangoAuth0EngineConfig(AppConfig):
	"""Configuration for Django app.
	"""
	name = "django_auth0_engine"
	verbose_name = "Django Auth0 Engine"

	def ready(self):
		"""Fetches package specific constant values from settings. It looks
		for the following variables:

	    	AUTH0_CLIENT_ID
	    		Auth0 application's client_id

	    	AUTH0_CLIENT_SECRET
	    		Auth0 application's client_secret

	    	AUTH0_DOMAIN
	    		Tenant domain

	    	AUTH0_AUDIENCE (optional)
	    		API audience

	    	AUTH0_DEFAULT_SCOPES (optional)
	    		String containing scopes that are used when requesting for
	    		access_token.

			USER_DB_BACKEND (optional)
				Databse backend class used by User class.

	    If any of the above information is missing, an AuthEngineError is raised.
		"""
		
		if hasattr(settings, "AUTH0_CLIENT_ID"):
			cfg._AUTH0_CLIENT_ID = settings.AUTH0_CLIENT_ID
		else:
			raise AuthEngineError(
				loc="DjangoAuth0EngineConfig", 
				error="AuthEngine Not Configured Correctly",
				description="client_id missing"
			)

		if hasattr(settings, "AUTH0_CLIENT_SECRET"):
			cfg._AUTH0_CLIENT_SECRET	= settings.AUTH0_CLIENT_SECRET
		else:
			raise AuthEngineError(
				loc="DjangoAuth0EngineConfig", 
				error="AuthEngine Not Configured Correctly",
				description="client_secret is missing"
			)

		if hasattr(settings, "AUTH0_DOMAIN"):
			cfg._AUTH0_DOMAIN			= settings.AUTH0_DOMAIN
			cfg._MANAGEMENT_AUDIENCE	= f"https://{cfg._AUTH0_DOMAIN}/api/v2/"
		else:
			raise AuthEngineError(
				loc="DjangoAuth0EngineConfig", 
				error="AuthEngine Not Configured Correctly",
				description="domain is missing."
			)

		if hasattr(settings, "AUTH0_AUDIENCE"):
			cfg._AUTH0_AUDIENCE		= settings.AUTH0_AUDIENCE
		elif cfg._AUTH0_CLIENT_ID:
			cfg._AUTH0_AUDIENCE		= cfg._AUTH0_CLIENT_ID
		else:
			raise AuthEngineError(
				loc="DjangoAuth0EngineConfig", 
				error="AuthEngine Not Configured Correctly",
				description="audience is missing."
			)

		if hasattr(settings, "DEFAULT_SCOPES"):
			cfg._DEFAULT_SCOPES = settings.DEFAULT_SCOPES

		if hasattr(settings, "USER_DB_BACKEND"):
			cfg._USER_DB_BACKEND = settings.USER_DB_BACKEND
