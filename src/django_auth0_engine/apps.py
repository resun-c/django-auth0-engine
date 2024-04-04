from django_auth0_engine.exceptions import AuthEngineException
from . import cfg
from django.apps import AppConfig
from django.conf import settings

class DjangoAuth0EngineConfig(AppConfig):
	"""Configuration for Django app."""
	
	name = "django_auth0_engine"
	verbose_name = "Django Auth0 Engine"

	def ready(self):
		"""Fetches package-specific constant values from settings. It looks
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
	    		Scopes that are used when AuthEngine functions are invoked
				without any scope.

			USER_DB_BACKEND (optional)
				Database backend class used by User class.

	    If any of the above information is missing, an AuthEngineError is raised.
		"""
		
		if hasattr(settings, "AUTH0_CLIENT_ID"):
			cfg._AUTH0_CLIENT_ID = settings.AUTH0_CLIENT_ID
		else:
			raise AuthEngineException.MisconfiguredEngine("AUTH0_CLIENT_ID")

		if hasattr(settings, "AUTH0_CLIENT_SECRET"):
			cfg._AUTH0_CLIENT_SECRET	= settings.AUTH0_CLIENT_SECRET
		else:
			raise AuthEngineException.MisconfiguredEngine("AUTH0_CLIENT_SECRET")

		if hasattr(settings, "AUTH0_DOMAIN"):
			cfg._AUTH0_DOMAIN							=	settings.AUTH0_DOMAIN
			cfg._AUTH0_ISSUER							=	cfg._AUTH0_ISSUER.format(cfg._AUTH0_DOMAIN)
			cfg._AUTH0_JWKS_URL							=	cfg._AUTH0_JWKS_URL.format(cfg._AUTH0_DOMAIN)
			cfg._MANAGEMENT_AUDIENCE					=	cfg._MANAGEMENT_AUDIENCE.format(cfg._AUTH0_DOMAIN)
			
			cfg.Provider.URL.Auth.token					=	cfg.Provider.URL.Auth.token.format(cfg._AUTH0_DOMAIN)
			cfg.Provider.URL.Auth.dbcon_signup			=	cfg.Provider.URL.Auth.dbcon_signup.format(
																cfg._AUTH0_DOMAIN
															)
			cfg.Provider.URL.Auth.dbcon_change_password	=	cfg.Provider.URL.Auth.dbcon_change_password.format(
																cfg._AUTH0_DOMAIN
															)
			cfg.Provider.URL.Auth.userinfo				=	cfg.Provider.URL.Auth.userinfo.format(cfg._AUTH0_DOMAIN)
			
			cfg.Provider.URL.Management.users_endpoint	=	cfg.Provider.URL.Management.users_endpoint.format(
																cfg._AUTH0_DOMAIN
															)
		else:
			raise AuthEngineException.MisconfiguredEngine("AUTH0_DOMAIN")

		if hasattr(settings, "AUTH0_AUDIENCE"):
			cfg._AUTH0_AUDIENCE		= settings.AUTH0_AUDIENCE
		elif cfg._AUTH0_CLIENT_ID:
			cfg._AUTH0_AUDIENCE		= cfg._AUTH0_CLIENT_ID
		else:
			raise AuthEngineException.MisconfiguredEngine("AUTH0_AUDIENCE")

		if hasattr(settings, "DEFAULT_SCOPES"):
			cfg._DEFAULT_SCOPES = settings.DEFAULT_SCOPES

		if hasattr(settings, "USER_DB_BACKEND"):
			cfg._USER_DB_BACKEND = settings.USER_DB_BACKEND
