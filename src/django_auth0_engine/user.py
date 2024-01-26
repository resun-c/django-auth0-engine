"""Support to access and manage users.
"""

from math import fabs
from typing import Any
from django.http import HttpRequest
from . import cfg
from . import auth_engine as AuthEngine
from . import management_engine as ManagementEngine
from .oidc import OIDCClaimsStruct
from .exceptions import AuthEngineError
from .response import AuthEngineResponse
import copy

def _dict_diff(new:dict[str, Any], old:dict[str, Any]) -> dict[str, Any]:
	"""Helper function to compare two dict and get the difference between old
	and new.
	"""
	diff = {}
	# loop through items
	for key, val in new.items():
		# if the value is a dict recursively check the difference
		if isinstance(val, dict):
			old_val = old.get(key)
			if old_val:
				sub_diff = _dict_diff(val, old_val)
				if sub_diff:
					diff[key] = sub_diff
			else:
				diff[key] = val
		# logical comparison for non dict value
		elif val != old.get(key):
			diff[key] = val
	return diff

class User(OIDCClaimsStruct, AuthEngineResponse):
	"""Class to access and manage a user. Each instance represents a registered
	user and is constructed from information returned by successful
	authentication.

	**kwarg:
		keyword arguments of user's information
	"""

	# A list of keys for user attributes that can be updated in the Auth0
	# server through the Management API.
	UPDATABLE_ATTRIBUTES = {
		"blocked":				{"type": bool},
		"email_verified":		{"type": bool},
		"email":				{"type": str},
		"phone_number":			{"type": str},
		"phone_verified":		{"type": bool},
		"user_metadata":		{"type": dict},
		"app_metadata":			{"type": dict},
		"given_name":			{"type": str,	"length":	lambda s: len(s) >= 1 and len(s) <= 150},
		"family_name":			{"type": str,	"length":	lambda s: len(s) >= 1 and len(s) <= 150},
		"name":					{"type": str,	"length":	lambda s: len(s) >= 1 and len(s) <= 300},
		"nickname":				{"type": str,	"length":	lambda s: len(s) >= 1 and len(s) <= 300},
		"picture":				{"type": str},
		"verify_email":			{"type": bool},
		"verify_phone_number":	{"type": bool},
		"password":				{"type": str},
		"connection":			{"type": str},
		"client_id":			{"type": str},
		"username":				{"type": str,	"length":	lambda s: len(s) >= 1 and len(s) <= 128},
	}
	
	def __init__(self, **kwarg) -> None:
		self.blocked					:bool			=	False
		self.email_verified				:bool			=	False
		self.email						:str | None		=	None
		self.phone_number				:str | None		=	None
		self.phone_verified				:bool			=	False
		self.user_metadata				:dict			=	{}
		self.app_metadata				:dict			=	{}
		self.given_name					:str | None		=	None
		self.family_name				:str | None		=	None
		self.name						:str | None		=	None
		self.nickname					:str | None		=	None
		self.picture					:str | None		=	None
		self.verify_email				:bool			=	False
		self.verify_phone_number		:bool			=	False
		self.password					:str | None		=	None
		self.connection					:str | None		=	None
		self.client_id					:str | None		=	None
		self.username					:str | None		=	None
		self.user_id					:str | None		=	None
		
		# init AuthEngineResponse
		super(OIDCClaimsStruct, self).__init__(**kwarg)

		self._request					:HttpRequest | None		= None
		self._db_backend				:Any | None				= cfg._USER_DB_BACKEND
		self._db						:Any | None				= None
		self._initial_user_dict			:dict					= {}

		self.__dict__.update(**kwarg)
		
		# staticmethod get provides user_id not sub
		if hasattr(self, "user_id") and not hasattr(self, "sub"):
			self.sub = self.user_id
		
		self._initial_user_dict = self.to_dict()

		self.__bool__()

	def __bool__(self) -> bool:
		"""Returns true if a sub, an access token, and an ID token exist in an
		instance. The existence of those properties indicates a registered
		user.
		"""
		if (			# for User initialized from openid informations
				hasattr(self, "sub")
				and hasattr(self, "access_token")
	  			and hasattr(self, "id_token")
			) or (		# for User initialized from management users endpoint
				hasattr(self, "user_id")
				and hasattr(self, "user_id")
			):
			self._bool = True
		
		return self._bool

	def __eq__(self, __user: object) -> bool:
		"""This method compares the current user instance with another user
		instance to determine if they represent the same user.

		__user (User):
			User to compare with.
		"""
		if isinstance(__user, User) and hasattr(__user, "sub"):
			return self.sub == __user.sub
		return False
	
	@property
	def db(self):
		"""Retrieves and returns the user's database record by invoking the
		specified database backend.

		By default, USER_DB_BACKEND is used as the database backend.
		
		See the user_class documentation for details.
		"""
		if not self._db and self._db_backend:
			self._db = self._db_backend(self)
		return self._db
	
	@staticmethod
	def get(sub):
		"""Gets a user's information and constructs a User object."""
		if response := ManagementEngine.get_user(sub):
			u = User(**response.__dict__)
			u._bool = True					# set _bool manually as u doesn't have access_token and id_token
			return u
		return User()
	
	def set_db_backend(self, _db_backend:Any):
		"""Sets a database backend for a User instance.

		By default, the USER_DB_BACKEND is used to retrieve the database record
		of a User. This method sets a different database backend for a User
		instance.

		_db_backend (Any):
			User Database Backend to set.
		"""
		self._db_backend = _db_backend
	
	def valid_user_key(self, key: str) -> bool:
		"""Returns whether or not the key is a valid user attribute key
		recognized by the Auth0 Management API.

		key (str):
			key to check.
		"""
		return key in self.UPDATABLE_ATTRIBUTES

	def validate_user_dict(self, data:dict[str, Any]) -> None:
		"""Validates a dict of user data against the list of valid user
		attribute keys. If any invalid key is present, an AuthEngineError
		exception is raised.

		data (dict):
			dict of user data to validate
		"""
		for key in data:
			if not self.valid_user_key(key):
				raise AuthEngineError(
					loc="User.validate_user_dict",
					error="Invalid properties in User data",
					description=f"""Additional properties not allowed: {key}.
					Consider storing them in app_metadata or user_metadata. See
					"Users Metadata" in https://auth0.com/docs/api/v2/changes
					for more details"""
				)

	def to_dict(self) -> dict:
		"""Returns a dict consisting of the Auth0 Management API-specific user
		attributes.
		"""
		data = {}
		for key in self.__dict__:
			if self.valid_user_key(key):
				data[key] = copy.deepcopy(self.__dict__[key])
		return data
	
	def changed_user_data(self):
		"""Returns a dict containing the user attributes that have been changed
		since the instance creation or last update.
		"""
		return _dict_diff(self.to_dict(), self._initial_user_dict)

	def update(self, data:dict[str, Any] | None = None) -> bool | AuthEngineResponse:
		"""Updates user attributes on the Auth0 server. It validates the
		provided data before updating. If no data is provided, it automatically
		detects which fields have been changed and updates only those fields.
		Returns an AuthEngineError instance if unable to update.

		data (dict):
			dict containing the attributes to be updated.
		"""
		# if data is given valiudate it
		if data:
			self.validate_user_dict(data)
		# get the changed data otherwise
		else:
			data = self.changed_user_data()

		# if data is not empty update
		if data:
			updated_user = ManagementEngine.update_user(self.sub, data)
			# if data is updated initialized itself with the updated data
			if updated_user:
				# refresh the access token
				refreshed_user = AuthEngine.refresh_access_token(self._request, self.refresh_token)
				# update updated_user with new data receved after refreshing the access token
				updated_user.__dict__.update(dict(refreshed_user))
				# update the instance itself with the data of updated_user
				self.__dict__.update(dict(updated_user))
				# set new _initial_user_dict
				self._initial_user_dict = self.to_dict()
				return True
			else:
				return updated_user

		# Not data to updated
		return True

