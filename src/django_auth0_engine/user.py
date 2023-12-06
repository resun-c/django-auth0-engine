from typing import Any
from . import cfg
from .management_engine import ManagementEngine
from .oidc import OIDCClaimsStruct
from .exceptions import AuthEngineError
from .response import AuthEngineResponse

def dict_diff(new:dict[str, Any], old:dict[str, Any]) -> dict[str, Any]:
	"""This function returns a dictionary containing the differences between two
	dictionaries. It identifies key-value pairs present in new but not in old,
	as well as key-value pairs in old with different values in new.
	"""
	diff = {}
	# loop through items
	for key, val in new.items():
		# if the value is a dict recursively check the difference
		if isinstance(val, dict):
			old_val = old.get(key)
			if old_val:
				sub_diff = dict_diff(val, old_val)
				if sub_diff:
					diff[key] = sub_diff
			else:
				diff[key] = val
		# logical comparison for non dict value
		elif val != old.get(key):
			diff[key] = val
	return diff

class User(OIDCClaimsStruct, AuthEngineResponse):
	"""The User class represents a user object returned by successful
	authentication operations performed by the AuthEngine. It provides access
	to various user information and supports update functionality.

	Args:
		**kwarg: keyword arguments of user's information
	"""

	# A list of keys for attributes that can be updated in the user's
	# information through the Management API.
	UPDATABLE_ATTRIBUTES = [
		"app_metadata",
		"blocked",
		"email",
		"email_verified",
		"family_name",
		"given_name",
		"name",
		"nickname",
		"password",
		"phone_number",
		"phone_verified",
		"picture",
		"username",
		"user_metadata",
		"verify_email"
	]
	def __init__(self, **kwarg) -> None:
		super().__init__()
		AuthEngineResponse.__init__(self, **kwarg)
		self._db_backend				:Any | None		= cfg._USER_DB_BACKEND
		self._db						:Any | None		= None
		self._initial_user_dict			:dict			= {}

		self.__dict__.update(**kwarg)
		self._initial_user_dict = self.to_dict()

		self.__bool__()

	def __bool__(self) -> bool:
		"""This method checks the presence of both the access token and the ID
		token to determine if the user object represents a valid user. If any
		errors are present, it initializes an AuthEngineError object with the
		error information.
		"""
		if self.sub and self.access_token:
			self._bool = True
		
		if hasattr(self, "error"):
			self._bool = False
			self.error = AuthEngineError(**self.__dict__)
		
		return self._bool

	def __eq__(self, __user: object) -> bool:
		"""This method compares the current user object with another user object
		to determine if they represent the same user.
		"""
		if isinstance(__user, User) and hasattr(__user, "sub"):
			return self.sub == __user.sub
		return False

	@property
	def id(self):
		"""The user's unique ID (also known as "sub")."""
		if self:
			return self.sub
		return None
	
	@property
	def db(self):
		"""This property allows access to the user's data stored in the configured
		database backend.
		"""
		if not self._db and self._db_backend:
			return self._db_backend(**(self.__dict__))
		return self._db
	
	def set_db_backend(self, _db_backend_class:Any):
		"""This method sets a specific database backend for the user instance.
		This is primarily useful for scenarios involving multiple database
		backends.

		Args:
			_db_backend_class: A class that is initialized using user's sub
			(id) given through keyword arguments.
		"""
		self._db_backend = _db_backend_class
	
	def valid_user_key(self, key: str):
		"""This method checks whether a provided key is a valid user attribute key
		recognized by the Auth0 Management API.

		Args:
			key (str): Key to be checked.
		
		"""
		return key in self.UPDATABLE_ATTRIBUTES

	def validate_user_dict(self, data:dict[str, Any]):
		"""This method validates a provided dictionary of user data against the
		list of valid user attribute keys. If any invalid key is present, it
		raises an AuthEngineError exception.

		Args:
			data (dict[str, Any]): Data to be checked.
		"""
		for key in data:
			if not self.valid_user_key(key):
				raise AuthEngineError(
					error="Invalid properties in User data",
					description=f"""Additional properties not allowed: {key}.
					Consider storing them in app_metadata or user_metadata. See
					"Users Metadata" in https://auth0.com/docs/api/v2/changes
					for more details"""
				)

	def to_dict(self) -> dict:
		"""This method returns a dictionary representation of the user data,
		ensuring it contains only valid keys that can be sent for update to the
		Management API.
		"""
		data = {}
		for key in self.__dict__:
			if self.valid_user_key(key):
				data[key] = self.__dict__[key]
		return data
	
	def changed_user_data(self):
		"""This method returns a dictionary containing only the user data that
		has been changed since the object's creation or last update.
		"""
		return dict_diff(self.to_dict(), self._initial_user_dict)

	def update(self, data:dict[str, Any] | None = None) -> bool:
		"""Updates user data in the server

		Args:
			data (dict, optional): dict of data to be updated. It is validated
			before updating. If not provided, it autometically detect which
			fields have been updated and send only those fields for update to
			the server.
	
		Return:
			It returns user's state.
		"""
		# if data is given valiudate it
		if data:
			self.validate_user_dict(data)
		# get the changed data otherwise
		else:
			data = self.changed_user_data()

		# if data is not empty update
		if data:
			updated_user = ManagementEngine().update_user(self.sub, data)
			# if data is updated initialized itself with the updated data
			if updated_user:
				self.__dict__.update(updated_user.__dict__)
				self._initial_user_dict = self.to_dict()

			# upon updating check for error and set it's boolean state
		return self.__bool__()

