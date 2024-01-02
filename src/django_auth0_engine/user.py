from typing import Any
from django.http import HttpRequest
from . import cfg
from . import auth_engine as AuthEngine
from . import management_engine as ManagementEngine
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
	"""The User class represents a user registered with the Auth0 application. It
	is constructed using information returned by successful authentication
	operations performed by the AuthEngine. The User object offers various
	functionalities, including updating information on the Auth0 server and
	providing direct access to database records through a custom backend. All
	the Open ID Claims are available as property.

	Args:
		**kwarg: keyword arguments of user's information
	"""

	# A list of keys for user attributes that can be updated in the Auth0
	# server through the Management API.
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
		self.app_metadata				:dict
		self.blocked					:str
		self.email						:str
		self.email_verified				:str
		self.family_name				:str
		self.given_name					:str
		self.name						:str
		self.nickname					:str
		self.password					:str
		self.phone_number				:str
		self.phone_verified				:str
		self.picture					:str
		self.username					:str
		self.user_metadata				:dict
		self.verify_email				:str
		self._request					:HttpRequest | None		= None
		self._db_backend				:Any | None				= cfg._USER_DB_BACKEND
		self._db						:Any | None				= None
		self._initial_user_dict			:dict					= {}

		self.__dict__.update(**kwarg)
		self._initial_user_dict = self.to_dict()

		self.__bool__()

	def __bool__(self) -> bool:
		"""This method checks the sub, the access token, and the ID token to
		determine if the user object represents a valid user. If the object
		represents a valid user, it returns True; False otherwise. If an
		attribute with the name error exists in the object, it creates an
		AuthEngineError object with the error information, sets the error
		attribute to this object, and returns False.
		"""
		if self.sub and self.access_token and self.id_token:
			self._bool = True
		
		if hasattr(self, "error"):
			self._bool = False
			self.error = AuthEngineError(
					loc="User",
					**self.__dict__)
		
		return self._bool

	def __eq__(self, __user: object) -> bool:
		"""This method compares the current user object with another user object
		to determine if they represent the same user.

		Args:
			__user (User): User to compare with.

		Returns:
			True if __user is same; False otherwise.
		"""
		if isinstance(__user, User) and hasattr(__user, "sub"):
			return self.sub == __user.sub
		return False

	@property
	def id(self):
		"""The user's unique ID ("sub", according to the OIDC terminology).
		"""
		if self:
			return self.sub
		return None
	
	@property
	def db(self):
		"""This property invokes the the configured USER_DB_BACKEND with a
		reference to itself as the first argument and returns the database
		record returned by USER_DB_BACKEND
		
		See user_object documentation for details.
		"""
		if not self._db and self._db_backend:
			self._db = self._db_backend(self)
		return self._db
	
	def set_db_backend(self, _db_backend:Any):
		"""This method allows setting a different database backend for a User
		object. It is particularly useful when working with multiple user
		databases. If the user record is not found in the default user database
		backend, set the desired user database backend using this method before
		accessing the User.db property. This method assigns the _db_backend
		parameter as the database backend to the User object. Once the desired
		user database backend is set, accessing the User.db property will
		trigger the assigned backend to look up the user record.

		Args:
			_db_backend (Any): User Database Backend to set.
		"""
		self._db_backend = _db_backend
	
	def valid_user_key(self, key: str):
		"""This method checks whether a provided key is a valid user attribute key
		recognized by the Auth0 Management API.

		Args:
			key (str): key to check.
		
		Returns:
			True if key is valid; False otherwise.
		"""
		return key in self.UPDATABLE_ATTRIBUTES

	def validate_user_dict(self, data:dict[str, Any]):
		"""This method validates a provided dictionary of user data against the
		list of valid user attribute keys. 

		Args:
			data (dict): dictionary of user data to validate
		
		Raises:
			If any invalid key is present, it raises an AuthEngineError
			exception.
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
		"""This method returns a dictionary containing only the user data that has
		been changed since the object's creation or last update.
		"""
		return dict_diff(self.to_dict(), self._initial_user_dict)

	def update(self, data:dict[str, Any] | None = None) -> bool | AuthEngineResponse:
		"""This method updates the user's data on the Auth0 server. The method
		validates the provided data before updating. If no data is provided,
		it automatically detects which fields have been changed using the
		User.changed_user_data() method. Only the changed fields are sent for
		updating to the server.

		Args:
			data (dict): dictionary containing the attributes to be updated.

		Returns:
			If the update is successful, the user object is updated with the
			new data and the method returns True. If any errors occur, it
			returns the error. If there is no data to update, it simply returns
			True.
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

