import pprint

class AuthEngineResponse():
	"""
	AuthEngineResponse serves as a base class for various response objects
	returned by methods within the AuthEngine and the ManagementEngine class.
	It provides a standardized way to access response data and check for
	successful operations.
	
	Args:
		**kwarg: keyword arguments of user's information
	"""
	def __init__(self, **kwarg) -> None:
		self.access_token		:str | None
		self.refresh_token		:str | None
		self.id_token			:str | None
		self.token_type			:str | None
		self.expires_in			:int | None
		self.message			:str | None
		self._bool				:bool			=	False
		self.token_refreshed	:bool			=	False

		self.__dict__.update(**kwarg)

	def __bool__(self) -> bool:
		"""Returns the value of the private variable _bool. It's subclasses
		defines the value of _bool depending on the result of an operation.
		"""
		return self._bool
	
	def __str__(self) -> str:
		"""Returns a formatted string representing the response object. The string
		is formatted using pprint.pformat().
		"""
		return pprint.pformat(dict(self))
	
	def __repr__(self) -> str:
		"""Returns a formatted string representing all key-value pairs of the
		response. The string is formatted using pprint.pformat().
		"""
		return pprint.pformat(self.__dict__)
	
	def __iter__(self):
		"""Allows iterating over publicly accessible variables of the response
		object. (Public variables:
		https://docs.python.org/3/tutorial/classes.html#private-variables)
		"""
		data = self.__dict__

		for key in data:
			if key[0] != '_':
				yield (key, data[key])
