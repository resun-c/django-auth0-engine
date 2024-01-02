import pprint

class AuthEngineResponse():
	"""AuthEngineResponse serves as a base class for various response objects
	returned by different methods of this module. It provides a standardized
	way to access response data and check for successful operations.

	Args:
		**kwarg: keyword argument containing information of the  response.
	"""
	def __init__(self, **kwarg) -> None:
		self.access_token		:str
		self.refresh_token		:str
		self.id_token			:str
		self.token_type			:str
		self.expires_in			:int
		self.message			:str
		self._bool				:bool			=	False
		self._token_refreshed	:bool			=	False
		self.large_text			:str
		self.loc				:str

		self.__dict__.update(**kwarg)

	def __bool__(self) -> bool:
		"""Returns the value of the private [1] variable _bool. Various subclasses
		determine the value of _bool based on the outcome of an operation. Upon
		successful operation, _bool must be set to True; otherwise, it remains
		False. By default, _bool is initialized as False.
		"""
		return self._bool
	
	def __str__(self) -> str:
		"""Returns a formatted string containing all the public [1] properties of the
		response object. The formatting utilizes the pprint.pformat() method.
		"""
		return pprint.pformat(dict(self))
	
	def __repr__(self) -> str:
		"""Returns a formatted string containing all properties, including both
		public [1] and private [1] ones, of the response. The formatting utilizes the
		pprint.pformat() method.
		"""
		return pprint.pformat(self.__dict__)
	
	def __iter__(self):
		"""This method returns an iterator object, enabling iteration through the
		public [1] variables of the response object.
		"""
		data = self.__dict__

		for key in data:
			if key[0] != '_':
				yield (key, self.safe(data[key]))

	def safe(self, __value):
		if isinstance(__value, bytes):
			return __value.decode()
		else:
			return __value

	"""
	[1] Public and Private variables are defined here:
	https://docs.python.org/3/tutorial/classes.html#private-variables
	"""