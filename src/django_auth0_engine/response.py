import pprint
from typing import Any

class AuthEngineResponse():
	"""A base class for various responses returned by different functions of
	this package. It provides a standardized way to access response data and
	check for successful operations.

	**kwarg:
		keyword argument containing information of the response.
	"""
	def __init__(self, **kwarg) -> None:
		self.access_token		:str				=	""
		self.refresh_token		:str				=	""
		self.id_token			:str				=	""
		self.token_type			:str				=	""
		self.message			:str				=	""
		self.loc				:str				=	""
		self.expires_in			:int				=	0
		self._bool				:bool				=	True
		self._token_refreshed	:bool				=	False
		self._error				:Any				=	None
		self._exception			:Exception			=	None	# type: ignore

		self.__dict__.update(**kwarg)

	def __bool__(self) -> bool:
		"""Returns the value of the private [1] variable _bool. Various
		subclasses determine the value of _bool based on the response of an
		operation. By default, _bool is initialized as False.
		"""
		return self._bool
	
	def __str__(self) -> str:
		"""
		"""
		
		if self._error:
			return str(self._error)
		elif self._exception:
			return str(self._exception)

		return str(self.message)
	
	def __repr__(self) -> str:
		"""Returns a formatted string containing all properties, including both
		public [1] and private [1] ones, of the response. The formatting utilizes the
		pprint.pformat() method.
		"""
		return pprint.pformat(self.__dict__)
	
	def __iter__(self):
		"""This method returns an iterator object, enabling iteration through the
		public [1] variables of the response instance.
		"""
		data = self.__dict__

		for key in data:
			if key[0] != '_':
				yield (key, self._safe(data[key]))

	def _safe(self, __value):
		"""Returns a safe string of __value."""
		if isinstance(__value, bytes):
			return __value.decode()
		else:
			return __value
	
	@property
	def error(self):
		return self._error
	
	@error.setter
	def error(self, __value):
		self._error	= __value
		
	@property
	def exception(self):
		return self._exception
	
	@exception.setter
	def exception(self, __value:Exception):
		self._exception	= __value
	
	def append_loc(self, __loc):
		self.loc = f"{self.loc}{f" / {__loc}" if __loc else ""}"
		
	def prepend_loc(self, __loc):
		self.loc = f"{__loc}{f" / {self.loc}" if self.loc else ""}"
	
	"""
	[1] Public and Private variables are defined here:
	https://docs.python.org/3/tutorial/classes.html#private-variables
	"""