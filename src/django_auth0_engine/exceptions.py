from typing import overload
import pprint
from .response import AuthEngineResponse

class AuthEngineError(AuthEngineResponse, Exception):
	"""A custom exception that is used throughout this package.

	loc (str):
		Where the exception occured.
	
	error (str, optional):
		A string representing the name of the error.
		
	description (str, optional):
		A short explanation of the error.

	**kwarg:
		keyword argument containing additional information about the error.
    """
	
	@overload
	def __init__(self) -> None:...
	@overload
	def __init__(self, loc) -> None:...
	@overload
	def __init__(self, loc:str, error:str) -> None:...
	@overload
	def __init__(self, loc:str, error:str, description:str) -> None:...
	
	def __init__(self, loc = "Unknown", error = None, description = None, /, **kwarg) -> None: # type: ignore
		self.loc			:str | None				= loc
		self.error			:str | None				= error
		self.description	:str | None				= description
		self.message		:str | None				= None

		if not self.error:
			if "error_code" in kwarg:
				self.error = kwarg.pop("error_code")
			else:
				self.error = "Unknown AuthEngineError"
		error = f"{self.error} at {self.loc}"

		if not self.description:
			self.description = "Unavailable"

		# init AuthEngineResponse
		super().__init__(**kwarg)
		
		# init Exception
		super(AuthEngineResponse, self).__init__(self.__repr__())
		
		if self.description:
			self.add_note(self.description)
		if self.message:
			self.add_note(self.message)

	def __str__(self) -> str:
		"""Returns a formatted string containing all properties of the error. The
		string is formatted using pprint.pformat().
		"""
		return_dict = {}
		for key in self.__dict__:
			if self.__dict__.get(key):
				return_dict[key] = self.__dict__.get(key)

		return pprint.pformat(return_dict)
	
	def __repr__(self) -> str:
		"""Returns a string summarizing the error in the format
		"error: description/message. at: loc".
		"""
		description = self.description or self.message
		return f"{self.error}: {description}. at: {self.loc}"
	
	def __bool__(self) -> bool:
		"""Always returns False."""
		return False