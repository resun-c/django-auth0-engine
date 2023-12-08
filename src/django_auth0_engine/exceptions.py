from typing import overload
import pprint
from auth0 import Auth0Error
from .response import AuthEngineResponse

class AuthEngineError(Exception, AuthEngineResponse):
	"""This is a custom exception class used by various methods in this module. It
	encapsulates information about the error encountered during the
	authentication process and other processes.

	Args:
		error (str, optional): A string representing the name of the error.
		
		description (str, optional): A short explanation of the error.

		**kwarg: keyword argument containing additional information about the
			error.

    """
	
	@overload
	def __init__(self) -> None:...
	@overload
	def __init__(self, error:str) -> None:...

	@overload
	def __init__(self, error:str, description:str) -> None:...

	@overload
	def __init__(self, auth0_error:Auth0Error) -> None:
		self.__init__(**(auth0_error.__dict__))

	def __init__(self, error = None, description = None, /, **kwarg) -> None: # type: ignore
		self.error:str | None					= error
		self.description:str | None				= description
		self.message:str | None					= None

		if not self.error:
			if "error_code" in kwarg:
				self.error = kwarg.pop("error_code")
			else:
				self.error = "Unknown AuthEngineError"

		if not self.description:
			self.description = "Unavailable"

		self.__dict__.update(**kwarg)
		AuthEngineResponse.__init__(self)
		Exception.__init__(self, self.__repr__())
		
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
		"error: description/message".
		"""
		description = self.description or self.message
		return f"{self.error}: {description}"
	
	def __bool__(self) -> bool:
		"""Always returns False."""
		return False