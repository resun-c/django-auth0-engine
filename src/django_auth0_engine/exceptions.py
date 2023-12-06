from typing import overload
import pprint
from auth0 import Auth0Error
from .response import AuthEngineResponse

class AuthEngineError(Exception, AuthEngineResponse):
	"""Custom exception class raised by different methods of the AuthEngine class.
	It encapsulates information about the error encountered during the
	authentication process. error is a string representing the name of the
	error. description is short explanation of the error.

    Args:
        error (str, optional): Name of the error. if not provided, kwarg is searched
			for "error" and "error_code" key and treated as the name of the error.

        description (str, optional): A description of error. if not provided,
			kwarg is searched for "error_description" and "message" key and treated as
			the description.

        kwarg (keyword arguments): Additional arguments. if a value of error is already
			provided and an "error" key with a different value exists in kwarg, then the
			value from kwarg it is held in additional_error. The same is applied for description.

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
		self.additional_error:str | None		= None
		self.additional_description:str | None	= None

		if not self.error:
			if "error" in kwarg:
				self.error = kwarg.pop("error")
			elif "error_code" in kwarg:
				self.error = kwarg.pop("error_code")
			else:
				self.error = "AuthEngineBaseError.Unknown"
		
		if not self.description:
			if "error_description" in kwarg:
				self.description = kwarg.pop("error_description")
			elif "message" in kwarg:
				self.description = kwarg.pop("message")
			else:
				self.error = "None"

		if self.error and "error" in kwarg:
			if self.error != kwarg.get("error"):
				self.additional_error = kwarg.get("error")
			kwarg.pop("error")
		if self.description and "error_description" in kwarg:
			if self.description != kwarg.get("error_description"):
				self.additional_error = kwarg.get("error_description")
			kwarg.pop("error_description")

		self.__dict__.update(**kwarg)
		AuthEngineResponse.__init__(self)
		Exception.__init__(self, self.__repr__())
		
		if self.description:
			self.add_note(self.description)
		if self.message:
			self.add_note(self.message)

	def __str__(self) -> str:
		"""Returns a formatted string with detailed information about the error
		using pprint.pformat().
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