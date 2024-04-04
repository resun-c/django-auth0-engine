from .response import AuthEngineResponse

class AuthEngineError(AuthEngineResponse):
	"""A subclass of AuthEngineResponse that represents an error.

	error (str, optional):
		An one sentence string representation of the error.
		
	loc (str):
		Where the exception occured.
		
	description (str, optional):
		A short explanation of the error.
		
	exception (Exception, optional):
		The exception if any that caused the error.

	**kwarg:
		keyword argument containing additional information about the error.
    """
	
	def __init__(
			self,
			error:str = "",
			loc:str  = "",
			description:str = "",
			exception:Exception = None, # type: ignore
			/, **kwarg
		) -> None: # type: ignore
		super().__init__()
		
		self.loc			:str				=	loc
		self.error								=	error
		self.description	:str				=	description
		self.exception							=	exception
		
		# error key in kwarg, and no explicite error is provided
		if "error" in kwarg:
			if not self.error:
				self.error = str(kwarg.pop("error"))	# error may not be str
			else:
				self.error_1 = str(kwarg.pop("error"))	# store it as a successive error
		
		# if kwarg has loc add it at the end of loc
		if "loc" in kwarg and self.loc:
			self.loc = f"{self.loc} / {kwarg.pop("loc")}"
		
		# if error is not provided and error_code exists in error, treat is as the error.
		if not self.error:
			if "error_code" in kwarg:
				self.error = str(kwarg.pop("error_code"))	# error_code are usually int
			else:
				self.error = "Unknown"
		
		self.__dict__.update(**kwarg)
		
		# if both description and message is unavailable then description is "Unavailable"
		# if not self.description and not self.message:
		# 	self.description = "Unavailable"
			
		# if error is missing and exception is given str(exception) is the error
		if not self.error and self.exception:
			self.error = str(self.exception)
		
		# if exception has loc add it at the end of loc
		if hasattr(exception, "loc"):
			if self.loc:
				self.loc = f"{self.loc} / {exception.__getattribute__("loc")}"
			else:
				self.loc = exception.__getattribute__("loc")
	
	def __str__(self) -> str:
		return repr(self)
	
	def __repr__(self) -> str:
		"""Returns a string summarizing the error in the format:
		"error[ caused by exception][ at loc]. description. message."
		"""
		
		# error
		s = f"{self.error}"
		
		# exception
		if self.exception:
			s += f" caused by {str(self.exception)}"
		
		# loc
		if self.loc:
			s += f" at {self.loc}"
		
		# period ofter error[ exception][ loc]
		s += "."
		
		# description
		if self.description:
			s += f" {self.description}{"." if self.description[-1] != "." else ""}"
		
		# message
		if self.message:
			s += f" {self.message}{"." if self.message[-1] != "." else ""}"
		
		return s
	
	def __bool__(self) -> bool:
		"""AuthEngineError is always False."""
		return False
