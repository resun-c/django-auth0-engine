from .error import AuthEngineError

class AuthEngineExceptionBase(Exception):
	"""Custom exception base class used by other exception classes.
	
	error (str, AuthEngineError, optional):
		str is treated as an one sentence string representation of the error.
		if it's ab AuthEngineError then other attributes are acquired from it. 
		
	loc (str):
		Where the exception occured. if self.loc already exists then loc is
		prepended to that.
		
	description (str, optional):
		A short explanation of the error.
		
	"""
	def __init__(
			self,
			error:str | AuthEngineError = "",
			loc:str = "",
			description:str = "",
		) -> None:
		self.error			=	error
		self.loc			=	loc
		self.description	=	description
		self.message		=	""
		
		if isinstance(error, AuthEngineError):
			self.error = error.error
			self.description = error.description
			if error.loc:
				if loc:
					self.loc = f"{loc} / {error.loc}"
				else:
					self.loc = {error.loc}
			
			if error.message:
				self.message = error.message
		
		super().__init__(repr(self))
		
		if description:
			self.add_note(description)
			
	def __repr__(self) -> str:
		"""Returns a string summarizing the error in the format:
		"error[ at loc]. description. message."
		"""
		
		# error
		s = f"{self.error}"
		
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

class AuthEngineException(AuthEngineExceptionBase):
	"""Custom exception that is used primarily by AuthEngine.
	"""
	class MisconfiguredEngine(AuthEngineExceptionBase):
		def __init__(
				self,
				missing: str = "",
			) -> None:
			super().__init__(f"DjangoAuth0Engine is missing {missing}")
		
	class Unauthorized(AuthEngineExceptionBase):
		def __init__(self) -> None:
			super().__init__("Unauthorized Request!")
	
class ManagementEngineException(AuthEngineExceptionBase):
	"""Custom exception that is used by ManagementEngine.
	"""
	
	class AccessTokenMissing(AuthEngineExceptionBase):
		def __init__(
			self,
			loc:str,
		) -> None:
			super().__init__(
				error = f"Access Token is missing",
				loc=loc
				)
	
	class NoAccessTokenReceived(AuthEngineExceptionBase):
		def __init__(
			self,
			loc:str,
			payload
		) -> None:
			super().__init__(
				error = f"Couldn't fetch Access Token",
				loc = loc,
				description = str(payload)
			)
		