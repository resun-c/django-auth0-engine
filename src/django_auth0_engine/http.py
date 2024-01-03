from urllib.parse import urlparse, urlencode, quote
from http.client import HTTPSConnection, HTTPConnection, HTTPResponse
import json
from typing import Any
from pprint import pprint
from django_auth0_engine.exceptions import AuthEngineError

class PdefHeader:
	"""Some Predefined HTTP Headers."""
	
	CONTENT_XWFU	= {"content-type": "application/x-www-form-urlencoded"}
	CONTENT_JSON	= {"content-type": "application/json"}
	ACCEPT_JSON		= {"Accept": "application/json"}

class ContentType:
	"""Some HTTP Content Types."""

	html	=	"text/html"
	plain	=	"text/plain"
	label	=	"content-type"
	json	=	"application/json"
	xwfu	=	"application/x-www-form-urlencoded"

class Response:
	"""Represents a HTTP Response."""

	def __init__(self, response:HTTPResponse) -> None:
		self._response				= response
		self.headers				= dict(self._response.getheaders())
		self.status					= self._response.status
		self.reason					= self._response.reason
		self.raw_content: bytes		= self._response.read()

	def __bool__(self) -> bool:
		"""Whether or not it's a successful response."""
		if self.status >= 200 and self.status < 300:
			return True
		
		return False
	
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
				yield (key, data[key])
	
	@property
	def content_type(self) -> str:
		"""The content type of the response."""
		return str(self.headers.get("Content-Type"))
	
	@property
	def length(self) -> int:
		"""The length of the returned content."""
		return int(self.headers.get("Content-Length", 0))
	
	@property
	def is_json(self) -> bool:
		"""Whether or not the returned content is in JSON format."""
		return ContentType.json in self.content_type

	@property
	def json(self) -> Any:
		"""Returns dict containing parsed json content."""
		dict = None
		if self.is_json:
			try:
				dict = json.loads(self.raw_content)
			except json.JSONDecodeError:
				pass
		# if ContentType.json in self.content_type:
		return dict # type: ignore
	
	@property
	def content(self) -> Any:
		"""Returns the content in the format defined by "Content-Type" header.

		If Content-Type is JSON, the parsed JSON is returned. IF it's plain
		text or html, the ASCII decoded string is returned.
		"""
		match self.content_type:
			case ContentType.json:
				return self.json
			case ContentType.plain:
				return str(self.raw_content.decode())
			case ContentType.html:
				return str(self.raw_content.decode())
			case _:
				return str(self.raw_content.decode())

	@property
	def error(self):
		"""If any Error is encountered, it is returned as an AuthEngineError
		instance.
		"""
		if not self:
			if self.is_json:
				return AuthEngineError(**self.json)
			else:
				return AuthEngineError(loc = "Response", error = "Unknown", description = str(self.content))
			
	
	
	"""
	[1] Public and Private variables are defined here:
	https://docs.python.org/3/tutorial/classes.html#private-variables
	"""

class Request:
	"""This class make HTTP/HTTPS requests by employing
	http.client.HTTPConnection/http.client.HTTPSConnection and returns the
	response as an instance of Response.
	"""
	
	def con_url(self, url:str,) -> tuple[HTTPConnection | HTTPSConnection, str]:
		"""Returns a tuple consisting of an HTTPConnection/HTTPSConnection
		instance and the URL to be used by that connection.
		"""
		# parsed url
		purl = urlparse(url)

		if purl.scheme == "http" or purl.scheme == "HTTP":
			con = HTTPConnection(purl.netloc)
		else:
			con = HTTPSConnection(purl.netloc)

		# construct the url
		if purl.path and purl.params and purl.query and purl.fragment:
			curl = f"{purl.path};{purl.params}?{purl.query}#{purl.fragment}"
		elif purl.path and purl.params and purl.query:
			curl = f"{purl.path};{purl.params}?{purl.query}"
		elif purl.path and purl.params:
			curl = f"{purl.path};{purl.params}"
		elif purl.path:
			curl = f"{purl.path}"
		else:
			curl = ""
		
		return (con, curl)
	
	def make_body(self, headers:dict[str, str], body:Any):
		"""Constructs suitable body for HTTP/HTTPS request based on the
		content-type header. If content-type header is not present,
		application/x-www-form-urlencoded is used as content type. Returns the
		body.
		"""
		if ContentType.label not in headers:
			headers[ContentType.label] = ContentType.xwfu

		if isinstance(body, str):
			return body
		
		match headers[ContentType.label]:
			case ContentType.xwfu:
				return urlencode(body, quote_via=quote)
			case ContentType.json:
				return json.dumps(body)
			case _:
				return body

	def _get(self, url:str, headers:dict[str, str]={}) -> Response:
		"""Makes a HTTP GET request and returns the response as a Response
		instance.
		"""
		con, curl = self.con_url(url)
		con.request("GET", url=curl, headers=headers)
		response = con.getresponse()
		return Response(response)
	
	def _post(self, url:str, headers:dict[str, str]={}, body:Any=None) -> Response:
		"""Makes a HTTP POST request and returns the response as a Response
		instance.
		"""
		con, curl = self.con_url(url)
		con.request(
			"POST",
			url=curl,
			body=self.make_body(headers, body),
			headers=headers
		)
		response = con.getresponse()
		return Response(response)

	def _patch(self, url:str, headers:dict[str, str]={}, body:Any=None) -> Response:
		"""Makes a HTTP PATCH request and returns the response as a Response
		instance.
		"""
		con, curl = self.con_url(url)
		con.request(
			"PATCH",
			url=curl,
			body=self.make_body(headers, body),
			headers=headers
		)
		response = con.getresponse()
		return Response(response)
	
	@staticmethod
	def get(url:str, headers:dict[str, str]={}) -> Response:
		"""An Alias staticmethod for _get that creates the Request itself."""
		req = Request()
		return req._get(url, headers)
	
	@staticmethod
	def post(url:str, headers:dict[str, str]={}, body:Any=None) -> Response:
		"""An Alias staticmethod for _post that creates the Request itself."""
		req = Request()
		return req._post(url, headers, body)
	
	@staticmethod
	def patch(url:str, headers:dict[str, str]={}, body:Any=None) -> Response:
		"""An Alias staticmethod for _patch that creates the Request itself."""
		req = Request()
		return req._patch(url, headers, body)