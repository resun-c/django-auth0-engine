from urllib.parse import urlparse, urlencode, quote
from http.client import HTTPSConnection, HTTPConnection, HTTPResponse
import json
from typing import Any
from pprint import pprint
from django_auth0_engine.exceptions import AuthEngineError

class PdefHeader:
	# some simple header
	CONTENT_XWFU	= {"content-type": "application/x-www-form-urlencoded"}
	CONTENT_JSON	= {"content-type": "application/json"}
	ACCEPT_JSON		= {"Accept": "application/json"}

class ContentType:
	html	=	"text/html"
	plain	=	"text/plain"
	label	=	"content-type"
	json	=	"application/json"
	xwfu	=	"application/x-www-form-urlencoded"

class Response:
	def __init__(self, response:HTTPResponse) -> None:
		self._response				= response
		self.headers				= dict(self._response.getheaders())
		self.status					= self._response.status
		self.reason					= self._response.reason
		self.raw_content: bytes		= self._response.read()

	def __bool__(self) -> bool:
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
		return str(self.headers.get("Content-Type"))
	
	@property
	def length(self) -> int:
		return int(self.headers.get("Content-Length", 0))
	
	@property
	def is_json(self) -> bool:
		return ContentType.json in self.content_type

	@property
	def json(self) -> dict[str, Any]:
		"""Returns dict containing parsed json content"""
		dict = None
		if self.is_json:
			try:
				dict = json.loads(self.raw_content)
			except json.JSONDecodeError:
				pass
		# if ContentType.json in self.content_type:
		return dict # type: ignore
	
	@property
	def content(self) -> dict[str, Any] | str:
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
		if not self:
			if self.is_json:
				return AuthEngineError(**self.json)
			else:
				return AuthEngineError(loc = "Response", error = "Unknown", description = str(self.content))

class Request:
	def con_url(self, url:str,) -> tuple[HTTPConnection | HTTPSConnection, str]:
		purl = urlparse(url)
		if purl.scheme == "http" or purl.scheme == "HTTP":
			con = HTTPConnection(purl.netloc)
		else:
			con = HTTPSConnection(purl.netloc)

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

	def _get(self, url:str, headers:dict[str, str]) -> Response:
		con, curl = self.con_url(url)
		con.request("GET", url=curl, headers=headers)
		response = con.getresponse()
		return Response(response)
	
	def _post(self, url:str, headers:dict[str, str]={}, body:Any=None) -> Response:
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
		req = Request()
		return req._get(url, headers)
	
	@staticmethod
	def post(url:str, headers:dict[str, str]={}, body:Any=None) -> Response:
		req = Request()
		return req._post(url, headers, body)
	
	@staticmethod
	def patch(url:str, headers:dict[str, str]={}, body:Any=None) -> Response:
		req = Request()
		return req._patch(url, headers, body)