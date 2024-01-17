class OIDCClaimsStruct:
	"""	Registered claims
		source: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
	"""
	iss                   :str | None		# Issuer
	sub                   :str | None		# Subject
	aud                   :str | None		# Audience
	exp                   :str | None		# Expiration Time
	nbf                   :str | None		# Not Before
	iat                   :str | None		# Issued At
	jti                   :str | None		# JWT ID

	_all_registered_claims_keys	=	["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

	"""	OIDC public claims
		source: https://www.iana.org/assignments/jwt/jwt.xhtml#claims
	"""
	name                  :str | None		# Full name
	given_name            :str | None		# Given name(s) or first name(s)
	family_name           :str | None		# Surname(s) or last name(s)
	middle_name           :str | None		# Middle name(s)
	nickname              :str | None		# Casual name
	preferred_username    :str | None		# Shorthand name by which the End-User wishes to be referred to
	profile               :str | None		# Profile page URL
	picture               :str | None		# Profile picture URL
	website               :str | None		# Web page or blog URL
	email                 :str | None		# Preferred e-mail address
	email_verified        :str | None		# True if the e-mail address has been verified; otherwise false
	gender                :str | None		# Gender
	birthdate             :str | None		# Birthday
	zoneinfo              :str | None		# Time zone
	locale                :str | None		# Locale
	phone_number          :str | None		# Preferred telephone number
	phone_number_verified :str | None		# True if the phone number has been verified; otherwise false
	address               :str | None		# Preferred postal address
	updated_at            :str | None		# Time the information was last updated
	azp                   :str | None		# Authorized party - the party to which the ID Token was issued
	nonce                 :str | None		# Value used to associate a Client session with an ID Token (MAY also be used for nonce values in other applications of JWTs)
	auth_time             :str | None		# Time when the authentication occurred
	at_hash               :str | None		# Access Token hash value
	c_hash                :str | None		# Code hash value
	acr                   :str | None		# Authentication Context Class Reference
	amr                   :str | None		# Authentication Methods References
	sub_jwk               :str | None		# Public key used to check the signature of an ID Token
	cnf                   :str | None		# Confirmation
	sip_from_tag          :str | None		# SIP From tag header field parameter value
	sip_date              :str | None		# SIP Date header field value
	sip_callid            :str | None		# SIP Call-Id header field value
	sip_cseq_num          :str | None		# SIP CSeq numeric header field parameter value
	sip_via_branch        :str | None		# SIP Via branch header field parameter value
	orig                  :str | None		# Originating Identity String
	dest                  :str | None		# Destination Identity String
	mky                   :str | None		# Media Key Fingerprint String
	events                :str | None		# Security Events
	toe                   :str | None		# Time of Event
	txn                   :str | None		# Transaction Identifier
	rph                   :str | None		# Resource Priority Header Authorization
	sid                   :str | None		# Session ID
	vot                   :str | None		# Vector of Trust value
	vtm                   :str | None		# Vector of Trust trustmark URL
	attest                :str | None		# Attestation level as defined in SHAKEN framework
	origid                :str | None		# Originating Identifier as defined in SHAKEN framework
	act                   :str | None		# Actor
	scope                 :str | None		# Scope Values
	client_id             :str | None		# Client Identifier
	may_act               :str | None		# Authorized Actor - the party that is authorized         to become the actor
	jcard                 :str | None		# jCard data
	at_use_nbr            :str | None		# Number of API requests for which the access token can be used
	div                   :str | None		# Diverted Target of a Call
	opt                   :str | None		# Original PASSporT (in Full Form)
	vc                    :str | None		# Verifiable Credential as specified in the W3C Recommendation
	vp                    :str | None		# Verifiable Presentation as specified in the W3C Recommendation
	sph                   :str | None		# SIP Priority header field
	ace_profile           :str | None		# The ACE profile a token is supposed to be used         with.
	cnonce                :str | None		# "client-nonce".  A nonce previously provided to         the AS by the RS via the client.  Used to verify token freshness         when the RS cannot synchronize its clock with the AS.
	exi                   :str | None		# "Expires in".  Lifetime of the token in seconds         from the time the RS first sees it.  Used to implement a weaker         from of token expiration for devices that cannot synchronize their         internal clocks.
	roles                 :str | None		# Roles
	groups                :str | None		# Groups
	entitlements          :str | None		# Entitlements
	token_introspection   :str | None		# Token introspection response
	ueid                  :str | None		# The Universal Entity ID (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	sueids                :str | None		# Semi-permanent UEIDs (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	oemid                 :str | None		# Hardware OEM ID (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	hwmodel               :str | None		# Model identifier for hardware (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	hwversion             :str | None		# Hardware Version Identifier (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	secboot               :str | None		# Indicate whether the boot was secure (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	dbgstat               :str | None		# Indicate status of debug facilities (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	location              :str | None		# The geographic location (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	eat_profile           :str | None		# Indicates the EAT profile followed (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	submods               :str | None		# The section containing submodules (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
	cdniv                 :str | None		# CDNI Claim Set Version
	cdnicrit              :str | None		# CDNI Critical Claims Set
	cdniip                :str | None		# CDNI IP Address
	cdniuc                :str | None		# CDNI URI Container
	cdniets               :str | None		# CDNI Expiration Time Setting for Signed Token Renewal
	cdnistt               :str | None		# CDNI Signed Token Transport Method for Signed Token Renewal
	cdnistd               :str | None		# CDNI Signed Token Depth
	sig_val_claims        :str | None		# Signature Validation Token
	authorization_details :str | None		# The claim authorization_details contains a JSON array of JSON objects representing the rights of the access token. Each JSON object contains the data to specify the authorization requirements for a certain type of resource.
	verified_claims       :str | None		# This container Claim is composed of the verification evidence related to a certain verification process and the corresponding Claims about the End-User which were verified in this process.
	place_of_birth        :str | None		# A structured Claim representing the End-User's place of birth.
	nationalities         :str | None		# String array representing the End-User's nationalities.
	birth_family_name     :str | None		# Family name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the family name(s) later in life for any reason. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
	birth_given_name      :str | None		# Given name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the given name later in life for any reason. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
	birth_middle_name     :str | None		# Middle name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the middle name later in life for any reason. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
	salutation            :str | None		# End-User's salutation, e.g., "Mr."
	title                 :str | None		# End-User's title, e.g., "Dr."
	msisdn                :str | None		# End-User's mobile phone number formatted according to ITU-T recommendation [E.164]
	also_known_as         :str | None		# Stage name, religious name or any other type of alias/pseudonym with which a person is known in a specific context besides its legal name. This must be part of the applicable legislation and thus the trust framework (e.g., be an attribute on the identity card).
	htm                   :str | None		# The HTTP method of the request
	htu                   :str | None		# The HTTP URI of the request (without query and fragment parts)
	ath                   :str | None		# The base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value
	atc                   :str | None		# Authority Token Challenge
	sub_id                :str | None		# Subject Identifier
	rcd                   :str | None		# Rich Call Data Information
	rcdi                  :str | None		# Rich Call Data Integrity Information
	crn                   :str | None		# Call Reason
	msgi                  :str | None		# Message Integrity Information
	_claim_names          :str | None		# JSON object whose member names are the Claim Names for the Aggregated and Distributed Claims
	_claim_sources        :str | None		# JSON object whose member names are referenced by the member values of the _claim_names member

	_all_public_claims_keys	=		[
			"name",
			"given_name",
			"family_name",
			"middle_name",
			"nickname",
			"preferred_username",
			"profile",
			"picture",
			"website",
			"email",
			"email_verified",
			"gender",
			"birthdate",
			"zoneinfo",
			"locale",
			"phone_number",
			"phone_number_verified",
			"address",
			"updated_at",
			"azp",
			"nonce",
			"auth_time",
			"at_hash",
			"c_hash",
			"acr",
			"amr",
			"sub_jwk",
			"cnf",
			"sip_from_tag",
			"sip_date",
			"sip_callid",
			"sip_cseq_num",
			"sip_via_branch",
			"orig",
			"dest",
			"mky",
			"events",
			"toe",
			"txn",
			"rph",
			"sid",
			"vot",
			"vtm",
			"attest",
			"origid",
			"act",
			"scope",
			"client_id",
			"may_act",
			"jcard",
			"at_use_nbr",
			"div",
			"opt",
			"vc",
			"vp",
			"sph",
			"ace_profile",
			"cnonce",
			"exi",
			"roles",
			"groups",
			"entitlements",
			"token_introspection",
			"ueid",
			"sueids",
			"oemid",
			"hwmodel",
			"hwversion",
			"secboot",
			"dbgstat",
			"location",
			"eat_profile",
			"submods",
			"cdniv",
			"cdnicrit",
			"cdniip",
			"cdniuc",
			"cdniets",
			"cdnistt",
			"cdnistd",
			"sig_val_claims",
			"authorization_details",
			"verified_claims",
			"place_of_birth",
			"nationalities",
			"birth_family_name",
			"birth_given_name",
			"birth_middle_name",
			"salutation",
			"title",
			"msisdn",
			"also_known_as",
			"htm",
			"htu",
			"ath",
			"atc",
			"sub_id",
			"rcd",
			"rcdi",
			"crn",
			"msgi",
			"_claim_names",
			"_claim_sources"
		]

	@staticmethod
	def is_registered_claim(key) -> bool:
		"""Determines whether or not key is a registered claim.
		"""
		return key in OIDCClaimsStruct._all_registered_claims_keys

	@staticmethod
	def is_public_claim(key) -> bool:
		"""Determines whether or not key is a public claim.
		"""
		return key in OIDCClaimsStruct._all_public_claims_keys

	@staticmethod
	def is_claim(key) -> bool:
		"""Determines whether or not key is a OIDC claim.
		"""
		return OIDCClaimsStruct.is_registered_claim(key) or OIDCClaimsStruct.is_public_claim(key)