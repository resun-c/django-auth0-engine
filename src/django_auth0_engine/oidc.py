class OIDCClaimsStruct:
	def __init__(self) -> None:
		"""	Registered claims
			source: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
		"""
		self.iss                   :str | None		# Issuer
		self.sub                   :str | None		# Subject
		self.aud                   :str | None		# Audience
		self.exp                   :str | None		# Expiration Time
		self.nbf                   :str | None		# Not Before
		self.iat                   :str | None		# Issued At
		self.jti                   :str | None		# JWT ID

		self._all_registered_claims_keys	=	["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

		"""	OIDC public claims
			source: https://www.iana.org/assignments/jwt/jwt.xhtml#claims
		"""
		self.name                  :str | None		# Full name
		self.given_name            :str | None		# Given name(s) or first name(s)
		self.family_name           :str | None		# Surname(s) or last name(s)
		self.middle_name           :str | None		# Middle name(s)
		self.nickname              :str | None		# Casual name
		self.preferred_username    :str | None		# Shorthand name by which the End-User wishes to be referred to
		self.profile               :str | None		# Profile page URL
		self.picture               :str | None		# Profile picture URL
		self.website               :str | None		# Web page or blog URL
		self.email                 :str | None		# Preferred e-mail address
		self.email_verified        :str | None		# True if the e-mail address has been verified; otherwise false
		self.gender                :str | None		# Gender
		self.birthdate             :str | None		# Birthday
		self.zoneinfo              :str | None		# Time zone
		self.locale                :str | None		# Locale
		self.phone_number          :str | None		# Preferred telephone number
		self.phone_number_verified :str | None		# True if the phone number has been verified; otherwise false
		self.address               :str | None		# Preferred postal address
		self.updated_at            :str | None		# Time the information was last updated
		self.azp                   :str | None		# Authorized party - the party to which the ID Token was issued
		self.nonce                 :str | None		# Value used to associate a Client session with an ID Token (MAY also be used for nonce values in other applications of JWTs)
		self.auth_time             :str | None		# Time when the authentication occurred
		self.at_hash               :str | None		# Access Token hash value
		self.c_hash                :str | None		# Code hash value
		self.acr                   :str | None		# Authentication Context Class Reference
		self.amr                   :str | None		# Authentication Methods References
		self.sub_jwk               :str | None		# Public key used to check the signature of an ID Token
		self.cnf                   :str | None		# Confirmation
		self.sip_from_tag          :str | None		# SIP From tag header field parameter value
		self.sip_date              :str | None		# SIP Date header field value
		self.sip_callid            :str | None		# SIP Call-Id header field value
		self.sip_cseq_num          :str | None		# SIP CSeq numeric header field parameter value
		self.sip_via_branch        :str | None		# SIP Via branch header field parameter value
		self.orig                  :str | None		# Originating Identity String
		self.dest                  :str | None		# Destination Identity String
		self.mky                   :str | None		# Media Key Fingerprint String
		self.events                :str | None		# Security Events
		self.toe                   :str | None		# Time of Event
		self.txn                   :str | None		# Transaction Identifier
		self.rph                   :str | None		# Resource Priority Header Authorization
		self.sid                   :str | None		# Session ID
		self.vot                   :str | None		# Vector of Trust value
		self.vtm                   :str | None		# Vector of Trust trustmark URL
		self.attest                :str | None		# Attestation level as defined in SHAKEN framework
		self.origid                :str | None		# Originating Identifier as defined in SHAKEN framework
		self.act                   :str | None		# Actor
		self.scope                 :str | None		# Scope Values
		self.client_id             :str | None		# Client Identifier
		self.may_act               :str | None		# Authorized Actor - the party that is authorized         to become the actor
		self.jcard                 :str | None		# jCard data
		self.at_use_nbr            :str | None		# Number of API requests for which the access token can be used
		self.div                   :str | None		# Diverted Target of a Call
		self.opt                   :str | None		# Original PASSporT (in Full Form)
		self.vc                    :str | None		# Verifiable Credential as specified in the W3C Recommendation
		self.vp                    :str | None		# Verifiable Presentation as specified in the W3C Recommendation
		self.sph                   :str | None		# SIP Priority header field
		self.ace_profile           :str | None		# The ACE profile a token is supposed to be used         with.
		self.cnonce                :str | None		# "client-nonce".  A nonce previously provided to         the AS by the RS via the client.  Used to verify token freshness         when the RS cannot synchronize its clock with the AS.
		self.exi                   :str | None		# "Expires in".  Lifetime of the token in seconds         from the time the RS first sees it.  Used to implement a weaker         from of token expiration for devices that cannot synchronize their         internal clocks.
		self.roles                 :str | None		# Roles
		self.groups                :str | None		# Groups
		self.entitlements          :str | None		# Entitlements
		self.token_introspection   :str | None		# Token introspection response
		self.ueid                  :str | None		# The Universal Entity ID (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.sueids                :str | None		# Semi-permanent UEIDs (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.oemid                 :str | None		# Hardware OEM ID (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.hwmodel               :str | None		# Model identifier for hardware (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.hwversion             :str | None		# Hardware Version Identifier (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.secboot               :str | None		# Indicate whether the boot was secure (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.dbgstat               :str | None		# Indicate status of debug facilities (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.location              :str | None		# The geographic location (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.eat_profile           :str | None		# Indicates the EAT profile followed (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.submods               :str | None		# The section containing submodules (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23)
		self.cdniv                 :str | None		# CDNI Claim Set Version
		self.cdnicrit              :str | None		# CDNI Critical Claims Set
		self.cdniip                :str | None		# CDNI IP Address
		self.cdniuc                :str | None		# CDNI URI Container
		self.cdniets               :str | None		# CDNI Expiration Time Setting for Signed Token Renewal
		self.cdnistt               :str | None		# CDNI Signed Token Transport Method for Signed Token Renewal
		self.cdnistd               :str | None		# CDNI Signed Token Depth
		self.sig_val_claims        :str | None		# Signature Validation Token
		self.authorization_details :str | None		# The claim authorization_details contains a JSON array of JSON objects representing the rights of the access token. Each JSON object contains the data to specify the authorization requirements for a certain type of resource.
		self.verified_claims       :str | None		# This container Claim is composed of the verification evidence related to a certain verification process and the corresponding Claims about the End-User which were verified in this process.
		self.place_of_birth        :str | None		# A structured Claim representing the End-User's place of birth.
		self.nationalities         :str | None		# String array representing the End-User's nationalities.
		self.birth_family_name     :str | None		# Family name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the family name(s) later in life for any reason. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
		self.birth_given_name      :str | None		# Given name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the given name later in life for any reason. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
		self.birth_middle_name     :str | None		# Middle name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the middle name later in life for any reason. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
		self.salutation            :str | None		# End-User's salutation, e.g., "Mr."
		self.title                 :str | None		# End-User's title, e.g., "Dr."
		self.msisdn                :str | None		# End-User's mobile phone number formatted according to ITU-T recommendation [E.164]
		self.also_known_as         :str | None		# Stage name, religious name or any other type of alias/pseudonym with which a person is known in a specific context besides its legal name. This must be part of the applicable legislation and thus the trust framework (e.g., be an attribute on the identity card).
		self.htm                   :str | None		# The HTTP method of the request
		self.htu                   :str | None		# The HTTP URI of the request (without query and fragment parts)
		self.ath                   :str | None		# The base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value
		self.atc                   :str | None		# Authority Token Challenge
		self.sub_id                :str | None		# Subject Identifier
		self.rcd                   :str | None		# Rich Call Data Information
		self.rcdi                  :str | None		# Rich Call Data Integrity Information
		self.crn                   :str | None		# Call Reason
		self.msgi                  :str | None		# Message Integrity Information
		self._claim_names          :str | None		# JSON object whose member names are the Claim Names for the Aggregated and Distributed Claims
		self._claim_sources        :str | None		# JSON object whose member names are referenced by the member values of the _claim_names member

		self._all_public_claims_keys	=		[
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

	def is_registered_claim(self, key) -> bool:
		"""Determines whether or not key is a registered claim.
		"""
		return key in self._all_registered_claims_keys

	def is_public_claim(self, key) -> bool:
		"""Determines whether or not key is a public claim.
		"""
		return key in self._all_public_claims_keys

	def is_claim(self, key) -> bool:
		"""Determines whether or not key is a OIDC claim.
		"""
		return (self.is_registered_claim(key) or self.is_public_claim(key))