# _class_ OIDCClaimsStruct:
An object holding all the OIDC claims. Registered claims are taken from https://datatracker.ietf.org/doc/html/rfc7519#section-4.1. Public claims are taken from https://www.iana.org/assignments/jwt/jwt.xhtml#claims

## Registered claims

### OIDCClaimsStruct.__iss__
Issuer.

### OIDCClaimsStruct.__sub__
Subject.

### OIDCClaimsStruct.__aud__
Audience.

### OIDCClaimsStruct.__exp__
Expiration Time.

### OIDCClaimsStruct.__nbf__
Not Before.

### OIDCClaimsStruct.__iat__
Issued At.

### OIDCClaimsStruct.__jti__
JWT ID.


## Public claims

### OIDCClaimsStruct.__name__
Full name.

### OIDCClaimsStruct.__given_name__
Given name(s) or first name(s).

### OIDCClaimsStruct.__family_name__
Surname(s) or last name(s).

### OIDCClaimsStruct.__middle_name__
Middle name(s).

### OIDCClaimsStruct.__nickname__
Casual name.

### OIDCClaimsStruct.__preferred_username__
Shorthand name by which the End-User wishes to be referred to.

### OIDCClaimsStruct.__profile__
Profile page URL.

### OIDCClaimsStruct.__picture__
Profile picture URL.

### OIDCClaimsStruct.__website__
Web page or blog URL.

### OIDCClaimsStruct.__email__
Preferred e-mail address.

### OIDCClaimsStruct.__email_verified__
True if the e-mail address has been verified; otherwise false.

### OIDCClaimsStruct.__gender__
Gender.

### OIDCClaimsStruct.__birthdate__
Birthday.

### OIDCClaimsStruct.__zoneinfo__
Time zone.

### OIDCClaimsStruct.__locale__
Locale.

### OIDCClaimsStruct.__phone_number__
Preferred telephone number.

### OIDCClaimsStruct.__phone_number_verified__
True if the phone number has been verified; otherwise false.

### OIDCClaimsStruct.__address__
Preferred postal address.

### OIDCClaimsStruct.__updated_at__
Time the information was last updated.

### OIDCClaimsStruct.__azp__
Authorized party - the party to which the ID Token was issued.

### OIDCClaimsStruct.__nonce__
Value used to associate a Client session with an ID Token (MAY also be used for nonce values in other applications of JWTs).

### OIDCClaimsStruct.__auth_time__
Time when the authentication occurred.

### OIDCClaimsStruct.__at_hash__
Access Token hash value.

### OIDCClaimsStruct.__c_hash__
Code hash value.

### OIDCClaimsStruct.__acr__
Authentication Context Class Reference.

### OIDCClaimsStruct.__amr__
Authentication Methods References.

### OIDCClaimsStruct.__sub_jwk__
Public key used to check the signature of an ID Token.

### OIDCClaimsStruct.__cnf__
Confirmation.

### OIDCClaimsStruct.__sip_from_tag__
SIP From tag header field parameter value.

### OIDCClaimsStruct.__sip_date__
SIP Date header field value.

### OIDCClaimsStruct.__sip_callid__
SIP Call-Id header field value.

### OIDCClaimsStruct.__sip_cseq_num__
SIP CSeq numeric header field parameter value.

### OIDCClaimsStruct.__sip_via_branch__
SIP Via branch header field parameter value.

### OIDCClaimsStruct.__orig__
Originating Identity String.

### OIDCClaimsStruct.__dest__
Destination Identity String.

### OIDCClaimsStruct.__mky__
Media Key Fingerprint String.

### OIDCClaimsStruct.__events__
Security Events.

### OIDCClaimsStruct.__toe__
Time of Event.

### OIDCClaimsStruct.__txn__
Transaction Identifier.

### OIDCClaimsStruct.__rph__
Resource Priority Header Authorization.

### OIDCClaimsStruct.__sid__
Session ID.

### OIDCClaimsStruct.__vot__
Vector of Trust value.

### OIDCClaimsStruct.__vtm__
Vector of Trust trustmark URL.

### OIDCClaimsStruct.__attest__
Attestation level as defined in SHAKEN framework.

### OIDCClaimsStruct.__origid__
Originating Identifier as defined in SHAKEN framework.

### OIDCClaimsStruct.__act__
Actor

### OIDCClaimsStruct.__scope__
Scope Values

### OIDCClaimsStruct.__client_id__
Client Identifier

### OIDCClaimsStruct.__may_act__
Authorized Actor - the party that is authorized to become the actor.

### OIDCClaimsStruct.__jcard__
jCard data.

### OIDCClaimsStruct.__at_use_nbr__
Number of API requests for which the access token can be used.

### OIDCClaimsStruct.__div__
Diverted Target of a Call.

### OIDCClaimsStruct.__opt__
Original PASSporT (in Full Form).

### OIDCClaimsStruct.__vc__
Verifiable Credential as specified in the W3C Recommendation.

### OIDCClaimsStruct.__vp__
Verifiable Presentation as specified in the W3C Recommendation.

### OIDCClaimsStruct.__sph__
SIP Priority header field.

### OIDCClaimsStruct.__ace_profile__
The ACE profile a token is supposed to be used with.

### OIDCClaimsStruct.__cnonce__
"client-nonce".  A nonce previously provided to the AS by the RS via the client. Used to verify token freshness when the RS cannot synchronize its clock with the AS.

### OIDCClaimsStruct.__exi__
"Expires in".  Lifetime of the token in seconds from the time the RS first sees it. Used to implement a weaker from of token expiration for devices that cannot synchronize their internal clocks.

### OIDCClaimsStruct.__roles__
Roles.

### OIDCClaimsStruct.__groups__
Groups.

### OIDCClaimsStruct.__entitlements__
Entitlements.

### OIDCClaimsStruct.__token_introspection__
Token introspection response.

### OIDCClaimsStruct.__ueid__
The Universal Entity ID (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__sueids__
Semi-permanent UEIDs (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__oemid__
Hardware OEM ID (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__hwmodel__
Model identifier for hardware (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__hwversion__
Hardware Version Identifier (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__secboot__
Indicate whether the boot was secure (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__dbgstat__
Indicate status of debug facilities (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__location__
The geographic location (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__eat_profile__
Indicates the EAT profile followed (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__submods__
The section containing submodules (TEMPORARY - registered 2022-03-23, extension registered 2023-02-13, expires 2024-03-23).

### OIDCClaimsStruct.__cdniv__
CDNI Claim Set Version.

### OIDCClaimsStruct.__cdnicrit__
CDNI Critical Claims Set.

### OIDCClaimsStruct.__cdniip__
CDNI IP Address.

### OIDCClaimsStruct.__cdniuc__
CDNI URI Container.

### OIDCClaimsStruct.__cdniets__
CDNI Expiration Time Setting for Signed Token Renewal.

### OIDCClaimsStruct.__cdnistt__
CDNI Signed Token Transport Method for Signed Token Renewal.

### OIDCClaimsStruct.__cdnistd__
CDNI Signed Token Depth.

### OIDCClaimsStruct.__sig_val_claims__
Signature Validation Token.

### OIDCClaimsStruct.__authorization_details__
The claim authorization_details contains a JSON array of JSON objects representing the rights of the access token. Each JSON object contains the data to specify the authorization requirements for a certain type of resource.

### OIDCClaimsStruct.__verified_claims__
This container Claim is composed of the verification evidence related to a certain verification process and the corresponding Claims about the End-User which were verified in this process.

### OIDCClaimsStruct.__place_of_birth__
A structured Claim representing the End-User's place of birth.

### OIDCClaimsStruct.__nationalities__
String array representing the End-User's nationalities.

### OIDCClaimsStruct.__birth_family_name__
Family name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the family name(s) later in life for any reason. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.

### OIDCClaimsStruct.__birth_given_name__
Given name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the given name later in life for any reason. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.

### OIDCClaimsStruct.__birth_middle_name__
Middle name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the middle name later in life for any reason. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.

### OIDCClaimsStruct.__salutation__
End-User's salutation, e.g., "Mr.".

### OIDCClaimsStruct.__title__
End-User's title, e.g., "Dr.".

### OIDCClaimsStruct.__msisdn__
End-User's mobile phone number formatted according to ITU-T recommendation [E.164].

### OIDCClaimsStruct.__also_known_as__
Stage name, religious name or any other type of alias/pseudonym with which a person is known in a specific context besides its legal name. This must be part of the applicable legislation and thus the trust framework (e.g., be an attribute on the identity card).

### OIDCClaimsStruct.__htm__
The HTTP method of the request.

### OIDCClaimsStruct.__htu__
The HTTP URI of the request (without query and fragment parts).

### OIDCClaimsStruct.__ath__
The base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value.

### OIDCClaimsStruct.__atc__
Authority Token Challenge.

### OIDCClaimsStruct.__sub_id__
Subject Identifier.

### OIDCClaimsStruct.__rcd__
Rich Call Data Information.

### OIDCClaimsStruct.__rcdi__
Rich Call Data Integrity Information.

### OIDCClaimsStruct.__crn__
Call Reason.

### OIDCClaimsStruct.__msgi__
Message Integrity Information.

### OIDCClaimsStruct.__\_claim_names__
JSON object whose member names are the Claim Names for the Aggregated and Distributed Claims.

### OIDCClaimsStruct.__\_claim_sources__
JSON object whose member names are referenced by the member values of the _claim_names member.
				
These are the methods available in a user object:

### OIDCClaimsStruct.__is_registered_claim__(key)
Determines whether or not key is a registered claim.

### OIDCClaimsStruct.__is_public_claim__(key)
Determines whether or not key is a public claim.

### OIDCClaimsStruct.__is_claim__(key)
Determines whether or not key is a OIDC claim.
