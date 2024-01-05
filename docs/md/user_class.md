# User Class

The User class is the basic element for accessing and managing a user. It
is somewhat identical to the standard Django User Model. It has extended
features to take advantage of OIDC and Auth0 technologies.

### User Database Interaction

For a lightweight representation, a User instance is constructed only
from OpenID Connect (OIDC) information obtained from Auth0 ID tokens.
Though not implemented by default, it provides database integration
functionalities through a User Database Backend.

### User Database Backend

User Database Backends are functions or classes that, when invoked with
a User instance as the first argument, search a database with necessary
user attributes and retrieve the record of that user. After retrieval,
it can return that record as an object or any other data type.


To use database interaction, assign a User Database Backend to the
USER_DB_BACKEND variable in settings (see the Writing User Database Backend
section below). Then access the user's database record through the User.db
property in your code.

Here's an example:

in settings.py

```
USER_DB_BACKEND = UserFirestore		# see the Writing User Database Backend
									# section bellow
```

in views.py

```
def home(request):
	user = request.user
	if user:
		user_record = user.db		# user_record is an instance of
									# UserFirestore that represents the
									# document of the user in Firestore
		...
	else:
		# unauthorized
		...
```

## Writing User Database Backend

A User Database Backend can be a function or a class that takes a Django
Auth0 Engine User instance as the first argument and returns the user's
database record as an object or any other data type.

Here are some examples of User Database Backends:

### 1. UserFirestore

This database backend uses Firestore to store user data. It treats each
document in a Firestore collection (USER_COLL) as the record of a user.
Each document is identified uniquely by the id (sub) of a User instance.

```
class UserFirestore():
	def __init__(self, user) -> None:
		self.id     = user.sub		# id of the user
		self.ref    = None			# Firestore document reference
		self.snap   = None			# Firestore document snapshot
		self.data   = {}			# Firestore document data as dict

		# if no sub/id is provided do nothing
		if self.id:
			self.ref    = USER_COLL.document(self.id)
			self.snap   = self.ref.get()
			data        = self.snap.to_dict()
			if data:
				self.data |= data

	# to check if successfully retrieved data
	def __bool__(self) -> bool:
		# no id, ref and snap means no data
		return bool(self.id and self.ref and self.snap)

	# updates user's data
	def update(self):
		if self:
			return self.ref.set(self.data)

```

As UserFirestore retrieves the user record in initialization, you can
directly assign it to USER_DB_BACKEND. Again, initializing UserFirestore
works fine for new users as Firestore automatically creates a document when
no document exists with an ID (in this case, it is User.sub which is unique
for every user).

### 2. UserModel

This database backend uses Django Models. sub is the primary key for the
database table.

Note: 32 chars for the sub field is enough per this remark:
https://community.auth0.com/t/is-256-a-safe-max-length-for-a-user-id/34040/7

```
class UserModel(models.Model):
	# primary_key = True set sub as the primary key for the table
	sub = models.CharField(max_length=32, primary_key = True)
	...

	# given a User instance as the first argument retrieve the record of
	#the user
	@staticmethod
	def retrieve(user):
		record = None
		# if user is provided return None
		if user:
			record = UserModel.objects.get(pk=user.sub)

		return record
```

UserModel does not retrieve a user record in initialization (doing so would
harm the functionality of the Model class). So, it can not be directly
assigned to USER_DB_BACKEND. The UserModel.retrieve() static method
retrieves the user record and can be assigned USER_DB_BACKEND. When a User
instance calls the retrieve() method it returns a UserModel instance.

One drawback of the retrieve() method is that, for a new user, it does not
create a database record. You could, however, modify the method so that it
creates a record when no existing record was found. Here's a modified
version of the retrieve method that does so:

```
@staticmethod
def retrieve(user):
	record = None
	# if user is provided return None
	if user:
		record = UserModel.objects.get(pk=user.sub)
		# if no user record was found create one
		if not record:
			record = UserModel(sub = user.sub)
			record.save()
	return record
	
```