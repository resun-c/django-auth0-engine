# User object

The User object is a fundamental element of the Django Auth0 Engine and
plays a critical role in user management within your application. It
resembles the standard Django User object but extends its capabilities
specifically by leveraging OIDC and Auth0 technologies.

### User Database Interaction

The User object in Django Auth0 Engine is built using OpenID Connect
(OIDC) information obtained from Auth0 ID tokens. This allows for a
lightweight representation of the user without requiring database
interaction by default. However, the User object provides
functionalities for integrating database interaction through a User
Database Backend.

### User Database Backend

User Database Backends are functions or classes that, when invoked with
a User object as the first argument, search a database with necessary
user attributes and retrieve the record. After retrieval, it can return
that record as an object or any other data type.


To use database interaction, assign a User Database Backend to the
USER_DB_BACKEND variable in settings (see the Writing User Database Backend
section bellow). Then access the user's database record through the User.db
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

# Writing User Database Backend

A User Database Backend works as follows:

1. Receive a User object as the first argument, containing user attributes like email, username, and ID.

2. Search a database for a matching user record using the attributes of the User object (e.g., id or username).
		
3. If a match is found, retrieve the user's data (e.g., application specific information) and return it.

### Here are some example User Database Backend:

## 1. UserFirestore

This database backend utilizes Firestore as the underlying storage solution
for user data in your Django application. It leverages Firestore
collections and documents to represent user information efficiently. It
utilizes the dedicated collection (FIRESTORE_USER_COLLECTION) where each
document represents a single user, identified uniquely by their sub (ID)
obtained from Auth0.

```
class UserFirestore():
	def __init__(self, user) -> None:
		self.id     = user.sub		# id of the user
		self.ref    = None			# Firestore document reference
		self.snap   = None			# Firestore document snapshot
		self.data   = {}			# Firestore document data as dict

		# if no sub/id is provided do nothing
		if self.id:
			self.ref    = FIRESTORE_USER_COLLECTION.document(self.id)
			self.snap   = self.ref.get()
			data        = self.snap.to_dict()
			if data:
				self.data |= data

	# to check if successfully retrieved data
	def __bool__(self) -> bool:
		# no id represents no data
		return bool(self.id and self.ref and self.snap)

	# updates user's data
	def update(self):
		if self:
			return self.ref.set(self.data)
```

As UserFirestore retrieves user record using User.sub in initialization,
you can directly assign UserFirestore to USER_DB_BACKEND. Again,
initializing UserFirestore works fine for new user as Firestore
automatically creates a document when there exists no document with an ID
(in this case, it is User.sub which is unique for every user).

## 2. UserModel

This database backend uses Django Models. sub is the primary key for the
database table.

Note: 32 chars for the sub field is enough per this remark:
https://community.auth0.com/t/is-256-a-safe-max-length-for-a-user-id/34040/7

```
class UserModel(models.Model):
	# primary_key = True set sub as the primary key for the table
	sub = models.CharField(max_length=32, primary_key = True)
	...

	# given a User object as the first argument retrieve record of the user
	@staticmethod
	def retrieve(user):
		record = None
		# if user is provided return None
		if user:
			record = UserModel.objects.get(pk=user.sub)

		return record
```

UserModel does not retrieve user record in initialization (doing so would
harm the functionality of the Model class). So, you can not directly assign
UserModel to USER_DB_BACKEND. The UserModel.retrieve() static method helps
here. You can assign UserModel.retrieve() to USER_DB_BACKEND. When the User
object call UserModel.retrieve() with a reference to itself, the
UserModel.retrieve() method returns an UserModel instance representing the
user record in the database table.

One drawback of the UserModel.retrieve() method is that, for new user it can
not create a database record by itself. You could however, modify the method
so that it creates an record when no existing record was found. Again, you
wouldn't be able to provide any other information to UserModel when
UserModel.retrieve() creates the record. Here's a modified version of
UserModel.retrieve() method that creates an record when no record was found:

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