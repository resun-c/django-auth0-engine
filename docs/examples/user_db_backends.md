Some example of `USER_DB_BACKEND`.

## 1. UserFirestore

This database backend utilizes Firestore as the underlying storage solution for user data in your Django application. It leverages Firestore collections and documents to represent user information efficiently. It utilizes the dedicated collection (`FIRESTORE_USER_COLLECTION`) where each document represents a single user, identified uniquely by their `sub` (ID) obtained from Auth0.

```
class UserFirestore():
	def __init__(self, **kwarg) -> None:
		self.id     = kwarg.get("sub", None)
		self.ref    = None
		self.snap   = None
		self.data   = {}

        # if no sub is provided do nothing
		if self.id:
			self.ref    = FIRESTORE_USER_COLLECTION.document(self.id)
			self.snap   = self.ref.get()
			data        = self.snap.to_dict()
			if data:
				self.data |= data
		
    # to check if successfully retrieved data
	def __bool__(self) -> bool:
        # no id represents no user
		return bool(self.id and self.ref and self.snap)

    # updates user's data
	def update(self):
		if self:
			return self.ref.set(self.data)
```

As `UserFirestore` retrieves user entry using `User.sub` in initialization, you can directly assign `UserFirestore` to `USER_DB_BACKEND`. Again, initializing `UserFirestore` works fine for new user as Firestore automatically creates a document when there exists no document with an ID (in this case, it is User.sub which is unique for every user).

## 2. UserModel

This database backend uses Django `Models`.


Note: 32 chars for the `sub` field is enough per this remark: https://community.auth0.com/t/is-256-a-safe-max-length-for-a-user-id/34040/7

```
class UserModel(models.Model):
    # primary_key = True set sub as the primary key for the table
    sub = models.CharField(max_length=32, primary_key = True)
    ...

    # given the User.sub as keyword argument retrieve entry of the user
    @staticmethod
    def retrieve(**kwarg):
        user = None
        # if no sub is provided return None
        if "sub" in kwarg:
            user = UserModel.objects.get(pk=kwarg["sub"])

        return user
```

`UserModel` does not retrieve user entry in initialization (doing so would harm the functionality of `Model` class). So, you can not directly assign `UserModel` to `USER_DB_BACKEND`. The `UserModel.retrieve()` static method helps here. You can assign `UserModel.retrieve` to `USER_DB_BACKEND`. When the `User` object call `UserModel.retrieve` with attributes of the user, it returns an `UserModel` instance representing the user entry in the database table.

One drawback of the `UserModel.retrieve()` method is that, for new user it can not create a database entry by itself. You could however, modify the method so that it creates an entry when no existing entry was found. Again, you wouldn't be able to provide any required information to `UserModel` when `UserModel.retrieve()` creates the entry. Here's a modified version of `UserModel.retrieve()` method that creates an entry when no entry was found:

```
@staticmethod
def retrieve(**kwarg):
    user = None
    # if no sub is provided return None
    if "sub" in kwarg:
        user = UserModel.objects.get(pk=kwarg["sub"])
        # if no user entry was found create one
        if not user:
            user = UserModel(sub = kwarg["sub"])
            user.save()
    return user
```