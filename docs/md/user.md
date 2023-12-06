# dict_diff(new, old)
This function returns a dictionary containing the differences between two dictionaries. It identifies key-value pairs present in new but not in old, as well as key-value pairs in old with different values in new.

# _class_ User(**kwarg)
The User class represents a user object returned by successful authentication operations performed by the AuthEngine. It provides access to various user information and supports update functionality.

All the Open ID Claims are available as property.

These are the property available in a user object:

### UPDATABLE_ATTRIBUTES
A list of keys for attributes that can be updated in the user's information through the Management API.

### property User.__id__
The user's unique ID (also known as "sub").
	
### property User.__db__
This property allows access to the user's data stored in the configured database backend.

Database Backend can be defined in settings using the USER_DB_BACKEND variable.

These are the methods available in a user object:

### User.__\_\_bool\_\___()
This method checks the presence of both the access token and the ID token to determine if the user object represents a valid user. If any errors are present, it initializes an AuthEngineError object with the error information.

### User.__\_\_eq\_\___(\_\_user: object)
This method compares the current user object with another user object to determine if they represent the same user.

### User.__set_db_backend__(_db_backend_class)
This method sets a specific database backend for the user instance. This is primarily useful for scenarios involving multiple database backends. If a user's data is not available in the default db backend, then before accessing User.bd the db backend should be set using this method. _db_backend_class is the class that is initialized using user's sub (id) given through keyword arguments.
	
### User.__valid_user_key__(key)
This method checks whether a provided key is a valid user attribute key recognized by the Auth0 Management API.

### User.__validate_user_dict__(data)
This method validates a provided dictionary of user data against the list of valid user attribute keys. If any invalid key is present, it raises an AuthEngineError exception.

### User.__to_dict__()
This method returns a dictionary representation of the user data, ensuring it contains only valid keys that can be sent for update to the Management API.
	
### User.__changed_user_data__()
This method returns a dictionary containing only the user data that has been changed since the object's creation or last update.

### User.__update__(self, [data])
This method updates the user's information on the Auth0 server. The data parameter should be a dictionary containing the attributes to be updated. The method validates the provided data before updating. If data is not provided it automatically detects which fields have been changed. It only sends these changed fields for update to the server. Upon successful update, the user object itself is updated with the new data. If any errors occur, the user object's boolean state is set to False. After the operation it returns the return value of User.__\_\_bool\_\___().