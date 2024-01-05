## _class_ __AuthEngineResponse__(**kwarg)
A base class for various responses returned by different functions of
this package. It provides a standardized way to access response data and
check for successful operations.

### **kwarg
keyword argument containing information of the response.

### AuthEngineResponse.__\_\_bool\_\___()
Returns the value of the private [1] variable `_bool`. Various
subclasses determine the value of `_bool` based on the response of an
operation. By default, `_bool` is initialized as False.

### AuthEngineResponse.__\_\_str\_\___()
Returns a formatted string containing all the public [1] properties of the
response instance. The formatting utilizes the `pprint.pformat()` method.

### AuthEngineResponse.__\_\_repr\_\___()
Returns a formatted string containing all properties, including both
public [1] and private [1] ones, of the response. The formatting utilizes the
`pprint.pformat()` method.
		
### AuthEngineResponse.__\_\_iter\_\___()
This method returns an iterator object, enabling iteration through the
public [1] variables of the response instance.

### AuthEngineResponse.__\_safe__(\_\_value)
Returns a safe string of `__value`.

[1] Public and Private variables are defined here:
https://docs.python.org/3/tutorial/classes.html#private-variables