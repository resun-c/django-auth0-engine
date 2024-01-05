## _class_ __AuthEngineError__()
## _class_ __AuthEngineError__(loc)
## _class_ __AuthEngineError__(loc, error)
## _class_ __AuthEngineError__(loc, error, description)
## _class_ __AuthEngineError__(loc, error, description, /, **kwarg)
A custom exception that is used throughout this package.

### loc
Where the exception occured.
        
### error
A string representing the name of the error.
		
### description
A short explanation of the error.

### **kwarg
keyword argument containing additional information about the error.


### AuthEngineError.__\_\_str\_\___()
Returns a formatted string containing all properties of the error. The
string is formatted using `pprint.pformat()`.
	
### AuthEngineError.__\_\_repr\_\___()
Returns a string summarizing the error in the format
"error: description/message".
	
### AuthEngineError.__\_\_bool\_\___()
Always returns False.