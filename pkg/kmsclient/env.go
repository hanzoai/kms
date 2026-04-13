package kmsclient

import "os"

// lookupEnv wraps os.LookupEnv for testability.
var lookupEnv = os.LookupEnv

// setEnv wraps os.Setenv for testability.
var setEnv = os.Setenv
