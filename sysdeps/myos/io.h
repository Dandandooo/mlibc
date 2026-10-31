#define IOC_GETBLKSZ 0 // no arg, return value is block size
#define IOC_RESET    1 // no arg, return value 0 or -ENOTSUP

#define IOC_GETEND 4 // arg is unsigned long long *
#define IOC_SETEND 5 // arg is const unsigned long long *
#define IOC_GETPOS 6 // arg is unsigned long long *
#define IOC_SETPOS 7 // arg is const unsigned long long *

