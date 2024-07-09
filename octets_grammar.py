from gramfuzz.fields import *

Def("octets",
    And(String(min=1, max=1, charset="ABCDEF0123456789"), String(min=1, max=1, charset="ABCDEF0123456789")),
    cat="octets")
