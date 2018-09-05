import sys
import re

header = '''// File generated automatically -- DO NOT EDIT
#include <gio/gio.h>

#include "signon-errors.h"
#include "signon-internals.h"

static const GDBusErrorEntry signon_error_entries[] = {
'''

footer = '''
};
'''

f = open(sys.argv[2], 'w')
f.write(header)

regex = re.compile(r'SIGNON_ERROR_([A-Z_0-9]*).*', re.IGNORECASE)
for line in open(sys.argv[1], 'r'):
    if re.search(r'^ *SIGNON_ERROR_*', line):
        f.write(regex.sub(r'{ SIGNON_ERROR_\1, SIGNOND_\1_ERR_NAME },', line))

f.write(footer)
