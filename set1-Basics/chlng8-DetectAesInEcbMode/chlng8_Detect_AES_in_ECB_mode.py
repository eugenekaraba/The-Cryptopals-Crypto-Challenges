#!/usr/bin/python

import re

with open('chlng8_file') as f:
    content = f.readlines()

content = [x.strip() for x in content]
for x in content:
    if len(set(re.findall('................................',x))) < 10:
        print "The line that has been encrypted with ECB is:\n", x