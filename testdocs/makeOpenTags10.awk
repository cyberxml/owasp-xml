#!/usr/bin/awk -f

BEGIN {
print "<?xml version='1.0' encoding='UTF-8'?>"
for (i=1; i<=10; i++)
printf("<element_%d>\n", i)
print("</element_1>")
} 
