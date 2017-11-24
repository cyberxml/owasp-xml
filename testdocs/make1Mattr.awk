#!/usr/bin/awk -f

BEGIN {
print "<?xml version='1.0' encoding='UTF-8'?>"
print "<root "
for (i=1; i<=1000000; i++)
printf("a%d='%d'\n", i, i)
print "/>"
} 
