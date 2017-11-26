#!/usr/bin/python

from owasp_xml import *
import sys

thisxmldoc=sys.argv[1]

timeoutlimit=10
filelength=10
opentagsallowed=40

def process_results((result,retstr)):
    if result > 0:
        print("FLAG: Deny")
        print("META: "+retstr)
        exit(1)

process_results(owasp_xml_2_1_more_time_required(thisxmldoc,timeoutlimit))
process_results(owasp_xml_2_2_1_document_parsing(thisxmldoc))
process_results(owasp_xml_2_3_coersive_parsing(thisxmldoc,opentagsallowed))
process_results(owasp_xml_3_1a_schemaLocation_defined(thisxmldoc))
process_results(owasp_xml_3_1b_schema_validates(thisxmldoc))

# looks like we've made it!
print("FLAG: Allow")
print("META: OWASP_XML good")



