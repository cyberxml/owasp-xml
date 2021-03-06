from owasp_xml import *

timelimit=10 # seconds allowed for xml parser to load
testflag=True
testxmldoc="../testdocs/U_RedHat_5_STIG_V1R18_Manual-xccdf.xml"
# note, this file generated by script make10Mattr.awk > test10Mattr.xml

'''
mintimeparse=1
maxtimeparse=10
testfile_2_1="../testdocs/test1Mattr.xml"
print("OWASP:2_1a Testing xml_more_time_required at %s second(s) with file %s" % (mintimeparse,testfile_2_1))
xml_more_time_required(testfile_2_1,mintimeparse)

print("OWASP:2_1b Testing xml_more_time_required at %s second(s) with file %s" % (maxtimeparse,testfile_2_1))
xml_more_time_required(testfile_2_1,maxtimeparse)

testfile_2_2_1="../testdocs/owasp-2_2_1-maldoc-to-maldoc.xml"
print("OWASP:2.2.1 Testing double-hyphen within comment with file" % (testfile_2_2_1))
xml_document_parsing(testfile_2_2_1)

testfile_2_3a="../testdocs/owasp-2_2_3-10-open-elements.xml"
testfile_2_3b="../testdocs/owasp-2_2_3-100-open-elements.xml"
print("OWASP:2.3a Testing coersive parsing with %d open tags and a tolerance for %d" % (9,40))
result=owasp_xml_2_3_coersive_parsing(testfile_2_3a)
print("Result 2.3a: %d" % result)
print("OWASP:2.3b Testing coersive parsing with %d open tags and a tolerance for %d" % (99,40))
result=owasp_xml_2_3_coersive_parsing(testfile_2_3b)
print("Result 2.3b: %d" % result)
'''

testfile_3_1a="../testdocs/U_RedHat_5_STIG_V1R18_Manual-xccdf.xml"
print("OWASP:3.1a Document without schema %s" % testfile_3_1a)
result,retstr=owasp_xml_3_1a_schemaLocation_defined(testfile_3_1a)
print("Result 3.1a: %d, %s" % (result, retstr))

testfile_3_1b="../testdocs/U_RedHat_5_STIG_V1R18_Manual-xccdf.xml"
print("OWASP:3.1b Document without schema %s" % testfile_3_1b)
result,retstr=owasp_xml_3_1b_schema_validates(testfile_3_1b)
print("Result 3.1b: %d, %s" % (result, retstr))

testfile_3_1b="../testdocs/U_RedHat_5_STIG_V1R18_Manual-xccdf-20111124rb.xml"
print("OWASP:3.1b Document without schema %s" % testfile_3_1b)
result,retstr=owasp_xml_3_1b_schema_validates(testfile_3_1b)
print("Result 3.1b: %d, %s" % (result, retstr))


