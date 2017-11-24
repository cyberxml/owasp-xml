import signal
from contextlib import contextmanager
from xml.etree import ElementTree
from lxml import etree

timelimit=10 # 2.1 seconds allowed for xml parser to load
testflag=True
testxmldoc="../testdocs/U_RedHat_5_STIG_V1R18_Manual-xccdf.xml"

#TODO: maybe make this a percentage instead of hard value?
opentagsallowed=40 # 2.3 


class TimeoutException(Exception): pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
       yield
    finally:
       signal.alarm(0)

# OWASP 2.1 More Time Required
def xml_more_time_required(xmldoc,seconds):
    try:
        with time_limit(seconds):
            with open(xmldoc, 'rt') as f:
                tree = ElementTree.parse(f)
        print("File %s parsed within time" % (xmldoc))
    except TimeoutException as e:
        print("File %s parsing timed out" % (xmldoc))

# OWASP 2.2.1 Malformed Document to Malformed Document
def xml_document_parsing(xmldoc):
    try:
        with open(xmldoc, 'rt') as f:
            tree = ElementTree.parse(f)
        print("File %s parsed with xml.tree.ElementTree" % (xmldoc))
    except ElementTree.ParseError as e:
        print("File %s does not parse with xml.tree.ElementTree" % (xmldoc))
        print("ElementTree.ParseError: %s" % (e))


# OWASP 2.2.2 Well-Formed Document to Well-Formed Document Normalized
# this is not ready and the OWASP issue is really about the parser, not the document.
def owasp_xml_2_2_2_normalization(xmldoc):
    try:
        with open(xmldoc, 'rt') as f:
            tree = ElementTree.parse("xmldoc")
        print("File %s parsed with lxml.etree.ElementTree" % (xmldoc))
    except ElementTree.ParseError as e:
        print("File %s does not parse with xml.tree.ElementTree" % (xmldoc))
        print("ElementTree.ParseError: %s" % (e))

# OWASP 2.3 Coersive Parsing
# https://stackoverflow.com/questions/35761133/python-how-to-check-for-open-and-close-tags
def owasp_xml_2_3_coersive_parsing(xmldoc):
    stack = []
    with open(xmldoc, 'r') as parse_file:
        for line in parse_file:
            #print "INPUT LINE:", line
            if "<?" in line:
                 pass
            else:
                ltag = line.find('<')
                if ltag > -1:
                    rtag = line.find('>')
                    if rtag > -1:
                        # Found left and right brackets: grab tag
                        tag = line[ltag+1: rtag]
                        open_tag = tag[0] != '/'
                        if open_tag:
                            # Add tag to stack
                            stack.append(tag)
                            #print "TRACE open", stack
                        else:
                            tag = tag[1:]
                            if len(stack) == 0:
                                #print "No blocks are open; tried to close", tag
                                pass
                            else:
                                if stack[-1] == tag:
                                    # Close the block
                                    stack.pop()
                                    #print "TRACE close", tag, stack
                                else:
                                    #print "Tried to close", tag, "but most recent open block is", stack[0]
                                    if tag in stack:
                                        stack.remove(tag)
                                        #print "Prior block closed; continuing"
        
        if len(stack):
            if len(stack) > opentagsallowed:
                print "Number of blocks still open at EOF:", len(stack)
                return(len(stack))
            else:
                print "Number of blocks still open at EOF:", len(stack)
                return(0)
        else:
           return(0)


# OWASP 3.1a: Document without schema
def owasp_xml_3_1a_schemaLocation_defined(xmldoc):
    # TODO: handle DTD
    # find internal XSD
    tree=etree.parse(xmldoc)
    root=tree.getroot()
    if not root.attrib['{http://www.w3.org/2001/XMLSchema-instance}schemaLocation']:
        return(1,"OWASP 3.1a: schemaLocation is not defined")
    else:
        return(0,"OWASP 3.1a: schemaLocation is defined")

# OWASP 3.1b: Document validates with schema
def owasp_xml_3_1b_schema_validates(xmldoc):
    # TODO: handle DTD
    # find internal XSD
    tree=etree.parse(xmldoc)
    root=tree.getroot()
    if not root.attrib['{http://www.w3.org/2001/XMLSchema-instance}schemaLocation']:
        return(1,"OWASP 3.1b: schemaLocation is not defined")
    else:
        valids = []
        xsds=[]
        # get xsd file locations from schemaLocation
        for x in root.attrib['{http://www.w3.org/2001/XMLSchema-instance}schemaLocation'].split():
            if x.endswith('.xsd'):
                xsds.append(x)
        # verify that xsd files are defined
        if not len(xsds):
            return(2,"OWASP 3.1.b: schemaLocation in %s has no xsd files" % (xmldoc))
        # process each xsd
        for x in xsds:
            try:
                xsdtree = etree.parse(x)
            except:
                return(3, "OWASP 3.1.b: in %s xsd schema %s could not be parsed by etree" % (xmldoc,x))
            try:
                xmlschema = etree.XMLSchema(xsdtree)
            except:
                return(4, "OWASP 3.1.b: in %s xsd schema %s could not be imported" % (xmldoc,x))
            if xmlschema.validate(tree):
                # make sure you test all schemas
                valids.append(x)
                
        if len(valids):
            return(0, "OWASP 3.1.b: xml document %s validates with internally defined schema %s" % (xmldoc,valids))
        else: 
            return(5, "OWASP 3.1.b: xml document %s does not validate with internally defined schema" % (xmldoc))
            

     

