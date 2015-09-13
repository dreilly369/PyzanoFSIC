import os.path
#! /usr/bin/python

import hashlib
import sys
import os
import json
from commands import *
from optparse import OptionParser
import binascii
import string
import httplib
from httplib import HTTPConnection, HTTPS_PORT
import ssl
import socket

#Pyzano Imports
sep = os.sep
sys.path.insert(0, os.getcwd()+sep+"core"+sep)
import pyzano_multi_filescan
from pyzano_multi_filescan import VirusTotal
from pyzano_mysql import DBManager

banner = '''
                           _,.-----.,_
                        ,-~           ~-.
                       ,^___           ___^.
                      /~"   ~"   .   "~   "~\
                      
                     | Y     ~-. | ,-~     Y |
                     | |        }:{        | |
                     j l       / | \       ! l
                  .-~  (__,.--" .^. "--.,__)  ~-.
                 (           / / | \ \           )
                  \.____,   ~  \/"\/  ~   .____,/
                   ^.____                 ____.^
                      | |T ~\  !   !  /~ T| |
                      | |l   _ _ _ _ _   !| |
                      | l \/V V V V V V\/ j |
                      l  \ \|_|_|_|_|_|/ /  !
                       \  \[T T T T T TI/  /
                        \  `^-^-^-^-^-^'  /
                         \               /
                          \.           ,/
                            "^-.___,-^"

                ,-.   ,-.  .  . ,--,               
                |  ) /  /\ |\ |   /                
                |-<  | / | | \|  `.    ,-. ,-. ,-. 
                |  ) \/  / |  |    )   `-. |-' |   
                `-'   `-'  '  ' `-'  o `-' `-' `-' 
                                  
                    '''
failed_banner = '''
          .-""""""-.
        .'          '.
       /   O      O   \\\t
      :           `    :
  oni |           `    | sad
      :    .------.    :
       \  '        '  /
        '.          .'
          '-......-'
'''


class HTTPSConnection(HTTPConnection):
    "This class allows communication via SSL."
    default_port = HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
            strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
            source_address=None):
        HTTPConnection.__init__(self, host, port, strict, timeout,
                source_address)
        self.key_file = key_file
        self.cert_file = cert_file

    def connect(self):
        "Connect to a host on a given (SSL) port."
        sock = socket.create_connection((self.host, self.port),
                self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        # this is the only line we modified from the httplib.py file
        # we added the ssl_version variable
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1)

#now we override the one in httplib
httplib.HTTPSConnection = HTTPSConnection
# ssl_version corrections are done


def load_config():
    sep = os.sep
    base_dir = os.path.realpath(__file__).strip(sys.argv[0])
    conf_loc = base_dir + "config" + sep + "pyzano_config.json"
    return json.load(open(conf_loc,"r"))

def is_empty(struct):
    if struct:
        return False
    else:
        return True
    
def vscan_file(file,upload):
    print "Scanning %s" % file
    vt_scanner = VirusTotal(file, upload)
    res = vt_scanner.submit()
    if res:
        if int(res.get("result")) > 0:
            cnt = 0
            for k in res.get("report")[1]:
                if res.get("report")[1][k] != '':
                    print "\033[1;31m%s : %s\033[1;m" % (k, res.get("report")[1][k])
                    cnt += 1
            if cnt > 0:
                start_str = "\033[1;31m"
            else:
                start_str = "\033[1;32m"
            end_str = "\033[1;m"
            print "%sDetected by: %d Scanners\nYou can see the scan at\n%s%s" % (start_str,cnt,res.get("permalink"),end_str)
    return True

def handleChangedInteractive(fn):
    choice = ""
    while choice.lower() not in ["update","revert","skip","u","r","s"]:
        print "How would you like to handle %s?:" % fn
        choice = raw_input("(u)pdate DB, (r)evert from DB, or (s)kip: ")
    if choice in ["u","update"]:
        return 'u'
    elif choice in ["r","revert"]:
        return 'r'
    else:
        return 's'

def handleNewInteractive(fn):
    choice = ""
    while choice.lower() not in ["delete","add","skip","d","a","s"]:
        print "How would you like to handle %s?:" % fn
        choice = raw_input("(d)elete from FS, (a)dd to DB (s)kip")
    if choice in ["d","delete"]:
        return 'd'
    elif choice in ["a","add"]:
        return 'a'
    else:
        return 's'

# Expand this section to add different change functions such as diff or delete later
def handleChange(fileName,submit_file=False):
    print "%s Has changed." % fileName
    floc = os.path.abspath(fileName)
    if not submit_file:
        print "Scanning File Hash with VirusTotal. This is only cursory."
        vscan_file(floc,submit_file)
        return True
    else:
        print "Submitting File to VirusTotal"
        vscan_file(floc,submit_file)
        return True
    
# Recurse over directories and pass the files to the file hashing function
def hashDir(dir, blockSize, verbose=None, upload_file=False,storeBin=False,disposistions=["i","i"],scanFile=True):
    output = {}
    
    if ignoreThis(dir):
        print failed_banner
        print "Dir in ignore list. Skipping. Remove it from the config if you want it scanned."
        exit(0)
    for f in os.listdir(dir):
        
        sep = os.sep
        at = os.path.abspath(dir+sep+f)
        #print "checking "+at
        
        if os.path.isdir(at):
            if not ignoreThis(at):
                hashDir(at,blockSize,verbose,upload_file,storeBin,disposistions,scanFile) # recurse into directory
        elif os.path.isfile(at):
            if ignoreThis(at):
                pass
            else:
                res = hashFile(at,blockSize,verbose,upload_file,storeBin,disposistions,scanFile)
                #print res
                vkey = os.path.basename(at)
                output[vkey] = {"location":at,"fingerprint":res}
                if verbose is not None:
                    output[os.path.basename(at)]['absolute'] = os.path.isabs(at)
                    output[os.path.basename(at)]['is_file'] =  os.path.isfile(at)
                    output[os.path.basename(at)]['is_dir'] =  os.path.isdir(at)
                    output[os.path.basename(at)]['is_link'] = os.path.islink(at)
                    output[os.path.basename(at)]['mountpoint'] = os.path.ismount(at)
                    output[os.path.basename(at)]['exists'] = os.path.exists(at)
                    output[os.path.basename(at)]['link_exists'] = os.path.lexists(at)
        else:
            print 'Unable to read ' + at
            
    return output

#Hash a file and check it against the database        
def hashFile(fileName, blocksize=65536,verbose=None,uploadFile=False,storeBin=False,disposistions=["i","i"],scanFile=True):
    hasher = hashlib.sha1()
    conf = load_config()
    dbm = DBManager(conf)
    
    with open(fileName, 'rb') as afile:
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            
            buf = afile.read(blocksize)
            
    fingerprint = hasher.hexdigest()
    
    row = {"host_name":"","file_name":os.path.basename(fileName),"file_location":fileName,"file_fingerprint":fingerprint}
    exists = (dbm.fingerprintRecordExists(fingerprint) or dbm.fileRecordExists(fileName)) 
    if storeBin:
        #base64 Encode the Hex Data to store in the DB
        afile = open(fileName, 'rb')
        bytes = afile.read()
        hexadecimal = binascii.hexlify(bytes)
        #print len(hexadecimal)
        afile.close()
        
        if len(hexadecimal) > 4294967295:#Max size of TEXTLARGE in MySQL. Working on a fix for this
            print "Encoded Bin to Large!"
            raise Exception
        row["bin_string"] = hexadecimal
        
    is_new = "True"   
    has_changed = "False"
    
    if not exists:
        #Handle case where this is a new file
        print "%s is new. FINGERPRINT: %s." % (fileName,fingerprint)
        if scanFile:
            vscan_file(os.path.abspath(fileName),uploadFile)   
        
        if dispos[0] is "i":
            c = handleNewInteractive(fileName)
        else:
            c = dispos[0]
            
        if c is "d":
            os.remove(os.path.abspath(fileName))
        elif c is "a":
            dbm.writeToDatabase(row)
        elif c is "p":
            print row
    else:
        #Handle cases Where files already exists in DB
        where_str = "file_fingerprint=\"%s\" or file_location=\"%s\"" % (fingerprint,fileName)
        rows = dbm.readFromDatabase("id,file_fingerprint,bin_string",where_str)
        is_new = "False"
        for res in rows:
            if fingerprint != res[1]:
                #Handle case where fingerprint has changed
                if dispos[1] is "i":
                    c = handleChangedInteractive(fileName)
                else:
                    c = dispos[1]
                has_changed = "True"
                if c is "u":
                    if scanFile:
                        handleChange(fileName)
                    dbm.updateRow(int(res[0]), row)
                elif c is "r":
                    where_str = "file_fingerprint=\"%s\"" % fingerprint
                    rows = dbm.readFromDatabase("file_fingerprint,bin_string",where_str)
                    data = binascii.unhexlify(b64decode(rows[0][1]))
                    with open(fileName,"wb") as f:
                        f.write(data)
                        f.close()
                elif c is "p":
                    print row
                    
            elif storeBin and res[2] != hexadecimal:
                print "Data changed for %s. Updating." % fileName
                #Handle Case where File is kown but we want to add the bin data
                dbm.updateRow(int(res[0]), {"bin_string":hexadecimal})
                
    if verbose is not None:
        try:
            is_backed_up = (row["bin_string"] != None)
        except:
            is_backed_up = False
        print 'File        :', os.path.basename(fileName)
        print 'Path        :', os.path.abspath(fileName)
        print 'New?        :', is_new
        print 'Changed?    :', has_changed
        print 'Fingerprint :', fingerprint
        print 'Backed Up?  :', is_backed_up
        print 'Absolute    :', os.path.isabs(fileName)
        print 'Is File?    :', os.path.isfile(fileName)
        print 'Is Dir?     :', os.path.isdir(fileName)
        print 'Is Link?    :', os.path.islink(fileName)
        print 'Mountpoint? :', os.path.ismount(fileName)
        print 'Exists?     :', os.path.exists(fileName)
        print 'Link Exists?:', os.path.lexists(fileName)
        print 
        
    return (row)

def ignoreThis(dirty):
    theThing = ''.join(filter(string.printable.__contains__, dirty))
    config = load_config()
    if os.path.isdir(theThing):
        if theThing in config["EXCLUDES"]["DIRECTORIES"]:
            return True
        
    elif os.path.isfile(theThing):
        extension = theThing.split(".")[-1]
        
        if os.path.abspath(theThing) in config["EXCLUDES"]["FILES"] or extension in config["EXCLUDES"]["EXTENSIONS"]:
            print "Skip %s" % theThing
            return True
    return False
            
if __name__ == "__main__":
    parser = OptionParser()
    
    # Misc options
    parser.add_option("-i", "--init", dest="initDb", default=False,
                      help="Initialize SQLLite3 (and MySQL if i=!) DBs and return")
    
    # Handle System change options
    parser.add_option("-w", "--handle-deleted", dest="handleDeleted", default="i",
                      help="Handle Deleted Files by: (i)nteractive, (d)elete from db, or (r)estore to file system")
    parser.add_option("-x", "--handle-changed", dest="handleChanged", default="i",
                      help="Handle Changed Files by: (i)nteractive, (u)pdate db, or (r)estore from")
    parser.add_option("-y", "--handle-added", dest="handleAdded", default="i",
                      help="Handle Added Files by: (i)nteractive, (a)dd to db, or (d)elete from file system")
    parser.add_option("-e", "--email-db", dest="emailDb", default=None,
                      help="Email the VT scan DB to the Admin email at the end. If \"-e !\" email the DB and exit")
    parser.add_option("-n", "--no-scan", dest="noScan", default=False,
                      help="Only create Fingerprints, Do not check hashes.")
    # Scanner options
    #parser.add_option("-j", "--jotti-scan", dest="jottiToo", default=False,
    #                  help="The directory to start Hashing in. (cancels -f)")
    #parser.add_option("-l", "--log-file", dest="logFile",default="pyzano_results.log",
    #                  help="The directory to start Hashing in. (cancels -f)")
    parser.add_option("-d", "--directory", dest="topDir",
                      help="The directory to start Hashing in. (cancels -f)")
    parser.add_option("-f", "--hash-file", dest="singleFile",
                      help="Set a single file to hash (canceled by -d)")
    parser.add_option("-b", "--block-size", dest="blockSize", default=65536,
                      help="Change the default SHA1 block size from 65536. Only do this if you know what you are doing")
    parser.add_option("-v", "--verbose", dest="makeVerbose",
                      help="Output file details for each file scanned. ")  
    parser.add_option("-s", "--store-file", dest="storeBinData", default=False,
                      help="If True: encoded copies of the binary data will be stored in the Database. ")
    parser.add_option("-z", "--upload-file", dest="uploadFile", default=False,
                      help="If True: Files that are new or changed will be uploaded to VirusTotal (If the hash is not found first)")
                      
    (options, args) = parser.parse_args()
    arglen = len(args)
    
    
    if options.initDb != False:
        if options.initDb is "!":
            pyzano_multi_filescan.initdbs(True)
        else:
            pyzano_multi_filescan.initdbs()
            
        print banner
        exit(0)
    if options.emailDb is "!":
        from pyzano_email_client import EmailManager
        em = EmailManager()
        em.emailDBFile()
        print "emailed DB."
        exit(0)
    
    # Safety Check the options        
    if options.topDir is None and options.singleFile is None:
        print "Must define a Directory (-d) or File (-f)"
        print failed_banner
        exit(1)
    if options.handleDeleted.lower() not in ["skip","s","d","i","r","p","print","delete","interactive","restore"]:
        print failed_banner
        print "-w must be (s)kip, (p)rint, (i)nteractive, (d)elete, or (r)estore"
        exit(1)
    
    if options.handleChanged.lower() not in ["skip","s","u","i","r","p","print","update","interactive","restore"]:
        print failed_banner
        print "-x must be (s)kip, (p)rint, (i)nteractive, (u)pdate, or (r)estore"
        exit(1)

    if options.handleAdded.lower() not in ["skip","s","d","i","a","p","print","delete","interactive","add"]:
        print failed_banner
        print "-y must be (s)kip, (p)rint, (i)nteractive, (d)elete, or (a)dd"
        exit(1)
    
    verbUp = None
    #Turn on file info outputting if verbose
    if options.makeVerbose is not None:
        verbUp = True
    
    scanFile = True
    if options.noScan != False:
        scanFile = False
    
    #make the disposition tuple to handle new files and changed files
    dispos = []
    if options.handleAdded.lower() in ["skip","s"]:
        dispos.append("s")
    elif options.handleAdded.lower() in ["delete","d"]:
        dispos.append("d")
    elif options.handleAdded.lower() in ["p","print"]:
        dispos.append("p")
    elif options.handleAdded.lower() in ["add","a"]:
        dispos.append("a")
    else:
        dispos.append("i")
        
    if options.handleChanged.lower() in ["skip","s"]:
        dispos.append("s")
    elif options.handleChanged.lower() in ["update","u"]:
        dispos.append("d")
    elif options.handleAdded.lower() in ["p","print"]:
        dispos.append("p")
    elif options.handleChanged.lower() in ["restore","r"]:
        dispos.append("a")
    else:
        dispos.append("i")    
        
    #Check if this is a directory scan
    if options.topDir is None:
        hashFile(options.singleFile, options.blockSize, verbUp, options.uploadFile,options.storeBinData,dispos,scanFile)
    else:
        hashDir(options.topDir, options.blockSize, verbUp, options.uploadFile,options.storeBinData,dispos,scanFile)
        
    # Handle Files that exist in the DB, but not on the file System
    if options.handleDeleted.lower() not in ["skip","s"]:
        from pyzano_missing_files import MissingFileScanner
        if options.handleDeleted.lower() in ["d","delete"]: 
            scanner = MissingFileScanner("d")
        elif options.handleDeleted.lower() in ["p","print"]: 
            scanner = MissingFileScanner("p")
        elif options.handleDeleted.lower() in ["r","restore"]: 
            scanner = MissingFileScanner("r")
        else: 
            scanner = MissingFileScanner()
        scanner.scanForRemoved()
        
    if options.emailDb is not None:
        from pyzano_email_client import EmailManager
        em = EmailManager()
        em.emailDBFile()
    print banner
    exit(0)
    
