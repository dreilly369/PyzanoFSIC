import os.path
#! /usr/bin/python
import os
import json
import re
import binascii
import subprocess

from pyzano_mysql import DBManager

class MissingFileScanner:
    disposition = 'i' # i = interactive, r = restore from DB, d = delete from DB
    topDir = ""
    
    def __init__(self,startAt="/",disposition='i'):
        self.disposition = disposition
        self.topDir = startAt
        
    def load_config(self):
        base_dir = os.path.dirname(os.path.dirname(__file__))
        sep = os.sep
        conf_loc = base_dir+sep+"config"+sep+"pyzano_config.json"
        return json.load(open(conf_loc,"r"))

    def scanForRemoved(self):
        conf = self.load_config()
        dbm = DBManager(conf)
        wHost = "host_name=\"%s\" AND " % conf["HOSTNAME"]
        wLoc = "file_location LIKE \"%s" % self.topDir
        wLoc += "%\""
        files = dbm.readFromDatabase("file_location,id", wHost + wLoc)
        missing_files = []
        for file_row in files:
            theF = re.sub(r'\\(.)', r'\1',file_row[0])
            if not os.path.isfile(theF):
                missing_files.append([file_row[1],theF])
        for fpack in missing_files:
            row_id = fpack[0]
            if self.disposition is "i":
                choice = self.handleMissingInteractive(theF)
            else:
                choice = self.disposition
                
            if choice is "d":
                print "removing from db"
                self.handleDeleteFromDB(row_id)
            elif choice is "r":
                print "restoring to %s" % theF
                self.handleRevertFromDb(row_id)
            else: 
                print "skipping"
                pass
                
        return missing_files
    
    def handleMissingInteractive(self,fn):
        choice = ""
        while choice.lower() not in ["delete","revert","skip","d","r","s"]:
            print "How would you like to handle %s?:" % fn
            choice = raw_input("(d)elete from DB, (r)estore from DB, or (s)kip: ")
        if choice in ["d","delete"]:
            return 'd'
        elif choice in ["r","restore"]:
            return 'r'
        else:
            return 's'

    def handleDeleteFromDB(self,row_id):
        where_str = "id="+str(row_id)
        dbm = DBManager(self.load_config())
        dbm.deleteFromDatabase(where_str)
        
    def handleRevertFromDb(self,row_id):
        dbm = DBManager(self.load_config())
        where_str = "id="+str(row_id)
        rows = dbm.readFromDatabase("file_fingerprint,bin_string,file_location",where_str)
        if rows[0][1] is None:
            print "%s was not backed up!!!" % rows[0][2]
            return False
        data = binascii.unhexlify(rows[0][1])
        local = re.sub(r'\\(.)', r'\1',rows[0][2])
        container = os.path.dirname(rows[0][2])
        if not os.path.isdir(container):
            call = "mkdir -p %s" % container
            print call
            subprocess.call(call)
        
        with open(local,"wb") as f:
            f.write(data)
            f.close()
        print "%s was restored" % rows[0][2]
