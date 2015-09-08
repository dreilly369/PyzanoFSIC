#! /usr/bin/python
import os
import json
import re
import binascii

from pyzano_mysql import DBManager

class MissingFileScanner:
    disposition = 'i' # i = interactive, r = restore from DB, d = delete from DB
    def __init__(self,disposition='i'):
        self.disposition = disposition
        
    def load_config(self):
        base_dir = os.path.dirname(os.path.dirname(__file__))
        sep = os.sep
        conf_loc = base_dir+sep+"config"+sep+"pyzano_config.json"
        return json.load(open(conf_loc,"r"))

    def scanForRemoved(self):
        dbm = DBManager(self.load_config())
        files = dbm.readFromDatabase("file_location,id","1")
        missing_files = []
        for file_row in files:
            theF = re.sub(r'\\(.)', r'\1',file_row[0])
            if not os.path.isfile(theF):
                missing_files.append([file_row[1],theF])
        for fpack in missing_files:
            row_id = fpack[0]
            if self.disposition is "i":
                choice = self.handleMissingInteractive(row_id,theF)
            else:
                choice = self.disposition
                
            if choice is "d":
                self.handleDeleteFromDB(row_id)
            elif choice is "r":
                self.handleRevertFromDb(row_id)
        return missing_files
    
    def handleMissingInteractive(self,row_id,fn):
        choice = ""
        while choice.lower() not in ["delete","revert","skip","d","r","s"]:
            print "How would you like to handle %s?:" % fn
            choice = raw_input("(d)elete from DB, (r)evert from DB, or (s)kip: ")
        if choice in ["d","delete"]:
            return 'd'
        elif choice in ["r","revert"]:
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
        with open(local,"wb") as f:
            f.write(data)
            f.close()
