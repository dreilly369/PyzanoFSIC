import re
import MySQLdb as mdb
from commands import *
import time
class DBManager:
    con = ''
    host = ''
    usr = ''
    pwd = ''
    dbn = ''
    def __init__(self,conf):    
        self.host = conf['MYSQLDURL']
        self.usr = conf['MYSQLUSER']
        self.pwd = conf['MYSQLPASS']
        self.dbn = conf['MYSQLDBNAME']
    
    def connect_db(self):
        return mdb.connect(self.host, self.usr, self.pwd, self.dbn)
    
    def readFromDatabase(self, tbl, projection, where):
        with self.connect_db() as con: 

            cur = self.connect_db().cursor()
            cmdString = "SELECT "+projection+" FROM "+tbl+" WHERE "+where
            cur.execute(cmdString)

            rows = cur.fetchall()
            con.close()
            return rows

    def writeToDatabase(self, tbl, dataSet):
        with self.connect_db() as con:
            insertString = "INSERT INTO "+tbl+"("
            valueString = "VALUES("
            for row in dataSet:
                valueString += "\'"+re.escape(dataSet.get(row))+"\',";
                insertString += row +",";

            #remove last commas
            valueString = valueString[:-1]
            insertString = insertString[:-1]

            #cap the the strings 
            insertString += ")"
            valueString += ")"

            commandString = insertString+" "+valueString
            #cur = con.cursor()
            try:
                con.execute(commandString)
                con.close()
                return
            except Exception:
                i = 0
                time.sleep(30)
                while i < 5:
                    con = self.connect_db()
                    try:
                        con.execute(commandString)
                        con.close()
                        return
                    except Exception:
                        i += 1
                        
    def deleteFromDatabase(self, tbl, where):
        with self.connect_db() as con: 
            cur = self.connect_db().cursor()
            cmdString = "DELETE FROM "+tbl+" WHERE "+where
            cur.execute(cmdString)

            rows = cur.fetchall()
            con.close()
            return rows
    
    def updateRow(self, tbl, row_id,fields):
        with self.connect_db() as con:
            update_str = "UPDATE %s SET " % tbl
            data_str = ""
            for k in fields:
                data_str += "%s='%s'," % (k,fields[k])
            #remove last commas
            data_str = data_str[:-1]+" "
            where_str = "WHERE id=%d;" % row_id
            commandString = update_str+data_str+where_str
            con.execute(commandString)
            con.close()

    def fingerprintRecordExists(self, fingerprint):
        ret = self.readFromDatabase("fingerprints","id","file_fingerprint='%s'" % fingerprint)
        if ret is None or len(ret)<1:
            return False
        else:
            return True
        
    def fileRecordExists(self, fileName):
        ret = self.readFromDatabase("fingerprints","id","file_location='%s'" % fileName)
        if not ret or len(ret)<1:
            return False
        else:
            return True
