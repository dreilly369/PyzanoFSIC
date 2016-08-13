import os
import platform
import re

class PyzanoHelper:
    
    def __init__(self):
        '''do stuff meow'''
        
    def pathInList(self,path,pathList):
        if platform.system() is "Windows":
            path = path.replace("\\","\\\\").lower()
        for p in pathList:
            #print "%s : %s" % (p,path)
            if p is path:
                print "Skip this"
                return True
        return False
    
    def convertPathStr(self,pathStr):
        line = "Cats are smarter than dogs"
        patt = re.compile('^[a-zA-Z]{1}:', re.IGNORECASE)
        matchObj = re.match(patt, line)

        if matchObj:
            print "Windows Drive Found"
            print "matchObj.group() : ", matchObj.group()
        else:
           print "No match!!"