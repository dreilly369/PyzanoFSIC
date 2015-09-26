import os
import platform

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
