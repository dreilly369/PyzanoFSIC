#! /usr/bin/python
import StringIO
import traceback
import wmi
from _winreg import (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, 
                     OpenKey, EnumValue, QueryValueEx)


reg_keys = [
    {
   "Description": "Files recently accessed by Windows Media Player",
   "Location": "HKEY_CURRENT_USER\Software\Microsoft\MediaPlayer\Player\RecentFileList"
   }
 ] 

# This script enumerates interesting Windows registry key values
softFile = open('softLog.log', 'w')
errorLog = open('errors.log', 'w')
 
r = wmi.Registry ()
result, names = r.EnumKey (hDefKey=HKEY_LOCAL_MACHINE, sSubKeyName=r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
 
softFile.write('These subkeys are found under "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall"\n\n')
errorLog.write("Errors\n\n")
separator = "*" * 80
keyPath = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
 
for subkey in names:
    try:
        softFile.write(separator + '\n\n')
        path = keyPath + "\\" + subkey
        key = OpenKey(HKEY_LOCAL_MACHINE, path, 0, KEY_ALL_ACCESS) 
        try:
            temp = QueryValueEx(key, 'DisplayName')
            display = str(temp[0])
            softFile.write('Display Name: ' + display + '\nRegkey: ' + subkey + '\n')
        except:
            softFile.write('Regkey: ' + subkey + '\n')
 
    except:
        fp = StringIO.StringIO()
        traceback.print_exc(file=fp)
        errorMessage = fp.getvalue()
        error = 'Error for ' + key + '. Message follows:\n' + errorMessage
        errorLog.write(error)
        errorLog.write("\n\n")
 
softFile.close()
errorLog.close()