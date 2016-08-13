#!/usr/bin/env python
import os
import json
from base64 import b64encode
import smtplib

SUBJECT = "Email Data"

# This class handles emailing the detector results to the admin email
class EmailManager:
            
    def load_config(self):
        base_dir = os.path.dirname(os.path.dirname(__file__))
        sep = os.sep
        conf_loc = base_dir+sep+"config"+sep+"pyzano_config.json"
        return json.load(open(conf_loc,"r"))

    def emailDBFile(self):
        conf = self.load_config()
        sep = os.sep
        db_dir = os.path.dirname(os.path.dirname(__file__))+sep+conf["SQLL3DBNAME"]

        conf = self.load_config()
        email = conf["REPORTEMAIL"]
        subj = "Pyzano Report for %s" % conf["HOSTNAME"]
        gmail_user = conf["GMAILUSER"]
        gmail_pwd = conf["GMAILPASS"]
        msg = {}
        msg['Subject'] = subj 
        msg['From'] = "Pyzano %s" % conf["HOSTNAME"]
        msg['To'] = email
        data_file = b64encode(open(db_dir,"rb").read())
        print data_file
        
        # Prepare actual message
        message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
        """ % (msg['From'], email, msg['Subject'], data_file)
        
        try:
            server = smtplib.SMTP('smtp.gmail.com:587')
            server.ehlo()
            server.starttls()  
            server.login(gmail_user, gmail_pwd)
            server.sendmail(gmail_user, email, message)
            server.close()
            print 'success'
        except:
            print "failed to send mail"
            raise Exception