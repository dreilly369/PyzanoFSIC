# PyzanoFSIC
Pyzano FS Integrity Checker is a tool for monitoring the integrity of a Linux File System. It recursively scans directories for files. It then takes the hash value of the files binary data and compares it to the last known hash for that file. It has several features such as:
* Store Binary backups of important files and programs (see limitations)
* Restore Files and folders from the backups
* Monitor System tables and binaries for rootkit changes
* option to send the File to VirusTotal if it is not found
* Works with online scanners:
  - VirusTotal
  - Jotti
  - NoVirusThanks (Requires upload)
  - ThreatExpert (Requires upload)


# Usage
## Pyzano Options
Usage: pyzano.py [options]
For more details use:
  ```python pyzano.py -h```

## Getting Started
The VirusTotal results are stored in a SQLLite .db file for easier submittion. The Database has to be initialized before it can be used. This can be done with the call:
  ```python pyzano.py --init !```
If you plan to run a local MySQL Database, otherwise:
```python pyzano.py --init True```

Now we can populate the file fingerprint database. If you know that you are working from  clean image you can add the option:
```
--no-scan True
```
To skip scanning the3 Hashes with VirusTotal. This will significantly increase the speed of the first scan, which can take a considerable amount of time on a large file system. 

There are two primary use cases for Pyzano:
## File System Integrity Checker (FSIC)
The primary use of Pyzano is to verify that no data has been changed on a local machine without the users knowledge. It can be scheduled to regularly run checks of important directories and alert the user to new files, changed files, and deleted files. It is usually preferable to not have Pyzano submit files in this mode since you may end up submitting files you did not mean to. An example call to check the entire local partition:
```
  python pyzano.py \
  --verbose True \
  --handle-added i \
  --handle-deleted i \
  --handle-changed i \
  --directory /
```
  
## Malware Analysis Tool-Chain Helper (MATCH)
Because Pyano can monitor the entire Linux File System, it can be used to monitor a lot of changes made my a potential MalWare sample. To use Pyzano in this manner install it inside a target Virtual Machine and edit the configuration to store the records on the host systems Mysql DB. That will avoid the database results potentially being contaminated by the malware. This method stores an encoded format of the binary data for the files, so it is important to have enough storage space for your Snapshot DB on your host.
Next run a snapshot scan of the clean VM:
```
  python pyzano.py \
  --store-file True \
  --handle-deleted s \
  --handle-changed s \
  --handle-added a \
  --no-scan True \
  --directory /dreilly369/venv/test_drive/
```

Now, run the malware sample inside the VM using your normal analysis method. When it is finished executing you can run a comparison scan using the following command:
```
  python pyzano.py \
  --verbose 1 \
  --handle-added i \
  --handle-deleted i \
  --handle-changed i \
  --upload-file True \
  --email-db True \
  --directory /dreilly369/venv/test_drive/
```
  
The output of the command will step through the files added, changed, and deleted since the last run. New and changed files will be scanned (and uploaded if neccessary) to VirusTotal. It will then prompt you to choose what to do. You can just skip through to read what FS changes were made. You do not have to revert at this point because the next command will handle resetting the environment from the DB for you:
```
  python pyzano.py \
  --handle-added delete \
  --handle-deleted restore \
  --handle-changed revert \
  --directory /dreilly369/venv/test_drive/
```
  
Note the use of the full variable name. This is perfectly acceptable and will often times make scripts easier to read.

## Emailing the VirusTotal Results
During any scan you can add the:
```
--email-db True
```
option to have the VirusTotal results DB emailed to the configured Admin Email via a GMail account. The Database is base64 encoded and sent as text inside an email.

# Limitations
Currently there is a known limitation on the size of the Binary that can be stored in the MySQL Database. This is becaue of the max_allowed_packet size. Currently the maximum packet size allowed is 1Gb. There us also a restriction on the length of the encoded binary's string. That limit is 4,294,967,295 characters. Pyzano will throw an exception if either of these conditions is violated. You may still scan these files, and store their meta data, but you will nto be able to create a binary backup via Pyzano.
