#! /usr/bin/python

# This file is part of PsExecTools.
# Please see LICENSE for details.

from PsExecTools import PsExecTools

username = ""
domain = ""
password = ""
target = ""

psexec = PsExecTools(target, username, password, domain=domain)
psexec.smb_mkdir("C:\\test\\")
psexec.smb_mkdir_noClean("D:\\test_stays")
psexec.command("cmd.exe /C dir C:\\")
psexec.smb_clean()
psexec.command("cmd.exe /C dir C:\\")
