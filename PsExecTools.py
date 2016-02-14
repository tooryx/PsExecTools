#! /usr/bin/python

# This file is part of PsExecTools.
# Please see LICENSE for details.

# Most of this file is just calls to impacket...
# ...and comments. Lots of comments.
#
# Author: tooryx
# March, 2015

import re
import nmap

from psexec import PSEXEC
from impacket import smb
from impacket.smbconnection import *

class PsExecTools(object):
	"""
	PsExecTools is just a bunch of usefull functions that allow a more
	powerfull instrumentation of psExec in python.

	The basic goal of this library is to help with file transfer.
	Thus, you can load multiple files, launch an action and then
		automatically clean behind you.

						/\ WARNING /\
	In your scripts, you have to implement the exception management process.
	This has not been implemented in the library to help you implement better
		exception handling.
						\/ WARNING \/

	One PsExecTools instance = One target.
	This was decided for better use.

	Basic example:

	for host in HOST_LIST:
		psexec = PsExecTools(host, u, p, d):
		psexec.mkdir("C:\mytempdir\\")
		psexec.smb_put_file("/tmp/mimikatz.exe", "C:\mytempdir\mimi.exe")
		psexec.command("mimikatz.exe [...]")
		psexec.smb_clean()
	"""

	def __init__(self, target, username, password=None, domain=".", share="C$", \
				lmHash=None, ntHash=None):
		"""
		This function initialize the tools.
		It's reponsible for initializing the SMB connection.

		Tips: Using "." as a domain automatically chose the station name.
		Though this trick may not work on old Windows.

		The share name is used only for file transfer.
		Indeed, impacket retrieves share for psExec already.
		"""
		self._smbConn = None
		# Possible values for dialect:
		#	smb.SMB_DIALECT
		#   SMB2_DIALECT_002
		#   SMB2_DIALECT_21
		#   SMB2_DIALECT_30
		self._smbDialect = smb.SMB_DIALECT
		self._uploadedFileHistory = []
		self._createdDirHistory = []
		self._output = Output()
		self._hasBeenScanned = False
		self._isHostUp = False
		self.target = target
		self.username = username
		self.password = password
		self.domain = domain
		self.share = share
		self.lmHash = ""
		self.ntHash = ""

		self._output.echoNewHost(target)

		if not lmHash and not ntHash and not password:
			raise Exception("[Err] At least one authentication mode should be set")

	# FIXME: destruct functions.

	def _smb_close(self):
		"""
		<Internal function>
		Close the SMB connection.
		"""
		if self._smbConn:
			self._smbConn.logoff
			del(self._smbConn)

	def _smb_connect(self):
		"""
		<Internal function>
		Initiate the SMB connection for file transfer.
		"""
		if self._smbConn:
			return

		self._smbConn = SMBConnection('*SMBSERVER', \
			self.target, preferredDialect=self._smbDialect)
		self._smbConn.login(self.username, self.password, self.domain, \
			self.lmHash, self.ntHash)

	def _compute_relative_path(self, absolutePath):
		# FIXME: This is nonsence. Use python re here.
		if self.share == "C$" or self.share == "c$":
			if absolutePath[:3] == "C:\\":
				relativePath = absolutePath[3:]
			else:
				raise Exception("[Err] Absolute path not in c$")
		else:
			relativePath = "..\..\%s" % (absolutePath[3:])

		return relativePath

	def isHostAlive(self):
		"""
		Runs a quick nmap on the host to ensure it's up.
		Althought I'd recommend running an nmap more globally for performances.

		Return value: True if host has 139 and 445 open, False if host hasn't.
		"""
		if not self._hasBeenScanned:
			self._output.echoHostInfo("Is host ready ?")
			nm = nmap.PortScanner()
			nm.scan(hosts=self.target, arguments="-Pn -p 139,445")

			self._isHostUp = (nm[self.target].has_tcp(139) and nm[self.target].has_tcp(445) and nm[self.target]['tcp'][139]["state"] == "open" and nm[self.target]['tcp'][445]["state"] == "open")

			if not self._isHostUp:
				self._output.echoHostInfo("Host is not ready (down or smb disabled).")
			else:
				self._output.echoHostInfo("Host ready. Let's go!")

		return self._isHostUp

	def smb_put_file(self, localAbsolutePath, remoteAbsolutePath):
		"""
		Put a local file on the remote server.

		Arguments
			localAbsolutePath: The absolute path to the local file.
			remoteAbsolutePath: The absolute path of the file on the server.

		Return value: 0 on success, 1 on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		if not remoteAbsolutePath in self._uploadedFileHistory:
			self._uploadedFileHistory.append(remoteAbsolutePath)

		self.smb_put_file_noClean(localAbsolutePath, remoteAbsolutePath)

	def smb_put_file_noClean(self, localAbsolutePath, remoteAbsolutePath):
		"""
		Put a local file on the remote server.
		The file is not added to the history of uploaded file.
		Hence, it won't be cleaned...

		Arguments
			localAbsolutePath: The absolute path to the local file.
			remoteAbsolutePath: The absolute path of the file on the server.

		No return value, exception raised on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		self._output.echoHostInfo("Uploading file: %s" % (remoteAbsolutePath))
		relPath = self._compute_relative_path(remoteAbsolutePath)

		try:
			with open(localAbsolutePath, "r") as f:
				self._smbConn.putFile(self.share, relPath, f.read)
		except SessionError as ex:
			self._output.echoError(ex)
			raise ex

	def smb_get_file(self, remoteAbsolutePath, localAbsolutePath):
		"""
		Retrieves a file of the server.

		Arguments
			remoteAbsolutePath: The absolute path of the file on the server.
			localAbsolutePath: The absolute path where the file should be stored.

		No return value, exception raised on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		self._output.echoHostInfo("Downloading file: %s" % (remoteAbsolutePath))
		relPath = self._compute_relative_path(remoteAbsolutePath)

		try:
			with open(localAbsolutePath, "w") as f:
				self._smbConn.getFile(self.share, relPath, f.write)
		except SessionError as ex:
			self._output.echoError(ex)
			raise ex

	def smb_del_file(self, remoteAbsolutePath):
		"""
		Deletes a file.

		Arguments
			remoteAbsolutePath: The absolute path of the file on the server.

		No return value, exception raised on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		self._output.echoHostInfo("Deleting file: %s" % (remoteAbsolutePath))
		relPath = self._compute_relative_path(remoteAbsolutePath)

		try:
			self._smbConn.deleteFile(self.share, relPath)
		except SessionError as ex:
			self._output.echoError(ex)
			raise ex

	def smb_mkdir(self, remoteAbsolutePath):
		"""
		Creates a directory on the remote server.

		Arguments
			remoteAbsolutePath: Absolute path of the directory to be created.

		No return value, exception raised on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		if not remoteAbsolutePath in self._createdDirHistory:
			self._createdDirHistory.append(remoteAbsolutePath)

		self.smb_mkdir_noClean(remoteAbsolutePath)

	def smb_mkdir_noClean(self, remoteAbsolutePath):
		"""
		Creates a directory on the remote server.
		The directory is not added to the history of created dir.
		Hence, it won't be cleaned...

		Arguments
			remoteAbsolutePath: Absolute path of the directory to be created.

		No return value, exception raised on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		self._output.echoHostInfo("Creating dir %s" % (remoteAbsolutePath))
		relPath = self._compute_relative_path(remoteAbsolutePath)

		try:
			self._smbConn.createDirectory(self.share, relPath)
		except SessionError as ex:
			self._output.echoError(ex)
			raise ex

	def smb_rmdir(self, remoteAbsolutePath):
		"""
		Deletes a directory on the remote server.

		Arguments
			remoteAbsolutePath: Absolute path of the directory to be deleted.

		No return value, exception raised on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		self._output.echoHostInfo("Removing dir %s" % (remoteAbsolutePath))
		relPath = self._compute_relative_path(remoteAbsolutePath)

		try:
			self._smbConn.deleteDirectory(self.share, relPath)
		except SessionError as ex:
			self._output.echoError(ex)
			raise ex

	def smb_clean(self):
		"""
		Clean all uploaded file (that have been historized) / created directories.

		No return value, exception raised on error.
		"""
		if not self._smbConn:
			self._smb_connect()

		self._output.echoHostInfo("Cleaning off")

		for f in self._uploadedFileHistory:
			self.smb_del_file(f)

		for d in self._createdDirHistory:
			self.smb_rmdir(d)

	def command(self, commandToExecute):
		"""
		Executes a command using psExec.

		Arguments
			commandToExecute: The command to execute... Duh.

		Return value: Return code of the command.
		"""
		if (not self.lmHash and not self.ntHash) or (not self.ntHash):
			hashes = None
		else:
			lmHash = lmHash if lmHash else "000000000000000000"
			hashes = "%s:%s" % (lmHash, ntHash)

		self._output.echoHostInfo("Preparing for command exec")

		try:
			execute = PSEXEC(commandToExecute, None, None, None, \
				username=self.username, password=self.password, \
				domain=self.domain, hashes=hashes)
			execute.run(self.target)
		except SystemExit as ex:
			return ex

class Output(object):
	"""
	Because we want classy outputs!
	"""
	def __init__(self, colorEnabled=True):
		self._colorEnabled = colorEnabled

		if self._colorEnabled:
			self._red = "\033[31;01m"
			self._blue = "\033[34;01m"
			self._green = "\033[32;01m"
			self._yellow = "\033[33;01m"
			self._bold = "\033[00;01m"
			self._nocolor = "\033[00m"
		else:
			self._red = ""
			self._blue = ""
			self._green = ""
			self._yellow = ""
			self._bold = ""
			self._nocolor = ""

	def echoNewHost(self, hostName):
		print "%s[%s+%s]%s %s" % (self._bold, self._green, self._bold, \
		 self._nocolor, hostName)

	def echoError(self, error):
		print "%s[%sERR%s]%s %s" % (self._bold, self._red, self._bold, \
			self._nocolor, error)

	def echoHostInfo(self, info):
		print "  %s[%s-%s]%s %s" % (self._blue, self._yellow, self._blue, \
			self._nocolor, info)
