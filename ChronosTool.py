#!/usr/bin/python

import serial
import time
import datetime

###################################################################################################
class CBMcmd():
	"Class for handling Chronos Base Module commands"

	def __init__( self, opcode, payload=[] ):
		self.opcode = opcode
		self.payload = bytearray( payload )
		self.len = len( self.payload ) + 3
	
	def opcode( self, opcode ):
		self.opcode = opcode

	@staticmethod
	def maxlen():
		return 28

	def len( self ):
		return self.len

	def payload( self, payload ):
		self.payload = bytearray( payload )
		self.len = len( self.payload ) + 3

	def tobytes( self ):
		return bytearray( [0xff, self.opcode, self.len]  ) + bytearray( self.payload )

	def tostr( self ):
		return str( self.tobytes() )

	def tohex( self ):
		return self.tostr().encode('hex')

	def getitem( self ):
		return self.tobytes()

#x = CBMcmd( 0x47, "abcdefg" )
#print x.tohex()

###################################################################################################
class CBMpayload:
	"Class for handling Chronos Base Module command payloads"

	def __init__( self, data ):
		self.data = bytearray( data )

	@staticmethod
	def maxlen():
		return CBMcmd.maxlen()

	def tocmd( self, opcode ):
		return CBMcmd( opcode, self.data )

#x = CBMpayload( "abcdefghijklmnop" )
#print x.tocmd(0x47).tohex()

###################################################################################################
class CBMburst:
	"Class for handling Chronos Base Module bursts"

	max_burst_len = 0xf7

	def __init__( self, type, data ):
		self.type = type
		self.data = bytearray( data )
		self.len = len( self.data ) + 2

	@classmethod
	def maxlen( cls ):
		return cls.max_burst_len

	@classmethod
	def setmaxlen( cls, len ):
		cls.max_burst_len = len
		print "Maximum CBM burst length set to", hex( len )

	def topayloads( self ):
		#Reshape each burst into payloads
		max_payload_len = CBMpayload.maxlen()
		payloads = []
		burst = bytearray( [self.type, self.len-2] ) + self.data
		while burst:
			payload = CBMpayload( burst[:max_payload_len] )
			burst = burst[max_payload_len:]
			payloads.append( payload )
		return payloads

#x = CBMburst( 0x01, "ABCDEFGHIJKLMNOPQRTUVWXYZabcdefghijklmnopq" )
#print x.topayloads()[0].tocmd(0x47).tohex()
#print x.topayloads()[1].tocmd(0x47).tohex()


###################################################################################################
class CBMchunk:
	"Class for Chronos Base Module chunks"

	def __init__( self, address, data ):
		self.address = address
		self.data = bytearray( data )
		self.len = len( self.data ) + 2

	def tobursts( self ):
		#Reshape chunk into burst sequences
		max_burst_len = CBMburst.maxlen()
		bursts = []
		chunk = bytearray( [self.address>>8, self.address&0xff] ) + self.data
		nr = 0
		while chunk:
			if nr == 0:
				#First burst
				burst_id = 0x01
			else:
				#Consecutive bursts
				burst_id = 0x02
			nr += 1
			burst = CBMburst( burst_id, chunk[:max_burst_len] )
			chunk = chunk[max_burst_len:]
			bursts.append( burst )
		return bursts

#x = CBMchunk( 0xa000, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" )
#for b in x.tobursts():
#	for p in b.topayloads():
#		print p.tocmd(0x47).tohex()

###################################################################################################
class CBMdata:
	"Class for Chronos Base Module chunked data"

	def __init__( self, data=[] ):
		self.chunks = []
		self.data = bytearray( data )

	def importtxt( self, src ):
		if isinstance( src, str ):
			lines = src.split( "\n" )
			if len( lines ) == 1:
				filename = lines[0]
				file = open( filename, "r" )
				lines = file.readlines()
				file.close()
			else:
				if not lines[0][0] == '@':
					lines = []
		elif isinstance( src, list ):
			lines = src
		else:
			lines = []

		# Detect malformed txt file
		if lines[0][0] != '@' or lines[-1].strip() != 'q':
			lines = []

		if len( lines ) != 0:

			# Remove the final q-line
			lines.pop()

			# Iterate the chunks
			# Create a list of [ address, data ] per chunk
			chunk_data = bytearray()
			for line in lines:
				line = line.strip()
				if line[0] == '@':
					if chunk_data:
						self.chunks.append( CBMchunk( address, chunk_data ) )
					# New chunk starts with two-byte @address
					address = int( line[1:], 16 )
					print "New chunk found at address @" + hex(address)
					chunk_data = bytearray()
				else:
					data = line.replace( ' ', '' ).decode( 'hex' )
					chunk_data += bytearray( data )
			# Write out last chunk
			if chunk_data:
				self.chunks.append( CBMchunk( address, chunk_data ) )
			else:
				print "Error importing data."
		else:
			print "Error importing data."

		# Print chunks summary
		for chunk in self.chunks:
			print "Chunk @" + hex(chunk.address), "length", len(chunk.data)

	def tochunks( self ):
		return self.chunks


#data = CBMdata()
#data.importtxt( "ram_based_updater.txt" )
#for c in data.tochunks():
#	for b in c.tobursts():
#		for p in b.topayloads():
#			print p.tocmd(0x47).tohex()


###################################################################################################
class CBM:
	"Class for the Chronos base module"

	def __init__( self, device_name ):
		print 'Using Chronos Base Module on', device_name
		self.device = serial.Serial( device_name, 115200, timeout = 1 )
		self.allstatus()
		self.reset()
		self.allstatus()
		#Original Chronos tool reads twice
		response = self._wbsl_getmaxpayload()
		response = self._wbsl_getmaxpayload()
		CBMburst.setmaxlen( response.payload[0] )
		self.allstatus()

	def __del__( self ):
		print 'Closing Chronos Base Module at', self.device.port
		#self.reset()
		self.device.close

	def send( self, cmd ):
		self.device.write( cmd.tostr() )
		time.sleep( 0.015 )
		print 'SENT:', cmd.tohex()
		response = bytearray( self.device.read( 3 ) )
		if response[2] > 3:
			response += bytearray( self.device.read( response[2]-3 ) )
		self.response = CBMcmd( response[1], response[3:] )
		print 'RECV:', self.response.tohex()
		return self.response

	def sendcmd( self, opcode, payload=[] ):
		cmd = CBMcmd( opcode, payload )
		return self.send( cmd )

	def _reset( self ):
		return self.sendcmd( 0x01 )		#BM_Reset

	def _getstatus( self ):
		return self.sendcmd( 0x00, [0x00] )	#BM_GetStatus

	def _br_stop( self ):
		return self.sendcmd( 0x06 )		#BM_BR_Stop

	def _spl_start( self ):
		return self.sendcmd( 0x07 )		#BM_SPL_Start

	def _spl_getdata( self ):
		return self.sendcmd( 0x08, [0x00, 0x00, 0x00, 0x00] )	#BM_GetStatus

	def _spl_stop( self ):
		return self.sendcmd( 0x09 )		#BM_SPL_Stop

	def _sync_start( self ):
		return self.sendcmd( 0x30 )		#BM_SYNC_Start

	def _sync_getbufferstatus( self ):
		return self.sendcmd( 0x32, [0x00] )	#BM_SYNC_GetBufferStatus
	
	def _sync_readbuffer( self ):
		return self.sendcmd( 0x33, [0x00] )	#BM_SYNC_ReadBuffer

	def _wbsl_start( self ):
		return self.sendcmd( 0x40 )		#BM_WBSL_Start

	def _wbsl_stop( self ):
		return self.sendcmd( 0x46 )		#BM_WBSL_Stop

	def _wbsl_getstatus( self ):
		return self.sendcmd( 0x41, [0x00] )	#BM_WBSL_GetStatus

	def _wbsl_getmaxpayload( self ):
		return self.sendcmd( 0x49, [0x00] )	#BM_WBSL_GetMaxPayload

	def _wbsl_getpacketstatus( self ):
		return self.sendcmd( 0x48, [0x00] )	#BM_WBSL_GetPacketStatus

	def reset( self ):
		self._reset()
		return self._getstatus()

	def spl_start( self ): 
		return self._spl_start()

	def spl_getdata( self ):
		return self._spl_getdata()

	def spl_stop( self ):
		self._spl_start()
		return self._spl_stop()

	def sync_start( self ):
		return self._sync_start().payload

	def sync_getbufferstatus( self ):
		return self._sync_getbufferstatus().payload

	def wbsl_start( self ):
		#self.spl_stop()
		#time.sleep( 0.5 )
		#self._br_stop()
		#time.sleep( 1.0 )
		ret = self._wbsl_start().payload
		time.sleep( 0.1 )
		return ret	

	def wbsl_stop( self ):
		return self._wbsl_stop().payload

	def getstatus( self ):
		return self._getstatus().payload

	def wbsl_getstatus( self ):
		return self._wbsl_getstatus().payload

	def wbsl_getpacketstatus( self ):
		return self._wbsl_getpacketstatus().payload

	def allstatus( self ):
		return [self.getstatus(), self.wbsl_getstatus(), self.wbsl_getpacketstatus()]
		
	def sendburst( self, burst ):
		for payload in burst.topayloads():
			ret = self.send( payload.tocmd( 0x47 ) )
		return ret

	def sendburstheader( self, bursts ):
		#Construct initial info block
		nr_of_bursts = len( bursts )
		payload = bytearray( [0x00, nr_of_bursts&0xff, nr_of_bursts>>8] )
		return self.sendcmd( 0x47, payload )

	def spl_sync( self, dt=[], celsius=0, meters=0 ):
		if not dt:
			dt = datetime.datetime.now()
		payload = bytearray( 0x13 )
		payload[0x00] = 0x03
		payload[0x01] = dt.hour+0x80 #assume 24h
		payload[0x02] = dt.minute
		payload[0x03] = dt.second
		payload[0x04] = 0x07
		payload[0x05] = dt.year-0x700
		payload[0x06] = dt.month
		payload[0x07] = dt.day
		payload[0x08] = 0x06
		payload[0x09] = 0x1e
		payload[0x0a] = (celsius*10)>>8
		payload[0x0b] = (celsius*10)&0xff
		payload[0x0c] = meters>>8
		payload[0x0d] = meters&0xff

		self.spl_start()
		raw_input("Put your watch in sync mode and press return...")
		self.sendcmd( 0x31, payload ) #BM_SYNC_SendCommand
		time.sleep( 1 )
		self.spl_stop()

	def transmitburst( self, data ):
		self.wbsl_start()
		time.sleep( 0.5 )

		chunklist = data.tochunks()
		burstlist = []
		for chunk in chunklist:
			burstlist += chunk.tobursts()

		for burst in burstlist:
			done = 0
			while not done:
				status = self.wbsl_getpacketstatus()[0]
				if   status == 1:	#WBSL_DISABLED
					time.sleep( 0.2 )
				elif status == 2:	#WBSL_PROCESSING
					time.sleep( 0.1 )
				elif status == 4:	#WBSL_WAITFORSIZE
					self.sendburstheader( burstlist )
				elif status == 8:	#WBSL_WAITFORDATA
					if burstlist:
						self.sendburst( burstlist[0] )
						burstlist = burstlist[1:]
					else:
						print "WARNING: Burstlist underflow!"
						time.sleep(0.05)
				else:			#WBSL_COMPLETE
					done = 1
					break
		self.wbsl_stop()

	def wbsl_download( self, txtdata ):

		#Prepare data for downloading to watch
		updater = CBMdata()
		updater.importtxt( "ram_based_updater.txt" )
		data = CBMdata()
		data.importtxt( txtdata )

		print "Put your watch in rfbl \"open\" mode and press return."
		raw_input( "Afterwards, wait for a few seconds and start rfbl download..." )

		self.transmitburst( updater )
		self.transmitburst( data )		
		time.sleep( 1 )

###################################################################################################
# main

bm = CBM( "/dev/cu.usbmodem001" )
bm.wbsl_download( "eZChronos.txt" )
bm.spl_sync()


