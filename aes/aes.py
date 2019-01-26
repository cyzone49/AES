import sys
import numpy as np

class AES:

	def __init__(self):
		self.key = []
		self.nb = 4
		self.Rcon = [ 0x00000000,
           0x01000000, 0x02000000, 0x04000000, 0x08000000,
           0x10000000, 0x20000000, 0x40000000, 0x80000000,
           0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
           0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000,
           0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
           0x97000000, 0x35000000, 0x6A000000, 0xD4000000,
           0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000,
           0xC5000000, 0x91000000, 0x39000000, 0x72000000,
           0xE4000000, 0xD3000000, 0xBD000000, 0x61000000,
           0xC2000000, 0x9F000000, 0x25000000, 0x4A000000,
           0x94000000, 0x33000000, 0x66000000, 0xCC000000,
           0x83000000, 0x1D000000, 0x3A000000, 0x74000000,
           0xE8000000, 0xCB000000, 0x8D000000 ]

		self.Sbox = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 ],
					[ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 ],
					[ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 ],
					[ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 ],
					[ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 ],
					[ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf ],
					[ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 ],
					[ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 ],
					[ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 ],
					[ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb ],
					[ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 ],
					[ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 ],
					[ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a ],
					[ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e ],
					[ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf ],
					[ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]]

		self.invSBox = [[ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb ],
						[ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb ],
						[ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e ],
						[ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 ],
						[ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 ],
						[ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 ],
						[ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 ],
						[ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b ],
						[ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 ],
						[ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e ],
						[ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ],
						[ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 ],
						[ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f ],
						[ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef ],
						[ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 ],
						[ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ]]


	'''Finite Field Arithmetic'''
	def ffAdd( self, a, b ):
		return ( a^b ) & 0xff

	def xtime( self, a ):
		a = a << 1
		if ( a & 0x100 ):
			a ^= 0x11b
		return a

	def ffMultiply( self, a, b ):
		temp = a
		xtimes = []
		for i in range(8):
			xtimes.append( temp )
			temp = self.xtime( temp )

		result = 0
		for i in range(8):
			if b & 0x01 == 0x01:
				result ^= xtimes[i]
			b = b >> 1
		return result

	'''Key Expansion'''
	def subByte( self, a ):
		return self.Sbox[ ( a & 0xf0 ) >> 4 ][ a & 0xf ]

	def invSubByte( self, a ):
		return self.invSBox[ ( a & 0xf0 ) >> 4 ][ a & 0xf ]

	def subWord( self, a ):
		bytes = []
		bytes.append( ( a & 0xff000000 ) >> 24 )
		bytes.append( ( a & 0xff0000 ) >> 16 )
		bytes.append( ( a & 0xff00 ) >> 8 )
		bytes.append( a & 0xFF )

		result = 0
		for byte in bytes:
			result = ( result << 8 ) + self.subByte( byte )
		return result

	def rotWord( self, a ):
		return ( ( a << 8 ) & 0xffffffff ) | ( ( a >> 24 ) & 0xff )

	def keyExpansion( self, key, nk, nr ):
		# pass
		w = []
		for i in range( nk ):
			w.append( ( key >> ( 32 * ( nk - i - 1 ) ) ) & 0xffffffff )

		for i in range(nk, self.nb * (nr + 1)):
			temp = w[ i - 1 ]

			if nk > 6 and ( i % nk ) == 4 :
				temp = self.subWord( temp )
			elif i % nk == 0:
				temp = self.rotWord( temp )
				temp = self.subWord( temp )
				rcon = self.Rcon[ int( i / nk ) ]
				temp = temp ^ rcon

			w.append( w[ i - nk ] ^ temp )

		return w

	'''
	Cipher functions
	With their coressponding inverse functions
	'''

	def genEmptyState( self ):
		row = [ 0 ] * 4
		return [ row, row, row, row ]

	def subBytes( self, state ):
		# return [ [ self.Sbox[ byte ] for byte in word] for word in state ]
		result = [ [], [], [], [] ]
		for x in range(4):
			for y in range(4):
				result[ x ].append( self.subByte( state[ x ][ y ] ) )
		return result

	def invSubBytes( self, state ):
		result = [ [], [], [], [] ]
		for x in range(4):
			for y in range(4):
				result[ x ].append( self.invSubByte( state[ x ][ y ] ) )
		return result

	def shiftRows(self, state):
		result = [ [], [], [], [] ]
		for i in range(4):
			result[ i ] = state[ i ][ i: ] + state[ i ][ :i ]
		return result

	def invShiftRows( self, state ):
		result = [ [], [], [], [] ]
		for i in range(4):
			result[ i ] = state[ i ][ ( 4 - i ): ] + state[i][ :( 4 - i ) ]
		return result

	def mixColumns(self, state):
		# result = self.genEmptyState()
		result = [ [0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0] ]
		for col in range( 4 ):

			result[ 0 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( self.ffMultiply( 0x02, state[0][col] ),self.ffMultiply( 0x03, state[1][col] ) ), state[2][col] ), state[3][col] )

			result[ 1 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( state[0][col], self.ffMultiply( 0x02, state[1][col] ) ), self.ffMultiply( 0x03, state[2][col] ) ), state[3][col] )

			result[ 2 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( state[0][col], state[1][col] ), self.ffMultiply( 0x02, state[2][col] ) ), self.ffMultiply( 0x03, state[3][col] ) )

			result[ 3 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( self.ffMultiply( 0x03, state[0][col] ), state[1][col] ), state[2][col] ), self.ffMultiply( 0x02, state[3][col] ) )

		return result

	def invMixColumns(self, state):
		# result = self.genEmptyState()
		result = [ [0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0] ]
		for col in range(4):

			result[ 0 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( self.ffMultiply( 0x0e, state[0][col] ), self.ffMultiply( 0x0b, state[1][col]) ), self.ffMultiply( 0x0d, state[2][col] )), self.ffMultiply(0x09, state[3][col]))

			result[ 1 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( self.ffMultiply( 0x09, state[0][col] ), self.ffMultiply( 0x0e, state[1][col]) ), self.ffMultiply( 0x0b, state[2][col] )), self.ffMultiply(0x0d, state[3][col]))

			result[ 2 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( self.ffMultiply( 0x0d, state[0][col] ), self.ffMultiply( 0x09, state[1][col]) ), self.ffMultiply( 0x0e, state[2][col] )), self.ffMultiply(0x0b, state[3][col]))

			result[ 3 ][ col ] = self.ffAdd(self.ffAdd(self.ffAdd( self.ffMultiply( 0x0b, state[0][col] ), self.ffMultiply( 0x0d, state[1][col]) ), self.ffMultiply( 0x09, state[2][col] )), self.ffMultiply(0x0e, state[3][col]))

		return result

	def getRoundKey(self, w, round):
		roundKey = [ [0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0] ]
		for x in range(4):
			for y in range(4):
				roundKey[ x ][ y ] = ( w[ round * 4 + y ] >> ( ( 3 - x ) * 8 ) ) & 0xff
		return roundKey

	def addRoundKey( self, w, round, state ):
		result = [ [0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0] ]
		roundKey = self.getRoundKey( w, round )
		for x in range(4):
			for y in range(4):
				result[x][y] = self.ffAdd( state[x][y], roundKey[x][y] )
		return result

	def invAddRoundKey( self, state ):
		return self.addRoundKey( state )

	def cipher( self, input, key, nk, nr, debugMode=False ):
		result = [ [0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0] ]
		w = self.keyExpansion( key, nk, nr )
		state = self.toMatrix( input )
		state = self.addRoundKey(w, 0, state)
		round = 1

		if debugMode == True:
			print( "\nround[0].input:\t\t" + hex( input ) )
			print( "round[0].k_sch:\t\t" + hex( self.toHexBytes( self.getRoundKey( w, 0 ) ) ) )

		# first nr - 1 rounds
		while round < nr :
			if debugMode == True:
				print( "round[" + str( round ) + "].start:\t\t" + hex( self.toHexBytes( state ) ) )
			state = self.subBytes( state )
			if debugMode == True:
				print( "round[" + str( round ) + "].s_box:\t\t" + hex( self.toHexBytes( state ) ) )
			state = self.shiftRows( state )
			if debugMode == True:
				print( "round[" + str( round ) + "].s_row:\t\t" + hex( self.toHexBytes( state ) ) )
			state = self.mixColumns( state )
			if debugMode == True:
				print( "round[" + str( round ) + "].m_col:\t\t" + hex( self.toHexBytes( state ) ) )
				print( "round[" + str( round ) + "].k_sch:\t\t" + hex( self.toHexBytes( self.getRoundKey( w, round ) ) ) )
			state = self.addRoundKey( w, round, state )
			round += 1

		# last round
		round = nr
		if debugMode == True:
			print( "round[" + str( round ) + "].start:\t" + hex( self.toHexBytes( state ) ) )

		state = self.subBytes(state)
		if debugMode == True:
			print( "round[" + str( round ) + "].s_box:\t" + hex( self.toHexBytes( state ) ) )

		state = self.shiftRows(state)
		if debugMode == True:
			print( "round[" + str( round ) + "].s_row:\t" + hex( self.toHexBytes( state ) ) )

		state = self.addRoundKey(w, round, state)
		if debugMode == True:
			print( "round[" + str( round ) + "].k_sch:\t" + hex( self.toHexBytes( self.getRoundKey( w, round ) ) ) )
			print( "round[" + str( round ) + "].output:\t" + hex( self.toHexBytes( state ) ) )

		return state

	def invCipher( self, input, key, nk, nr, debugMode=False ):
		result = [ [0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0] ]
		w = self.keyExpansion( key, nk, nr )
		state = self.toMatrix( input )
		state = self.addRoundKey( w, nr, state )

		if debugMode == True:
			print( "\nround[0].iinput:\t" + hex( input ) )
			print( "round[0].ik_sch\t\t" + hex( self.toHexBytes( self.getRoundKey( w, nr ) ) ) )


		round = nr - 1
		# first nr - 1 rounds
		while round > 0:
			if debugMode == True:
				print( "round[" + str( nr - round ) + "].istart\t\t" + hex( self.toHexBytes( state ) ) )

			state = self.invShiftRows( state )
			if debugMode == True:
				print( "round[" + str( nr - round ) + "].isrow\t\t" + hex( self.toHexBytes( state ) ) )

			state = self.invSubBytes( state )
			if debugMode == True:
				print( "round[" + str( nr - round ) + "].is_box\t\t" + hex( self.toHexBytes( state ) ) )

			state = self.addRoundKey(w, round, state)
			if debugMode == True:
				print( "round[" + str( nr - round ) + "].ik_sch\t\t" + hex( self.toHexBytes( self.getRoundKey( w, round ) ) ) )
				print( "round[" + str( nr - round ) + "].ik_add\t\t" + hex( self.toHexBytes( state ) ) )

			state = self.invMixColumns(state)
			round -= 1

		if debugMode == True:
			print( "round[" + str( nr ) + "].istart\t" + hex( self.toHexBytes( state ) ) )

		# last round
		state = self.invShiftRows( state )
		if debugMode == True:
			print( "round[" + str( nr ) + "].is_row\t" + hex( self.toHexBytes( state ) ) )

		state = self.invSubBytes( state )
		if debugMode == True:
			print( "round[" + str( nr ) + "].is_box\t" + hex( self.toHexBytes( state ) ) )
			print( "round[" + str( nr ) + "].ik_sch\t" + hex( self.toHexBytes( self.getRoundKey( w, 0 ) ) ) )

		state = self.addRoundKey( w, 0, state )
		if debugMode == True:
			print( "round[" + str( nr ) + "].ioutput\t" + hex( self.toHexBytes( state ) ) )

		return state

	'''
	Helper functions for Debugging purposes
	'''
	def toMatrix(self, bytes):
		result = [ [], [], [], [] ]
		for i in range(16):
			result[ i % 4 ].append( ( bytes >> ( ( 16 - i - 1 ) * 8 ) ) & 0xff )
		return result

	def toHexBytes(self, matrix):
		bytes = 0
		for y in range(4):
			for x in range(4):
				bytes = (bytes << 8) + matrix[x][y]
		return bytes

	'''
	test cipher() function
	param: input text, key, nk, nr, and sample output to compare to
	prints out cipher correctly if generated output == sample output,
	fails otherwise
	'''
	def testCipher( self, input, key, nk, nr, output, debugMode=False ):
		print("PLAINTEXT:\t\t" + str(hex(input)))
		print("KEY:\t\t\t" + str(hex(key)))
		print("\nCIPHER (ENCRYPT):")

		result = self.cipher( input, key, nk, nr, debugMode )
		print( "\n\nCalculated Result\t" + hex( self.toHexBytes( result ) ) )
		print( "Correct Output\t\t" + hex( output ) )
		if str( np.array( result ) ) == str( np.array( self.toMatrix( output ) ) ):
			print("\t >> Cipher correctly")
		else:
			print("\t >> Cipher fails")

	def testInvCipher( self, input, key, nk, nr, output, debugMode=False ):
		# print("PLAINTEXT:\t\t" + str(hex(input)))
		# print("KEY:\t\t\t" + str(hex(key)))
		print( "\nEQUIVALENT INVERSE CIPHER (DECRYPT):")

		result = self.invCipher( input, key, nk, nr, debugMode )
		print( "\n\nCalculated Result\t" + hex( self.toHexBytes( result ) ) )
		print( "Correct Output\t\t" + hex( output ) )
		if str( np.array( result ) ) == str( np.array( self.toMatrix( output ) ) ):
			print("\t >> Inverse Cipher correctly")
		else:
			print("\t >> Inverse Cipher fails")


	'''
	main method to test cipher functionalities.
	** Note: to enable debugMode, set last param of testCipher to True **
	'''
def main():

	aes = AES()
	np.set_printoptions(formatter={'int':hex})
	print("\n\nStarted unit testing")

	print("\n\n----------------------------------------------------")
	print("\nAES 128 ( nk = 4, nr = 10 )")
	aes.testCipher( 0x00112233445566778899aabbccddeeff,
					0x000102030405060708090a0b0c0d0e0f,
					4,
					10,
					0x69c4e0d86a7b0430d8cdb78070b4c55a, True )


	aes.testInvCipher( 0x69c4e0d86a7b0430d8cdb78070b4c55a,
						0x000102030405060708090a0b0c0d0e0f,
						4,
						10,
						0x00112233445566778899aabbccddeeff, True )


	print("\n\n----------------------------------------------------")
	print("\nAES 192 ( nk = 6, nr = 12 )")
	aes.testCipher( 0x00112233445566778899aabbccddeeff,
					0x000102030405060708090a0b0c0d0e0f1011121314151617,
					6,
					12,
					0xdda97ca4864cdfe06eaf70a0ec0d7191 )
	aes.testInvCipher( 0xdda97ca4864cdfe06eaf70a0ec0d7191,
						0x000102030405060708090a0b0c0d0e0f1011121314151617,
						6,
						12,
						0x00112233445566778899aabbccddeeff )


	print("\n\n----------------------------------------------------")
	print("\nAES 256 ( nk = 8, nr = 14 )")
	aes.testCipher( 0x00112233445566778899aabbccddeeff,
					0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f,
					8,
					14,
					0x8ea2b7ca516745bfeafc49904b496089 )
	aes.testInvCipher( 0x8ea2b7ca516745bfeafc49904b496089,
					0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f,
					8,
					14,
					0x00112233445566778899aabbccddeeff )

if __name__ == "__main__":
    main()
