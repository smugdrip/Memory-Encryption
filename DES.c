/** 
    @file DES.c
    @author John Butterfield (jpbutte2)
    Implementation of the DES algorithm. This component holds
    the necessary functions that the DES encryption and decryption
    algorithms uses.
*/

#include "DES.h"

void prepareKey( byte key[ BLOCK_BYTES ], char const *textKey )
{

    strncpy( (char *)key, textKey, BYTE_SIZE );

    memset( key + strlen(textKey), 0, BLOCK_BYTES - strlen(textKey) );
}

/**
    Perform a "left rotation" on an array of bytes. The bits are shifted
    left with the highest order bit wrapping around.
    @param bytes the array of bytes to rotate
    @param n the amount bits are rotated by
*/
static void leftRotate( byte bytes[], int n )
{
    int bits[ BLOCK_HALF_BITS ]; // array to store individual bits

    for ( int i = 0; i < BLOCK_HALF_BYTES; i++ ) {
        unsigned char value = bytes[ i ];
        for ( int j = 0; j < BYTE_SIZE; j++ ) {
            bits[ i * BYTE_SIZE + j ] = ( value >> ( (BYTE_SIZE - 1) - j) ) & 1;
        }
    }

    // Perform rotation on the first 28 bits
    for ( int i = 0; i < n; i++ ) {
        int temp = bits[ 0 ];
        for (int j = 0; j < ( SUBKEY_HALF_BITS - 1 ); j++) {
            bits[ j ] = bits[ j + 1 ];
        }
        bits[ ( SUBKEY_HALF_BITS - 1 ) ] = temp;
    }

    for ( int i = 0; i < BLOCK_HALF_BYTES; i++ ) {
        byte value = 0;
        for ( int j = 0; j < BYTE_SIZE; j++ ) {
            value |= ( bits [ i * BYTE_SIZE + j ] << ( (BYTE_SIZE - 1) - j ) );
        }
        bytes[ i ] = value;
    }
}

void generateSubkeys( byte K[ ROUND_COUNT ][ SUBKEY_BYTES ], byte const key[ BLOCK_BYTES ] )
{
    
    byte C[ ROUND_TO_BYTES( SUBKEY_HALF_BITS ) ];
    byte D[ ROUND_TO_BYTES( SUBKEY_HALF_BITS ) ];

    // Initial permutation of the key to get C0 and D0
    permute( C, key, leftSubkeyPerm, SUBKEY_HALF_BITS );
    permute( D, key, rightSubkeyPerm, SUBKEY_HALF_BITS );

    for ( int i = 1; i < ROUND_COUNT; i++ ) {
        // Rotate C and D according to the shift schedule
        leftRotate( C, subkeyShiftSchedule[i] );
        leftRotate( D, subkeyShiftSchedule[i] );

        // Create a combined array to hold C and D, ensuring it is 56 bits (7 bytes) long
        byte combined[ C_D_BYTES ];

        // Clearing combined array
        memset( combined, 0, sizeof( combined ) );

        // Copying the bits from C and D into combined
        for ( int j = 1; j <= SUBKEY_HALF_BITS; j++ ) {
            putBit( combined, j, getBit( C, j ) );
            putBit( combined, j + SUBKEY_HALF_BITS, getBit( D, j ) );
        }

        // Permute combined C and D to get the subkey
        permute( K[ i ], combined, subkeyPerm, SUBKEY_BITS );
    }
}

int getBit( byte const data[], int idx )
{
    idx--;

    // Calculating the byte index
    int byteIndex = idx / BYTE_SIZE;

    // Calculating the bit position within the byte
    int bitPosition = idx % BYTE_SIZE;

    // Extracting the bit using bitwise AND and bit shifting
    return ( data[ byteIndex ] >> (( BYTE_SIZE - 1 ) - bitPosition)) & 1;
}

void putBit(byte data[], int idx, int val)
{
    // Adjusting the index to start from 0
    idx--;

    // Calculating the byte index
    int byteIndex = idx / BYTE_SIZE;

    // Calculating the bit position within the byte
    int bitPosition = idx % BYTE_SIZE;

    if ( val == 1 ) {
        // Set the bit
        data[ byteIndex ] |= ( 1 << ( ( BYTE_SIZE - 1 ) - bitPosition ) );
    } else {
        // Clear the bit
        data[ byteIndex ] &= ~( 1 << ( ( BYTE_SIZE - 1 ) - bitPosition ) );
    }
}

void permute( byte output[], byte const input[], int const perm[], int n )
{
    // Initialize all bits in output to 0
    int outputBytes = ROUND_TO_BYTES( n );
    for ( int i = 0; i < outputBytes; i++ ) {
        output[ i ] = 0;
    }

    // Perform the permutation
    for ( int i = 0; i < n; i++ ) {
        int bit = getBit( input, perm[ i ] );
        putBit( output, i + 1, bit );
    }

}

void encryptBlock( DESBlock *block, byte const K[ ROUND_COUNT ][ SUBKEY_BYTES ] ) 
{
    byte L[ BLOCK_HALF_BYTES ], R[ BLOCK_HALF_BYTES ], newR[ BLOCK_HALF_BYTES ];

    // Initial permutation
    permute( L, block->data, leftInitialPerm, BLOCK_HALF_BITS );
    permute( R, block->data, rightInitialPerm, BLOCK_HALF_BITS );

    // 16 Rounds
    for ( int i = 1; i < ROUND_COUNT; i++ ) {
        memcpy( newR, R, BLOCK_HALF_BYTES );  // Copy R to newR for processing

        // Apply fFunction
        byte fResult[ BLOCK_HALF_BYTES ];
        fFunction( fResult, R, K[ i ] );

        // XOR fResult with L and store in R
        for ( int j = 0; j < BLOCK_HALF_BYTES; j++ ) {
            R[ j ] = L[ j ] ^ fResult[ j ];
        }

        memcpy( L, newR, BLOCK_HALF_BYTES );  // L becomes the old R
    }

    // Combine R16 and L16
    byte encryptedBlock[ BLOCK_BYTES ];
    memcpy( encryptedBlock, R, BLOCK_HALF_BYTES );
    memcpy( encryptedBlock + BLOCK_HALF_BYTES, L, BLOCK_HALF_BYTES );

    // Final permutation
    permute( block->data, encryptedBlock, finalPerm, BLOCK_BYTES * BYTE_SIZE );
}

void fFunction( byte result[ BLOCK_HALF_BYTES ], byte const R[ BLOCK_HALF_BYTES ], 
                byte const K[ SUBKEY_BYTES ] )
{
    
    byte expandedR[ SUBKEY_BYTES ]; // 48-bit expanded R value
    permute( expandedR, R, expandedRSelector, SUBKEY_BITS );

    byte B[ SUBKEY_BYTES ]; // 48-bit value to store the XOR result
    for ( int i = 0; i < SUBKEY_BYTES; i++ ) {
        B[ i ] = expandedR[ i ] ^ K[ i ];
    }

    byte sBoxOutput[ BLOCK_HALF_BYTES ]; // 32-bit output from the S-Boxes
    
    for ( int i = 0; i < BLOCK_BYTES; i++ ) {
        
        byte sBoxResult[ 1 ];
        sBox( sBoxResult, B, i );

        // Place 4-bit S-Box result in the correct position in sBoxOutput
        for (int j = 1; j <= SBOX_RESULT_BITS ; ++j) {
            putBit( sBoxOutput, i * SBOX_RESULT_BITS + j, getBit( sBoxResult, j ) );
        }

    }

    // permute with fFunctionPerm
    permute( result, sBoxOutput, fFunctionPerm, BLOCK_HALF_BITS );

}

void sBox(byte output[ 1 ], byte const input[ SUBKEY_BYTES ], int idx )
{

    output[0] = 0;
    
    // Calculate the start index for bit extraction, considering 1-based indexing
    int startBitIdx = idx * SBOX_INP_BITS + 1; // +1 because the indexing starts at 1

    // Extract bits for the 'row' variable
    int bit1 = getBit( input, startBitIdx );
    int bit6 = getBit( input, startBitIdx + ( SBOX_INP_BITS - 1 ) );
    int row = ( bit1 << 1 ) | bit6;

    // Initialize the 'column' variable
    int column = 0;

    // Extract and concatenate bits 2-5 for the 'column' variable
    for (int i = 0; i < SBOX_INP_BITS - 2; i++) {
        int bit = getBit( input, startBitIdx + i + 1 ); // +1 to get the second bit
        column |= (bit << ( 3 - i ) );
    }

    byte sBoxValue = sBoxTable[ idx ][ row ][ column ];

    sBoxValue <<= SBOX_RESULT_BITS;

    output[ 0 ] = sBoxValue;

}

void decryptBlock( DESBlock *block, byte const K[ ROUND_COUNT ][ SUBKEY_BYTES ] )
{
    byte L[ BLOCK_HALF_BYTES], R[ BLOCK_HALF_BYTES ], newR[ BLOCK_HALF_BYTES ];

    // Initial permutation
    permute( L, block->data, leftInitialPerm, BLOCK_HALF_BITS );
    permute( R, block->data, rightInitialPerm, BLOCK_HALF_BITS );

    // 16 Rounds - but with the subkeys in reverse order
    for ( int i = ROUND_COUNT - 1; i >= 1; i-- ) {
        memcpy( newR, R, BLOCK_HALF_BYTES );  // Copy R to newR for processing

        // Apply fFunction with the subkey in reverse order
        byte fResult[ BLOCK_HALF_BYTES ];
        fFunction( fResult, R, K[i] );

        // XOR fResult with L and store in R
        for ( int j = 0; j < BLOCK_HALF_BYTES; j++ ) {
            R[ j ] = L[ j ] ^ fResult[ j ];
        }

        memcpy( L, newR, BLOCK_HALF_BYTES );  // L becomes the old R
    }

    // Combine R16 and L16
    byte decryptedBlock[ BLOCK_BYTES ];
    memcpy( decryptedBlock, R, BLOCK_HALF_BYTES );
    memcpy( decryptedBlock + BLOCK_HALF_BYTES, L, BLOCK_HALF_BYTES );

    // Final permutation
    permute( block->data, decryptedBlock, finalPerm, BLOCK_BYTES * BYTE_SIZE );

}
