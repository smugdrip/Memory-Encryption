/** 
    @file DES.h
    @author John Butterfield (jpbutte2)
    Header for the DES Implementation.
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include "DESMagic.h"

/** Number of bits in a byte. */
#define BYTE_SIZE 8

/** Round a number of bits up to the nearest number of bytes needed 
    to store that many bits. */
#define ROUND_TO_BYTES( bits ) (((bits) + BYTE_SIZE - 1)/BYTE_SIZE)

/** Number of bits in the output byte of sBox function */
#define SBOX_RESULT_BITS 4

/** Number of bits the sBox function uses from the input array */
#define SBOX_INP_BITS 6

/** Number of bits in a C and D array during subkey generation */
#define C_D_BITS 56

/** Number of bytes in a C and D array during subkey generation */
#define C_D_BYTES ROUND_TO_BYTES( C_D_BITS )

/** Number of bytes in a DES block. */
#define BLOCK_BYTES ROUND_TO_BYTES( BLOCK_BITS )

/** Number of bytes in the left or right halves of a block (L and R). */
#define BLOCK_HALF_BYTES ROUND_TO_BYTES( BLOCK_HALF_BITS )

/** Number of bytes to store the left-side and right-side values (C
    and D) used to create the subkeys. */
#define SUBKEY_HALF_BYTES ROUND_TO_BYTES( SUBKEY_HALF_BITS )

/** Number of bytes to store a whole subkey (K_1 .. K_16). */
#define SUBKEY_BYTES ROUND_TO_BYTES( SUBKEY_BITS )

/** Type used to represent a block to encrypt or decrypt with DES. */
typedef struct {
  /** Sequence of bytes in the block. */
  byte data[ BLOCK_BYTES ];

  /** Number of bytes currently in the data array (e.g., the last block in a file could
      be shorter. */
  int len;
} DESBlock;

/**
    This function checks the given text key to make sure it’s not too
    long. It copies the characters of this key from textKey to the 
    key array and pads with zero bytes up to the length of a DES block.
    @param key a byte representing the key to the encryption algorithm
    @param textKey a string representing a potential key to the 
                    encryption algorithm
*/
void prepareKey( byte key[ BLOCK_BYTES ], char const *textKey );

/**
    This function returns zero or one based on the value of the bit
    at index idx in the given array of bytes. For example, 
    getbit( data, 1 ) should return 1 if the high-order bit of the 
    first byte of data is set.
    @param data an array of bytes to check a bit in
    @param idx the index of the bit to check from data
    @return 1 if the high-order bit of the first byte of data is set
*/
int getBit( byte const data[], int idx );

/**
    This function clears (if val is zero) or sets (if val is one) the 
    bit at index idx of the data array. For example, putBit( data, 2, 0 )
    will clear the second-highest-order bit in the first byte of the 
    data array.
    @param data an array of bytes to modify
    @param idx the index of the bit from data to modify
    @param val 1 or 0 representing clearing or setting the bit at idx
*/
void putBit( byte data[], int idx, int val );

/**
    This function performs the permute operation, copying n bits 
    from the given input array to output selected by the first n 
    elements of perm. If n isn’t multiple of 8, then this function 
    should set any remaining bits in the last byte to zero.
    @param output the resulting array of bytes after permutation
    @param input the given array of bytes
    @param perm array of ints representing the bits to change in input
    @param n the number of bits to permute
*/
void permute( byte output[], byte const input[], int const perm[], int n );

/**
    This function computes 16 subkeys based on the input key. 
    The resulting subkeys are stored in K[ 1 ] .. K[ 16 ].
    @param K 2D array of bytes, with each array of bytes representing 
            a subkey
    @param key array of bytes representing the input key
*/
void generateSubkeys( byte K[ ROUND_COUNT ][ SUBKEY_BYTES ], byte const key[ BLOCK_BYTES ] );

/**
    This function returns the result of an sBox() calculation in the 
    four high order bits of output[ 0 ]. The idx value ranges from 
    0 to 7. The result is an element of sBoxTable[ idx ] selected by 
    bits idx * 6 + 1 to idx * 6 + 6 of B.
    @param output the result of calling sBox() on the input byte array
    @param input an array of bytes to call sBox() on
    @param idx the index to call sBoxTable on
*/
void sBox( byte output[ 1 ], byte const input[ SUBKEY_BYTES ], int idx );

/**
    This computes the f function based on the given 32-bit value R 
    and the given 48-bit subkey, S. The result is stored in the 
    result array.
    @param result the result of calling the f function with the given R and K
    @param R an array of bytes representing a 32-bit value
    @param K an array of bytes representing a sub-key
*/
void fFunction( byte result[ BLOCK_HALF_BYTES ], byte const R[ BLOCK_HALF_BYTES ], byte const K[ SUBKEY_BYTES ] );

/**
    This function performs the encrypt operation on the byte array 
    in block, using the subkeys in the K array.
    @param block a pointer to a structure representing a block of 
                memory to encrypt
    @param K a 2D array of bytes with each array representing a subkey
*/
void encryptBlock( DESBlock *block, byte const K[ ROUND_COUNT ][ SUBKEY_BYTES ] );

/**
    This function performs the decrypt operation on the byte array in 
    block, using the subkeys in the K array.
    @param block a pointer to a structure representing a block of 
                memory to decrypt
    @param K a 2D array of bytes with each array representing a subkey
*/
void decryptBlock( DESBlock *block, byte const K[ ROUND_COUNT ][ SUBKEY_BYTES ] );
