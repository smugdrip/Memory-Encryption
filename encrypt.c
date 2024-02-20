/**
    @file encrypt.c
    @author John Butterfield (jpbutte2)
    This is the main component for the encrypt program. It contains 
    the main function and uses the other components to read the 
    input file, to perform encryption and to write out the 
    ciphertext output.
*/

#include "io.h"
#include <stdbool.h>

/** Number of expected arguments in the command line */
#define EXP_ARGC 4

/** The expected index of the input file */
#define INP_F_IDX 2

/** The expected index of the output file */
#define OUT_F_IDX 3

/** The expected index of the text key */
#define K_IDX 1

/**
    Main method for the DES encryption 
    @param argc Number of command line arguments
    @param argv Array of strings of command line arguments
    @return the program exit status
*/
int main( int argc, char *argv[] )
{
    if ( argc != EXP_ARGC ) {
        fprintf( stderr, "usage: encrypt <key> <input_file> <output_file>\n" );
        exit ( 1 );
    }

    if ( strlen(argv[ K_IDX ]) > BYTE_SIZE) {
        fprintf( stderr, "Key too long\n" );
        exit( 1 );
    }

    FILE *inputFile = fopen( argv[ INP_F_IDX ], "rb" );

    if ( inputFile == NULL ) {
        perror( argv[ INP_F_IDX ] );
        exit( 1 );
    }

    FILE *outputFile = fopen( argv[ OUT_F_IDX ], "wb" );

    if ( outputFile == NULL ) {
        perror( argv[ OUT_F_IDX ] );
        exit( 1 );
    }

    byte key[ BLOCK_BYTES ];
    prepareKey( key, argv[ K_IDX ] );

    byte K[ ROUND_COUNT ][ SUBKEY_BYTES ];
    generateSubkeys( K, key );

    DESBlock block;
    bool endOfFileReached = false;

    while (!endOfFileReached) {
        
        readBlock(inputFile, &block);

        if (block.len == 0) {
            break;
        } else if ( block.len < BYTE_SIZE ) {
            endOfFileReached = true;
            block.len = BYTE_SIZE; // because padding was added during readBlock
        }

        encryptBlock( &block, K );

        writeBlock( outputFile, &block );
    }

    fclose( inputFile );
    fclose( outputFile );

    return 0;
}
