/**
    @file io.c
    @author John Butterfield (jpbutte2)
    Input/Output component that reads or writes binary
    files that the DES algorithm uses.
*/

#include "io.h"

void readBlock(FILE *fp, DESBlock *block) {
    
    // Add padding
    memset(block->data, 0, BLOCK_BYTES);

    // Read up to 8 bytes from the file
    size_t bytesRead = fread( block->data, sizeof( byte ), BLOCK_BYTES, fp );

    // Set the number of bytes read
    block->len = bytesRead;
}

void writeBlock(FILE *fp, DESBlock const *block) {

    // Write the content of the block
    fwrite(block->data, sizeof(byte), block->len, fp);
    
}
