/*
 * BitPadding.js
 * See BitPadding.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */
function initBitPadding( packageRoot ) {
    __unit( "BitPadding.js" );
    __uses( "packages.js" );
    // __uses( "trace.js" );
    // __uses( "elapse.js" );

    function BitPadding() {
    }

    function maxsize( length ){
	return length-1;
    }

    function encode( input, length ) {
	// if length is not specified, calculate the sufficient length for the length of input data.
	if ( length == null ) {
	    length = input.length+1;
	}

	var maxsize = length -1;

	// trim input data if input data length exceeds the specified length by "length" parameter.
	// -1 for the terminater byte.
	if ( maxsize < input.length ) { 
	    throw "the size of input data (" + input.length + " bytes) must not exceed " + maxsize + "byte. \n"+maxsize+"(maxsize)="+length+"(bit-length of the RSA key )-1(size of the terminator byte)";
	}

	// Create output array.
	var output = new Array( length );

	for ( var i=0; i<input.length; i++ ) {
	    output[i] = input[i];
	}

	// Pad input data with bit-padding-method to make it fit to the length.
	output[input.length] = 0x80;
	for ( var i=input.length+1; i<length; i++ ) {
	    output[i] = 0x00;
	}

	return output;
    }

    function decode( input ) {
	var length  = input.length
	// initialization

	// create output array.
	var output = input.concat();

	// Chop the remaining by bit-padding-method.
	for ( var i=output.length-1; 0<=i; i-- ) {
	    // trace( output[i].toString(16) );
	    if ( output[i]==0x80 ) {
		output = output.slice( 0,i );
		break;
	    } else if ( output[i] ==0x00 ) {
	    } else {
		throw "decode() : found illegal character 0x" + output[i].toString(16).toUpperCase();
		//output = output.slice( 0,i );
		//break;
	    }
	}
	return output;
    }
    function blocksize() {
	return 1;
    }

    BitPadding.prototype.encode = encode;
    BitPadding.prototype.decode = decode;
    BitPadding.prototype.maxsize = maxsize;
    BitPadding.prototype.blocksize = blocksize;

    function create() {
	return new BitPadding();
    }

    BitPadding.create = create;

    __export( packageRoot, "titaniumcore.crypto.BitPadding", BitPadding );
}

initBitPadding( this );

// vim:ts=8 sw=4:noexpandtab:
