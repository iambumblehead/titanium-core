/*
 * SOAEP.js
 * See SOAEP.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */

// Sub-Optimal Asymmetric Encryption Padding
function initSOAEP( packages ) {
    __unit( "SOAEP.js" );
    __uses( "packages.js" );
    // __uses( "trace.js" );
    // __uses( "elapse.js" );
    __uses( "binary.js" );
    __uses( "Cipher.js" );
    __uses( "SecureRandom.js" );

    var SecureRandom = __import( this,"titaniumcore.crypto.SecureRandom" );
    var Cipher = __import( this,"titaniumcore.crypto.Cipher" );

    // var encrypt = Cipher.create( algorithm, Cipher.ENCRYPT, Cipher.ECB, Cipher.NO_PADDING );
    // var decrypt = Cipher.create( algorithm, Cipher.DECRYPT, Cipher.ECB, Cipher.NO_PADDING );
    // var inputText  = dataBytes.concat();
    // var cipherText = encrypt.execute( keyBytes, inputText.concat() );
    // var outputText  = decrypt.execute( keyBytes, cipherText.concat() );

    function SOAEP( random, cipherAlgorithm, withBitPadding ) {
	if ( withBitPadding == null ) {
	    withBitPadding = true;
	}
	this.random = random == null ? new SecureRandom() : random ;
	this.cipherAlgorithm = cipherAlgorithm == null ? Cipher.algorithm( Cipher.TWOFISH ) : cipherAlgorithm;
	this.withBitPadding = withBitPadding;
    }

    function maxsize( length ){
	var blocksize = this.cipherAlgorithm.blocksize;
	return length-blocksize + ( this.withBitPadding ? -1 : 0 );
    }


    function encode( input, length ) {
	// initialization
	var blocksize = this.cipherAlgorithm.blocksize;

	// if length is not specified, calculate the sufficient length for the length of input data.
	if ( length == null ) {
	    length = Math.ceil( (1+input.length) / blocksize ) * blocksize + blocksize;
	}
	// alert( ""+input.length+"/"+length );

	if ( 0!=(length % blocksize ) ) {
	    throw "SOAEP.encode() error : length("+length+") must be a multiple of " + blocksize + " since the block size of " + this.cipherAlgorithm.name + " is " +blocksize;
	}

	var blockCount = Math.floor( length / blocksize );

	// var maxsize = length - blocksize -1;
	var maxsize = this.maxsize( length );

	// trim input data if input data length exceeds the specified length by "length" parameter.
	// -1 for the terminater byte.
	if ( maxsize < input.length ) { 
	    throw "SOAEP.encode() error : the size of input data (" + input.length + " bytes) must not exceed " + maxsize + "byte. \n"+maxsize+"(maxsize)="+length+"(bit-length of the RSA key )-" + blocksize+"( blocksize of the cipher algorithm)" + ( this.withBitPadding ? "-1(size of the terminator byte)" : "" ) ;
	    // input = input.slice( 0, length-blocksize -1 ); 
	}

	// Create output array.
	var output = new Array( length );

	// Create a random token block. Use it as synmmetoric cipher key later.
	var randomized = new Array( blocksize );
	this.random.nextBytes( randomized );

	// Copy input text to output
	for ( var i=0; i<input.length; i++ ) {
	    output[i] = input[i];
	}

	// Pad input data with bit-padding-method to make it fit to the length.
	if ( this.withBitPadding ) {
	    output[input.length] = 0x80;
	    for ( var i=input.length+1; i<length-blocksize; i++ ) {
		output[i] = 0x00;
	    }
	} else {
	    for ( var i=input.length; i<length-blocksize; i++ ) {
		output[i] = 0x00;
	    }
	}

	// Copy the random token block to the last block in output.
	for ( var i=length-blocksize,j=0; i<length; i++,j++ ) {
	    output[i] = randomized[j];
	}

	// Encode blocks as CBC mode in reverse order.
	var iv = randomized.concat();
	this.cipherAlgorithm.open( randomized );

	for ( var idx=blockCount-2; 0<=idx; idx-- ) {
	    var offset = idx*blocksize;
	    for ( var i=offset,j=0; j<blocksize; i++,j++ ) {
		output[i] ^= iv[j];
	    }
	    this.cipherAlgorithm.encrypt( output,offset );
	    iv = output.slice( offset, offset+blocksize );
	}
	this.cipherAlgorithm.close();

	// Encode the blocks again in normal order. 
	// Use first block as cipher-key and iv.
	var firstblock = output.slice( 0, blocksize );
	iv = firstblock;
	this.cipherAlgorithm.open( firstblock );
	for ( var idx=1; idx<blockCount; idx++ ) {
	    var offset = idx*blocksize;
	    for ( var i=offset,j=0; j<blocksize; i++,j++ ) {
		output[i] ^= iv[j];
	    }
	    this.cipherAlgorithm.encrypt( output, offset );
	    iv = output.slice( offset, offset+blocksize );
	}

	this.cipherAlgorithm.close();

	return output;
    }

    function decode( input ) {
	var length  = input.length
	// initialization
	var blocksize = this.cipherAlgorithm.blocksize;
	if ( 0!=length % blocksize ) {
	    throw "SOAEP.decode() error : length "+length+" must be a multiple of " + blocksize;
	}
	var blockCount = Math.floor( length / blocksize );

	// create output array.
	var output = input.concat();

	// Decode  1
	// Use first block as cipher-key and iv.
	var firstblock = output.slice( 0, blocksize );
	var iv = firstblock;
	this.cipherAlgorithm.open( firstblock );
	for ( var idx=1; idx<blockCount; idx++ ) {
	    var offset = idx*blocksize;
	    var iv2 = output.slice( offset, offset+blocksize );
	    this.cipherAlgorithm.decrypt( output, offset );
	    for ( var i=offset,j=0; j<blocksize; i++,j++ ) {
		output[i] ^= iv[j];
		// trace("i="+i)
	    }
	    iv = iv2;
	}


	// Decode  2
	// Encode blocks as CBC mode in reverse order.
	var lastblock_offset = (blockCount-1)*blocksize;
	var lastblock = output.slice( lastblock_offset, lastblock_offset + blocksize );
	var iv = lastblock;
	this.cipherAlgorithm.open( lastblock );

	for ( var idx=blockCount-2; 0<=idx; idx-- ) {
	    var offset = idx*blocksize;
	    var iv2=output.slice( offset, offset+blocksize );
	    this.cipherAlgorithm.decrypt( output, offset );
	    for ( var i=offset,j=0; j<blocksize; i++,j++ ) {
		output[i] ^= iv[j];
	    }
	    iv = iv2;
	}
	this.cipherAlgorithm.close();

	// trace( "SOAEP:" + base16(output ) );

	// Chop the remaining by bit-padding-method.
	if ( this.withBitPadding ) {
	    for ( var i=lastblock_offset-1; 0<=i; i-- ) {
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
	} else {
	    output = output.slice( 0,lastblock_offset );
	}
	
	return output;
    }
    function blocksize(){
	return this.cipherAlgorithm.blocksize;
    }

    SOAEP.prototype.encode = encode;
    SOAEP.prototype.decode = decode;
    SOAEP.prototype.maxsize = maxsize;
    SOAEP.prototype.blocksize = blocksize;

    function create( random, cipherAlgorithm, withBitPadding ) {
	return new SOAEP( random, cipherAlgorithm, withBitPadding );
    }

    SOAEP.create = create;

    // __package( packages, path ).SOAEP = SOAEP;
    __export( packages, "titaniumcore.crypto.SOAEP", SOAEP );
}

initSOAEP( this );

// vim:ts=8 sw=4:noexpandtab:
