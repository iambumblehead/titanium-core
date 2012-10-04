/*
 * SHA.js
 * See SHA.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */
function initializeInterfaceSHA( packageRoot ) {
if ( packageRoot.__PACKAGE_ENABLED ) {
    __unit( "SHA.js" );
    __uses( "packages.js" );
    __uses( "jsSHA.js" );
}
    // import
    // .. nothing
    
    /*
     * main class
     */
    function SHA( variant, shaFunc, inputFunc, outputFunc ) {
	this.variant = variant;
	this.shaFunc = shaFunc;
	this.inputFunc = inputFunc;
	this.outputFunc = outputFunc;
    }

    /*
     * a default convert function. do nothing.
     * @param	anything.
     * @return  anything.
     */
    function nop(value){
	return value;
    }


    /*
     * convert a 32bit-integer array to a byte array. ( as big-endian )
     * @param{Array<Number>}  32bit-integer array
     * @return  byte array
     */
    // function ia2ba( ia ) {
    //     var length = ia.length << 2 ;
    //     var ba = new Array( length );
    //     for ( var i=0; i< length; i++ ) {
    //         ba[i] = 0xFF & ( ia[ i >> 2 ] << ( 3 - ( i % 4 ) ) * 8 );
    //     }
    //     return ba;
    // }


    /*
     * convert a byte array to a 32bit-integer array. ( as big-endian )
     * @param  {Array<Number>} byte array
     * @return 32bit-integer array
     */
    // function ba2ia( ba ) {
    //     var ia = new Array( ( ba.length + 3 ) >> 2 ); // ceil( ba.length / 4 )
    //     for ( var i=0; i<ia.length; i++ ) {
    //         ia[i]=0;
    //     }
    //     for ( var i=0; i<ba.length; i++ ) {
    //         ia[ i>>2 ] |= ( ba[i] << ( 8 * ( 3 - ( i % 4 )  ) ) );
    //     }
    //     return ia;
    // }

    function ia2ba( ia ) {
	var length = ia.length <<2;
	var ba = new Array( length );
	for(var ii=0,bi=0;ii<ia.length&&bi<ba.length; ){
	    ba[bi++] = 0xff & ( ia[ii] >> 24 );
	    ba[bi++] = 0xff & ( ia[ii] >> 16 );
	    ba[bi++] = 0xff & ( ia[ii] >>  8 );
	    ba[bi++] = 0xff & ( ia[ii] >>  0 );
	    ii++;
	}
	return ba;
    }
    function ba2ia( ba ) {
	var length = (ba.length+3)>>2;
	var ia = new Array( length );;
	for(var ii=0,bi=0; ii<ia.length && bi<ba.length; ){
	    ia[ii++] = 
		( bi < ba.length ? (ba[bi++]  << 24 ) : 0 ) |
		( bi < ba.length ? (ba[bi++]  << 16 ) : 0 ) |
		( bi < ba.length ? (ba[bi++]  <<  8 ) : 0 ) |
		( bi < ba.length ? (ba[bi++]/*<< 0*/) : 0 ) ;
	}
	return ia;
    }

    function str2ba( str ) {
	return str2utf8( str );
    };

    function hex2ba( hexstr ) {
	return base16_decode( hexstr );
    };

    function b642ba( ba ) {
	return base64_encode( ba );
    };

    /*
     * convert an integer array to hexadecimal string.
     * @param  {Array<Integer>} an integer array
     * @return a hexadecimal string
     */
    var arr_upper = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F" ];
    var arr_lower = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f" ];
    function ia2hex(ia,arr) {
	var result ="";
	for ( var i=0; i<ia.length; i++ ) {
	    var ii=ia[i];
	    for ( var j=28;0<=j; j-=4 ) {
		result += arr[( 0xF & ( ii >> j ) )];
	    }
	}
	return result;
    }
    function ia2hex_lower(ia) {
	return ia2hex(ia,arr_lower );
    }
    function ia2hex_upper(ia) {
	return ia2hex(ia,arr_upper );
    }


    function ia2b64( ia ) {
	return base64_encode( ia2ba(ia) );
    }
    function ia2str( ia ) {
	return utf82str( ia2ba(ia) );
    };

    // trace( ( 0xFFFFFFF5 ).toString(16) );
    // trace( ia2hex( [ 0xFFFFFFF5, 0xFFFFFFFF ] ) );

    /*
     * 
     */
    function create( variant, inputFormat, outputFormat ) {
	var inputFunc  = null;
	var outputFunc = null;

	if ( inputFormat == null ) {
	    inputFunc = nop;
	} else if ( typeof( inputFormat ) == 'function' ) {
	    inputFunc = inputFormat;
	} else {
	    switch ( inputFormat ) {
	    case "BIN":
	    case "binary":
		inputFunc = nop;
		break;
	    case "STR":
	    case "STR(UTF8)":
	    case "string":
		inputFunc = str2ba;
		break;
	    case "HEX":
	    case "hex":
		inputFunc = hex2ba;
		break;
	    case "B64":
	    case "base64":
		inputFunc = b642ba;
		break;
	    default :
		throw "INPUT FORMAT NOT RECOGNIZED";
	    }
	}

	if ( outputFormat == null ) {
	    outputFunc = ia2ba;
	} else if ( typeof( outputFormat ) == 'function' ) {
	    outputFunc = outputFormat;
	} else {
	    switch ( outputFormat ) {
	    case "binary":
	    case "BIN":
		outputFunc = ia2ba;
		break;
	    case "STR":
	    case "STR(UTF8)":
	    case "string":
		inputFunc = ia2str;
	    case "HEX":
		outputFunc = ia2hex_upper;
		break;
	    case "hex":
		outputFunc = ia2hex_lower;
		break;
	    case "B64":
	    case "base64":
		outputFunc = ia2b64;
		break;
	    default:
		throw "OUTPUT FORMAT NOT RECOGNIZED";
	    }
	}

	var shaFunc = null;
	switch (variant) {
	case "SHA-1":
	    shaFunc = packageRoot.sha.core.coreSHA1
	    break;
	case "SHA-224":
	    shaFunc = packageRoot.sha.core.coreSHA2
	    break;
	case "SHA-256":
	    shaFunc = packageRoot.sha.core.coreSHA2
	    break;
	case "SHA-384":
	    shaFunc = packageRoot.sha.core.coreSHA2
	    break;
	case "SHA-512":
	    shaFunc = packageRoot.sha.core.coreSHA2
	    break;
	default:
	    throw "HASH NOT RECOGNIZED";
	}

	return new SHA( variant, shaFunc, inputFunc, outputFunc );
    }

    function hash( input ) {
	var bytes         = this.inputFunc( input );
	// trace( "input bytes : " + base16( bytes ) );
	var messageLength = bytes.length * 8;
	var message       = ba2ia( bytes );
	// trace( "input integer[0] : " + message[0].toString(16) );
	var output        = this.outputFunc( this.shaFunc( message , messageLength, this.variant ) );
	return output;
    }

    SHA.prototype.hash = hash;
    SHA.create = create;


    //
    // export
    //

    // creating package
    if ( packageRoot.sha == null ) packageRoot.sha = {};

    // export the class
    packageRoot.sha.SHA = SHA;

    __export( packageRoot, "titaniumcore.crypto.SHA",SHA );

} // of function initializeInterfaceSHA()


initializeInterfaceSHA( this );


// vim:ts=8 sw=4:noexpandtab:
