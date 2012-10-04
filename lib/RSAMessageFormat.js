// Requires: RSA_init1.js, binary.js, packages.js, BigInteger_init1.js, BigInteger_init2.js, 
// RSA_init1.js, RSA_init2.js

/*
 * RSAMessageFormat.js
 * See RSAMessageFormat.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */

function initRSAMessageFormat(packageRoot) {
    __unit( "RSAMessageFormat.js" );
    __uses( "packages.js" );
    __uses( "binary.js" );

    // __uses( "SecureRandom.js" );
    __uses( "BigInteger.init1.js" );
    __uses( "BigInteger.init2.js" );
    __uses( "RSA.init1.js" );
    __uses( "RSA.init2.js" );
    // __uses( "Cipher.js" );
    // __uses( "SOAEP.js" );
    // __uses( "BitPadding.js" );
    // __uses( "trace.js" );

    // import
    var BigInteger = __import( this,"titaniumcore.crypto.BigInteger" );
    var RSA = __import( this,"titaniumcore.crypto.RSA" );
    // var SOAEP = __import( this,"titaniumcore.crypto.SOAEP" );
    // var Cipher = __import( this,"titaniumcore.crypto.Cipher" );
    // var SecureRandom = __import( this,"titaniumcore.crypto.SecureRandom" );
    // var BitPadding = __import( this,"titaniumcore.crypto.BitPadding" );

    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    // function createRSA( directionName ) {
    //     return new RSA();
    // }
    function createPadding( paddingType ) {
	return paddingType;
	//switch ( paddingType ){
	//    case TYPE_SOAEP :
	//	var random = new SecureRandom();
	//	var cipherAlgorithm = Cipher.algorithm( Cipher.TWOFISH );
	//	return SOAEP.create( random, cipherAlgorithm );
	//    case TYPE_BITPADDING :
	//	return BitPadding.create();
	//    default :
	//	throw "never happen";
	//}
    }

    function pack(s) {
	var result = "";
	for ( var i=0; i<s.length; i++ ) {
	    var c = s.charAt( i );
	    if ( c==" " || c=="\t" || c=="\r" || c=="\n" ) {
	    } else {
		result += c;
	    }
	}
	return result;
    }
    function base64check( input ){
	if ( typeof input == "string" ) {
	    return base64x_decode( pack(  input  ) );
	} else {
	    return input;
	}
    }

    function utf8check( input ) {
	if ( typeof input == "string" ) {
	    return str2utf8( input );
	} else {
	    return input;
	}
    }

    function CONST(name){
	this.name=name;
    }
    CONST.prototype.toString = function() {
	return this.name;
    };

    var PUBLIC = new CONST( "PUBLIC" );
    var PRIVATE = new CONST( "PRIVATE" );

    var SYNC = new CONST( "SYNC" );
    var ASYNC = new CONST( "ASYNC" );

    var TYPE_SOAEP = new CONST( "SOAEP" );
    var TYPE_BITPADDING = new CONST( "BITPADDING" );

    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    function encrypt( /* _key,*/ rsa, _text, paddingType, type, concurrent, _progress, _result, _done ) {
	// // create a RSA processor.
	// var rsa = createRSA();

	// // decode key and text.
	// var key  = base64check( _key ); 

	var text = utf8check( _text ); 

	// // set public/private key
	// switch ( type ) {
	//     case PUBLIC  :
	// 	rsa.publicKeyBytes( key );
	// 	break;
	//     case PRIVATE  :
	// 	rsa.privateKeyBytes( key );
	// 	break;
	//     default :
	// 	throw "never happen";
	// }

	// calculate capacity of this RSA key. 
	// var length = rsa.n.bitLength() >> 3;
	var length = rsa.ksize >> 3;

	// clip the plain text
	// text = text.slice( 0, padding.maxsize( length ) );
	// pad the plain text
	// create a padding processor.
	var padding = createPadding( paddingType );
	text = padding.encode( text, length );
	// trace( text.length + "/"+base16( text ) );
	// trace( rsa.n.bitLength() +"/"+ base16( rsa.n.toByteArray() ) );

	// // preserve top bit.
	// var topbit = ( text[0] & 0x80 ) != 0;
	// // set top bit to 0;
	// text[0] &= 0x7f;
	// var topByte= topbit ? 0xff : 0x00;
	var topByte= null;

	// encrypt
	var result;

	// 
	var finalization = function() {
	    if ( topByte != null ) {
		// append an information byte which contains information about topByte.
		result.push( topByte );
	    }
	    // result = stringBreak( base64x_encode( result ), 48 ); 
	    // result = base64x_encode( result ); 
	};

	// add zero to the first byte in order to make it an unsigned integer value.
	text.unshift(0);

	// encrypt
	switch ( concurrent ) {
	    case SYNC :
		switch ( type ) {
		    case PUBLIC  :
			result = rsa.processPublic( new BigInteger( text ) ).toByteArray();
			finalization();
			return result;

		    case PRIVATE  :
			result = rsa.processPrivate( new BigInteger( text ) ).toByteArray();
			finalization();
			return result;

		    default :
			throw "never happen";
		}

		break;
	    case ASYNC :
		__uses( "nonstructured.js" );
		__uses( "RSA.init3.js" );
		switch ( type ) {
		    case PUBLIC  :
			var proc = nonstruct.getNew([
			    function(){
				return rsa.stepping_processPublic( new BigInteger( text ) );
			    },
			    function(scope,param,subparam) {
				result = subparam.result.toByteArray();
				finalization();
				_result( result );
				return glob.BREAK;
			    },
			    glob.EXIT
			]);
			var progress = function(c) {
			    _progress(c);
			};
			var done = function() {
			    _done.apply( null, arguments );
			    // _done( result );
			};
			var timerID = ( proc ).ready().frequency(1).timeout(1).progress(progress).done(done).go();
			return timerID;
		    case PRIVATE  :
			var proc = nonstruct.getNew([
			    function(){
				return rsa.stepping_processPrivate( new BigInteger( text ) );
			    },
			    function(scope,param,subparam) {
				result = subparam.result.toByteArray();
				finalization();
				_result( result );
				return glob.BREAK;
			    },
			    glob.EXIT
			]);
			var progress = function(c) {
			    _progress(c);
			};
			var done = function() {
			    _done.apply( null, arguments );
			    // _done( result );
			};
			var timerID = ( proc ).ready().frequency(1).timeout(1).progress(progress).done(done).go();
			return timerID;
		    default :
			throw "never happen";
		}
		break;
	    default :
		throw "never happen";
	}

	throw "never happen";
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    function decrypt( /* _key,*/ rsa, _text, paddingType, type, concurrent, _progress, _result, _done ) {
	// var rsa = createRSA();
	// var key  = base64check( _key ); 
	var text = base64check( _text ); 
	var padding = createPadding( paddingType );

	// // set public/private key
	// switch ( type ) {
	//     case PUBLIC  :
	// 	rsa.publicKeyBytes( key );
	// 	break;
	//     case PRIVATE  :
	// 	rsa.privateKeyBytes( key );
	// 	break;
	//     default :
	// 	throw "never happen";
	// }

	// retrieve the information byte.
	// var topByte = text.pop();
	var topByte = null;

	var result;

	function finalization() {
	    // var normalizedLength = rsa.n.bitLength()/8;
	    // var normalizedLength = rsa.ksize/8;
	    var normalizedLength = rsa.ksize>>3;

	    if ( result != null ) {
		// 0pad
		while ( result.length < normalizedLength ) {
		    // trace("unshift");
		    result.unshift(0);
		}
		while ( normalizedLength < result.length ) {
		    // trace("shift");
		    result.shift();
		}
	    }
	    // trace( result.length + "/"+base16( result ) );

	    if ( topByte != null ) {
		// restore top bit.
		if ( topByte & 0x80 != 0 ) {
		    result[0] |= 0x80;
		}else{
		    result[0] &= 0x7f;
		}
	    }
	    
	    // pad plain text
	    result = padding.decode( result );

	    // // decode as utf8 string
	    // result = utf82str( result );
	}

	// decrypt
	switch ( concurrent ) {
	    case SYNC :
		switch ( type ) {
		    case PUBLIC  :
			result = rsa.processPublic( new BigInteger( text ) ).toByteArray();
			finalization();
			return result;

		    case PRIVATE  :
			result = rsa.processPrivate( new BigInteger( text ) ).toByteArray();
			finalization();
			return result;

		    default :
			throw "never happen";
		}

		break;
	    case ASYNC :
		__uses( "nonstructured.js" );
		__uses( "RSA.init3.js" );
		switch ( type ) {
		    case PUBLIC  :
			var proc = nonstruct.getNew([
			    function(){
				return rsa.stepping_processPublic( new BigInteger( text ) );
			    },
			    function(scope,param,subparam) {
				result = subparam.result.toByteArray();
				finalization();
				_result( result );
				return glob.BREAK;
			    },
			    glob.EXIT
			]);
			var progress = function(c) {
			    _progress(c);
			};
			var done = function() {
			    _done.apply(null,arguments);
			    // _done( result );
			};
			var timerID = ( proc ).ready().frequency(1).timeout(1).progress(progress).done(done).go();
			return timerID;
		    case PRIVATE  :
			var proc = nonstruct.getNew([
			    function() {
				return rsa.stepping_processPrivate( new BigInteger( text ) );
			    },
			    function(scope,param,subparam) {
				result = subparam.result.toByteArray();
				finalization();
				_result( result );
				return glob.BREAK;
			    },
			    glob.EXIT
			]);
			var progress = function(c) {
			    _progress(c);
			};
			var done = function() {
			    _done.apply(null,arguments);
			    // _done( result );
			};
			var timerID = ( proc ).ready().frequency(1).timeout(1).progress(progress).done(done).go();
			return timerID;
		    default :
			throw "never happen";
		}
		break;
	    default :
		throw "never happen";
	}

	throw "never happen";
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    function maxsize( /* _key,*/ rsa, paddingType, type ) {
	// var rsa = createRSA();
	// var key = base64check( _key ); 
	//
	// // set public/private key
	// switch ( type ) {
	//     case PUBLIC  :
	// 	rsa.publicKeyBytes( key );
	// 	break;
	//     case PRIVATE  :
	// 	rsa.privateKeyBytes( key );
	// 	break;
	//     default :
	// 	throw "never happen";
	// }

	// if ( paddingType ){
	//     // create a padding processor.
	//     var padding = createPadding( paddingType );
	//     var length = rsa.n.bitLength() >> 3;
	//     return padding.maxsize( length );
	// } else {
	//     return (rsa.n.bitLength() -1) >> 3;
	// }

	// create a padding processor.
	var padding = createPadding( paddingType );
	var length = rsa.n.bitLength() >> 3;
	return padding.maxsize( length );
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    //
    ////////////////////////////////////////////////////////////////////////////////////////////

    function RSAMessageFormat( padding ){
	this.padding = padding;
    }
    function publicEncrypt( rsa, _text ) {
	return encrypt( rsa, _text, this.padding(), PUBLIC, SYNC );
    }
    function publicDecrypt( rsa, _text ) {
	return decrypt( rsa, _text, this.padding(), PUBLIC, SYNC );
    }
    function privateEncrypt( rsa, _text ) {
	return encrypt( rsa, _text, this.padding(), PRIVATE, SYNC );
    }
    function privateDecrypt( rsa, _text ) {
	return decrypt( rsa, _text, this.padding(), PRIVATE, SYNC );
    }

    function publicEncryptAsync( rsa, _text, _progress, _result, _done ) {
	return encrypt( rsa, _text, this.padding(), PUBLIC, ASYNC, _progress, _result, _done );
    }
    function publicDecryptAsync( rsa, _text, _progress, _result, _done ) {
	return decrypt( rsa, _text, this.padding(), PUBLIC, ASYNC, _progress, _result, _done );
    }
    function privateEncryptAsync( rsa, _text, _progress, _result, _done ) {
	return encrypt( rsa, _text, this.padding(), PRIVATE, ASYNC, _progress, _result, _done );
    }
    function privateDecryptAsync( rsa, _text, _progress, _result, _done ) {
	return decrypt( rsa, _text, this.padding(), PRIVATE, ASYNC, _progress, _result, _done );
    }

    function publicEncryptMaxSize( rsa ) {
	return maxsize( rsa, this.padding(), PUBLIC);
    }
    function privateEncryptMaxSize( rsa ) {
	return maxsize( rsa, this.padding(), PRIVATE);
    }

    RSAMessageFormat.prototype.publicEncrypt  = publicEncrypt;
    RSAMessageFormat.prototype.publicDecrypt  = publicDecrypt;
    RSAMessageFormat.prototype.privateEncrypt = privateEncrypt;
    RSAMessageFormat.prototype.privateDecrypt = privateDecrypt;
    RSAMessageFormat.prototype.privateEncryptAsync = privateEncryptAsync;
    RSAMessageFormat.prototype.privateDecryptAsync = privateDecryptAsync;
    RSAMessageFormat.prototype.publicEncryptMaxSize = publicEncryptMaxSize;
    RSAMessageFormat.prototype.privateEncryptMaxSize = privateEncryptMaxSize;
    RSAMessageFormat.prototype.install = function( RSA ) {
        RSA.installMessageFormat( this );
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    //
    ////////////////////////////////////////////////////////////////////////////////////////////

    // export
    __export( this,"titaniumcore.crypto.RSAMessageFormat", RSAMessageFormat );

    // packageRoot.publicEncrypt  = publicEncrypt;
    // packageRoot.publicDecrypt  = publicDecrypt;
    // packageRoot.privateEncrypt = privateEncrypt;
    // packageRoot.privateDecrypt = privateDecrypt;
    // packageRoot.privateEncryptAsync = privateEncryptAsync;
    // packageRoot.privateDecryptAsync = privateDecryptAsync;
    // packageRoot.publicEncryptMaxSize = publicEncryptMaxSize;
    // packageRoot.privateEncryptMaxSize = privateEncryptMaxSize;
}

initRSAMessageFormat( this );

// vim:ts=8 sw=4:noexpandtab:
