/*
 * RSAKeyFormat.js
 * See RSAKeyFormat.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */
function initRSAKeyFormat( packageRoot ) {
    __unit( "RSAKeyFormat.js" );
    __uses( "packages.js" );
    __uses( "BigInteger.init1.js" );
    __uses( "binary.js" );
    __uses( "SOAEP.js" );

    var BigInteger = __import( packageRoot, "titaniumcore.crypto.BigInteger" );
    var SOAEP = __import( packageRoot, "titaniumcore.crypto.SOAEP" );

    var createReader = function(value) {
	var idx=0;
	return {
	    read_block : function() {
		var size = ba2i( value.slice(idx,idx+4) );
		idx+=4;
		if ( value.length<idx+size ) throw "Array Index Out of Bounds Exception("+(idx+size )+")";
		var data = value.slice( idx, idx + size );
		idx+=size;
		return data;
	    },
	    read : function () {
		var size = ba2i( value.slice(idx,idx+4) );
		idx+=4;
		return size;
	    }
	};
    };

    function check(a){
	if ( a.className == "BigInteger" ) {
	    return a;
	} else {
	    return new BigInteger(a);
	}
    }

    function encodePadding( value ){
	return SOAEP.create().encode( value );
    }

    function decodePadding( value ){
	return SOAEP.create().decode( value );
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

    function encodePublicKey( n, e, ksize ) {
	var bn = check(n).toByteArray();
	var be = check(e).toByteArray();

	var arr = [];
	arr = arr.concat( i2ba( ksize ) );
	arr = arr.concat( i2ba( bn.length ) );
	arr = arr.concat( bn );
	arr = arr.concat( i2ba( be.length ) );
	arr = arr.concat( be );

	arr = encodePadding( arr );

	return arr;
    }

    function encodePrivateKey( n, e, d, ksize ) {
	var bn = check(n).toByteArray();
	var be = check(e).toByteArray();
	var bd = check(d).toByteArray();

	var arr = [];
	arr = arr.concat( i2ba( ksize ) );
	arr = arr.concat( i2ba(bn.length) );
	arr = arr.concat( bn );
	arr = arr.concat( i2ba(be.length) );
	arr = arr.concat( be );
	arr = arr.concat( i2ba(bd.length) );
	arr = arr.concat( bd );

	arr = encodePadding( arr );

	return arr;
    }

    function decodePublicKey( value ) {
	value = base64check(value);
	value = decodePadding( value );
	var reader = createReader( value );
	var ksize = reader.read();
	var n = reader.read_block();
	var e = reader.read_block();

	return { ksize:ksize, n:n, e:e };
    }
    function decodePrivateKey( value ) {
	value = base64check(value);
	value = decodePadding( value );
	var reader = createReader(value);
	var ksize = reader.read();
	var n= reader.read_block();
	var e= reader.read_block();
	var d= reader.read_block();
	return { ksize:ksize, n:n, e:e, d:d };
    }

    function RSAKeyFormat(){
    }

    RSAKeyFormat.encodePublicKey  = encodePublicKey;
    RSAKeyFormat.encodePrivateKey = encodePrivateKey;
    RSAKeyFormat.decodePublicKey  = decodePublicKey;
    RSAKeyFormat.decodePrivateKey = decodePrivateKey;

    __export( packageRoot, "titaniumcore.crypto.RSAKeyFormat", RSAKeyFormat );
};

initRSAKeyFormat( this );

// vim:ts=8:noexpandtab:
