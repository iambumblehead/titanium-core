/* 
 * A JavaScript implementation of the SHA family of hashes, as defined in FIPS PUB 180-2
 * Version 1.1 Copyright Brian Turek 2008
 * Distributed under the BSD License
 * See http://jssha.sourceforge.net/ for more information
 *
 * Several functions taken from Paul Johnson
 *
 * Modified on November 10,2008 by Atsushi Oka http://oka.nu/ 
 */

function initializeInterface_jsSHA(packageRoot) {
if ( packageRoot.__PACKAGE_ENABLED ) {
    __unit( "jsSHA.class.js" );
    __uses( "jsSHA.js" );
}

/*
 * Convert a string to an array of big-endian words
 * If charSize is ASCII, characters >255 have their hi-byte silently ignored.
 *
 * @param {String} str String to be converted to binary representation
 * @return Integer array representation of the parameter
 */
function str2binb(str) {
    // trace("str2binb:"+jsSHA);
    var bin = [];
    var mask = (1 << jsSHA.charSize) - 1;
    var length = str.length * jsSHA.charSize;

    for (var i = 0; i < length; i += jsSHA.charSize) {
	bin[i >> 5] |= (str.charCodeAt(i / jsSHA.charSize) & mask) << (32 - jsSHA.charSize - i % 32);
    }

    return bin;
};

/*
 * Convert an array of big-endian words to a hex string.
 *
 * @private
 * @param {Array} binarray Array of integers to be converted to hexidecimal representation
 * @return Hexidecimal representation of the parameter in String form
 */
function binb2hex(binarray) {
    var hex_tab = jsSHA.hexCase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    var length = binarray.length * 4;

    for (var i = 0; i < length; i++) {
	str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF) + hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8)) & 0xF);
    }

    return str;
};


/*
 * Convert an array of big-endian words to a base-64 string
 *
 * @private
 * @param {Array} binarray Array of integers to be converted to base-64 representation
 * @return Base-64 encoded representation of the parameter in String form
 */
function binb2b64(binarray) {
    var tab = "ABCDEFGHIJKLMNOPQRSTUVWxYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var str = "";
    var length = binarray.length * 4;
    for (var i = 0; i < length; i += 3)
    {
	var triplet = (((binarray[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16) | (((binarray[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8) | ((binarray[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
	for (var j = 0; j < 4; j++) {
	    if (i * 8 + j * 6 > binarray.length * 32) {
		str += jsSHA.b64pad;
	    } else {
		str += tab.charAt((triplet >> 6 * (3 - j)) & 0x3F);
	    }
	}
    }
    return str;
};


/*
 * jsSHA is the workhorse of the library.  Instantiate it with the string to be hashed
 * as the parameter
 *
 * @constructor
 * @param {String} srcString The string to be hashed
 */

function jsSHA( srcString ) {
    var sha1   = null;
    var sha224 = null;
    var sha256 = null;
    var sha384 = null;
    var sha512 = null;

    var strBinLen = srcString.length * jsSHA.charSize;
    var strToHash = str2binb( srcString );

    // trace( "strBinLen : "+ strBinLen );
    // trace( "strToHash : "+ strToHash[0].toString(16) );
    // trace( "strToHash.length : "+ strToHash.length );
    // trace( "strToHash * 32 : "+ strToHash.length * 32 );

    /*
     * Returns the desired SHA hash of the string specified at instantiation using the specified parameters
     *
     * @param {String} variant The desired SHA variant (SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512)
     * @param {String} format The desired output formatting (B64 or HEX)
     * @return The string representation of the hash in the format specified
     */
    this.getHash = function ( variant, format ) {
	var formatFunc = null;

	switch (format) {
	case "HEX":
	    formatFunc = binb2hex;
	    break;
	case "B64":
	    formatFunc = binb2b64;
	    break;
	default:
	    // MODIFIED
	    // return "FORMAT NOT RECOGNIZED";
	    throw "FORMAT NOT RECOGNIZED";
	}

	// ADDED
	var message = strToHash.concat();

	switch (variant) {
	case "SHA-1":
	    if (sha1 === null) {
		// sha1 = coreSHA1();
		sha1 = sha.core.coreSHA1( message, strBinLen );
	    }
	    return formatFunc(sha1);
	case "SHA-224":
	    if (sha224 === null) {
		// sha224 = coreSHA2(variant);
		sha224 = sha.core.coreSHA2( message, strBinLen, variant );
	    }
	    return formatFunc(sha224);
	case "SHA-256":
	    if (sha256 === null) {
		// sha256 = coreSHA2(variant);
		sha256 = sha.core.coreSHA2( message, strBinLen, variant );
	    }
	    return formatFunc(sha256);
	case "SHA-384":
	    if (sha384 === null) {
		// sha384 = coreSHA2(variant);
		sha384 = sha.core.coreSHA2( message, strBinLen, variant );
	    }
	    return formatFunc(sha384);
	case "SHA-512":
	    if (sha512 === null) {
		// sha512 = coreSHA2(variant);
		sha512 = sha.core.coreSHA2( message, strBinLen, variant );
	    }
	    return formatFunc(sha512);
	default:
	    // MODIFIED
	    // return "HASH NOT RECOGNIZED";
	    throw "HASH NOT RECOGNIZED";
	}
    };
}


/*
 * Configurable variables. Defaults typically work
 */
jsSHA.charSize = 8; /* Number of Bits Per character (8 for ASCII, 16 for Unicode)	  */
jsSHA.b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
jsSHA.hexCase = 0; /* hex output format. 0 - lowercase; 1 - uppercase		*/

// CREATING PACKAGE
if ( packageRoot.sha == null ) this.sha = {};

// PUBLISHING jsSHA class
packageRoot.sha.jsSHA = jsSHA;

} // of function initializeInterface_jsSHA()


initializeInterface_jsSHA( this );


// vim:ts=8 sw=4:noexpandtab:
