// Requires: packages.js, Cipher.js, SecureRandom.js, SOAEP.js, 
// RSAMessageFormat.js, BitPadding.js

/*
 * RSAMessageFormatSOAEP.js
 * See RSAMessageFormatSOAEP.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */

function initMessageFormatBitPadding(packageRoot) {
    __unit( "RSAMessageFormatBitPadding.js" );
    __uses( "packages.js" );
    __uses( "Cipher.js" );
    __uses( "SecureRandom.js" );
    __uses( "SOAEP.js" );
    __uses( "RSAMessageFormat.js" );

    // import
    var BitPadding = __import( this,"titaniumcore.crypto.BitPadding" );
    var RSAMessageFormat = __import( this,"titaniumcore.crypto.RSAMessageFormat" );

    function factory(){
	return BitPadding.create();
    }
    var RSAMessageFormatBitPadding = new RSAMessageFormat( factory );

    // export
    __export( this,"titaniumcore.crypto.RSAMessageFormatBitPadding", RSAMessageFormatBitPadding );
}

initMessageFormatBitPadding( this );

// vim:ts=8 sw=4:noexpandtab:
