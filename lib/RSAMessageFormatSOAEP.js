// Requires: packages.js, Cipher.js, SecureRandom.js, SOAEP.js, RSAMessageFormat.js

/*
 * RSAMessageFormatSOAEP.js
 * See RSAMessageFormatSOAEP.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 */

function initMessageFormatSOAEP(packageRoot) {
    __unit( "RSAMessageFormatSOAEP.js" );
    __uses( "packages.js" );
    __uses( "Cipher.js" );
    __uses( "SecureRandom.js" );
    __uses( "SOAEP.js" );
    __uses( "RSAMessageFormat.js" );

    // import
    var SOAEP = __import( this,"titaniumcore.crypto.SOAEP" );
    var Cipher = __import( this,"titaniumcore.crypto.Cipher" );
    var SecureRandom = __import( this,"titaniumcore.crypto.SecureRandom" );
    var RSAMessageFormat = __import( this,"titaniumcore.crypto.RSAMessageFormat" );

    function factory(){
	var random = new SecureRandom();
	var cipherAlgorithm = Cipher.algorithm( Cipher.TWOFISH );
	return SOAEP.create( random, cipherAlgorithm );
    }
 
    var RSAMessageFormatSOAEP = new RSAMessageFormat( factory );

    // export
    __export( this,"titaniumcore.crypto.RSAMessageFormatSOAEP", RSAMessageFormatSOAEP );
}

initMessageFormatSOAEP( this );

// vim:ts=8 sw=4:noexpandtab:
