// Filename: RSA_manager.js  
// Timestamp: 2012.10.04-09:25:38 (last modified)  
// Author(s): Ots Oka, Bumblehead (www.bumblehead.com)  
// Requires: BigInteger_init1.js, BigInteger_init2.js,  
// RSA_init1.js, RSA_init2.js, RSA_init3.js, RSAKeyFormat.js,
// RSAMessageFormatSOAEP.js, RSAMessageFormatBitPadding.js
//
// http://ats.oka.nu/titaniumcore/js/crypto/RSA.sample1.html



var RSA_manager = (function () {

  __unit( "RSA.sample1.html" );
  __uses( "BigInteger.init1.js" );
  __uses( "BigInteger.init2.js" );
  __uses( "RSA.init1.js" );
  __uses( "RSA.init2.js" );
  __uses( "RSA.init3.js" );
  __uses( "RSAKeyFormat.js" );

  __uses( "RSAMessageFormatSOAEP.js" );
  __uses( "RSAMessageFormatBitPadding.js" );

  // import
  var BigInteger = __import( this,"titaniumcore.crypto.BigInteger" );
  var RSA = __import( this,"titaniumcore.crypto.RSA" );

  var RSAMessageFormatSOAEP = __import( this, "titaniumcore.crypto.RSAMessageFormatSOAEP" );
  var RSAMessageFormatBitPadding = __import( this, "titaniumcore.crypto.RSAMessageFormatBitPadding" );

  var RSAKeyFormat = __import( packageRoot, "titaniumcore.crypto.RSAKeyFormat" );

  RSA.installKeyFormat( RSAKeyFormat );

  // install key format.

  // main
  var timerID = null;
  var radioIndex=0;
  var radioCount = 4;
  function rotateRadio(){
    //radioIndex = ( radioIndex +1 ) % 4;
    //for ( var i=0; i<radioCount; i++ ) {
    //  document.form1["r"+i].checked = false;
    //}
    //document.form1["r"+radioIndex].checked = true;
  }
  function outputTrace(v){
    //var d = iframe.document;
    //d.open();
    //d.write( "<html><body><pre>");
    //d.write( v );
    //d.write( "</pre></body></html>");
    //d.close();
  }
  function outputTrace2(v){
    //document.form1.indicator.value=v;
  }
  function nextBytes( bs ) {
    for ( var i=0; i<bs.length; i++ ) {
      bs[i]= Math.floor( Math.random() * 256 );
    }
    return bs;
  }
  function variableText( rsaKey, bytelen ) {
    var text =  nextBytes( new array( bytelen ) );
    // text.unshift(0);
    text[0] &= 0x7f;
    // text[0] = 0x00;

    var text = new BigInteger( text );
    return testCipher( rsaKey, text );
  }

  function testCipher( rsaKey, bitext ) {
    var text = bitext;
    var encrypted = rsaKey.processPublic( text );
    var decrypted = rsaKey.processPrivate( encrypted );

    function Result() {
      this.text = function(){
        return text;
      };
      this.encrypted = function() {
        return encrypted;
      };
      this.decrypted = function() {
        return decrypted;
      };
      this.toString = function(){
        var s = "";
        s+=( "t:" + text.     toString(16) );
        s+="\r\n";
        s+=( "e:" + encrypted.toString(16) );
        s+="\r\n";
        s+=( "d:" + decrypted.toString(16) );
        s+="\r\n";
        if ( this.result() ) {
	  s+="OK\r\n";
	  s+="\r\n";
        } else {
	  s+="NG\r\n";
	  s+="\r\n";
        }
        return s;
      };
      this.lengthCheck = function() {
        var v = text.compareTo( rsaKey.n ) ;
        if ( v<0 ) {
	  return "text < n";
        } else if (v==0) {
	  return "n=text";
        } else {
	  return "n<text";
        }
      };
      this.result = function() {
        return ( text.compareTo( decrypted ) == 0 ) ? true : false;
      };
    };
    return new Result();
  }
  function StringBuilder() {
    this.value = "";
    this.append = function(v){
      this.value += v.toString();
      return this;
    };
    this.toString = function() {
      return this.value;
    };
  }


  return {
    reset : function () {
      /*
      BigInteger = __import( this,"titaniumcore.crypto.BigInteger" );
      RSA = __import( this,"titaniumcore.crypto.RSA" );
      RSAKeyFormat = __import( packageRoot, "titaniumcore.crypto.RSAKeyFormat" );

      RSA.installKeyFormat( RSAKeyFormat );
      // install key format.
       */

      // main
      clearInterval(timerID);
      timerID = null;
    },


    pemAugment : function (o) {

    },

    // transitional format for pub and pri key is base64 string
    getPubKeyEncrypted : function (pubKey, message) {
      var rsa = new RSA(), rawPubKey;
      rsa.messageFormat = RSAMessageFormatBitPadding;      
      //rsa.messageFormat = RSAMessageFormatSOAEP;
      rsa.publicKeyBytes(base64x_decode(pubKey));
      return base64x_encode(rsa.publicEncrypt(message));
    },

    getPriKeyDecryptedAsync : function (priKeyObj, cipher, fn) {
      var rawPubKey, result,
          onProgressFun = function () {},
          onDecryptResultFun = function (value) { 
            result = utf82str(value); 
            fn(null, result); 
          },
          onPrivateDoneFun = function () {};
          cipher = cipher.replace(/\s/gi, '');
      
    },

    getPriKeyDecryptedAsync : function (priKeyByteArr, cipher, fn) {
      var rsa = new RSA(), rawPubKey, result,
          onProgressFun = function () {},
          onDecryptResultFun = function (value) { 
            result = utf82str(value); 
            fn(null, result); 
          },
          onPrivateDoneFun = function () {};
      rsa.messageFormat = RSAMessageFormatBitPadding;  
      //rsa.messageFormat = RSAMessageFormatSOAEP;

      rsa.privateKeyBytes(priKeyByteArr);
      rsa.privateDecryptAsync(cipher, onProgressFun, onDecryptResultFun, onPrivateDoneFun);
    },

    test_pubKeyEncrypt_priKeyDecrypt : function (rsaKey, fn) {
      var priKey = base64x_encode( rsaKey.privateKeyBytes() );
      var pubKey = base64x_encode( rsaKey.publicKeyBytes() );

      var cipher = this.getPubKeyEncrypted(pubKey, 'test message');
      this.getPriKeyDecryptedAsync(priKey, cipher, function (err, value) {
         if (value === 'test message') {
           fn(null, 'success');
         } else {
           fn('failed');
         }
      });
    },

    execute : function (keylen, exp, onProgressFun, fn) {
      this.reset();

      if ( timerID != null ) {
        return;
      }
      
      // atsushi oka's rsa script depends on prototype members
      // that it defines on the Object and other core objects
      // 
      // we've moved definition of these prototpye members into a function
      // that we may choose to call only when needed (key generation)
      // we hope to remove them when the key is finished
      // 
      // these are found in the `nonstructured` file
      //

      //augmentObjectPrototype();

      var rsaKey = new RSA();
      var resultList = [];
      var testCount=10;

      var progress = function(c){
        onProgressFun();
      };

      var result = function( rsa ) {
      };
      var finalization = function() {
        resultList.push( variableText( rsaKey, keylen / 8 ) );
        return --testCount<=0;
      };

      var done = function( succeeded, count, time ,startTime, finishTime ) {
        fn(rsaKey);
      };
      timerID = rsaKey.generateAsync( keylen, exp, progress, result, done );
    },

    cancel : function () {

    }
  };

}());


var success = 0,
    failure = 0;

(function test(x) {
  if (!x--) return null;
  RSA_manager.execute(1024, '3', function(){}, function (RSAObj) {
    // response is an RSA key object, given from `new RSA()`
    setTimeout(function () { 
      var priKey = base64x_encode( RSAObj.privateKeyBytes() ),
          pubKey = base64x_encode( RSAObj.publicKeyBytes() ),
          cipher = RSA_manager.getPubKeyEncrypted(pubKey, 'test message');      
      RSA_manager.getPriKeyDecryptedAsync(priKey, cipher, function (err, value) {
         if (value === 'test message') {
           console.log('success ' + ++success);
         } else {
           console.log('failure ' + ++failure);
         }
        test(x);
      });
    }, 2);
  });
}(3));

