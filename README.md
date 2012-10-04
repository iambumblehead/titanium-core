The Titanium Core Files 
=======================

### OVERVIEW:

A collection of scripts for encryption/decryption. 

Numerous authors produced the scripts included here:

 * [Tom Wu][0] JSBN, RSA, BigInteger. BSD license.
 * [Atsushi Oka][1] RSA, BigInteger, [MORE][1]. LGPL.  
 * [Brian Turek][2] and Paul Johnson -jsSHA. BSD License
 * [Michiel van Everdingen][3] -Cipher.js -AES, SERPENT, TWOFISH. "Open Source".

A description of these files from one of its authors, [Atsushi Oka][1]:

> This library is an object oriented cryptography toolkit that implements 
> several fundamental cryptographic algorithms including TWOFISH, SERPENT, 
> RIJNDAEL, RSA with key-generation and SHA(SHA-1,224,256,384,512) for 
> JavaScript. This library works in ActionScript as well. The unique feature 
> of this library is asynchronous processing. A heavyweight process such as 
> 4096bit RSA key generation will be done asynchronously so that this library 
> does not cause problems such as freezing browsers, "slow-downing" warning 
> dialogs, etc.

The original RSA-related scripts authored by Tom Wu are not sufficient for 
browser scripting environments. Key generation involves one un-interruptable 
process.

Atsushi Oka's [modified version][1] of these scripts is better suited for
browser environments. Additionally, his code is documented and simple to use.
Unfortunately, his scripts augment host objects and they use an unfamiliar 
script-loading utility. I have modified his files to _instead_  use a series of 
super constructors. These are primarily found in _tools/NonStructureLib.js_. I 
have only updated the RSA-related code to use these constructors.

Atsushi Oka's scripts require the additional code to allow usage of his
[Nested Closure Oriented Programming][4], a programming paradigm he invented for
use with javascript.

[0]: http://www-cs-students.stanford.edu/~tjw/jsbn/                       "jsbn"
[1]: http://ats.oka.nu/titaniumcore/js/crypto/readme.txt            "atushi oka"
[2]: http://sourceforge.net/users/caligatio                        "brian turek"
[3]: http://home.versatel.nl/MAvanEverdingen/index.html             "everdingen"
[4]: http://ats.oka.nu/titaniumcore/js/nonstructured/nonstructured.readme.txt "l"

---------------------------------------------------------  

#### <a id="get-started">GET STARTED:

Include the titanium-core scripts in your document. At present there are quite
a few files and only some of the files are needed for certain tasks. It would 
be possible to spend time editing these files to remove some of the 
dependencies. Maybe I'll do it in the future.

 > `<script src="/js/titanium-core/lib/tools/elapse.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/tools/packages.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/tools/isarray.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/BigInteger_init1.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/RSA_init1.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/BigInteger_init2.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/SecureRandom.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/RSA_init2.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/tools/binary.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/RSAMessageFormat.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/Cipher.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/SOAEP.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/RSAMessageFormatSOAEP.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/BitPadding.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/RSAMessageFormatBitPadding.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/RSAKeyFormat.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/tools/NonStructureLib.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/tools/nonstructured.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/BigInteger_init3.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/lib/RSA_init3.js" type="text/javascript"></script>`  
 > `<script src="/js/titanium-core/RSA_manager.js" type="text/javascript"></script>`  

And a simple example seems sufficient:

 > `var success = 0, failure = 0;`  

 > `(function test(x) {`  
 > &nbsp;&nbsp; `if (!x--) return null;`  
 > &nbsp;&nbsp; `RSA_manager.execute(1024, '3', function(){}, function (RSAObj) {`  
 > &nbsp;&nbsp; &nbsp;&nbsp; `// response is an RSA key object, given from _new RSA()_`  
 > &nbsp;&nbsp; &nbsp;&nbsp; `setTimeout(function () {`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `var priKey = base64x_encode( RSAObj.privateKeyBytes() ),`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `pubKey = base64x_encode( RSAObj.publicKeyBytes() ),`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `cipher = RSA_manager.getPubKeyEncrypted(pubKey, 'test message');`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `RSA_manager.getPriKeyDecryptedAsync(priKey, cipher, function (err, value) {`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `if (value === 'test message') {`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp;  &nbsp;&nbsp; `console.log('success ' + ++success);`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `} else {`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp;  &nbsp;&nbsp; `console.log('failure ' + ++failure);`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `}`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `test(x);`  
 > &nbsp;&nbsp; &nbsp;&nbsp; &nbsp;&nbsp; `});`  
 > &nbsp;&nbsp; &nbsp;&nbsp; `}, 2);`  
 > &nbsp;&nbsp; `});`  
 > `}(3));`  
 
 
 The RSA_manager code comes primarly from code that is taken directly from one
 of Atsushi Oka's demonstration pages, [here][6] and [here][7]. I've made very
 few changes to the code and much of it is not needed for the generation of
 keys, encryption, decryption etc. You are forewarned.

[5]: https://www.github.com/iambumblehead/scroungejs               "scroungejs"
[6]: http://ats.oka.nu/titaniumcore/js/crypto/RSA.sample1.html     "rsa sample"
[7]: http://ats.oka.nu/titaniumcore/js/crypto/RSA.sample2.html     "rsa sample"
