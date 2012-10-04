<html>
<head>
<title>JavaScript Cryptography Toolkit</title>
<style>
body {
padding:0px;
margin:0px;
border:0px;
background-image:url(http://ats.oka.nu/background.png);
background-repeat:repeat-y;
background-position: center center;
background-color:#ffffff;
font-family: "Arial", sans-serif;
/*font-family: sans-serif; */
}
#d1 {
text-align:center;
width:100%;
}
#d2 {
border:0px solid gray;
text-align:left;
min-width:none;
width:650px;
margin-left:auto;
margin-right:auto;
padding:30px;
}
</style>
</head>
<body>
<div id="d1">
<pre id="d2">


    JavaScript Cryptography Toolkit

                                                           Titaniumcore Project
================================================================================
Atsushi Oka [ <a href="http://oka.nu/">http://oka.nu/</a> ]                                       Jan 10,2009


This library is an object oriented cryptography toolkit that implements several
fundamental cryptographic algorithms including TWOFISH, SERPENT, RIJNDAEL, RSA
with key-generation and SHA(SHA-1,224,256,384,512) for JavaScript. This library
works in ActionScript as well. The unique feature of this library is
asynchronous processing. A heavyweight process such as 4096bit RSA key
generation will be done asynchronously so that this library does not cause
problems such as freezing browsers, "slow-downing" warning dialogs, etc.


Demonstration

    Block-Cipher Demonstration
        <a href="./Cipher.sample.html">Cipher.sample.html</a>

    RSA Key-Generation and Encryption/Decryption
        <a href="./RSA.sample1.html">RSA.sample1.html</a>
        <a href="./RSA.sample2.html">RSA.sample2.html</a>

    SHA Digest Calculation Demonstration
        <a href="./SHA.sample.html">SHA.sample.html</a>


Contents

    <a href="./Cipher.js">Cipher.js</a>
        Contains Cipher class which implements some block-cipher algorithms.
        See <a href="./Cipher.readme.txt">Cipher.readme.txt</a>

    <a href="./RSA.init1.js">RSA.init1.js</a>
    <a href="./RSA.init2.js">RSA.init2.js</a>
    <a href="./RSA.init3.js">RSA.init3.js</a>
    <a href="./RSA.init4.js">RSA.init4.js</a>
        Contains RSA class which implements RSA encryption,decryption and
        key-generation with asynchronous processing feature.
        See <a href="./RSA.readme.txt">RSA.readme.txt</a>

    <a href="./BigInteger.init1.js">BigInteger.init1.js</a>
    <a href="./BigInteger.init2.js">BigInteger.init2.js</a>
    <a href="./BigInteger.init3.js">BigInteger.init3.js</a>
        Contains BigInteger class which implements calculation of variable
        length integer.
        See <a href="./BigInteger.readme.txt">BigInteger.readme.txt</a>

    <a href="./SecureRandom.js">SecureRandom.js</a>
        Contains SecureRandom class which implements Arcfour pseudo random
        generator.
        See <a href="./SecureRandom.readme.txt">SecureRandom.readme.txt</a>

    <a href="./BitPadding.js">BitPadding.js</a>
        Contains a class that implements "bit-padding" padding-scheme.
        See <a href="./BitPadding.readme.txt">BitPadding.readme.txt</a>

    <a href="./SOAEP.js">SOAEP.js</a>
        Contains a class that implements a padding-scheme SOAEP. SOAEP is an
        original scheme that I have designed for Titaniumcore project.
        See <a href="./SOAEP.readme.txt">SOAEP.readme.txt</a>

    <A href="./RSAKeyFormat.js">RSAKeyFormat.js</a>
        Contains some methods that convert RSA key and a binary string.
        See <a href="./RSAKeyFormat.readme.txt">RSAKeyFormat.readme.txt</a>

    <a href="./RSAMessageFormat.js">RSAMessageFormat.js</a>
        Defining facade methods for RSA encryption/decryption.
        See <a href="./RSAMessageFormat.readme.txt">RSAMessageFormat.readme.txt</a>

    <a href="./SHA.js">SHA.js</a>
        Contains SHA class that calculates various SHA hash value.

        See <a href="./SHA.readme.txt">SHA.readme.txt</a>

    <a href="./jsSHA.js">jsSHA.js</a>
    <a href="./jsSHA.class.js">jsSHA.class.js</a>
        Contains the core methods for SHA calculation.
        See <a href="./jsSHA.readme.txt">jsSHA.readme.txt</a> 

        SPECIAL THANKS to Brian Turek [ <a href="http://sourceforge.net/users/caligatio">http://sourceforge.net/users/caligatio</a> ]

Notice
    - Dependency
      Most of above scripts depend on "tools" scripts and "nonstructured.js".

        - "tools" scripts
          "tools" is a set of utility scripts.  See <a href="../tools/readme.txt">readme.txt</a>.

        - <a href="./nonstructured.js">nonstructured.js</a>
          "nonstructured.js" is a framework for asynchronous execution.
          See <a href="../nonstructured/nonstructured.readme.txt">nonstructured.readme.txt</a> 


    - Data Conversion 
    
      This library does not support utf-8 conversion nor base64
      conversion directly. Most of functions in this library only take byte
      arrays as their parameters and their result is as a byte array object.
      This library does not implement conversions.  This is intended to keep
      higher reusability. 
    
      When data conversion between utf-8 or base64 to binary data is
      necessary, use <a href="../tools/binary.js">binary.js</a>" or another conversion library.
      <a href="../tools/binary.js">binary.js</a> is included in "tools" directory.

      See <a href="../tools/binary.readme.txt">binary.readme.txt</a> for further information.


Acknowledgment
================================================================================

    The core algorithm of Cipher.js is originally written by
    Michiel van Everdingen.

        The original form can be referred at 
            <a href="http://home.versatel.nl/MAvanEverdingen/Code/code.html">http://home.versatel.nl/MAvanEverdingen/Code/code.html</a>

        Contact of the Author
            Michiel van Everdingen
            <a href="http://home.versatel.nl/MAvanEverdingen/index.html">http://home.versatel.nl/MAvanEverdingen/index.html</a>

        See <a href="./Cipher.readme.txt">Cipher.readme.txt</a>


    ---

    Following files were originally written by Tom Wu :

        SecureRandom.js
        BigInteger.init1.js
        BigInteger.init2.js
        BigInteger.init3.js
        RSA.init1.js
        RSA.init2.js
        RSA.init3.js

        Copyright (c) 2005  Tom Wu
        All Rights Reserved.
        <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/">http://www-cs-students.stanford.edu/~tjw/jsbn/</a>

        See "LICENSE" for details.
        <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/LICENSE">http://www-cs-students.stanford.edu/~tjw/jsbn/LICENSE</a>

        See <a href="./RSA.readme.txt">RSA.readme.txt</a>

    ---

    jsSHA.js is written by Brian Turek [ <a href="http://sourceforge.net/users/caligatio">http://sourceforge.net/users/caligatio</a> ].

        &gt; A JavaScript implementation of the SHA family of hashes, 
        &gt; as defined in FIPS PUB 180-2
        &gt; Version 1.1 Copyright Brian Turek 2008
        &gt; Distributed under the BSD License
        &gt; See <a href="http://jssha.sourceforge.net/">http://jssha.sourceforge.net/</a> for more information
        &gt;
        &gt; Several functions taken from Paul Johnson

        See <a href="./jsSHA.readme.txt">jsSHA.readme.txt</a>



================================================================================
This library is distributed under LGPL.

// vim:expandtab:

</pre>
</div>
</body>
</html>
