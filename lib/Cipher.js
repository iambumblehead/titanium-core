/*
 * Cipher.js
 * A block-cipher algorithm implementation on JavaScript
 * See Cipher.readme.txt for further information.
 *
 * Copyright(c) 2009 Atsushi Oka [ http://oka.nu/ ]
 * This script file is distributed under the LGPL
 *
 * ACKNOWLEDGMENT
 *
 *     The main subroutines are written by Michiel van Everdingen.
 * 
 *     Michiel van Everdingen
 *     http://home.versatel.nl/MAvanEverdingen/index.html
 * 
 *     All rights for these routines are reserved to Michiel van Everdingen.
 *
 */

function initBlockCipher( packageRoot ) {
    __unit( "Cipher.js" );
    __uses( "packages.js" );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Math
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var MAXINT = 0xFFFFFFFF;

function rotb(b,n){ return ( b<<n | b>>>( 8-n) ) & 0xFF; }
function rotw(w,n){ return ( w<<n | w>>>(32-n) ) & MAXINT; }
function getW(a,i){ return a[i]|a[i+1]<<8|a[i+2]<<16|a[i+3]<<24; }
function setW(a,i,w){ a.splice(i,4,w&0xFF,(w>>>8)&0xFF,(w>>>16)&0xFF,(w>>>24)&0xFF); }
function setWInv(a,i,w){ a.splice(i,4,(w>>>24)&0xFF,(w>>>16)&0xFF,(w>>>8)&0xFF,w&0xFF); }
function getB(x,n){ return (x>>>(n*8))&0xFF; }

function getNrBits(i){ var n=0; while (i>0){ n++; i>>>=1; } return n; }
function getMask(n){ return (1<<n)-1; }

// added 2008/11/13 XXX MUST USE ONE-WAY HASH FUNCTION FOR SECURITY REASON
function randByte() {
    return Math.floor( Math.random() * 256 );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Ciphers
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


var ALGORITHMS = {};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function createRijndael() {
    //
	var keyBytes      = null;
	var dataBytes     = null;
	var dataOffset    = -1;
	// var dataLength    = -1;
	var algorithmName = null;
	//var idx2          = -1;
    //

    algorithmName = "rijndael"

    var aesNk;
    var aesNr;

    var aesPows;
    var aesLogs;
    var aesSBox;
    var aesSBoxInv;
    var aesRco;
    var aesFtable;
    var aesRtable;
    var aesFi;
    var aesRi;
    var aesFkey;
    var aesRkey;

    function aesMult(x, y){ return (x&&y) ? aesPows[(aesLogs[x]+aesLogs[y])%255]:0; }

    function aesPackBlock() {
      return [ getW(dataBytes,dataOffset), getW(dataBytes,dataOffset+4), getW(dataBytes,dataOffset+8), getW(dataBytes,dataOffset+12) ];
    }

    function aesUnpackBlock(packed){
      for ( var j=0; j<4; j++,dataOffset+=4) setW( dataBytes, dataOffset, packed[j] );
    }

    function aesXTime(p){
      p <<= 1;
      return p&0x100 ? p^0x11B : p;
    }

    function aesSubByte(w){
      return aesSBox[getB(w,0)] | aesSBox[getB(w,1)]<<8 | aesSBox[getB(w,2)]<<16 | aesSBox[getB(w,3)]<<24;
    }

    function aesProduct(w1,w2){
      return aesMult(getB(w1,0),getB(w2,0)) ^ aesMult(getB(w1,1),getB(w2,1))
	   ^ aesMult(getB(w1,2),getB(w2,2)) ^ aesMult(getB(w1,3),getB(w2,3));
    }

    function aesInvMixCol(x){
      return aesProduct(0x090d0b0e,x)     | aesProduct(0x0d0b0e09,x)<<8 |
	     aesProduct(0x0b0e090d,x)<<16 | aesProduct(0x0e090d0b,x)<<24;
    }

    function aesByteSub(x){
      var y=aesPows[255-aesLogs[x]];
      x=y;  x=rotb(x,1);
      y^=x; x=rotb(x,1);
      y^=x; x=rotb(x,1);
      y^=x; x=rotb(x,1);
      return x^y^0x63;
    }

    function aesGenTables(){
      var i,y;
      aesPows = [ 1,3 ];
      aesLogs = [ 0,0,null,1 ];
      aesSBox = new Array(256);
      aesSBoxInv = new Array(256);
      aesFtable = new Array(256);
      aesRtable = new Array(256);
      aesRco = new Array(30);

      for ( i=2; i<256; i++){
	aesPows[i]=aesPows[i-1]^aesXTime( aesPows[i-1] );
	aesLogs[aesPows[i]]=i;
      }

      aesSBox[0]=0x63;
      aesSBoxInv[0x63]=0;
      for ( i=1; i<256; i++){
	y=aesByteSub(i);
	aesSBox[i]=y; aesSBoxInv[y]=i;
      }

      for (i=0,y=1; i<30; i++){ aesRco[i]=y; y=aesXTime(y); }

      for ( i=0; i<256; i++){
	y = aesSBox[i];
	aesFtable[i] = aesXTime(y) | y<<8 | y<<16 | (y^aesXTime(y))<<24;
	y = aesSBoxInv[i];
	aesRtable[i]= aesMult(14,y) | aesMult(9,y)<<8 |
		      aesMult(13,y)<<16 | aesMult(11,y)<<24;
      }
    }

    function aesInit( key ){
      keyBytes = key;
      keyBytes=keyBytes.slice(0,32);
      var i,k,m;
      var j = 0;
      var l = keyBytes.length;

      while ( l!=16 && l!=24 && l!=32 ) keyBytes[l++]=keyBytes[j++];
      aesGenTables();

      aesNk = keyBytes.length >>> 2;
      aesNr = 6 + aesNk;

      var N=4*(aesNr+1);

      aesFi = new Array(12);
      aesRi = new Array(12);
      aesFkey = new Array(N);
      aesRkey = new Array(N);

      for (m=j=0;j<4;j++,m+=3){
	aesFi[m]=(j+1)%4;
	aesFi[m+1]=(j+2)%4;
	aesFi[m+2]=(j+3)%4;
	aesRi[m]=(4+j-1)%4;
	aesRi[m+1]=(4+j-2)%4;
	aesRi[m+2]=(4+j-3)%4;
      }

      for (i=j=0;i<aesNk;i++,j+=4) aesFkey[i]=getW(keyBytes,j);

      for (k=0,j=aesNk;j<N;j+=aesNk,k++){
	aesFkey[j]=aesFkey[j-aesNk]^aesSubByte(rotw(aesFkey[j-1], 24))^aesRco[k];
	if (aesNk<=6)
	  for (i=1;i<aesNk && (i+j)<N;i++) aesFkey[i+j]=aesFkey[i+j-aesNk]^aesFkey[i+j-1];
	else{
	  for (i=1;i<4 &&(i+j)<N;i++) aesFkey[i+j]=aesFkey[i+j-aesNk]^aesFkey[i+j-1];
	  if ((j+4)<N) aesFkey[j+4]=aesFkey[j+4-aesNk]^aesSubByte(aesFkey[j+3]);
	  for (i=5;i<aesNk && (i+j)<N;i++) aesFkey[i+j]=aesFkey[i+j-aesNk]^aesFkey[i+j-1];
	}
      }

      for (j=0;j<4;j++) aesRkey[j+N-4]=aesFkey[j];
      for (i=4;i<N-4;i+=4){
	k=N-4-i;
	for (j=0;j<4;j++) aesRkey[k+j]=aesInvMixCol(aesFkey[i+j]);
      }
      for (j=N-4;j<N;j++) aesRkey[j-N+4]=aesFkey[j];
    }

    function aesClose(){
      aesPows=aesLogs=aesSBox=aesSBoxInv=aesRco=null;
      aesFtable=aesRtable=aesFi=aesRi=aesFkey=aesRkey=null;
    }

    function aesRounds( block, key, table, inc, box ){
      var tmp = new Array( 4 );
      var i,j,m,r;

      for ( r=0; r<4; r++ ) block[r]^=key[r];
      for ( i=1; i<aesNr; i++ ){
	for (j=m=0;j<4;j++,m+=3){
	  tmp[j]=key[r++]^table[block[j]&0xFF]^
		 rotw(table[(block[inc[m]]>>>8)&0xFF], 8)^
		 rotw(table[(block[inc[m+1]]>>>16)&0xFF], 16)^
		 rotw(table[(block[inc[m+2]]>>>24)&0xFF], 24);
	}
	var t=block; block=tmp; tmp=t;
      }

      for (j=m=0;j<4;j++,m+=3)
	tmp[j]=key[r++]^box[block[j]&0xFF]^
	       rotw(box[(block[inc[m  ]]>>> 8)&0xFF], 8)^
	       rotw(box[(block[inc[m+1]]>>>16)&0xFF],16)^
	       rotw(box[(block[inc[m+2]]>>>24)&0xFF],24);
      return tmp;
    }

    function aesEncrypt( data,offset ){
      dataBytes = data;
      dataOffset = offset;
      aesUnpackBlock( aesRounds( aesPackBlock(), aesFkey, aesFtable, aesFi, aesSBox ) );
    }

    function aesDecrypt( data,offset){
      dataBytes = data;
      dataOffset = offset;
      aesUnpackBlock( aesRounds(aesPackBlock(), aesRkey, aesRtable, aesRi, aesSBoxInv ) );
    }

    return {
	name    : "rijndael",
	blocksize : 128/8,
	open    : aesInit,
	close   : aesClose,
	encrypt : aesEncrypt,
	decrypt : aesDecrypt
    };
}
ALGORITHMS.RIJNDAEL = {
    create : createRijndael
};


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Serpent
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


function createSerpent() {
    //
	var keyBytes      = null;
	var dataBytes     = null;
	var dataOffset    = -1;
	//var dataLength    = -1;
	var algorithmName = null;
	// var idx2          = -1;
    //

    algorithmName = "serpent";

    var srpKey=[];

    function srpK(r,a,b,c,d,i){
      r[a]^=srpKey[4*i]; r[b]^=srpKey[4*i+1]; r[c]^=srpKey[4*i+2]; r[d]^=srpKey[4*i+3];
    }

    function srpLK(r,a,b,c,d,e,i){
      r[a]=rotw(r[a],13);r[c]=rotw(r[c],3);r[b]^=r[a];r[e]=(r[a]<<3)&MAXINT;
      r[d]^=r[c];r[b]^=r[c];r[b]=rotw(r[b],1);r[d]^=r[e];r[d]=rotw(r[d],7);r[e]=r[b];
      r[a]^=r[b];r[e]=(r[e]<<7)&MAXINT;r[c]^=r[d];r[a]^=r[d];r[c]^=r[e];r[d]^=srpKey[4*i+3];
      r[b]^=srpKey[4*i+1];r[a]=rotw(r[a],5);r[c]=rotw(r[c],22);r[a]^=srpKey[4*i+0];r[c]^=srpKey[4*i+2];
    }

    function srpKL(r,a,b,c,d,e,i){
      r[a]^=srpKey[4*i+0];r[b]^=srpKey[4*i+1];r[c]^=srpKey[4*i+2];r[d]^=srpKey[4*i+3];
      r[a]=rotw(r[a],27);r[c]=rotw(r[c],10);r[e]=r[b];r[c]^=r[d];r[a]^=r[d];r[e]=(r[e]<<7)&MAXINT;
      r[a]^=r[b];r[b]=rotw(r[b],31);r[c]^=r[e];r[d]=rotw(r[d],25);r[e]=(r[a]<<3)&MAXINT;
      r[b]^=r[a];r[d]^=r[e];r[a]=rotw(r[a],19);r[b]^=r[c];r[d]^=r[c];r[c]=rotw(r[c],29);
    }

    var srpS=[
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x3];r[x3]|=r[x0];r[x0]^=r[x4];r[x4]^=r[x2];r[x4]=~r[x4];r[x3]^=r[x1];
      r[x1]&=r[x0];r[x1]^=r[x4];r[x2]^=r[x0];r[x0]^=r[x3];r[x4]|=r[x0];r[x0]^=r[x2];
      r[x2]&=r[x1];r[x3]^=r[x2];r[x1]=~r[x1];r[x2]^=r[x4];r[x1]^=r[x2];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x1];r[x1]^=r[x0];r[x0]^=r[x3];r[x3]=~r[x3];r[x4]&=r[x1];r[x0]|=r[x1];
      r[x3]^=r[x2];r[x0]^=r[x3];r[x1]^=r[x3];r[x3]^=r[x4];r[x1]|=r[x4];r[x4]^=r[x2];
      r[x2]&=r[x0];r[x2]^=r[x1];r[x1]|=r[x0];r[x0]=~r[x0];r[x0]^=r[x2];r[x4]^=r[x1];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x3]=~r[x3];r[x1]^=r[x0];r[x4]=r[x0];r[x0]&=r[x2];r[x0]^=r[x3];r[x3]|=r[x4];
      r[x2]^=r[x1];r[x3]^=r[x1];r[x1]&=r[x0];r[x0]^=r[x2];r[x2]&=r[x3];r[x3]|=r[x1];
      r[x0]=~r[x0];r[x3]^=r[x0];r[x4]^=r[x0];r[x0]^=r[x2];r[x1]|=r[x2];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x1];r[x1]^=r[x3];r[x3]|=r[x0];r[x4]&=r[x0];r[x0]^=r[x2];r[x2]^=r[x1];r[x1]&=r[x3];
      r[x2]^=r[x3];r[x0]|=r[x4];r[x4]^=r[x3];r[x1]^=r[x0];r[x0]&=r[x3];r[x3]&=r[x4];
      r[x3]^=r[x2];r[x4]|=r[x1];r[x2]&=r[x1];r[x4]^=r[x3];r[x0]^=r[x3];r[x3]^=r[x2];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x3];r[x3]&=r[x0];r[x0]^=r[x4];r[x3]^=r[x2];r[x2]|=r[x4];r[x0]^=r[x1];
      r[x4]^=r[x3];r[x2]|=r[x0];r[x2]^=r[x1];r[x1]&=r[x0];r[x1]^=r[x4];r[x4]&=r[x2];
      r[x2]^=r[x3];r[x4]^=r[x0];r[x3]|=r[x1];r[x1]=~r[x1];r[x3]^=r[x0];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x1];r[x1]|=r[x0];r[x2]^=r[x1];r[x3]=~r[x3];r[x4]^=r[x0];r[x0]^=r[x2];
      r[x1]&=r[x4];r[x4]|=r[x3];r[x4]^=r[x0];r[x0]&=r[x3];r[x1]^=r[x3];r[x3]^=r[x2];
      r[x0]^=r[x1];r[x2]&=r[x4];r[x1]^=r[x2];r[x2]&=r[x0];r[x3]^=r[x2];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x1];r[x3]^=r[x0];r[x1]^=r[x2];r[x2]^=r[x0];r[x0]&=r[x3];r[x1]|=r[x3];
      r[x4]=~r[x4];r[x0]^=r[x1];r[x1]^=r[x2];r[x3]^=r[x4];r[x4]^=r[x0];r[x2]&=r[x0];
      r[x4]^=r[x1];r[x2]^=r[x3];r[x3]&=r[x1];r[x3]^=r[x0];r[x1]^=r[x2];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x1]=~r[x1];r[x4]=r[x1];r[x0]=~r[x0];r[x1]&=r[x2];r[x1]^=r[x3];r[x3]|=r[x4];r[x4]^=r[x2];
      r[x2]^=r[x3];r[x3]^=r[x0];r[x0]|=r[x1];r[x2]&=r[x0];r[x0]^=r[x4];r[x4]^=r[x3];
      r[x3]&=r[x0];r[x4]^=r[x1];r[x2]^=r[x4];r[x3]^=r[x1];r[x4]|=r[x0];r[x4]^=r[x1];
    }];

    var srpSI=[
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x3];r[x1]^=r[x0];r[x3]|=r[x1];r[x4]^=r[x1];r[x0]=~r[x0];r[x2]^=r[x3];
      r[x3]^=r[x0];r[x0]&=r[x1];r[x0]^=r[x2];r[x2]&=r[x3];r[x3]^=r[x4];r[x2]^=r[x3];
      r[x1]^=r[x3];r[x3]&=r[x0];r[x1]^=r[x0];r[x0]^=r[x2];r[x4]^=r[x3];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x1]^=r[x3];r[x4]=r[x0];r[x0]^=r[x2];r[x2]=~r[x2];r[x4]|=r[x1];r[x4]^=r[x3];
      r[x3]&=r[x1];r[x1]^=r[x2];r[x2]&=r[x4];r[x4]^=r[x1];r[x1]|=r[x3];r[x3]^=r[x0];
      r[x2]^=r[x0];r[x0]|=r[x4];r[x2]^=r[x4];r[x1]^=r[x0];r[x4]^=r[x1];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x2]^=r[x1];r[x4]=r[x3];r[x3]=~r[x3];r[x3]|=r[x2];r[x2]^=r[x4];r[x4]^=r[x0];
      r[x3]^=r[x1];r[x1]|=r[x2];r[x2]^=r[x0];r[x1]^=r[x4];r[x4]|=r[x3];r[x2]^=r[x3];
      r[x4]^=r[x2];r[x2]&=r[x1];r[x2]^=r[x3];r[x3]^=r[x4];r[x4]^=r[x0];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x2]^=r[x1];r[x4]=r[x1];r[x1]&=r[x2];r[x1]^=r[x0];r[x0]|=r[x4];r[x4]^=r[x3];
      r[x0]^=r[x3];r[x3]|=r[x1];r[x1]^=r[x2];r[x1]^=r[x3];r[x0]^=r[x2];r[x2]^=r[x3];
      r[x3]&=r[x1];r[x1]^=r[x0];r[x0]&=r[x2];r[x4]^=r[x3];r[x3]^=r[x0];r[x0]^=r[x1];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x2]^=r[x3];r[x4]=r[x0];r[x0]&=r[x1];r[x0]^=r[x2];r[x2]|=r[x3];r[x4]=~r[x4];
      r[x1]^=r[x0];r[x0]^=r[x2];r[x2]&=r[x4];r[x2]^=r[x0];r[x0]|=r[x4];r[x0]^=r[x3];
      r[x3]&=r[x2];r[x4]^=r[x3];r[x3]^=r[x1];r[x1]&=r[x0];r[x4]^=r[x1];r[x0]^=r[x3];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x1];r[x1]|=r[x2];r[x2]^=r[x4];r[x1]^=r[x3];r[x3]&=r[x4];r[x2]^=r[x3];r[x3]|=r[x0];
      r[x0]=~r[x0];r[x3]^=r[x2];r[x2]|=r[x0];r[x4]^=r[x1];r[x2]^=r[x4];r[x4]&=r[x0];r[x0]^=r[x1];
      r[x1]^=r[x3];r[x0]&=r[x2];r[x2]^=r[x3];r[x0]^=r[x2];r[x2]^=r[x4];r[x4]^=r[x3];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x0]^=r[x2];r[x4]=r[x0];r[x0]&=r[x3];r[x2]^=r[x3];r[x0]^=r[x2];r[x3]^=r[x1];
      r[x2]|=r[x4];r[x2]^=r[x3];r[x3]&=r[x0];r[x0]=~r[x0];r[x3]^=r[x1];r[x1]&=r[x2];
      r[x4]^=r[x0];r[x3]^=r[x4];r[x4]^=r[x2];r[x0]^=r[x1];r[x2]^=r[x0];
    },
    function(r,x0,x1,x2,x3,x4){
      r[x4]=r[x3];r[x3]&=r[x0];r[x0]^=r[x2];r[x2]|=r[x4];r[x4]^=r[x1];r[x0]=~r[x0];r[x1]|=r[x3];
      r[x4]^=r[x0];r[x0]&=r[x2];r[x0]^=r[x1];r[x1]&=r[x2];r[x3]^=r[x2];r[x4]^=r[x3];
      r[x2]&=r[x3];r[x3]|=r[x0];r[x1]^=r[x4];r[x3]^=r[x4];r[x4]&=r[x0];r[x4]^=r[x2];
    }];

    var srpKc=[7788,63716,84032,7891,78949,25146,28835,67288,84032,40055,7361,1940,77639,27525,24193,75702,
      7361,35413,83150,82383,58619,48468,18242,66861,83150,69667,7788,31552,40054,23222,52496,57565,7788,63716];
    var srpEc=[44255,61867,45034,52496,73087,56255,43827,41448,18242,1939,18581,56255,64584,31097,26469,
      77728,77639,4216,64585,31097,66861,78949,58006,59943,49676,78950,5512,78949,27525,52496,18670,76143];
    var srpDc=[44255,60896,28835,1837,1057,4216,18242,77301,47399,53992,1939,1940,66420,39172,78950,
      45917,82383,7450,67288,26469,83149,57565,66419,47400,58006,44254,18581,18228,33048,45034,66508,7449];

    function srpInit(key)
    {
      keyBytes = key;
      var i,j,m,n;
      function keyIt(a,b,c,d,i){ srpKey[i]=r[b]=rotw(srpKey[a]^r[b]^r[c]^r[d]^0x9e3779b9^i,11); }
      function keyLoad(a,b,c,d,i){ r[a]=srpKey[i]; r[b]=srpKey[i+1]; r[c]=srpKey[i+2]; r[d]=srpKey[i+3]; }
      function keyStore(a,b,c,d,i){ srpKey[i]=r[a]; srpKey[i+1]=r[b]; srpKey[i+2]=r[c]; srpKey[i+3]=r[d]; }

      keyBytes.reverse();
      keyBytes[keyBytes.length]=1; while (keyBytes.length<32) keyBytes[keyBytes.length]=0;
      for (i=0; i<8; i++){
	srpKey[i] = (keyBytes[4*i+0] & 0xff)       | (keyBytes[4*i+1] & 0xff) <<  8 |
	(keyBytes[4*i+2] & 0xff) << 16 | (keyBytes[4*i+3] & 0xff) << 24;
      }

      var r = [srpKey[3],srpKey[4],srpKey[5],srpKey[6],srpKey[7]];

      i=0; j=0;
      while (keyIt(j++,0,4,2,i++),keyIt(j++,1,0,3,i++),i<132){
	keyIt(j++,2,1,4,i++); if (i==8){j=0;}
	keyIt(j++,3,2,0,i++); keyIt(j++,4,3,1,i++);
      }

      i=128; j=3; n=0;
      while(m=srpKc[n++],srpS[j++%8](r,m%5,m%7,m%11,m%13,m%17),m=srpKc[n],keyStore(m%5,m%7,m%11,m%13,i),i>0){
	i-=4; keyLoad(m%5,m%7,m%11,m%13,i);
      }
    }

    function srpClose(){
      srpKey=[];
    }

    function srpEncrypt( data,offset)
    {
      dataBytes = data;
      dataOffset = offset;
      var blk = dataBytes.slice(dataOffset,dataOffset+16); blk.reverse();
      var r=[getW(blk,0),getW(blk,4),getW(blk,8),getW(blk,12)];

      srpK(r,0,1,2,3,0);
      var n=0, m=srpEc[n];
      while (srpS[n%8](r,m%5,m%7,m%11,m%13,m%17),n<31){ m=srpEc[++n]; srpLK(r,m%5,m%7,m%11,m%13,m%17,n); }
      srpK(r,0,1,2,3,32);

      for (var j=3; j>=0; j--,dataOffset+=4) setWInv(dataBytes,dataOffset,r[j]);
    }

    function srpDecrypt(data,offset)
    {
      dataBytes = data;
      dataOffset = offset;
      var blk = dataBytes.slice(dataOffset,dataOffset+16); blk.reverse();
      var r=[getW(blk,0),getW(blk,4),getW(blk,8),getW(blk,12)];

      srpK(r,0,1,2,3,32);
      var n=0, m=srpDc[n];
      while (srpSI[7-n%8](r,m%5,m%7,m%11,m%13,m%17),n<31){ m=srpDc[++n]; srpKL(r,m%5,m%7,m%11,m%13,m%17,32-n); }
      srpK(r,2,3,1,4,0);

      setWInv(dataBytes,dataOffset,r[4]); setWInv(dataBytes,dataOffset+4,r[1]); setWInv(dataBytes,dataOffset+8,r[3]); setWInv(dataBytes,dataOffset+12,r[2]);
      dataOffset+=16;
    }

    return {
	name    : "serpent",
	blocksize : 128/8,
	open    : srpInit,
	close   : srpClose,
	encrypt : srpEncrypt,
	decrypt : srpDecrypt
    };
}
ALGORITHMS.SERPENT = {
    create : createSerpent
};


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Twofish
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function createTwofish() {
    //
	var keyBytes      = null;
	var dataBytes     = null;
	var dataOffset    = -1;
	// var dataLength    = -1;
	var algorithmName = null;
	// var idx2          = -1;
    //

    algorithmName = "twofish";

    var tfsKey=[];
    var tfsM=[[],[],[],[]];

    function tfsInit(key)
    {
      keyBytes = key;
      var  i, a, b, c, d, meKey=[], moKey=[], inKey=[];
      var kLen;
      var sKey=[];
      var  f01, f5b, fef;

      var q0=[[8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4],[2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5]];
      var q1=[[14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13],[1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8]];
      var q2=[[11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1],[4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15]];
      var q3=[[13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10],[11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10]];
      var ror4=[0,8,1,9,2,10,3,11,4,12,5,13,6,14,7,15];
      var ashx=[0,9,2,11,4,13,6,15,8,1,10,3,12,5,14,7];
      var q=[[],[]];
      var m=[[],[],[],[]];

      function ffm5b(x){ return x^(x>>2)^[0,90,180,238][x&3]; }
      function ffmEf(x){ return x^(x>>1)^(x>>2)^[0,238,180,90][x&3]; }

      function mdsRem(p,q){
	var i,t,u;
	for(i=0; i<8; i++){
	  t = q>>>24;
	  q = ((q<<8)&MAXINT) | p>>>24;
	  p = (p<<8)&MAXINT;
	  u = t<<1; if (t&128){ u^=333; }
	  q ^= t^(u<<16);
	  u ^= t>>>1; if (t&1){ u^=166; }
	  q ^= u<<24 | u<<8;
	}
	return q;
      }

      function qp(n,x){
	var a,b,c,d;
	a=x>>4; b=x&15;
	c=q0[n][a^b]; d=q1[n][ror4[b]^ashx[a]];
	return q3[n][ror4[d]^ashx[c]]<<4 | q2[n][c^d];
      }

      function hFun(x,key){
	var a=getB(x,0), b=getB(x,1), c=getB(x,2), d=getB(x,3);
	switch(kLen){
	case 4:
	  a = q[1][a]^getB(key[3],0);
	  b = q[0][b]^getB(key[3],1);
	  c = q[0][c]^getB(key[3],2);
	  d = q[1][d]^getB(key[3],3);
	case 3:
	  a = q[1][a]^getB(key[2],0);
	  b = q[1][b]^getB(key[2],1);
	  c = q[0][c]^getB(key[2],2);
	  d = q[0][d]^getB(key[2],3);
	case 2:
	  a = q[0][q[0][a]^getB(key[1],0)]^getB(key[0],0);
	  b = q[0][q[1][b]^getB(key[1],1)]^getB(key[0],1);
	  c = q[1][q[0][c]^getB(key[1],2)]^getB(key[0],2);
	  d = q[1][q[1][d]^getB(key[1],3)]^getB(key[0],3);
	}
	return m[0][a]^m[1][b]^m[2][c]^m[3][d];
      }

      keyBytes=keyBytes.slice(0,32); i=keyBytes.length;
      while ( i!=16 && i!=24 && i!=32 ) keyBytes[i++]=0;

      for (i=0; i<keyBytes.length; i+=4){ inKey[i>>2]=getW(keyBytes,i); }
      for (i=0; i<256; i++){ q[0][i]=qp(0,i); q[1][i]=qp(1,i); }
      for (i=0; i<256; i++){
	f01 = q[1][i]; f5b = ffm5b(f01); fef = ffmEf(f01);
	m[0][i] = f01 + (f5b<<8) + (fef<<16) + (fef<<24);
	m[2][i] = f5b + (fef<<8) + (f01<<16) + (fef<<24);
	f01 = q[0][i]; f5b = ffm5b(f01); fef = ffmEf(f01);
	m[1][i] = fef + (fef<<8) + (f5b<<16) + (f01<<24);
	m[3][i] = f5b + (f01<<8) + (fef<<16) + (f5b<<24);
      }

      kLen = inKey.length/2;
      for (i=0; i<kLen; i++){
	a = inKey[i+i];   meKey[i] = a;
	b = inKey[i+i+1]; moKey[i] = b;
	sKey[kLen-i-1] = mdsRem(a,b);
      }
      for (i=0; i<40; i+=2){
	a=0x1010101*i; b=a+0x1010101;
	a=hFun(a,meKey);
	b=rotw(hFun(b,moKey),8);
	tfsKey[i]=(a+b)&MAXINT;
	tfsKey[i+1]=rotw(a+2*b,9);
      }
      for (i=0; i<256; i++){
	a=b=c=d=i;
	switch(kLen){
	case 4:
	  a = q[1][a]^getB(sKey[3],0);
	  b = q[0][b]^getB(sKey[3],1);
	  c = q[0][c]^getB(sKey[3],2);
	  d = q[1][d]^getB(sKey[3],3);
	case 3:
	  a = q[1][a]^getB(sKey[2],0);
	  b = q[1][b]^getB(sKey[2],1);
	  c = q[0][c]^getB(sKey[2],2);
	  d = q[0][d]^getB(sKey[2],3);
	case 2:
	  tfsM[0][i] = m[0][q[0][q[0][a]^getB(sKey[1],0)]^getB(sKey[0],0)];
	  tfsM[1][i] = m[1][q[0][q[1][b]^getB(sKey[1],1)]^getB(sKey[0],1)];
	  tfsM[2][i] = m[2][q[1][q[0][c]^getB(sKey[1],2)]^getB(sKey[0],2)];
	  tfsM[3][i] = m[3][q[1][q[1][d]^getB(sKey[1],3)]^getB(sKey[0],3)];
	}
      }
    }

    function tfsG0(x){ return tfsM[0][getB(x,0)]^tfsM[1][getB(x,1)]^tfsM[2][getB(x,2)]^tfsM[3][getB(x,3)]; }
    function tfsG1(x){ return tfsM[0][getB(x,3)]^tfsM[1][getB(x,0)]^tfsM[2][getB(x,1)]^tfsM[3][getB(x,2)]; }

    function tfsFrnd(r,blk){
      var a=tfsG0(blk[0]); var b=tfsG1(blk[1]);
      blk[2] = rotw( blk[2]^(a+b+tfsKey[4*r+8])&MAXINT, 31 );
      blk[3] = rotw(blk[3],1) ^ (a+2*b+tfsKey[4*r+9])&MAXINT;
      a=tfsG0(blk[2]); b=tfsG1(blk[3]);
      blk[0] = rotw( blk[0]^(a+b+tfsKey[4*r+10])&MAXINT, 31 );
      blk[1] = rotw(blk[1],1) ^ (a+2*b+tfsKey[4*r+11])&MAXINT;
    }

    function tfsIrnd(i,blk){
      var a=tfsG0(blk[0]); var b=tfsG1(blk[1]);
      blk[2] = rotw(blk[2],1) ^ (a+b+tfsKey[4*i+10])&MAXINT;
      blk[3] = rotw( blk[3]^(a+2*b+tfsKey[4*i+11])&MAXINT, 31 );
      a=tfsG0(blk[2]); b=tfsG1(blk[3]);
      blk[0] = rotw(blk[0],1) ^ (a+b+tfsKey[4*i+8])&MAXINT;
      blk[1] = rotw( blk[1]^(a+2*b+tfsKey[4*i+9])&MAXINT, 31 );
    }

    function tfsClose(){
      tfsKey=[];
      tfsM=[[],[],[],[]];
    }

    function tfsEncrypt( data,offset){
      dataBytes = data;
      dataOffset = offset;
      var blk=[getW(dataBytes,dataOffset)^tfsKey[0], getW(dataBytes,dataOffset+4)^tfsKey[1], getW(dataBytes,dataOffset+8)^tfsKey[2], getW(dataBytes,dataOffset+12)^tfsKey[3]];
      for (var j=0;j<8;j++){ tfsFrnd(j,blk); }
      setW(dataBytes,dataOffset   ,blk[2]^tfsKey[4]);
      setW(dataBytes,dataOffset+ 4,blk[3]^tfsKey[5]);
      setW(dataBytes,dataOffset+ 8,blk[0]^tfsKey[6]);
      setW(dataBytes,dataOffset+12,blk[1]^tfsKey[7]);
      dataOffset+=16;
    }

    function tfsDecrypt(data,offset){
      dataBytes = data;
      dataOffset = offset;
      var blk=[getW(dataBytes,dataOffset)^tfsKey[4], getW(dataBytes,dataOffset+4)^tfsKey[5], getW(dataBytes,dataOffset+8)^tfsKey[6], getW(dataBytes,dataOffset+12)^tfsKey[7]];
      for (var j=7;j>=0;j--){ tfsIrnd(j,blk); }
      setW(dataBytes,dataOffset   ,blk[2]^tfsKey[0]);
      setW(dataBytes,dataOffset+ 4,blk[3]^tfsKey[1]);
      setW(dataBytes,dataOffset+ 8,blk[0]^tfsKey[2]);
      setW(dataBytes,dataOffset+12,blk[1]^tfsKey[3]);
      dataOffset+=16;
    }

    return {
	name    : "twofish",
	blocksize : 128/8,
	open    : tfsInit,
	close   : tfsClose,
	encrypt : tfsEncrypt,
	decrypt : tfsDecrypt
    };
}
ALGORITHMS.TWOFISH  = {
    create : createTwofish
};




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BLOCK CIPHER MODES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var MODES = {};

function createECB() {
    function encryptOpenECB() {
	this.algorithm.open( this.keyBytes );
	this.dataLength = this.dataBytes.length;
	this.dataOffset=0;
	// idx2=0;
	return;
    }

    function encryptCloseECB() {
	this.algorithm.close();
    }
    function encryptProcECB(){
	this.algorithm.encrypt( this.dataBytes, this.dataOffset );
	this.dataOffset += this.algorithm.blocksize;
	if (this.dataLength<=this.dataOffset) {
	    return 0;
	} else {
	    return this.dataLength-this.dataOffset;
	}
    }
    function decryptOpenECB() {
	this.algorithm.open( this.keyBytes );
	// this.dataLength = dataBytes.length;
	this.dataLength = this.dataBytes.length;
	this.dataOffset=0;
	// idx2=0;
	return;
    }

    function decryptProcECB(){
	this.algorithm.decrypt( this.dataBytes, this.dataOffset );
	this.dataOffset += this.algorithm.blocksize;
	if ( this.dataLength<=this.dataOffset ){
	    return 0;
	} else {
	    return this.dataLength-this.dataOffset;
	}
    }
    function decryptCloseECB() {
	this.algorithm.close();

	// ???
	while( this.dataBytes[this.dataBytes.length-1] ==0 )
	    this.dataBytes.pop();
	// while( dataBytes[dataBytes.length-1] ==0 )
	//     dataBytes.pop();
    }

    return {
	encrypt : {
	    open  : encryptOpenECB,
	    exec  : encryptProcECB, 
	    close : encryptCloseECB
	},
	decrypt : {
	    open  : decryptOpenECB,
	    exec  : decryptProcECB,
	    close : decryptCloseECB 
	}
    };
}
MODES.ECB = createECB();


function createCBC() {
    function encryptOpenCBC() {
	this.algorithm.open( this.keyBytes );
	this.dataBytes.unshift(
	    randByte(),randByte(),randByte(),randByte(),   randByte(),randByte(),randByte(),randByte(), 
	    randByte(),randByte(),randByte(),randByte(),   randByte(),randByte(),randByte(),randByte()
	);
	this.dataLength = this.dataBytes.length;
	this.dataOffset=16;
	// idx2=0;
	return;
    }
    function encryptProcCBC(){
	for (var idx2=this.dataOffset; idx2<this.dataOffset+16; idx2++)
	    this.dataBytes[idx2] ^= this.dataBytes[idx2-16];
	this.algorithm.encrypt( this.dataBytes, this.dataOffset );
	this.dataOffset += this.algorithm.blocksize;

	if (this.dataLength<=this.dataOffset) {
	    return 0;
	} else {
	    return this.dataLength-this.dataOffset;
	}
    }
    function encryptCloseCBC() {
	this.algorithm.close();
    }

    function decryptOpenCBC() {
	this.algorithm.open( this.keyBytes );
	this.dataLength = this.dataBytes.length;

	// notice it start from dataOffset:16
	this.dataOffset=16;

	// added 2008/12/31
	// 1. Create a new field for initialization vector.
	// 2. Get initialized vector and store it on the new field. 
	this.iv = this.dataBytes.slice(0,16);

	// idx2=0;
	return;
    }

    // function decryptProcCBC(){
    //     this.dataOffset=this.dataLength-this.dataOffset;
    //
    //     this.algorithm.decrypt( this.dataBytes, this.dataOffset );
    //     this.dataOffset += this.algorithm.blocksize;
    //
    //     for (var idx2=this.dataOffset-16; idx2<this.dataOffset; idx2++)
    //         this.dataBytes[idx2] ^= this.dataBytes[idx2-16];
    //
    //     this.dataOffset = this.dataLength+32-this.dataOffset;
    //
    //     if ( this.dataLength<=this.dataOffset ){
    //         return 0;
    //     } else {
    //         return this.dataLength-this.dataOffset;
    //     }
    // }

    function decryptProcCBC(){
	// copy cipher text for later use of initialization vector.
	var iv2 = this.dataBytes.slice( this.dataOffset, this.dataOffset + 16 );
	// decryption
	this.algorithm.decrypt( this.dataBytes, this.dataOffset );
	// xor with the current initialization vector. 
	for ( var ii=0; ii<16; ii++ )
	    this.dataBytes[this.dataOffset+ii] ^= this.iv[ii];

	// advance the index counter.
	this.dataOffset += this.algorithm.blocksize;
	// set the copied previous cipher text as the current initialization vector.
	this.iv = iv2;

	if ( this.dataLength<=this.dataOffset ){
	    return 0;
	} else {
	    return this.dataLength-this.dataOffset;
	}
    }
    function decryptCloseCBC() {
	this.algorithm.close();
	// trace( "splice.before:"+base16( this.dataBytes ) );
	this.dataBytes.splice(0,16);
	// trace( "splice.after:"+base16( this.dataBytes ) );

	// ???
	while( this.dataBytes[this.dataBytes.length-1] ==0 )
	    this.dataBytes.pop();
    }

    return {
	encrypt : {
	    open  : encryptOpenCBC,
	    exec  : encryptProcCBC, 
	    close : encryptCloseCBC
	},
	decrypt : {
	    open  : decryptOpenCBC,
	    exec  : decryptProcCBC,
	    close : decryptCloseCBC 
	}
    };
}
MODES.CBC = createCBC();

function createCFB() {
    function encryptOpenCFB() {
	throw "not implemented!";
    }
    function encryptProcCFB(){
	throw "not implemented!";
    }
    function encryptCloseCFB() {
	throw "not implemented!";
    }
    function decryptOpenCFB() {
	throw "not implemented!";
    }
    function decryptProcCFB(){
	throw "not implemented!";
    }
    function decryptCloseCFB() {
	throw "not implemented!";
    }

    return {
	encrypt : {
	    open  : encryptOpenCFB,
	    exec  : encryptProcCFB, 
	    close : encryptCloseCFB
	},
	decrypt : {
	    open  : decryptOpenCFB,
	    exec  : decryptProcCFB,
	    close : decryptCloseCFB 
	}
    };
}
MODES.CFB = createCFB();

function createOFB(){
    function encryptOpenOFB() {
	throw "not implemented!";
    }
    function encryptProcOFB(){
	throw "not implemented!";
    }
    function encryptCloseOFB() {
	throw "not implemented!";
    }
    function decryptOpenOFB() {
	throw "not implemented!";
    }
    function decryptProcOFB(){
	throw "not implemented!";
    }
    function decryptCloseOFB() {
	throw "not implemented!";
    }

    return {
	encrypt : {
	    open  : encryptOpenOFB,
	    exec  : encryptProcOFB, 
	    close : encryptCloseOFB
	},
	decrypt : {
	    open  : decryptOpenOFB,
	    exec  : decryptProcOFB,
	    close : decryptCloseOFB 
	}
    };
}
MODES.OFB = createOFB();

function createCTR() {
    function encryptOpenCTR() {
	throw "not implemented!";
    }
    function encryptProcCTR(){
	throw "not implemented!";
    }
    function encryptCloseCTR() {
	throw "not implemented!";
    }
    function decryptOpenCTR() {
	throw "not implemented!";
    }
    function decryptProcCTR(){
	throw "not implemented!";
    }
    function decryptCloseCTR() {
	throw "not implemented!";
    }

    return {
	encrypt : {
	    open  : encryptOpenCTR,
	    exec  : encryptProcCTR, 
	    close : encryptCloseCTR
	},
	decrypt : {
	    open  : decryptOpenCTR,
	    exec  : decryptProcCTR,
	    close : decryptCloseCTR 
	}
    };
}
MODES.CTR = createCTR();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PADDING ALGORITHMS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var PADDINGS = {};

/*
 * | DD DD DD DD DD DD DD DD | DD DD DD 80 00 00 00 00 |
 */
function createRFC1321() {
    function appendPaddingRFC1321(data) {
	var len = 16 - ( data.length % 16 );
	data.push( 0x80 );
	for ( var i=1;i<len;i++ ) {
	    data.push( 0x00 );
	}
	return data;
    }
    // trace( "appendPaddingRFC1321:" + base16( appendPaddingRFC1321( [0,1,2,3,4,5,6,7,8] ) ) );

    function removePaddingRFC1321(data) {
	for ( var i=data.length-1; 0<=i; i-- ) {
	    var val = data[i];
	    if ( val == 0x80 ) {
		data.splice( i );
		break;
	    } else if ( val != 0x00 ) {
		break;
	    }
	}
	return data;
    }
    // trace( "removePaddingRFC1321:" + base16( removePaddingRFC1321( [0,1,2,3,4,5,6,7,8,9,0x80,00,00,00,00] ) ) );
    return {
	append : appendPaddingRFC1321,
	remove : removePaddingRFC1321 
    };
};
PADDINGS.RFC1321 = createRFC1321();

/*
 * ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 04 |
 */
function createANSIX923() {
    function appendPaddingANSIX923(data) {
	var len = 16 - ( data.length % 16 );
	for ( var i=0; i<len-1; i++ ) {
	    data.push( 0x00 );
	}
	data.push( len );
	return data;
    }
    // trace( "appendPaddingANSIX923:" + base16( appendPaddingANSIX923( [0,1,2,3,4,5,6,7,8,9 ] ) ) );

    function removePaddingANSIX923(data) {
	var len = data.pop();
	if ( 16 < len ) len = 16;
	for ( var i=1; i<len; i++ ) {
	    data.pop();
	}
	return data;
    }
    // trace( "removePaddingANSIX923:" + base16( removePaddingANSIX923( [0,1,2,3,4,5,6,7,8,9,0x00,00,00,00,0x05] ) ) );
    return {
	append : appendPaddingANSIX923,
	remove : removePaddingANSIX923 
    };
}
PADDINGS.ANSIX923 = createANSIX923();

/*
 * ... | DD DD DD DD DD DD DD DD | DD DD DD DD 81 A6 23 04 |
 */
function createISO10126() {

    function appendPaddingISO10126(data) {
	var len = 16 - ( data.length % 16 );
	for ( var i=0; i<len-1; i++ ) {
	    data.push( randByte() );
	}
	data.push( len );
	return data;
    }
    // trace( "appendPaddingISO10126:" + base16( appendPaddingISO10126( [0,1,2,3,4,5,6,7,8,9 ] ) ) );
    function removePaddingISO10126(data) {
	var len = data.pop();
	if ( 16 < len ) len = 16;
	for ( var i=1; i<len; i++ ) {
	    data.pop();
	}
	return data;
    }
    // trace( "removePaddingISO10126:" + base16( removePaddingISO10126( [0,1,2,3,4,5,6,7,8,9,0x00,00,00,00,0x05] ) ) );
    return {
	append : appendPaddingISO10126,
	remove : removePaddingISO10126
    };
}
PADDINGS.ISO10126 = createISO10126();


/*
 * 01
 * 02 02
 * 03 03 03
 * 04 04 04 04
 * 05 05 05 05 05
 * etc.
 */
function createPKCS7() {
    function appendPaddingPKCS7(data) {
	// trace( "appendPaddingPKCS7");
	// alert( "appendPaddingPKCS7");
	var len = 16 - ( data.length % 16 );
	for ( var i=0; i<len; i++ ) {
	    data.push( len );
	}
	// trace( "data:"+base16(data) );
	// trace( "data.length:"+data.length );
	return data;
    }
    // trace( "appendPaddingPKCS7:" + base16( appendPaddingPKCS7( [0,1,2,3,4,5,6,7,8,9 ] ) ) );
    function removePaddingPKCS7(data) {
	var len = data.pop();
	if ( 16 < len ) len = 0;
	for ( var i=1; i<len; i++ ) {
	    data.pop();
	}
	return data;
    }
    // trace( "removePaddingPKCS7:" + base16( removePaddingPKCS7( [0,1,2,3,4,5,6,7,8,9,0x00,04,04,04,0x04] ) ) );
    return {
	append : appendPaddingPKCS7,
	remove : removePaddingPKCS7 
    };
}
PADDINGS.PKCS7 = createPKCS7();

/*
 * NO PADDINGS
 */
function createNoPadding() {
    function appendPaddingNone(data) {
	return data;
    }
    // trace( "appendPaddingPKCS7:" + base16( appendPaddingPKCS7( [0,1,2,3,4,5,6,7,8,9 ] ) ) );
    function removePaddingNone(data) {
	return data;
    }
    // trace( "removePaddingPKCS7:" + base16( removePaddingPKCS7( [0,1,2,3,4,5,6,7,8,9,0x00,04,04,04,0x04] ) ) );
    return {
	append : appendPaddingNone,
	remove : removePaddingNone 
    };
}
PADDINGS.NO_PADDING = createNoPadding();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ENCRYPT/DECRYPT
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
var DIRECTIONS = {
    ENCRYPT : "encrypt",
    DECRYPT : "decrypt"
};



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// INTERFACE
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function Cipher( algorithm, direction, mode, padding ) {
    this.algorithm = algorithm;
    this.direction = direction;
    this.mode = mode;
    this.padding = padding;

    this.modeOpen  = mode[ direction ].open;
    this.modeExec  = mode[ direction ].exec;
    this.modeClose = mode[ direction ].close;

    // NOTE : values below are reffered by MODE functions via "this" parameter.
    this.keyBytes  = null;
    this.dataBytes = null;
    this.dataOffset = -1;
    this.dataLength = -1;

}

Cipher.prototype = new Object();
Cipher.prototype.inherit = Cipher;

function open( keyBytes, dataBytes ) {
    if ( keyBytes == null ) throw "keyBytes is null";
    if ( dataBytes == null ) throw "dataBytes is null";

    // BE CAREFUL : THE KEY GENERATING ALGORITHM OF SERPENT HAS SIDE-EFFECT
    // TO MODIFY THE KEY ARRAY.  IT IS NECESSARY TO DUPLICATE IT BEFORE
    // PROCESS THE CIPHER TEXT. 
    this.keyBytes = keyBytes.concat();

    // DATA BUFFER IS USUALLY LARGE. DON'T DUPLICATE IT FOR PERFORMANCE REASON.
    this.dataBytes = dataBytes/*.concat()*/;

    this.dataOffset = 0;
    this.dataLength = dataBytes.length;

    //if ( this.direction == Cipher.ENCRYPT ) // fixed 2008/12/31
    if ( this.direction == DIRECTIONS.ENCRYPT ) {
	this.padding.append( this.dataBytes );
    }

    this.modeOpen();
}

function operate() {
    return this.modeExec();
}

function close() {
    this.modeClose();
    // if ( this.direction == Cipher.DECRYPT ) // fixed 2008/12/31
    if ( this.direction == DIRECTIONS.DECRYPT ) {
	this.padding.remove( this.dataBytes );
    }
    return this.dataBytes;
}

function execute( keyBytes, dataBytes ) {
    this.open( keyBytes, dataBytes );
    for(;;) {
	var size = this.operate();
	if ( 0<size ) {
	    // trace( size );
	    //alert( size );
	    continue;
	} else {
	    break;
	}
    }
    return this.close();
}

Cipher.prototype.open = open;
Cipher.prototype.close = close;
Cipher.prototype.operate = operate;
Cipher.prototype.execute = execute;

////////////////////////////////////////////////////////////////////////

// this.updateMode = function() {
//     this.modeProcs = this.mode[ this.direction ];
// };


////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


Cipher.ENCRYPT  = "ENCRYPT";
Cipher.DECRYPT  = "DECRYPT";

Cipher.RIJNDAEL = "RIJNDAEL";
Cipher.SERPENT  = "SERPENT";
Cipher.TWOFISH  = "TWOFISH";

Cipher.ECB      = "ECB";
Cipher.CBC      = "CBC";
Cipher.CFB      = "CFB";
Cipher.OFB      = "OFB";
Cipher.CTR      = "CTR";

Cipher.RFC1321    = "RFC1321";
Cipher.ANSIX923   = "ANSIX923";
Cipher.ISO10126   = "ISO10126";
Cipher.PKCS7      = "PKCS7";
Cipher.NO_PADDING = "NO_PADDING";

Cipher.create = function( algorithmName, directionName, modeName, paddingName ) {

    if ( algorithmName == null ) algorithmName = Cipher.RIJNDAEL;
    if ( directionName == null ) directionName = Cipher.ENCRYPT;
    if ( modeName      == null ) modeName      = Cipher.CBC;
    if ( paddingName   == null ) paddingName   = Cipher.PKCS7;

    var algorithm  = ALGORITHMS[ algorithmName ];
    var direction  = DIRECTIONS[ directionName ];
    var mode       = MODES[ modeName ];
    var padding    = PADDINGS[ paddingName ];

    if ( algorithm  == null ) throw "Invalid algorithm name '" + algorithmName + "'.";
    if ( direction  == null ) throw "Invalid direction name '" + directionName + "'.";
    if ( mode       == null ) throw "Invalid mode name '"      + modeName      + "'.";
    if ( padding    == null ) throw "Invalid padding name '"   + paddingName   + "'.";

    return new Cipher( algorithm.create(), direction, mode, padding );
};

Cipher.algorithm = function( algorithmName ) {
    if ( algorithmName == null ) throw "Null Pointer Exception ( algorithmName )";
    var algorithm  = ALGORITHMS[ algorithmName ];
    if ( algorithm  == null ) throw "Invalid algorithm name '" + algorithmName + "'.";
    // trace( "ss" );
    // trace( algorithm );
    return algorithm.create();
}


///////////////////////////////////
// export
///////////////////////////////////
__export( packageRoot, "titaniumcore.crypto.Cipher", Cipher );

} // the end of initBlockCipher();


initBlockCipher( this );


// vim:ts=8 sw=4:noexpandtab:
