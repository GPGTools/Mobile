
/* OpenPGP encryption using RSA/AES
 * Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
 * version 2.0, check www.haneWIN.de for the latest version

 * This software is provided as-is, without express or implied warranty.
 * Permission to use, copy, modify, distribute or sell this software, with or
 * without fee, for any purpose and by any individual or organization, is hereby
 * granted, provided that the above copyright notice and this paragraph appear
 * in all copies. Distribution as a part of an application or binary must
 * include the above copyright notice in the documentation and/or other
 * materials provided with the application or distribution.
 */

var bpbl = 16;   // block size in bytes

// ------------------------
// String to hex conversion

function str2hex(s)
{
 var hex = "0123456789abcdef";
 var r = '';

 for(var i=0; i<s.length; i++)
 {
  b = s.charCodeAt(i);
  r += hex.charAt((b>>>4)&0xf) + hex.charAt(b&0xf);

 }
 return r;
}

function hex2str(h)
{
  var s = '';
  for(var i=0; i<h.length; i+=2)
    s+= String.fromCharCode(parseInt(h.slice(i, i+2), 16));
  return s;
}

// --------------------------------------
// GPG CFB symmetric decryption using AES

function GPGdecode(key, ciphertext)
{
 var lsk = key.length;
 var iblock = new Array(bpbl);
 var ablock = new Array(bpbl);
 var expandedKey = new Array();
 var i, n, text = '';

 keySizeInBits = lsk*8;
 expandedKey = keyExpansion(key);

 // initialisation vector
 for(i=0; i < bpbl; i++) iblock[i] = 0;

 iblock = AESencrypt(iblock, expandedKey);

 for(i = 0; i < bpbl; i++)
 {
  ablock[i] = ciphertext.charCodeAt(i);
  iblock[i] ^= ablock[i];
 }

 ablock = AESencrypt(ablock, expandedKey);

 // test check octets
 if(iblock[bpbl-2]!=(ablock[0]^ciphertext.charCodeAt(bpbl))
 || iblock[bpbl-1]!=(ablock[1]^ciphertext.charCodeAt(bpbl+1)))
 {
  alert("session key decryption failed");
  return text;
 }

 // resync
 for(i=0; i<bpbl; i++) iblock[i] = ciphertext.charCodeAt(i+2);

 for(n=bpbl+2; n<ciphertext.length; n+=bpbl)
 {
  ablock = AESencrypt(iblock, expandedKey);

  for(i = 0; i<bpbl; i++)
  {
   iblock[i] = ciphertext.charCodeAt(n+i);
   text += String.fromCharCode(ablock[i]^iblock[i]);
  }
 }
 return text;
}

// -----------------------------------------------------------

function doDecrypt(p,q,d,u,text)
{
  var i=0, len, r='';

  if(text.indexOf('-----BEGIN PGP') == 0) {
    //var a=text.indexOf('\n');
    //if(a>0) a = text.indexOf('\n', a+1);
    a=text.search(/^((\r\n|\r|\n)|$)/gm);
    var e=text.indexOf('\n=');
    if(a>0 && e>0) text = text.slice(a+1,e);
  }

  var s=r2s(text);

  while(i < s.length)
  {
    r += '\n';

    var tag = s.charCodeAt(i++);

    if((tag&128) == 0) break;

    if(tag&64)
    {
      tag&=63;
      len=s.charCodeAt(i++);
      if(len>191 && len<224) len=((len-192)<<8) + s.charCodeAt(i++);
      else if(len>223 &&len<255) len = (1<<(len&0x1f));
      else if(len==255)
         len = (s.charCodeAt(i++)<<24) + (s.charCodeAt(i++)<<16) + (s.charCodeAt(i++)<<8) + s.charCodeAt(i++);
      r+="Tag:"+tag;
    }
    else
    {
      len = tag&3;
      tag = (tag>>>2)&15;
      r+="Tag:"+tag+" Len-Type:"+len;

      if(len==0) len = s.charCodeAt(i++);
      else if(len==1) len = (s.charCodeAt(i++)<<8) + s.charCodeAt(i++);
      else if(len==2)
        len = (s.charCodeAt(i++)<<24) + (s.charCodeAt(i++)<<16) + (s.charCodeAt(i++)<<8) + s.charCodeAt(i++);
      else len = s.length-i-1;
    }
    r+=" Length:"+len;

    var start=i;

    if(tag==1)
    {
      r+=' => Public Key encrypted session key Packet\n';

      var vers=s.charCodeAt(i++);
      r+="PKESK Version:"+vers+'\n';
      var id=s.substr(i, 8);
      r+="PKESK KeyId:"+str2hex(id)+'\n';
      i+=8;

      var algo=s.charCodeAt(i++);
      r+="PKESK Algorithm:"+algo+'\n';

      var lb = s.charCodeAt(i)*256 + s.charCodeAt(i+1);
      var lm = Math.floor((lb+7)/8);
      var mod = s.substr(i,lm+2);

      i+=lm+2;

      // RSA decrypt the session key
      var key=b2mpi(RSAdecrypt(mpi2b(mod),d,p,q,u));

      lb = Math.floor((key.charCodeAt(0)*256 + key.charCodeAt(1)+7)/8);
      if(lb+2 != key.length || key.charCodeAt(2) != 2)
      {
        alert('RSA decryption of session key failed');
        break;
      }
      for(l=3;l<key.length;) if(key.charCodeAt(l++) == 0) break;
      if(l+3 >= key.length)
      {
        alert('RSA decryption of session key failed');
        break;
      }
      alg = key.charCodeAt(l++);
      if(alg != 7 && alg != 8 && alg != 9)
      {
        alert('symmectric encryption not AES, AES192, AES256');
        break;
      }
      seskey = key.substr(l, key.length-l-2);
      var c = 0;
      for(var j=0; j<seskey.length; j++) c+=seskey.charCodeAt(j);
      c&=0xffff;
      if(c!=key.charCodeAt(key.length-2)*256+key.charCodeAt(key.length-1))
      {
        alert('session key checksum failed');
        break;
      }
      r+='PKESK Sessionkey:'+lb+','+seskey.length+','+str2hex(seskey)+'\n';
    }
    else if(tag==2)
    {
      r+= ' => Signature Packet\n';
    }
    else if(tag==3)
    {
      r+= ' => Symmetric-Key Encrypted Session Key Packet\n';
    }
    else if(tag==4)
    {
      r+= ' => One-Pass Signature Packet\n';
    }
    else if(tag==5)
    {
      r+=' => Secret Key Packet\n';

      var vers=s.charCodeAt(i++);
      var time=(s.charCodeAt(i++)<<24) + (s.charCodeAt(i++)<<16) + (s.charCodeAt(i++)<<8) + s.charCodeAt(i++);

      r+='Version:'+vers+' Created:'+time+'\n';

      if(vers==3)
      {
        var valid=s.charCodeAt(i++)<<8 + s.charCodeAt(i++);
        r+="Valid:"+valid+'\n';
      }

      var algo=s.charCodeAt(i++);
      r+="Algorithm:"+algo+'\n';

      var k = i;
      var lm = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
      var mod = mpi2b(s.substr(i,lm+2));

      r+="PK-modulus:"+lm+","+mod+'\n';
      i+=lm+2;
      var le = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
      var exp = mpi2b(s.substr(i,le+2));
      r+="PK-exp:"+le+","+exp+'\n';
      i+=le+2;

//      r+='---Public Key in Base64---\n'+s2r(s.substr(k,lm+le+4))+'\n---\n';

      var ske=s.charCodeAt(i++);
      var s2k=0;
      var enc=0;
      var hash=1;
      var key = '';
      var pass = '';

      r+="SK-Encryption:"+ske+'\n';

      if(ske != 0)
      {
        if(ske==255 || ske==254)
        {
          enc=s.charCodeAt(i++);
          r+="SK-CipherAlgorithm:"+enc+'\n';

          s2k=s.charCodeAt(i++);
          hash=s.charCodeAt(i++);

          r+="SK-S2K:"+s2k+' SK-HashAlgorithm:'+hash + '\n';

          if(hash != 2) alert('only SHA-1 implemented');

          if(s2k==0)
          {
            pass = window.prompt("Password:", "");

            if(hash == 2) key = str_sha1(pass);
          }
          else if(s2k==1)
          {
            pass = s.substr(i, 8) + window.prompt("Password:", "");;

            r+='salt:'+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','
                      +s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++);

            if(hash == 2) key = str_sha1(pass);
          }
          else if(s2k==3)
          {
            pass = s.substr(i, 8) + window.prompt("Password:", "");

            r+='salt:'+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','
                      +s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++);

            var cnt = s.charCodeAt(i);

            cnt = (16 +(cnt&15)) << (((cnt>>>4)&15)+6);
            var isp = pass;

            while(isp.length < cnt) isp += pass;

            r+= '\nSalt+Password Length:' + pass.length + ' ISP:' + isp.length;

            if(pass.length < cnt) isp = isp.substr(0, cnt);

            r+= ' count:'+ s.charCodeAt(i++) + '=>' + cnt;

            if(hash == 2) key = str_sha1(isp);
          }
          r+='\nKey:';

          var ekey = new Array(16);
          for(var j = 0; j < 16; j++)
          {
            ekey[j] = key.charCodeAt(j);
            r += ' ' + ekey[j];
          }
          r+='\n';

          var ablock = new Array(8);
          var iblock = new Array(8);
          for(var j = 0; j < 8; j++) iblock[j] = s.charCodeAt(i+j);

          r+='IV:'+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+
                  +s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+','+s.charCodeAt(i++)+'\n';

          var elen = start+len-i;
          r+= 'Encrypted data length:' + elen + '\n';

          var cast = new cast5(ekey);
          var text = '';

          for(var n=i; n<start+len; n+=8)
          {
            ablock = cast.Encrypt(iblock);

            for(j=0; j<8; j++)
            {
              if(n+j >= start+len) break;
              iblock[j] = s.charCodeAt(n+j);
              text += String.fromCharCode(ablock[j]^iblock[j]);
            }
          }

          if(ske == 254)
          {
            elen -= 20
            var sha = str_sha1(text.substr(0, elen));
            var n;
            for(n=0; n < 20; n++)
            {
              if(sha.charCodeAt(n) != text.charCodeAt(elen+n))
              {
                r += 'SHA-1 check failed, wrong Password?\n';
                break;
              }
            }
            if(n == 20) r += 'SHA-1 check ok\n';
          }
          else
          {
            elen -= 2;
            var sum = 0;
            for(var n = 0; n < elen; n++) sum += text.charCodeAt(n);

            var check = text.charCodeAt(elen)*256 + text.charCodeAt(elen+1);
            if((sum & 65535) == check) r += 'checksum ok\n';
            else r += 'checksum failed\n';
          }

      // ----------

          i = 0;
          var ld = Math.floor((text.charCodeAt(i)*256 + text.charCodeAt(i+1)+7)/8);
          dk = mpi2b(text.substr(i,ld+2));
          r+="SK-d:"+ld+","+dk+'\n';
          i+=ld+2;

          var lp = Math.floor((text.charCodeAt(i)*256 + text.charCodeAt(i+1)+7)/8);
          pk = mpi2b(text.substr(i,lp+2));
          r+="SK-p:"+lp+","+pk+'\n';
          i+=lp+2;

          var lq = Math.floor((text.charCodeAt(i)*256 + text.charCodeAt(i+1)+7)/8);
          qk = mpi2b(text.substr(i,lq+2));
          r+="SK-q:"+lq+","+qk+'\n';
          i+=lq+2;

          var lu = Math.floor((text.charCodeAt(i)*256 + text.charCodeAt(i+1)+7)/8);
          uk = mpi2b(text.substr(i,lu+2));
          r+="SK-u:"+lu+","+uk+'\n';
          i+=lu+2;
        }
        else
        {
          r+='---could not decode encrypted private key---\n';
        }
      }
      else
      {
      var ld = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
      dk = mpi2b(s.substr(i,ld+2));
      r+="SK-d:"+ld+","+dk+'\n';
      i+=ld+2;

      var lp = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
      pk = mpi2b(s.substr(i,lp+2));

      r+="SK-p:"+lp+","+pk+'\n';
      i+=lp+2;

      var lq = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
      qk = mpi2b(s.substr(i,lq+2));

      r+="SK-q:"+lq+","+qk+'\n';
      i+=lq+2;

      var lu = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
      uk = mpi2b(s.substr(i,lu+2));

      r+="SK-u:"+lu+","+uk+'\n';
      i+=lu+2;
     }
   }
   else if(tag==6)
   {
     r+= ' => Public Key Packet\n';
     var vers=s.charCodeAt(i++);
     var time=(s.charCodeAt(i++)<<24) + (s.charCodeAt(i++)<<16) + (s.charCodeAt(i++)<<8) + s.charCodeAt(i++);

     r+='Version:'+vers+' Created:'+time+'\n';

     if(vers==3)
     {
       var valid=s.charCodeAt(i++)<<8 + s.charCodeAt(i++);
       r+="Valid:"+valid+'\n';
     }

     var algo=s.charCodeAt(i++);
     r+="Algorithm:"+algo+'\n';

     var k = i;
     var lm = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
     var mod = mpi2b(s.substr(i,lm+2));

     r+="PK-modulus:"+lm+","+mod+'\n';
     i+=lm+2;
     var le = Math.floor((s.charCodeAt(i)*256 + s.charCodeAt(i+1)+7)/8);
     var exp = mpi2b(s.substr(i,le+2));
     r+="PK-exp:"+le+","+exp+'\n';
     i+=le+2;

//     r+='---Public Key in Base64---\n'+s2r(s.substr(k,lm+le+4))+'\n---\n';
   }
   else if(tag==7)
   {
     r+= ' => Secret-Subkey Packet\n';
   }
   else if(tag==8)
   {
     r+= ' => Compressed Data Packet\n';
   }
   else if(tag==9)
   {
     r+= ' => Symmetrically Encrypted Data Packet\n';

     s = GPGdecode(seskey, s.substr(i, len));
     r+= '---Start of decrypted packets---\n';
     i = 0; // decrypted data in packet format
     continue;
   }
   else if(tag==11)
   {
     r+= ' => Literal data Packet\n';

     var typ=s.charAt(i++);
     r+="LiteralType:"+typ+'\n';
     var l=s.charCodeAt(i++);
     var name = s.substr(i, l);
     i+=l;
     var date = (s.charCodeAt(i++)<<24) + (s.charCodeAt(i++)<<16) + (s.charCodeAt(i++)<<8) + s.charCodeAt(i++);
     r+='File:'+name+'\nDate:'+date+'\n';
     text=s.substr(i,len-l-6);
     r+='---Start of literal data---\n'+text+'\n---\n';
   }
   else if(tag==12)   // user id
   {
     r+=' => Trust Packet\n';
   }
   else if(tag==13)   // user id
   {
     r+=' => User id Packet\n' + s.substr(i,len)+'\n';
   }
   else if(tag==14)
   {
     r+= ' => Public-Subkey Packet\n';
   }
   else
   {
     r+= '\n';
   }

   i = start+len;
 }
 return r;
}
