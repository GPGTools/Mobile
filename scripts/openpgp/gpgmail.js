/**
 * OpenPGP integration for GPGMail_Mobile.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @version 2011-02-22
 * @see     http://gpgtools.org
 * @license BSD
 * @todo    Remove hard coded keys and use key management instead.
 * @todo    I18N.
 */

/* hard coded keys for now ------------------------------------------------- */
var keytype = 0;
var exp_u   = "12075,254029157,49411353,118585420,30333430,182355735,113267204,59879655,246186742,89307457,122612671,87009111,182656057,146899134,253466372,74988166,102757214,66706255,113".split(',');
var exp_d   = "16128693,257125582,198009612,139557212,137415092,28244646,262178813,164292477,91525038,156964779,247191904,267451101,228712303,53989207,261371544,246153944,150829682,249770095,25129227,261561015,81191918,43848397,16495765,53235668,162006057,193519501,106995674,95902518,126698399,218294843,33861852,240767243,89592116,130861474,79306072,77555856,3499".split(',');
var exp_p   = "226197815,195655162,238712700,84661672,79309410,250904587,203484457,240974443,224227230,126874073,179538153,39985901,31019509,61544693,181895321,140514284,265995133,48022167,232".split(',');
var exp_q   = "59391045,127440241,248887009,192654032,240088215,223902554,87919612,632607,82318265,127773417,126207976,43284671,118612664,11872646,165429592,27674223,243581030,191560393,249".split(',');
var pubkey  = "BADiejt3X/biElrPwczuou+GxI1eVbbb0mAS5Eek0h8SKGBO9cHC/tj3uWG/bF6A2+q0WLj+46mI9j60drz5osu3aerjZkiZiGFj9GhdnvYZ7ErT+wV8koxj/2Lrbq8iQyfNpj76VqTl7Rl09BaR/eSm6o6mQ1clqqiEV0FOcTi30wARAQAB";
var keyid   = "a99b311c7f20062a";
/* ------------------------------------------------------------------------- */


/* ------------------------------------------------------------------------- */
function encrypt() {
    var text = document.encrypt.rawtext.value;

    var startTime = new Date();
    var text_enc = OpenPGP_Encrypt(keyid, keytype, pubkey, text);
    var endTime = new Date();

    document.encrypt.rawtext.value = text_enc;
    document.getElementById("sendMailButton").href=
        "mailto:alex@willner.ws?subject=Encrypted:%20Test&body=" +
        encodeURIComponent(document.getElementById("text").value);
    document.getElementById("sendMailButton").removeAttribute('disabled');
    document.getElementById("sendMailButton").style.color = "#fff";

    document.encrypt.howLong.value =
        (endTime.getTime()-startTime.getTime())/1000.0 + " ms";
}
/* ------------------------------------------------------------------------- */


/* ------------------------------------------------------------------------- */
function decryptWithKey(key) {
    var text = document.decrypt.encryptedtext.value;
    document.getElementById("decryptButton").setAttribute('disabled');
    document.getElementById("decryptButton").style.color = "#333";
    document.decrypt.encryptedtext.value = "Please wait...";
    alert("This might take some time...");

    var startTime = new Date();
    if (undefined != key && key.length) {
        key = OpenPGP_GetSecretInformation(key);
        exp_u   = key['u'];
        exp_d   = key['d'];
        exp_p   = key['p'];
        exp_q   = key['q'];
    }
    var text_plain = OpenPGP_Decrypt(exp_p, exp_q, exp_d, exp_u, text);
    var endTime = new Date();

    document.decrypt.encryptedtext.value = text_plain;
    document.getElementById("decryptButton").removeAttribute('disabled');
    document.getElementById("decryptButton").style.color = "#fff";

    document.decrypt.howLongDecrypt.value =
        (endTime.getTime()-startTime.getTime())/1000.0 + " ms";
}

function decrypt() {
    dbGetFirstPrivateKey(decryptWithKey);
}
/* ------------------------------------------------------------------------- */
