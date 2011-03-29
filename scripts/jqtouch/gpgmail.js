/**
 * jQTouch initialization for GPGMail_Mobile.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @version 2011-02-22
 * @see     http://gpgtools.org
 * @license BSD
 * @todo    Nothing.
 */

/* init jQTouch ------------------------------------------------------------ */
var jQT = new $.jQTouch({
    icon: 'images/gpgmail_icon.png',
    addGlossToIcon: true,
    startupScreen: 'images/gpgmail_startup.png',
    statusBar: 'black'
});
/* ------------------------------------------------------------------------- */


/* fix copy and paste in WebKit -------------------------------------------- */
function fixCopyPaste(el) {
    el.bind('paste', function(e) {
    var element = $(this).context;
    var text = $(this).val();
    var start = element.selectionStart;
    var pastedText = e.originalEvent.clipboardData.getData('text/plain');
    $(this).val(text.substring(0, element.selectionStart)
        + pastedText
        + text.substring(element.selectionEnd, text.length));
        element.selectionStart = start+pastedText.length;
        element.selectionEnd = element.selectionStart;
    });
}

$(function(){
    fixCopyPaste($('#rawtext'));
    fixCopyPaste($('#encryptedtext'));
    fixCopyPaste($('#key'));
});
/* ------------------------------------------------------------------------- */
