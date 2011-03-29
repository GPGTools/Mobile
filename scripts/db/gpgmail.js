/**
 * Database implementation for GPGMail_Mobile.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @version 2011-02-22
 * @see     http://gpgtools.org
 * @license BSD
 */

/* database binding -------------------------------------------------------- */
$(function() {
                $('a[name="importKey"]').bind('click',function() {
                        if($('textarea[name="key"]').val() == "") {
                            alert("Currently only import via copy&paste is supported");
                            return;
                        }
                        if($('input[name="keyname"]').val() == "") {
                            alert("Please set a key name");
                            return;
                        }
                        dbSetPrivateKey($('input[name="keyname"]').val(),
                                        $('textarea[name="key"]').val());
                });
});
$(function() {
                $('a[name="deleteKey"]').bind('click',function() {
                        if($('select[name="secretkeys"]').val() == undefined) {
                            alert("Please select a key");
                            return;
                        }
                        dbRemovePrivateKey($('select[name="secretkeys"]').val());
                });
});
$(function() {
                $('input[name="defaultSign"]').bind('click',function() {
                        if($(this).is(':checked')) {
                            dbSetDefaultSign(1);
                        } else  {
                            dbSetDefaultSign(0);
                        }
                });
});
/* ------------------------------------------------------------------------- */


/* database initialization ------------------------------------------------- */
var db = null;

function sqlFail(tx, err) { alert("SQL failed: " + err.message); }
function sqlWin(response) { console.log("SQL succeeded."); }
function txFail(err) { alert("TX failed: " + err.message); }
function txWin(tx) { console.log("TX succeeded."); }

try {
    if (window.openDatabase) {
        db = openDatabase("GPGMail", "1.0", "GPGMail mobile", 200000);
        if (!db)
            alert("Failed to open the database on disk.  This is probably " +
                  "because the version was bad or there is not enough space" +
                  "left in this domain's quota");
    } else {
        alert("Couldn't open the database.");
    }
} catch(err) {
    db = null;
    alert("Couldn't open the database (exception): " + err);
}

if (db != null) {addEventListener('load', dbInitialize(), false);}

function dbInitialize() {
    db.transaction(function(tx) {
        tx.executeSql("SELECT COUNT(*) FROM Options", [],
            function(result) {/**/;},
            function(tx, error) {
                tx.executeSql("CREATE TABLE Options (" +
                              " id REAL UNIQUE, " +
                              " defaultSign TEXT, " +
                              " defaultVerify TEXT)",
                              [],
                              sqlWin,
                              sqlFail
                             );
        });
    }, txFail, txWin);
    db.transaction(function(tx) {
        tx.executeSql("SELECT COUNT(*) FROM PrivateKeys", [],
            function(result) {/**/;},
            function(tx, error) {
                tx.executeSql("CREATE TABLE PrivateKeys " +
                              " (id REAL UNIQUE, key TEXT)",
                              [],
                              sqlWin,
                              sqlFail
                             );
            });
    }, txFail, txWin);
    dbShowPrivateKeys();
}
/* ------------------------------------------------------------------------- */


/* ------------------------------------------------------------------------- */
function dbSetPrivateKey(id, key) {
    db.transaction(function (tx) {
        tx.executeSql("REPLACE INTO PrivateKeys (id, key) " +
                      " VALUES (?, ?)",
                      [id, key],
                      function(tx, result) {dbShowPrivateKeys(); sqlWin();},
                      sqlFail
                     );
    }, txFail, txWin);
}
function dbRemovePrivateKey(id) {
    db.transaction(function (tx) {
        tx.executeSql("DELETE FROM PrivateKeys WHERE id = ?",
                      [id],
                      function(tx, result) {dbShowPrivateKeys(); sqlWin();},
                      sqlFail
                     );
    }, txFail, txWin);
}
function dbGetFirstPrivateKey(callback) {
    key = "";
    db.transaction(function (tx) {
        tx.executeSql("SELECT * FROM PrivateKeys LIMIT 1",
                      [],
                      function(tx, result) {
                          if (result.rows.length > 0) {
                              key = result.rows.item(0)['key'];
                          }
                      },
                      sqlFail);
    }, txFail, txWin);
    callback(key);
}
function dbShowPrivateKeys() {
    db.transaction(function (tx) {
        tx.executeSql("SELECT * FROM PrivateKeys",
                      [],
                      function(tx, result) {
                          $('#secretkeys').children().remove();
                          for(var i = 0; i < result.rows.length; i++) {
                              id = result.rows.item(i)['id'];
                              key = result.rows.item(i)['key'];
                              $('#secretkeys').append('<option value="'+id+'">'+id+'</option>');
                          }
                      },
                      sqlFail);
    }, txFail, txWin);
}
/* ------------------------------------------------------------------------- */


/* ------------------------------------------------------------------------- */
function dbIsDefaultSign() {
    db.transaction(function (tx) {
        tx.executeSql("SELECT defaultSign FROM Options WHERE id = 1", [],
                      sqlWin, sqlFail);
    }, txFail, txWin);
}

function dbSetDefaultSign(isSet) {
    db.transaction(function (tx) {
        tx.executeSql("UPDATE Options SET defaultSign = ? WHERE id = 1",
                      [isSet], sqlWin, sqlFail);
    }, txFail, txWin);
}
/* ------------------------------------------------------------------------- */
