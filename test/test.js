var util = require('util');
var se = require('../se');


exports.testEncryptDecrypt = function(test){
  
  var key = "sdiovjq387ghafivna";
  var text = "Hello World";
  
  var cipher = se.encrypt(key, text)
  var decipher = se.decrypt(key, cipher)
  
  test.equal(decipher, text, 'decipher: '+decipher +' text: '+text);
  test.done();
};


exports.testSearch = function(test){
  
  var key = "sdiovjq387ghafivna";
  var text = "Hello World";
  
  var cipher = se.encrypt(key, text)
  
  var e_keyword = se.encrypt_word(key, 'Hello')
  test.ok(se.search(cipher, e_keyword));
  
  var e_keyword = se.encrypt_word(key, 'World')
  test.ok(se.search(cipher, e_keyword));
  
  test.done();
};







