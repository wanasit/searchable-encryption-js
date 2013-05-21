#!/usr/local/bin/node

var sjcl = require('./sjcl.js');


/**
* XOR - 32*4 BitArray
* @param { BitArray } a - 32*4 bits
* @param { BitArray } b - 32*4 bits 
* @return BitArray - a xor b
*/
function xor(a, b){
  return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
}

function make128BitWord(word){
  while(word.length < 4) word = word.concat([0]);
  if(word.length > 4) word = word.slice(0, 4);
  return word;
}

function G_random_generator(key){
  
  var cipher = new sjcl.cipher.aes(key);
  var seed = make128BitWord(key)
  function next(){
    seed = cipher.encrypt(seed)
    return seed;
  }
  
  return {next:next}
}

function F_random_function(s, i){
  s = make128BitWord(s)
  i = make128BitWord(i)
  var cipher = new sjcl.cipher.aes(s);
  return cipher.encrypt(i)
}

function E_deterministic_encrypt(key, word){
  word = make128BitWord(word);
  var cipher = new sjcl.cipher.aes(key);
  return cipher.encrypt(word);
}

function D_deterministic_decrypt(key, word){
  word = make128BitWord(word);
  var cipher = new sjcl.cipher.aes(key);
  return cipher.decrypt(word);
}

module.exports.encrypt = function encrypt(key, doc){
  
  if(typeof key === 'string'){
    key = sjcl.codec.utf8String.toBits(key);
    key = make128BitWord(key)
  }
  
  var plain_words = doc.split(' ')
  var encrypted_words = [];
  var cipher = new sjcl.cipher.aes(key);
  var G = G_random_generator(key)
  
  plain_words.forEach(function(word, index){
    //Convert to binary
    word = sjcl.codec.utf8String.toBits(word);
    var e_word = E_deterministic_encrypt(key, word);
    var s  = G.next().slice(0, 2);
    var fs = F_random_function(e_word.slice(0,2), s).slice(0, 2);
    var t = s.concat(fs)
    
    var c_word = xor(e_word, t);
    
    c_word = sjcl.codec.hex.fromBits(c_word);
    encrypted_words.push(c_word)
  })
  
  return encrypted_words.join('')
}

module.exports.decrypt = function decrypt (key, e_doc) {
  
  if(typeof key === 'string'){
    key = sjcl.codec.utf8String.toBits(key);
    key = make128BitWord(key)
  }
  
  var words = [];
  var G = G_random_generator(key)
  
  for(var i=0; i < e_doc.length; i+=32){
    
    //Hex encode of 4*32 bits word 
    var c_word = e_doc.substring(i, i+32);
    c_word = sjcl.codec.hex.toBits(c_word);
    
    var s = G.next().slice(0, 2);
    var e_word_half = xor( c_word.concat([0,0]), s.concat([0,0])).slice(0, 2)
    var fs = F_random_function(e_word_half, s).slice(0, 2);
    var t = s.concat(fs)
    
    var e_word = xor(c_word, t);
      
    var word = D_deterministic_decrypt(key, e_word);
    word = sjcl.codec.utf8String.fromBits(word);

    var index = word.indexOf('\u0000')
    if(index > 0) word = word.slice(0, index)
    
    words.push(word)
  }
  
  return words.join(' ') 
}

module.exports.search = function seach(e_doc, e_word){
  
  if(typeof e_word === 'string'){
    e_word = sjcl.codec.hex.toBits(e_word);
  }
  
  for(var i=0; i < e_doc.length; i+=32){
    
    //Hex encode of 4*32 bits word 
    var c_word = e_doc.substring(i, i+32);
    c_word = sjcl.codec.hex.toBits(c_word);
    
    var t = xor(c_word, e_word);
    
    var s = t.slice(0, 2);
    var fs = t.slice(2, 4);
    
    var expect_fs = F_random_function(e_word.slice(0,2), s).slice(0, 2);
    if(expect_fs[0] == fs[0] && expect_fs[1] == fs[1]) return true
  }
  
  return false
}

module.exports.encrypt_word = function(key, word) {
  
  if(typeof key === 'string'){
    key = sjcl.codec.utf8String.toBits(key);
    key = make128BitWord(key)
  }
  
  if(typeof word === 'string'){
    word = sjcl.codec.utf8String.toBits(word);
  }
  
  var e_word = E_deterministic_encrypt(key, word);
  return sjcl.codec.hex.fromBits(e_word);
}