var sha256 = (typeof window !== 'undefined') ? window.sha256 : require('../' + (process.env.SHA256_SRC || 'sha256.js'));
var test = require('tape');

var hashVectors = require('./data/sha256.random');
var hmacVectors = require('./data/hmac.random');
var pbkdfVectors = require('./data/pbkdf.random');

function enc(x) { return (new Buffer(x)).toString('base64'); }
function dec(s) {
  var b = new Buffer(s, 'base64');
  var x = new Uint8Array(b.length);
  for (var i = 0; i < b.length; i++) x[i] = b[i];
  return x;
}
function hex(x) { return (new Buffer(x).toString('hex')); }

test('sha256 random test vectors', function(t) {
  hashVectors.forEach(function(vec) {
    var msg = dec(vec[0]);
    var goodHash = dec(vec[1]);
    var hash = sha256(msg);
    t.equal(hex(hash), hex(goodHash));
  });
  t.end();
});

test('sha256.Hash API test', function(t) {
    var vec = hashVectors[10];
    var h = new sha256.Hash();
    h.update(dec(vec[0]));
    var digest = h.digest();
    t.equal(hex(digest), hex(dec(vec[1])));
    t.equal(hex(h.digest()), hex(digest));
    t.throws(function() { h.update(dec(vec[0])); }, Error);
    h.reset();
    h.update(dec(vec[0]));
    t.equal(hex(h.digest()), hex(digest));
    h.clean();
    t.notEqual(hex(h.digest()), hex(digest));
    t.end();
});

test('sha256.hmac random test vectors', function(t) {
  hmacVectors.forEach(function(vec) {
    var msg = dec(vec[0]);
    var key = dec(vec[1]);
    var goodMac = dec(vec[2]);
    var mac = sha256.hmac(key, msg);
    t.equal(hex(mac), hex(goodMac));
  });
  t.end();
});

test('sha256.HMAC API test', function(t) {
    var vec = hmacVectors[10];
    var h = new sha256.HMAC(dec(vec[1]));
    h.update(dec(vec[0]));
    var digest = h.digest();
    t.equal(hex(digest), hex(dec(vec[2])));
    t.equal(hex(h.digest()), hex(digest));
    t.throws(function() { h.update(dec(vec[0])); }, Error);
    h.reset();
    h.update(dec(vec[0]));
    t.equal(hex(h.digest()), hex(digest));
    h.clean();
    t.notEqual(hex(h.digest()), hex(digest));
    t.end();
});

test('sha256.pbkdf2 random test vectors', function(t) {
  pbkdfVectors.forEach(function(vec, i) {
    var password = dec(vec[0]);
    var salt = dec(vec[1]);
    var goodDk = dec(vec[2]);
    var rounds = 128 - i + 2;
    var dkLen = goodDk.length;
    var dk = sha256.pbkdf2(password, salt, rounds, dkLen);
    t.equal(hex(dk), hex(goodDk));
  });
  t.end();
});

