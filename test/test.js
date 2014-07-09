var sha256 = (typeof window !== 'undefined') ? window.sha256 : require('../' + (process.env.SHA256_SRC || 'sha256.js'));
var test = require('tape');

var randomVectors = require('./data/sha256.random');

function enc(x) { return (new Buffer(x)).toString('base64'); }
function dec(s) {
  var b = new Buffer(s, 'base64');
  var x = new Uint8Array(b.length);
  for (var i = 0; i < b.length; i++) x[i] = b[i];
  return x;
}
function hex(x) { return (new Buffer(x).toString('hex')); }

test('sha256 random test vectors', function(t) {
  randomVectors.forEach(function(vec) {
    var msg = dec(vec[0]);
    var goodHash = dec(vec[1]);
    var hash = sha256(msg);
    t.equal(hex(hash), hex(goodHash));
  });
  t.end();
});
