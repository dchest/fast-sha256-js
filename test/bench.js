var sha256 = (typeof window !== 'undefined') ? window.sha256 : require('../' + (process.env.SHA256_SRC || 'sha256.js'));
var helpers = (typeof require !== 'undefined') ? require('./helpers') : window.helpers;
var log = helpers.log;
if (!sha256) throw new Error('sha256 is not loaded');

function benchmark(fn, bytes) {
  var start = new Date();
  var num = 5000;
  for (var i = 0; i < num; i++) fn();
  var elapsed = (new Date()) - start;
  log.print(' ' + ((bytes*num/1024/1024*1000)/elapsed).toFixed(3), 'MB/s');
  log.print(' ' + ((num*1000)/elapsed).toFixed(3), 'ops/s');
}

function benchmarkOps(fn,  num) {
  var start = new Date();
  for (var i = 0; i < num; i++) fn();
  var elapsed = (new Date()) - start;
  log.print(' ' + ((num*1000)/elapsed).toFixed(3), 'ops/s');
}

function benchmarkTime(fn) {
  var start = new Date();
  fn();
  var elapsed = (new Date()) - start;
  log.print(' ' + elapsed.toFixed(0), 'ms');
}

function benchmarkHash(bytes) {
  log.start('Benchmarking sha256 (' + bytes + ' bytes)');
  var m = new Uint8Array(bytes);
  for (var i = 0; i < m.length; i++) m[i] = i & 0xff;
  benchmark(function(){
    sha256(m);
  }, bytes);
}

function benchmarkHMAC(bytes) {
  log.start('Benchmarking sha256.hmac (' + bytes + ' bytes)');
  var k = new Uint8Array(32), m = new Uint8Array(bytes);
  for (var i = 0; i < k.length; i++) k[i] = i & 0xff;
  for (i = 0; i < m.length; i++) m[i] = (i+32) & 0xff;
  benchmark(function(){
    sha256.hmac(k, m);
  }, bytes);
}

function benchmarkPBKDF2(rounds) {
  log.start('Benchmarking sha256.pbkdf2 (' + rounds + ' rounds)');
  var i, p = new Uint8Array(32), s = new Uint8Array(32);
  for (i = 0; i < p.length; i++) p[i] = i & 0xff;
  for (i = 0; i < s.length; i++) s[i] = (i+32) & 0xff;
  benchmarkTime(function(){
    sha256.pbkdf2(p, s, rounds, 32);
  });
}

benchmarkHash(8192);
benchmarkHash(1024);
benchmarkHMAC(1024);
benchmarkHMAC(64);
benchmarkPBKDF2(5000);
benchmarkPBKDF2(10000);
