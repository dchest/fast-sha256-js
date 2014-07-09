var sha256 = (typeof window !== 'undefined') ? window.sha256 : require('../' + (process.env.SHA256_SRC || 'sha256.js'));
var helpers = (typeof require !== 'undefined') ? require('./helpers') : window.helpers;
var log = helpers.log;
if (!sha256) throw new Error('sha256 is not loaded');

function benchmark(fn, bytes) {
  var start = new Date();
  var num = 200;
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

function benchmarkSha256(bytes) {
  log.start('Benchmarking sha256 (' + bytes + ' bytes)');
  var m = new Uint8Array(bytes);
  for (var i = 0; i < m.length; i++) m[i] = i & 0xff;
  benchmark(function(){
    sha256(m);
  }, bytes);
}

benchmarkSha256(8192);
benchmarkSha256(1024);
