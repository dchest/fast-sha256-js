var sha256 = (typeof window !== 'undefined') ? window.sha256 : require('../' + (process.env.SHA256_SRC || 'sha256.js'));
var helpers = (typeof require !== 'undefined') ? require('./helpers') : window.helpers;
var log = helpers.log;
if (!sha256) throw new Error('sha256 is not loaded');

function benchmark(fn, MB) {
  var start = new Date();
  MB = MB || 1;
  for (var i = 0; i < MB*1024; i++) {
    fn();
  }
  var elapsed = (new Date()) - start;
  log.print(' ' + ((MB*1000)/elapsed).toFixed(3), 'MB/s');
  log.print(' ' + (((MB*1024)*1000)/elapsed).toFixed(3), 'ops/s');
}

function benchmarkOps(fn,  num) {
  var start = new Date();
  for (var i = 0; i < num; i++) {
    fn();
  }
  var elapsed = (new Date()) - start;
  log.print(' ' + ((num*1000)/elapsed).toFixed(3), 'ops/s');
}

function benchmarkSha256() {
  log.start('Benchmarking sha256');
  var m = new Uint8Array(1024);
  for (var i = 0; i < 1024; i++) m[i] = i & 255;
  benchmark(function(){
    sha256(m);
  });
}

benchmarkSha256();
