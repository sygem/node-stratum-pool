var events = require('events');
var crypto = require('crypto');

var bignum = require('bignum');
var vh = require('verushash');

var util = require('./util.js');
var blockTemplate = require('./blockTemplate.js');
var veilBlockTemplate = require('./veilBlockTemplate.js');
var zBlockTemplate = require('./zBlockTemplate.js');
var kawpowBlockTemplate = require('./kawpowBlockTemplate.js');

var EH_PARAMS_MAP = {
    "125_4": {
        SOLUTION_LENGTH: 106,
        SOLUTION_SLICE: 2,
    },
    "144_5": {
        SOLUTION_LENGTH: 202,
        SOLUTION_SLICE: 2,
    },
    "192_7": {
        SOLUTION_LENGTH: 806,
        SOLUTION_SLICE: 6,
    },
    "200_9": {
        SOLUTION_LENGTH: 2694,
        SOLUTION_SLICE: 6,
    }
};

//Unique extranonce per subscriber
var ExtraNonceCounter = function(options){

    var instanceId = options.instanceId || crypto.randomBytes(4).readUInt32LE(0);
    var counter = instanceId << 27;

    this.next = function(){
        if (options.coin.isKawPow) {
            return (crypto.randomBytes(3).toString('hex'));
        }
        var extraNonce = util.packUInt32BE(Math.abs(counter++));
        return extraNonce.toString('hex');
    };

    this.size = 4; //bytes
};

//Unique job per new block template
var JobCounter = function(options){
    var maxCounter = (options.coin.isZCashProtocol || options.coin.isKawPow) ? 0xffffffffff : 0xffff;
    var counter = (options.coin.isZCashProtocol || options.coin.isKawPow) ? 0x0000cccc : 0;

    this.next = function(){
        counter++;
        if (counter % maxCounter === 0)
            counter = 1;
        return this.cur();
    };

    this.cur = function () {
        if (options.coin.isKawPow) {
            var counter_buf = new Buffer(32);
            counter_buf.writeUIntBE('000000000000000000000000', 0, 24);
            counter_buf.writeUIntBE(counter, 24, 8);
            return counter_buf.toString('hex');
        } else {
            return counter.toString(16);
        }
    };
};

function isHexString(s) {
    var check = String(s).toLowerCase();
    if(check.length % 2) {
        return false;
    }
    for (i = 0; i < check.length; i=i+2) {
        var c = check[i] + check[i+1];
        if (!isHex(c))
            return false;
    }
    return true;
}

function isHex(c) {
    var a = parseInt(c,16);
    var b = a.toString(16).toLowerCase();
    if(b.length % 2) {
        b = '0' + b;
    }
    if (b !== c) {
        return false;
    }
    return true;
}

/**
 * Emits:
 * - newBlock(blockTemplate) - When a new block (previously unknown to the JobManager) is added, use this event to broadcast new jobs
 * - share(shareData, blockHex) - When a worker submits a share. It will have blockHex if a block was found
**/
var JobManager = module.exports = function JobManager(options){


    //private members

    var _this = this;
    var jobCounter = new JobCounter(options);

    var shareMultiplier = algos[options.coin.algorithm].multiplier;
    
    //public members

    this.extraNonceCounter = new ExtraNonceCounter(options);
    if (!options.coin.isZCashProtocol) {
        this.extraNoncePlaceholder = Buffer.from('f000000ff111111f', 'hex');
        this.extraNonce2Size = this.extraNoncePlaceholder.length - this.extraNonceCounter.size;
    }

    this.currentJob;
    this.validJobs = {};

    var hashDigest = algos[options.coin.algorithm].hash(options.coin);

    var coinbaseHasher = (function(){
        switch(options.coin.algorithm){
            case 'keccak':
            case 'fugue':
            case 'groestl':
                if (options.coin.normalHashing === true)
                    return util.sha256d;
                else
                    return util.sha256;
            default:
                return util.sha256d;
        }
    })();


    var blockHasher = (function () {
        if (!options.coin.isZCashProtocol) {
            switch (options.coin.algorithm) {
                case 'scrypt':
                    if (options.coin.reward === 'POS') {
                        return function (d) {
                            return util.reverseBuffer(hashDigest.apply(this, arguments));
                        };
                    }
                case 'scrypt-jane':
                    if (options.coin.reward === 'POS') {
                        return function (d) {
                            return util.reverseBuffer(hashDigest.apply(this, arguments));
                        };
                    }
                case 'scrypt-n':
                case 'ghostrider':
                case 'sha1':
                    return function (d) {
                        return util.reverseBuffer(util.sha256d(d));
                    };
                case 'kawpow':
                    return function (d) {
                        return util.reverseBuffer(util.sha256(d));
                    };
                default:
                    return function () {
                        return util.reverseBuffer(hashDigest.apply(this, arguments));
                    };
            }
        } else {
            return function (d) {
                return util.reverseBuffer(util.sha256d(d));
            };
        }
    })();

    if (options.coin.isZCashProtocol) {
        this.updateCurrentJob = function(rpcData) {
            var tmpBlockTemplate = new zBlockTemplate(
                jobCounter.next(),
                rpcData,
                _this.extraNoncePlaceholder,
                options.recipients,
                options.address,
                options.coin.coinbase,
                options.coin
            );
    
            _this.currentJob = tmpBlockTemplate;
            _this.emit('updatedBlock', tmpBlockTemplate, true);
            _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;
        }
    } else if (options.coin.isKawPow) {
        this.updateCurrentJob = function (rpcData) {
            var tmpBlockTemplate = new kawpowBlockTemplate(
                jobCounter.next(),
                rpcData,
                options.coin.reward,
                options.recipients,
                options.address
            );
        
            _this.currentJob = tmpBlockTemplate;
            _this.emit('updatedBlock', tmpBlockTemplate, true);
            _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;
          };
    } else if (options.coin.isVeil) {
        this.updateCurrentJob = function (rpcData) {
            var tmpBlockTemplate = new veilBlockTemplate(
                jobCounter.next(),
                rpcData,
                options.poolAddressScript,
                _this.extraNoncePlaceholder,
                options.coin.reward,
                options.coin.txMessages,
                options.recipients
            );
        
            _this.currentJob = tmpBlockTemplate;
            _this.emit('updatedBlock', tmpBlockTemplate, true);
            _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;
          };
    } else {
        this.updateCurrentJob = function(rpcData){
            var tmpBlockTemplate = new blockTemplate(
                jobCounter.next(),
                rpcData,
                options.poolAddressScript,
                _this.extraNoncePlaceholder,
                options.coin.reward,
                options.coin.txMessages,
                options.recipients
            );

            _this.currentJob = tmpBlockTemplate;
            _this.emit('updatedBlock', tmpBlockTemplate, true);
            _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;
        }
    }

    //returns true if processed a new block
    if (options.coin.isZCashProtocol) {
        this.processTemplate = function (rpcData) {
            /* Block is new if A) its the first block we have seen so far or B) the blockhash is different and the
             block height is greater than the one we have */
            var isNewBlock = typeof(_this.currentJob) === 'undefined';
            if (!isNewBlock && _this.currentJob.rpcData.previousblockhash !== rpcData.previousblockhash) {
                isNewBlock = true;
    
                //If new block is outdated/out-of-sync than return
                if (rpcData.height < _this.currentJob.rpcData.height)
                    return false;
            }
    
            if (!isNewBlock) return false;
    
            var tmpBlockTemplate = new zBlockTemplate(
                jobCounter.next(),
                rpcData,
                _this.extraNoncePlaceholder,
                options.recipients,
                options.address,
                options.coin.coinbase,
                options.coin
            );
    
            this.currentJob = tmpBlockTemplate;
    
            this.validJobs = {};
            _this.emit('newBlock', tmpBlockTemplate);
    
            this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;
    
            return true;
        };
    } else if (options.coin.isKawPow) {
        this.processTemplate = function (rpcData) {

            /* Block is new if A) its the first block we have seen so far or B) the blockhash is different and the
             block height is greater than the one we have */
            var isNewBlock = typeof(_this.currentJob) === 'undefined';
            if (!isNewBlock && _this.currentJob.rpcData.previousblockhash !== rpcData.previousblockhash) {
                isNewBlock = true;
        
                //If new block is outdated/out-of-sync than return
                if (rpcData.height < _this.currentJob.rpcData.height) return false;
            }
        
            if (!isNewBlock) return false;
        
        
            var tmpBlockTemplate = new kawpowBlockTemplate(
              jobCounter.next(),
              rpcData,
              options.coin.reward,
              options.recipients,
              options.address
            );
        
            this.currentJob = tmpBlockTemplate;
        
            this.validJobs = {};
            _this.emit('newBlock', tmpBlockTemplate);
        
            this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;
        
            return true;
        
        };
    } else {
        this.processTemplate = function(rpcData){

            /* Block is new if A) its the first block we have seen so far or B) the blockhash is different and the
               block height is greater than the one we have */
            var isNewBlock = typeof(_this.currentJob) === 'undefined';
            if  (!isNewBlock && _this.currentJob.rpcData.previousblockhash !== rpcData.previousblockhash){
                isNewBlock = true;
    
                //If new block is outdated/out-of-sync than return
                if (rpcData.height < _this.currentJob.rpcData.height)
                    return false;
            }
    
            if (!isNewBlock) return false;
    
    
            var tmpBlockTemplate = new blockTemplate(
                jobCounter.next(),
                rpcData,
                options.poolAddressScript,
                _this.extraNoncePlaceholder,
                options.coin.reward,
                options.coin.txMessages,
                options.recipients
            );
    
            this.currentJob = tmpBlockTemplate;
    
            this.validJobs = {};
            _this.emit('newBlock', tmpBlockTemplate);
    
            this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;
    
            return true;
    
        };
    }
    

    // PROCESS SHARE
    if (options.coin.isZCashProtocol) {
        this.processShare = function (jobId, previousDifficulty, difficulty, extraNonce1, extraNonce2, nTime, nonce, ipAddress, port, workerName, soln, isSoloMining) {
            var shareError = function (error) {
                _this.emit('share', {
                    job: jobId,
                    ip: ipAddress,
                    worker: workerName,
                    difficulty: difficulty,
                    isSoloMining: isSoloMining,
                    error: error[1]
                });
                return {error: error, result: null};
            };
    
            var submitTime = Date.now() / 1000 | 0;
    
            var job = this.validJobs[jobId];
    
            if (typeof job === 'undefined' || job.jobId != jobId) {
                return shareError([21, 'job not found']);
            }
    
            if (nTime.length !== 8) {
                return shareError([20, 'incorrect size of ntime']);
            }
    
            let nTimeInt = parseInt(nTime.substr(6, 2) + nTime.substr(4, 2) + nTime.substr(2, 2) + nTime.substr(0, 2), 16)
    
            if (Number.isNaN(nTimeInt)) {
                return shareError([20, 'invalid ntime'])
            }
    
            if (nTimeInt < job.rpcData.curtime || nTimeInt > submitTime + 7200) {
                return shareError([20, 'ntime out of range'])
            }
    
            if (nonce.length !== 64) {
                return shareError([20, 'incorrect size of nonce']);
            }
    
            /**
             * TODO: This is currently accounting only for equihash. make it smarter.
             */
            let parameters = options.coin.parameters
            if (!parameters) {
                parameters = {
                    N: 200,
                    K: 9,
                    personalization: 'ZcashPoW'
                }
            }
    
            let N = parameters.N || 200
            let K = parameters.K || 9
            let expectedLength = EH_PARAMS_MAP[N + '_' + K].SOLUTION_LENGTH || 2694
            let solutionSlice = EH_PARAMS_MAP[N + '_' + K].SOLUTION_SLICE || 0
    
            if (soln.length !== expectedLength) {
                return shareError([20, 'Error: Incorrect size of solution (' + soln.length + '), expected ' + expectedLength]);
            }
    
            if (!isHexString(extraNonce2)) {
                return shareError([20, 'invalid hex in extraNonce2']);
            }
    
            if (!job.registerSubmit(nonce, soln)) {
                return shareError([22, 'duplicate share']);
            }
    
            //var extraNonce1Buffer = Buffer.from(extraNonce1, 'hex');
            //var extraNonce2Buffer = Buffer.from(extraNonce2, 'hex');
    
            var headerBuffer = job.serializeHeader(nTime, nonce); // 144 bytes (doesn't contain soln)
            var headerSolnBuffer = Buffer.concat([headerBuffer, Buffer.from(soln, 'hex')]);
            var headerHash;
    
            switch (options.coin.algorithm) {
                case 'verushash':
                    headerHash = vh.hash(headerSolnBuffer);
                    break;
                default:
                    headerHash = util.sha256d(headerSolnBuffer);
                    break;
            };
    
            var headerBigNum = bignum.fromBuffer(headerHash, {endian: 'little', size: 32});
    
            var blockHashInvalid;
            var blockHash;
            var blockHex;
    
            var shareDiff = evdiff1 / headerBigNum.toNumber() * shareMultiplier;
            var blockDiffAdjusted = job.difficulty * shareMultiplier;
    
            // check if valid solution
            if (hashDigest(headerBuffer, Buffer.from(soln.slice(solutionSlice), 'hex')) !== true) {
                return shareError([20, 'invalid solution']);
            }
    
            //check if block candidate
            if (headerBigNum.le(job.target)) {
                blockHex = job.serializeBlock(headerBuffer, Buffer.from(soln, 'hex')).toString('hex');
                blockHash = util.reverseBuffer(headerHash).toString('hex');
            } else {
                if (options.emitInvalidBlockHashes)
                    blockHashInvalid = util.reverseBuffer(util.sha256d(headerSolnBuffer)).toString('hex');
    
                //Check if share didn't reached the miner's difficulty)
                if (shareDiff / difficulty < 0.99) {
                    //Check if share matched a previous difficulty from before a vardiff retarget
                    if (previousDifficulty && shareDiff >= previousDifficulty) {
                        difficulty = previousDifficulty;
                    } else {
                        return shareError([23, 'low difficulty share of ' + shareDiff]);
                    }
    
                }
            }
    
            _this.emit('share', {
                job: jobId,
                ip: ipAddress,
                port: port,
                worker: workerName,
                height: job.rpcData.height,
                blockReward: job.rpcData.reward,
                difficulty: difficulty,
                shareDiff: shareDiff.toFixed(8),
                blockDiff: blockDiffAdjusted,
                blockDiffActual: job.difficulty,
                blockHash: blockHash,
                blockHashInvalid: blockHashInvalid,
                isSoloMining: isSoloMining
            }, blockHex);
    
            return {result: true, error: null, blockHash: blockHash};
        };
    } else if (options.coin.isKawPow) {
        this.processShare = function (miner_given_jobId, previousDifficulty, difficulty, miner_given_nonce, ipAddress, port, workerName, miner_given_header, miner_given_mixhash, callback_parent) {

            var submitTime = Date.now() / 1000 | 0;
        
            var shareError = function (error) {
              _this.emit('share', {
                  job: miner_given_jobId,
                  ip: ipAddress,
                  worker: workerName,
                  difficulty: difficulty,
                  error: error[1]
              });
              callback_parent( {error: error, result: null});
              return;
            };
        
            var job = this.validJobs[miner_given_jobId];
            console.log("JOB: "+JSON.stringify(job));
        
            if (typeof job === 'undefined' || job.jobId != miner_given_jobId)
              return shareError([20, 'job not found']);
        
            //calculate our own header hash, do not trust miner-given value
            var headerBuffer = job.serializeHeader(); // 140 bytes, doesn't contain nonce or mixhash/solution
            var header_hash = util.reverseBuffer(util.sha256d(headerBuffer)).toString('hex');
        
            if (job.curTime < (submitTime - 600))
              return shareError([20, 'job is too old']);
        
            if (!isHexString(miner_given_header))
              return shareError([20, 'invalid header hash, must be hex']);
                
            if (header_hash != miner_given_header)
              return shareError([20, 'invalid header hash']);
            
            if (!isHexString(miner_given_nonce))
              return shareError([20, 'invalid nonce, must be hex']);
            
            if (!isHexString(miner_given_mixhash))
              return shareError([20, 'invalid mixhash, must be hex']);
            
            if (miner_given_nonce.length !== 16)
              return shareError([20, 'incorrect size of nonce, must be 8 bytes']);
            
            if (miner_given_mixhash.length !== 64)
              return shareError([20, 'incorrect size of mixhash, must be 32 bytes']);
        
            if (!job.registerSubmit(header_hash.toLowerCase(), miner_given_nonce.toLowerCase()))
              return shareError([22, 'duplicate share']);
        
            var powLimit = algos.kawpow.diff; // TODO: Get algos object from argument
            var adjPow = powLimit / difficulty;
            if ((64 - adjPow.toString(16).length) === 0) {
                var zeroPad = '';
            }
            else {
                var zeroPad = '0';
                zeroPad = zeroPad.repeat((64 - (adjPow.toString(16).length)));
            }
            var target_share_hex = (zeroPad + adjPow.toString(16)).substr(0,64);
            
            var blockHashInvalid;
            var blockHash;
            var blockHex;
        
            console.log("Using "+options.kawpow_validator+" for validation.");
        
            if (options.kawpow_validator == "kawpowd") {
        
              async.series([
                function(callback) {
                  var kawpowd_url = 'http://'+options.kawpow_wrapper_host+":"+options.kawpow_wrapper_port+'/'+'?header_hash='+header_hash+'&mix_hash='+miner_given_mixhash+'&nonce='+miner_given_nonce+'&height='+job.rpcData.height+'&share_boundary='+target_share_hex+'&block_boundary='+job.target_hex;
          
                  http.get(kawpowd_url, function (res) {
                  res.setEncoding("utf8");
                  let body = "";
                  res.on("data", data => {
                    body += data;
                  });
                  res.on("end", () => {
                    body = JSON.parse(body);
                    // console.log("JSON RESULT FROM KAWPOWD: "+JSON.stringify(body));
                    console.log("********** INCOMING SHARE FROM WORKER ************");
                    console.log("header_hash            = " + header_hash);
                    console.log("miner_sent_header_hash = " + miner_given_header);
                    console.log("miner_sent_mixhash     = " + miner_given_mixhash);
                    console.log("miner_sent_nonce       = " + miner_given_nonce);
                    console.log("height                 = " + job.rpcData.height);
                    console.log("job.difficulty         = " + job.difficulty);
                    console.log("BLOCK.target           = " + job.target_hex);
                    console.log('SHARE.target           = ' + target_share_hex);
                    console.log('digest                 = ' + body.digest);
                    console.log("miner_sent_jobid       = " + miner_given_jobId);
                    console.log('job                    = ' + miner_given_jobId);
                    console.log('worker                 = ' + workerName);
                    console.log('height                 = ' + job.rpcData.height);
                    console.log('difficulty             = ' + difficulty);
                    console.log('kawpowd_url            = ' + kawpowd_url);
                    console.log("********** END INCOMING SHARE FROM WORKER ************");
                    if (body.share == false) {
                      if (body.block == false) {
                        // It didn't meet either requirement.
                        callback('kawpow share didn\'t meet job or block difficulty level', false);
                        return shareError([20, 'kawpow validation failed']);
                      }
                    }
          
                    // At this point, either share or block is true (or both)
          
                    if (body.block == true) {
                      // Good block.
                      blockHex = job.serializeBlock(new Buffer(header_hash, 'hex'), new Buffer(miner_given_nonce, 'hex'), new Buffer(miner_given_mixhash, 'hex')).toString('hex');
                      blockHash = body.digest;
                    }
                    callback(null, true);
                    return;
                  });
                });
              },
              function(callback) {
          
                  var blockDiffAdjusted = job.difficulty * shareMultiplier
                  var shareDiffFixed = undefined;
          
                  if (blockHash !== undefined) {
                      var headerBigNum = bignum.fromBuffer(blockHash, {endian: 'little', size: 32});
                      var shareDiff = diff1 / headerBigNum.toNumber() * shareMultiplier;
                      shareDiffFixed = shareDiff.toFixed(8);
                  }
                  _this.emit('share', {
                    job: miner_given_jobId,
                    ip: ipAddress,
                    port: port,
                    worker: workerName,
                    height: job.rpcData.height,
                    blockReward: job.rpcData.coinbasevalue,
                    difficulty: difficulty,
                    shareDiff: shareDiffFixed,
                    blockDiff: blockDiffAdjusted,
                    blockDiffActual: job.difficulty,
                    blockHash: blockHash,
                    blockHashInvalid: blockHashInvalid
                  }, blockHex);
          
                  callback_parent({result: true, error: null, blockHash: blockHash});
                  callback(null, true);
                  return;
              }
              ], function(err, results) {
                if (err != null) {
                  emitErrorLog("kawpow verify failed, ERRORS: "+err);
                  return;
                }
              });
        
        
            } else {
        
              _this.daemon.cmd('getkawpowhash', [ header_hash, miner_given_mixhash, miner_given_nonce, job.rpcData.height, job.target_hex ], function (results) {
        
                var digest = results[0].response.digest;
                var result = results[0].response.result;
                var mix_hash = results[0].response.mix_hash;
                var meets_target = results[0].response.meets_target;
        
                if (result == 'true') {
                  // console.log("SHARE IS VALID");
                  let headerBigNum = BigInt(result, 32);
                  if (job.target.ge(headerBigNum)) {
                    // console.log("BLOCK CANDIDATE");
                    var blockHex = job.serializeBlock(new Buffer(header_hash, 'hex'), new Buffer(miner_given_nonce, 'hex'), new Buffer(mix_hash, 'hex')).toString('hex');
                    var blockHash = digest;
                  }
                  var blockDiffAdjusted = job.difficulty * shareMultiplier
                  var shareDiffFixed = undefined;
        
                  if (blockHash !== undefined) {
                      var shareDiff = diff1 / headerBigNum * shareMultiplier;
                      shareDiffFixed = shareDiff.toFixed(8);
                  }
        
                  _this.emit('share', {
                      job: miner_given_jobId,
                      ip: ipAddress,
                      port: port,
                      worker: workerName,
                      height: job.rpcData.height,
                      blockReward: job.rpcData.coinbasevalue,
                      difficulty: difficulty,
                      shareDiff: shareDiffFixed,
                      blockDiff: blockDiffAdjusted,
                      blockDiffActual: job.difficulty,
                      blockHash: blockHash,
                      blockHashInvalid: blockHashInvalid
                  }, blockHex);
        
                  // return {result: true, error: null, blockHash: blockHash};
                  // callback_parent( {error: error, result: null});
                  callback_parent({result: true, error: null, blockHash: blockHash});
        
                } else {
                  // console.log("SHARE FAILED");
                  return shareError([20, 'bad share: invalid hash']);
                }
        
        
              });
            }
        };
    } else {
        this.processShare = function(jobId, previousDifficulty, difficulty, extraNonce1, extraNonce2, nTime, nonce, ipAddress, port, workerName, versionMask, isSoloMining){
            var shareError = function(error){
                _this.emit('share', {
                    job: jobId,
                    ip: ipAddress,
                    worker: workerName,
                    difficulty: difficulty,
                    isSoloMining: isSoloMining,
                    error: error[1]
                });
                return {error: error, result: null};
            };
    
            var submitTime = Date.now() / 1000 | 0;
    
            if (extraNonce2.length / 2 !== _this.extraNonce2Size)
                return shareError([20, 'incorrect size of extranonce2']);
    
            var job = this.validJobs[jobId];
    
            if (typeof job === 'undefined' || job.jobId != jobId ) {
                return shareError([21, 'job not found']);
            }
    
            if (nTime.length !== 8) {
                return shareError([20, 'incorrect size of ntime']);
            }
    
            var nTimeInt = parseInt(nTime, 16);
            if (nTimeInt < job.rpcData.curtime || nTimeInt > submitTime + 7200) {
                return shareError([20, 'ntime out of range']);
            }
    
            if (nonce.length !== 8) {
                return shareError([20, 'incorrect size of nonce']);
            }
    
            if (!job.registerSubmit(extraNonce1, extraNonce2, nTime, nonce)) {
                return shareError([22, 'duplicate share']);
            }
    
    
            var extraNonce1Buffer = new Buffer(extraNonce1, 'hex');
            var extraNonce2Buffer = new Buffer(extraNonce2, 'hex');
    
            var coinbaseBuffer = job.serializeCoinbase(extraNonce1Buffer, extraNonce2Buffer);
            var coinbaseHash = coinbaseHasher(coinbaseBuffer);
    
            var merkleRoot = util.reverseBuffer(job.merkleTree.withFirst(coinbaseHash)).toString('hex');
    
            var headerBuffer = job.serializeHeader(merkleRoot, nTime, nonce);
            var headerHash = hashDigest(headerBuffer, nTimeInt);
            var headerBigNum = bignum.fromBuffer(headerHash, {endian: 'little', size: 32});
    
            var blockHashInvalid;
            var blockHash;
            var blockHex;
    
            var shareDiff = diff1 / headerBigNum.toNumber() * shareMultiplier;
    
            var blockDiffAdjusted = job.difficulty * shareMultiplier;
    
            //Check if share is a block candidate (matched network difficulty)
            if (job.target.ge(headerBigNum)){
                blockHex = job.serializeBlock(headerBuffer, coinbaseBuffer).toString('hex');
                if (options.coin.algorithm === 'blake' 
                || options.coin.algorithm === 'blake2s'
                || options.coin.algorithm === 'neoscrypt'
                || options.coin.algorithm === 'lyra2'
                || options.coin.algorithm === 'lyra2re2'
                || options.coin.algorithm === 'allium'
                || options.coin.algorithm === 'lyra2v2'
                || options.coin.algorithm === 'lyra2v3'
                || options.coin.algorithm === 'qubit'
                || options.coin.algorithm === 'skein'
                || options.coin.algorithm === 'x11'
                || options.coin.algorithm === 'x16r'
                || options.coin.algorithm === 'x17'
                || options.coin.algorithm === 'odo'
                || options.coin.algorithm === 'groestl'
                || options.coin.algorithm === 'groestlmyriad'
                ) {                
                    blockHash = util.reverseBuffer(util.sha256d(headerBuffer, nTime)).toString('hex');
                }
                else {
                    blockHash = blockHasher(headerBuffer, nTime).toString('hex');
                }
            }
            else {
                if (options.emitInvalidBlockHashes)
                    blockHashInvalid = util.reverseBuffer(util.sha256d(headerBuffer)).toString('hex');
    
                //Check if share didn't reached the miner's difficulty)
                if (shareDiff / difficulty < 0.99){
    
                    //Check if share matched a previous difficulty from before a vardiff retarget
                    if (previousDifficulty && shareDiff >= previousDifficulty){
                        difficulty = previousDifficulty;
                    }
                    else{
                        return shareError([23, 'low difficulty share of ' + shareDiff]);
                    }
    
                }
            }
    
            _this.emit('share', {
                job: jobId,
                ip: ipAddress,
                port: port,
                worker: workerName,
                height: job.rpcData.height,
                blockReward: job.rpcData.coinbasevalue,
                difficulty: difficulty,
                shareDiff: shareDiff.toFixed(8),
                blockDiff : blockDiffAdjusted,
                blockDiffActual: job.difficulty,
                blockHash: blockHash,
                blockHashInvalid: blockHashInvalid,
                isSoloMining: isSoloMining
            }, blockHex);
    
            return {result: true, error: null, blockHash: blockHash};
        };
    }
};
JobManager.prototype.__proto__ = events.EventEmitter.prototype;
