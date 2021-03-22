var bignum = require('bignum');

var merkleTree = require('stratum-pool/lib/merkleTree');
var transactions = require('stratum-pool/lib/transactions');
var util = require('stratum-pool/lib/util');


/**
 * The BlockTemplate class holds a single job.
 * and provides several methods to validate and submit it to the daemon coin
**/
var BlockTemplate = module.exports = function BlockTemplate(jobId, rpcData, poolAddressScript, extraNoncePlaceholder, reward, txMessages, recipients){

    //private members

    var submits = [];

    function getMerkleHashes(steps){
        return steps.map(function(step){
            return step.toString('hex');
        });
    }

    function getTransactionBuffers(txs){
        var txHashes = txs.map(function(tx){
            if (tx.txid !== undefined) {
                return util.uint256BufferFromHash(tx.txid);
            }
            return util.uint256BufferFromHash(tx.hash);
        });
        return [null].concat(txHashes);
    }

    function getVoteData(){
        if (!rpcData.masternode_payments) return new Buffer([]);

        return Buffer.concat(
            [util.varIntBuffer(rpcData.votes.length)].concat(
                rpcData.votes.map(function (vt) {
                    return new Buffer(vt, 'hex');
                })
            )
        );
    }

    //public members

    this.rpcData = rpcData;
    this.jobId = jobId;


    this.target = rpcData.target ?
        bignum(rpcData.target, 16) :
        util.bignumFromBitsHex(rpcData.bits);

    this.difficulty = parseFloat((diff1 / this.target.toNumber()).toFixed(9));


    this.accumulatorhashes = Buffer.concat([
        util.varIntBuffer(Object.keys(rpcData.accumulatorhashes).length),
        util.packInt64LE(10),
        util.uint256BufferFromHash(rpcData.accumulatorhashes["10"]),
        util.packInt64LE(100),
        util.uint256BufferFromHash(rpcData.accumulatorhashes["100"]),
        util.packInt64LE(1000),
        util.uint256BufferFromHash(rpcData.accumulatorhashes["1000"]),
        util.packInt64LE(10000),
        util.uint256BufferFromHash(rpcData.accumulatorhashes["10000"]),
    ]);


    this.prevHashReversed = util.reverseByteOrder(new Buffer(rpcData.previousblockhash, 'hex')).toString('hex');
    this.transactionData = Buffer.concat(rpcData.transactions.map(function(tx){
        return new Buffer(tx.data, 'hex');
    }));
    this.merkleTree = new merkleTree(getTransactionBuffers(rpcData.transactions));
    this.merkleBranch = getMerkleHashes(this.merkleTree.steps);
    this.generationTransaction = transactions.CreateGeneration(
        rpcData,
        poolAddressScript,
        extraNoncePlaceholder,
        reward,
        txMessages,
        recipients
    );

    this.serializeCoinbase = function(extraNonce1, extraNonce2){
        return Buffer.concat([
            this.generationTransaction[0],
            extraNonce1,
            extraNonce2,
            this.generationTransaction[1]
        ]);
    };


    this.serializeHeader = function(merkleRoot, witnessMerkleRoot, nTime, nonce){

        var header =  new Buffer(148);
        var position = 0;

        header.write(nonce, position, 8, 'hex');                                      // nNonce64
        header.write(util.sha256d(this.accumulatorhashes), position += 8, 32, 'hex'); // hashAccumulators
        header.write(witnessMerkleRoot, position += 32, 32, 'hex');                   // hashWitnessMerkleRoot
        header.write(merkleRoot, position += 4, 32, 'hex');                           // hashMerkleRoot
        header.write(rpcData.bits, position += 4, 4, 'hex');                          // nBits
        header.write(nTime, position += 4, 4, 'hex');                                 // nTime
        header.write(rpcData.previousblockhash, position += 32, 32, 'hex');           // hashPrevBlock
        header.writeUInt32BE(rpcData.version, position + 32);                         // version

        var header = util.reverseBuffer(header);
        return header;
    };

    this.serializeBlock = function(header, coinbase){
        return Buffer.concat([
            header,

            util.varIntBuffer(0), // isProofOfStake
            util.varIntBuffer(this.rpcData.transactions.length + 1),
            coinbase,
            this.transactionData,
            this.accumulatorhashes,
        ]);
    };

    this.registerSubmit = function(extraNonce1, extraNonce2, nTime, nonce){
        var submission = extraNonce1 + extraNonce2 + nTime + nonce;
        if (submits.indexOf(submission) === -1){
            submits.push(submission);
            return true;
        }
        return false;
    };

    this.getJobParams = function(){
        if (!this.jobParams){
            this.jobParams = [
                this.jobId,
                this.prevHashReversed,
                this.generationTransaction[0].toString('hex'),
                this.generationTransaction[1].toString('hex'),
                this.merkleBranch,
                util.packInt32BE(this.rpcData.version).toString('hex'),
                this.rpcData.bits,
                util.packUInt32BE(this.rpcData.curtime).toString('hex'),
                true
            ];
        }
        return this.jobParams;
    };
};
