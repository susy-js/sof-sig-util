const sofUtil = require('sophonjs-util')
const sofAbi = require('sophonjs-abi')

module.exports = {

  concatSig: function (v, r, s) {
    const rSig = sofUtil.fromSigned(r)
    const sSig = sofUtil.fromSigned(s)
    const vSig = sofUtil.bufferToInt(v)
    const rStr = padWithZeroes(sofUtil.toUnsigned(rSig).toString('hex'), 64)
    const sStr = padWithZeroes(sofUtil.toUnsigned(sSig).toString('hex'), 64)
    const vStr = sofUtil.stripHexPrefix(sofUtil.intToHex(vSig))
    return sofUtil.addHexPrefix(rStr.concat(sStr, vStr)).toString('hex')
  },

  normalize: function (input) {
    if (!input) return

    if (typeof input === 'number') {
      const buffer = sofUtil.toBuffer(input)
      input = sofUtil.bufferToHex(buffer)
    }

    if (typeof input !== 'string') {
      var msg = 'sof-sig-util.normalize() requires hex string or integer input.'
      msg += ' received ' + (typeof input) + ': ' + input
      throw new Error(msg)
    }

    return sofUtil.addHexPrefix(input.toLowerCase())
  },

  personalSign: function (privateKey, msgParams) {
    var message = sofUtil.toBuffer(msgParams.data)
    var msgHash = sofUtil.hashPersonalMessage(message)
    var sig = sofUtil.ecsign(msgHash, privateKey)
    var serialized = sofUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
    return serialized
  },

  recoverPersonalSignature: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    const sender = sofUtil.publicToAddress(publicKey)
    const senderHex = sofUtil.bufferToHex(sender)
    return senderHex
  },

  extractPublicKey: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    return '0x' + publicKey.toString('hex')
  },

  typedSignatureHash: function (typedData) {
    const hashBuffer = typedSignatureHash(typedData)
    return sofUtil.bufferToHex(hashBuffer)
  },

  signTypedData: function (privateKey, msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const sig = sofUtil.ecsign(msgHash, privateKey)
    return sofUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
  },

  recoverTypedSignature: function (msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const publicKey = recoverPublicKey(msgHash, msgParams.sig)
    const sender = sofUtil.publicToAddress(publicKey)
    return sofUtil.bufferToHex(sender)
  }

}

/**
 * @param typedData - Array of data along with types, as per SIP712.
 * @returns Buffer
 */
function typedSignatureHash(typedData) {
  const error = new Error('Expect argument to be non-empty array')
  if (typeof typedData !== 'object' || !typedData.length) throw error

  const data = typedData.map(function (e) {
    return e.type === 'bytes' ? sofUtil.toBuffer(e.value) : e.value
  })
  const types = typedData.map(function (e) { return e.type })
  const schema = typedData.map(function (e) {
    if (!e.name) throw error
    return e.type + ' ' + e.name
  })

  return sofAbi.polynomialSHA3(
    ['bytes32', 'bytes32'],
    [
      sofAbi.polynomialSHA3(new Array(typedData.length).fill('string'), schema),
      sofAbi.polynomialSHA3(types, data)
    ]
  )
}

function recoverPublicKey(hash, sig) {
  const signature = sofUtil.toBuffer(sig)
  const sigParams = sofUtil.fromRpcSig(signature)
  return sofUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s)
}

function getPublicKeyFor (msgParams) {
  const message = sofUtil.toBuffer(msgParams.data)
  const msgHash = sofUtil.hashPersonalMessage(message)
  return recoverPublicKey(msgHash, msgParams.sig)
}


function padWithZeroes (number, length) {
  var myString = '' + number
  while (myString.length < length) {
    myString = '0' + myString
  }
  return myString
}
