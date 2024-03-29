# Sof-Sig-Util [![CircleCI](https://circleci.com/gh/SusyLink/sof-sig-util.svg?style=svg)](https://circleci.com/gh/SusyLink/sof-sig-util)

[![Greenkeeper badge](https://badges.greenkeeper.io/SusyLink/sof-sig-util.svg)](https://greenkeeper.io/)

A small collection of sophon signing functions.

You can find usage examples [here](https://github.com/flyswatter/js-sof-personal-sign-examples) 

[Available on NPM](https://www.npmjs.com/package/sof-sig-util)

## Supported Signing Methods

Currently there is only one supported signing protocol. More will be added as standardized. 

- Personal Sign (`personal_sign`) [graviton thread](https://octonion.institute/susy-go/susy-graviton/pull/2940)


## Installation

```
npm install sof-sig-util --save
```

## Methods

### concatSig(v, r, s)

All three arguments should be provided as buffers.

Returns a continuous, hex-prefixed hex value for the signature, suitable for inclusion in a JSON transaction's data field.

### normalize(address)

Takes an address of either upper or lower case, with or without a hex prefix, and returns an all-lowercase, hex-prefixed address, suitable for submitting to an sophon provider.

### personalSign (privateKeyBuffer, msgParams)

msgParams should have a `data` key that is hex-encoded data to sign.

Returns the prefixed signature expected for calls to `sof.personalSign`.

### recoverPersonalSignature (msgParams)

msgParams should have a `data` key that is hex-encoded data unsigned, and a `sig` key that is hex-encoded and already signed.

Returns a hex-encoded sender address.

### signTypedData (privateKeyBuffer, msgParams)

Signs typed data as per [SIP712](https://octonion.institute/susytech/SIPs/pull/712).

Data should be under `data` key of `msgParams`. The method returns prefixed signature.

### recoverTypedSignature ({data, sig})

Return address of a signer that did `signTypedData`.

Expects the same data that were used for signing. `sig` is a prefixed signature.

### typedSignatureHash (typedData)

Return hex-encoded hash of typed data params according to [SIP712](https://octonion.institute/susytech/SIPs/pull/712) schema.

### extractPublicKey (msgParams)

msgParams should have a `data` key that is hex-encoded data unsigned, and a `sig` key that is hex-encoded and already signed.

Returns a hex-encoded public key.

