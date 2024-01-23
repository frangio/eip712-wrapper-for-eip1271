# Replay Protection for EIP-1271 via Nested EIP-712

EIP-1271 signatures where the wallet keys sign an application message directly may be vulnerable to replay on other EIP-1271 wallets with the same set of owners. In particular, if the wallet has a single owner, and the owner controls multiple wallets (with the same key), the owner's signature for one of the wallets will be considered valid for all other wallets. Depending on the signed message contents, this may enable a protocol action intended for a single wallet to be replayed on all other wallets.

To implement replay protection the signature must be bound to the smart contract wallet by including its address somewhere in the signed message.

An initial implementation might look like this:

```solidity
address owner;

function isValidSignature(bytes32 messageHash, bytes calldata signature) {
    bytes32 boundHash = keccak256(abi.encode(messageHash, address(this)));
    if (recoverSigner(boundHash, signature) == owner) {
        return this.isValidSignature.selector;
    } else {
        return 0xffffffff;
    }
}
```

The signed message is correctly bound to the wallet address (`address(this)`). However, it may not be possible at all for the owner to generate this signature if they don't have direct access to the private key material. In fact, signing keys can often only be used through the standard APIs `personal_sign` and `eth_signTypedData`. This is the case when the signer is a hardware wallet. These methods are important because they enable the hardware to act as a "last line of defense", where the signed message contents are made available to the signer to be audited.

This repository proposes a solution to protect EIP-1271 wallets against replay attacks, while allowing full auditability of the signed message contents, by wrapping the message in an envelope that binds it to a specific EIP-1271 wallet. We first evaluate `personal_sign` and see that it is not sufficient to build this envelope, then we arrive at a satisfactory solution using an EIP-712 envelope that we call "Nested EIP-712".

## `personal_sign`

Using this API method a protocol can request a signature for a human-readable message. The message will be displayed to the signer in full by a hardware wallet.

In order for an EIP-1271 wallet to use this method for replay protection, it must therefore generate a human-readable message envelope. In addition to the wallet address, we would like it to include the original message contents for auditability. However, note that it must be possible to reproduce the message in the smart contract wallet, and EIP-1271 only makes available the `messageHash` that was ultimately signed by the private key (constructed according to `personal_sign` or `eth_signTypedData` depending on the application request). Therefore, the message contents are not available to the smart contract. The best we can do is include a hex representation of the message hash as shown below:

```solidity
function isValidSignature(bytes32 messageHash, bytes calldata signature) {
    string memory wrappedMessage = string.concat(
        "signing ",
        messageHash.toHexString(),
        " for account ",
        address(this).toHexString(),
    );
    bytes32 boundHash = bytes(wrappedMessage).toEthSignedMessageHash(); // personal_sign
    if (recoverSigner(boundHash, signature) == owner) {
        return this.isValidSignature.selector;
    } else {
        return 0xffffffff;
    }
}
```

This is not satisfactory for full auditability of the signed message.

## `eth_signTypedData` a.k.a. EIP-712

The messages that can be signed by this API method are much richer: they are typed structured data, and are tied to the verifying contract by a domain separator. This message, with all of its parameters and the domain it is intended for, will (or should) be displayed in full to the signer.

This allows us to carefully construct a message envelope that gives full transparency of the signed message contents while also binding it to an EIP-1271 wallet.

A TypeScript implementation of the logic can be found in [`eip1271-account.ts`](/master/src/eip1271-account.ts) in this repository, and a largely compatible Solidity implementation can be found in [#688](https://github.com/Vectorized/solady/pull/688) in the Solady repository.

In order to bind the signature to a wallet, the wallet defines its own EIP-712 domain, and the envelope will be bound to this domain.

An application may request either a `personal_sign` or `eth_signTypedData` signature, each of which has to be handled differently.

In the case of a `personal_sign` message, the EIP-712 envelope will contain the plain text message. Remember that the wallet contract will receive a message hash, and that this hash is constructed in a special way according to `personal_sign`, namely by prepending it with `"\x19Ethereum Signed Message:\n" + <length (ASCII decimals)>`. To make the envelope work, we have to include the prefixed message instead of the original one, but this successfully retains full auditability.

In the case of an `eth_signTypedData` message, the EIP-712 envelope will embed the original message object, so that all of its parameters are displayed to the user. Although the object is fully embedded, the resulting EIP-712 message hash will be completely different from the message hash that a protocol will pass to `isValidSignature`, since the protocol reconstructs it independently from the application-specific parameters. We have no other choice than to include the encoding of the embedded message in the envelope as well, which must include the protocol domain. We will need to include additional data in the signature for the wallet contract to be able to reproduce the envelope hash.

The details are a little too extensive to explain here, and the curious reader is encouraged to check out the TypeScript reference implementation [`eip1271-account.ts`](/master/src/eip1271-account.ts).

## Possible Issues
These EIP-1271 signatures will be up to 4 64-byte words in size. A provider for a smart contract wallet would need to return this signature as the result of a call to `personal_sign` or `eth_signTypedData`, and this may be unsupported by API clients that expect a return value of 129 bytes, or specifically the `r,s,v` parameters of an ECDSA signature, as is for example [specified for EIP-712](https://eips.ethereum.org/EIPS/eip-712#specification-of-the-eth_signtypeddata-json-rpc). The author believes these APIs should be specified as returning opaque blobs of arbitrary size for smart contract wallet support.
