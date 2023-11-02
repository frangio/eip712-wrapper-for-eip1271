import assert from 'assert';
import type { Hex, TypedDataParameter, TypedDataDefinition, WalletClient, Transport, Chain, Account } from 'viem';
import { concat, size, slice, recoverAddress, keccak256, compactSignatureToSignature, signatureToHex, signatureToCompactSignature, hexToSignature } from 'viem';
import { toAccount } from 'viem/accounts';
import { hashType, hashStruct } from './utils/hashTypedData.js';
import { hashDomain } from './utils/eip712.js';
import { prefixMessage } from './utils/prefixMessage.js';

const wrapperTypeName = 'EIP1271Wrapper';

type WalletClientWithAccount = WalletClient<Transport, Chain | undefined, Account>;

/**
 * A Viem Account that implements the message signing logic for an ERC-1271-enabled smart contract wallet.
 *
 * @param accountAddress - The address of the smart contract wallet this account represents.
 * @param signerClient - A client for the wallet signer.
 */
export function eip1271Account(accountAddress: Hex, signerClient: WalletClientWithAccount) {
  const accountDomain = { verifyingContract: accountAddress };
  const accountDomainHash = hashDomain(accountDomain);

  const signTypedDataCompact: typeof signerClient.signTypedData = async (msg) => {
    const signature = await signerClient.signTypedData(msg);
    const { r, yParityAndS } = signatureToCompactSignature(hexToSignature(signature));
    return concat([r, yParityAndS]);
  };

  return Object.assign(
    toAccount({
      address: accountAddress,

      // personal_sign
      async signMessage({ message }) {
        // Wrap the message as EIP-712 data to be shown to the signer
        const wrappedMessage = {
          domain: accountDomain,
          primaryType: wrapperTypeName,
          types: {
            [wrapperTypeName]: [
              { name: 'message', type: 'string' },
            ],
          },
          message: {
            message: prefixMessage(message),
          },
        } as const;

        const typeHash = hashType(wrappedMessage);

        // Request an EIP-712 signature from the signer
        const rawCompactSignature = await signTypedDataCompact(wrappedMessage);

        return concat([rawCompactSignature, typeHash]);
      },

      // EIP-712
      async signTypedData(typedData) {
        const types = typedData.types as Record<string, readonly TypedDataParameter[]>;
        assert(types[wrapperTypeName] === undefined, `Duplicate type definition for ${wrapperTypeName}`);

        const messageDomain = typedData.domain;
        assert(messageDomain !== undefined, `Duplicate type definition for ${wrapperTypeName}`);

        const messageDomainHash = hashDomain(messageDomain);
        const contentsHash = hashStruct({ data: typedData.message, primaryType: typedData.primaryType, types });

        // Wrap the message as EIP-712 data to be shown to the signer
        const wrappedTypedData: TypedDataDefinition = {
          domain: accountDomain,
          primaryType: wrapperTypeName,
          types: {
            [wrapperTypeName]: [
              { name: 'contents', type: typedData.primaryType },
              { name: 'message', type: 'bytes' },
            ],
            ...types,
          },
          message: {
            contents: typedData.message, // Full contents of the message
            message: concat(['0x1901', messageDomainHash, contentsHash]), // EIP-712 encoding of the message
          },
        };

        const typeHash = hashType(wrappedTypedData);

        // Request the EIP-712 signature from the signer
        const rawCompactSignature = await signTypedDataCompact(wrappedTypedData);

        // Include all values needed to validate the signature given the inner message hash
        //
        // `messageDomainHash` is not strictly needed and it could be removed to make signature shorter,
        // but including it allows the smart contract to validate the integrity of the EIP-712 object,
        // specifically that the `message` field indeed is the encoding of the `contents` field.
        return concat([rawCompactSignature, typeHash, messageDomainHash, contentsHash]);
      },

      async signTransaction() {
        throw Error('Unimplemented');
      },
    }),
    {
      // EIP-1271 signature validation logic
      async isValidSignature(messageHash: Hex, signature: Hex) {
        const r = slice(signature, 0, 32, { strict: true });
        const yParityAndS = slice(signature, 32, 64, { strict: true });
        const rawSignature = signatureToHex(compactSignatureToSignature({ r, yParityAndS }));

        const typeHash = slice(signature, 64, 96, { strict: true });

        switch (size(signature)) {
          case 96: {
            const hash = keccak256(concat(['0x1901', accountDomainHash, keccak256(concat([typeHash, messageHash]))]));
            const recovered = await recoverAddress({ hash, signature: rawSignature });
            return recovered === signerClient.account.address;
          }

          case 160: {
            const messageDomainHash = slice(signature, 96, 128, { strict: true });
            const contentsHash = slice(signature, 128, 160, { strict: true });

            const hash = keccak256(concat(['0x1901', accountDomainHash, keccak256(concat([typeHash, contentsHash, messageHash]))]));
            const recovered = await recoverAddress({ hash, signature: rawSignature });

            const reconstructedMessageHash = keccak256(concat(['0x1901', messageDomainHash, contentsHash]));

            return messageHash === reconstructedMessageHash && recovered === signerClient.account.address;
          }

          default: {
            return false;
          }
        }
      }
    },
  );
}
