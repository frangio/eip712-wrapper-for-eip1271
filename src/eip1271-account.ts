import type { Hex, TypedDataParameter, TypedDataDefinition } from 'viem';
import { concat, size, slice, recoverAddress, keccak256, compactSignatureToSignature, signatureToHex, signatureToCompactSignature, hexToSignature } from 'viem';
import { privateKeyToAccount, toAccount } from 'viem/accounts';
import { hashType, hashTypedData, hashStruct } from './utils/hashTypedData.js';
import assert from 'assert';
import { hashDomain } from './utils/eip712.js';
import { prefixMessage } from './utils/prefixMessage.js';

const wrapperTypeName = 'EIP1271Wrapper';

export function eip1271Account(signerKey: Hex, address: Hex, chainId?: number) {
  const accountDomain = { verifyingContract: address, chainId };
  const accountDomainSeparator = hashDomain(accountDomain);

  const signerAccount = privateKeyToAccount(signerKey);

  const signTypedDataCompact: typeof signerAccount.signTypedData = async (msg) => {
    const signature = await signerAccount.signTypedData(msg);
    const { r, yParityAndS } = signatureToCompactSignature(hexToSignature(signature));
    return concat([r, yParityAndS]);
  };

  return Object.assign(
    toAccount({
      address,

      async signMessage({ message }) {
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

        const rawCompactSignature = await signTypedDataCompact(wrappedMessage);
        const typeHash = hashType(wrappedMessage);

        return concat([rawCompactSignature, typeHash]);
      },

      async signTypedData(typedData) {
        const types = typedData.types as Record<string, readonly TypedDataParameter[]>;
        assert(types[wrapperTypeName] === undefined, `Duplicate type definition for ${wrapperTypeName}`);

        const messageDomain = typedData.domain;
        assert(messageDomain !== undefined, `Duplicate type definition for ${wrapperTypeName}`);

        const messageDomainSeparator = hashDomain(messageDomain);
        const contentsHash = hashStruct({ data: typedData.message, primaryType: typedData.primaryType, types });

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
            contents: typedData.message,
            message: concat(['0x1901', messageDomainSeparator, contentsHash]),
          },
        };

        const rawCompactSignature = await signTypedDataCompact(wrappedTypedData);
        const typeHash = hashType(wrappedTypedData);

        return concat([rawCompactSignature, typeHash, messageDomainSeparator, contentsHash]);
      },

      async signTransaction() {
        throw Error('Unimplemented');
      },
    }),
    {
      async isValidSignature(messageHash: Hex, signature: Hex) {
        const r = slice(signature, 0, 32, { strict: true });
        const yParityAndS = slice(signature, 32, 64, { strict: true });
        const rawSignature = signatureToHex(compactSignatureToSignature({ r, yParityAndS }));

        const typeHash = slice(signature, 64, 96, { strict: true });

        switch (size(signature)) {
          case 96: {
            const hash = keccak256(concat(['0x1901', accountDomainSeparator, keccak256(concat([typeHash, messageHash]))]));
            const recovered = await recoverAddress({ hash, signature: rawSignature });
            return recovered === signerAccount.address;
          }

          case 160: {
            const messageDomainSeparator = slice(signature, 96, 128, { strict: true });
            const contentsHash = slice(signature, 128, 160, { strict: true });
            const hash = keccak256(concat(['0x1901', accountDomainSeparator, keccak256(concat([typeHash, contentsHash, messageHash]))]));
            const messageHash2 = keccak256(concat(['0x1901', messageDomainSeparator, contentsHash]));
            const recovered = await recoverAddress({ hash, signature: rawSignature });
            return messageHash === messageHash2 && recovered === signerAccount.address;
          }

          default: {
            return false;
          }
        }
      }
    },
  );
}
