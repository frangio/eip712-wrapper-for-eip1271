import { type SignableMessage, stringToBytes, toBytes, bytesToString, concat } from 'viem';

export function prefixMessage(message: SignableMessage): string {
  const messageBytes = (() => {
    if (typeof message === 'string') return stringToBytes(message)
    if (message.raw instanceof Uint8Array) return message.raw
    return toBytes(message.raw)
  })()
  const prefixBytes = stringToBytes(
    `\x19Ethereum Signed Message:\n${messageBytes.length}`,
  );
  return bytesToString(concat([prefixBytes, messageBytes]));
}

