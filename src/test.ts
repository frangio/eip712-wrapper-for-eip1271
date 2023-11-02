import { type TypedDataDefinition, createWalletClient, getContractAddress, hashMessage, hashTypedData, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { eip1271Account } from './eip1271-account.js';

const signerKey = '0x2e8193b8019d1086a29a921b8ac5118079bb83de0613e312bbc2a17a7ee824e6';

const signerClient = createWalletClient({
  account: privateKeyToAccount(signerKey),
  transport: http('http://localhost:8545'),
});

const accountAddress = getContractAddress({ from: signerClient.account.address, nonce: 0n });

const account = eip1271Account(accountAddress, signerClient);

// personal_sign
{
  const message = 'hello';
  const signature = await account.signMessage({ message });

  if (await account.isValidSignature(hashMessage(message), signature)) {
    console.log('personal_sign ok');
  } else {
    console.log('personal_sign failed');
  }
}

// EIP-712
{
  const typedData = {
    domain: {
      name: 'Protocol X',
    },
    types: {
      Permit: [
        { name: 'amount', type: 'uint256' },
      ],
    },
    primaryType: 'Permit',
    message: {
      amount: 42n,
    },
  } as const satisfies TypedDataDefinition;

  const signature = await account.signTypedData(typedData);

  if (await account.isValidSignature(hashTypedData(typedData), signature)) {
    console.log('EIP-712 ok');
  } else {
    console.log('EIP-712 failed');
  }
}
