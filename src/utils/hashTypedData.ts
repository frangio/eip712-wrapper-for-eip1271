// Vendored from https://github.com/wagmi-dev/viem/blob/viem@1.18.1/src/utils/signature/hashTypedData.ts

import type { AbiParameter, TypedData, TypedDataDomain } from 'abitype'
import { type Hex, type TypedDataDefinition, encodeAbiParameters, concat, toHex, keccak256, validateTypedData } from 'viem';

type MessageTypeProperty = {
  name: string
  type: string
}

export type HashTypedDataParameters<
  TTypedData extends TypedData | { [key: string]: unknown } = TypedData,
  TPrimaryType extends string = string,
> = TypedDataDefinition<TTypedData, TPrimaryType>

export type HashTypedDataReturnType = Hex

export function hashTypedData<
  TTypedData extends TypedData | { [key: string]: unknown },
  TPrimaryType extends string = string,
>({
  domain: domain_,
  message,
  primaryType,
  types: types_,
}: HashTypedDataParameters<TTypedData, TPrimaryType>): HashTypedDataReturnType {
  const domain: TypedDataDomain = typeof domain_ === 'undefined' ? {} : domain_
  const types = {
    EIP712Domain: [
      typeof domain?.name === 'string' && { name: 'name', type: 'string' },
      domain?.version && { name: 'version', type: 'string' },
      typeof domain?.chainId === 'number' && {
        name: 'chainId',
        type: 'uint256',
      },
      domain?.verifyingContract && {
        name: 'verifyingContract',
        type: 'address',
      },
      domain?.salt && { name: 'salt', type: 'bytes32' },
    ].filter(Boolean),
    ...(types_ as TTypedData),
  }

  // Need to do a runtime validation check on addresses, byte ranges, integer ranges, etc
  // as we can't statically check this with TypeScript.
  validateTypedData({
    domain,
    message,
    primaryType,
    types,
  } as TypedDataDefinition)

  const parts: Hex[] = ['0x1901']
  if (domain)
    parts.push(
      hashDomain({
        domain,
        types: types as Record<string, MessageTypeProperty[]>,
      }),
    )

  if (primaryType !== 'EIP712Domain') {
    parts.push(
      hashStruct({
        data: message,
        primaryType: primaryType as string,
        types: types as Record<string, MessageTypeProperty[]>,
      }),
    )
  }

  return keccak256(concat(parts))
}

export function hashDomain({
  domain,
  types,
}: {
  domain: TypedDataDomain
  types: Record<string, readonly MessageTypeProperty[]>
}) {
  return hashStruct({
    data: domain,
    primaryType: 'EIP712Domain',
    types,
  })
}

export function hashStruct({
  data,
  primaryType,
  types,
}: {
  data: Record<string, unknown>
  primaryType: string
  types: Record<string, readonly MessageTypeProperty[]>
}) {
  const encoded = encodeData({
    data,
    primaryType,
    types,
  })
  return keccak256(encoded)
}

export function encodeData({
  data,
  primaryType,
  types,
}: {
  data: Record<string, unknown>
  primaryType: string
  types: Record<string, readonly MessageTypeProperty[]>
}) {
  const encodedTypes: AbiParameter[] = [{ type: 'bytes32' }]
  const encodedValues: unknown[] = [hashType({ primaryType, types })]

  for (const field of types[primaryType]) {
    const [type, value] = encodeField({
      types,
      name: field.name,
      type: field.type,
      value: data[field.name],
    })
    encodedTypes.push(type)
    encodedValues.push(value)
  }

  return encodeAbiParameters(encodedTypes, encodedValues)
}

export function hashType({
  primaryType,
  types,
}: {
  primaryType: string
  types: Record<string, readonly MessageTypeProperty[]>
}) {
  const encodedHashType = toHex(encodeType({ primaryType, types }))
  return keccak256(encodedHashType)
}

export function encodeType({
  primaryType,
  types,
}: {
  primaryType: string
  types: Record<string, readonly MessageTypeProperty[]>
}) {
  let result = ''
  const unsortedDeps = findTypeDependencies({ primaryType, types })
  unsortedDeps.delete(primaryType)

  const deps = [primaryType, ...Array.from(unsortedDeps).sort()]
  for (const type of deps) {
    result += `${type}(${types[type]
      .map(({ name, type: t }) => `${t} ${name}`)
      .join(',')})`
  }

  return result
}

function findTypeDependencies(
  {
    primaryType: primaryType_,
    types,
  }: {
    primaryType: string
    types: Record<string, readonly MessageTypeProperty[]>
  },
  results: Set<string> = new Set(),
): Set<string> {
  const match = primaryType_.match(/^\w*/u)
  const primaryType = match?.[0]!
  if (results.has(primaryType) || types[primaryType] === undefined) {
    return results
  }

  results.add(primaryType)

  for (const field of types[primaryType]) {
    findTypeDependencies({ primaryType: field.type, types }, results)
  }
  return results
}

function encodeField({
  types,
  name,
  type,
  value,
}: {
  types: Record<string, readonly MessageTypeProperty[]>
  name: string
  type: string
  value: any
}): [type: AbiParameter, value: any] {
  if (types[type] !== undefined) {
    return [
      { type: 'bytes32' },
      keccak256(encodeData({ data: value, primaryType: type, types })),
    ]
  }

  if (type === 'bytes') {
    const prepend = value.length % 2 ? '0' : ''
    value = `0x${prepend + value.slice(2)}`
    return [{ type: 'bytes32' }, keccak256(value)]
  }

  if (type === 'string') return [{ type: 'bytes32' }, keccak256(toHex(value))]

  if (type.lastIndexOf(']') === type.length - 1) {
    const parsedType = type.slice(0, type.lastIndexOf('['))
    const typeValuePairs = (value as [AbiParameter, any][]).map((item) =>
      encodeField({
        name,
        type: parsedType,
        types,
        value: item,
      }),
    )
    return [
      { type: 'bytes32' },
      keccak256(
        encodeAbiParameters(
          typeValuePairs.map(([t]) => t),
          typeValuePairs.map(([, v]) => v),
        ),
      ),
    ]
  }

  return [{ type }, value]
}
