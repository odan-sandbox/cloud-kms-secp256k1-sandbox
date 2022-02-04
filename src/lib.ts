import crypto from "crypto";

import { Signer } from "@ethersproject/abstract-signer";
import { defineReadOnly } from "@ethersproject/properties";

import type { Deferrable } from "@ethersproject/properties";
import type { Bytes } from "@ethersproject/bytes";
import type {
  Provider,
  TransactionRequest,
} from "@ethersproject/abstract-provider";
import * as asn1js from "asn1js";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import type { Signer as ISigner } from "aws-kms-signer";
import { Signature, Address } from "aws-kms-signer";

import { Adapter } from "../node_modules/aws-kms-ethers-signer/dist/adapter";

function toArrayBuffer(buffer: Buffer) {
  const ab = new ArrayBuffer(buffer.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }
  return ab;
}

export class CloudKmsSigner implements ISigner {
  private client: KeyManagementServiceClient;
  private name =
    "projects/aws-kms-provider/locations/asia-northeast1/keyRings/for-e2e-test/cryptoKeys/for-e2e-test/cryptoKeyVersions/1";

  constructor() {
    this.client = new KeyManagementServiceClient();
  }

  async getAddress(): Promise<Address> {
    const [publicKey] = await this.client.getPublicKey({
      name: this.name,
    });

    if (!publicKey.pem) {
      throw new Error();
    }

    const key = crypto.createPublicKey({ key: publicKey.pem, format: "pem" });

    const buffer = key.export({ format: "der", type: "spki" });

    return Address.fromPublicKey(buffer.slice(-64));
  }

  async sign(digest: Buffer): Promise<Signature> {
    const [signResponse] = await this.client.asymmetricSign({
      name: this.name,
      digest: {
        sha256: digest,
      },
    });

    if (!signResponse.signature) {
      throw new TypeError();
    }
    if (typeof signResponse.signature === "string") {
      throw new TypeError();
    }

    const buffer = Buffer.from(
      Buffer.from(signResponse.signature).toString("hex"),
      "hex"
    );

    const { result } = asn1js.fromBER(toArrayBuffer(buffer));

    const values = (result as asn1js.Sequence).valueBlock
      .value as asn1js.Integer[];

    function decode(value: asn1js.Integer) {
      const slice = value.valueBlock.blockLength == 33 ? 1 : 0;

      return Buffer.from(value.valueBlock.valueHex).slice(slice);
    }

    const r = decode(values[0]);
    const s = decode(values[1]);

    return Signature.fromDigest(digest, await this.getAddress(), r, s);
  }
}

export class CloudKmsEthersSigner extends Signer {
  private readonly adapter: Adapter;

  constructor(provider?: Provider) {
    super();
    defineReadOnly(this, "provider", provider);

    const version = "0.0.0";

    const signer = new CloudKmsSigner();
    this.adapter = new Adapter({ signer, version }, provider);
  }

  async getAddress(): Promise<string> {
    return this.adapter.getAddress();
  }

  async signMessage(message: Bytes | string): Promise<string> {
    return this.adapter.signMessage(message);
  }

  async signTransaction(
    deferrableTransaction: Deferrable<TransactionRequest>
  ): Promise<string> {
    return this.adapter.signTransaction(deferrableTransaction);
  }

  connect(provider: Provider): CloudKmsEthersSigner {
    return new CloudKmsEthersSigner(provider);
  }
}
