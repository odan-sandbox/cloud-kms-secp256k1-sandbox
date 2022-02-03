import { KeyManagementServiceClient } from "@google-cloud/kms";
import crypto from "crypto";
import * as asn1js from "asn1js";
import secp256k1 from "secp256k1";

// dyld[59772]: missing symbol called というエラーが出る
// const crc32c = require("fast-crc32c");

async function getPublicKey(): Promise<void> {
  const client = new KeyManagementServiceClient();

  const name =
    "projects/aws-kms-provider/locations/asia-northeast1/keyRings/for-e2e-test/cryptoKeys/for-e2e-test/cryptoKeyVersions/1";

  const [publicKey] = await client.getPublicKey({
    name,
  });

  if (name !== publicKey.name) {
    throw new Error("incorrect name");
  }

  /*
  if (crc32c.calculate(publicKey.pem) !== publicKey.pemCrc32c?.value) {
    throw new Error("incorrect pem");
  }
  */
  if (!publicKey.pem) {
    return;
  }

  const key = crypto.createPublicKey({ key: publicKey.pem, format: "pem" });

  const buffer = key.export({ format: "der", type: "spki" });

  console.log("publicKey", buffer.slice(-64).toString("hex"));
}

async function sign(): Promise<void> {
  const client = new KeyManagementServiceClient();

  const name =
    "projects/aws-kms-provider/locations/asia-northeast1/keyRings/for-e2e-test/cryptoKeys/for-e2e-test/cryptoKeyVersions/1";

  const message = "poyo";
  const hash = crypto.createHash("sha256");

  hash.update(message);
  const digest = hash.digest();

  const [signResponse] = await client.asymmetricSign({
    name,
    digest: {
      sha256: digest,
    },
  });

  if (!signResponse.signature) {
    return;
  }

  if (typeof signResponse.signature === "string") {
    return;
  }

  function toArrayBuffer(buffer: Buffer) {
    const ab = new ArrayBuffer(buffer.length);
    const view = new Uint8Array(ab);
    for (let i = 0; i < buffer.length; ++i) {
      view[i] = buffer[i];
    }
    return ab;
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

  // console.log(r.toString("hex"));
  // console.log(s.toString("hex"));

  const publicKey0 = secp256k1
    .ecdsaRecover(
      Uint8Array.from(Buffer.concat([r, s])),
      0,
      Uint8Array.from(digest),
      false
    )
    .slice(1);
  const publicKey1 = secp256k1
    .ecdsaRecover(
      Uint8Array.from(Buffer.concat([r, s])),
      1,
      Uint8Array.from(digest),
      false
    )
    .slice(1);

  console.log("publicKey0", Buffer.from(publicKey0).toString("hex"));
  console.log("publicKey1", Buffer.from(publicKey1).toString("hex"));
}

async function main(): Promise<void> {
  await getPublicKey();
  await sign();
}

main();

process.on("unhandledRejection", (reason) => {
  console.error(reason);
  process.exit(1);
});

/*
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1PZkpC+R30dOTpdUn3c6GH7YX5Ovn8QF
OimWHZyBDqM8iJSjE2Mcfu6DkW7zKtXbwyHwax1gDwOe7iJIjWtI0Q==
-----END PUBLIC KEY-----
 */
