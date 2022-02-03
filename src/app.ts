import { KeyManagementServiceClient } from "@google-cloud/kms";
import crypto from "crypto";

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
  console.log({ publicKey });
  console.log(publicKey.pemCrc32c);

  if (!publicKey.pem) {
    return;
  }

  const key = crypto.createPublicKey({ key: publicKey.pem, format: "pem" });

  const buffer = key.export({ format: "der", type: "spki" });

  console.log(buffer.slice(-64));
  console.log(key.export({ format: "jwk" }));
}

async function main(): Promise<void> {}

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
