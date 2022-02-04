import { ethers } from "ethers";
import { CloudKmsEthersSigner } from "./lib";

async function main() {
  const rpcUrl = process.env.RPC_URL!;
  const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
  const signer = new CloudKmsEthersSigner().connect(provider);

  const address = await signer.getAddress();

  console.log({ address });

  const tx = await signer.sendTransaction({
    from: address,
    to: address,
  });

  console.log({ tx });

  const receipt = await tx.wait();

  console.log({ receipt });
}

main();
