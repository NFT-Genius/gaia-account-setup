const fcl = require("@onflow/fcl");
const { ec: EC } = require("elliptic");
const { SHA3 } = require("sha3");

require('dotenv/config');

// const { ec: EC } = elliptic;
const ec = new EC("p256");

const ACCESS_NODE = process.env.ACCESS_NODE;
const GAIA_CONTRACT = process.env.GAIA_CONTRACT;
const RECIPIENT_KEY = process.env.RECIPIENT_KEY;
const RECIPIENT_ADDRESS = process.env.RECIPIENT_ADDRESS;
const ACCOUNT_INDEX = process.env.ACCOUNT_INDEX;

const signWithKey = (privateKey, msg) => {
  const key = ec.keyFromPrivate(Buffer.from(privateKey, "hex"));
  const sig = key.sign(hashMsg(msg));
  const n = 32;
  const r = sig.r.toArrayLike(Buffer, "be", n);
  const s = sig.s.toArrayLike(Buffer, "be", n);
  return Buffer.concat([r, s]).toString("hex");
};

const hashMsg = (msg) => {
  const sha = new SHA3(256);
  sha.update(Buffer.from(msg, "hex"));
  return sha.digest();
};

fcl
  .config()
  .put("accessNode.api", ACCESS_NODE)
  .put("0xGaiaContract", GAIA_CONTRACT);

const TX = fcl.cdc`
import Gaia from 0xGaiaContract

// This transaction configures an account to hold assets.
transaction {

    let address: Address

    prepare(account: AuthAccount) {
      //INITIALIZING PARAMS
      self.address = account.address
        
        // First, check to see if a moment collection already exists
        if account.borrow<&Gaia.Collection>(from: Gaia.CollectionStoragePath) == nil {
            // create a new Gaia Collection
            let collection <- Gaia.createEmptyCollection() as! @Gaia.Collection
            // Put the new Collection in storage
            account.save(<-collection, to: Gaia.CollectionStoragePath)
            // create a public capability for the collection
            account.link<&{Gaia.CollectionPublic}>(Gaia.CollectionPublicPath, target: Gaia.CollectionStoragePath)
        }
  }
}
`;

const authorizeMinter = () => {
  return async (account) => {
    const sign = signWithKey;
    const pk = RECIPIENT_KEY;

    return {
      ...account,
      tempId: `${RECIPIENT_ADDRESS}-${ACCOUNT_INDEX}`,
      addr: fcl.sansPrefix(RECIPIENT_ADDRESS),
      keyId: Number(ACCOUNT_INDEX),
      signingFunction: (signable) => {
        return {
          addr: fcl.withPrefix(RECIPIENT_ADDRESS),
          keyId: Number(ACCOUNT_INDEX),
          signature: sign(pk, signable.message),
        };
      },
    };
  };
};

async function setupAccount() {
  try {
    const txId = await fcl
      .send([
        fcl.transaction(TX),
        fcl.payer(authorizeMinter()), // current user is responsible for paying for the transaction
        fcl.proposer(authorizeMinter()), // current user acting as the nonce
        fcl.authorizations([authorizeMinter()]), // current user will be first AuthAccount
        fcl.limit(100), // set the compute limit
      ])
      .then(fcl.decode);
    console.log(`Transaction ID: ${txId}`);
    const sealedResult = await fcl.tx(txId).onceSealed();
    console.log(sealedResult);
  } catch (err) {
    console.error(err);
  }
}

setupAccount();
