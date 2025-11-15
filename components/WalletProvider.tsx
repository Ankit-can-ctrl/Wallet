"use client";

import React, { Children, createContext, useContext, useState } from "react";

// StoredEncrypted type (or interface) that describes the structure of the encrypted
// wallet data you save in storage.
// StoredEncrypted = encrypted version of your private key/seed + metadata needed to decrypt it later.
// This is what you save in the browser (IndexedDB) instead of saving the plain private key (unsafe).
type StoredEncrypted = {
  ct: string;
  iv: string;
  salt: string;
};

type WalletContextType = {
  keypair?: any;
  //   wallet functions :
  // createFromMnemonics function create wallet using mnemonic and password
  createFromMnemonics: (mnemonic: string, password: string) => Promise<void>;
  //   restores wallet using encrypted data
  importEncrypted: (data: StoredEncrypted, password: string) => Promise<void>;
  //reads encrypted wallet from storage
  exportEncrypted: () => Promise<StoredEncrypted | undefined>;
  // clear memory keypair and remove encrypted data
  logout: () => Promise<void>;
};
const WalletContext = createContext<WalletContextType | undefined>(undefined);

export const WalletProvider: React.FC<{ children: React.ReactNode }> = ({
  Children,
}) => {
  const [keypair, setKeypair] = useState<any | undefined>(undefined);

  async function createFromMnemonics(mnemonic: string, password: string) {
    // dynamic import as bip39 is not browser safe
    const bip39 = await import("bip39");
    // converts the 12/24-word mnemonic into a raw 64-byte seed
    const seed = Buffer.from(bip39.mnemonicToSeedSync(mnemonic));

    // 2. Encrypt the seed using the password
    const encrypted = await encryptSeed(seed, password);
  }

  return (
    <WalletContext.Provider
      value={{
        keypair,
        createFromMnemonics,
        importEncrypted,
        exportEncrypted,
        logout,
      }}
    ></WalletContext.Provider>
  );
};

export function useWallet() {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error("useWallet must be inside WalletProvide.");
  return ctx;
}
