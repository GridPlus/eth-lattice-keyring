const crypto = require('crypto');
const EventEmitter = require('events').EventEmitter;
const SDK = require('gridplus-sdk');
const Transaction = require('ethereumjs-tx').Transaction;
const Common = require('ethereumjs-common').default
const Util = require('ethereumjs-util');
const keyringType = 'Lattice Hardware';
const HARDENED_OFFSET = 0x80000000;
const PER_PAGE = 5;
const CLOSE_CODE = -1000;
const STANDARD_HD_PATH = `m/44'/60'/0'/0/x`

class LatticeKeyring extends EventEmitter {
  constructor (opts={}) {
    super()
    this.type = keyringType;
    this._resetDefaults();
    this.deserialize(opts);
  }

  //-------------------------------------------------------------------
  // Keyring API (per `https://github.com/MetaMask/eth-simple-keyring`)
  //-------------------------------------------------------------------
  deserialize (opts = {}) {
    if (opts.hdPath)
      this.hdPath = opts.hdPath;
    if (opts.creds)
      this.creds = opts.creds;
    if (opts.accounts)
      this.accounts = opts.accounts;
    if (opts.accountIndices)
      this.accountIndices = opts.accountIndices
    if (opts.walletUID)
      this.walletUID = opts.walletUID;
    if (opts.name)  // Legacy; use is deprecated and appName is more descriptive
      this.appName = opts.name;
    if (opts.appName)
      this.appName = opts.appName;
    if (opts.network)
      this.network = opts.network;
    if (opts.page)
      this.page = opts.page;
    return Promise.resolve()
  }

  setHdPath(hdPath) {
    this.hdPath = hdPath;
  }

  serialize() {
    return Promise.resolve({
      creds: this.creds,
      accounts: this.accounts,
      accountIndices: this.accountIndices,
      walletUID: this.walletUID,
      appName: this.appName,
      name: this.name,  // Legacy; use is deprecated
      network: this.network,
      page: this.page,
      hdPath: this.hdPath,
    })
  }

  isUnlocked () {
    return this._hasCreds() && this._hasSession()
  }

  // Initialize a session with the Lattice1 device using the GridPlus SDK
  unlock(updateData=true) {
    return new Promise((resolve, reject) => {
      this._getCreds()
      .then((creds) => {
        if (creds) {
          this.creds.deviceID = creds.deviceID;
          this.creds.password = creds.password;
          this.creds.endpoint = creds.endpoint || null;
        }
        return this._initSession();
      })
      .then(() => {
        return this._connect(updateData);
      })
      .then(() => {
        return resolve('Unlocked');
      })
      .catch((err) => {
        return reject(new Error(err));
      })
    })
  }

  // Add addresses to the local store and return the full result
  addAccounts(n=1) {
    return new Promise((resolve, reject) => {
      if (n === CLOSE_CODE) {
        // Special case: use a code to forget the device. 
        // (This function is overloaded due to constraints upstream)
        this.forgetDevice();
        return resolve([]);
      } else if (n <= 0) {
        // Avoid non-positive numbers.
        return reject('Number of accounts to add must be a positive number.');
      } else {
        // Normal behavior: establish the connection and fetch addresses.
        this.unlock()
        .then(() => {
          return this._fetchAddresses(n, this.unlockedAccount)
        })
        .then((addrs) => {
          // Add these indices
          addrs.forEach((addr, i) => {
            if (this.accounts.indexOf(addr) === -1) {
              this.accounts.push(addr)
              this.accountIndices.push(this.unlockedAccount+i)
            }
          })
          return resolve(this.accounts);
        })
        .catch((err) => {
          return reject(new Error(err));
        })
      }
    })
  }

  // Return the local store of addresses
  getAccounts() {
    return Promise.resolve(this.accounts ? this.accounts.slice() : [].slice());
  }

  signTransaction (address, tx) {
    return new Promise((resolve, reject) => {
      this._unlockAndFindAccount(address)
      .then((addrIdx) => {
        // Build the Lattice request data and make request
        // We expect `tx` to be an `ethereumjs-tx` object, meaning all fields are bufferized
        // To ensure everything plays nicely with gridplus-sdk, we convert everything to hex strings
        const txData = {
          chainId: tx.getChainId() || 1,
          nonce: `0x${tx.nonce.toString('hex')}` || 0,
          gasPrice: `0x${tx.gasPrice.toString('hex')}`,
          gasLimit: `0x${tx.gasLimit.toString('hex')}`,
          to: `0x${tx.to.toString('hex')}`,
          value: `0x${tx.value.toString('hex')}`,
          data: tx.data.length === 0 ? null : `0x${tx.data.toString('hex')}`,
          signerPath: this._getHDPathIndices(addrIdx),
        }
        return this._signTxData(txData)
      })
      .then((signedTx) => {
        // Add the sig params. `signedTx = { sig: { v, r, s }, tx, txHash}`
        if (!signedTx.sig || !signedTx.sig.v || !signedTx.sig.r || !signedTx.sig.s)
          return reject(new Error('No signature returned.'));
        tx.r = Buffer.from(signedTx.sig.r, 'hex');
        tx.s = Buffer.from(signedTx.sig.s, 'hex');
        tx.v = signedTx.sig.v;
        // For non-mainnet EIP155 chains, we have to create a custom network in order to instantiate
        // the validating ethereumjs-tx Transaction object
        // For EIP155 chains, v = CHAIN_ID * 2 + 35, meaning it can never be <35
        // Non-EIP155 chains use v = {27,28}
        const useCustomEip155Chain = (tx.getChainId() !== 1) && 
                                  (parseInt(`0x${tx.v.toString('hex')}`) > 28);
        // Not sure how to get `networkId` so I'm just going to use the `chainId` value for both.
        // see: https://medium.com/@pedrouid/chainid-vs-networkid-how-do-they-differ-on-ethereum-eec2ed41635b
        const customNetwork = Common.forCustomChain('mainnet', { 
          name: 'notMainnet', 
          networkId: tx.getChainId(),
          chainId: tx.getChainId(), 
        }, 'byzantium')
        let validatingTx;
        if (true == useCustomEip155Chain)
          validatingTx = new Transaction(tx, { common: customNetwork });
        else
          validatingTx = new Transaction(tx)
        // Use the validating transaction to confirm the `from` sender matches the address we
        // signed from (i.e. `address`)
        const signer = Util.toChecksumAddress(`0x${validatingTx.from.toString('hex')}`)
        const inputAddress = Util.toChecksumAddress(address)
        if (signer !== inputAddress)
          return reject(new Error(`Unexpected signer. Got ${signer}. Expected ${inputAddress}`))
        return resolve(tx)
      })
      .catch((err) => {
        return reject(new Error(err));
      })
    })
  }

  signPersonalMessage(address, msg) {
    return this.signMessage(address, { payload: msg, protocol: 'signPersonal' });
  }

  signTypedData(address, msg, opts) {
    if (opts.version && (opts.version !== 'V4' && opts.version !== 'V3'))
      throw new Error(`Only signTypedData V3 and V4 messages (EIP712) are supported. Got version ${opts.version}`);
    return this.signMessage(address, { payload: msg, protocol: 'eip712' })
  }

  signMessage(address, msg) {
    return new Promise((resolve, reject) => {
      this._unlockAndFindAccount(address)
      .then((addrIdx) => {
        const { payload, protocol } = msg;
        if (!payload || !protocol)
          return reject('`payload` and `protocol` fields must be included in the request');
        const req = {
          currency: 'ETH_MSG',
          data: {
            protocol,
            payload,
            signerPath: this._getHDPathIndices(addrIdx),
          }
        }
        if (!this._hasSession())
          return reject('No SDK session started. Cannot sign transaction.')
        this.sdkSession.sign(req, (err, res) => {
          if (err)
            return reject(new Error(err));
          if (!res.sig)
            return reject(new Error('No signature returned'));
          // Convert the `v` to a number. It should convert to 0 or 1
          try {
            let v = res.sig.v.toString('hex');
            if (v.length < 2)
              v = `0${v}`;
            return resolve(`0x${res.sig.r}${res.sig.s}${v}`);
          } catch (err) {
            return reject(new Error('Invalid signature format returned.'))
          }
        })
      })
    })
  }

  exportAccount(address) {
    return Promise.reject(Error('exportAccount not supported by this device'))
  }

  removeAccount(address) {
    // We only allow one account at a time, so removing any account
    // should result in a state reset. The user will need to reconnect
    // to the Lattice
    this.forgetDevice();
  }

  getFirstPage() {
    this.page = 0;
    return this._getPage(0);
  }

  getNextPage () {
    return this._getPage(1);
  }

  getPreviousPage () {
    return this._getPage(-1);
  }

  setAccountToUnlock (index) {
    this.unlockedAccount = parseInt(index, 10)
  }

  forgetDevice () {
    this._resetDefaults();
  }

  //-------------------------------------------------------------------
  // Internal methods and interface to SDK
  //-------------------------------------------------------------------
  // Find the account index of the requested address.
  // Note that this is the BIP39 path index, not the index in the address cache.
  _unlockAndFindAccount(address) {
    return new Promise((resolve, reject) => {
      // NOTE: We are passing `false` here because we do NOT want
      // state data to be updated as a result of a transaction request.
      // It is possible the user inserted or removed a SafeCard and
      // will not be able to sign this transaction. If that is the
      // case, we just want to return an error message
      this.unlock(false)
      .then(() => {
        return this.getAccounts()
      })
      .then((addrs) => {
        // Find the signer in our current set of accounts
        // If we can't find it, return an error
        let addrIdx = null;
        addrs.forEach((addr, i) => {
          if (address.toLowerCase() === addr.toLowerCase())
            addrIdx = i;
        })
        if (addrIdx === null)
          return reject('Signer not present');
        return resolve(this.accountIndices[addrIdx]);
      })
      .catch((err) => {
        return reject(err);
      })
    })
  }

  _getHDPathIndices(insertIdx=0) {
    const path = this.hdPath.split('/').slice(1);
    const indices = [];
    let usedX = false;
    path.forEach((_idx) => {
      const isHardened = (_idx[_idx.length - 1] === "'");
      let idx = isHardened ? HARDENED_OFFSET : 0;
      // If there is an `x` in the path string, we will use it to insert our
      // index. This is useful for e.g. Ledger Live path. Most paths have the
      // changing index as the last one, so having an `x` in the path isn't
      // usually necessary.
      if (_idx.indexOf('x') > -1) {
        idx += insertIdx;
        usedX = true;
      } else if (isHardened) {
        idx += Number(_idx.slice(0, _idx.length - 1));
      } else {
        idx += Number(_idx);
      }
      indices.push(idx);
    })
    // If this path string does not include an `x`, we just append the index
    // to the end of the extracted set
    if (usedX === false) {
      indices.push(insertIdx);
    }
    // Sanity check -- Lattice firmware will throw an error for large paths
    if (indices.length > 5)
      throw new Error('Only HD paths with up to 5 indices are allowed.')
    return indices;
  }

  _resetDefaults() {
    this.accounts = [];
    this.accountIndices = [];
    this.isLocked = true;
    this.creds = {
      deviceID: null,
      password: null,
      endpoint: null,
    };
    this.walletUID = null;
    this.sdkSession = null;
    this.page = 0;
    this.unlockedAccount = 0;
    this.network = null;
    this.hdPath = STANDARD_HD_PATH;
  }

  _getCreds() {
    return new Promise((resolve, reject) => {
      // We only need to setup if we don't have a deviceID
      if (this._hasCreds())
        return resolve();

      // If we are not aware of what Lattice we should be talking to,
      // we need to open a window that lets the user go through the
      // pairing or connection process.
      const name = this.appName ? this.appName : 'Unknown'
      let base = 'https://wallet.gridplus.io';
      switch (this.network) {
        case 'rinkeby':
          base = 'https://gridplus-web-wallet-dev.herokuapp.com';
          break;
        default:
          break;
      }
      let url = `${base}?keyring=${name}`;
      if (this.network)
        url += `&network=${this.network}`
      const popup = window.open(url);
      popup.postMessage('GET_LATTICE_CREDS', base);

      // PostMessage handler
      function receiveMessage(event) {
        // Ensure origin
        if (event.origin !== base)
          return;
        // Parse response data
        try {
          const data = JSON.parse(event.data);
          if (!data.deviceID || !data.password)
            return reject(Error('Invalid credentials returned from Lattice.'));
          return resolve(data);
        } catch (err) {
          return reject(err);
        }
      }
      window.addEventListener("message", receiveMessage, false);
    })
  }

  // [re]connect to the Lattice. This should be done frequently to ensure
  // the expected wallet UID is still the one active in the Lattice.
  // This will handle SafeCard insertion/removal events.
  // updateData - true if you want to overwrite walletUID and accounts in
  //              the event that we find we are not synced.
  //              If left false and we notice a new walletUID, we will
  //              return an error.
  _connect(updateData) {
    return new Promise((resolve, reject) => {
      this.sdkSession.connect(this.creds.deviceID, (err) => {
        if (err)
          return reject(err);
        // Save the current wallet UID
        const activeWallet = this.sdkSession.getActiveWallet();
        if (!activeWallet || !activeWallet.uid)
          return reject("No active wallet");
        const newUID = activeWallet.uid.toString('hex');
        // If we fetched a walletUID that does not match our current one,
        // reset accounts and update the known UID
        if (newUID != this.walletUID) {
          // If we don't want to update data, return an error
          if (updateData === false)
            return reject('Wallet has changed! Please reconnect.')
          
          // By default we should clear out accounts and update with
          // the new walletUID. We should NOT fill in the accounts yet,
          // as we reserve that functionality to `addAccounts`
          this.accounts = [];
          this.walletUID = newUID;
        }
        return resolve();
      });
    })
  }

  _initSession() {
    return new Promise((resolve, reject) => {
      if (this._hasSession())
        return resolve();
      try {
        let url = 'https://signing.gridpl.us';
        if (this.network && this.network !== 'mainnet')
          url = 'https://signing.staging-gridpl.us'
        if (this.creds.endpoint)
          url = this.creds.endpoint
        const setupData = {
          name: this.appName,
          baseUrl: url,
          crypto,
          timeout: 120000,
          privKey: this._genSessionKey(),
          network: this.network
        }
        this.sdkSession = new SDK.Client(setupData);
        return resolve();
      } catch (err) {
        return reject(err);
      }
    })
  }

  _fetchAddresses(n=1, i=0, recursedAddrs=[]) {
    return new Promise((resolve, reject) => {
      if (!this._hasSession())
        return reject('No SDK session started. Cannot fetch addresses.')

      this.__fetchAddresses(n, i, (err, addrs) => {
        if (err)
          return reject(err);
        else
          return resolve(addrs);
      })
    })
  }

  __fetchAddresses(n=1, i=0, cb, recursedAddrs=[]) {
     // Determine if we need to do a recursive call here. We prefer not to
      // because they will be much slower, but Ledger paths require it since
      // they are non-standard.
      if (n === 0)
        return cb(null, recursedAddrs);
      const shouldRecurse = this._hdPathHasInternalVarIdx();

      // Make the request to get the requested address
      const addrData = { 
        currency: 'ETH', 
        startPath: this._getHDPathIndices(i), 
        n: shouldRecurse ? 1 : n,
        skipCache: true,
      };
      this.sdkSession.getAddresses(addrData, (err, addrs) => {
        if (err)
          return cb(`Error fetching addresses: ${err}`);
        // Sanity check -- if this returned 0 addresses, handle the error
        if (addrs.length < 1)
          return cb('No addresses returned');
        // Return the addresses we fetched *without* updating state
        if (shouldRecurse) {
          return this.__fetchAddresses(n-1, i+1, cb, recursedAddrs.concat(addrs));
        } else {
          return cb(null, addrs);
        }
      })
  }

  _signTxData(txData) {
    return new Promise((resolve, reject) => {
      if (!this._hasSession())
        return reject('No SDK session started. Cannot sign transaction.')
      this.sdkSession.sign({ currency: 'ETH', data: txData }, (err, res) => {
        if (err)
          return reject(err);
        if (!res.tx)
          return reject('No transaction payload returned.');
        return resolve(res)
      })
    })
  }

  _getPage(increment=0) {
    return new Promise((resolve, reject) => {
      this.page += increment;
      if (this.page < 0)
        this.page = 0;
      const start = PER_PAGE * this.page;
      // Otherwise unlock the device and fetch more addresses
      this.unlock()
      .then(() => {
        return this._fetchAddresses(PER_PAGE, start)
      })
      .then((addrs) => {
        const accounts = []
        addrs.forEach((address, i) => {
          accounts.push({
            address,
            balance: null,
            index: start + i,
          })
        })
        return resolve(accounts)
      })
      .catch((err) => {
        return reject(err);
      })
    })
  }

  _hasCreds() {
    return this.creds.deviceID !== null && this.creds.password !== null && this.appName;
  }

  _hasSession() {
    return this.sdkSession && this.walletUID;
  }

  _genSessionKey() {
    if (this.name && !this.appName) // Migrate from legacy param if needed
      this.appName = this.name;
    if (!this._hasCreds())
      throw new Error('No credentials -- cannot create session key!');
    const buf = Buffer.concat([
      Buffer.from(this.creds.password), 
      Buffer.from(this.creds.deviceID), 
      Buffer.from(this.appName)
    ])
    return crypto.createHash('sha256').update(buf).digest();
  }

  // Determine if an HD path has a variable index internal to it.
  // e.g. m/44'/60'/x'/0/0 -> true, while m/44'/60'/0'/0/x -> false
  // This is just a hacky helper to avoid having to recursively call for non-ledger
  // derivation paths. Ledger is SO ANNOYING TO SUPPORT.
  _hdPathHasInternalVarIdx() {
    const path = this.hdPath.split('/').slice(1);
    for (let i = 0; i < path.length -1; i++) {
      if (path[i].indexOf('x') > -1)
        return true;
    }
    return false;
  }

}

LatticeKeyring.type = keyringType
module.exports = LatticeKeyring;