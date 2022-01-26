const crypto = require('crypto');
const EventEmitter = require('events').EventEmitter;
const BN = require('bignumber.js');
const SDK = require('gridplus-sdk');
const EthTx = require('@ethereumjs/tx');
const Common = require('@ethereumjs/common').default;
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
      this.accountIndices = opts.accountIndices;
    if (opts.accountOpts)
      this.accountOpts = opts.accountOpts;
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
      accountOpts: this.accountOpts,
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
  unlock() {
    return new Promise((resolve, reject) => {
      // Force compatability. `this.accountOpts` were added after other
      // state params and must be synced in order for this keyring to function.
      if ((!this.accountOpts) || 
          (this.accounts.length > 0 && this.accountOpts.length != this.accounts.length)) 
      {
        this.forgetDevice();
        return reject(new Error(
          'You can now add multiple Lattice and SafeCard accounts at the same time! ' +
          'Your accounts have been cleared. Please press Continue to add them back in.'
        ));
      }

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
        return this._connect();
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
          const walletUID = this._getCurrentWalletUID();
          // Add these indices
          addrs.forEach((addr, i) => {
            let alreadySaved = false;
            for (let j = 0; j < this.accounts.length; j++) {
              if ((this.accounts[j] === addr) && 
                  (this.accountOpts[j].walletUID === walletUID) &&
                  (this.accountOpts[j].hdPath === this.hdPath))
                alreadySaved = true;
            }
            if (!alreadySaved) {
              this.accounts.push(addr);
              this.accountIndices.push(this.unlockedAccount+i);
              this.accountOpts.push({
                walletUID,
                hdPath: this.hdPath,
              })
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
      .then((accountIdx) => {
        // Build the Lattice request data and make request
        // We expect `tx` to be an `ethereumjs-tx` object, meaning all fields are bufferized
        // To ensure everything plays nicely with gridplus-sdk, we convert everything to hex strings
        const addressIdx = this.accountIndices[accountIdx];
        const addressParentPath = this.accountOpts[accountIdx].hdPath;
        const txData = {
          chainId: `0x${this._getEthereumJsChainId(tx).toString('hex')}` || 1,
          nonce: `0x${tx.nonce.toString('hex')}` || 0,
          gasLimit: `0x${tx.gasLimit.toString('hex')}`,
          to: tx.to.toString('hex'),
          value: `0x${tx.value.toString('hex')}`,
          data: tx.data.length === 0 ? null : `0x${tx.data.toString('hex')}`,
          signerPath: this._getHDPathIndices(addressParentPath, addressIdx),
        }
        switch (tx._type) {
          case 2: // eip1559
            if ((tx.maxPriorityFeePerGas === null || tx.maxFeePerGas === null) ||
                (tx.maxPriorityFeePerGas === undefined || tx.maxFeePerGas === undefined))
              throw new Error('`maxPriorityFeePerGas` and `maxFeePerGas` must be included for EIP1559 transactions.');
            txData.maxPriorityFeePerGas = `0x${tx.maxPriorityFeePerGas.toString('hex')}`;
            txData.maxFeePerGas = `0x${tx.maxFeePerGas.toString('hex')}`;
            txData.accessList = tx.accessList || [];
            txData.type = 2;
            break;
          case 1: // eip2930
            txData.accessList = tx.accessList || [];
            txData.gasPrice = `0x${tx.gasPrice.toString('hex')}`;
            txData.type = 1;
            break;
          default: // legacy
            txData.gasPrice = `0x${tx.gasPrice.toString('hex')}`;
            txData.type = null;
            break;
        }
        // Lattice firmware v0.11.0 implemented EIP1559 and EIP2930 so for previous verisons
        // we need to overwrite relevant params and revert to legacy type.
        // Note: `this.sdkSession.fwVersion is of format [fix, minor, major, reserved]
        const forceLegacyTx = this.sdkSession.fwVersion[2] < 1 && 
                              this.sdkSession.fwVersion[1] < 11;
        if (forceLegacyTx && txData.type === 2) {
          console.warn('Lattice firmware must be >=0.11.0 to support EIP1559 transactions. Revering to legacy.');
          txData.gasPrice = txData.maxFeePerGas;
          txData.revertToLegacy = true;
          delete txData.type;
          delete txData.maxFeePerGas;
          delete txData.maxPriorityFeePerGas;
          delete txData.accessList;
        } else if (forceLegacyTx && txData.type === 1) {
          console.warn('Lattice firmware must be >=0.11.0 to support EIP2930 transactions. Reverting to legacy.');
          txData.revertToLegacy = true;
          delete txData.type;
          delete txData.accessList;
        }
        // Get the signature
        return this._signTxData(txData)
      })
      .then((signedTx) => {
        // Add the sig params. `signedTx = { sig: { v, r, s }, tx, txHash}`
        if (!signedTx.sig || !signedTx.sig.v || !signedTx.sig.r || !signedTx.sig.s)
          return reject(new Error('No signature returned.'));
        const txToReturn = tx.toJSON();
        const v = signedTx.sig.v.length === 0 ? '0' : signedTx.sig.v.toString('hex')
        txToReturn.r = Util.addHexPrefix(signedTx.sig.r.toString('hex'));
        txToReturn.s = Util.addHexPrefix(signedTx.sig.s.toString('hex'));
        txToReturn.v = Util.addHexPrefix(v);

        if (signedTx.revertToLegacy === true) {
          // If firmware does not support an EIP1559/2930 transaction we revert to legacy
          txToReturn.type = 0;
          txToReturn.gasPrice = signedTx.gasPrice;
        } else {
          // Otherwise relay the tx type
          txToReturn.type = signedTx.type;
        }

        // Build the tx for export
        let validatingTx;
        const _chainId = `0x${this._getEthereumJsChainId(tx).toString('hex')}`;
        const chainId = new BN(_chainId).toNumber();
        const customNetwork = Common.forCustomChain('mainnet', {
          name: 'notMainnet',
          networkId: chainId,
          chainId: chainId,
        }, 'london')

        validatingTx = EthTx.TransactionFactory.fromTxData(txToReturn, {
          common: customNetwork, freeze: Object.isFrozen(tx)
        })
        return resolve(validatingTx)
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
      .then((accountIdx) => {
        let { payload, protocol } = msg;
        // If the message is not an object we assume it is a legacy signPersonal request
        if (!payload || !protocol) {
          payload = msg;
          protocol = 'signPersonal';
        }
        const addressIdx = this.accountIndices[accountIdx];
        const addressParentPath = this.accountOpts[accountIdx].hdPath;
        const req = {
          currency: 'ETH_MSG',
          data: {
            protocol,
            payload,
            signerPath: this._getHDPathIndices(addressParentPath, addressIdx),
          }
        }
        if (!this._hasSession())
          return reject(new Error('No SDK session started. Cannot sign transaction.'));
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
      .catch((err) => {
        return reject(new Error(err));
      })
    })
  }

  exportAccount(address) {
    return Promise.reject(Error('exportAccount not supported by this device'))
  }

  removeAccount(address) {
    this.accounts.forEach((account, i) => {
      if (account.toLowerCase() === address.toLowerCase()) {
        this.accounts.splice(i, 1);
        this.accountIndices.splice(i, 1);
        this.accountOpts.splice(i, 1);
        return;
      }
    })
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
      this.unlock()
      .then(() => {
        return this.getAccounts()
      })
      .then((addrs) => {
        // Find the signer in our current set of accounts
        // If we can't find it, return an error
        let accountIdx = null;
        addrs.forEach((addr, i) => {
          if (address.toLowerCase() === addr.toLowerCase())
            accountIdx = i;
        })
        if (accountIdx === null)
          return reject('Signer not present');
        // Make sure the account is associated with the current wallet
        if (this.accountOpts[accountIdx].walletUID !== this._getCurrentWalletUID()) {
          return reject(new Error('Account on a different wallet. ' +
                                  'Please switch to the correct wallet on your Lattice.'));
        }
        return resolve(accountIdx);
      })
      .catch((err) => {
        return reject(err);
      })
    })
  }

  _getHDPathIndices(hdPath, insertIdx=0) {
    const path = hdPath.split('/').slice(1);
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
    this.accountOpts = [];
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

  _openConnectorTab(url) {
    return new Promise((resolve, reject) => {
      const browserTab = window.open(url);
      // Preferred option for Chromium browsers. This extension runs in a window
      // for Chromium so we can do window-based communication very easily.
      if (browserTab) {
        return resolve({ chromium: browserTab });
      } else if (browser && browser.tabs && browser.tabs.create) {
        // FireFox extensions do not run in windows, so it will return `null` from
        // `window.open`. Instead, we need to use the `browser` API to open a tab. 
        // We will surveille this tab to see if its URL parameters change, which 
        // will indicate that the user has logged in.
        browser.tabs.create({url})
        .then((tab) => {
          return resolve({ firefox: tab });
        })
        .catch((err) => {
          return reject(new Error('Failed to open Lattice connector.'))
        })
      } else {
        return reject(new Error('Unknown browser context. Cannot open Lattice connector.'))
      }

    })
  }

  _findTabById(id) {
    return new Promise((resolve, reject) => {
      browser.tabs.query({})
      .then((tabs) => {
        tabs.forEach((tab) => {
          if (tab.id === id) {
            return resolve(tab);
          }
        })
        return resolve(null);
      })
      .catch((err) => {
        return reject(err);
      })
    })
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
      const base = 'https://lattice.gridplus.io';
      const url = `${base}?keyring=${name}&forceLogin=true`;
      let listenInterval;

      // PostMessage handler
      function receiveMessage(event) {
        // Ensure origin
        if (event.origin !== base)
          return;
        // Stop the listener
        try {
          clearInterval(listenInterval);
        } catch (err) {
          console.warn('Failed to close interval', err);
        }
        // Parse and return creds
        try {
          const creds = JSON.parse(event.data);
          if (!creds.deviceID || !creds.password)
            return reject(new Error('Invalid credentials returned from Lattice.'));
          return resolve(creds);
        } catch (err) {
          return reject(err);
        }
      }

      // Open the tab
      this._openConnectorTab(url)
      .then((conn) => {
        if (conn.chromium) {
          // On a Chromium browser we can just listen for a window message
          window.addEventListener("message", receiveMessage, false);
          // Watch for the open window closing before creds are sent back
          listenInterval = setInterval(() => {
            if (conn.chromium.closed) {
              clearInterval(listenInterval);
              return reject(new Error('Lattice connector closed.'));
            }
          }, 500);
        } else if (conn.firefox) {
          // For Firefox we cannot use `window` in the extension and can't
          // directly communicate with the tabs very easily so we use a
          // workaround: listen for changes to the URL, which will contain
          // the login info.
          // NOTE: This will only work if have `https://lattice.gridplus.io/*`
          // host permissions in your manifest file (and also `activeTab` permission)
          const loginUrlParam = '&loginCache=';
          listenInterval = setInterval(() => {
            this._findTabById(conn.firefox.id)
            .then((tab) => {
              if (!tab || !tab.url) {
                return reject(new Error('Lattice connector closed.'));
              }
              // If the tab we opened contains a new URL param
              const paramLoc = tab.url.indexOf(loginUrlParam);
              if (paramLoc < 0) 
                return;
              const dataLoc = paramLoc + loginUrlParam.length;
              // Stop this interval
              clearInterval(listenInterval);
              try {
                // Parse the login data. It is a stringified JSON object 
                // encoded as a base64 string.
                const _creds = Buffer.from(tab.url.slice(dataLoc), 'base64').toString();
                // Close the tab and return the credentials
                browser.tabs.remove(tab.id)
                .then(() => {
                  const creds = JSON.parse(_creds);
                  if (!creds.deviceID || !creds.password)
                    return reject(new Error('Invalid credentials returned from Lattice.'));
                  return resolve(creds);
                })
              } catch (err) {
                return reject('Failed to get login data from Lattice. Please try again.')
              }
            })
          }, 500);
        }
      })
    })
  }

  // [re]connect to the Lattice. This should be done frequently to ensure
  // the expected wallet UID is still the one active in the Lattice.
  // This will handle SafeCard insertion/removal events.
  _connect() {
    return new Promise((resolve, reject) => {
      this.sdkSession.connect(this.creds.deviceID, (err) => {
        if (err)
          return reject(err);
        // Save the current wallet UID
        const activeWallet = this.sdkSession.getActiveWallet();
        if (!activeWallet || !activeWallet.uid)
          return reject(new Error('No active wallet'));
        const newUID = activeWallet.uid.toString('hex');
        // If we fetched a walletUID that does not match our current one,
        // reset accounts and update the known UID
        if (newUID != this.walletUID) {
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
        startPath: this._getHDPathIndices(this.hdPath, i), 
        n: shouldRecurse ? 1 : n,
        skipCache: true,
      };
      this.sdkSession.getAddresses(addrData, (err, addrs) => {
        if (err)
          return cb(err);
        // Sanity check -- if this returned 0 addresses, handle the error
        if (addrs.length < 1)
          return cb(new Error('No addresses returned'));
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
        return reject(new Error('No SDK session started. Cannot sign transaction.'));
      this.sdkSession.sign({ currency: 'ETH', data: txData }, (err, res) => {
        if (err)
          return reject(err);
        if (!res.tx)
          return reject(new Error('No transaction payload returned.'));
        // Here we catch an edge case where the requester is asking for an EIP1559
        // transaction but firmware is not updated to support it. We fallback to legacy.
        res.type = txData.type;
        if (txData.revertToLegacy) {
          res.revertToLegacy = true;
          res.gasPrice = txData.gasPrice;
        }
        // Return the signed tx
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

  // Get the chainId for whatever object this is.
  // Returns a hex string without the 0x prefix
  _getEthereumJsChainId(tx) {
    if (typeof tx.getChainId === 'function')
      return tx.getChainId();
    else if (tx.common && typeof tx.common.chainIdBN === 'function')
      return tx.common.chainIdBN().toString(16);
    else if (typeof tx.chainId === 'number')
      return tx.chainId.toString(16);
    else if (typeof tx.chainId === 'string')
      return tx.chainId;
    return '1';
  }

  _getCurrentWalletUID() {
    if (!this.sdkSession)
      return null;
    return this.sdkSession.getActiveWallet().uid.toString('hex');
  }

}

LatticeKeyring.type = keyringType
module.exports = LatticeKeyring;