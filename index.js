const crypto = require('crypto');
const EventEmitter = require('events').EventEmitter;
const SDK = require('gridplus-sdk');
const keyringType = 'GridPlus Lattice';
const CONNECT_URL = 'https://wallet.gridplus.io';
const SIGNING_URL = 'https://signing.staging-gridpl.us';
const HARDENED_OFFSET = 0x80000000;

class LatticeKeyring extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.type = keyringType
    this.accounts = {}; // Addresses indexed on walletUID
    this.isLocked = true;
    this.creds = {
      deviceID: null,
      password: null,
    };
    this.walletUID = null;
    this.sdkSession = null;
    this.deserialize(opts)
  }

  //-------------------------------------------------------------------
  // Keyring API (per `https://github.com/MetaMask/eth-simple-keyring`)
  //-------------------------------------------------------------------
  deserialize (opts = {}) {
    if (opts.creds)
      this.creds = opts.creds;
    if (opts.accounts)
      this.accounts = opts.accounts;
    return Promise.resolve()
  }

  serialize() {
    return Promise.resolve({
      creds: this.creds,
      accounts: this.accounts,
    })
  }

  isUnlocked () {
    return this.isLocked === false;
  }

  unlock() {
    if (this.isUnlocked()) 
      return Promise.resolve()
    return new Promise((resolve, reject) => {
      this._start(resolve, reject)
      .then(() => {
        // Get the first address
        return this._getAddress()
      })
      .then(() => { resolve(); })
      .catch((err) => { return reject(err); })
    })
  }

  addAccounts(n=1) {
    if (n > 10) 
      return Promise.reject('Only up to 10 accounts may be added at once.')
    if (!this._isSetup())
      return Promise.reject('SDK is not connected. Please reconnect.')
    return new Promise((resolve, reject) => {
      const i = this.accounts[this.walletUID].length;
      this._getAddress(n, i)
      .then(() => { return resolve(); })
      .catch((err) => { return reject(err); })
    })
  }

  getAccounts() {
    if (!this._isSetup())
      return Promise.reject('SDK is not connected. Please reconnect.')
    return resolve(this.accounts[this.walletUID]);
  }

  signTransaction(address, transaction) { 
    return reject('Not yet implemented')
  }

  signMessage(address, data) {
    return reject('Not yet implemented')
  }

  exportAccount(address) {
    return reject('Not supported by this device')
  }

  removeAccount(address) {
    return reject('Not yet implemented')
  }

  //-------------------------------------------------------------------
  // Internal methods and interface to SDK
  //-------------------------------------------------------------------
  _start() {
    return new Promise((resolve, reject) => {
      // We only need to setup if we don't have a deviceID
      if (this._hasCreds())
        return resolve();

      // If we are not aware of what Lattice we should be talking to,
      // we need to open a window that lets the user go through the
      // pairing or connection process.
      const popup = window.open(`${CONNECT_URL}?keyring=true`);
      popup.postMessage('REQ_CREDS');
      // PostMessage handler
      function receiveMessage(event) {
        // Ensure origin
        if (event.origin !== CONNECT_URL)
          return;
        // Parse response data
        try {
          const data = JSON.parse(event.data);
          this.creds.deviceID = data.deviceID;
          this.creds.password = data.password;
          this._initSession(resolve, reject);
        } catch (err) {
          return reject(err);
        }
      }
      window.addEventListener("message", receiveMessage, false);
    })
  }

  _initSession(resolve, reject) {
    try {
      const setupData = {
        name: 'Metamask',
        baseUrl: SIGNING_URL,
        crypto,
        timeout: 120000,
        privKey: this._genSessionKey(),
      }
      this.sdkSession = new SDK.Client(setup);
      // Connect to the device
      this.sdkSession.connect(this.creds.deviceID, (err) => {
        if (err)
          return reject(err);
        // Save the current wallet UID
        this.walletUID = getActiveWallet.uid.toString('hex');
        if (!this.accounts[this.walletUID])
          this.accounts[this.walletUID] = [];
        return resolve();
      });

    } catch (err) {
      return reject(err);
    }
  }

  _getAddress(n=1, i=0) {
    return new Promise((resolve, reject) => {
      if (!this._isSetup())
        return reject('No SDK session started. Cannot fetch addresses.')
      const accounts = this.accounts[this.walletUID];
      if (i > accounts.length)
        return reject(`Requested address is out of bounds. You may only request index <${this.accounts.length}`)

      // If we have already cached the address, we don't need to do it again
      if (accounts.length > i)
        return resolve();
      
      // Make the request to get the requested address
      const addrData = { 
        currency: 'ETH', 
        startPath: [HARDENED_OFFSET+44, HARDENED_OFFSET+60, HARDENED_OFFSET, 0, i], 
        n, // Only request one at a time. This module only supports ETH, so no gap limits
      }
      this.sdkSession.getAddresses(addrData, (err, addrs) => {
        if (err)
          return reject(err);
        if (addrs.length < 1)
          return reject('No addresses returned')
        if (i == accounts.length)
          accounts.push(addrs[0])
        else
          accounts[i] = addrs[0]; // This should not be reachable, but just in case...
        
        return resolve();
      })
    })
  }

  _hasCreds() {
    return this.creds.deviceID !== null && this.creds.password !== null;
  }

  _isSetup() {
    return this.sdkSession && this.walletUID
  }

  _genSessionKey() {
    if (!this._hasCreds())
      throw new Error('No credentials -- cannot create session key!');
    const buf = Buffer.from(JSON.stringify(this.creds));
    return crypto.createHash('sha256').update(buf).digest();
  }

}

LatticeKeyring.type = keyringType
module.exports = LatticeKeyring;