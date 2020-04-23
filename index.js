const crypto = require('crypto');
const EventEmitter = require('events').EventEmitter;
const SDK = require('gridplus-sdk');
const keyringType = 'Lattice Hardware';
const CONNECT_URL = 'http://localhost:5000';
const SIGNING_URL = 'https://signing.staging-gridpl.us';
const HARDENED_OFFSET = 0x80000000;
const PER_PAGE = 5;

class LatticeKeyring extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.type = keyringType
    this._resetDefaults();
    this.deserialize(opts);
  }

  //-------------------------------------------------------------------
  // Keyring API (per `https://github.com/MetaMask/eth-simple-keyring`)
  //-------------------------------------------------------------------
  deserialize (opts = {}) {
    if (opts.creds)
      this.creds = opts.creds;
    if (opts.accounts)
      this.addresses = opts.accounts;
    if (opts.walletUID)
      this.walletUID = opts.walletUID;
    return Promise.resolve()
  }

  serialize() {
    return Promise.resolve({
      creds: this.creds,
      accounts: this.addresses,
      walletUID: this.walletUID,
    })
  }

  isUnlocked () {
    return this._hasCreds() && this._hasSession()
  }

  unlock() {
    if (this.isUnlocked()) 
      return Promise.resolve()
    return new Promise((resolve, reject) => {
      this._getCreds()
      .then((creds) => {
        if (creds) {
          this.creds.deviceID = creds.deviceID;
          this.creds.password = creds.password;
        }
        return this._initSession();
      })
      .then(() => {
        return resolve('Unlocked');
      })
      .catch((err) => {
        return reject(Error(`Error unlocking ${err}`));
      })
    })
  }

  addAccounts(n=1) {
    return this.__V1_getFirstAddress()
  }

  getAccounts() {
    return Promise.resolve(this.addresses[this.walletUID] || [])
  }

  signTransaction(address, transaction) { 
    return Promise.reject(Error('signTransaction not yet implemented'))
  }

  signMessage(address, data) {
    return Promise.reject(Error('signMessage not yet implemented'))  
  }

  exportAccount(address) {
    return Promise.reject(Error('exportAccount not supported by this device'))
  }

  // V1: Only one account per walletUID, so we reset the array to empty in the
  //    case of a match.
  removeAccount(address) {
    if (this.walletUID) {
      if (this.addresses[this.walletUID][0].toLowerCase() === address.toLowerCase())
        this.addresses[this.walletUID] = [];
    }
  }

  getFirstPage() {
    this.page = 0;
    return this._getPage(1);
  }

  getNextPage () {
    return this.getFirstPage();
    // return this._getPage(1)
  }

  getPreviousPage () {
    return this.getFirstPage();
    // return this._getPage(-1)
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
  // V1: Only return the first account
  __V1_getFirstAddress() {
    return new Promise((resolve, reject) => {
      this.unlock()
      .then(() => {
        return this._getAddress(1, 0)
      })
      .then((addrs) => {
        return resolve(addrs);
      })
      .catch((err) => {
        return reject(err);
      })
    })
  }

  _resetDefaults() {
    this.addresses = {};
    this.isLocked = true;
    this.creds = {
      deviceID: null,
      password: null,
    };
    this.walletUID = null;
    this.sdkSession = null;
    this.page = 0;
    this.unlockedAccount = 0;
  }

  _getCreds() {
    return new Promise((resolve, reject) => {
      // We only need to setup if we don't have a deviceID
      if (this._hasCreds())
        return resolve();

      // If we are not aware of what Lattice we should be talking to,
      // we need to open a window that lets the user go through the
      // pairing or connection process.
      const popup = window.open(`${CONNECT_URL}?keyring=true`);
      popup.postMessage('GET_LATTICE_CREDS', CONNECT_URL);

      // PostMessage handler
      function receiveMessage(event) {
        // Ensure origin
        if (event.origin !== CONNECT_URL)
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

  _initSession() {
    return new Promise((resolve, reject) => {
      try {
        const setupData = {
          name: 'Metamask',
          baseUrl: SIGNING_URL,
          crypto,
          timeout: 120000,
          privKey: this._genSessionKey(),
        }
        this.sdkSession = new SDK.Client(setupData);
        // Connect to the device
        this.sdkSession.connect(this.creds.deviceID, (err) => {
          if (err)
            return reject(`(connect) ${err}`);
          // Save the current wallet UID
          const activeWallet = this.sdkSession.getActiveWallet();
          if (!activeWallet || !activeWallet.uid)
            return reject("No active wallet");
          this.walletUID = activeWallet.uid.toString('hex');
          if (!this.addresses[this.walletUID])
            this.addresses[this.walletUID] = [];
          return resolve();
        });
      } catch (err) {
        return reject(err);
      }
    })
  }

  _getAddress(n=1, i=0) {
    return new Promise((resolve, reject) => {
      if (!this._hasSession())
        return reject('No SDK session started. Cannot fetch addresses.')

      // The Lattice does not allow for us to skip indices.
      if (i > this.addresses[this.walletUID].length)
        return reject(`Requested address is out of bounds. You may only request index <${this.addresses.length}`)

      // If we have already cached the address(es), we don't need to do it again
      if (this.addresses[this.walletUID].length > i)
        return resolve(this.addresses[this.walletUID].slice(i, n));
      
      // Make the request to get the requested address
      const addrData = { 
        currency: 'ETH', 
        startPath: [HARDENED_OFFSET+44, HARDENED_OFFSET+60, HARDENED_OFFSET, 0, i], 
        n, // Only request one at a time. This module only supports ETH, so no gap limits
      }
      this.sdkSession.getAddresses(addrData, (err, addrs) => {
        if (err)
          return reject(Error(`Error getting addresses: ${err}`));
        // Sanity check -- if this returned 0 addresses, handle the error
        if (addrs.length < 1)
          return reject('No addresses returned');
        // Add the address(es). This if statement should always get hit, as we do not
        // allow skipping indices and would have returned addresses upstream if `i` were
        // less than the array length
        if (i == this.addresses[this.walletUID].length)
          this.addresses[this.walletUID] = this.addresses[this.walletUID].concat(addrs)
        
        return resolve(this.addresses[this.walletUID])
      })
    })
  }

  _getPage(increment=1) {
    return new Promise((resolve, reject) => {
      this.page += increment;
      if (this.page <= 0)
        this.page = 1;
      const start = PER_PAGE * (this.page - 1);
      const to = PER_PAGE * this.page;

      this.unlock()
      .then(() => {
        // V1: Disabled
        // If we already have the addresses, use them them
        // if (this.addresses[this.walletUID].length >= to)
          // return Promise.resolve(this.addresses[this.walletUID].slice(start, to));
        
        // Otherwise we need to fetch them
        //-----------
        // V1: We will only support export of one (the first) address
        return this._getAddress(1, 0);
        // return this._getAddress(PER_PAGE, start);
        //-----------
      })
      .then((addrs) => {
        // Build some account objects from the addresses
        const localAccounts = [];
        addrs.forEach((addr, i) => {
          localAccounts.push({
            address: addr,
            balance: null,
            index: start + i,
          })
        })
        return resolve(localAccounts);
      })
      .catch((err) => {
        return reject(err);
      })
    })
  }

  _hasCreds() {
    return this.creds.deviceID !== null && this.creds.password !== null;
  }

  _hasSession() {
    return this.sdkSession && this.walletUID;
  }

  _genSessionKey() {
    if (!this._hasCreds())
      throw new Error('No credentials -- cannot create session key!');
    const buf = Buffer.concat([Buffer.from(this.creds.password), Buffer.from(this.creds.deviceID)])
    return crypto.createHash('sha256').update(buf).digest();
  }

}

LatticeKeyring.type = keyringType
module.exports = LatticeKeyring;