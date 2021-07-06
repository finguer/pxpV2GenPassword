
const md5 = require('crypto-js/md5');
const AES = require('crypto-js/aes');
const CryptoJS = require('crypto-js');
const Base64 = require('crypto-js/enc-base64');
const Utf8 = require('crypto-js/enc-utf8');
const Hex = require('crypto-js/enc-hex');
const { v4: uuidv4 } = require('uuid');



class Encryption {
  /**
   * @var integer Return encrypt method or Cipher method number. (128, 192, 256)
   */
  get encryptMethodLength() {
    var encryptMethod = this.encryptMethod;
    // get only number from string.
    // @link https://stackoverflow.com/a/10003709/128761 Reference.
    var aesNumber = encryptMethod.match(/\d+/)[0];
    return parseInt(aesNumber);
  }// encryptMethodLength


  /**
   * @var integer Return cipher method divide by 8. example: AES number 256 will be 256/8 = 32.
   */
  get encryptKeySize() {
    var aesNumber = this.encryptMethodLength;
    return parseInt(aesNumber / 8);
  }// encryptKeySize


  /**
   * @link http://php.net/manual/en/function.openssl-get-cipher-methods.php Refer to available methods in PHP if we are working between JS & PHP encryption.
   * @var string Cipher method.
   *              Recommended AES-128-CBC, AES-192-CBC, AES-256-CBC
   *              due to there is no `openssl_cipher_iv_length()` function in JavaScript
   *              and all of these methods are known as 16 in iv_length.
   */
  get encryptMethod() {
    return 'AES-256-CBC';
  }// encryptMethod


  /**
   * Decrypt string.
   *
   * @link https://stackoverflow.com/questions/41222162/encrypt-in-php-openssl-and-decrypt-in-javascript-cryptojs Reference.
   * @link https://stackoverflow.com/questions/25492179/decode-a-base64-string-using-cryptojs Crypto JS base64 encode/decode reference.
   * @param string encryptedString The encrypted string to be decrypt.
   * @param string key The key.
   * @return string Return decrypted string.
   */
  decrypt(encryptedString, key) {
    var json = JSON.parse(Utf8.stringify(Base64.parse(encryptedString)));

    var salt = Hex.parse(json.salt);
    var iv = Hex.parse(json.iv);

    var encrypted = json.ciphertext;// no need to base64 decode.

    var iterations = parseInt(json.iterations);
    if (iterations <= 0) {
      iterations = 999;
    }
    var encryptMethodLength = (this.encryptMethodLength / 4);// example: AES number is 256 / 4 = 64
    var hashKey = CryptoJS.PBKDF2(key, salt, { 'hasher': CryptoJS.algo.SHA512, 'keySize': (encryptMethodLength / 8), 'iterations': iterations });

    var decrypted = AES.decrypt(encrypted, hashKey, { 'mode': CryptoJS.mode.CBC, 'iv': iv });

    return decrypted.toString(Utf8);
  }// decrypt


  /**
   * Encrypt string.
   *
   * @link https://stackoverflow.com/questions/41222162/encrypt-in-php-openssl-and-decrypt-in-javascript-cryptojs Reference.
   * @link https://stackoverflow.com/questions/25492179/decode-a-base64-string-using-cryptojs Crypto JS base64 encode/decode reference.
   * @param string string The original string to be encrypt.
   * @param string key The key.
   * @return string Return encrypted string.
   */
  encrypt(string, key) {
    var iv = CryptoJS.lib.WordArray.random(16);// the reason to be 16, please read on `encryptMethod` property.

    var salt = CryptoJS.lib.WordArray.random(256);
    var iterations = 999;
    var encryptMethodLength = (this.encryptMethodLength / 4);// example: AES number is 256 / 4 = 64
    var hashKey = CryptoJS.PBKDF2(key, salt, { 'hasher': CryptoJS.algo.SHA512, 'keySize': (encryptMethodLength / 8), 'iterations': iterations });

    var encrypted = AES.encrypt(string, hashKey, { 'mode': CryptoJS.mode.CBC, 'iv': iv });
    var encryptedString = Base64.stringify(encrypted.ciphertext);

    var output = {
      'ciphertext': encryptedString,
      'iv': Hex.stringify(iv),
      'salt': Hex.stringify(salt),
      'iterations': iterations
    };

    return Base64.stringify(Utf8.parse(JSON.stringify(output)));
  }// encrypt
}



const prefix = uuidv4();
const enc = new Encryption();
const user = "favio.figueroa".normalize("NFD").replace(/[\u0300-\u036f]/g, "");//remove accents from user
const md5Pass = md5("favio.figueroa").toString();
const encrypted = enc.encrypt(prefix + '$$' + user, md5Pass);
console.log('encrypted',encrypted)
