unit Winapi.WinCrypt;

interface

uses
  Windows, Winapi.BCrypt, Winapi.NCrypt;

{$IF not DECLARED(size_t)}
type
  size_t = LONG_PTR;
  {$EXTERNALSYM size_t}
{$IFEND}


{$IF not DECLARED(LPVOID)}
type
  LPVOID = Pointer;
  {$EXTERNALSYM LPVOID}
{$IFEND}

{$IF not DECLARED(PCWSTR)}
type
  PCWSTR = PWideChar;
  {$EXTERNALSYM PCWSTR}
{$IFEND}

{$REGION 'wincrypt.h'}

{$MINENUMSIZE 4}
{$WARN SYMBOL_PLATFORM OFF}

//
// Algorithm IDs and Flags
//

// ALG_ID crackers
function GET_ALG_CLASS(x: Cardinal{ALG_ID}): Cardinal; inline;
{$EXTERNALSYM GET_ALG_CLASS}
function GET_ALG_TYPE(x: Cardinal{ALG_ID}): Cardinal; inline;
{$EXTERNALSYM GET_ALG_TYPE}
function GET_ALG_SID(x: Cardinal{ALG_ID}): Cardinal; inline;
{$EXTERNALSYM GET_ALG_SID}

// Algorithm classes
// certenrolld_begin -- ALG_CLASS_*
const
  ALG_CLASS_ANY                  = (0);
  {$EXTERNALSYM ALG_CLASS_ANY}
  ALG_CLASS_SIGNATURE            = (1 shl 13);
  {$EXTERNALSYM ALG_CLASS_SIGNATURE}
  ALG_CLASS_MSG_ENCRYPT          = (2 shl 13);
  {$EXTERNALSYM ALG_CLASS_MSG_ENCRYPT}
  ALG_CLASS_DATA_ENCRYPT         = (3 shl 13);
  {$EXTERNALSYM ALG_CLASS_DATA_ENCRYPT}
  ALG_CLASS_HASH                 = (4 shl 13);
  {$EXTERNALSYM ALG_CLASS_HASH}
  ALG_CLASS_KEY_EXCHANGE         = (5 shl 13);
  {$EXTERNALSYM ALG_CLASS_KEY_EXCHANGE}
  ALG_CLASS_ALL                  = (7 shl 13);
  {$EXTERNALSYM ALG_CLASS_ALL}
// certenrolld_end

// Algorithm types
const
  ALG_TYPE_ANY                   = (0);
  {$EXTERNALSYM ALG_TYPE_ANY}
  ALG_TYPE_DSS                   = (1 shl 9);
  {$EXTERNALSYM ALG_TYPE_DSS}
  ALG_TYPE_RSA                   = (2 shl 9);
  {$EXTERNALSYM ALG_TYPE_RSA}
  ALG_TYPE_BLOCK                 = (3 shl 9);
  {$EXTERNALSYM ALG_TYPE_BLOCK}
  ALG_TYPE_STREAM                = (4 shl 9);
  {$EXTERNALSYM ALG_TYPE_STREAM}
  ALG_TYPE_DH                    = (5 shl 9);
  {$EXTERNALSYM ALG_TYPE_DH}
  ALG_TYPE_SECURECHANNEL         = (6 shl 9);
  {$EXTERNALSYM ALG_TYPE_SECURECHANNEL}

// Generic sub-ids
const
  ALG_SID_ANY                    = (0);
  {$EXTERNALSYM ALG_SID_ANY}

// Some RSA sub-ids
const
  ALG_SID_RSA_ANY                = 0;
  {$EXTERNALSYM ALG_SID_RSA_ANY}
  ALG_SID_RSA_PKCS               = 1;
  {$EXTERNALSYM ALG_SID_RSA_PKCS}
  ALG_SID_RSA_MSATWORK           = 2;
  {$EXTERNALSYM ALG_SID_RSA_MSATWORK}
  ALG_SID_RSA_ENTRUST            = 3;
  {$EXTERNALSYM ALG_SID_RSA_ENTRUST}
  ALG_SID_RSA_PGP                = 4;
  {$EXTERNALSYM ALG_SID_RSA_PGP}

// Some DSS sub-ids
//
const
  ALG_SID_DSS_ANY                = 0;
  {$EXTERNALSYM ALG_SID_DSS_ANY}
  ALG_SID_DSS_PKCS               = 1;
  {$EXTERNALSYM ALG_SID_DSS_PKCS}
  ALG_SID_DSS_DMS                = 2;
  {$EXTERNALSYM ALG_SID_DSS_DMS}
  ALG_SID_ECDSA                  = 3;
  {$EXTERNALSYM ALG_SID_ECDSA}

// Block cipher sub ids
// DES sub_ids
const
  ALG_SID_DES                    = 1;
  {$EXTERNALSYM ALG_SID_DES}
  ALG_SID_3DES                   = 3;
  {$EXTERNALSYM ALG_SID_3DES}
  ALG_SID_DESX                   = 4;
  {$EXTERNALSYM ALG_SID_DESX}
  ALG_SID_IDEA                   = 5;
  {$EXTERNALSYM ALG_SID_IDEA}
  ALG_SID_CAST                   = 6;
  {$EXTERNALSYM ALG_SID_CAST}
  ALG_SID_SAFERSK64              = 7;
  {$EXTERNALSYM ALG_SID_SAFERSK64}
  ALG_SID_SAFERSK128             = 8;
  {$EXTERNALSYM ALG_SID_SAFERSK128}
  ALG_SID_3DES_112               = 9;
  {$EXTERNALSYM ALG_SID_3DES_112}
  ALG_SID_CYLINK_MEK             = 12;
  {$EXTERNALSYM ALG_SID_CYLINK_MEK}
  ALG_SID_RC5                    = 13;
  {$EXTERNALSYM ALG_SID_RC5}
  ALG_SID_AES_128                = 14;
  {$EXTERNALSYM ALG_SID_AES_128}
  ALG_SID_AES_192                = 15;
  {$EXTERNALSYM ALG_SID_AES_192}
  ALG_SID_AES_256                = 16;
  {$EXTERNALSYM ALG_SID_AES_256}
  ALG_SID_AES                    = 17;
  {$EXTERNALSYM ALG_SID_AES}

// Fortezza sub-ids
const
  ALG_SID_SKIPJACK               = 10;
  {$EXTERNALSYM ALG_SID_SKIPJACK}
  ALG_SID_TEK                    = 11;
  {$EXTERNALSYM ALG_SID_TEK}

// KP_MODE
const
  CRYPT_MODE_CBCI                = 6;       // ANSI CBC Interleaved
  {$EXTERNALSYM CRYPT_MODE_CBCI}
  CRYPT_MODE_CFBP                = 7;       // ANSI CFB Pipelined
  {$EXTERNALSYM CRYPT_MODE_CFBP}
  CRYPT_MODE_OFBP                = 8;       // ANSI OFB Pipelined
  {$EXTERNALSYM CRYPT_MODE_OFBP}
  CRYPT_MODE_CBCOFM              = 9;       // ANSI CBC + OF Masking
  {$EXTERNALSYM CRYPT_MODE_CBCOFM}
  CRYPT_MODE_CBCOFMI             = 10;      // ANSI CBC + OFM Interleaved
  {$EXTERNALSYM CRYPT_MODE_CBCOFMI}

// RC2 sub-ids
const
  ALG_SID_RC2                    = 2;
  {$EXTERNALSYM ALG_SID_RC2}

// Stream cipher sub-ids
const
  ALG_SID_RC4                    = 1;
  {$EXTERNALSYM ALG_SID_RC4}
  ALG_SID_SEAL                   = 2;
  {$EXTERNALSYM ALG_SID_SEAL}

// Diffie-Hellman sub-ids
const
  ALG_SID_DH_SANDF               = 1;
  {$EXTERNALSYM ALG_SID_DH_SANDF}
  ALG_SID_DH_EPHEM               = 2;
  {$EXTERNALSYM ALG_SID_DH_EPHEM}
  ALG_SID_AGREED_KEY_ANY         = 3;
  {$EXTERNALSYM ALG_SID_AGREED_KEY_ANY}
  ALG_SID_KEA                    = 4;
  {$EXTERNALSYM ALG_SID_KEA}
  ALG_SID_ECDH                   = 5;
  {$EXTERNALSYM ALG_SID_ECDH}

// Hash sub ids
const
  ALG_SID_MD2                    = 1;
  {$EXTERNALSYM ALG_SID_MD2}
  ALG_SID_MD4                    = 2;
  {$EXTERNALSYM ALG_SID_MD4}
  ALG_SID_MD5                    = 3;
  {$EXTERNALSYM ALG_SID_MD5}
  ALG_SID_SHA                    = 4;
  {$EXTERNALSYM ALG_SID_SHA}
  ALG_SID_SHA1                   = 4;
  {$EXTERNALSYM ALG_SID_SHA1}
  ALG_SID_MAC                    = 5;
  {$EXTERNALSYM ALG_SID_MAC}
  ALG_SID_RIPEMD                 = 6;
  {$EXTERNALSYM ALG_SID_RIPEMD}
  ALG_SID_RIPEMD160              = 7;
  {$EXTERNALSYM ALG_SID_RIPEMD160}
  ALG_SID_SSL3SHAMD5             = 8;
  {$EXTERNALSYM ALG_SID_SSL3SHAMD5}
  ALG_SID_HMAC                   = 9;
  {$EXTERNALSYM ALG_SID_HMAC}
  ALG_SID_TLS1PRF                = 10;
  {$EXTERNALSYM ALG_SID_TLS1PRF}
  ALG_SID_HASH_REPLACE_OWF       = 11;
  {$EXTERNALSYM ALG_SID_HASH_REPLACE_OWF}
  ALG_SID_SHA_256                = 12;
  {$EXTERNALSYM ALG_SID_SHA_256}
  ALG_SID_SHA_384                = 13;
  {$EXTERNALSYM ALG_SID_SHA_384}
  ALG_SID_SHA_512                = 14;
  {$EXTERNALSYM ALG_SID_SHA_512}

// secure channel sub ids
const
  ALG_SID_SSL3_MASTER            = 1;
  {$EXTERNALSYM ALG_SID_SSL3_MASTER}
  ALG_SID_SCHANNEL_MASTER_HASH   = 2;
  {$EXTERNALSYM ALG_SID_SCHANNEL_MASTER_HASH}
  ALG_SID_SCHANNEL_MAC_KEY       = 3;
  {$EXTERNALSYM ALG_SID_SCHANNEL_MAC_KEY}
  ALG_SID_PCT1_MASTER            = 4;
  {$EXTERNALSYM ALG_SID_PCT1_MASTER}
  ALG_SID_SSL2_MASTER            = 5;
  {$EXTERNALSYM ALG_SID_SSL2_MASTER}
  ALG_SID_TLS1_MASTER            = 6;
  {$EXTERNALSYM ALG_SID_TLS1_MASTER}
  ALG_SID_SCHANNEL_ENC_KEY       = 7;
  {$EXTERNALSYM ALG_SID_SCHANNEL_ENC_KEY}

// misc ECC sub ids
const
  ALG_SID_ECMQV                  = 1;
  {$EXTERNALSYM ALG_SID_ECMQV}


// Our silly example sub-id
const
  ALG_SID_EXAMPLE                = 80;
  {$EXTERNALSYM ALG_SID_EXAMPLE}

// certenrolls_begin -- PROV_ENUMALGS_EX
{$IF not DECLARED(ALG_ID)}
type
  ALG_ID = Cardinal;
  {$EXTERNALSYM ALG_ID}
{$IFEND}
// certenrolls_end

// algorithm identifier definitions
const
  CALG_MD2               = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD2);
  {$EXTERNALSYM CALG_MD2}
  CALG_MD4               = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD4);
  {$EXTERNALSYM CALG_MD4}
  CALG_MD5               = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD5);
  {$EXTERNALSYM CALG_MD5}
  CALG_SHA               = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA);
  {$EXTERNALSYM CALG_SHA}
  CALG_SHA1              = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA1);
  {$EXTERNALSYM CALG_SHA1}
  CALG_MAC               = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MAC);           // Deprecated. Don't use.
  {$EXTERNALSYM CALG_MAC}
  CALG_RSA_SIGN          = (ALG_CLASS_SIGNATURE or ALG_TYPE_RSA or ALG_SID_RSA_ANY);
  {$EXTERNALSYM CALG_RSA_SIGN}
  CALG_DSS_SIGN          = (ALG_CLASS_SIGNATURE or ALG_TYPE_DSS or ALG_SID_DSS_ANY);
  {$EXTERNALSYM CALG_DSS_SIGN}
  CALG_NO_SIGN           = (ALG_CLASS_SIGNATURE or ALG_TYPE_ANY or ALG_SID_ANY);
  {$EXTERNALSYM CALG_NO_SIGN}
  CALG_RSA_KEYX          = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_RSA or ALG_SID_RSA_ANY);
  {$EXTERNALSYM CALG_RSA_KEYX}
  CALG_DES               = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DES);
  {$EXTERNALSYM CALG_DES}
  CALG_3DES_112          = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES_112);
  {$EXTERNALSYM CALG_3DES_112}
  CALG_3DES              = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES);
  {$EXTERNALSYM CALG_3DES}
  CALG_DESX              = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DESX);
  {$EXTERNALSYM CALG_DESX}
  CALG_RC2               = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC2);
  {$EXTERNALSYM CALG_RC2}
  CALG_RC4               = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_RC4);
  {$EXTERNALSYM CALG_RC4}
  CALG_SEAL              = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_SEAL);
  {$EXTERNALSYM CALG_SEAL}
  CALG_DH_SF             = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_SANDF);
  {$EXTERNALSYM CALG_DH_SF}
  CALG_DH_EPHEM          = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_EPHEM);
  {$EXTERNALSYM CALG_DH_EPHEM}
  CALG_AGREEDKEY_ANY     = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_AGREED_KEY_ANY);
  {$EXTERNALSYM CALG_AGREEDKEY_ANY}
  CALG_KEA_KEYX          = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_KEA);
  {$EXTERNALSYM CALG_KEA_KEYX}
  CALG_HUGHES_MD5        = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_ANY or ALG_SID_MD5);
  {$EXTERNALSYM CALG_HUGHES_MD5}
  CALG_SKIPJACK          = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_SKIPJACK);
  {$EXTERNALSYM CALG_SKIPJACK}
  CALG_TEK               = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_TEK);
  {$EXTERNALSYM CALG_TEK}
  CALG_CYLINK_MEK        = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_CYLINK_MEK);  // Deprecated. Do not use
  {$EXTERNALSYM CALG_CYLINK_MEK}
  CALG_SSL3_SHAMD5       = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SSL3SHAMD5);
  {$EXTERNALSYM CALG_SSL3_SHAMD5}
  CALG_SSL3_MASTER       = (ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL3_MASTER);
  {$EXTERNALSYM CALG_SSL3_MASTER}
  CALG_SCHANNEL_MASTER_HASH  = (ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MASTER_HASH);
  {$EXTERNALSYM CALG_SCHANNEL_MASTER_HASH}
  CALG_SCHANNEL_MAC_KEY  = (ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MAC_KEY);
  {$EXTERNALSYM CALG_SCHANNEL_MAC_KEY}
  CALG_SCHANNEL_ENC_KEY  = (ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_ENC_KEY);
  {$EXTERNALSYM CALG_SCHANNEL_ENC_KEY}
  CALG_PCT1_MASTER       = (ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_PCT1_MASTER);
  {$EXTERNALSYM CALG_PCT1_MASTER}
  CALG_SSL2_MASTER       = (ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL2_MASTER);
  {$EXTERNALSYM CALG_SSL2_MASTER}
  CALG_TLS1_MASTER       = (ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_TLS1_MASTER);
  {$EXTERNALSYM CALG_TLS1_MASTER}
  CALG_RC5               = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC5);
  {$EXTERNALSYM CALG_RC5}
  CALG_HMAC              = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HMAC);
  {$EXTERNALSYM CALG_HMAC}
  CALG_TLS1PRF           = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_TLS1PRF);
  {$EXTERNALSYM CALG_TLS1PRF}
  CALG_HASH_REPLACE_OWF  = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HASH_REPLACE_OWF);
  {$EXTERNALSYM CALG_HASH_REPLACE_OWF}
  CALG_AES_128           = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_128);
  {$EXTERNALSYM CALG_AES_128}
  CALG_AES_192           = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_192);
  {$EXTERNALSYM CALG_AES_192}
  CALG_AES_256           = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_256);
  {$EXTERNALSYM CALG_AES_256}
  CALG_AES               = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES);
  {$EXTERNALSYM CALG_AES}
  CALG_SHA_256           = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_256);
  {$EXTERNALSYM CALG_SHA_256}
  CALG_SHA_384           = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_384);
  {$EXTERNALSYM CALG_SHA_384}
  CALG_SHA_512           = (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_512);
  {$EXTERNALSYM CALG_SHA_512}
  CALG_ECDH              = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_ECDH);
  {$EXTERNALSYM CALG_ECDH}
  CALG_ECMQV             = (ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_ANY or ALG_SID_ECMQV);
  {$EXTERNALSYM CALG_ECMQV}
  CALG_ECDSA             = (ALG_CLASS_SIGNATURE or ALG_TYPE_DSS or ALG_SID_ECDSA);
  {$EXTERNALSYM CALG_ECDSA}

// resource number for signatures in the CSP
const
  SIGNATURE_RESOURCE_NUMBER      = $29A;
  {$EXTERNALSYM SIGNATURE_RESOURCE_NUMBER}

type
  PVTableProvStruc = ^TVTableProvStruc;
  _VTableProvStruc = record
    Version: DWORD;
    FuncVerifyImage: FARPROC;
    FuncReturnhWnd: FARPROC;
    dwProvType: DWORD;
    pbContextInfo: PByte;
    cbContextInfo: DWORD;
    pszProvName: LPSTR;
  end;
  {$EXTERNALSYM _VTableProvStruc}
  VTableProvStruc = _VTableProvStruc;
  {$EXTERNALSYM VTableProvStruc}
  TVTableProvStruc = _VTableProvStruc;

// Used for certenroll.idl:
// certenrolls_begin -- HCRYPT*
{$IF not DECLARED(HCRYPTPROV)}
type
  HCRYPTPROV = ULONG_PTR;
  {$EXTERNALSYM HCRYPTPROV}
  HCRYPTKEY = ULONG_PTR;
  {$EXTERNALSYM HCRYPTKEY}
  HCRYPTHASH = ULONG_PTR;
  {$EXTERNALSYM HCRYPTHASH}
{$IFEND}

// certenrolls_end



// dwFlags definitions for CryptAcquireContext
const
  CRYPT_VERIFYCONTEXT    = $F0000000;
  {$EXTERNALSYM CRYPT_VERIFYCONTEXT}
  CRYPT_NEWKEYSET        = $00000008;
  {$EXTERNALSYM CRYPT_NEWKEYSET}
  CRYPT_DELETEKEYSET     = $00000010;
  {$EXTERNALSYM CRYPT_DELETEKEYSET}
  CRYPT_MACHINE_KEYSET   = $00000020;
  {$EXTERNALSYM CRYPT_MACHINE_KEYSET}
  CRYPT_SILENT           = $00000040;
  {$EXTERNALSYM CRYPT_SILENT}
  CRYPT_DEFAULT_CONTAINER_OPTIONAL = $00000080;
  {$EXTERNALSYM CRYPT_DEFAULT_CONTAINER_OPTIONAL}

// dwFlag definitions for CryptGenKey
const
  CRYPT_EXPORTABLE       = $00000001;
  {$EXTERNALSYM CRYPT_EXPORTABLE}
  CRYPT_USER_PROTECTED   = $00000002;
  {$EXTERNALSYM CRYPT_USER_PROTECTED}
  CRYPT_CREATE_SALT      = $00000004;
  {$EXTERNALSYM CRYPT_CREATE_SALT}
  CRYPT_UPDATE_KEY       = $00000008;
  {$EXTERNALSYM CRYPT_UPDATE_KEY}
  CRYPT_NO_SALT          = $00000010;
  {$EXTERNALSYM CRYPT_NO_SALT}
  CRYPT_PREGEN           = $00000040;
  {$EXTERNALSYM CRYPT_PREGEN}
  CRYPT_RECIPIENT        = $00000010;
  {$EXTERNALSYM CRYPT_RECIPIENT}
  CRYPT_INITIATOR        = $00000040;
  {$EXTERNALSYM CRYPT_INITIATOR}
  CRYPT_ONLINE           = $00000080;
  {$EXTERNALSYM CRYPT_ONLINE}
  CRYPT_SF               = $00000100;
  {$EXTERNALSYM CRYPT_SF}
  CRYPT_CREATE_IV        = $00000200;
  {$EXTERNALSYM CRYPT_CREATE_IV}
  CRYPT_KEK              = $00000400;
  {$EXTERNALSYM CRYPT_KEK}
  CRYPT_DATA_KEY         = $00000800;
  {$EXTERNALSYM CRYPT_DATA_KEY}
  CRYPT_VOLATILE         = $00001000;
  {$EXTERNALSYM CRYPT_VOLATILE}
  CRYPT_SGCKEY           = $00002000;
  {$EXTERNALSYM CRYPT_SGCKEY}
//PKCS12_ALLOW_OVERWRITE_KEY = $00004000;
//PKCS12_NO_PERSIST_KEY      = $00008000;
//should use other than these two
const
  CRYPT_USER_PROTECTED_STRONG = $00100000;
  {$EXTERNALSYM CRYPT_USER_PROTECTED_STRONG}
  CRYPT_ARCHIVABLE       = $00004000;
  {$EXTERNALSYM CRYPT_ARCHIVABLE}
  CRYPT_FORCE_KEY_PROTECTION_HIGH = $00008000;
  {$EXTERNALSYM CRYPT_FORCE_KEY_PROTECTION_HIGH}

  RSA1024BIT_KEY         = $04000000;
  {$EXTERNALSYM RSA1024BIT_KEY}

// dwFlags definitions for CryptDeriveKey
const
  CRYPT_SERVER           = $00000400;
  {$EXTERNALSYM CRYPT_SERVER}

  KEY_LENGTH_MASK        = $FFFF0000;
  {$EXTERNALSYM KEY_LENGTH_MASK}

// dwFlag definitions for CryptExportKey
const
  CRYPT_Y_ONLY           = $00000001;
  {$EXTERNALSYM CRYPT_Y_ONLY}
  CRYPT_SSL2_FALLBACK    = $00000002;
  {$EXTERNALSYM CRYPT_SSL2_FALLBACK}
  CRYPT_DESTROYKEY       = $00000004;
  {$EXTERNALSYM CRYPT_DESTROYKEY}
  CRYPT_OAEP             = $00000040;  // used with RSA encryptions/decryptions
  {$EXTERNALSYM CRYPT_OAEP}            // CryptExportKey, CryptImportKey,
                                       // CryptEncrypt and CryptDecrypt

  CRYPT_BLOB_VER3        = $00000080;  // export version 3 of a blob type
  {$EXTERNALSYM CRYPT_BLOB_VER3}
  CRYPT_IPSEC_HMAC_KEY   = $00000100;  // CryptImportKey only
  {$EXTERNALSYM CRYPT_IPSEC_HMAC_KEY}

// dwFlags definitions for CryptDecrypt
//  See also CRYPT_OAEP, above.
//  Note, the following flag is not supported for CryptEncrypt
const
  CRYPT_DECRYPT_RSA_NO_PADDING_CHECK     = $00000020;
  {$EXTERNALSYM CRYPT_DECRYPT_RSA_NO_PADDING_CHECK}

// dwFlags definitions for CryptCreateHash
const
  CRYPT_SECRETDIGEST     = $00000001;
  {$EXTERNALSYM CRYPT_SECRETDIGEST}

// dwFlags definitions for CryptHashData
const
  CRYPT_OWF_REPL_LM_HASH = $00000001;  // this is only for the OWF replacement CSP
  {$EXTERNALSYM CRYPT_OWF_REPL_LM_HASH}

// dwFlags definitions for CryptHashSessionKey
const
  CRYPT_LITTLE_ENDIAN    = $00000001;
  {$EXTERNALSYM CRYPT_LITTLE_ENDIAN}

// dwFlags definitions for CryptSignHash and CryptVerifySignature
const
  CRYPT_NOHASHOID        = $00000001;
  {$EXTERNALSYM CRYPT_NOHASHOID}
  CRYPT_TYPE2_FORMAT     = $00000002;  // Not supported
  {$EXTERNALSYM CRYPT_TYPE2_FORMAT}
  CRYPT_X931_FORMAT      = $00000004;  // Not supported
  {$EXTERNALSYM CRYPT_X931_FORMAT}

// dwFlag definitions for CryptSetProviderEx and CryptGetDefaultProvider
const
  CRYPT_MACHINE_DEFAULT  = $00000001;
  {$EXTERNALSYM CRYPT_MACHINE_DEFAULT}
  CRYPT_USER_DEFAULT     = $00000002;
  {$EXTERNALSYM CRYPT_USER_DEFAULT}
  CRYPT_DELETE_DEFAULT   = $00000004;
  {$EXTERNALSYM CRYPT_DELETE_DEFAULT}

// exported key blob definitions
// certenrolld_begin -- *BLOB
const
  SIMPLEBLOB             = $1;
  {$EXTERNALSYM SIMPLEBLOB}
  PUBLICKEYBLOB          = $6;
  {$EXTERNALSYM PUBLICKEYBLOB}
  PRIVATEKEYBLOB         = $7;
  {$EXTERNALSYM PRIVATEKEYBLOB}
  PLAINTEXTKEYBLOB       = $8;
  {$EXTERNALSYM PLAINTEXTKEYBLOB}
  OPAQUEKEYBLOB          = $9;
  {$EXTERNALSYM OPAQUEKEYBLOB}
  PUBLICKEYBLOBEX        = $A;
  {$EXTERNALSYM PUBLICKEYBLOBEX}
  SYMMETRICWRAPKEYBLOB   = $B;
  {$EXTERNALSYM SYMMETRICWRAPKEYBLOB}
  KEYSTATEBLOB           = $C;
  {$EXTERNALSYM KEYSTATEBLOB}
// certenrolld_end

// certenrolld_begin -- AT_*
const
  AT_KEYEXCHANGE         = 1;
  {$EXTERNALSYM AT_KEYEXCHANGE}
  AT_SIGNATURE           = 2;
  {$EXTERNALSYM AT_SIGNATURE}
// certenrolld_end
const
  CRYPT_USERDATA         = 1;
  {$EXTERNALSYM CRYPT_USERDATA}

// dwParam
const
  KP_IV                  = 1;       // Initialization vector
  {$EXTERNALSYM KP_IV}
  KP_SALT                = 2;       // Salt value
  {$EXTERNALSYM KP_SALT}
  KP_PADDING             = 3;       // Padding values
  {$EXTERNALSYM KP_PADDING}
  KP_MODE                = 4;       // Mode of the cipher
  {$EXTERNALSYM KP_MODE}
  KP_MODE_BITS           = 5;       // Number of bits to feedback
  {$EXTERNALSYM KP_MODE_BITS}
  KP_PERMISSIONS         = 6;       // Key permissions DWORD
  {$EXTERNALSYM KP_PERMISSIONS}
  KP_ALGID               = 7;       // Key algorithm
  {$EXTERNALSYM KP_ALGID}
  KP_BLOCKLEN            = 8;       // Block size of the cipher
  {$EXTERNALSYM KP_BLOCKLEN}
  KP_KEYLEN              = 9;       // Length of key in bits
  {$EXTERNALSYM KP_KEYLEN}
  KP_SALT_EX             = 10;      // Length of salt in bytes
  {$EXTERNALSYM KP_SALT_EX}
  KP_P                   = 11;      // DSS/Diffie-Hellman P value
  {$EXTERNALSYM KP_P}
  KP_G                   = 12;      // DSS/Diffie-Hellman G value
  {$EXTERNALSYM KP_G}
  KP_Q                   = 13;      // DSS Q value
  {$EXTERNALSYM KP_Q}
  KP_X                   = 14;      // Diffie-Hellman X value
  {$EXTERNALSYM KP_X}
  KP_Y                   = 15;      // Y value
  {$EXTERNALSYM KP_Y}
  KP_RA                  = 16;      // Fortezza RA value
  {$EXTERNALSYM KP_RA}
  KP_RB                  = 17;      // Fortezza RB value
  {$EXTERNALSYM KP_RB}
  KP_INFO                = 18;      // for putting information into an RSA envelope
  {$EXTERNALSYM KP_INFO}
  KP_EFFECTIVE_KEYLEN    = 19;      // setting and getting RC2 effective key length
  {$EXTERNALSYM KP_EFFECTIVE_KEYLEN}
  KP_SCHANNEL_ALG        = 20;      // for setting the Secure Channel algorithms
  {$EXTERNALSYM KP_SCHANNEL_ALG}
  KP_CLIENT_RANDOM       = 21;      // for setting the Secure Channel client random data
  {$EXTERNALSYM KP_CLIENT_RANDOM}
  KP_SERVER_RANDOM       = 22;      // for setting the Secure Channel server random data
  {$EXTERNALSYM KP_SERVER_RANDOM}
  KP_RP                  = 23;
  {$EXTERNALSYM KP_RP}
  KP_PRECOMP_MD5         = 24;
  {$EXTERNALSYM KP_PRECOMP_MD5}
  KP_PRECOMP_SHA         = 25;
  {$EXTERNALSYM KP_PRECOMP_SHA}
  KP_CERTIFICATE         = 26;      // for setting Secure Channel certificate data (PCT1)
  {$EXTERNALSYM KP_CERTIFICATE}
  KP_CLEAR_KEY           = 27;      // for setting Secure Channel clear key data (PCT1)
  {$EXTERNALSYM KP_CLEAR_KEY}
  KP_PUB_EX_LEN          = 28;
  {$EXTERNALSYM KP_PUB_EX_LEN}
  KP_PUB_EX_VAL          = 29;
  {$EXTERNALSYM KP_PUB_EX_VAL}
  KP_KEYVAL              = 30;
  {$EXTERNALSYM KP_KEYVAL}
  KP_ADMIN_PIN           = 31;
  {$EXTERNALSYM KP_ADMIN_PIN}
  KP_KEYEXCHANGE_PIN     = 32;
  {$EXTERNALSYM KP_KEYEXCHANGE_PIN}
  KP_SIGNATURE_PIN       = 33;
  {$EXTERNALSYM KP_SIGNATURE_PIN}
  KP_PREHASH             = 34;
  {$EXTERNALSYM KP_PREHASH}
  KP_ROUNDS              = 35;
  {$EXTERNALSYM KP_ROUNDS}
  KP_OAEP_PARAMS         = 36;      // for setting OAEP params on RSA keys
  {$EXTERNALSYM KP_OAEP_PARAMS}
  KP_CMS_KEY_INFO        = 37;
  {$EXTERNALSYM KP_CMS_KEY_INFO}
  KP_CMS_DH_KEY_INFO     = 38;
  {$EXTERNALSYM KP_CMS_DH_KEY_INFO}
  KP_PUB_PARAMS          = 39;      // for setting public parameters
  {$EXTERNALSYM KP_PUB_PARAMS}
  KP_VERIFY_PARAMS       = 40;      // for verifying DSA and DH parameters
  {$EXTERNALSYM KP_VERIFY_PARAMS}
  KP_HIGHEST_VERSION     = 41;      // for TLS protocol version setting
  {$EXTERNALSYM KP_HIGHEST_VERSION}
  KP_GET_USE_COUNT       = 42;      // for use with PP_CRYPT_COUNT_KEY_USE contexts
  {$EXTERNALSYM KP_GET_USE_COUNT}
  KP_PIN_ID              = 43;
  {$EXTERNALSYM KP_PIN_ID}
  KP_PIN_INFO            = 44;
  {$EXTERNALSYM KP_PIN_INFO}

// KP_PADDING
const
  PKCS5_PADDING          = 1;       // PKCS 5 (sec 6.2) padding method
  {$EXTERNALSYM PKCS5_PADDING}
  RANDOM_PADDING         = 2;
  {$EXTERNALSYM RANDOM_PADDING}
  ZERO_PADDING           = 3;
  {$EXTERNALSYM ZERO_PADDING}

// KP_MODE
const
  CRYPT_MODE_CBC         = 1;       // Cipher block chaining
  {$EXTERNALSYM CRYPT_MODE_CBC}
  CRYPT_MODE_ECB         = 2;       // Electronic code book
  {$EXTERNALSYM CRYPT_MODE_ECB}
  CRYPT_MODE_OFB         = 3;       // Output feedback mode
  {$EXTERNALSYM CRYPT_MODE_OFB}
  CRYPT_MODE_CFB         = 4;       // Cipher feedback mode
  {$EXTERNALSYM CRYPT_MODE_CFB}
  CRYPT_MODE_CTS         = 5;       // Ciphertext stealing mode
  {$EXTERNALSYM CRYPT_MODE_CTS}

// KP_PERMISSIONS
const
  CRYPT_ENCRYPT          = $0001;  // Allow encryption
  {$EXTERNALSYM CRYPT_ENCRYPT}
  CRYPT_DECRYPT          = $0002;  // Allow decryption
  {$EXTERNALSYM CRYPT_DECRYPT}
  CRYPT_EXPORT           = 40004;  // Allow key to be exported
  {$EXTERNALSYM CRYPT_EXPORT}
  CRYPT_READ             = $0008;  // Allow parameters to be read
  {$EXTERNALSYM CRYPT_READ}
  CRYPT_WRITE            = $0010;  // Allow parameters to be set
  {$EXTERNALSYM CRYPT_WRITE}
  CRYPT_MAC              = $0020;  // Allow MACs to be used with key
  {$EXTERNALSYM CRYPT_MAC}
  CRYPT_EXPORT_KEY       = $0040;  // Allow key to be used for exporting keys
  {$EXTERNALSYM CRYPT_EXPORT_KEY}
  CRYPT_IMPORT_KEY       = $0080;  // Allow key to be used for importing keys
  {$EXTERNALSYM CRYPT_IMPORT_KEY}
  CRYPT_ARCHIVE          = $0100;  // Allow key to be exported at creation only
  {$EXTERNALSYM CRYPT_ARCHIVE}

  HP_ALGID               = $0001;  // Hash algorithm
  {$EXTERNALSYM HP_ALGID}
  HP_HASHVAL             = $0002;  // Hash value
  {$EXTERNALSYM HP_HASHVAL}
  HP_HASHSIZE            = $0004;  // Hash value size
  {$EXTERNALSYM HP_HASHSIZE}
  HP_HMAC_INFO           = $0005;  // information for creating an HMAC
  {$EXTERNALSYM HP_HMAC_INFO}
  HP_TLS1PRF_LABEL       = $0006;  // label for TLS1 PRF
  {$EXTERNALSYM HP_TLS1PRF_LABEL}
  HP_TLS1PRF_SEED        = $0007;  // seed for TLS1 PRF
  {$EXTERNALSYM HP_TLS1PRF_SEED}

  CRYPT_FAILED           = BOOL(False);
  {$EXTERNALSYM CRYPT_FAILED}
  CRYPT_SUCCEED          = BOOL(True);
  {$EXTERNALSYM CRYPT_SUCCEED}

function RCRYPT_SUCCEEDED(rt: BOOL): Boolean; inline;
{$EXTERNALSYM RCRYPT_SUCCEEDED}
function RCRYPT_FAILED(rt: BOOL): Boolean; inline;
{$EXTERNALSYM RCRYPT_FAILED}

//
// CryptGetProvParam
//
const
  PP_ENUMALGS            = 1;
  {$EXTERNALSYM PP_ENUMALGS}
  PP_ENUMCONTAINERS      = 2;
  {$EXTERNALSYM PP_ENUMCONTAINERS}
  PP_IMPTYPE             = 3;
  {$EXTERNALSYM PP_IMPTYPE}
  PP_NAME                = 4;
  {$EXTERNALSYM PP_NAME}
  PP_VERSION             = 5;
  {$EXTERNALSYM PP_VERSION}
  PP_CONTAINER           = 6;
  {$EXTERNALSYM PP_CONTAINER}
  PP_CHANGE_PASSWORD     = 7;
  {$EXTERNALSYM PP_CHANGE_PASSWORD}
  PP_KEYSET_SEC_DESCR    = 8;       // get/set security descriptor of keyset
  {$EXTERNALSYM PP_KEYSET_SEC_DESCR}
  PP_CERTCHAIN           = 9;       // for retrieving certificates from tokens
  {$EXTERNALSYM PP_CERTCHAIN}
  PP_KEY_TYPE_SUBTYPE    = 10;
  {$EXTERNALSYM PP_KEY_TYPE_SUBTYPE}
  PP_PROVTYPE            = 16;
  {$EXTERNALSYM PP_PROVTYPE}
  PP_KEYSTORAGE          = 17;
  {$EXTERNALSYM PP_KEYSTORAGE}
  PP_APPLI_CERT          = 18;
  {$EXTERNALSYM PP_APPLI_CERT}
  PP_SYM_KEYSIZE         = 19;
  {$EXTERNALSYM PP_SYM_KEYSIZE}
  PP_SESSION_KEYSIZE     = 20;
  {$EXTERNALSYM PP_SESSION_KEYSIZE}
  PP_UI_PROMPT           = 21;
  {$EXTERNALSYM PP_UI_PROMPT}
  PP_ENUMALGS_EX         = 22;
  {$EXTERNALSYM PP_ENUMALGS_EX}
  PP_ENUMMANDROOTS       = 25;
  {$EXTERNALSYM PP_ENUMMANDROOTS}
  PP_ENUMELECTROOTS      = 26;
  {$EXTERNALSYM PP_ENUMELECTROOTS}
  PP_KEYSET_TYPE         = 27;
  {$EXTERNALSYM PP_KEYSET_TYPE}
  PP_ADMIN_PIN           = 31;
  {$EXTERNALSYM PP_ADMIN_PIN}
  PP_KEYEXCHANGE_PIN     = 32;
  {$EXTERNALSYM PP_KEYEXCHANGE_PIN}
  PP_SIGNATURE_PIN       = 33;
  {$EXTERNALSYM PP_SIGNATURE_PIN}
  PP_SIG_KEYSIZE_INC     = 34;
  {$EXTERNALSYM PP_SIG_KEYSIZE_INC}
  PP_KEYX_KEYSIZE_INC    = 35;
  {$EXTERNALSYM PP_KEYX_KEYSIZE_INC}
  PP_UNIQUE_CONTAINER    = 36;
  {$EXTERNALSYM PP_UNIQUE_CONTAINER}
  PP_SGC_INFO            = 37;
  {$EXTERNALSYM PP_SGC_INFO}
  PP_USE_HARDWARE_RNG    = 38;
  {$EXTERNALSYM PP_USE_HARDWARE_RNG}
  PP_KEYSPEC             = 39;
  {$EXTERNALSYM PP_KEYSPEC}
  PP_ENUMEX_SIGNING_PROT = 40;
  {$EXTERNALSYM PP_ENUMEX_SIGNING_PROT}
  PP_CRYPT_COUNT_KEY_USE = 41;
  {$EXTERNALSYM PP_CRYPT_COUNT_KEY_USE}
  PP_USER_CERTSTORE      = 42;
  {$EXTERNALSYM PP_USER_CERTSTORE}
  PP_SMARTCARD_READER    = 43;
  {$EXTERNALSYM PP_SMARTCARD_READER}
  PP_SMARTCARD_GUID      = 45;
  {$EXTERNALSYM PP_SMARTCARD_GUID}
  PP_ROOT_CERTSTORE      = 46;
  {$EXTERNALSYM PP_ROOT_CERTSTORE}
  PP_SMARTCARD_READER_ICON = 47;
  {$EXTERNALSYM PP_SMARTCARD_READER_ICON}

  CRYPT_FIRST            = 1;
  {$EXTERNALSYM CRYPT_FIRST}
  CRYPT_NEXT             = 2;
  {$EXTERNALSYM CRYPT_NEXT}
  CRYPT_SGC_ENUM         = 4;
  {$EXTERNALSYM CRYPT_SGC_ENUM}

  CRYPT_IMPL_HARDWARE    = 1;
  {$EXTERNALSYM CRYPT_IMPL_HARDWARE}
  CRYPT_IMPL_SOFTWARE    = 2;
  {$EXTERNALSYM CRYPT_IMPL_SOFTWARE}
  CRYPT_IMPL_MIXED       = 3;
  {$EXTERNALSYM CRYPT_IMPL_MIXED}
  CRYPT_IMPL_UNKNOWN     = 4;
  {$EXTERNALSYM CRYPT_IMPL_UNKNOWN}
  CRYPT_IMPL_REMOVABLE   = 8;
  {$EXTERNALSYM CRYPT_IMPL_REMOVABLE}

// key storage flags
const
  CRYPT_SEC_DESCR        = $00000001;
  {$EXTERNALSYM CRYPT_SEC_DESCR}
  CRYPT_PSTORE           = $00000002;
  {$EXTERNALSYM CRYPT_PSTORE}
  CRYPT_UI_PROMPT        = $00000004;
  {$EXTERNALSYM CRYPT_UI_PROMPT}

// protocol flags
const
  CRYPT_FLAG_PCT1        = $0001;
  {$EXTERNALSYM CRYPT_FLAG_PCT1}
  CRYPT_FLAG_SSL2        = $0002;
  {$EXTERNALSYM CRYPT_FLAG_SSL2}
  CRYPT_FLAG_SSL3        = $0004;
  {$EXTERNALSYM CRYPT_FLAG_SSL3}
  CRYPT_FLAG_TLS1        = $0008;
  {$EXTERNALSYM CRYPT_FLAG_TLS1}
  CRYPT_FLAG_IPSEC       = $0010;
  {$EXTERNALSYM CRYPT_FLAG_IPSEC}
  CRYPT_FLAG_SIGNING     = $0020;
  {$EXTERNALSYM CRYPT_FLAG_SIGNING}

// SGC flags
const
  CRYPT_SGC              = $0001;
  {$EXTERNALSYM CRYPT_SGC}
  CRYPT_FASTSGC          = $0002;
  {$EXTERNALSYM CRYPT_FASTSGC}

//
// CryptSetProvParam
//
const
  PP_CLIENT_HWND         = 1;
  {$EXTERNALSYM PP_CLIENT_HWND}
  PP_CONTEXT_INFO        = 11;
  {$EXTERNALSYM PP_CONTEXT_INFO}
  PP_KEYEXCHANGE_KEYSIZE = 12;
  {$EXTERNALSYM PP_KEYEXCHANGE_KEYSIZE}
  PP_SIGNATURE_KEYSIZE   = 13;
  {$EXTERNALSYM PP_SIGNATURE_KEYSIZE}
  PP_KEYEXCHANGE_ALG     = 14;
  {$EXTERNALSYM PP_KEYEXCHANGE_ALG}
  PP_SIGNATURE_ALG       = 15;
  {$EXTERNALSYM PP_SIGNATURE_ALG}
  PP_DELETEKEY           = 24;
  {$EXTERNALSYM PP_DELETEKEY}
  PP_PIN_PROMPT_STRING      = 44;
  {$EXTERNALSYM PP_PIN_PROMPT_STRING}
  PP_SECURE_KEYEXCHANGE_PIN = 47;
  {$EXTERNALSYM PP_SECURE_KEYEXCHANGE_PIN}
  PP_SECURE_SIGNATURE_PIN   = 48;
  {$EXTERNALSYM PP_SECURE_SIGNATURE_PIN}

// certenrolld_begin -- PROV_RSA_*
const
  PROV_RSA_FULL          = 1;
  {$EXTERNALSYM PROV_RSA_FULL}
  PROV_RSA_SIG           = 2;
  {$EXTERNALSYM PROV_RSA_SIG}
  PROV_DSS               = 3;
  {$EXTERNALSYM PROV_DSS}
  PROV_FORTEZZA          = 4;
  {$EXTERNALSYM PROV_FORTEZZA}
  PROV_MS_EXCHANGE       = 5;
  {$EXTERNALSYM PROV_MS_EXCHANGE}
  PROV_SSL               = 6;
  {$EXTERNALSYM PROV_SSL}
  PROV_RSA_SCHANNEL      = 12;
  {$EXTERNALSYM PROV_RSA_SCHANNEL}
  PROV_DSS_DH            = 13;
  {$EXTERNALSYM PROV_DSS_DH}
  PROV_EC_ECDSA_SIG      = 14;
  {$EXTERNALSYM PROV_EC_ECDSA_SIG}
  PROV_EC_ECNRA_SIG      = 15;
  {$EXTERNALSYM PROV_EC_ECNRA_SIG}
  PROV_EC_ECDSA_FULL     = 16;
  {$EXTERNALSYM PROV_EC_ECDSA_FULL}
  PROV_EC_ECNRA_FULL     = 17;
  {$EXTERNALSYM PROV_EC_ECNRA_FULL}
  PROV_DH_SCHANNEL       = 18;
  {$EXTERNALSYM PROV_DH_SCHANNEL}
  PROV_SPYRUS_LYNKS      = 20;
  {$EXTERNALSYM PROV_SPYRUS_LYNKS}
  PROV_RNG               = 21;
  {$EXTERNALSYM PROV_RNG}
  PROV_INTEL_SEC         = 22;
  {$EXTERNALSYM PROV_INTEL_SEC}
  PROV_REPLACE_OWF       = 23;
  {$EXTERNALSYM PROV_REPLACE_OWF}
  PROV_RSA_AES           = 24;
  {$EXTERNALSYM PROV_RSA_AES}
// certenrolld_end

//
// STT defined Providers
//
const
  PROV_STT_MER           = 7;
  {$EXTERNALSYM PROV_STT_MER}
  PROV_STT_ACQ           = 8;
  {$EXTERNALSYM PROV_STT_ACQ}
  PROV_STT_BRND          = 9;
  {$EXTERNALSYM PROV_STT_BRND}
  PROV_STT_ROOT          = 10;
  {$EXTERNALSYM PROV_STT_ROOT}
  PROV_STT_ISS           = 11;
  {$EXTERNALSYM PROV_STT_ISS}

//
// Provider friendly names
//
const
  MS_DEF_PROV_A          = 'Microsoft Base Cryptographic Provider v1.0';
  {$EXTERNALSYM MS_DEF_PROV_A}
  MS_DEF_PROV_W          = 'Microsoft Base Cryptographic Provider v1.0';
  {$EXTERNALSYM MS_DEF_PROV_W}
  MS_DEF_PROV            = MS_DEF_PROV_W;
  {$EXTERNALSYM MS_DEF_PROV}

  MS_ENHANCED_PROV_A     = 'Microsoft Enhanced Cryptographic Provider v1.0';
  {$EXTERNALSYM MS_ENHANCED_PROV_A}
  MS_ENHANCED_PROV_W     = 'Microsoft Enhanced Cryptographic Provider v1.0';
  {$EXTERNALSYM MS_ENHANCED_PROV_W}
  MS_ENHANCED_PROV       = MS_ENHANCED_PROV_W;
  {$EXTERNALSYM MS_ENHANCED_PROV}

  MS_STRONG_PROV_A       = 'Microsoft Strong Cryptographic Provider';
  {$EXTERNALSYM MS_STRONG_PROV_A}
  MS_STRONG_PROV_W       = 'Microsoft Strong Cryptographic Provider';
  {$EXTERNALSYM MS_STRONG_PROV_W}
  MS_STRONG_PROV         = MS_STRONG_PROV_W;
  {$EXTERNALSYM MS_STRONG_PROV}

  MS_DEF_RSA_SIG_PROV_A  = 'Microsoft RSA Signature Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_RSA_SIG_PROV_A}
  MS_DEF_RSA_SIG_PROV_W  = 'Microsoft RSA Signature Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_RSA_SIG_PROV_W}
  MS_DEF_RSA_SIG_PROV    = MS_DEF_RSA_SIG_PROV_W;
  {$EXTERNALSYM MS_DEF_RSA_SIG_PROV}

  MS_DEF_RSA_SCHANNEL_PROV_A = 'Microsoft RSA SChannel Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_RSA_SCHANNEL_PROV_A}
  MS_DEF_RSA_SCHANNEL_PROV_W = 'Microsoft RSA SChannel Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_RSA_SCHANNEL_PROV_W}
  MS_DEF_RSA_SCHANNEL_PROV   = MS_DEF_RSA_SCHANNEL_PROV_W;
  {$EXTERNALSYM MS_DEF_RSA_SCHANNEL_PROV}

  MS_DEF_DSS_PROV_A      = 'Microsoft Base DSS Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_DSS_PROV_A}
  MS_DEF_DSS_PROV_W      = 'Microsoft Base DSS Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_DSS_PROV_W}
  MS_DEF_DSS_PROV        = MS_DEF_DSS_PROV_W;
  {$EXTERNALSYM MS_DEF_DSS_PROV}

  MS_DEF_DSS_DH_PROV_A   = 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_DSS_DH_PROV_A}
  MS_DEF_DSS_DH_PROV_W   = 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_DSS_DH_PROV_W}
  MS_DEF_DSS_DH_PROV     = MS_DEF_DSS_DH_PROV_W;
  {$EXTERNALSYM MS_DEF_DSS_DH_PROV}

  MS_ENH_DSS_DH_PROV_A   = 'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider';
  {$EXTERNALSYM MS_ENH_DSS_DH_PROV_A}
  MS_ENH_DSS_DH_PROV_W   = 'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider';
  {$EXTERNALSYM MS_ENH_DSS_DH_PROV_W}
  MS_ENH_DSS_DH_PROV     = MS_ENH_DSS_DH_PROV_W;
  {$EXTERNALSYM MS_ENH_DSS_DH_PROV}

  MS_DEF_DH_SCHANNEL_PROV_A = 'Microsoft DH SChannel Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_DH_SCHANNEL_PROV_A}
  MS_DEF_DH_SCHANNEL_PROV_W = 'Microsoft DH SChannel Cryptographic Provider';
  {$EXTERNALSYM MS_DEF_DH_SCHANNEL_PROV_W}
  MS_DEF_DH_SCHANNEL_PROV   = MS_DEF_DH_SCHANNEL_PROV_W;
  {$EXTERNALSYM MS_DEF_DH_SCHANNEL_PROV}

  MS_SCARD_PROV_A        = 'Microsoft Base Smart Card Crypto Provider';
  {$EXTERNALSYM MS_SCARD_PROV_A}
  MS_SCARD_PROV_W        = 'Microsoft Base Smart Card Crypto Provider';
  {$EXTERNALSYM MS_SCARD_PROV_W}
  MS_SCARD_PROV          = MS_SCARD_PROV_W;
  {$EXTERNALSYM MS_SCARD_PROV}

  MS_ENH_RSA_AES_PROV_A  = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
  {$EXTERNALSYM MS_ENH_RSA_AES_PROV_A}
  MS_ENH_RSA_AES_PROV_W  = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
  {$EXTERNALSYM MS_ENH_RSA_AES_PROV_W}
  MS_ENH_RSA_AES_PROV_XP_A = 'Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)';
  {$EXTERNALSYM MS_ENH_RSA_AES_PROV_XP_A}
  MS_ENH_RSA_AES_PROV_XP_W = 'Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)';
  {$EXTERNALSYM MS_ENH_RSA_AES_PROV_XP_W}
  MS_ENH_RSA_AES_PROV_XP = MS_ENH_RSA_AES_PROV_XP_W;
  {$EXTERNALSYM MS_ENH_RSA_AES_PROV_XP}
  MS_ENH_RSA_AES_PROV    = MS_ENH_RSA_AES_PROV_W;
  {$EXTERNALSYM MS_ENH_RSA_AES_PROV}

  MAXUIDLEN              = 64;
  {$EXTERNALSYM MAXUIDLEN}

// Exponentiation Offload Reg Location
const
  EXPO_OFFLOAD_REG_VALUE = 'ExpoOffload';
  {$EXTERNALSYM EXPO_OFFLOAD_REG_VALUE}
  EXPO_OFFLOAD_FUNC_NAME = 'OffloadModExpo';
  {$EXTERNALSYM EXPO_OFFLOAD_FUNC_NAME}

//
// Registry key in which the following private key-related
// values are created.
//
{$IF not DECLARED(szKEY_CRYPTOAPI_PRIVATE_KEY_OPTIONS)}
const
  szKEY_CRYPTOAPI_PRIVATE_KEY_OPTIONS = 'Software\Policies\Microsoft\Cryptography';
  {$EXTERNALSYM szKEY_CRYPTOAPI_PRIVATE_KEY_OPTIONS}
{$IFEND}

//
// Registry values for enabling and controlling the caching (and timeout)
// of private keys.  This feature is intended for UI-protected private
// keys.
//
// Note that in Windows 2000 and later, private keys, once read from storage,
// are cached in the associated HCRYPTPROV structure for subsequent use.
//
// In Server 2003 and XP SP1, new key caching behavior is available.  Keys
// that have been read from storage and cached may now be considered "stale"
// if a period of time has elapsed since the key was last used.  This forces
// the key to be re-read from storage (which will make the DPAPI UI appear
// again).
//
// Optional Key Timeouts:
//
// In Windows Server 2003, XP SP1, and later, new key caching behavior is
// available.  Keys that have been read from storage and cached per-context
// may now be considered "stale" if a period of time has elapsed since the
// key was last used.  This forces the key to be re-read from storage (which
// will make the Data Protection API dialog appear again if the key is
// UI-protected).
//
// To enable the new behavior, create the registry DWORD value
// szKEY_CACHE_ENABLED and set it to 1.  The registry DWORD value
// szKEY_CACHE_SECONDS must also be created and set to the number of seconds
// that a cached private key may still be considered usable.
//
const
  szKEY_CACHE_ENABLED                    = 'CachePrivateKeys';
  {$EXTERNALSYM szKEY_CACHE_ENABLED}
  szKEY_CACHE_SECONDS                    = 'PrivateKeyLifetimeSeconds';
  {$EXTERNALSYM szKEY_CACHE_SECONDS}

//
// In platforms later than (and not including) Windows Server 2003, private
// keys are always cached for a period of time per-process, even when
// not being used in any context.
//
// The differences between the process-wide caching settings described below
// and the Optional Key Timeouts described above are subtle.
//
//  - The Optional Key Timeout policy is applied only when an attempt is made
//    to use a specific private key with an open context handle (HCRYPTPROV).
//    If szKEY_CACHE_SECONDS have elapsed since the key was last used, the
//    private key will be re-read from storage.
//
//  - The Cache Purge Interval policy, below, is applied whenever any
//    non-ephemeral private key is used or read from storage.  If
//    szPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS have elapsed since the last
//    purge occurred, all cached keys that have not been referenced since the
//    last purge will be removed from the cache.
//
//    If a private key that is purged from the cache is currently
//    referenced in an open context, then the key will be re-read from storage
//    the next time an attempt is made to use it (via any context).
//
// The following two registry DWORD values control this behavior.
//

//
// Registry value for controlling the maximum number of persisted
// (non-ephemeral) private keys that can be cached per-process.  If the cache
// fills up, keys will be replaced on a least-recently-used basis.  If the
// maximum number of cached keys is set to zero, no keys will be globally
// cached.
//
const
  szPRIV_KEY_CACHE_MAX_ITEMS             = 'PrivKeyCacheMaxItems';
  {$EXTERNALSYM szPRIV_KEY_CACHE_MAX_ITEMS}
  cPRIV_KEY_CACHE_MAX_ITEMS_DEFAULT      = 20;
  {$EXTERNALSYM cPRIV_KEY_CACHE_MAX_ITEMS_DEFAULT}

//
// Registry value for controlling the interval at which the private key
// cache is proactively purged of outdated keys.
//
const
  szPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS = 'PrivKeyCachePurgeIntervalSeconds';
  {$EXTERNALSYM szPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS}
  cPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS_DEFAULT = 86400; // 1 day
  {$EXTERNALSYM cPRIV_KEY_CACHE_PURGE_INTERVAL_SECONDS_DEFAULT}

  CUR_BLOB_VERSION       = 2;
  {$EXTERNALSYM CUR_BLOB_VERSION}

// structure for use with CryptSetKeyParam for CMS keys
// DO NOT USE THIS STRUCTURE!!!!!
type
  PCMSKeyInfo = ^TCMSKeyInfo;
  _CMS_KEY_INFO = record
    dwVersion: DWORD;                             // sizeof(CMS_KEY_INFO)
    Algid: ALG_ID;                                // algorithmm id for the key to be converted
    pbOID: PBYTE;                                 // pointer to OID to hash in with Z
    cbOID: DWORD;                                 // length of OID to hash in with Z
  end;
  {$EXTERNALSYM _CMS_KEY_INFO}
  CMS_KEY_INFO = _CMS_KEY_INFO;
  {$EXTERNALSYM CMS_KEY_INFO}
  TCMSKeyInfo = _CMS_KEY_INFO;
  PCMS_KEY_INFO = PCMSKeyInfo;
  {$EXTERNALSYM PCMS_KEY_INFO}

// structure for use with CryptSetHashParam with CALG_HMAC
type
  PHMACInfo = ^THMACInfo;
  _HMAC_Info = record
    HashAlgid: ALG_ID;
    pbInnerString: PBYTE;
    cbInnerString: DWORD;
    pbOuterString: PBYTE;
    cbOuterString: DWORD;
  end;
  {$EXTERNALSYM _HMAC_Info}
  HMAC_INFO = _HMAC_Info;
  {$EXTERNALSYM HMAC_INFO}
  THMACInfo = _HMAC_Info;
  PHMAC_INFO = PHMACInfo;
  {$EXTERNALSYM PHMAC_INFO}

// structure for use with CryptSetKeyParam with KP_SCHANNEL_ALG
type
  PSChannelAlg = ^TSChannelAlg;
  _SCHANNEL_ALG = record
    dwUse: DWORD;
    Algid: ALG_ID;
    cBits: DWORD;
    dwFlags: DWORD;
    dwReserved: DWORD;
  end;
  {$EXTERNALSYM _SCHANNEL_ALG}
  SCHANNEL_ALG = _SCHANNEL_ALG;
  {$EXTERNALSYM SCHANNEL_ALG}
  TSChannelAlg = _SCHANNEL_ALG;
  PSCHANNEL_ALG = PSChannelAlg;
  {$EXTERNALSYM PSCHANNEL_ALG}

// uses of algortihms for SCHANNEL_ALG structure
const
  SCHANNEL_MAC_KEY    = $00000000;
  {$EXTERNALSYM SCHANNEL_MAC_KEY}
  SCHANNEL_ENC_KEY    = $00000001;
  {$EXTERNALSYM SCHANNEL_ENC_KEY}

// uses of dwFlags SCHANNEL_ALG structure
const
  INTERNATIONAL_USAGE = $00000001;
  {$EXTERNALSYM INTERNATIONAL_USAGE}

type
  PProvEnumAlgs = ^TProvEnumAlgs;
  _PROV_ENUMALGS = record
    aiAlgid: ALG_ID;
    dwBitLen: DWORD;
    dwNameLen: DWORD;
    szName: array [0..19] of AnsiChar;
  end;
  {$EXTERNALSYM _PROV_ENUMALGS}
  PROV_ENUMALGS = _PROV_ENUMALGS;
  {$EXTERNALSYM PROV_ENUMALGS}
  TProvEnumAlgs = _PROV_ENUMALGS;

// certenrolls_begin -- PROV_ENUMALGS_EX
type
  PProvEnumAlgsEx = ^TProvEnumAlgsEx;
  _PROV_ENUMALGS_EX = record
    aiAlgid: ALG_ID;
    dwDefaultLen: DWORD;
    dwMinLen: DWORD;
    dwMaxLen: DWORD;
    dwProtocols: DWORD;
    dwNameLen: DWORD;
    szName: array [0..19] of AnsiChar;
    dwLongNameLen: DWORD;
    szLongName: array [0..39] of AnsiChar;
  end;
  {$EXTERNALSYM _PROV_ENUMALGS_EX}
  PROV_ENUMALGS_EX = _PROV_ENUMALGS_EX;
  {$EXTERNALSYM PROV_ENUMALGS_EX}
  TProvEnumAlgsEx = _PROV_ENUMALGS_EX;
// certenrolls_end

type
  PPublicKeyStruc = ^TPublicKeyStruc;
  _PUBLICKEYSTRUC = record
    bType: BYTE;
    bVersion: BYTE;
    reserved: WORD;
    aiKeyAlg: ALG_ID;
  end;
  {$EXTERNALSYM _PUBLICKEYSTRUC}
  PUBLICKEYSTRUC = _PUBLICKEYSTRUC;
  {$EXTERNALSYM PUBLICKEYSTRUC}
  TPublicKeyStruc = _PUBLICKEYSTRUC;

  PBlobHeader = ^TBlobHeader;
  BLOBHEADER = _PUBLICKEYSTRUC;
  {$EXTERNALSYM BLOBHEADER}
  TBlobHeader = _PUBLICKEYSTRUC;

type
  PRSAPubKey = ^TRSAPubKey;
  _RSAPUBKEY = record
    magic: DWORD;                     // Has to be RSA1
    bitlen: DWORD;                    // # of bits in modulus
    pubexp: DWORD;                    // public exponent
                                      // Modulus data follows
  end;
  {$EXTERNALSYM _RSAPUBKEY}
  RSAPUBKEY = _RSAPUBKEY;
  {$EXTERNALSYM RSAPUBKEY}
  TRSAPubKey = _RSAPUBKEY;

type
  _PUBKEY = record
    magic: DWORD;
    bitlen: DWORD;                    // # of bits in modulus
  end;
  {$EXTERNALSYM _PUBKEY}

  PDHPubKey = ^TDHPubKey;
  DHPUBKEY = _PUBKEY;
  {$EXTERNALSYM DHPUBKEY}
  TDHPubKey = _PUBKEY;

  PDSSPubKey = ^TDSSPubKey;
  DSSPUBKEY = _PUBKEY;
  {$EXTERNALSYM DSSPUBKEY}
  TDSSPubKey = _PUBKEY;

  PKEAPubKey = ^TKEAPubKey;
  KEAPUBKEY = _PUBKEY;
  {$EXTERNALSYM KEAPUBKEY}
  TKEAPubKey = _PUBKEY;

  PTEKPubKey = ^TTEKPubKey;
  TEKPUBKEY = _PUBKEY;
  {$EXTERNALSYM TEKPUBKEY}
  TTEKPubKey = _PUBKEY;

type
  PDSSSeed = ^TDSSSeed;
  _DSSSEED = record
    counter: DWORD;
    seed: array [0..19] of BYTE;
  end;
  {$EXTERNALSYM _DSSSEED}
  DSSSEED = _DSSSEED;
  {$EXTERNALSYM DSSSEED}
  TDSSSeed = _DSSSEED;

type
  _PUBKEYVER3 = record
    magic: DWORD;
    bitlenP: DWORD;                   // # of bits in prime modulus
    bitlenQ: DWORD;                   // # of bits in prime q, 0 if not available
    bitlenJ: DWORD;                   // # of bits in (p-1)/q, 0 if not available
    DSSSeed: TDSSSeed;
  end;
  {$EXTERNALSYM _PUBKEYVER3}

  PDHPubKeyVer3 = ^TDHPubKeyVer3;
  DHPUBKEY_VER3 = _PUBKEYVER3;
  {$EXTERNALSYM DHPUBKEY_VER3}
  TDHPubKeyVer3 = _PUBKEYVER3;

  PDSSPubKeyVer3 = ^TDSSPubKeyVer3;
  DSSPUBKEY_VER3 = _PUBKEYVER3;
  {$EXTERNALSYM DSSPUBKEY_VER3}
  TDSSPubKeyVer3 = _PUBKEYVER3;

type
  _PRIVKEYVER3 = record
    magic: DWORD;
    bitlenP: DWORD;                   // # of bits in prime modulus
    bitlenQ: DWORD;                   // # of bits in prime q, 0 if not available
    bitlenJ: DWORD;                   // # of bits in (p-1)/q, 0 if not available
    bitlenX: DWORD;                   // # of bits in X
    DSSSeed: TDSSSeed;
  end;
  {$EXTERNALSYM _PRIVKEYVER3}

  PDHPrivKeyVer3 = ^TDHPrivKeyVer3;
  DHPRIVKEY_VER3 = _PRIVKEYVER3;
  {$EXTERNALSYM DHPRIVKEY_VER3}
  TDHPrivKeyVer3 = _PRIVKEYVER3;

  PDSSPrivKeyVer3 = ^TDSSPrivKeyVer3;
  DSSPRIVKEY_VER3 = _PRIVKEYVER3;
  {$EXTERNALSYM DSSPRIVKEY_VER3}
  TDSSPrivKeyVer3 = _PRIVKEYVER3;

type
  PKeyTypeSubType = ^TKeyTypeSubType;
  _KEY_TYPE_SUBTYPE = record
    dwKeySpec: DWORD;
    &Type: TGUID;
    Subtype: TGUID;
  end;
  {$EXTERNALSYM _KEY_TYPE_SUBTYPE}
  KEY_TYPE_SUBTYPE = _KEY_TYPE_SUBTYPE;
  {$EXTERNALSYM KEY_TYPE_SUBTYPE}
  TKeyTypeSubType = _KEY_TYPE_SUBTYPE;
  PKEY_TYPE_SUBTYPE = PKeyTypeSubType;
  {$EXTERNALSYM PKEY_TYPE_SUBTYPE}

type
  PCertFortezzaDataProp = ^TCertFortezzaDataProp;
  _CERT_FORTEZZA_DATA_PROP = record
    SerialNumber: array [0..7] of Byte;
    CertIndex: Integer;
    CertLabel: array [0..35] of Byte;
  end;
  {$EXTERNALSYM _CERT_FORTEZZA_DATA_PROP}
  CERT_FORTEZZA_DATA_PROP = _CERT_FORTEZZA_DATA_PROP;
  {$EXTERNALSYM CERT_FORTEZZA_DATA_PROP}
  TCertFortezzaDataProp = _CERT_FORTEZZA_DATA_PROP;

type
  PCryptRC4KeyState = ^TCryptRC4KeyState;
  _CRYPT_RC4_KEY_STATE = record
    Key: array [0..15] of Byte;
    SBox: array [0..255] of Byte;
    i: Byte;
    j: Byte;
  end;
  {$EXTERNALSYM _CRYPT_RC4_KEY_STATE}
  CRYPT_RC4_KEY_STATE = _CRYPT_RC4_KEY_STATE;
  {$EXTERNALSYM CRYPT_RC4_KEY_STATE}
  TCryptRC4KeyState = _CRYPT_RC4_KEY_STATE;
  PCRYPT_RC4_KEY_STATE = PCryptRC4KeyState;
  {$EXTERNALSYM PCRYPT_RC4_KEY_STATE}

type
  PCryptDESKeyState = ^TCryptDESKeyState;
  _CRYPT_DES_KEY_STATE = record
    Key: array [0..7] of Byte;
    IV: array [0..7] of Byte;
    Feedback: array [0..7] of Byte;
  end;
  {$EXTERNALSYM _CRYPT_DES_KEY_STATE}
  CRYPT_DES_KEY_STATE = _CRYPT_DES_KEY_STATE;
  {$EXTERNALSYM CRYPT_DES_KEY_STATE}
  TCryptDESKeyState = _CRYPT_DES_KEY_STATE;
  PCRYPT_DES_KEY_STATE = PCryptDESKeyState;
  {$EXTERNALSYM PCRYPT_DES_KEY_STATE}

type
  PCrypt3DESKeyState = ^TCrypt3DESKeyState;
  _CRYPT_3DES_KEY_STATE = record
    Key: array [0..23] of Byte;
    IV: array [0..7] of Byte;
    Feedback: array [0..7] of Byte;
  end;
  {$EXTERNALSYM _CRYPT_3DES_KEY_STATE}
  CRYPT_3DES_KEY_STATE = _CRYPT_3DES_KEY_STATE;
  {$EXTERNALSYM CRYPT_3DES_KEY_STATE}
  TCrypt3DESKeyState = _CRYPT_3DES_KEY_STATE;
  PCRYPT_3DES_KEY_STATE = PCrypt3DESKeyState;
  {$EXTERNALSYM PCRYPT_3DES_KEY_STATE}

type
  PCryptAES128KeyState = ^TCryptAES128KeyState;
  _CRYPT_AES_128_KEY_STATE = record
    Key: array [0..15] of Byte;
    IV: array [0..15] of Byte;
    EncryptionState: array [0..10, 0..15] of Byte;      // 10 rounds + 1
    DecryptionState: array [0..10, 0..15] of Byte;
    Feedback: array [0..15] of Byte;
  end;
  {$EXTERNALSYM _CRYPT_AES_128_KEY_STATE}
  CRYPT_AES_128_KEY_STATE = _CRYPT_AES_128_KEY_STATE;
  {$EXTERNALSYM CRYPT_AES_128_KEY_STATE}
  TCryptAES128KeyState = _CRYPT_AES_128_KEY_STATE;
  PCRYPT_AES_128_KEY_STATE = PCryptAES128KeyState;
  {$EXTERNALSYM PCRYPT_AES_128_KEY_STATE}

type
  PCryptAES256KeyState = ^TCryptAES256KeyState;
  _CRYPT_AES_256_KEY_STATE = record
    Key: array [0..31] of Byte;
    IV: array [0..15] of Byte;
    EncryptionState: array [0..14, 0..15] of Byte;      // 14 rounds + 1
    DecryptionState: array [0..14, 0..15] of Byte;
    Feedback: array [0..15] of Byte;
  end;
  {$EXTERNALSYM _CRYPT_AES_256_KEY_STATE}
  CRYPT_AES_256_KEY_STATE = _CRYPT_AES_256_KEY_STATE;
  {$EXTERNALSYM CRYPT_AES_256_KEY_STATE}
  TCryptAES256KeyState = _CRYPT_AES_256_KEY_STATE;
  PCRYPT_AES_256_KEY_STATE = PCryptAES256KeyState;
  {$EXTERNALSYM PCRYPT_AES_256_KEY_STATE}


//+-------------------------------------------------------------------------
//  CRYPTOAPI BLOB definitions
//--------------------------------------------------------------------------
// certenrolls_begin -- *_BLOB
type
  _CRYPTOAPI_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;
  {$EXTERNALSYM _CRYPTOAPI_BLOB}

  PCryptIntegerBlob = ^TCryptIntegerBlob;
  CRYPT_INTEGER_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_INTEGER_BLOB}
  TCryptIntegerBlob = _CRYPTOAPI_BLOB;
  PCRYPT_INTEGER_BLOB = PCryptIntegerBlob;
  {$EXTERNALSYM PCRYPT_INTEGER_BLOB}

  PCryptUIntBlob = ^TCryptUIntBlob;
  CRYPT_UINT_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_UINT_BLOB}
  TCryptUIntBlob = _CRYPTOAPI_BLOB;
  PCRYPT_UINT_BLOB = PCryptUIntBlob;
  {$EXTERNALSYM PCRYPT_UINT_BLOB}

  PCryptObjIDBlob = ^TCryptObjIDBlob;
  CRYPT_OBJID_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_OBJID_BLOB}
  TCryptObjIDBlob = _CRYPTOAPI_BLOB;
  PCRYPT_OBJID_BLOB = PCryptObjIDBlob;
  {$EXTERNALSYM PCRYPT_OBJID_BLOB}

  PCertNameBlob = ^TCertNameBlob;
  CERT_NAME_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CERT_NAME_BLOB}
  TCertNameBlob = _CRYPTOAPI_BLOB;
  PCERT_NAME_BLOB = PCertNameBlob;
  {$EXTERNALSYM PCERT_NAME_BLOB}

  PCertRDNValueBlob = ^TCertRDNValueBlob;
  CERT_RDN_VALUE_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CERT_RDN_VALUE_BLOB}
  TCertRDNValueBlob = _CRYPTOAPI_BLOB;
  PCERT_RDN_VALUE_BLOB = PCertRDNValueBlob;
  {$EXTERNALSYM PCERT_RDN_VALUE_BLOB}

  PCertBlob = ^TCertBlob;
  CERT_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CERT_BLOB}
  TCertBlob = _CRYPTOAPI_BLOB;
  PCERT_BLOB = PCertBlob;
  {$EXTERNALSYM PCERT_BLOB}

  PCRLBlob = ^TCRLBlob;
  CRL_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRL_BLOB}
  TCRLBlob = _CRYPTOAPI_BLOB;
  PCRL_BLOB = PCRLBlob;
  {$EXTERNALSYM PCRL_BLOB}

  PDataBlob = ^TDataBlob;
  DATA_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM DATA_BLOB}
  TDataBlob = _CRYPTOAPI_BLOB;
  PDATA_BLOB = PDataBlob;
  {$EXTERNALSYM PDATA_BLOB}

  PCryptDataBlob = ^TCryptDataBlob;
  CRYPT_DATA_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_DATA_BLOB}
  TCryptDataBlob = _CRYPTOAPI_BLOB;
  PCRYPT_DATA_BLOB = PCryptDataBlob;
  {$EXTERNALSYM PCRYPT_DATA_BLOB}

  PCryptHashBlob = ^TCryptHashBlob;
  CRYPT_HASH_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_HASH_BLOB}
  TCryptHashBlob = _CRYPTOAPI_BLOB;
  PCRYPT_HASH_BLOB = PCryptHashBlob;
  {$EXTERNALSYM PCRYPT_HASH_BLOB}

  PCryptDigestBlob = ^TCryptDigestBlob;
  CRYPT_DIGEST_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_DIGEST_BLOB}
  TCryptDigestBlob = _CRYPTOAPI_BLOB;
  PCRYPT_DIGEST_BLOB = PCryptDigestBlob;
  {$EXTERNALSYM PCRYPT_DIGEST_BLOB}

  PCryptDERBlob = ^TCryptDERBlob;
  CRYPT_DER_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_DER_BLOB}
  TCryptDERBlob = _CRYPTOAPI_BLOB;
  PCRYPT_DER_BLOB = PCryptDERBlob;
  {$EXTERNALSYM PCRYPT_DER_BLOB}

  PCryptAttrBlob = ^TCryptAttrBlob;
  CRYPT_ATTR_BLOB = _CRYPTOAPI_BLOB;
  {$EXTERNALSYM CRYPT_ATTR_BLOB}
  TCryptAttrBlob = _CRYPTOAPI_BLOB;
  PCRYPT_ATTR_BLOB = PCryptAttrBlob;
  {$EXTERNALSYM PCRYPT_ATTR_BLOB}

// certenrolls_end

// structure for use with CryptSetKeyParam for CMS keys
type
  PCMSDHKeyInfo = ^TCMSDHKeyInfo;
  _CMS_DH_KEY_INFO = record
    dwVersion: DWORD;            // sizeof(CMS_DH_KEY_INFO)
    Algid: ALG_ID;               // algorithmm id for the key to be converted
    pszContentEncObjId: LPSTR;   // pointer to OID to hash in with Z
    PubInfo: TCryptDataBlob;     // OPTIONAL - public information
    pReserved: Pointer;          // reserved - should be NULL
  end;
  {$EXTERNALSYM _CMS_DH_KEY_INFO}
  CMS_DH_KEY_INFO = _CMS_DH_KEY_INFO;
  {$EXTERNALSYM CMS_DH_KEY_INFO}
  TCMSDHKeyInfo = _CMS_DH_KEY_INFO;
  PCMS_DH_KEY_INFO = PCMSDHKeyInfo;
  {$EXTERNALSYM PCMS_DH_KEY_INFO}

function CryptAcquireContextA(
  out phProv: HCRYPTPROV;
  szContainer: LPCSTR;
  szProvider: LPCSTR;
  dwProvType: DWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptAcquireContextA}

function CryptAcquireContextW(
  out phProv: HCRYPTPROV;
  szContainer: LPCWSTR;
  szProvider: LPCWSTR;
  dwProvType: DWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptAcquireContextW}

function CryptAcquireContext(
  out phProv: HCRYPTPROV;
  szContainer: LPCWSTR;
  szProvider: LPCWSTR;
  dwProvType: DWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptAcquireContext}

function CryptReleaseContext(
  hProv: HCRYPTPROV;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptReleaseContext}

function CryptGenKey(
  hProv: HCRYPTPROV;
  Algid: ALG_ID;
  dwFlags: DWORD;
  out phKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptGenKey}

function CryptDeriveKey(
  hProv: HCRYPTPROV;
  Algid: ALG_ID;
  hBaseData: HCRYPTHASH;
  dwFlags: DWORD;
  out phKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptDeriveKey}

function CryptDestroyKey(
  hKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptDestroyKey}

function CryptSetKeyParam(
  hKey: HCRYPTKEY;
  dwParam: DWORD;
  pbData: PByte;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetKeyParam}

function CryptGetKeyParam(
  hKey: HCRYPTKEY;
  dwParam: DWORD;
  pbData: PByte;
  var pdwDataLen: DWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetKeyParam}

function CryptSetHashParam(
  hHash: HCRYPTHASH;
  dwParam: DWORD;
  pbData: PByte;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetHashParam}

function CryptGetHashParam(
  hHash: HCRYPTHASH;
  dwParam: DWORD;
  pbData: PByte;
  var pdwDataLen: DWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetHashParam}

function CryptSetProvParam(
  hProv: HCRYPTPROV;
  dwParam: DWORD;
  pbData: PByte;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetProvParam}

function CryptGetProvParam(
  hProv: HCRYPTPROV;
  dwParam: DWORD;
  pbData: PByte;
  var pdwDataLen: DWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetProvParam}

function CryptGenRandom(
  hProv: HCRYPTPROV;
  dwLen: DWORD;
  pbBuffer: PByte): BOOL; winapi;
{$EXTERNALSYM CryptGenRandom}

function CryptGetUserKey(
  hProv: HCRYPTPROV;
  dwKeySpec: DWORD;
  out phUserKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptGetUserKey}

function CryptExportKey(
  hKey: HCRYPTKEY;
  hExpKey: HCRYPTKEY;
  dwBlobType: DWORD;
  dwFlags: DWORD;
  pbData: PByte;
  var pdwDataLen: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptExportKey}

function CryptImportKey(
  hProv: HCRYPTPROV;
  pbData: PByte;
  dwDataLen: DWORD;
  hPubKey: HCRYPTKEY;
  dwFlags: DWORD;
  out phKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptImportKey}

function CryptEncrypt(
  hKey: HCRYPTKEY;
  hHash: HCRYPTHASH;
  Final: BOOL;
  dwFlags: DWORD;
  pbData: PByte;
  var pdwDataLen: DWORD;
  dwBufLen: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEncrypt}

function CryptDecrypt(
  hKey: HCRYPTKEY;
  hHash: HCRYPTHASH;
  Final: BOOL;
  dwFlags: DWORD;
  pbData: PByte;
  var pdwDataLen: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptDecrypt}

function CryptCreateHash(
  hProv: HCRYPTPROV;
  Algid: ALG_ID;
  hKey: HCRYPTKEY;
  dwFlags: DWORD;
  out phHash: HCRYPTHASH): BOOL; winapi;
{$EXTERNALSYM CryptCreateHash}

function CryptHashData(
  hHash: HCRYPTHASH;
  pbData: PByte;
  dwDataLen: DWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptHashData}

function CryptHashSessionKey(
  hHash: HCRYPTHASH;
  hKey: HCRYPTKEY;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptHashSessionKey}

function CryptDestroyHash(
  hHash: HCRYPTHASH): BOOL; winapi;
{$EXTERNALSYM CryptDestroyHash}

function CryptSignHashA(
  hHash: HCRYPTHASH;
  dwKeySpec: DWORD;
  szDescription: LPCSTR;
  dwFlags: DWORD;
  pbSignature: PByte;
  var pdwSigLen: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignHashA}

function CryptSignHashW(
  hHash: HCRYPTHASH;
  dwKeySpec: DWORD;
  szDescription: LPCWSTR;
  dwFlags: DWORD;
  pbSignature: PByte;
  var pdwSigLen: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignHashW}

function CryptSignHash(
  hHash: HCRYPTHASH;
  dwKeySpec: DWORD;
  szDescription: LPCWSTR;
  dwFlags: DWORD;
  pbSignature: PByte;
  var pdwSigLen: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignHash}

function CryptVerifySignatureA(
  hHash: HCRYPTHASH;
  pbSignature: PByte;
  dwSigLen: DWORD;
  hPubKey: HCRYPTKEY;
  szDescription: LPCSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptVerifySignatureA}

function CryptVerifySignatureW(
  hHash: HCRYPTHASH;
  pbSignature: PByte;
  dwSigLen: DWORD;
  hPubKey: HCRYPTKEY;
  szDescription: LPCWSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptVerifySignatureW}

function CryptVerifySignature(
  hHash: HCRYPTHASH;
  pbSignature: PByte;
  dwSigLen: DWORD;
  hPubKey: HCRYPTKEY;
  szDescription: LPCWSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptVerifySignature}

function CryptSetProviderA(
  pszProvName: LPCSTR;
  dwProvType: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetProviderA}

function CryptSetProviderW(
  pszProvName: LPCWSTR;
  dwProvType: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetProviderW}

function CryptSetProvider(
  pszProvName: LPCWSTR;
  dwProvType: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetProvider}

function CryptSetProviderExA(
  pszProvName: LPCSTR;
  dwProvType: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetProviderExA}

function CryptSetProviderExW(
  pszProvName: LPCWSTR;
  dwProvType: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetProviderExW}

function CryptSetProviderEx(
  pszProvName: LPCWSTR;
  dwProvType: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetProviderEx}

function CryptGetDefaultProviderA(
  dwProvType: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  pszProvName: LPSTR;
  var pcbProvName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetDefaultProviderA}

function CryptGetDefaultProviderW(
  dwProvType: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  pszProvName: LPWSTR;
  var pcbProvName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetDefaultProviderW}

function CryptGetDefaultProvider(
  dwProvType: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  pszProvName: LPWSTR;
  var pcbProvName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetDefaultProvider}

function CryptEnumProviderTypesA(
  dwIndex: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out pdwProvType: DWORD;
  szTypeName: LPSTR;
  var pcbTypeName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEnumProviderTypesA}

function CryptEnumProviderTypesW(
  dwIndex: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out pdwProvType: DWORD;
  szTypeName: LPWSTR;
  var pcbTypeName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEnumProviderTypesW}

function CryptEnumProviderTypes(
  dwIndex: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out pdwProvType: DWORD;
  szTypeName: LPWSTR;
  var pcbTypeName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEnumProviderTypes}

function CryptEnumProvidersA(
  dwIndex: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out pdwProvType: DWORD;
  szProvName: LPSTR;
  var pcbProvName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEnumProvidersA}

function CryptEnumProvidersW(
  dwIndex: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out pdwProvType: DWORD;
  szProvName: LPWSTR;
  var pcbProvName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEnumProvidersW}

function CryptEnumProviders(
  dwIndex: DWORD;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out pdwProvType: DWORD;
  szProvName: LPWSTR;
  var pcbProvName: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEnumProviders}

function CryptContextAddRef(
  hProv: HCRYPTPROV;
  pdwReserved: PDWORD;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptContextAddRef}

function CryptDuplicateKey(
  hKey: HCRYPTKEY;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out phKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptDuplicateKey}

function CryptDuplicateHash(
  hHash: HCRYPTHASH;
  pdwReserved: PDWORD;
  dwFlags: DWORD;
  out phHash: HCRYPTHASH): BOOL; winapi;
{$EXTERNALSYM CryptDuplicateHash}


//
// This function is provided in Microsoft Windows 2000 as a means of
// installing the 128-bit encryption provider. This function is unavailable
// in Microsoft Windows XP, because Windows XP ships with the 128-bit
// encryption provider.
//
function GetEncSChannel(
  out pData: PByte;
  out dwDecSize: DWORD): BOOL; cdecl;
{$EXTERNALSYM GetEncSChannel}

// In Vista, the following APIs were updated to support the new
// CNG (Cryptography Next Generation) BCrypt* and NCrypt* APIs in addition
// to the above CAPI1 APIs.

// Include the definitions for the CNG APIs
{$HPPEMIT '#include <bcrypt.h>'}


{$HPPEMIT '#include <ncrypt.h>'}

// This type is used when the API can take either the CAPI1 HCRYPTPROV or
// the CNG NCRYPT_KEY_HANDLE. Where appropriate, the HCRYPTPROV will be
// converted to a NCRYPT_KEY_HANDLE via the CNG NCryptTranslateHandle().
type
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = ULONG_PTR;
  {$EXTERNALSYM HCRYPTPROV_OR_NCRYPT_KEY_HANDLE}

// This type is used where the HCRYPTPROV parameter is no longer used.
// The caller should always pass in NULL.
type
  HCRYPTPROV_LEGACY = ULONG_PTR;
  {$EXTERNALSYM HCRYPTPROV_LEGACY}

//+-------------------------------------------------------------------------
//  In a CRYPT_BIT_BLOB the last byte may contain 0-7 unused bits. Therefore, the
//  overall bit length is cbData * 8 - cUnusedBits.
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_CONTEXT
type
  PCryptBitBlob = ^TCryptBitBlob;
  _CRYPT_BIT_BLOB = record
    cbData: DWORD;
    pbData: PByte;
    cUnusedBits: DWORD;
  end;
  {$EXTERNALSYM _CRYPT_BIT_BLOB}
  CRYPT_BIT_BLOB = _CRYPT_BIT_BLOB;
  {$EXTERNALSYM CRYPT_BIT_BLOB}
  TCryptBitBlob = _CRYPT_BIT_BLOB;
  PCRYPT_BIT_BLOB = PCryptBitBlob;
  {$EXTERNALSYM PCRYPT_BIT_BLOB}

//+-------------------------------------------------------------------------
//  Type used for any algorithm
//
//  Where the Parameters CRYPT_OBJID_BLOB is in its encoded representation. For most
//  algorithm types, the Parameters CRYPT_OBJID_BLOB is NULL (Parameters.cbData = 0).
//--------------------------------------------------------------------------
type
  PCryptAlgorithmIdentifier = ^TCryptAlgorithmIdentifier;
  _CRYPT_ALGORITHM_IDENTIFIER = record
    pszObjId: LPSTR;
    Parameters: TCryptObjIDBlob;
  end;
  {$EXTERNALSYM _CRYPT_ALGORITHM_IDENTIFIER}
  CRYPT_ALGORITHM_IDENTIFIER = _CRYPT_ALGORITHM_IDENTIFIER;
  {$EXTERNALSYM CRYPT_ALGORITHM_IDENTIFIER}
  TCryptAlgorithmIdentifier = _CRYPT_ALGORITHM_IDENTIFIER;
  PCRYPT_ALGORITHM_IDENTIFIER = PCryptAlgorithmIdentifier;
  {$EXTERNALSYM PCRYPT_ALGORITHM_IDENTIFIER}
// certenrolls_end


// Following are the definitions of various algorithm object identifiers
// RSA
const
  szOID_RSA               = '1.2.840.113549';
  {$EXTERNALSYM szOID_RSA}
  szOID_PKCS              = '1.2.840.113549.1';
  {$EXTERNALSYM szOID_PKCS}
  szOID_RSA_HASH          = '1.2.840.113549.2';
  {$EXTERNALSYM szOID_RSA_HASH}
  szOID_RSA_ENCRYPT       = '1.2.840.113549.3';
  {$EXTERNALSYM szOID_RSA_ENCRYPT}

  szOID_PKCS_1            = '1.2.840.113549.1.1';
  {$EXTERNALSYM szOID_PKCS_1}
  szOID_PKCS_2            = '1.2.840.113549.1.2';
  {$EXTERNALSYM szOID_PKCS_2}
  szOID_PKCS_3            = '1.2.840.113549.1.3';
  {$EXTERNALSYM szOID_PKCS_3}
  szOID_PKCS_4            = '1.2.840.113549.1.4';
  {$EXTERNALSYM szOID_PKCS_4}
  szOID_PKCS_5            = '1.2.840.113549.1.5';
  {$EXTERNALSYM szOID_PKCS_5}
  szOID_PKCS_6            = '1.2.840.113549.1.6';
  {$EXTERNALSYM szOID_PKCS_6}
  szOID_PKCS_7            = '1.2.840.113549.1.7';
  {$EXTERNALSYM szOID_PKCS_7}
  szOID_PKCS_8            = '1.2.840.113549.1.8';
  {$EXTERNALSYM szOID_PKCS_8}
  szOID_PKCS_9            = '1.2.840.113549.1.9';
  {$EXTERNALSYM szOID_PKCS_9}
  szOID_PKCS_10           = '1.2.840.113549.1.10';
  {$EXTERNALSYM szOID_PKCS_10}
  szOID_PKCS_12           = '1.2.840.113549.1.12';
  {$EXTERNALSYM szOID_PKCS_12}

  szOID_RSA_RSA           = '1.2.840.113549.1.1.1';
  {$EXTERNALSYM szOID_RSA_RSA}
  szOID_RSA_MD2RSA        = '1.2.840.113549.1.1.2';
  {$EXTERNALSYM szOID_RSA_MD2RSA}
  szOID_RSA_MD4RSA        = '1.2.840.113549.1.1.3';
  {$EXTERNALSYM szOID_RSA_MD4RSA}
  szOID_RSA_MD5RSA        = '1.2.840.113549.1.1.4';
  {$EXTERNALSYM szOID_RSA_MD5RSA}
  szOID_RSA_SHA1RSA       = '1.2.840.113549.1.1.5';
  {$EXTERNALSYM szOID_RSA_SHA1RSA}
  szOID_RSA_SETOAEP_RSA   = '1.2.840.113549.1.1.6';
  {$EXTERNALSYM szOID_RSA_SETOAEP_RSA}

  szOID_RSAES_OAEP        = '1.2.840.113549.1.1.7';
  {$EXTERNALSYM szOID_RSAES_OAEP}
  szOID_RSA_MGF1          = '1.2.840.113549.1.1.8';
  {$EXTERNALSYM szOID_RSA_MGF1}
  szOID_RSA_PSPECIFIED    = '1.2.840.113549.1.1.9';
  {$EXTERNALSYM szOID_RSA_PSPECIFIED}
  szOID_RSA_SSA_PSS       = '1.2.840.113549.1.1.10';
  {$EXTERNALSYM szOID_RSA_SSA_PSS}
  szOID_RSA_SHA256RSA     = '1.2.840.113549.1.1.11';
  {$EXTERNALSYM szOID_RSA_SHA256RSA}
  szOID_RSA_SHA384RSA     = '1.2.840.113549.1.1.12';
  {$EXTERNALSYM szOID_RSA_SHA384RSA}
  szOID_RSA_SHA512RSA     = '1.2.840.113549.1.1.13';
  {$EXTERNALSYM szOID_RSA_SHA512RSA}

  szOID_RSA_DH            = '1.2.840.113549.1.3.1';
  {$EXTERNALSYM szOID_RSA_DH}

  szOID_RSA_data          = '1.2.840.113549.1.7.1';
  {$EXTERNALSYM szOID_RSA_data}
  szOID_RSA_signedData    = '1.2.840.113549.1.7.2';
  {$EXTERNALSYM szOID_RSA_signedData}
  szOID_RSA_envelopedData = '1.2.840.113549.1.7.3';
  {$EXTERNALSYM szOID_RSA_envelopedData}
  szOID_RSA_signEnvData   = '1.2.840.113549.1.7.4';
  {$EXTERNALSYM szOID_RSA_signEnvData}
  szOID_RSA_digestedData  = '1.2.840.113549.1.7.5';
  {$EXTERNALSYM szOID_RSA_digestedData}
  szOID_RSA_hashedData    = '1.2.840.113549.1.7.5';
  {$EXTERNALSYM szOID_RSA_hashedData}
  szOID_RSA_encryptedData = '1.2.840.113549.1.7.6';
  {$EXTERNALSYM szOID_RSA_encryptedData}

  szOID_RSA_emailAddr     = '1.2.840.113549.1.9.1';
  {$EXTERNALSYM szOID_RSA_emailAddr}
  szOID_RSA_unstructName  = '1.2.840.113549.1.9.2';
  {$EXTERNALSYM szOID_RSA_unstructName}
  szOID_RSA_contentType   = '1.2.840.113549.1.9.3';
  {$EXTERNALSYM szOID_RSA_contentType}
  szOID_RSA_messageDigest = '1.2.840.113549.1.9.4';
  {$EXTERNALSYM szOID_RSA_messageDigest}
  szOID_RSA_signingTime   = '1.2.840.113549.1.9.5';
  {$EXTERNALSYM szOID_RSA_signingTime}
  szOID_RSA_counterSign   = '1.2.840.113549.1.9.6';
  {$EXTERNALSYM szOID_RSA_counterSign}
  szOID_RSA_challengePwd  = '1.2.840.113549.1.9.7';
  {$EXTERNALSYM szOID_RSA_challengePwd}
  szOID_RSA_unstructAddr  = '1.2.840.113549.1.9.8';
  {$EXTERNALSYM szOID_RSA_unstructAddr}
  szOID_RSA_extCertAttrs  = '1.2.840.113549.1.9.9';
  {$EXTERNALSYM szOID_RSA_extCertAttrs}
  szOID_RSA_certExtensions = '1.2.840.113549.1.9.14';
  {$EXTERNALSYM szOID_RSA_certExtensions}
  szOID_RSA_SMIMECapabilities = '1.2.840.113549.1.9.15';
  {$EXTERNALSYM szOID_RSA_SMIMECapabilities}
  szOID_RSA_preferSignedData = '1.2.840.113549.1.9.15.1';
  {$EXTERNALSYM szOID_RSA_preferSignedData}

  szOID_TIMESTAMP_TOKEN          = '1.2.840.113549.1.9.16.1.4';
  {$EXTERNALSYM szOID_TIMESTAMP_TOKEN}
  szOID_RFC3161_counterSign = '1.3.6.1.4.1.311.3.3.1';
  {$EXTERNALSYM szOID_RFC3161_counterSign}

  szOID_RSA_SMIMEalg             = '1.2.840.113549.1.9.16.3';
  {$EXTERNALSYM szOID_RSA_SMIMEalg}
  szOID_RSA_SMIMEalgESDH         = '1.2.840.113549.1.9.16.3.5';
  {$EXTERNALSYM szOID_RSA_SMIMEalgESDH}
  szOID_RSA_SMIMEalgCMS3DESwrap  = '1.2.840.113549.1.9.16.3.6';
  {$EXTERNALSYM szOID_RSA_SMIMEalgCMS3DESwrap}
  szOID_RSA_SMIMEalgCMSRC2wrap   = '1.2.840.113549.1.9.16.3.7';
  {$EXTERNALSYM szOID_RSA_SMIMEalgCMSRC2wrap}

  szOID_RSA_MD2           = '1.2.840.113549.2.2';
  {$EXTERNALSYM szOID_RSA_MD2}
  szOID_RSA_MD4           = '1.2.840.113549.2.4';
  {$EXTERNALSYM szOID_RSA_MD4}
  szOID_RSA_MD5           = '1.2.840.113549.2.5';
  {$EXTERNALSYM szOID_RSA_MD5}

  szOID_RSA_RC2CBC        = '1.2.840.113549.3.2';
  {$EXTERNALSYM szOID_RSA_RC2CBC}
  szOID_RSA_RC4           = '1.2.840.113549.3.4';
  {$EXTERNALSYM szOID_RSA_RC4}
  szOID_RSA_DES_EDE3_CBC  = '1.2.840.113549.3.7';
  {$EXTERNALSYM szOID_RSA_DES_EDE3_CBC}
  szOID_RSA_RC5_CBCPad    = '1.2.840.113549.3.9';
  {$EXTERNALSYM szOID_RSA_RC5_CBCPad}


  szOID_ANSI_X942         = '1.2.840.10046';
  {$EXTERNALSYM szOID_ANSI_X942}
  szOID_ANSI_X942_DH      = '1.2.840.10046.2.1';
  {$EXTERNALSYM szOID_ANSI_X942_DH}

  szOID_X957              = '1.2.840.10040';
  {$EXTERNALSYM szOID_X957}
  szOID_X957_DSA          = '1.2.840.10040.4.1';
  {$EXTERNALSYM szOID_X957_DSA}
  szOID_X957_SHA1DSA      = '1.2.840.10040.4.3';
  {$EXTERNALSYM szOID_X957_SHA1DSA}


// iso(1) member-body(2) us(840) 10045 keyType(2) unrestricted(1)
const
  szOID_ECC_PUBLIC_KEY    = '1.2.840.10045.2.1';
  {$EXTERNALSYM szOID_ECC_PUBLIC_KEY}

// iso(1) member-body(2) us(840) 10045 curves(3) prime(1) 7
const
  szOID_ECC_CURVE_P256    = '1.2.840.10045.3.1.7';
  {$EXTERNALSYM szOID_ECC_CURVE_P256}

// iso(1) identified-organization(3) certicom(132) curve(0) 34
const
  szOID_ECC_CURVE_P384    = '1.3.132.0.34';
  {$EXTERNALSYM szOID_ECC_CURVE_P384}

// iso(1) identified-organization(3) certicom(132) curve(0) 35
const
  szOID_ECC_CURVE_P521    = '1.3.132.0.35';
  {$EXTERNALSYM szOID_ECC_CURVE_P521}


// iso(1) member-body(2) us(840) 10045 signatures(4) sha1(1)
const
  szOID_ECDSA_SHA1        = '1.2.840.10045.4.1';
  {$EXTERNALSYM szOID_ECDSA_SHA1}

// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3)
const
  szOID_ECDSA_SPECIFIED   = '1.2.840.10045.4.3';
  {$EXTERNALSYM szOID_ECDSA_SPECIFIED}

// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 2
const
  szOID_ECDSA_SHA256      = '1.2.840.10045.4.3.2';
  {$EXTERNALSYM szOID_ECDSA_SHA256}

// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 3
const
  szOID_ECDSA_SHA384      = '1.2.840.10045.4.3.3';
  {$EXTERNALSYM szOID_ECDSA_SHA384}

// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 4
const
  szOID_ECDSA_SHA512      = '1.2.840.10045.4.3.4';
  {$EXTERNALSYM szOID_ECDSA_SHA512}


// NIST AES CBC Algorithms
// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4)  aesAlgs(1) }
const
  szOID_NIST_AES128_CBC       = '2.16.840.1.101.3.4.1.2';
  {$EXTERNALSYM szOID_NIST_AES128_CBC}
  szOID_NIST_AES192_CBC       = '2.16.840.1.101.3.4.1.22';
  {$EXTERNALSYM szOID_NIST_AES192_CBC}
  szOID_NIST_AES256_CBC       = '2.16.840.1.101.3.4.1.42';
  {$EXTERNALSYM szOID_NIST_AES256_CBC}

// For the above Algorithms, the AlgorithmIdentifier parameters must be
// present and the parameters field MUST contain an AES-IV:
//
//  AES-IV ::= OCTET STRING (SIZE(16))

// NIST AES WRAP Algorithms
const
  szOID_NIST_AES128_WRAP      = '2.16.840.1.101.3.4.1.5';
  {$EXTERNALSYM szOID_NIST_AES128_WRAP}
  szOID_NIST_AES192_WRAP      = '2.16.840.1.101.3.4.1.25';
  {$EXTERNALSYM szOID_NIST_AES192_WRAP}
  szOID_NIST_AES256_WRAP      = '2.16.840.1.101.3.4.1.45';
  {$EXTERNALSYM szOID_NIST_AES256_WRAP}


//      x9-63-scheme OBJECT IDENTIFIER ::= { iso(1)
//         identified-organization(3) tc68(133) country(16) x9(840)
//         x9-63(63) schemes(0) }


// ECDH single pass ephemeral-static KeyAgreement KeyEncryptionAlgorithm
const
  szOID_DH_SINGLE_PASS_STDDH_SHA1_KDF   = '1.3.133.16.840.63.0.2';
  {$EXTERNALSYM szOID_DH_SINGLE_PASS_STDDH_SHA1_KDF}
  szOID_DH_SINGLE_PASS_STDDH_SHA256_KDF = '1.3.132.1.11.1';
  {$EXTERNALSYM szOID_DH_SINGLE_PASS_STDDH_SHA256_KDF}
  szOID_DH_SINGLE_PASS_STDDH_SHA384_KDF = '1.3.132.1.11.2';
  {$EXTERNALSYM szOID_DH_SINGLE_PASS_STDDH_SHA384_KDF}

// For the above KeyEncryptionAlgorithm the following wrap algorithms are
// supported:
//  szOID_RSA_SMIMEalgCMS3DESwrap
//  szOID_RSA_SMIMEalgCMSRC2wrap
//  szOID_NIST_AES128_WRAP
//  szOID_NIST_AES192_WRAP
//  szOID_NIST_AES256_WRAP



// ITU-T UsefulDefinitions
const
  szOID_DS                 = '2.5';
  {$EXTERNALSYM szOID_DS}
  szOID_DSALG              = '2.5.8';
  {$EXTERNALSYM szOID_DSALG}
  szOID_DSALG_CRPT         = '2.5.8.1';
  {$EXTERNALSYM szOID_DSALG_CRPT}
  szOID_DSALG_HASH         = '2.5.8.2';
  {$EXTERNALSYM szOID_DSALG_HASH}
  szOID_DSALG_SIGN         = '2.5.8.3';
  {$EXTERNALSYM szOID_DSALG_SIGN}
  szOID_DSALG_RSA          = '2.5.8.1.1';
  {$EXTERNALSYM szOID_DSALG_RSA}
// NIST OSE Implementors' Workshop (OIW)
// http://nemo.ncsl.nist.gov/oiw/agreements/stable/OSI/12s_9506.w51
// http://nemo.ncsl.nist.gov/oiw/agreements/working/OSI/12w_9503.w51
const
  szOID_OIW                = '1.3.14';
  {$EXTERNALSYM szOID_OIW}
// NIST OSE Implementors' Workshop (OIW) Security SIG algorithm identifiers
const
  szOID_OIWSEC             = '1.3.14.3.2';
  {$EXTERNALSYM szOID_OIWSEC}
  szOID_OIWSEC_md4RSA      = '1.3.14.3.2.2';
  {$EXTERNALSYM szOID_OIWSEC_md4RSA}
  szOID_OIWSEC_md5RSA      = '1.3.14.3.2.3';
  {$EXTERNALSYM szOID_OIWSEC_md5RSA}
  szOID_OIWSEC_md4RSA2     = '1.3.14.3.2.4';
  {$EXTERNALSYM szOID_OIWSEC_md4RSA2}
  szOID_OIWSEC_desECB      = '1.3.14.3.2.6';
  {$EXTERNALSYM szOID_OIWSEC_desECB}
  szOID_OIWSEC_desCBC      = '1.3.14.3.2.7';
  {$EXTERNALSYM szOID_OIWSEC_desCBC}
  szOID_OIWSEC_desOFB      = '1.3.14.3.2.8';
  {$EXTERNALSYM szOID_OIWSEC_desOFB}
  szOID_OIWSEC_desCFB      = '1.3.14.3.2.9';
  {$EXTERNALSYM szOID_OIWSEC_desCFB}
  szOID_OIWSEC_desMAC      = '1.3.14.3.2.10';
  {$EXTERNALSYM szOID_OIWSEC_desMAC}
  szOID_OIWSEC_rsaSign     = '1.3.14.3.2.11';
  {$EXTERNALSYM szOID_OIWSEC_rsaSign}
  szOID_OIWSEC_dsa         = '1.3.14.3.2.12';
  {$EXTERNALSYM szOID_OIWSEC_dsa}
  szOID_OIWSEC_shaDSA      = '1.3.14.3.2.13';
  {$EXTERNALSYM szOID_OIWSEC_shaDSA}
  szOID_OIWSEC_mdc2RSA     = '1.3.14.3.2.14';
  {$EXTERNALSYM szOID_OIWSEC_mdc2RSA}
  szOID_OIWSEC_shaRSA      = '1.3.14.3.2.15';
  {$EXTERNALSYM szOID_OIWSEC_shaRSA}
  szOID_OIWSEC_dhCommMod   = '1.3.14.3.2.16';
  {$EXTERNALSYM szOID_OIWSEC_dhCommMod}
  szOID_OIWSEC_desEDE      = '1.3.14.3.2.17';
  {$EXTERNALSYM szOID_OIWSEC_desEDE}
  szOID_OIWSEC_sha         = '1.3.14.3.2.18';
  {$EXTERNALSYM szOID_OIWSEC_sha}
  szOID_OIWSEC_mdc2        = '1.3.14.3.2.19';
  {$EXTERNALSYM szOID_OIWSEC_mdc2}
  szOID_OIWSEC_dsaComm     = '1.3.14.3.2.20';
  {$EXTERNALSYM szOID_OIWSEC_dsaComm}
  szOID_OIWSEC_dsaCommSHA  = '1.3.14.3.2.21';
  {$EXTERNALSYM szOID_OIWSEC_dsaCommSHA}
  szOID_OIWSEC_rsaXchg     = '1.3.14.3.2.22';
  {$EXTERNALSYM szOID_OIWSEC_rsaXchg}
  szOID_OIWSEC_keyHashSeal = '1.3.14.3.2.23';
  {$EXTERNALSYM szOID_OIWSEC_keyHashSeal}
  szOID_OIWSEC_md2RSASign  = '1.3.14.3.2.24';
  {$EXTERNALSYM szOID_OIWSEC_md2RSASign}
  szOID_OIWSEC_md5RSASign  = '1.3.14.3.2.25';
  {$EXTERNALSYM szOID_OIWSEC_md5RSASign}
  szOID_OIWSEC_sha1        = '1.3.14.3.2.26';
  {$EXTERNALSYM szOID_OIWSEC_sha1}
  szOID_OIWSEC_dsaSHA1     = '1.3.14.3.2.27';
  {$EXTERNALSYM szOID_OIWSEC_dsaSHA1}
  szOID_OIWSEC_dsaCommSHA1 = '1.3.14.3.2.28';
  {$EXTERNALSYM szOID_OIWSEC_dsaCommSHA1}
  szOID_OIWSEC_sha1RSASign = '1.3.14.3.2.29';
  {$EXTERNALSYM szOID_OIWSEC_sha1RSASign}
// NIST OSE Implementors' Workshop (OIW) Directory SIG algorithm identifiers
const
  szOID_OIWDIR            = '1.3.14.7.2';
  {$EXTERNALSYM szOID_OIWDIR}
  szOID_OIWDIR_CRPT       = '1.3.14.7.2.1';
  {$EXTERNALSYM szOID_OIWDIR_CRPT}
  szOID_OIWDIR_HASH       = '1.3.14.7.2.2';
  {$EXTERNALSYM szOID_OIWDIR_HASH}
  szOID_OIWDIR_SIGN       = '1.3.14.7.2.3';
  {$EXTERNALSYM szOID_OIWDIR_SIGN}
  szOID_OIWDIR_md2        = '1.3.14.7.2.2.1';
  {$EXTERNALSYM szOID_OIWDIR_md2}
  szOID_OIWDIR_md2RSA     = '1.3.14.7.2.3.1';
  {$EXTERNALSYM szOID_OIWDIR_md2RSA}


// INFOSEC Algorithms
// joint-iso-ccitt(2) country(16) us(840) organization(1) us-government(101) dod(2) id-infosec(1)
const
  szOID_INFOSEC                       = '2.16.840.1.101.2.1';
  {$EXTERNALSYM szOID_INFOSEC}
  szOID_INFOSEC_sdnsSignature         = '2.16.840.1.101.2.1.1.1';
  {$EXTERNALSYM szOID_INFOSEC_sdnsSignature}
  szOID_INFOSEC_mosaicSignature       = '2.16.840.1.101.2.1.1.2';
  {$EXTERNALSYM szOID_INFOSEC_mosaicSignature}
  szOID_INFOSEC_sdnsConfidentiality   = '2.16.840.1.101.2.1.1.3';
  {$EXTERNALSYM szOID_INFOSEC_sdnsConfidentiality}
  szOID_INFOSEC_mosaicConfidentiality = '2.16.840.1.101.2.1.1.4';
  {$EXTERNALSYM szOID_INFOSEC_mosaicConfidentiality}
  szOID_INFOSEC_sdnsIntegrity         = '2.16.840.1.101.2.1.1.5';
  {$EXTERNALSYM szOID_INFOSEC_sdnsIntegrity}
  szOID_INFOSEC_mosaicIntegrity       = '2.16.840.1.101.2.1.1.6';
  {$EXTERNALSYM szOID_INFOSEC_mosaicIntegrity}
  szOID_INFOSEC_sdnsTokenProtection   = '2.16.840.1.101.2.1.1.7';
  {$EXTERNALSYM szOID_INFOSEC_sdnsTokenProtection}
  szOID_INFOSEC_mosaicTokenProtection = '2.16.840.1.101.2.1.1.8';
  {$EXTERNALSYM szOID_INFOSEC_mosaicTokenProtection}
  szOID_INFOSEC_sdnsKeyManagement     = '2.16.840.1.101.2.1.1.9';
  {$EXTERNALSYM szOID_INFOSEC_sdnsKeyManagement}
  szOID_INFOSEC_mosaicKeyManagement   = '2.16.840.1.101.2.1.1.10';
  {$EXTERNALSYM szOID_INFOSEC_mosaicKeyManagement}
  szOID_INFOSEC_sdnsKMandSig          = '2.16.840.1.101.2.1.1.11';
  {$EXTERNALSYM szOID_INFOSEC_sdnsKMandSig}
  szOID_INFOSEC_mosaicKMandSig        = '2.16.840.1.101.2.1.1.12';
  {$EXTERNALSYM szOID_INFOSEC_mosaicKMandSig}
  szOID_INFOSEC_SuiteASignature       = '2.16.840.1.101.2.1.1.13';
  {$EXTERNALSYM szOID_INFOSEC_SuiteASignature}
  szOID_INFOSEC_SuiteAConfidentiality = '2.16.840.1.101.2.1.1.14';
  {$EXTERNALSYM szOID_INFOSEC_SuiteAConfidentiality}
  szOID_INFOSEC_SuiteAIntegrity       = '2.16.840.1.101.2.1.1.15';
  {$EXTERNALSYM szOID_INFOSEC_SuiteAIntegrity}
  szOID_INFOSEC_SuiteATokenProtection = '2.16.840.1.101.2.1.1.16';
  {$EXTERNALSYM szOID_INFOSEC_SuiteATokenProtection}
  szOID_INFOSEC_SuiteAKeyManagement   = '2.16.840.1.101.2.1.1.17';
  {$EXTERNALSYM szOID_INFOSEC_SuiteAKeyManagement}
  szOID_INFOSEC_SuiteAKMandSig        = '2.16.840.1.101.2.1.1.18';
  {$EXTERNALSYM szOID_INFOSEC_SuiteAKMandSig}
  szOID_INFOSEC_mosaicUpdatedSig      = '2.16.840.1.101.2.1.1.19';
  {$EXTERNALSYM szOID_INFOSEC_mosaicUpdatedSig}
  szOID_INFOSEC_mosaicKMandUpdSig     = '2.16.840.1.101.2.1.1.20';
  {$EXTERNALSYM szOID_INFOSEC_mosaicKMandUpdSig}
  szOID_INFOSEC_mosaicUpdatedInteg    = '2.16.840.1.101.2.1.1.21';
  {$EXTERNALSYM szOID_INFOSEC_mosaicUpdatedInteg}

// NIST Hash Algorithms
// joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2)
const
  szOID_NIST_sha256                   = '2.16.840.1.101.3.4.2.1';
  {$EXTERNALSYM szOID_NIST_sha256}
  szOID_NIST_sha384                   = '2.16.840.1.101.3.4.2.2';
  {$EXTERNALSYM szOID_NIST_sha384}
  szOID_NIST_sha512                   = '2.16.840.1.101.3.4.2.3';
  {$EXTERNALSYM szOID_NIST_sha512}

type
  PCryptObjIDTable = ^TCryptObjIDTable;
  _CRYPT_OBJID_TABLE = record
    dwAlgId: DWORD;
    pszObjId: LPCSTR;
  end;
  {$EXTERNALSYM _CRYPT_OBJID_TABLE}
  CRYPT_OBJID_TABLE = _CRYPT_OBJID_TABLE;
  {$EXTERNALSYM CRYPT_OBJID_TABLE}
  TCryptObjIDTable = _CRYPT_OBJID_TABLE;
  PCRYPT_OBJID_TABLE = PCryptObjIDTable;
  {$EXTERNALSYM PCRYPT_OBJID_TABLE}


//+-------------------------------------------------------------------------
//  PKCS #1 HashInfo (DigestInfo)
//--------------------------------------------------------------------------
type
  PCryptHashInfo = ^TCryptHashInfo;
  _CRYPT_HASH_INFO = record
    HashAlgorithm: TCryptAlgorithmIdentifier;
    Hash: TCryptHashBlob;
  end;
  {$EXTERNALSYM _CRYPT_HASH_INFO}
  CRYPT_HASH_INFO = _CRYPT_HASH_INFO;
  {$EXTERNALSYM CRYPT_HASH_INFO}
  TCryptHashInfo = _CRYPT_HASH_INFO;
  PCRYPT_HASH_INFO = PCryptHashInfo;
  {$EXTERNALSYM PCRYPT_HASH_INFO}

//+-------------------------------------------------------------------------
//  Type used for an extension to an encoded content
//
//  Where the Value's CRYPT_OBJID_BLOB is in its encoded representation.
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_CONTEXT
type
  PCertExtension = ^TCertExtension;
  _CERT_EXTENSION = record
    pszObjId: LPSTR;
    fCritical: BOOL;
    Value: TCryptObjIDBlob;
  end;
  {$EXTERNALSYM _CERT_EXTENSION}
  CERT_EXTENSION = _CERT_EXTENSION;
  {$EXTERNALSYM CERT_EXTENSION}
  TCertExtension = _CERT_EXTENSION;
  PCERT_EXTENSION = PCertExtension;
  {$EXTERNALSYM PCERT_EXTENSION}
  PCCERT_EXTENSION = PCertExtension;
  {$EXTERNALSYM PCCERT_EXTENSION}
// certenrolls_end

//+-------------------------------------------------------------------------
//  AttributeTypeValue
//
//  Where the Value's CRYPT_OBJID_BLOB is in its encoded representation.
//--------------------------------------------------------------------------
// certenrolls_begin -- CRYPT_ATTRIBUTE_TYPE_VALUE
type
  PCryptAttributeTypeValue = ^TCryptAttributeTypeValue;
  _CRYPT_ATTRIBUTE_TYPE_VALUE = record
    pszObjId: LPSTR;
    Value: TCryptObjIDBlob;
  end;
  {$EXTERNALSYM _CRYPT_ATTRIBUTE_TYPE_VALUE}
  CRYPT_ATTRIBUTE_TYPE_VALUE = _CRYPT_ATTRIBUTE_TYPE_VALUE;
  {$EXTERNALSYM CRYPT_ATTRIBUTE_TYPE_VALUE}
  TCryptAttributeTypeValue = _CRYPT_ATTRIBUTE_TYPE_VALUE;
  PCRYPT_ATTRIBUTE_TYPE_VALUE = PCryptAttributeTypeValue;
  {$EXTERNALSYM PCRYPT_ATTRIBUTE_TYPE_VALUE}
// certenrolls_end

//+-------------------------------------------------------------------------
//  Attributes
//
//  Where the Value's PATTR_BLOBs are in their encoded representation.
//--------------------------------------------------------------------------
// certenrolls_begin -- CRYPT_ATTRIBUTE
type
  PCryptAttribute = ^TCryptAttribute;
  _CRYPT_ATTRIBUTE = record
    pszObjId: LPSTR;
    cValue: DWORD;
    rgValue: PCryptAttrBlob;
  end;
  {$EXTERNALSYM _CRYPT_ATTRIBUTE}
  CRYPT_ATTRIBUTE = _CRYPT_ATTRIBUTE;
  {$EXTERNALSYM CRYPT_ATTRIBUTE}
  TCryptAttribute = _CRYPT_ATTRIBUTE;
  PCRYPT_ATTRIBUTE = PCryptAttribute;
  {$EXTERNALSYM PCRYPT_ATTRIBUTE}

type
  PCryptAttributes = ^TCryptAttributes;
  _CRYPT_ATTRIBUTES = record
    cAttr: DWORD;
    rgAttr: PCryptAttribute;
  end;
  {$EXTERNALSYM _CRYPT_ATTRIBUTES}
  CRYPT_ATTRIBUTES = _CRYPT_ATTRIBUTES;
  {$EXTERNALSYM CRYPT_ATTRIBUTES}
  TCryptAttributes = _CRYPT_ATTRIBUTES;
  PCRYPT_ATTRIBUTES = PCryptAttributes;
  {$EXTERNALSYM PCRYPT_ATTRIBUTES}
// certenrolls_end

//+-------------------------------------------------------------------------
//  Attributes making up a Relative Distinguished Name (CERT_RDN)
//
//  The interpretation of the Value depends on the dwValueType.
//  See below for a list of the types.
//--------------------------------------------------------------------------
type
  PCertRDNAttr = ^TCertRDNAttr;
  _CERT_RDN_ATTR = record
    pszObjId: LPSTR;
    dwValueType: DWORD;
    Value: TCertRDNValueBlob;
  end;
  {$EXTERNALSYM _CERT_RDN_ATTR}
  CERT_RDN_ATTR = _CERT_RDN_ATTR;
  {$EXTERNALSYM CERT_RDN_ATTR}
  TCertRDNAttr = _CERT_RDN_ATTR;
  PCERT_RDN_ATTR = PCertRDNAttr;
  {$EXTERNALSYM PCERT_RDN_ATTR}

//+-------------------------------------------------------------------------
//  CERT_RDN attribute Object Identifiers
//--------------------------------------------------------------------------
// Labeling attribute types:
const
  szOID_COMMON_NAME                   = '2.5.4.3';  // case-ignore string
  {$EXTERNALSYM szOID_COMMON_NAME}
  szOID_SUR_NAME                      = '2.5.4.4';  // case-ignore string
  {$EXTERNALSYM szOID_SUR_NAME}
  szOID_DEVICE_SERIAL_NUMBER          = '2.5.4.5';  // printable string
  {$EXTERNALSYM szOID_DEVICE_SERIAL_NUMBER}

// Geographic attribute types:
const
  szOID_COUNTRY_NAME                  = '2.5.4.6';  // printable 2char string
  {$EXTERNALSYM szOID_COUNTRY_NAME}
  szOID_LOCALITY_NAME                 = '2.5.4.7';  // case-ignore string
  {$EXTERNALSYM szOID_LOCALITY_NAME}
  szOID_STATE_OR_PROVINCE_NAME        = '2.5.4.8';  // case-ignore string
  {$EXTERNALSYM szOID_STATE_OR_PROVINCE_NAME}
  szOID_STREET_ADDRESS                = '2.5.4.9';  // case-ignore string
  {$EXTERNALSYM szOID_STREET_ADDRESS}

// Organizational attribute types:
const
  szOID_ORGANIZATION_NAME             = '2.5.4.10'; // case-ignore string
  {$EXTERNALSYM szOID_ORGANIZATION_NAME}
  szOID_ORGANIZATIONAL_UNIT_NAME      = '2.5.4.11'; // case-ignore string
  {$EXTERNALSYM szOID_ORGANIZATIONAL_UNIT_NAME}
  szOID_TITLE                         = '2.5.4.12'; // case-ignore string
  {$EXTERNALSYM szOID_TITLE}

// Explanatory attribute types:
const
  szOID_DESCRIPTION                   = '2.5.4.13'; // case-ignore string
  {$EXTERNALSYM szOID_DESCRIPTION}
  szOID_SEARCH_GUIDE                  = '2.5.4.14';
  {$EXTERNALSYM szOID_SEARCH_GUIDE}
  szOID_BUSINESS_CATEGORY             = '2.5.4.15'; // case-ignore string
  {$EXTERNALSYM szOID_BUSINESS_CATEGORY}

// Postal addressing attribute types:
const
  szOID_POSTAL_ADDRESS                = '2.5.4.16';
  {$EXTERNALSYM szOID_POSTAL_ADDRESS}
  szOID_POSTAL_CODE                   = '2.5.4.17'; // case-ignore string
  {$EXTERNALSYM szOID_POSTAL_CODE}
  szOID_POST_OFFICE_BOX               = '2.5.4.18'; // case-ignore string
  {$EXTERNALSYM szOID_POST_OFFICE_BOX}
  szOID_PHYSICAL_DELIVERY_OFFICE_NAME = '2.5.4.19'; // case-ignore string
  {$EXTERNALSYM szOID_PHYSICAL_DELIVERY_OFFICE_NAME}

// Telecommunications addressing attribute types:
const
  szOID_TELEPHONE_NUMBER              = '2.5.4.20'; // telephone number
  {$EXTERNALSYM szOID_TELEPHONE_NUMBER}
  szOID_TELEX_NUMBER                  = '2.5.4.21';
  {$EXTERNALSYM szOID_TELEX_NUMBER}
  szOID_TELETEXT_TERMINAL_IDENTIFIER  = '2.5.4.22';
  {$EXTERNALSYM szOID_TELETEXT_TERMINAL_IDENTIFIER}
  szOID_FACSIMILE_TELEPHONE_NUMBER    = '2.5.4.23';
  {$EXTERNALSYM szOID_FACSIMILE_TELEPHONE_NUMBER}
  szOID_X21_ADDRESS                   = '2.5.4.24'; // numeric string
  {$EXTERNALSYM szOID_X21_ADDRESS}
  szOID_INTERNATIONAL_ISDN_NUMBER     = '2.5.4.25'; // numeric string
  {$EXTERNALSYM szOID_INTERNATIONAL_ISDN_NUMBER}
  szOID_REGISTERED_ADDRESS            = '2.5.4.26';
  {$EXTERNALSYM szOID_REGISTERED_ADDRESS}
  szOID_DESTINATION_INDICATOR         = '2.5.4.27'; // printable string
  {$EXTERNALSYM szOID_DESTINATION_INDICATOR}

// Preference attribute types:
const
  szOID_PREFERRED_DELIVERY_METHOD     = '2.5.4.28';
  {$EXTERNALSYM szOID_PREFERRED_DELIVERY_METHOD}

// OSI application attribute types:
const
  szOID_PRESENTATION_ADDRESS          = '2.5.4.29';
  {$EXTERNALSYM szOID_PRESENTATION_ADDRESS}
  szOID_SUPPORTED_APPLICATION_CONTEXT = '2.5.4.30';
  {$EXTERNALSYM szOID_SUPPORTED_APPLICATION_CONTEXT}

// Relational application attribute types:
const
  szOID_MEMBER                        = '2.5.4.31';
  {$EXTERNALSYM szOID_MEMBER}
  szOID_OWNER                         = '2.5.4.32';
  {$EXTERNALSYM szOID_OWNER}
  szOID_ROLE_OCCUPANT                 = '2.5.4.33';
  {$EXTERNALSYM szOID_ROLE_OCCUPANT}
  szOID_SEE_ALSO                      = '2.5.4.34';
  {$EXTERNALSYM szOID_SEE_ALSO}

// Security attribute types:
const
  szOID_USER_PASSWORD                 = '2.5.4.35';
  {$EXTERNALSYM szOID_USER_PASSWORD}
  szOID_USER_CERTIFICATE              = '2.5.4.36';
  {$EXTERNALSYM szOID_USER_CERTIFICATE}
  szOID_CA_CERTIFICATE                = '2.5.4.37';
  {$EXTERNALSYM szOID_CA_CERTIFICATE}
  szOID_AUTHORITY_REVOCATION_LIST     = '2.5.4.38';
  {$EXTERNALSYM szOID_AUTHORITY_REVOCATION_LIST}
  szOID_CERTIFICATE_REVOCATION_LIST   = '2.5.4.39';
  {$EXTERNALSYM szOID_CERTIFICATE_REVOCATION_LIST}
  szOID_CROSS_CERTIFICATE_PAIR        = '2.5.4.40';
  {$EXTERNALSYM szOID_CROSS_CERTIFICATE_PAIR}

// Undocumented attribute types???
//szOID_???                           = '2.5.4.41';
const
  szOID_GIVEN_NAME                    = '2.5.4.42'; // case-ignore string
  {$EXTERNALSYM szOID_GIVEN_NAME}
  szOID_INITIALS                      = '2.5.4.43'; // case-ignore string
  {$EXTERNALSYM szOID_INITIALS}

// The DN Qualifier attribute type specifies disambiguating information to add
// to the relative distinguished name of an entry. It is intended to be used
// for entries held in multiple DSAs which would otherwise have the same name,
// and that its value be the same in a given DSA for all entries to which
// the information has been added.
const
  szOID_DN_QUALIFIER                  = '2.5.4.46';
  {$EXTERNALSYM szOID_DN_QUALIFIER}

// Pilot user attribute types:
const
  szOID_DOMAIN_COMPONENT = '0.9.2342.19200300.100.1.25'; // IA5, UTF8 string
  {$EXTERNALSYM szOID_DOMAIN_COMPONENT}

// used for PKCS 12 attributes
const
  szOID_PKCS_12_FRIENDLY_NAME_ATTR     = '1.2.840.113549.1.9.20';
  {$EXTERNALSYM szOID_PKCS_12_FRIENDLY_NAME_ATTR}
  szOID_PKCS_12_LOCAL_KEY_ID           = '1.2.840.113549.1.9.21';
  {$EXTERNALSYM szOID_PKCS_12_LOCAL_KEY_ID}
  szOID_PKCS_12_KEY_PROVIDER_NAME_ATTR = '1.3.6.1.4.1.311.17.1';
  {$EXTERNALSYM szOID_PKCS_12_KEY_PROVIDER_NAME_ATTR}
  szOID_LOCAL_MACHINE_KEYSET           = '1.3.6.1.4.1.311.17.2';
  {$EXTERNALSYM szOID_LOCAL_MACHINE_KEYSET}
  szOID_PKCS_12_EXTENDED_ATTRIBUTES    = '1.3.6.1.4.1.311.17.3';
  {$EXTERNALSYM szOID_PKCS_12_EXTENDED_ATTRIBUTES}
  szOID_PKCS_12_PROTECTED_PASSWORD_SECRET_BAG_TYPE_ID = '1.3.6.1.4.1.311.17.4';
  {$EXTERNALSYM szOID_PKCS_12_PROTECTED_PASSWORD_SECRET_BAG_TYPE_ID}

//+-------------------------------------------------------------------------
//  Microsoft CERT_RDN attribute Object Identifiers
//--------------------------------------------------------------------------
// Special RDN containing the KEY_ID. Its value type is CERT_RDN_OCTET_STRING.
const
  szOID_KEYID_RDN                    = '1.3.6.1.4.1.311.10.7.1';
  {$EXTERNALSYM szOID_KEYID_RDN}

//+-------------------------------------------------------------------------
//  EV RDN OIDs
//--------------------------------------------------------------------------
const
  szOID_EV_RDN_LOCALE                        = '1.3.6.1.4.1.311.60.2.1.1';
  {$EXTERNALSYM szOID_EV_RDN_LOCALE}
  szOID_EV_RDN_STATE_OR_PROVINCE             = '1.3.6.1.4.1.311.60.2.1.2';
  {$EXTERNALSYM szOID_EV_RDN_STATE_OR_PROVINCE}
  szOID_EV_RDN_COUNTRY                       = '1.3.6.1.4.1.311.60.2.1.3';
  {$EXTERNALSYM szOID_EV_RDN_COUNTRY}

//+-------------------------------------------------------------------------
//  CERT_RDN Attribute Value Types
//
//  For RDN_ENCODED_BLOB, the Value's CERT_RDN_VALUE_BLOB is in its encoded
//  representation. Otherwise, its an array of bytes.
//
//  For all CERT_RDN types, Value.cbData is always the number of bytes, not
//  necessarily the number of elements in the string. For instance,
//  RDN_UNIVERSAL_STRING is an array of ints (cbData == intCnt * 4) and
//  RDN_BMP_STRING is an array of unsigned shorts (cbData == ushortCnt * 2).
//
//  A RDN_UTF8_STRING is an array of UNICODE characters (cbData == charCnt *2).
//  These UNICODE characters are encoded as UTF8 8 bit characters.
//
//  For CertDecodeName, two 0 bytes are always appended to the end of the
//  string (ensures a CHAR or WCHAR string is null terminated).
//  These added 0 bytes are't included in the BLOB.cbData.
//--------------------------------------------------------------------------
const
  CERT_RDN_ANY_TYPE               = 0;
  {$EXTERNALSYM CERT_RDN_ANY_TYPE}
  CERT_RDN_ENCODED_BLOB           = 1;
  {$EXTERNALSYM CERT_RDN_ENCODED_BLOB}
  CERT_RDN_OCTET_STRING           = 2;
  {$EXTERNALSYM CERT_RDN_OCTET_STRING}
  CERT_RDN_NUMERIC_STRING         = 3;
  {$EXTERNALSYM CERT_RDN_NUMERIC_STRING}
  CERT_RDN_PRINTABLE_STRING       = 4;
  {$EXTERNALSYM CERT_RDN_PRINTABLE_STRING}
  CERT_RDN_TELETEX_STRING         = 5;
  {$EXTERNALSYM CERT_RDN_TELETEX_STRING}
  CERT_RDN_T61_STRING             = 5;
  {$EXTERNALSYM CERT_RDN_T61_STRING}
  CERT_RDN_VIDEOTEX_STRING        = 6;
  {$EXTERNALSYM CERT_RDN_VIDEOTEX_STRING}
  CERT_RDN_IA5_STRING             = 7;
  {$EXTERNALSYM CERT_RDN_IA5_STRING}
  CERT_RDN_GRAPHIC_STRING         = 8;
  {$EXTERNALSYM CERT_RDN_GRAPHIC_STRING}
  CERT_RDN_VISIBLE_STRING         = 9;
  {$EXTERNALSYM CERT_RDN_VISIBLE_STRING}
  CERT_RDN_ISO646_STRING          = 9;
  {$EXTERNALSYM CERT_RDN_ISO646_STRING}
  CERT_RDN_GENERAL_STRING         = 10;
  {$EXTERNALSYM CERT_RDN_GENERAL_STRING}
  CERT_RDN_UNIVERSAL_STRING       = 11;
  {$EXTERNALSYM CERT_RDN_UNIVERSAL_STRING}
  CERT_RDN_INT4_STRING            = 11;
  {$EXTERNALSYM CERT_RDN_INT4_STRING}
  CERT_RDN_BMP_STRING             = 12;
  {$EXTERNALSYM CERT_RDN_BMP_STRING}
  CERT_RDN_UNICODE_STRING         = 12;
  {$EXTERNALSYM CERT_RDN_UNICODE_STRING}
  CERT_RDN_UTF8_STRING            = 13;
  {$EXTERNALSYM CERT_RDN_UTF8_STRING}

  CERT_RDN_TYPE_MASK                 = $000000FF;
  {$EXTERNALSYM CERT_RDN_TYPE_MASK}
  CERT_RDN_FLAGS_MASK                = $FF000000;
  {$EXTERNALSYM CERT_RDN_FLAGS_MASK}

//+-------------------------------------------------------------------------
//  Flags that can be or'ed with the above Value Type when encoding/decoding
//--------------------------------------------------------------------------
// For encoding: when set, CERT_RDN_T61_STRING is selected instead of
// CERT_RDN_UNICODE_STRING if all the unicode characters are <= 0xFF
const
  CERT_RDN_ENABLE_T61_UNICODE_FLAG   = $80000000;
  {$EXTERNALSYM CERT_RDN_ENABLE_T61_UNICODE_FLAG}

// For encoding: when set, CERT_RDN_UTF8_STRING is selected instead of
// CERT_RDN_UNICODE_STRING.
const
  CERT_RDN_ENABLE_UTF8_UNICODE_FLAG  = $20000000;
  {$EXTERNALSYM CERT_RDN_ENABLE_UTF8_UNICODE_FLAG}

// For encoding: when set, CERT_RDN_UTF8_STRING is selected instead of
// CERT_RDN_PRINTABLE_STRING for DirectoryString types. Also,
// enables CERT_RDN_ENABLE_UTF8_UNICODE_FLAG.
const
  CERT_RDN_FORCE_UTF8_UNICODE_FLAG   = $10000000;
  {$EXTERNALSYM CERT_RDN_FORCE_UTF8_UNICODE_FLAG}

// For encoding: when set, the characters aren't checked to see if they
// are valid for the Value Type.
const
  CERT_RDN_DISABLE_CHECK_TYPE_FLAG   = $40000000;
  {$EXTERNALSYM CERT_RDN_DISABLE_CHECK_TYPE_FLAG}

// For decoding: by default, CERT_RDN_T61_STRING values are initially decoded
// as UTF8. If the UTF8 decoding fails, then, decoded as 8 bit characters.
// Setting this flag skips the initial attempt to decode as UTF8.
const
  CERT_RDN_DISABLE_IE4_UTF8_FLAG     = $01000000;
  {$EXTERNALSYM CERT_RDN_DISABLE_IE4_UTF8_FLAG}

// For encoding: If the string contains E/Email RDN, and the email-address
// (in RDN value) contains unicode characters outside of ASCII character set,
// the localpart and the hostname portion of the email-address would be first
// encoded in punycode and then the resultant Email-Address would be attempted
// to be encoded as IA5String. Punycode encoding of hostname is done on
// label-by-label basis.
// For decoding: If the name contains E/Email RDN, and local part or hostname
// portion of the email-address contains punycode encoded IA5String,
// The RDN string value is converted to its unicode equivalent.
const
  CERT_RDN_ENABLE_PUNYCODE_FLAG      = $02000000;
  {$EXTERNALSYM CERT_RDN_ENABLE_PUNYCODE_FLAG}

// Macro to check that the dwValueType is a character string and not an
// encoded blob or octet string
function IS_CERT_RDN_CHAR_STRING(X: DWORD): Boolean; inline;
{$EXTERNALSYM IS_CERT_RDN_CHAR_STRING}

//+-------------------------------------------------------------------------
//  A CERT_RDN consists of an array of the above attributes
//--------------------------------------------------------------------------
type
  PCertRDN = ^TCertRDN;
  _CERT_RDN = record
    cRDNAttr: DWORD;
    rgRDNAttr: PCertRDNAttr;
  end;
  {$EXTERNALSYM _CERT_RDN}
  CERT_RDN = _CERT_RDN;
  {$EXTERNALSYM CERT_RDN}
  TCertRDN = _CERT_RDN;
  PCERT_RDN = PCertRDN;
  {$EXTERNALSYM PCERT_RDN}

//+-------------------------------------------------------------------------
//  Information stored in a subject's or issuer's name. The information
//  is represented as an array of the above RDNs.
//--------------------------------------------------------------------------
type
  PCertNameInfo = ^TCertNameInfo;
  _CERT_NAME_INFO = record
    cRDN: DWORD;
    rgRDN: PCertRDN;
  end;
  {$EXTERNALSYM _CERT_NAME_INFO}
  CERT_NAME_INFO = _CERT_NAME_INFO;
  {$EXTERNALSYM CERT_NAME_INFO}
  TCertNameInfo = _CERT_NAME_INFO;
  PCERT_NAME_INFO = PCertNameInfo;
  {$EXTERNALSYM TCertNameInfo}

//+-------------------------------------------------------------------------
//  Name attribute value without the Object Identifier
//
//  The interpretation of the Value depends on the dwValueType.
//  See above for a list of the types.
//--------------------------------------------------------------------------
type
  PCertNameValue = ^TCertNameValue;
  _CERT_NAME_VALUE = record
    dwValueType: DWORD;
    Value: TCertRDNValueBlob;
  end;
  {$EXTERNALSYM _CERT_NAME_VALUE}
  CERT_NAME_VALUE = _CERT_NAME_VALUE;
  {$EXTERNALSYM CERT_NAME_VALUE}
  TCertNameValue = _CERT_NAME_VALUE;
  PCERT_NAME_VALUE = PCertNameValue;
  {$EXTERNALSYM PCERT_NAME_VALUE}

//+-------------------------------------------------------------------------
//  Public Key Info
//
//  The PublicKey is the encoded representation of the information as it is
//  stored in the bit string
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_CONTEXT
type
  PCertPublicKeyInfo = ^TCertPublicKeyInfo;
  _CERT_PUBLIC_KEY_INFO = record
    Algorithm: TCryptAlgorithmIdentifier;
    PublicKey: TCryptBitBlob;
  end;
  {$EXTERNALSYM _CERT_PUBLIC_KEY_INFO}
  CERT_PUBLIC_KEY_INFO = _CERT_PUBLIC_KEY_INFO;
  {$EXTERNALSYM CERT_PUBLIC_KEY_INFO}
  TCertPublicKeyInfo = _CERT_PUBLIC_KEY_INFO;
  PCERT_PUBLIC_KEY_INFO = PCertPublicKeyInfo;
  {$EXTERNALSYM PCERT_PUBLIC_KEY_INFO}
// certenrolls_end

const
  CERT_RSA_PUBLIC_KEY_OBJID           = szOID_RSA_RSA;
  {$EXTERNALSYM CERT_RSA_PUBLIC_KEY_OBJID}
  CERT_DEFAULT_OID_PUBLIC_KEY_SIGN    = szOID_RSA_RSA;
  {$EXTERNALSYM CERT_DEFAULT_OID_PUBLIC_KEY_SIGN}
  CERT_DEFAULT_OID_PUBLIC_KEY_XCHG    = szOID_RSA_RSA;
  {$EXTERNALSYM CERT_DEFAULT_OID_PUBLIC_KEY_XCHG}

//+-------------------------------------------------------------------------
//  ECC Private Key Info
//--------------------------------------------------------------------------
type
  PCryptECCPrivateKeyInfo = ^TCryptECCPrivateKeyInfo;
  _CRYPT_ECC_PRIVATE_KEY_INFO = record
    dwVersion: DWORD;                         // ecPrivKeyVer1(1)
    PrivateKey: TCryptDERBlob;                // d
    szCurveOid: LPSTR;                        // Optional
    PublicKey: TCryptBitBlob;                 // Optional (x, y)
  end;
  {$EXTERNALSYM _CRYPT_ECC_PRIVATE_KEY_INFO}
  CRYPT_ECC_PRIVATE_KEY_INFO = _CRYPT_ECC_PRIVATE_KEY_INFO;
  {$EXTERNALSYM CRYPT_ECC_PRIVATE_KEY_INFO}
  TCryptECCPrivateKeyInfo = _CRYPT_ECC_PRIVATE_KEY_INFO;
  PCRYPT_ECC_PRIVATE_KEY_INFO = PCryptECCPrivateKeyInfo;
  {$EXTERNALSYM PCRYPT_ECC_PRIVATE_KEY_INFO}

const
  CRYPT_ECC_PRIVATE_KEY_INFO_v1      = 1;
  {$EXTERNALSYM CRYPT_ECC_PRIVATE_KEY_INFO_v1}

//+-------------------------------------------------------------------------
//  structure that contains all the information in a PKCS#8 PrivateKeyInfo
//--------------------------------------------------------------------------
type
  PCryptPrivateKeyInfo = ^TCryptPrivateKeyInfo;
  _CRYPT_PRIVATE_KEY_INFO = record
    Version: DWORD;
    Algorithm: TCryptAlgorithmIdentifier;
    PrivateKey: TCryptDERBlob;
    pAttributes: PCryptAttributes;
  end;
  {$EXTERNALSYM _CRYPT_PRIVATE_KEY_INFO}
  CRYPT_PRIVATE_KEY_INFO = _CRYPT_PRIVATE_KEY_INFO;
  {$EXTERNALSYM CRYPT_PRIVATE_KEY_INFO}
  TCryptPrivateKeyInfo = _CRYPT_PRIVATE_KEY_INFO;
  PCRYPT_PRIVATE_KEY_INFO = PCryptPrivateKeyInfo;
  {$EXTERNALSYM PCRYPT_PRIVATE_KEY_INFO}

//+-------------------------------------------------------------------------
//  structure that contains all the information in a PKCS#8
//  EncryptedPrivateKeyInfo
//--------------------------------------------------------------------------
type
  PCryptEncryptedPrivateKeyInfo = ^TCryptEncryptedPrivateKeyInfo;
  _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO = record
    EncryptionAlgorithm: TCryptAlgorithmIdentifier;
    EncryptedPrivateKey: TCryptDataBlob;
  end;
  {$EXTERNALSYM _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO}
  CRYPT_ENCRYPTED_PRIVATE_KEY_INFO = _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO;
  {$EXTERNALSYM CRYPT_ENCRYPTED_PRIVATE_KEY_INFO}
  TCryptEncryptedPrivateKeyInfo = _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO;
  PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO = PCryptEncryptedPrivateKeyInfo;
  {$EXTERNALSYM PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO}

//+-------------------------------------------------------------------------
// this callback is given when an EncryptedProvateKeyInfo structure is
// encountered during ImportPKCS8.  the caller is then expected to decrypt
// the private key and hand back the decrypted contents.
//
// the parameters are:
// Algorithm - the algorithm used to encrypt the PrivateKeyInfo
// EncryptedPrivateKey - the encrypted private key blob
// pClearTextKey - a buffer to receive the clear text
// cbClearTextKey - the number of bytes of the pClearTextKey buffer
//                  note the if this is zero then this should be
//                  filled in with the size required to decrypt the
//                  key into, and pClearTextKey should be ignored
// pVoidDecryptFunc - this is the pVoid that was passed into the call
//                    and is preserved and passed back as context
//+-------------------------------------------------------------------------
type
  PCRYPT_DECRYPT_PRIVATE_KEY_FUNC = function(
    Algorithm: TCryptAlgorithmIdentifier;
    EncryptedPrivateKey: TCryptDataBlob;
    pbClearTextKey: PByte;
    out pcbClearTextKey: DWORD;
    pVoidDecryptFunc: LPVOID): BOOL; winapi;
  {$EXTERNALSYM PCRYPT_DECRYPT_PRIVATE_KEY_FUNC}
  TCryptDecryptPrivateKeyFunc = PCRYPT_DECRYPT_PRIVATE_KEY_FUNC;

//+-------------------------------------------------------------------------
// this callback is given when creating a PKCS8 EncryptedPrivateKeyInfo.
// The caller is then expected to encrypt the private key and hand back
// the encrypted contents.
//
// the parameters are:
// Algorithm - the algorithm used to encrypt the PrivateKeyInfo
// pClearTextPrivateKey - the cleartext private key to be encrypted
// pbEncryptedKey - the output encrypted private key blob
// cbEncryptedKey - the number of bytes of the pbEncryptedKey buffer
//                  note the if this is zero then this should be
//                  filled in with the size required to encrypt the
//                  key into, and pbEncryptedKey should be ignored
// pVoidEncryptFunc - this is the pVoid that was passed into the call
//                    and is preserved and passed back as context
//+-------------------------------------------------------------------------
type
  PCRYPT_ENCRYPT_PRIVATE_KEY_FUNC = function(
    pAlgorithm: PCryptAlgorithmIdentifier;
    pClearTextPrivateKey: PCryptDataBlob;
    pbEncryptedKey: PByte;
    out pcbEncryptedKey: DWORD;
    pVoidEncryptFunc: LPVOID): BOOL; winapi;
  {$EXTERNALSYM PCRYPT_ENCRYPT_PRIVATE_KEY_FUNC}
  TCryptEncryptPrivateKeyFunc = PCRYPT_ENCRYPT_PRIVATE_KEY_FUNC;

//+-------------------------------------------------------------------------
// this callback is given from the context of a ImportPKCS8 calls.  the caller
// is then expected to hand back an HCRYPTPROV to receive the key being imported
//
// the parameters are:
// pPrivateKeyInfo - pointer to a CRYPT_PRIVATE_KEY_INFO structure which
//                   describes the key being imported
// EncryptedPrivateKey - the encrypted private key blob
// phCryptProv - a pointer to a HCRRYPTPROV to be filled in
// pVoidResolveFunc - this is the pVoidResolveFunc passed in by the caller in the
//                    CRYPT_PRIVATE_KEY_BLOB_AND_PARAMS struct
//+-------------------------------------------------------------------------
type
  PCRYPT_RESOLVE_HCRYPTPROV_FUNC = function(
    pPrivateKeyInfo: PCryptPrivateKeyInfo;
    out phCryptProv: HCRYPTPROV;
    pVoidResolveFunc: LPVOID): BOOL; winapi;
  {$EXTERNALSYM PCRYPT_RESOLVE_HCRYPTPROV_FUNC}
  TCryptResolveHCryptProvFunc = PCRYPT_RESOLVE_HCRYPTPROV_FUNC;

//+-------------------------------------------------------------------------
// this struct contains a PKCS8 private key and two pointers to callback
// functions, with a corresponding pVoids.  the first callback is used to give
// the caller the opportunity to specify where the key is imported to.  the callback
// passes the caller the algoroithm OID and key size to use in making the decision.
// the other callback is used to decrypt the private key if the PKCS8 contains an
// EncryptedPrivateKeyInfo.  both pVoids are preserved and passed back to the caller
// in the respective callback
//+-------------------------------------------------------------------------
type
  PCryptPKCS8ImportParams = ^TCryptPKCS8ImportParams;
  _CRYPT_PKCS8_IMPORT_PARAMS = record
    PrivateKey: TCryptDigestBlob;                            // PKCS8 blob
    pResolvehCryptProvFunc: TCryptResolveHCryptProvFunc;     // optional
    pVoidResolveFunc: LPVOID;                                // optional
    pDecryptPrivateKeyFunc: TCryptDecryptPrivateKeyFunc;
    pVoidDecryptFunc: LPVOID;
  end;
  {$EXTERNALSYM _CRYPT_PKCS8_IMPORT_PARAMS}
  CRYPT_PKCS8_IMPORT_PARAMS = _CRYPT_PKCS8_IMPORT_PARAMS;
  {$EXTERNALSYM CRYPT_PKCS8_IMPORT_PARAMS}
  TCryptPKCS8ImportParams = _CRYPT_PKCS8_IMPORT_PARAMS;
  PCRYPT_PKCS8_IMPORT_PARAMS = PCryptPKCS8ImportParams;
  {$EXTERNALSYM PCRYPT_PKCS8_IMPORT_PARAMS}

  PCryptPrivateKeyBlobAndParams = ^TCryptPrivateKeyBlobAndParams;
  CRYPT_PRIVATE_KEY_BLOB_AND_PARAMS = _CRYPT_PKCS8_IMPORT_PARAMS;
  {$EXTERNALSYM CRYPT_PRIVATE_KEY_BLOB_AND_PARAMS}
  TCryptPrivateKeyBlobAndParams = _CRYPT_PKCS8_IMPORT_PARAMS;
  PCRYPT_PRIVATE_KEY_BLOB_AND_PARAMS = PCryptPrivateKeyBlobAndParams;
  {$EXTERNALSYM PCRYPT_PRIVATE_KEY_BLOB_AND_PARAMS}

//+-------------------------------------------------------------------------
// this struct contains information identifying a private key and a pointer
// to a callback function, with a corresponding pVoid. The callback is used
// to encrypt the private key. If the pEncryptPrivateKeyFunc is NULL, the
// key will not be encrypted and an EncryptedPrivateKeyInfo will not be generated.
// The pVoid is preserved and passed back to the caller in the respective callback
//+-------------------------------------------------------------------------
type
  PCryptPKCS8ExportParams = ^TCryptPKCS8ExportParams;
  _CRYPT_PKCS8_EXPORT_PARAMS = record
    hCryptProv: HCRYPTPROV;
    dwKeySpec: DWORD;
    pszPrivateKeyObjId: LPSTR;

    pEncryptPrivateKeyFunc: TCryptEncryptPrivateKeyFunc;
    pVoidEncryptFunc: LPVOID;
  end;
  {$EXTERNALSYM _CRYPT_PKCS8_EXPORT_PARAMS}
  CRYPT_PKCS8_EXPORT_PARAMS = _CRYPT_PKCS8_EXPORT_PARAMS;
  {$EXTERNALSYM CRYPT_PKCS8_EXPORT_PARAMS}
  TCryptPKCS8ExportParams = _CRYPT_PKCS8_EXPORT_PARAMS;
  PCRYPT_PKCS8_EXPORT_PARAMS = PCryptPKCS8ExportParams;
  {$EXTERNALSYM PCRYPT_PKCS8_EXPORT_PARAMS}

//+-------------------------------------------------------------------------
//  Information stored in a certificate
//
//  The Issuer, Subject, Algorithm, PublicKey and Extension BLOBs are the
//  encoded representation of the information.
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_CONTEXT
type
  PCertInfo = ^TCertInfo;
  _CERT_INFO = record
    dwVersion: DWORD;
    SerialNumber: TCryptIntegerBlob;
    SignatureAlgorithm: TCryptAlgorithmIdentifier;
    Issuer: TCertNameBlob;
    NotBefore: TFileTime;
    NotAfter: TFileTime;
    Subject: TCertNameBlob;
    SubjectPublicKeyInfo: TCertPublicKeyInfo;
    IssuerUniqueId: TCryptBitBlob;
    SubjectUniqueId: TCryptBitBlob;
    cExtension: DWORD;
    rgExtension: PCertExtension;
  end;
  {$EXTERNALSYM _CERT_INFO}
  CERT_INFO = _CERT_INFO;
  {$EXTERNALSYM CERT_INFO}
  TCertInfo = _CERT_INFO;
  PCERT_INFO = PCertInfo;
  {$EXTERNALSYM PCERT_INFO}
// certenrolls_end

//+-------------------------------------------------------------------------
//  Certificate versions
//--------------------------------------------------------------------------
const
  CERT_V1    = 0;
  {$EXTERNALSYM CERT_V1}
  CERT_V2    = 1;
  {$EXTERNALSYM CERT_V2}
  CERT_V3    = 2;
  {$EXTERNALSYM CERT_V3}

//+-------------------------------------------------------------------------
//  Certificate Information Flags
//--------------------------------------------------------------------------
const
  CERT_INFO_VERSION_FLAG                     = 1;
  {$EXTERNALSYM CERT_INFO_VERSION_FLAG}
  CERT_INFO_SERIAL_NUMBER_FLAG               = 2;
  {$EXTERNALSYM CERT_INFO_SERIAL_NUMBER_FLAG}
  CERT_INFO_SIGNATURE_ALGORITHM_FLAG         = 3;
  {$EXTERNALSYM CERT_INFO_SIGNATURE_ALGORITHM_FLAG}
  CERT_INFO_ISSUER_FLAG                      = 4;
  {$EXTERNALSYM CERT_INFO_ISSUER_FLAG}
  CERT_INFO_NOT_BEFORE_FLAG                  = 5;
  {$EXTERNALSYM CERT_INFO_NOT_BEFORE_FLAG}
  CERT_INFO_NOT_AFTER_FLAG                   = 6;
  {$EXTERNALSYM CERT_INFO_NOT_AFTER_FLAG}
  CERT_INFO_SUBJECT_FLAG                     = 7;
  {$EXTERNALSYM CERT_INFO_SUBJECT_FLAG}
  CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG     = 8;
  {$EXTERNALSYM CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG}
  CERT_INFO_ISSUER_UNIQUE_ID_FLAG            = 9;
  {$EXTERNALSYM CERT_INFO_ISSUER_UNIQUE_ID_FLAG}
  CERT_INFO_SUBJECT_UNIQUE_ID_FLAG           = 10;
  {$EXTERNALSYM CERT_INFO_SUBJECT_UNIQUE_ID_FLAG}
  CERT_INFO_EXTENSION_FLAG                   = 11;
  {$EXTERNALSYM CERT_INFO_EXTENSION_FLAG}

//+-------------------------------------------------------------------------
//  An entry in a CRL
//
//  The Extension BLOBs are the encoded representation of the information.
//--------------------------------------------------------------------------
type
  PCRLEntry = ^TCRLEntry;
  _CRL_ENTRY = record
    SerialNumber: TCryptIntegerBlob;
    RevocationDate: TFileTime;
    cExtension: DWORD;
    rgExtension: PCertExtension;
  end;
  {$EXTERNALSYM _CRL_ENTRY}
  CRL_ENTRY = _CRL_ENTRY;
  {$EXTERNALSYM CRL_ENTRY}
  TCRLEntry = _CRL_ENTRY;
  PCRL_ENTRY = PCRLEntry;
  {$EXTERNALSYM PCRL_ENTRY}

//+-------------------------------------------------------------------------
//  Information stored in a CRL
//
//  The Issuer, Algorithm and Extension BLOBs are the encoded
//  representation of the information.
//--------------------------------------------------------------------------
type
  PCRLInfo = ^TCRLInfo;
  _CRL_INFO = record
    dwVersion: DWORD;
    SignatureAlgorithm: TCryptAlgorithmIdentifier;
    Issuer: TCertNameBlob;
    ThisUpdate: TFileTime;
    NextUpdate: TFileTime;
    cCRLEntry: DWORD;
    rgCRLEntry: PCRLEntry;
    cExtension: DWORD;
    rgExtension:  PCertExtension;
  end;
  {$EXTERNALSYM _CRL_INFO}
  CRL_INFO = _CRL_INFO;
  {$EXTERNALSYM CRL_INFO}
  TCRLInfo = _CRL_INFO;
  PCRL_INFO = PCRLInfo;
  {$EXTERNALSYM PCRL_INFO}

//+-------------------------------------------------------------------------
//  CRL versions
//--------------------------------------------------------------------------
const
  CRL_V1    = 0;
  {$EXTERNALSYM CRL_V1}
  CRL_V2    = 1;
  {$EXTERNALSYM CRL_V2}

//+-------------------------------------------------------------------------
// Certificate Bundle
//--------------------------------------------------------------------------
const
  CERT_BUNDLE_CERTIFICATE = 0;
  {$EXTERNALSYM CERT_BUNDLE_CERTIFICATE}
  CERT_BUNDLE_CRL         = 1;
  {$EXTERNALSYM CERT_BUNDLE_CRL}

type
  PCertOrCRLBlob = ^TCertOrCRLBlob;
  _CERT_OR_CRL_BLOB = record
    dwChoice: DWORD;
    cbEncoded: DWORD;
    pbEncoded: PByte;
  end;
  {$EXTERNALSYM _CERT_OR_CRL_BLOB}
  CERT_OR_CRL_BLOB = _CERT_OR_CRL_BLOB;
  {$EXTERNALSYM CERT_OR_CRL_BLOB}
  TCertOrCRLBlob = _CERT_OR_CRL_BLOB;
  PCERT_OR_CRL_BLOB = PCertOrCRLBlob;
  {$EXTERNALSYM PCERT_OR_CRL_BLOB}

type
  PCertOrCRLBundle = ^TCertOrCRLBundle;
  _CERT_OR_CRL_BUNDLE = record
    cItem: DWORD;
    rgItem: PCertOrCRLBlob;
  end;
  {$EXTERNALSYM _CERT_OR_CRL_BUNDLE}
  CERT_OR_CRL_BUNDLE = _CERT_OR_CRL_BUNDLE;
  {$EXTERNALSYM CERT_OR_CRL_BUNDLE}
  TCertOrCRLBundle = _CERT_OR_CRL_BUNDLE;
  PCERT_OR_CRL_BUNDLE = PCertOrCRLBundle;
  {$EXTERNALSYM PCERT_OR_CRL_BUNDLE}

//+-------------------------------------------------------------------------
//  Information stored in a certificate request
//
//  The Subject, Algorithm, PublicKey and Attribute BLOBs are the encoded
//  representation of the information.
//--------------------------------------------------------------------------
type
  PCertRequestInfo = ^TCertRequestInfo;
  _CERT_REQUEST_INFO = record
    dwVersion: DWORD;
    Subject: TCertNameBlob;
    SubjectPublicKeyInfo: TCertPublicKeyInfo;
    cAttribute: DWORD;
    rgAttribute: PCryptAttribute;
  end;
  {$EXTERNALSYM _CERT_REQUEST_INFO}
  CERT_REQUEST_INFO = _CERT_REQUEST_INFO;
  {$EXTERNALSYM CERT_REQUEST_INFO}
  TCertRequestInfo = _CERT_REQUEST_INFO;
  PCERT_REQUEST_INFO = PCertRequestInfo;
  {$EXTERNALSYM PCERT_REQUEST_INFO}

//+-------------------------------------------------------------------------
//  Certificate Request versions
//--------------------------------------------------------------------------
const
  CERT_REQUEST_V1    = 0;
  {$EXTERNALSYM CERT_REQUEST_V1}

//+-------------------------------------------------------------------------
//  Information stored in Netscape's Keygen request
//--------------------------------------------------------------------------
type
  PCertKeygenRequestInfo = ^TCertKeygenRequestInfo;
  _CERT_KEYGEN_REQUEST_INFO = record
    dwVersion: DWORD;
    SubjectPublicKeyInfo: TCertPublicKeyInfo;
    pwszChallengeString: LPWSTR;                     // encoded as IA5
  end;
  {$EXTERNALSYM _CERT_KEYGEN_REQUEST_INFO}
  CERT_KEYGEN_REQUEST_INFO = _CERT_KEYGEN_REQUEST_INFO;
  {$EXTERNALSYM CERT_KEYGEN_REQUEST_INFO}
  TCertKeygenRequestInfo = _CERT_KEYGEN_REQUEST_INFO;
  PCERT_KEYGEN_REQUEST_INFO = PCertKeygenRequestInfo;
  {$EXTERNALSYM PCERT_KEYGEN_REQUEST_INFO}

const
  CERT_KEYGEN_REQUEST_V1    = 0;
  {$EXTERNALSYM CERT_KEYGEN_REQUEST_V1}

//+-------------------------------------------------------------------------
//  Certificate, CRL, Certificate Request or Keygen Request Signed Content
//
//  The "to be signed" encoded content plus its signature. The ToBeSigned
//  is the encoded CERT_INFO, CRL_INFO, CERT_REQUEST_INFO or
//  CERT_KEYGEN_REQUEST_INFO.
//--------------------------------------------------------------------------
type
  PCertSignedContentInfo = ^TCertSignedContentInfo;
  _CERT_SIGNED_CONTENT_INFO = record
    ToBeSigned: TCryptDERBlob;
    SignatureAlgorithm: TCryptAlgorithmIdentifier;
    Signature: TCryptBitBlob;
  end;
  {$EXTERNALSYM _CERT_SIGNED_CONTENT_INFO}
  CERT_SIGNED_CONTENT_INFO = _CERT_SIGNED_CONTENT_INFO;
  {$EXTERNALSYM CERT_SIGNED_CONTENT_INFO}
  TCertSignedContentInfo = _CERT_SIGNED_CONTENT_INFO;
  PCERT_SIGNED_CONTENT_INFO = PCertSignedContentInfo;
  {$EXTERNALSYM PCERT_SIGNED_CONTENT_INFO}

//+-------------------------------------------------------------------------
//  Certificate Trust List (CTL)
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CTL Usage. Also used for EnhancedKeyUsage extension.
//--------------------------------------------------------------------------
type
  PCTLUsage = ^TCTLUsage;
  _CTL_USAGE = record
    cUsageIdentifier: DWORD;
    rgpszUsageIdentifier: PLPSTR;                    // array of pszObjId
  end;
  {$EXTERNALSYM _CTL_USAGE}
  CTL_USAGE = _CTL_USAGE;
  {$EXTERNALSYM CTL_USAGE}
  TCTLUsage = _CTL_USAGE;
  PCTL_USAGE = PCTLUsage;
  {$EXTERNALSYM PCTL_USAGE}

  PCertEnhKeyUsage = ^TCertEnhKeyUsage;
  CERT_ENHKEY_USAGE = _CTL_USAGE;
  {$EXTERNALSYM CERT_ENHKEY_USAGE}
  TCertEnhKeyUsage = _CTL_USAGE;
  PCERT_ENHKEY_USAGE = PCertEnhKeyUsage;
  {$EXTERNALSYM PCERT_ENHKEY_USAGE}

  PCCTL_USAGE = PCTLUsage;
  {$EXTERNALSYM PCCTL_USAGE}

  PCCERT_ENHKEY_USAGE = PCertEnhKeyUsage;
  {$EXTERNALSYM PCCERT_ENHKEY_USAGE}

//+-------------------------------------------------------------------------
//  An entry in a CTL
//--------------------------------------------------------------------------
type
  PCTLEntry = ^TCTLEntry;
  _CTL_ENTRY = record
    SubjectIdentifier: TCryptDataBlob;               // For example, its hash
    cAttribute: DWORD;
    rgAttribute: PCryptAttribute                     // OPTIONAL
  end;
  {$EXTERNALSYM _CTL_ENTRY}
  CTL_ENTRY = _CTL_ENTRY;
  {$EXTERNALSYM CTL_ENTRY}
  TCTLEntry = _CTL_ENTRY;
  PCTL_ENTRY = PCTLEntry;
  {$EXTERNALSYM PCTL_ENTRY}

//+-------------------------------------------------------------------------
//  Information stored in a CTL
//--------------------------------------------------------------------------
type
  PCTLInfo = ^TCTLInfo;
  _CTL_INFO = record
    dwVersion: DWORD;
    SubjectUsage: TCTLUsage;
    ListIdentifier: TCryptDataBlob;                  // OPTIONAL
    SequenceNumber: TCryptIntegerBlob;               // OPTIONAL
    ThisUpdate: TFileTime;
    NextUpdate: TFileTime;                           // OPTIONAL
    SubjectAlgorithm: TCryptAlgorithmIdentifier;
    cCTLEntry: DWORD;
    rgCTLEntry: PCTLEntry;                           // OPTIONAL
    cExtension: DWORD;
    rgExtension: PCertExtension;                     // OPTIONAL
  end;
  {$EXTERNALSYM _CTL_INFO}
  CTL_INFO = _CTL_INFO;
  {$EXTERNALSYM CTL_INFO}
  TCTLInfo = _CTL_INFO;
  PCTL_INFO = PCTLInfo;
  {$EXTERNALSYM PCTL_INFO}

//+-------------------------------------------------------------------------
//  CTL versions
//--------------------------------------------------------------------------
const
  CTL_V1    = 0;
  {$EXTERNALSYM CTL_V1}

//+-------------------------------------------------------------------------
//  TimeStamp Request
//
//  The pszTimeStamp is the OID for the Time type requested
//  The pszContentType is the Content Type OID for the content, usually DATA
//  The Content is a un-decoded blob
//--------------------------------------------------------------------------
type
  PCryptTimeStampRequestInfo = ^TCryptTimeStampRequestInfo;
  _CRYPT_TIME_STAMP_REQUEST_INFO = record
    pszTimeStampAlgorithm: LPSTR;                    // pszObjId
    pszContentType: LPSTR;                           // pszObjId
    Content: TCryptObjIDBlob;
    cAttribute: DWORD;
    rgAttribute: PCryptAttribute;
  end;
  {$EXTERNALSYM _CRYPT_TIME_STAMP_REQUEST_INFO}
  CRYPT_TIME_STAMP_REQUEST_INFO = _CRYPT_TIME_STAMP_REQUEST_INFO;
  {$EXTERNALSYM CRYPT_TIME_STAMP_REQUEST_INFO}
  TCryptTimeStampRequestInfo = _CRYPT_TIME_STAMP_REQUEST_INFO;
  PCRYPT_TIME_STAMP_REQUEST_INFO = PCryptTimeStampRequestInfo;
  {$EXTERNALSYM PCRYPT_TIME_STAMP_REQUEST_INFO}

//+-------------------------------------------------------------------------
//  Name Value Attribute
//--------------------------------------------------------------------------
type
  PCryptEntrollmentNameValuePair = ^TCryptEntrollmentNameValuePair;
  _CRYPT_ENROLLMENT_NAME_VALUE_PAIR = record
    pwszName: LPWSTR;
    pwszValue: LPWSTR;
  end;
  {$EXTERNALSYM _CRYPT_ENROLLMENT_NAME_VALUE_PAIR}
  CRYPT_ENROLLMENT_NAME_VALUE_PAIR = _CRYPT_ENROLLMENT_NAME_VALUE_PAIR;
  {$EXTERNALSYM CRYPT_ENROLLMENT_NAME_VALUE_PAIR}
  TCryptEntrollmentNameValuePair = _CRYPT_ENROLLMENT_NAME_VALUE_PAIR;
  PCRYPT_ENROLLMENT_NAME_VALUE_PAIR = PCryptEntrollmentNameValuePair;
  {$EXTERNALSYM PCRYPT_ENROLLMENT_NAME_VALUE_PAIR}

//+-------------------------------------------------------------------------
//  CSP Provider
//--------------------------------------------------------------------------
type
  PCryptCSPProvider = ^TCryptCSPProvider;
  _CRYPT_CSP_PROVIDER = record
    dwKeySpec: DWORD;
    pwszProviderName: LPWSTR;
    Signature: TCryptBitBlob;
  end;
  {$EXTERNALSYM _CRYPT_CSP_PROVIDER}
  CRYPT_CSP_PROVIDER = _CRYPT_CSP_PROVIDER;
  {$EXTERNALSYM CRYPT_CSP_PROVIDER}
  TCryptCSPProvider = _CRYPT_CSP_PROVIDER;
  PCRYPT_CSP_PROVIDER = PCryptCSPProvider;
  {$EXTERNALSYM PCRYPT_CSP_PROVIDER}

//+-------------------------------------------------------------------------
//  Certificate and Message encoding types
//
//  The encoding type is a DWORD containing both the certificate and message
//  encoding types. The certificate encoding type is stored in the LOWORD.
//  The message encoding type is stored in the HIWORD. Some functions or
//  structure fields require only one of the encoding types. The following
//  naming convention is used to indicate which encoding type(s) are
//  required:
//      dwEncodingType              (both encoding types are required)
//      dwMsgAndCertEncodingType    (both encoding types are required)
//      dwMsgEncodingType           (only msg encoding type is required)
//      dwCertEncodingType          (only cert encoding type is required)
//
//  Its always acceptable to specify both.
//--------------------------------------------------------------------------
const
  CERT_ENCODING_TYPE_MASK    = $0000FFFF;
  {$EXTERNALSYM CERT_ENCODING_TYPE_MASK}
  CMSG_ENCODING_TYPE_MASK    = $FFFF0000;
  {$EXTERNALSYM CMSG_ENCODING_TYPE_MASK}

function GET_CERT_ENCODING_TYPE(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CERT_ENCODING_TYPE}
function GET_CMSG_ENCODING_TYPE(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CMSG_ENCODING_TYPE}

const
  CRYPT_ASN_ENCODING         = $00000001;
  {$EXTERNALSYM CRYPT_ASN_ENCODING}
  CRYPT_NDR_ENCODING         = $00000002;
  {$EXTERNALSYM CRYPT_NDR_ENCODING}
  X509_ASN_ENCODING          = $00000001;
  {$EXTERNALSYM X509_ASN_ENCODING}
  X509_NDR_ENCODING          = $00000002;
  {$EXTERNALSYM X509_NDR_ENCODING}
  PKCS_7_ASN_ENCODING        = $00010000;
  {$EXTERNALSYM PKCS_7_ASN_ENCODING}
  PKCS_7_NDR_ENCODING        = $00020000;
  {$EXTERNALSYM PKCS_7_NDR_ENCODING}


//+-------------------------------------------------------------------------
//  format the specified data structure according to the certificate
//  encoding type.
//
//  The default behavior of CryptFormatObject is to return single line
//  display of the encoded data, that is, each subfield will be concatenated with
//  a ", " on one line.  If user prefers to display the data in multiple line,
//  set the flag CRYPT_FORMAT_STR_MULTI_LINE, that is, each subfield will be displayed
//  on a seperate line.
//
//  If there is no formatting routine installed or registered
//  for the lpszStructType, the hex dump of the encoded BLOB will be returned.
//  User can set the flag CRYPT_FORMAT_STR_NO_HEX to disable the hex dump.
//--------------------------------------------------------------------------
function CryptFormatObject(
  dwCertEncodingType: DWORD;
  dwFormatType: DWORD;
  dwFormatStrType: DWORD;
  pFormatStruct: Pointer;
  lpszStructType: LPCSTR;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  pbFormat: Pointer;
  var pcbFormat: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptFormatObject}

//-------------------------------------------------------------------------
// constants for dwFormatStrType of function CryptFormatObject
//-------------------------------------------------------------------------
const
  CRYPT_FORMAT_STR_MULTI_LINE        = $0001;
  {$EXTERNALSYM CRYPT_FORMAT_STR_MULTI_LINE}
  CRYPT_FORMAT_STR_NO_HEX            = $0010;
  {$EXTERNALSYM CRYPT_FORMAT_STR_NO_HEX}

//-------------------------------------------------------------------------
// constants for dwFormatType of function CryptFormatObject
// when format X509_NAME or X509_UNICODE_NAME
//-------------------------------------------------------------------------
// Just get the simple string
const
  CRYPT_FORMAT_SIMPLE                = $0001;
  {$EXTERNALSYM CRYPT_FORMAT_SIMPLE}

//Put an attribute name infront of the attribute
//such as "O=Microsoft,DN=xiaohs"
const
  CRYPT_FORMAT_X509                  = $0002;
  {$EXTERNALSYM CRYPT_FORMAT_X509}

//Put an OID infront of the simple string, such as
//"2.5.4.22=Microsoft,2.5.4.3=xiaohs"
const
  CRYPT_FORMAT_OID                   = $0004;
  {$EXTERNALSYM CRYPT_FORMAT_OID}

//Put a ";" between each RDN.  The default is ","
const
  CRYPT_FORMAT_RDN_SEMICOLON         = $0100;
  {$EXTERNALSYM CRYPT_FORMAT_RDN_SEMICOLON}

//Put a "\n" between each RDN.
const
  CRYPT_FORMAT_RDN_CRLF              = $0200;
  {$EXTERNALSYM CRYPT_FORMAT_RDN_CRLF}


//Unquote the DN value, which is quoated by default va the following
//rules: if the DN contains leading or trailing
//white space or one of the following characters: ",", "+", "=",
//""", "\n",  "<", ">", "#" or ";". The quoting character is ".
//If the DN Value contains a " it is double quoted ("").
const
  CRYPT_FORMAT_RDN_UNQUOTE           = $0400;
  {$EXTERNALSYM CRYPT_FORMAT_RDN_UNQUOTE}

//reverse the order of the RDNs before converting to the string
const
  CRYPT_FORMAT_RDN_REVERSE           = $0800;
  {$EXTERNALSYM CRYPT_FORMAT_RDN_REVERSE}


//-------------------------------------------------------------------------
//  contants dwFormatType of function CryptFormatObject when format a DN.:
//
//  The following three values are defined in the section above:
//  CRYPT_FORMAT_SIMPLE:    Just a simple string
//                          such as  "Microsoft+xiaohs+NT"
//  CRYPT_FORMAT_X509       Put an attribute name infront of the attribute
//                          such as "O=Microsoft+xiaohs+NT"
//
//  CRYPT_FORMAT_OID        Put an OID infront of the simple string,
//                          such as "2.5.4.22=Microsoft+xiaohs+NT"
//
//  Additional values are defined as following:
//----------------------------------------------------------------------------
//Put a "," between each value.  Default is "+"
const
  CRYPT_FORMAT_COMMA                 = $1000;
  {$EXTERNALSYM CRYPT_FORMAT_COMMA}

//Put a ";" between each value
const
  CRYPT_FORMAT_SEMICOLON             = CRYPT_FORMAT_RDN_SEMICOLON;
  {$EXTERNALSYM CRYPT_FORMAT_SEMICOLON}

//Put a "\n" between each value
const
  CRYPT_FORMAT_CRLF                  = CRYPT_FORMAT_RDN_CRLF;
  {$EXTERNALSYM CRYPT_FORMAT_CRLF}

//+-------------------------------------------------------------------------
//  Encode / decode the specified data structure according to the certificate
//  encoding type.
//
//  See below for a list of the predefined data structures.
//--------------------------------------------------------------------------

type
  PFN_CRYPT_ALLOC = function(
    cbSize: size_t): LPVOID; winapi;
  {$EXTERNALSYM PFN_CRYPT_ALLOC}
  TFnCryptAlloc = PFN_CRYPT_ALLOC;

type
  PFN_CRYPT_FREE = procedure(
    pv: LPVOID); winapi;
  {$EXTERNALSYM PFN_CRYPT_FREE}
  TFnCryptFree = PFN_CRYPT_FREE;

type
  PCryptEncodePara = ^TCryptEncodePara;
  _CRYPT_ENCODE_PARA = record
    cbSize: DWORD;
    pfnAlloc: TFnCryptAlloc;                    // OPTIONAL
    pfnFree: TFnCryptFree;                      // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_ENCODE_PARA}
  CRYPT_ENCODE_PARA = _CRYPT_ENCODE_PARA;
  {$EXTERNALSYM CRYPT_ENCODE_PARA}
  TCryptEncodePara = _CRYPT_ENCODE_PARA;
  PCRYPT_ENCODE_PARA = PCryptEncodePara;
  {$EXTERNALSYM PCRYPT_ENCODE_PARA}

function CryptEncodeObjectEx(
  dwCertEncodingType: DWORD;
  lpszStructType: LPCSTR;
  pvStructInfo: Pointer;
  dwFlags: DWORD;
  pEncodePara: PCryptEncodePara;
  pvEncoded: Pointer;
  var pcbEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEncodeObjectEx}

function CryptEncodeObject(
  dwCertEncodingType: DWORD;
  lpszStructType: LPCSTR;
  pvStructInfo: Pointer;
  pbEncoded: PByte;
  var pcbEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEncodeObject}

// By default the signature bytes are reversed. The following flag can
// be set to inhibit the byte reversal.
//
// This flag is applicable to
//      X509_CERT_TO_BE_SIGNED
const
  CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG   = $8;
  {$EXTERNALSYM CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG}

//  When the following flag is set the called encode function allocates
//  memory for the encoded bytes. A pointer to the allocated bytes
//  is returned in pvEncoded. If pEncodePara or pEncodePara->pfnAlloc is
//  NULL, then, LocalAlloc is called for the allocation and LocalFree must
//  be called to do the free. Otherwise, pEncodePara->pfnAlloc is called
//  for the allocation.
//
//  *pcbEncoded is ignored on input and updated with the length of the
//  allocated, encoded bytes.
//
//  If pfnAlloc is set, then, pfnFree should also be set.
const
  CRYPT_ENCODE_ALLOC_FLAG            = $8000;
  {$EXTERNALSYM CRYPT_ENCODE_ALLOC_FLAG}

//  The following flag is applicable when encoding X509_UNICODE_NAME.
//  When set, CERT_RDN_T61_STRING is selected instead of
//  CERT_RDN_UNICODE_STRING if all the unicode characters are <= 0xFF
const
  CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG = CERT_RDN_ENABLE_T61_UNICODE_FLAG;
  {$EXTERNALSYM CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG}

//  The following flag is applicable when encoding X509_UNICODE_NAME.
//  When set, CERT_RDN_UTF8_STRING is selected instead of
//  CERT_RDN_UNICODE_STRING.
const
  CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG = CERT_RDN_ENABLE_UTF8_UNICODE_FLAG;
  {$EXTERNALSYM CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG}

//  The following flag is applicable when encoding X509_UNICODE_NAME.
//  When set, CERT_RDN_UTF8_STRING is selected instead of
//  CERT_RDN_PRINTABLE_STRING for DirectoryString types. Also,
//  enables CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG.
const
  CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG = CERT_RDN_FORCE_UTF8_UNICODE_FLAG;
  {$EXTERNALSYM CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG}

//  The following flag is applicable when encoding X509_UNICODE_NAME,
//  X509_UNICODE_NAME_VALUE or X509_UNICODE_ANY_STRING.
//  When set, the characters aren't checked to see if they
//  are valid for the specified Value Type.
const
  CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG = CERT_RDN_DISABLE_CHECK_TYPE_FLAG;
  {$EXTERNALSYM CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG}

//  The following flag is applicable when encoding the PKCS_SORTED_CTL. This
//  flag should be set if the identifier for the TrustedSubjects is a hash,
//  such as, MD5 or SHA1.
const
  CRYPT_SORTED_CTL_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG    = $10000;
  {$EXTERNALSYM CRYPT_SORTED_CTL_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG}

// The following flag is applicable when encoding structures that require
// IA5String encoding of host name(in DNS Name/ URL/ EmailAddress) containing
// non-IA5 characters by encoding the host name in punycode first.
const
  CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG  = $20000;
  {$EXTERNALSYM CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG}

// The following flag is applicable when encoding structures that require
// IA5String encoding of a path (http URL/Ldap query) containing non-IA5
// characters by encoding the path part as UTF8 percent encoding.
const
  CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG  = $40000;
  {$EXTERNALSYM CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG}

// The following flag is applicable when encoding structures that require
// IA5String encoding of the host name (URL) and path. If the data to be encoded
// contains non-IA5 characters then using this flag in during encoding will cause
// the hostname to be punycode and the path as UTF8-percent encoding
// For example: http://www.zzzzzz.com/yyyyy/qqqqq/rrrrrr.sssss
// If zzzzzz contains non-IA5 characters then using this flag will punycode
// encode the zzzzzz component.
// If yyyyy or qqqqq or rrrrrr or sssss contain non-IA5 characters then using
// this flag will UTF8 percent encode those characters which are not IA5.
const
  CRYPT_ENCODE_ENABLE_IA5CONVERSION_FLAG = (CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG or CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG);
  {$EXTERNALSYM CRYPT_ENCODE_ENABLE_IA5CONVERSION_FLAG}

type
  PCryptDecodePara = ^TCryptDecodePara;
  _CRYPT_DECODE_PARA = record
    cbSize: DWORD;
    pfnAlloc: TFnCryptAlloc;                    // OPTIONAL
    pfnFree: TFnCryptFree;                      // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_DECODE_PARA}
  CRYPT_DECODE_PARA = _CRYPT_DECODE_PARA;
  {$EXTERNALSYM CRYPT_DECODE_PARA}
  TCryptDecodePara = _CRYPT_DECODE_PARA;
  PCRYPT_DECODE_PARA = PCryptDecodePara;
  {$EXTERNALSYM PCRYPT_DECODE_PARA}

function CryptDecodeObjectEx(
  dwCertEncodingType: DWORD;
  lpszStructType: LPCSTR;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  dwFlags: DWORD;
  pDecodePara: PCryptDecodePara;
  pvStructInfo: Pointer;
  var pcbStructInfo: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptDecodeObjectEx}

function CryptDecodeObject(
  dwCertEncodingType: DWORD;
  lpszStructType: LPCSTR;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  dwFlags: DWORD;
  pvStructInfo: Pointer;
  var pcbStructInfo: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptDecodeObject}

// When the following flag is set the nocopy optimization is enabled.
// This optimization where appropriate, updates the pvStructInfo fields
// to point to content residing within pbEncoded instead of making a copy
// of and appending to pvStructInfo.
//
// Note, when set, pbEncoded can't be freed until pvStructInfo is freed.
const
  CRYPT_DECODE_NOCOPY_FLAG           = $1;
  {$EXTERNALSYM CRYPT_DECODE_NOCOPY_FLAG}

// For CryptDecodeObject(), by default the pbEncoded is the "to be signed"
// plus its signature. Set the following flag, if pbEncoded points to only
// the "to be signed".
//
// This flag is applicable to
//      X509_CERT_TO_BE_SIGNED
//      X509_CERT_CRL_TO_BE_SIGNED
//      X509_CERT_REQUEST_TO_BE_SIGNED
//      X509_KEYGEN_REQUEST_TO_BE_SIGNED
const
  CRYPT_DECODE_TO_BE_SIGNED_FLAG     = $2;
  {$EXTERNALSYM CRYPT_DECODE_TO_BE_SIGNED_FLAG}

// When the following flag is set, the OID strings are allocated in
// crypt32.dll and shared instead of being copied into the returned
// data structure. This flag may be set if crypt32.dll isn't unloaded
// before the caller is unloaded.
const
  CRYPT_DECODE_SHARE_OID_STRING_FLAG = $4;
  {$EXTERNALSYM CRYPT_DECODE_SHARE_OID_STRING_FLAG}

// By default the signature bytes are reversed. The following flag can
// be set to inhibit the byte reversal.
//
// This flag is applicable to
//      X509_CERT_TO_BE_SIGNED
const
  CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG   = $8;
  {$EXTERNALSYM CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG}

// When the following flag is set the called decode function allocates
// memory for the decoded structure. A pointer to the allocated structure
// is returned in pvStructInfo. If pDecodePara or pDecodePara->pfnAlloc is
// NULL, then, LocalAlloc is called for the allocation and LocalFree must
// be called to do the free. Otherwise, pDecodePara->pfnAlloc is called
// for the allocation.
//
// *pcbStructInfo is ignored on input and updated with the length of the
// allocated, decoded structure.
//
// This flag may also be set in the CryptDecodeObject API. Since
// CryptDecodeObject doesn't take a pDecodePara, LocalAlloc is always
// called for the allocation which must be freed by calling LocalFree.
const
  CRYPT_DECODE_ALLOC_FLAG            = $8000;
  {$EXTERNALSYM CRYPT_DECODE_ALLOC_FLAG}

// The following flag is applicable when decoding X509_UNICODE_NAME,
// X509_UNICODE_NAME_VALUE or X509_UNICODE_ANY_STRING.
// By default, CERT_RDN_T61_STRING values are initially decoded
// as UTF8. If the UTF8 decoding fails, then, decoded as 8 bit characters.
// Setting this flag skips the initial attempt to decode as UTF8.
const
  CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG = CERT_RDN_DISABLE_IE4_UTF8_FLAG;
  {$EXTERNALSYM CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG}

// The following flag is applicable when decoding structures that contain
// IA5String encoding of punycode encoded host name (in DNS Name/ URL/
// EmailAddress). Decoded value contains the the unicode equivalent of
// punycode encoded data.
const
  CRYPT_DECODE_ENABLE_PUNYCODE_FLAG  = 402000000;
  {$EXTERNALSYM CRYPT_DECODE_ENABLE_PUNYCODE_FLAG}

// The following flag is applicable when decoding structures that contain
// IA5String that is UTF8 percent encoded in the path part of a url.
const
  CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG = $04000000;
  {$EXTERNALSYM CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG}

// The following flag is applicable when decoding structures that contain
// an IA5String that is a punycode and UTF8-percent encoded host name and path (URL). The decoded
// value contains the Unicode equivalent of the punycode encoded host name and UTF8 percent
// encoded path.
const
  CRYPT_DECODE_ENABLE_IA5CONVERSION_FLAG = (CRYPT_DECODE_ENABLE_PUNYCODE_FLAG or CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG);
  {$EXTERNALSYM CRYPT_DECODE_ENABLE_IA5CONVERSION_FLAG}

//+-------------------------------------------------------------------------
//  Predefined X509 certificate data structures that can be encoded / decoded.
//--------------------------------------------------------------------------
const
  CRYPT_ENCODE_DECODE_NONE           = 0;
  {$EXTERNALSYM CRYPT_ENCODE_DECODE_NONE}
  X509_CERT                          = LPCSTR(1);
  {$EXTERNALSYM X509_CERT}
  X509_CERT_TO_BE_SIGNED             = LPCSTR(2);
  {$EXTERNALSYM X509_CERT_TO_BE_SIGNED}
  X509_CERT_CRL_TO_BE_SIGNED         = LPCSTR(3);
  {$EXTERNALSYM X509_CERT_CRL_TO_BE_SIGNED}
  X509_CERT_REQUEST_TO_BE_SIGNED     = LPCSTR(4);
  {$EXTERNALSYM X509_CERT_REQUEST_TO_BE_SIGNED}
  X509_EXTENSIONS                    = LPCSTR(5);
  {$EXTERNALSYM X509_EXTENSIONS}
  X509_NAME_VALUE                    = LPCSTR(6);
  {$EXTERNALSYM X509_NAME_VALUE}
  X509_NAME                          = LPCSTR(7);
  {$EXTERNALSYM X509_NAME}
  X509_PUBLIC_KEY_INFO               = LPCSTR(8);
  {$EXTERNALSYM X509_PUBLIC_KEY_INFO}

//+-------------------------------------------------------------------------
//  Predefined X509 certificate extension data structures that can be
//  encoded / decoded.
//--------------------------------------------------------------------------
const
  X509_AUTHORITY_KEY_ID              = LPCSTR(9);
  {$EXTERNALSYM X509_AUTHORITY_KEY_ID}
  X509_KEY_ATTRIBUTES                = LPCSTR(10);
  {$EXTERNALSYM X509_KEY_ATTRIBUTES}
  X509_KEY_USAGE_RESTRICTION         = LPCSTR(11);
  {$EXTERNALSYM X509_KEY_USAGE_RESTRICTION}
  X509_ALTERNATE_NAME                = LPCSTR(12);
  {$EXTERNALSYM X509_ALTERNATE_NAME}
  X509_BASIC_CONSTRAINTS             = LPCSTR(13);
  {$EXTERNALSYM X509_BASIC_CONSTRAINTS}
  X509_KEY_USAGE                     = LPCSTR(14);
  {$EXTERNALSYM X509_KEY_USAGE}
  X509_BASIC_CONSTRAINTS2            = LPCSTR(15);
  {$EXTERNALSYM X509_BASIC_CONSTRAINTS2}
  X509_CERT_POLICIES                 = LPCSTR(16);
  {$EXTERNALSYM X509_CERT_POLICIES}

//+-------------------------------------------------------------------------
//  Additional predefined data structures that can be encoded / decoded.
//--------------------------------------------------------------------------
const
  PKCS_UTC_TIME                      = LPCSTR(17);
  {$EXTERNALSYM PKCS_UTC_TIME}
  PKCS_TIME_REQUEST                  = LPCSTR(18);
  {$EXTERNALSYM PKCS_TIME_REQUEST}
  RSA_CSP_PUBLICKEYBLOB              = LPCSTR(19);
  {$EXTERNALSYM RSA_CSP_PUBLICKEYBLOB}
  X509_UNICODE_NAME                  = LPCSTR(20);
  {$EXTERNALSYM X509_UNICODE_NAME}

  X509_KEYGEN_REQUEST_TO_BE_SIGNED   = LPCSTR(21);
  {$EXTERNALSYM X509_KEYGEN_REQUEST_TO_BE_SIGNED}
  PKCS_ATTRIBUTE                     = LPCSTR(22);
  {$EXTERNALSYM PKCS_ATTRIBUTE}
  PKCS_CONTENT_INFO_SEQUENCE_OF_ANY  = LPCSTR(23);
  {$EXTERNALSYM PKCS_CONTENT_INFO_SEQUENCE_OF_ANY}

//+-------------------------------------------------------------------------
//  Predefined primitive data structures that can be encoded / decoded.
//--------------------------------------------------------------------------
const
  X509_UNICODE_NAME_VALUE            = LPCSTR(24);
  {$EXTERNALSYM X509_UNICODE_NAME_VALUE}
  X509_ANY_STRING                    = X509_NAME_VALUE;
  {$EXTERNALSYM X509_ANY_STRING}
  X509_UNICODE_ANY_STRING            = X509_UNICODE_NAME_VALUE;
  {$EXTERNALSYM X509_UNICODE_ANY_STRING}
  X509_OCTET_STRING                  = LPCSTR(25);
  {$EXTERNALSYM X509_OCTET_STRING}
  X509_BITS                          = LPCSTR(26);
  {$EXTERNALSYM X509_BITS}
  X509_INTEGER                       = LPCSTR(27);
  {$EXTERNALSYM X509_INTEGER}
  X509_MULTI_BYTE_INTEGER            = LPCSTR(28);
  {$EXTERNALSYM X509_MULTI_BYTE_INTEGER}
  X509_ENUMERATED                    = LPCSTR(29);
  {$EXTERNALSYM X509_ENUMERATED}
  X509_CHOICE_OF_TIME                = LPCSTR(30);
  {$EXTERNALSYM X509_CHOICE_OF_TIME}

//+-------------------------------------------------------------------------
//  More predefined X509 certificate extension data structures that can be
//  encoded / decoded.
//--------------------------------------------------------------------------
const
  X509_AUTHORITY_KEY_ID2             = LPCSTR(31);
  {$EXTERNALSYM X509_AUTHORITY_KEY_ID2}
  X509_AUTHORITY_INFO_ACCESS         = LPCSTR(32);
  {$EXTERNALSYM X509_AUTHORITY_INFO_ACCESS}
  X509_SUBJECT_INFO_ACCESS           = X509_AUTHORITY_INFO_ACCESS;
  {$EXTERNALSYM X509_SUBJECT_INFO_ACCESS}
  X509_CRL_REASON_CODE               = X509_ENUMERATED;
  {$EXTERNALSYM X509_CRL_REASON_CODE}
  PKCS_CONTENT_INFO                  = LPCSTR(33);
  {$EXTERNALSYM PKCS_CONTENT_INFO}
  X509_SEQUENCE_OF_ANY               = LPCSTR(34);
  {$EXTERNALSYM X509_SEQUENCE_OF_ANY}
  X509_CRL_DIST_POINTS               = LPCSTR(35);
  {$EXTERNALSYM X509_CRL_DIST_POINTS}
  X509_ENHANCED_KEY_USAGE            = LPCSTR(36);
  {$EXTERNALSYM X509_ENHANCED_KEY_USAGE}
  PKCS_CTL                           = LPCSTR(37);
  {$EXTERNALSYM PKCS_CTL}

  X509_MULTI_BYTE_UINT               = LPCSTR(38);
  {$EXTERNALSYM X509_MULTI_BYTE_UINT}
  X509_DSS_PUBLICKEY                 = X509_MULTI_BYTE_UINT;
  {$EXTERNALSYM X509_DSS_PUBLICKEY}
  X509_DSS_PARAMETERS                = LPCSTR(39);
  {$EXTERNALSYM X509_DSS_PARAMETERS}
  X509_DSS_SIGNATURE                 = LPCSTR(40);
  {$EXTERNALSYM X509_DSS_SIGNATURE}
  PKCS_RC2_CBC_PARAMETERS            = LPCSTR(41);
  {$EXTERNALSYM PKCS_RC2_CBC_PARAMETERS}
  PKCS_SMIME_CAPABILITIES            = LPCSTR(42);
  {$EXTERNALSYM PKCS_SMIME_CAPABILITIES}

// Qualified Certificate Statements Extension uses the same encode/decode
// function as PKCS_SMIME_CAPABILITIES. Its data structures are identical
// except for the names of the fields.
const
  X509_QC_STATEMENTS_EXT             = LPCSTR(42);
  {$EXTERNALSYM X509_QC_STATEMENTS_EXT}

//+-------------------------------------------------------------------------
//  data structures for private keys
//--------------------------------------------------------------------------
const
  PKCS_RSA_PRIVATE_KEY               = LPCSTR(43);
  {$EXTERNALSYM PKCS_RSA_PRIVATE_KEY}
  PKCS_PRIVATE_KEY_INFO              = LPCSTR(44);
  {$EXTERNALSYM PKCS_PRIVATE_KEY_INFO}
  PKCS_ENCRYPTED_PRIVATE_KEY_INFO    = LPCSTR(45);
  {$EXTERNALSYM PKCS_ENCRYPTED_PRIVATE_KEY_INFO}

//+-------------------------------------------------------------------------
//  certificate policy qualifier
//--------------------------------------------------------------------------
const
  X509_PKIX_POLICY_QUALIFIER_USERNOTICE = LPCSTR(46);
  {$EXTERNALSYM X509_PKIX_POLICY_QUALIFIER_USERNOTICE}

//+-------------------------------------------------------------------------
//  Diffie-Hellman Key Exchange
//--------------------------------------------------------------------------
const
  X509_DH_PUBLICKEY                  = X509_MULTI_BYTE_UINT;
  {$EXTERNALSYM X509_DH_PUBLICKEY}
  X509_DH_PARAMETERS                 = LPCSTR(47);
  {$EXTERNALSYM X509_DH_PARAMETERS}
  PKCS_ATTRIBUTES                    = LPCSTR(48);
  {$EXTERNALSYM PKCS_ATTRIBUTES}
  PKCS_SORTED_CTL                    = LPCSTR(49);
  {$EXTERNALSYM PKCS_SORTED_CTL}

//+-------------------------------------------------------------------------
//  ECC Signature
//--------------------------------------------------------------------------
// Uses the same encode/decode function as X509_DH_PARAMETERS. Its data
// structure is identical except for the names of the fields.
const
  X509_ECC_SIGNATURE                 = LPCSTR(47);
  {$EXTERNALSYM X509_ECC_SIGNATURE}

//+-------------------------------------------------------------------------
//  X942 Diffie-Hellman
//--------------------------------------------------------------------------
const
  X942_DH_PARAMETERS                 = LPCSTR(50);
  {$EXTERNALSYM X942_DH_PARAMETERS}

//+-------------------------------------------------------------------------
//  The following is the same as X509_BITS, except before encoding,
//  the bit length is decremented to exclude trailing zero bits.
//--------------------------------------------------------------------------
const
  X509_BITS_WITHOUT_TRAILING_ZEROES  = LPCSTR(51);
  {$EXTERNALSYM X509_BITS_WITHOUT_TRAILING_ZEROES}

//+-------------------------------------------------------------------------
//  X942 Diffie-Hellman Other Info
//--------------------------------------------------------------------------
const
  X942_OTHER_INFO                    = LPCSTR(52);
  {$EXTERNALSYM X942_OTHER_INFO}

  X509_CERT_PAIR                     = LPCSTR(53);
  {$EXTERNALSYM X509_CERT_PAIR}
  X509_ISSUING_DIST_POINT            = LPCSTR(54);
  {$EXTERNALSYM X509_ISSUING_DIST_POINT}
  X509_NAME_CONSTRAINTS              = LPCSTR(55);
  {$EXTERNALSYM X509_NAME_CONSTRAINTS}
  X509_POLICY_MAPPINGS               = LPCSTR(56);
  {$EXTERNALSYM X509_POLICY_MAPPINGS}
  X509_POLICY_CONSTRAINTS            = LPCSTR(57);
  {$EXTERNALSYM X509_POLICY_CONSTRAINTS}
  X509_CROSS_CERT_DIST_POINTS        = LPCSTR(58);
  {$EXTERNALSYM X509_CROSS_CERT_DIST_POINTS}

//+-------------------------------------------------------------------------
//  Certificate Management Messages over CMS (CMC) Data Structures
//--------------------------------------------------------------------------
const
  CMC_DATA                           = LPCSTR(59);
  {$EXTERNALSYM CMC_DATA}
  CMC_RESPONSE                       = LPCSTR(60);
  {$EXTERNALSYM CMC_RESPONSE}
  CMC_STATUS                         = LPCSTR(61);
  {$EXTERNALSYM CMC_STATUS}
  CMC_ADD_EXTENSIONS                 = LPCSTR(62);
  {$EXTERNALSYM CMC_ADD_EXTENSIONS}
  CMC_ADD_ATTRIBUTES                 = LPCSTR(63);
  {$EXTERNALSYM CMC_ADD_ATTRIBUTES}

//+-------------------------------------------------------------------------
//  Certificate Template
//--------------------------------------------------------------------------
const
  X509_CERTIFICATE_TEMPLATE          = LPCSTR(64);
  {$EXTERNALSYM X509_CERTIFICATE_TEMPLATE}

//+-------------------------------------------------------------------------
//  Online Certificate Status Protocol (OCSP) Data Structures
//--------------------------------------------------------------------------
const
  OCSP_SIGNED_REQUEST                = LPCSTR(65);
  {$EXTERNALSYM OCSP_SIGNED_REQUEST}
  OCSP_REQUEST                       = LPCSTR(66);
  {$EXTERNALSYM OCSP_REQUEST}
  OCSP_RESPONSE                      = LPCSTR(67);
  {$EXTERNALSYM OCSP_RESPONSE}
  OCSP_BASIC_SIGNED_RESPONSE         = LPCSTR(68);
  {$EXTERNALSYM OCSP_BASIC_SIGNED_RESPONSE}
  OCSP_BASIC_RESPONSE                = LPCSTR(69);
  {$EXTERNALSYM OCSP_BASIC_RESPONSE}

//+-------------------------------------------------------------------------
//  Logotype and Biometric Extensions
//--------------------------------------------------------------------------
const
  X509_LOGOTYPE_EXT                  = LPCSTR(70);
  {$EXTERNALSYM X509_LOGOTYPE_EXT}
  X509_BIOMETRIC_EXT                 = LPCSTR(71);
  {$EXTERNALSYM X509_BIOMETRIC_EXT}

  CNG_RSA_PUBLIC_KEY_BLOB            = LPCSTR(72);
  {$EXTERNALSYM CNG_RSA_PUBLIC_KEY_BLOB}
  X509_OBJECT_IDENTIFIER             = LPCSTR(73);
  {$EXTERNALSYM X509_OBJECT_IDENTIFIER}
  X509_ALGORITHM_IDENTIFIER          = LPCSTR(74);
  {$EXTERNALSYM X509_ALGORITHM_IDENTIFIER}
  PKCS_RSA_SSA_PSS_PARAMETERS        = LPCSTR(75);
  {$EXTERNALSYM PKCS_RSA_SSA_PSS_PARAMETERS}
  PKCS_RSAES_OAEP_PARAMETERS         = LPCSTR(76);
  {$EXTERNALSYM PKCS_RSAES_OAEP_PARAMETERS}

  ECC_CMS_SHARED_INFO                = LPCSTR(77);
  {$EXTERNALSYM ECC_CMS_SHARED_INFO}

//+-------------------------------------------------------------------------
//  TIMESTAMP
//--------------------------------------------------------------------------
const
  TIMESTAMP_REQUEST                  = LPCSTR(78);
  {$EXTERNALSYM TIMESTAMP_REQUEST}
  TIMESTAMP_RESPONSE                 = LPCSTR(79);
  {$EXTERNALSYM TIMESTAMP_RESPONSE}
  TIMESTAMP_INFO                     = LPCSTR(80);
  {$EXTERNALSYM TIMESTAMP_INFO}

//+-------------------------------------------------------------------------
//  CertificateBundle
//--------------------------------------------------------------------------
const
  X509_CERT_BUNDLE                   = LPCSTR(81);
  {$EXTERNALSYM X509_CERT_BUNDLE}

//+-------------------------------------------------------------------------
//  ECC Keys
//--------------------------------------------------------------------------
const
  X509_ECC_PRIVATE_KEY               = LPCSTR(82);   // CRYPT_ECC_PRIVATE_KEY_INFO
  {$EXTERNALSYM X509_ECC_PRIVATE_KEY}

  CNG_RSA_PRIVATE_KEY_BLOB           = LPCSTR(83);   // BCRYPT_RSAKEY_BLOB
  {$EXTERNALSYM CNG_RSA_PRIVATE_KEY_BLOB}

//+-------------------------------------------------------------------------
//  Predefined PKCS #7 data structures that can be encoded / decoded.
//--------------------------------------------------------------------------
const
  PKCS7_SIGNER_INFO                  = LPCSTR(500);
  {$EXTERNALSYM PKCS7_SIGNER_INFO}

//+-------------------------------------------------------------------------
//  Predefined PKCS #7 data structures that can be encoded / decoded.
//--------------------------------------------------------------------------
const
  CMS_SIGNER_INFO                    = LPCSTR(501);
  {$EXTERNALSYM CMS_SIGNER_INFO}

//+-------------------------------------------------------------------------
//  Predefined Software Publishing Credential (SPC)  data structures that
//  can be encoded / decoded.
//
//  Predefined values: 2000 .. 2999
//
//  See spc.h for value and data structure definitions.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  Extension Object Identifiers
//--------------------------------------------------------------------------
const
  szOID_AUTHORITY_KEY_IDENTIFIER  = '2.5.29.1';
  {$EXTERNALSYM szOID_AUTHORITY_KEY_IDENTIFIER}
  szOID_KEY_ATTRIBUTES            = '2.5.29.2';
  {$EXTERNALSYM szOID_KEY_ATTRIBUTES}
  szOID_CERT_POLICIES_95          = '2.5.29.3';
  {$EXTERNALSYM szOID_CERT_POLICIES_95}
  szOID_KEY_USAGE_RESTRICTION     = '2.5.29.4';
  {$EXTERNALSYM szOID_KEY_USAGE_RESTRICTION}
  szOID_SUBJECT_ALT_NAME          = '2.5.29.7';
  {$EXTERNALSYM szOID_SUBJECT_ALT_NAME}
  szOID_ISSUER_ALT_NAME           = '2.5.29.8';
  {$EXTERNALSYM szOID_ISSUER_ALT_NAME}
  szOID_BASIC_CONSTRAINTS         = '2.5.29.10';
  {$EXTERNALSYM szOID_BASIC_CONSTRAINTS}
  szOID_KEY_USAGE                 = '2.5.29.15';
  {$EXTERNALSYM szOID_KEY_USAGE}
  szOID_PRIVATEKEY_USAGE_PERIOD   = '2.5.29.16';
  {$EXTERNALSYM szOID_PRIVATEKEY_USAGE_PERIOD}
  szOID_BASIC_CONSTRAINTS2        = '2.5.29.19';
  {$EXTERNALSYM szOID_BASIC_CONSTRAINTS2}

  szOID_CERT_POLICIES             = '2.5.29.32';
  {$EXTERNALSYM szOID_CERT_POLICIES}
  szOID_ANY_CERT_POLICY           = '2.5.29.32.0';
  {$EXTERNALSYM szOID_ANY_CERT_POLICY}
  szOID_INHIBIT_ANY_POLICY        = '2.5.29.54';
  {$EXTERNALSYM szOID_INHIBIT_ANY_POLICY}

  szOID_AUTHORITY_KEY_IDENTIFIER2 = '2.5.29.35';
  {$EXTERNALSYM szOID_AUTHORITY_KEY_IDENTIFIER2}
  szOID_SUBJECT_KEY_IDENTIFIER    = '2.5.29.14';
  {$EXTERNALSYM szOID_SUBJECT_KEY_IDENTIFIER}
  szOID_SUBJECT_ALT_NAME2         = '2.5.29.17';
  {$EXTERNALSYM szOID_SUBJECT_ALT_NAME2}
  szOID_ISSUER_ALT_NAME2          = '2.5.29.18';
  {$EXTERNALSYM szOID_ISSUER_ALT_NAME2}
  szOID_CRL_REASON_CODE           = '2.5.29.21';
  {$EXTERNALSYM szOID_CRL_REASON_CODE}
  szOID_REASON_CODE_HOLD          = '2.5.29.23';
  {$EXTERNALSYM szOID_REASON_CODE_HOLD}
  szOID_CRL_DIST_POINTS           = '2.5.29.31';
  {$EXTERNALSYM szOID_CRL_DIST_POINTS}
  szOID_ENHANCED_KEY_USAGE        = '2.5.29.37';
  {$EXTERNALSYM szOID_ENHANCED_KEY_USAGE}

  szOID_ANY_ENHANCED_KEY_USAGE    = '2.5.29.37.0';
  {$EXTERNALSYM szOID_ANY_ENHANCED_KEY_USAGE}

// szOID_CRL_NUMBER -- Base CRLs only.  Monotonically increasing sequence
// number for each CRL issued by a CA.
const
  szOID_CRL_NUMBER                = '2.5.29.20';
  {$EXTERNALSYM szOID_CRL_NUMBER}
// szOID_DELTA_CRL_INDICATOR -- Delta CRLs only.  Marked critical.
// Contains the minimum base CRL Number that can be used with a delta CRL.
const
  szOID_DELTA_CRL_INDICATOR       = '2.5.29.27';
  {$EXTERNALSYM szOID_DELTA_CRL_INDICATOR}
  szOID_ISSUING_DIST_POINT        = '2.5.29.28';
  {$EXTERNALSYM szOID_ISSUING_DIST_POINT}
// szOID_FRESHEST_CRL -- Base CRLs only.  Formatted identically to a CDP
// extension that holds URLs to fetch the delta CRL.
const
  szOID_FRESHEST_CRL              = '2.5.29.46';
  {$EXTERNALSYM szOID_FRESHEST_CRL}
  szOID_NAME_CONSTRAINTS          = '2.5.29.30';
  {$EXTERNALSYM szOID_NAME_CONSTRAINTS}

// Note on 1/1/2000 szOID_POLICY_MAPPINGS was changed from "2.5.29.5"
const
  szOID_POLICY_MAPPINGS           = '2.5.29.33';
  {$EXTERNALSYM szOID_POLICY_MAPPINGS}
  szOID_LEGACY_POLICY_MAPPINGS    = '2.5.29.5';
  {$EXTERNALSYM szOID_LEGACY_POLICY_MAPPINGS}
  szOID_POLICY_CONSTRAINTS        = '2.5.29.36';
  {$EXTERNALSYM szOID_POLICY_CONSTRAINTS}


// Microsoft PKCS10 Attributes
const
  szOID_RENEWAL_CERTIFICATE          = '1.3.6.1.4.1.311.13.1';
  {$EXTERNALSYM szOID_RENEWAL_CERTIFICATE}
  szOID_ENROLLMENT_NAME_VALUE_PAIR   = '1.3.6.1.4.1.311.13.2.1';
  {$EXTERNALSYM szOID_ENROLLMENT_NAME_VALUE_PAIR}
  szOID_ENROLLMENT_CSP_PROVIDER      = '1.3.6.1.4.1.311.13.2.2';
  {$EXTERNALSYM szOID_ENROLLMENT_CSP_PROVIDER}
  szOID_OS_VERSION                   = '1.3.6.1.4.1.311.13.2.3';
  {$EXTERNALSYM szOID_OS_VERSION}

//
// Extension contain certificate type
const
  szOID_ENROLLMENT_AGENT             = '1.3.6.1.4.1.311.20.2.1';
  {$EXTERNALSYM szOID_ENROLLMENT_AGENT}

// Internet Public Key Infrastructure (PKIX)
const
  szOID_PKIX                      = '1.3.6.1.5.5.7';
  {$EXTERNALSYM szOID_PKIX}
  szOID_PKIX_PE                   = '1.3.6.1.5.5.7.1';
  {$EXTERNALSYM szOID_PKIX_PE}
  szOID_AUTHORITY_INFO_ACCESS     = '1.3.6.1.5.5.7.1.1';
  {$EXTERNALSYM szOID_AUTHORITY_INFO_ACCESS}
  szOID_SUBJECT_INFO_ACCESS       = '1.3.6.1.5.5.7.1.11';
  {$EXTERNALSYM szOID_SUBJECT_INFO_ACCESS}
  szOID_BIOMETRIC_EXT             = '1.3.6.1.5.5.7.1.2';
  {$EXTERNALSYM szOID_BIOMETRIC_EXT}
  szOID_QC_STATEMENTS_EXT         = '1.3.6.1.5.5.7.1.3';
  {$EXTERNALSYM szOID_QC_STATEMENTS_EXT}
  szOID_LOGOTYPE_EXT              = '1.3.6.1.5.5.7.1.12';
  {$EXTERNALSYM szOID_LOGOTYPE_EXT}

// Microsoft extensions or attributes
const
  szOID_CERT_EXTENSIONS           = '1.3.6.1.4.1.311.2.1.14';
  {$EXTERNALSYM szOID_CERT_EXTENSIONS}
  szOID_NEXT_UPDATE_LOCATION      = '1.3.6.1.4.1.311.10.2';
  {$EXTERNALSYM szOID_NEXT_UPDATE_LOCATION}
  szOID_REMOVE_CERTIFICATE        = '1.3.6.1.4.1.311.10.8.1';
  {$EXTERNALSYM szOID_REMOVE_CERTIFICATE}
  szOID_CROSS_CERT_DIST_POINTS    = '1.3.6.1.4.1.311.10.9.1';
  {$EXTERNALSYM szOID_CROSS_CERT_DIST_POINTS}

//  Microsoft PKCS #7 ContentType Object Identifiers
const
  szOID_CTL                       = '1.3.6.1.4.1.311.10.1';
  {$EXTERNALSYM szOID_CTL}

//  Microsoft Sorted CTL Extension Object Identifier
const
  szOID_SORTED_CTL                = '1.3.6.1.4.1.311.10.1.1';
  {$EXTERNALSYM szOID_SORTED_CTL}

// serialized serial numbers for PRS
{$IF not DECLARED(szOID_SERIALIZED)}
const
  szOID_SERIALIZED                = '1.3.6.1.4.1.311.10.3.3.1';
  {$EXTERNALSYM szOID_SERIALIZED}
{$IFEND}

// UPN principal name in SubjectAltName
{$IF not DECLARED(szOID_NT_PRINCIPAL_NAME)}
const
  szOID_NT_PRINCIPAL_NAME         = '1.3.6.1.4.1.311.20.2.3';
  {$EXTERNALSYM szOID_NT_PRINCIPAL_NAME}
{$IFEND}

// Internationalized Email Address in SubjectAltName (OtherName:UTF8)
{$IF not DECLARED(szOID_INTERNATIONALIZED_EMAIL_ADDRESS)}
const
  szOID_INTERNATIONALIZED_EMAIL_ADDRESS  = '1.3.6.1.4.1.311.20.2.4';
  {$EXTERNALSYM szOID_INTERNATIONALIZED_EMAIL_ADDRESS}
{$IFEND}

// Windows product update unauthenticated attribute
{$IF not DECLARED(szOID_PRODUCT_UPDATE)}
const
  szOID_PRODUCT_UPDATE            = '1.3.6.1.4.1.311.31.1';
  {$EXTERNALSYM szOID_PRODUCT_UPDATE}
{$IFEND}

// CryptUI
const
  szOID_ANY_APPLICATION_POLICY    = '1.3.6.1.4.1.311.10.12.1';
  {$EXTERNALSYM szOID_ANY_APPLICATION_POLICY}

//+-------------------------------------------------------------------------
//  Object Identifiers for use with Auto Enrollment
//--------------------------------------------------------------------------
const
  szOID_AUTO_ENROLL_CTL_USAGE     = '1.3.6.1.4.1.311.20.1';
  {$EXTERNALSYM szOID_AUTO_ENROLL_CTL_USAGE}

// Extension contain certificate type
// AKA Certificate template extension (v1)
const
  szOID_ENROLL_CERTTYPE_EXTENSION = '1.3.6.1.4.1.311.20.2';
  {$EXTERNALSYM szOID_ENROLL_CERTTYPE_EXTENSION}


  szOID_CERT_MANIFOLD             = '1.3.6.1.4.1.311.20.3';
  {$EXTERNALSYM szOID_CERT_MANIFOLD}

//+-------------------------------------------------------------------------
//  Object Identifiers for use with the MS Certificate Server
//--------------------------------------------------------------------------
{$IF not DECLARED(szOID_CERTSRV_CA_VERSION)}
const
  szOID_CERTSRV_CA_VERSION        = '1.3.6.1.4.1.311.21.1';
  {$EXTERNALSYM szOID_CERTSRV_CA_VERSION}
{$IFEND}


// szOID_CERTSRV_PREVIOUS_CERT_HASH -- Contains the sha1 hash of the previous
// version of the CA certificate.
const
  szOID_CERTSRV_PREVIOUS_CERT_HASH   = '1.3.6.1.4.1.311.21.2';
  {$EXTERNALSYM szOID_CERTSRV_PREVIOUS_CERT_HASH}

// szOID_CRL_VIRTUAL_BASE -- Delta CRLs only.  Contains the base CRL Number
// of the corresponding base CRL.
const
  szOID_CRL_VIRTUAL_BASE          = '1.3.6.1.4.1.311.21.3';
  {$EXTERNALSYM szOID_CRL_VIRTUAL_BASE}

// szOID_CRL_NEXT_PUBLISH -- Contains the time when the next CRL is expected
// to be published.  This may be sooner than the CRL's NextUpdate field.
const
  szOID_CRL_NEXT_PUBLISH          = '1.3.6.1.4.1.311.21.4';
  {$EXTERNALSYM szOID_CRL_NEXT_PUBLISH}

// Enhanced Key Usage for CA encryption certificate
const
  szOID_KP_CA_EXCHANGE            = '1.3.6.1.4.1.311.21.5';
  {$EXTERNALSYM szOID_KP_CA_EXCHANGE}

// Enhanced Key Usage for key recovery agent certificate
const
  szOID_KP_KEY_RECOVERY_AGENT     = '1.3.6.1.4.1.311.21.6';
  {$EXTERNALSYM szOID_KP_KEY_RECOVERY_AGENT}

// Certificate template extension (v2)
const
  szOID_CERTIFICATE_TEMPLATE      = '1.3.6.1.4.1.311.21.7';
  {$EXTERNALSYM szOID_CERTIFICATE_TEMPLATE}

// The root oid for all enterprise specific oids
const
  szOID_ENTERPRISE_OID_ROOT       = '1.3.6.1.4.1.311.21.8';
  {$EXTERNALSYM szOID_ENTERPRISE_OID_ROOT}

// Dummy signing Subject RDN
const
  szOID_RDN_DUMMY_SIGNER          = '1.3.6.1.4.1.311.21.9';
  {$EXTERNALSYM szOID_RDN_DUMMY_SIGNER}

// Application Policies extension -- same encoding as szOID_CERT_POLICIES
const
  szOID_APPLICATION_CERT_POLICIES    = '1.3.6.1.4.1.311.21.10';
  {$EXTERNALSYM szOID_APPLICATION_CERT_POLICIES}

// Application Policy Mappings -- same encoding as szOID_POLICY_MAPPINGS
const
  szOID_APPLICATION_POLICY_MAPPINGS  = '1.3.6.1.4.1.311.21.11';
  {$EXTERNALSYM szOID_APPLICATION_POLICY_MAPPINGS}

// Application Policy Constraints -- same encoding as szOID_POLICY_CONSTRAINTS
const
  szOID_APPLICATION_POLICY_CONSTRAINTS   = '1.3.6.1.4.1.311.21.12';
  {$EXTERNALSYM szOID_APPLICATION_POLICY_CONSTRAINTS}

  szOID_ARCHIVED_KEY_ATTR               = '1.3.6.1.4.1.311.21.13';
  {$EXTERNALSYM szOID_ARCHIVED_KEY_ATTR}
  szOID_CRL_SELF_CDP                    = '1.3.6.1.4.1.311.21.14';
  {$EXTERNALSYM szOID_CRL_SELF_CDP}


// Requires all certificates below the root to have a non-empty intersecting
// issuance certificate policy usage.
const
  szOID_REQUIRE_CERT_CHAIN_POLICY       = '1.3.6.1.4.1.311.21.15';
  {$EXTERNALSYM szOID_REQUIRE_CERT_CHAIN_POLICY}
  szOID_ARCHIVED_KEY_CERT_HASH          = '1.3.6.1.4.1.311.21.16';
  {$EXTERNALSYM szOID_ARCHIVED_KEY_CERT_HASH}
  szOID_ISSUED_CERT_HASH                = '1.3.6.1.4.1.311.21.17';
  {$EXTERNALSYM szOID_ISSUED_CERT_HASH}

// Enhanced key usage for DS email replication
const
  szOID_DS_EMAIL_REPLICATION            = '1.3.6.1.4.1.311.21.19';
  {$EXTERNALSYM szOID_DS_EMAIL_REPLICATION}

  szOID_REQUEST_CLIENT_INFO             = '1.3.6.1.4.1.311.21.20';
  {$EXTERNALSYM szOID_REQUEST_CLIENT_INFO}
  szOID_ENCRYPTED_KEY_HASH              = '1.3.6.1.4.1.311.21.21';
  {$EXTERNALSYM szOID_ENCRYPTED_KEY_HASH}
  szOID_CERTSRV_CROSSCA_VERSION         = '1.3.6.1.4.1.311.21.22';
  {$EXTERNALSYM szOID_CERTSRV_CROSSCA_VERSION}

//+-------------------------------------------------------------------------
//  Object Identifiers for use with the MS Directory Service
//--------------------------------------------------------------------------
const
  szOID_NTDS_REPLICATION     = '1.3.6.1.4.1.311.25.1';
  {$EXTERNALSYM szOID_NTDS_REPLICATION}


//+-------------------------------------------------------------------------
//  Extension Object Identifiers (currently not implemented)
//--------------------------------------------------------------------------
const
  szOID_SUBJECT_DIR_ATTRS        = '2.5.29.9';
  {$EXTERNALSYM szOID_SUBJECT_DIR_ATTRS}

//+-------------------------------------------------------------------------
//  Enhanced Key Usage (Purpose) Object Identifiers
//--------------------------------------------------------------------------
const
  szOID_PKIX_KP                   = '1.3.6.1.5.5.7.3';
  {$EXTERNALSYM szOID_PKIX_KP}

// Consistent key usage bits: DIGITAL_SIGNATURE, KEY_ENCIPHERMENT
// or KEY_AGREEMENT
const
  szOID_PKIX_KP_SERVER_AUTH       = '1.3.6.1.5.5.7.3.1';
  {$EXTERNALSYM szOID_PKIX_KP_SERVER_AUTH}

// Consistent key usage bits: DIGITAL_SIGNATURE
const
  szOID_PKIX_KP_CLIENT_AUTH       = '1.3.6.1.5.5.7.3.2';
  {$EXTERNALSYM szOID_PKIX_KP_CLIENT_AUTH}

// Consistent key usage bits: DIGITAL_SIGNATURE
const
  szOID_PKIX_KP_CODE_SIGNING      = '1.3.6.1.5.5.7.3.3';
  {$EXTERNALSYM szOID_PKIX_KP_CODE_SIGNING}

// Consistent key usage bits: DIGITAL_SIGNATURE, NON_REPUDIATION and/or
// (KEY_ENCIPHERMENT or KEY_AGREEMENT)
const
  szOID_PKIX_KP_EMAIL_PROTECTION  = '1.3.6.1.5.5.7.3.4';
  {$EXTERNALSYM szOID_PKIX_KP_EMAIL_PROTECTION}

// Consistent key usage bits: DIGITAL_SIGNATURE and/or
// (KEY_ENCIPHERMENT or KEY_AGREEMENT)
const
  szOID_PKIX_KP_IPSEC_END_SYSTEM  = '1.3.6.1.5.5.7.3.5';
  {$EXTERNALSYM szOID_PKIX_KP_IPSEC_END_SYSTEM}

// Consistent key usage bits: DIGITAL_SIGNATURE and/or
// (KEY_ENCIPHERMENT or KEY_AGREEMENT)
const
  szOID_PKIX_KP_IPSEC_TUNNEL      = '1.3.6.1.5.5.7.3.6';
  {$EXTERNALSYM szOID_PKIX_KP_IPSEC_TUNNEL}

// Consistent key usage bits: DIGITAL_SIGNATURE and/or
// (KEY_ENCIPHERMENT or KEY_AGREEMENT)
const
  szOID_PKIX_KP_IPSEC_USER        = '1.3.6.1.5.5.7.3.7';
  {$EXTERNALSYM szOID_PKIX_KP_IPSEC_USER}

// Consistent key usage bits: DIGITAL_SIGNATURE or NON_REPUDIATION
const
  szOID_PKIX_KP_TIMESTAMP_SIGNING = '1.3.6.1.5.5.7.3.8';
  {$EXTERNALSYM szOID_PKIX_KP_TIMESTAMP_SIGNING}

// OCSP response signer
const
  szOID_PKIX_KP_OCSP_SIGNING      = '1.3.6.1.5.5.7.3.9';
  {$EXTERNALSYM szOID_PKIX_KP_OCSP_SIGNING}

// Following extension is present to indicate no revocation checking
// for the OCSP signer certificate
const
  szOID_PKIX_OCSP_NOCHECK         = '1.3.6.1.5.5.7.48.1.5';
  {$EXTERNALSYM szOID_PKIX_OCSP_NOCHECK}

// OCSP Nonce
const
  szOID_PKIX_OCSP_NONCE           = '1.3.6.1.5.5.7.48.1.2';
  {$EXTERNALSYM szOID_PKIX_OCSP_NONCE}

// IKE (Internet Key Exchange) Intermediate KP for an IPsec end entity.
// Defined in draft-ietf-ipsec-pki-req-04.txt, December 14, 1999.
const
  szOID_IPSEC_KP_IKE_INTERMEDIATE = '1.3.6.1.5.5.8.2.2';
  {$EXTERNALSYM szOID_IPSEC_KP_IKE_INTERMEDIATE}


// iso (1) org (3) dod (6) internet (1) security (5) kerberosv5 (2) pkinit (3) 5
const
  szOID_PKINIT_KP_KDC             = '1.3.6.1.5.2.3.5';
  {$EXTERNALSYM szOID_PKINIT_KP_KDC}

//+-------------------------------------------------------------------------
//  Microsoft Enhanced Key Usage (Purpose) Object Identifiers
//+-------------------------------------------------------------------------

//  Signer of CTLs
const
  szOID_KP_CTL_USAGE_SIGNING      = '1.3.6.1.4.1.311.10.3.1';
  {$EXTERNALSYM szOID_KP_CTL_USAGE_SIGNING}

//  Signer of TimeStamps
const
  szOID_KP_TIME_STAMP_SIGNING     = '1.3.6.1.4.1.311.10.3.2';
  {$EXTERNALSYM szOID_KP_TIME_STAMP_SIGNING}

{$IF not DECLARED(szOID_SERVER_GATED_CRYPTO)}
const
  szOID_SERVER_GATED_CRYPTO       = '1.3.6.1.4.1.311.10.3.3';
  {$EXTERNALSYM szOID_SERVER_GATED_CRYPTO}
{$IFEND}

{$IF not DECLARED(szOID_SGC_NETSCAPE)}
const
  szOID_SGC_NETSCAPE              = '2.16.840.1.113730.4.1';
  {$EXTERNALSYM szOID_SGC_NETSCAPE}
{$IFEND}

const
  szOID_KP_EFS                    = '1.3.6.1.4.1.311.10.3.4';
  {$EXTERNALSYM szOID_KP_EFS}
  szOID_EFS_RECOVERY              = '1.3.6.1.4.1.311.10.3.4.1';
  {$EXTERNALSYM szOID_EFS_RECOVERY}

// Can use Windows Hardware Compatible (WHQL)
const
  szOID_WHQL_CRYPTO               = '1.3.6.1.4.1.311.10.3.5';
  {$EXTERNALSYM szOID_WHQL_CRYPTO}

// Signed by the NT5 build lab
const
  szOID_NT5_CRYPTO                = '1.3.6.1.4.1.311.10.3.6';
  {$EXTERNALSYM szOID_NT5_CRYPTO}

// Signed by and OEM of WHQL
const
  szOID_OEM_WHQL_CRYPTO           = '1.3.6.1.4.1.311.10.3.7';
  {$EXTERNALSYM szOID_OEM_WHQL_CRYPTO}

// Signed by the Embedded NT
const
  szOID_EMBEDDED_NT_CRYPTO        = '1.3.6.1.4.1.311.10.3.8';
  {$EXTERNALSYM szOID_EMBEDDED_NT_CRYPTO}

// Signer of a CTL containing trusted roots
const
  szOID_ROOT_LIST_SIGNER     = '1.3.6.1.4.1.311.10.3.9';
  {$EXTERNALSYM szOID_ROOT_LIST_SIGNER}

// Can sign cross-cert and subordinate CA requests with qualified
// subordination (name constraints, policy mapping, etc.)
const
  szOID_KP_QUALIFIED_SUBORDINATION   = '1.3.6.1.4.1.311.10.3.10';
  {$EXTERNALSYM szOID_KP_QUALIFIED_SUBORDINATION}

// Can be used to encrypt/recover escrowed keys
const
  szOID_KP_KEY_RECOVERY              = '1.3.6.1.4.1.311.10.3.11';
  {$EXTERNALSYM szOID_KP_KEY_RECOVERY}

// Signer of documents
const
  szOID_KP_DOCUMENT_SIGNING          = '1.3.6.1.4.1.311.10.3.12';
  {$EXTERNALSYM szOID_KP_DOCUMENT_SIGNING}


// The default WinVerifyTrust Authenticode policy is to treat all time stamped
// signatures as being valid forever. This OID limits the valid lifetime of the
// signature to the lifetime of the certificate. This allows timestamped
// signatures to expire. Normally this OID will be used in conjunction with
// szOID_PKIX_KP_CODE_SIGNING to indicate new time stamp semantics should be
// used. Support for this OID was added in WXP.
const
  szOID_KP_LIFETIME_SIGNING          = '1.3.6.1.4.1.311.10.3.13';
  {$EXTERNALSYM szOID_KP_LIFETIME_SIGNING}

  szOID_KP_MOBILE_DEVICE_SOFTWARE    = '1.3.6.1.4.1.311.10.3.14';
  {$EXTERNALSYM szOID_KP_MOBILE_DEVICE_SOFTWARE}

  szOID_KP_SMART_DISPLAY          = '1.3.6.1.4.1.311.10.3.15';
  {$EXTERNALSYM szOID_KP_SMART_DISPLAY}

  szOID_KP_CSP_SIGNATURE          = '1.3.6.1.4.1.311.10.3.16';
  {$EXTERNALSYM szOID_KP_CSP_SIGNATURE}

{$IF not DECLARED(szOID_DRM)}
const
  szOID_DRM                       = '1.3.6.1.4.1.311.10.5.1';
  {$EXTERNALSYM szOID_DRM}
{$IFEND}


// Microsoft DRM EKU
{$IF not DECLARED(szOID_DRM_INDIVIDUALIZATION)}
const
  szOID_DRM_INDIVIDUALIZATION = '1.3.6.1.4.1.311.10.5.2';
  {$EXTERNALSYM szOID_DRM_INDIVIDUALIZATION}
{$IFEND}


{$IF not DECLARED(szOID_LICENSES)}
const
  szOID_LICENSES                  = '1.3.6.1.4.1.311.10.6.1';
  {$EXTERNALSYM szOID_LICENSES}
{$IFEND}

{$IF not DECLARED(szOID_LICENSE_SERVER)}
const
  szOID_LICENSE_SERVER            = '1.3.6.1.4.1.311.10.6.2';
  {$EXTERNALSYM szOID_LICENSE_SERVER}
{$IFEND}

{$IF not DECLARED(szOID_KP_SMARTCARD_LOGON)}
const
  szOID_KP_SMARTCARD_LOGON        = '1.3.6.1.4.1.311.20.2.2';
  {$EXTERNALSYM szOID_KP_SMARTCARD_LOGON}
{$IFEND}

const
  szOID_KP_KERNEL_MODE_CODE_SIGNING  = '1.3.6.1.4.1.311.61.1.1';
  {$EXTERNALSYM szOID_KP_KERNEL_MODE_CODE_SIGNING}

  szOID_KP_KERNEL_MODE_TRUSTED_BOOT_SIGNING = '1.3.6.1.4.1.311.61.4.1';
  {$EXTERNALSYM szOID_KP_KERNEL_MODE_TRUSTED_BOOT_SIGNING}

// Signer of CRL
const
  szOID_REVOKED_LIST_SIGNER       = '1.3.6.1.4.1.311.10.3.19';
  {$EXTERNALSYM szOID_REVOKED_LIST_SIGNER}


// CTL containing disallowed entries
const
  szOID_DISALLOWED_LIST           = '1.3.6.1.4.1.311.10.3.30';
  {$EXTERNALSYM szOID_DISALLOWED_LIST}

// HAL Extensions
const
  szOID_KP_KERNEL_MODE_HAL_EXTENSION_SIGNING = '1.3.6.1.4.1.311.61.5.1';
  {$EXTERNALSYM szOID_KP_KERNEL_MODE_HAL_EXTENSION_SIGNING}

//+-------------------------------------------------------------------------
//  Microsoft Attribute Object Identifiers
//+-------------------------------------------------------------------------
const
  szOID_YESNO_TRUST_ATTR          = '1.3.6.1.4.1.311.10.4.1';
  {$EXTERNALSYM szOID_YESNO_TRUST_ATTR}

//+-------------------------------------------------------------------------
//  Qualifiers that may be part of the szOID_CERT_POLICIES and
//  szOID_CERT_POLICIES95 extensions
//+-------------------------------------------------------------------------
const
  szOID_PKIX_POLICY_QUALIFIER_CPS              = '1.3.6.1.5.5.7.2.1';
  {$EXTERNALSYM szOID_PKIX_POLICY_QUALIFIER_CPS}
  szOID_PKIX_POLICY_QUALIFIER_USERNOTICE       = '1.3.6.1.5.5.7.2.2';
  {$EXTERNALSYM szOID_PKIX_POLICY_QUALIFIER_USERNOTICE}

  szOID_ROOT_PROGRAM_FLAGS                     = '1.3.6.1.4.1.311.60.1.1';
  {$EXTERNALSYM szOID_ROOT_PROGRAM_FLAGS}


//+-------------------------------------------------------------------------
//  Root program qualifier flags, used in pbData field of
//  CERT_POLICY_QUALIFIER_INFO structure.
//+-------------------------------------------------------------------------

// Validation of the Organization (O) field in the subject name meets
// Root Program Requirements for display.
const
  CERT_ROOT_PROGRAM_FLAG_ORG          = $80;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_FLAG_ORG}

// Validation of the Locale (L), State (S), and Country (C) fields in
// the subject name meets Program Requirements for display.
const
  CERT_ROOT_PROGRAM_FLAG_LSC          = $40;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_FLAG_LSC}

// Subject logotype
const
  CERT_ROOT_PROGRAM_FLAG_SUBJECT_LOGO = $20;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_FLAG_SUBJECT_LOGO}

// Validation of the OrganizationalUnit (OU) field in the subject name
// meets Root Program Requirements for display.
const
  CERT_ROOT_PROGRAM_FLAG_OU           = $10;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_FLAG_OU}

// Validation of the address field in the subject name meets Root
// Program Requirements for display.
const
  CERT_ROOT_PROGRAM_FLAG_ADDRESS      = $08;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_FLAG_ADDRESS}


// OID for old qualifer
const
  szOID_CERT_POLICIES_95_QUALIFIER1            = '2.16.840.1.113733.1.7.1.1';
  {$EXTERNALSYM szOID_CERT_POLICIES_95_QUALIFIER1}

//+-------------------------------------------------------------------------
//  X509_CERT
//
//  The "to be signed" encoded content plus its signature. The ToBeSigned
//  content is the CryptEncodeObject() output for one of the following:
//  X509_CERT_TO_BE_SIGNED, X509_CERT_CRL_TO_BE_SIGNED or
//  X509_CERT_REQUEST_TO_BE_SIGNED.
//
//  pvStructInfo points to CERT_SIGNED_CONTENT_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_CERT_TO_BE_SIGNED
//
//  pvStructInfo points to CERT_INFO.
//
//  For CryptDecodeObject(), the pbEncoded is the "to be signed" plus its
//  signature (output of a X509_CERT CryptEncodeObject()).
//
//  For CryptEncodeObject(), the pbEncoded is just the "to be signed".
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_CERT_CRL_TO_BE_SIGNED
//
//  pvStructInfo points to CRL_INFO.
//
//  For CryptDecodeObject(), the pbEncoded is the "to be signed" plus its
//  signature (output of a X509_CERT CryptEncodeObject()).
//
//  For CryptEncodeObject(), the pbEncoded is just the "to be signed".
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_CERT_REQUEST_TO_BE_SIGNED
//
//  pvStructInfo points to CERT_REQUEST_INFO.
//
//  For CryptDecodeObject(), the pbEncoded is the "to be signed" plus its
//  signature (output of a X509_CERT CryptEncodeObject()).
//
//  For CryptEncodeObject(), the pbEncoded is just the "to be signed".
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_EXTENSIONS
//  szOID_CERT_EXTENSIONS
//
//  pvStructInfo points to following CERT_EXTENSIONS.
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_CONTEXTS
type
  PCertExtensions = ^TCertExtensions;
  _CERT_EXTENSIONS = record
    cExtension: DWORD;
    rgExtension: PCertExtension;
  end;
  {$EXTERNALSYM _CERT_EXTENSIONS}
  CERT_EXTENSIONS = _CERT_EXTENSIONS;
  {$EXTERNALSYM CERT_EXTENSIONS}
  TCertExtensions = _CERT_EXTENSIONS;
  PCERT_EXTENSIONS = PCertExtensions;
  {$EXTERNALSYM PCERT_EXTENSIONS}
// certenrolls_end

//+-------------------------------------------------------------------------
//  X509_NAME_VALUE
//  X509_ANY_STRING
//
//  pvStructInfo points to CERT_NAME_VALUE.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_UNICODE_NAME_VALUE
//  X509_UNICODE_ANY_STRING
//
//  pvStructInfo points to CERT_NAME_VALUE.
//
//  The name values are unicode strings.
//
//  For CryptEncodeObject:
//    Value.pbData points to the unicode string.
//    If Value.cbData = 0, then, the unicode string is NULL terminated.
//    Otherwise, Value.cbData is the unicode string byte count. The byte count
//    is twice the character count.
//
//    If the unicode string contains an invalid character for the specified
//    dwValueType, then, *pcbEncoded is updated with the unicode character
//    index of the first invalid character. LastError is set to:
//    CRYPT_E_INVALID_NUMERIC_STRING, CRYPT_E_INVALID_PRINTABLE_STRING or
//    CRYPT_E_INVALID_IA5_STRING.
//
//    To disable the above check, either set CERT_RDN_DISABLE_CHECK_TYPE_FLAG
//    in dwValueType or set CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG
//    in dwFlags passed to CryptEncodeObjectEx.
//
//    The unicode string is converted before being encoded according to
//    the specified dwValueType. If dwValueType is set to 0, LastError
//    is set to E_INVALIDARG.
//
//    If the dwValueType isn't one of the character strings (its a
//    CERT_RDN_ENCODED_BLOB or CERT_RDN_OCTET_STRING), then, CryptEncodeObject
//    will return FALSE with LastError set to CRYPT_E_NOT_CHAR_STRING.
//
//  For CryptDecodeObject:
//    Value.pbData points to a NULL terminated unicode string. Value.cbData
//    contains the byte count of the unicode string excluding the NULL
//    terminator. dwValueType contains the type used in the encoded object.
//    Its not forced to CERT_RDN_UNICODE_STRING. The encoded value is
//    converted to the unicode string according to the dwValueType.
//
//    If the encoded object isn't one of the character string types, then,
//    CryptDecodeObject will return FALSE with LastError set to
//    CRYPT_E_NOT_CHAR_STRING. For a non character string, decode using
//    X509_NAME_VALUE or X509_ANY_STRING.
//
//    By default, CERT_RDN_T61_STRING values are initially decoded
//    as UTF8. If the UTF8 decoding fails, then, decoded as 8 bit characters.
//    Set CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG in dwFlags
//    passed to either CryptDecodeObject or CryptDecodeObjectEx to
//    skip the initial attempt to decode as UTF8.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_NAME
//
//  pvStructInfo points to CERT_NAME_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_UNICODE_NAME
//
//  pvStructInfo points to CERT_NAME_INFO.
//
//  The RDN attribute values are unicode strings except for the dwValueTypes of
//  CERT_RDN_ENCODED_BLOB or CERT_RDN_OCTET_STRING. These dwValueTypes are
//  the same as for a X509_NAME. Their values aren't converted to/from unicode.
//
//  For CryptEncodeObject:
//    Value.pbData points to the unicode string.
//    If Value.cbData = 0, then, the unicode string is NULL terminated.
//    Otherwise, Value.cbData is the unicode string byte count. The byte count
//    is twice the character count.
//
//    If dwValueType = 0 (CERT_RDN_ANY_TYPE), the pszObjId is used to find
//    an acceptable dwValueType. If the unicode string contains an
//    invalid character for the found or specified dwValueType, then,
//    *pcbEncoded is updated with the error location of the invalid character.
//    See below for details. LastError is set to:
//    CRYPT_E_INVALID_NUMERIC_STRING, CRYPT_E_INVALID_PRINTABLE_STRING or
//    CRYPT_E_INVALID_IA5_STRING.
//
//    To disable the above check, either set CERT_RDN_DISABLE_CHECK_TYPE_FLAG
//    in dwValueType or set CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG
//    in dwFlags passed to CryptEncodeObjectEx.
//
//    Set CERT_RDN_UNICODE_STRING in dwValueType or set
//    CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG in dwFlags passed
//    to CryptEncodeObjectEx to select CERT_RDN_T61_STRING instead of
//    CERT_RDN_UNICODE_STRING if all the unicode characters are <= 0xFF.
//
//    Set CERT_RDN_ENABLE_UTF8_UNICODE_STRING in dwValueType or set
//    CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG in dwFlags passed
//    to CryptEncodeObjectEx to select CERT_RDN_UTF8_STRING instead of
//    CERT_RDN_UNICODE_STRING.
//
//    The unicode string is converted before being encoded according to
//    the specified or ObjId matching dwValueType.
//
//  For CryptDecodeObject:
//    Value.pbData points to a NULL terminated unicode string. Value.cbData
//    contains the byte count of the unicode string excluding the NULL
//    terminator. dwValueType contains the type used in the encoded object.
//    Its not forced to CERT_RDN_UNICODE_STRING. The encoded value is
//    converted to the unicode string according to the dwValueType.
//
//    If the dwValueType of the encoded value isn't a character string
//    type, then, it isn't converted to UNICODE. Use the
//    IS_CERT_RDN_CHAR_STRING() macro on the dwValueType to check
//    that Value.pbData points to a converted unicode string.
//
//    By default, CERT_RDN_T61_STRING values are initially decoded
//    as UTF8. If the UTF8 decoding fails, then, decoded as 8 bit characters.
//    Set CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG in dwFlags
//    passed to either CryptDecodeObject or CryptDecodeObjectEx to
//    skip the initial attempt to decode as UTF8.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  Unicode Name Value Error Location Definitions
//
//  Error location is returned in *pcbEncoded by
//  CryptEncodeObject(X509_UNICODE_NAME)
//
//  Error location consists of:
//    RDN_INDEX     - 10 bits << 22
//    ATTR_INDEX    - 6 bits << 16
//    VALUE_INDEX   - 16 bits (unicode character index)
//--------------------------------------------------------------------------
const
  CERT_UNICODE_RDN_ERR_INDEX_MASK    = $3FF;
  {$EXTERNALSYM CERT_UNICODE_RDN_ERR_INDEX_MASK}
  CERT_UNICODE_RDN_ERR_INDEX_SHIFT   = 22;
  {$EXTERNALSYM CERT_UNICODE_RDN_ERR_INDEX_SHIFT}
  CERT_UNICODE_ATTR_ERR_INDEX_MASK   = $003F;
  {$EXTERNALSYM CERT_UNICODE_ATTR_ERR_INDEX_MASK}
  CERT_UNICODE_ATTR_ERR_INDEX_SHIFT  = 16;
  {$EXTERNALSYM CERT_UNICODE_ATTR_ERR_INDEX_SHIFT}
  CERT_UNICODE_VALUE_ERR_INDEX_MASK  = $0000FFFF;
  {$EXTERNALSYM CERT_UNICODE_VALUE_ERR_INDEX_MASK}
  CERT_UNICODE_VALUE_ERR_INDEX_SHIFT = 0;
  {$EXTERNALSYM CERT_UNICODE_VALUE_ERR_INDEX_SHIFT}

function GET_CERT_UNICODE_RDN_ERR_INDEX(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CERT_UNICODE_RDN_ERR_INDEX}
function GET_CERT_UNICODE_ATTR_ERR_INDEX(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CERT_UNICODE_ATTR_ERR_INDEX}
function GET_CERT_UNICODE_VALUE_ERR_INDEX(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CERT_UNICODE_VALUE_ERR_INDEX}

//+-------------------------------------------------------------------------
//  X509_PUBLIC_KEY_INFO
//
//  pvStructInfo points to CERT_PUBLIC_KEY_INFO.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
//  X509_AUTHORITY_KEY_ID
//  szOID_AUTHORITY_KEY_IDENTIFIER
//
//  pvStructInfo points to following CERT_AUTHORITY_KEY_ID_INFO.
//--------------------------------------------------------------------------
type
  PCertAuthorityKeyIDInfo = ^TCertAuthorityKeyIDInfo;
  _CERT_AUTHORITY_KEY_ID_INFO = record
    KeyId: TCryptDataBlob;
    CertIssuer: TCertNameBlob;
    CertSerialNumber: TCryptIntegerBlob;
  end;
  {$EXTERNALSYM _CERT_AUTHORITY_KEY_ID_INFO}
  CERT_AUTHORITY_KEY_ID_INFO = _CERT_AUTHORITY_KEY_ID_INFO;
  {$EXTERNALSYM CERT_AUTHORITY_KEY_ID_INFO}
  TCertAuthorityKeyIDInfo = _CERT_AUTHORITY_KEY_ID_INFO;
  PCERT_AUTHORITY_KEY_ID_INFO = PCertAuthorityKeyIDInfo;
  {$EXTERNALSYM PCERT_AUTHORITY_KEY_ID_INFO}

//+-------------------------------------------------------------------------
//  X509_KEY_ATTRIBUTES
//  szOID_KEY_ATTRIBUTES
//
//  pvStructInfo points to following CERT_KEY_ATTRIBUTES_INFO.
//--------------------------------------------------------------------------
type
  PCertPrivateKeyValidity = ^TCertPrivateKeyValidity;
  _CERT_PRIVATE_KEY_VALIDITY = record
    NotBefore: TFileTime;
    NotAfter: TFileTime;
  end;
  {$EXTERNALSYM _CERT_PRIVATE_KEY_VALIDITY}
  CERT_PRIVATE_KEY_VALIDITY = _CERT_PRIVATE_KEY_VALIDITY;
  {$EXTERNALSYM CERT_PRIVATE_KEY_VALIDITY}
  TCertPrivateKeyValidity = _CERT_PRIVATE_KEY_VALIDITY;
  PCERT_PRIVATE_KEY_VALIDITY = PCertPrivateKeyValidity;
  {$EXTERNALSYM PCERT_PRIVATE_KEY_VALIDITY}

type
  PCertKeyAttributesInfo = ^TCertKeyAttributesInfo;
  _CERT_KEY_ATTRIBUTES_INFO = record
    KeyId: TCryptDataBlob;
    IntendedKeyUsage: TCryptBitBlob;
    pPrivateKeyUsagePeriod: PCertPrivateKeyValidity;     // OPTIONAL
  end;
  {$EXTERNALSYM _CERT_KEY_ATTRIBUTES_INFO}
  CERT_KEY_ATTRIBUTES_INFO = _CERT_KEY_ATTRIBUTES_INFO;
  {$EXTERNALSYM CERT_KEY_ATTRIBUTES_INFO}
  TCertKeyAttributesInfo = _CERT_KEY_ATTRIBUTES_INFO;
  PCERT_KEY_ATTRIBUTES_INFO = PCertKeyAttributesInfo;
  {$EXTERNALSYM PCERT_KEY_ATTRIBUTES_INFO}

// certenrolld_begin -- CERT_*_KEY_USAGE
// Byte[0]
const
  CERT_DIGITAL_SIGNATURE_KEY_USAGE    = $80;
  {$EXTERNALSYM CERT_DIGITAL_SIGNATURE_KEY_USAGE}
  CERT_NON_REPUDIATION_KEY_USAGE      = $40;
  {$EXTERNALSYM CERT_NON_REPUDIATION_KEY_USAGE}
  CERT_KEY_ENCIPHERMENT_KEY_USAGE     = $20;
  {$EXTERNALSYM CERT_KEY_ENCIPHERMENT_KEY_USAGE}
  CERT_DATA_ENCIPHERMENT_KEY_USAGE    = $10;
  {$EXTERNALSYM CERT_DATA_ENCIPHERMENT_KEY_USAGE}
  CERT_KEY_AGREEMENT_KEY_USAGE        = $08;
  {$EXTERNALSYM CERT_KEY_AGREEMENT_KEY_USAGE}
  CERT_KEY_CERT_SIGN_KEY_USAGE        = $04;
  {$EXTERNALSYM CERT_KEY_CERT_SIGN_KEY_USAGE}
  CERT_OFFLINE_CRL_SIGN_KEY_USAGE     = $02;
  {$EXTERNALSYM CERT_OFFLINE_CRL_SIGN_KEY_USAGE}
  CERT_CRL_SIGN_KEY_USAGE             = $02;
  {$EXTERNALSYM CERT_CRL_SIGN_KEY_USAGE}
  CERT_ENCIPHER_ONLY_KEY_USAGE        = $01;
  {$EXTERNALSYM CERT_ENCIPHER_ONLY_KEY_USAGE}
// Byte[1]
const
  CERT_DECIPHER_ONLY_KEY_USAGE        = $80;
  {$EXTERNALSYM CERT_DECIPHER_ONLY_KEY_USAGE}
// certenrolld_end

//+-------------------------------------------------------------------------
//  X509_KEY_USAGE_RESTRICTION
//  szOID_KEY_USAGE_RESTRICTION
//
//  pvStructInfo points to following CERT_KEY_USAGE_RESTRICTION_INFO.
//--------------------------------------------------------------------------
type
  PCertPolicyID = ^TCertPolicyID;
  _CERT_POLICY_ID = record
    cCertPolicyElementId: DWORD;
    rgpszCertPolicyElementId: PLPSTR;  // pszObjId
  end;
  {$EXTERNALSYM _CERT_POLICY_ID}
  CERT_POLICY_ID = _CERT_POLICY_ID;
  {$EXTERNALSYM CERT_POLICY_ID}
  TCertPolicyID = _CERT_POLICY_ID;
  PCERT_POLICY_ID = PCertPolicyID;
  {$EXTERNALSYM PCERT_POLICY_ID}

type
  PCertKeyUsageRestrictionInfo = ^TCertKeyUsageRestrictionInfo;
  _CERT_KEY_USAGE_RESTRICTION_INFO = record
    cCertPolicyId: DWORD;
    rgCertPolicyId: PCertPolicyID;
    RestrictedKeyUsage: TCryptBitBlob;
  end;
  {$EXTERNALSYM _CERT_KEY_USAGE_RESTRICTION_INFO}
  CERT_KEY_USAGE_RESTRICTION_INFO = _CERT_KEY_USAGE_RESTRICTION_INFO;
  {$EXTERNALSYM CERT_KEY_USAGE_RESTRICTION_INFO}
  TCertKeyUsageRestrictionInfo = _CERT_KEY_USAGE_RESTRICTION_INFO;
  PCERT_KEY_USAGE_RESTRICTION_INFO = PCertKeyUsageRestrictionInfo;
  {$EXTERNALSYM PCERT_KEY_USAGE_RESTRICTION_INFO}

// See CERT_KEY_ATTRIBUTES_INFO for definition of the RestrictedKeyUsage bits

//+-------------------------------------------------------------------------
//  X509_ALTERNATE_NAME
//  szOID_SUBJECT_ALT_NAME
//  szOID_ISSUER_ALT_NAME
//  szOID_SUBJECT_ALT_NAME2
//  szOID_ISSUER_ALT_NAME2
//
//  pvStructInfo points to following CERT_ALT_NAME_INFO.
//--------------------------------------------------------------------------

// certenrolld_begin -- CERT_ALT_NAME_*
const
  CERT_ALT_NAME_OTHER_NAME        = 1;
  {$EXTERNALSYM CERT_ALT_NAME_OTHER_NAME}
  CERT_ALT_NAME_RFC822_NAME       = 2;
  {$EXTERNALSYM CERT_ALT_NAME_RFC822_NAME}
  CERT_ALT_NAME_DNS_NAME          = 3;
  {$EXTERNALSYM CERT_ALT_NAME_DNS_NAME}
  CERT_ALT_NAME_X400_ADDRESS      = 4;
  {$EXTERNALSYM CERT_ALT_NAME_X400_ADDRESS}
  CERT_ALT_NAME_DIRECTORY_NAME    = 5;
  {$EXTERNALSYM CERT_ALT_NAME_DIRECTORY_NAME}
  CERT_ALT_NAME_EDI_PARTY_NAME    = 6;
  {$EXTERNALSYM CERT_ALT_NAME_EDI_PARTY_NAME}
  CERT_ALT_NAME_URL               = 7;
  {$EXTERNALSYM CERT_ALT_NAME_URL}
  CERT_ALT_NAME_IP_ADDRESS        = 8;
  {$EXTERNALSYM CERT_ALT_NAME_IP_ADDRESS}
  CERT_ALT_NAME_REGISTERED_ID     = 9;
  {$EXTERNALSYM CERT_ALT_NAME_REGISTERED_ID}
// certenrolld_end

// certenrolls_begin -- CERT_ALT_NAME_INFO
type
  PCertOtherName = ^TCertOtherName;
  _CERT_OTHER_NAME = record
    pszObjId: LPSTR;
    Value: TCryptObjIDBlob;
  end;
  {$EXTERNALSYM _CERT_OTHER_NAME}
  CERT_OTHER_NAME = _CERT_OTHER_NAME;
  {$EXTERNALSYM CERT_OTHER_NAME}
  TCertOtherName = _CERT_OTHER_NAME;
  PCERT_OTHER_NAME = PCertOtherName;
  {$EXTERNALSYM PCERT_OTHER_NAME}

type
  PCertAltNameEntry = ^TCertAltNameEntry;
  _CERT_ALT_NAME_ENTRY = record
    case dwAltNameChoice: DWORD of
    CERT_ALT_NAME_OTHER_NAME:
      (pOtherName: PCertOtherName);                     // 1
    CERT_ALT_NAME_RFC822_NAME:
      (pwszRfc822Name: LPWSTR);                         // 2  (encoded IA5)
    CERT_ALT_NAME_DNS_NAME:
      (pwszDNSName: LPWSTR);                            // 3  (encoded IA5)
    CERT_ALT_NAME_X400_ADDRESS:
      (); // Not implemented          x400Address;      // 4
    CERT_ALT_NAME_DIRECTORY_NAME:
      (DirectoryName: TCertNameBlob);                   // 5
    CERT_ALT_NAME_EDI_PARTY_NAME:
      (); // Not implemented          pEdiPartyName;    // 6
    CERT_ALT_NAME_URL:
      (pwszURL: LPWSTR);                                // 7  (encoded IA5)
    CERT_ALT_NAME_IP_ADDRESS:
      (IPAddress: TCryptDataBlob);                      // 8  (Octet String)
    CERT_ALT_NAME_REGISTERED_ID:
      (pszRegisteredID: LPSTR);                         // 9  (Object Identifer)
                                                        // certenrolls_skip
  end;
  {$EXTERNALSYM _CERT_ALT_NAME_ENTRY}
  CERT_ALT_NAME_ENTRY = _CERT_ALT_NAME_ENTRY;
  {$EXTERNALSYM CERT_ALT_NAME_ENTRY}
  TCertAltNameEntry = _CERT_ALT_NAME_ENTRY;
  PCERT_ALT_NAME_ENTRY = PCertAltNameEntry;
  {$EXTERNALSYM PCERT_ALT_NAME_ENTRY}
// certenrolls_end

// certenrolls_begin -- CERT_ALT_NAME_INFO
type
  PCertAltNameInfo = ^TCertAltNameInfo;
  _CERT_ALT_NAME_INFO = record
    cAltEntry: DWORD;
    rgAltEntry: PCertAltNameEntry;
  end;
  {$EXTERNALSYM _CERT_ALT_NAME_INFO}
  CERT_ALT_NAME_INFO = _CERT_ALT_NAME_INFO;
  {$EXTERNALSYM CERT_ALT_NAME_INFO}
  TCertAltNameInfo = _CERT_ALT_NAME_INFO;
  PCERT_ALT_NAME_INFO = PCertAltNameInfo;
  {$EXTERNALSYM PCERT_ALT_NAME_INFO}
// certenrolls_end

//+-------------------------------------------------------------------------
//  Alternate name IA5 Error Location Definitions for
//  CRYPT_E_INVALID_IA5_STRING.
//
//  Error location is returned in *pcbEncoded by
//  CryptEncodeObject(X509_ALTERNATE_NAME)
//
//  Error location consists of:
//    ENTRY_INDEX   - 8 bits << 16
//    VALUE_INDEX   - 16 bits (unicode character index)
//--------------------------------------------------------------------------
const
  CERT_ALT_NAME_ENTRY_ERR_INDEX_MASK  = $FF;
  {$EXTERNALSYM CERT_ALT_NAME_ENTRY_ERR_INDEX_MASK}
  CERT_ALT_NAME_ENTRY_ERR_INDEX_SHIFT = 16;
  {$EXTERNALSYM CERT_ALT_NAME_ENTRY_ERR_INDEX_SHIFT}
  CERT_ALT_NAME_VALUE_ERR_INDEX_MASK  = $0000FFFF;
  {$EXTERNALSYM CERT_ALT_NAME_VALUE_ERR_INDEX_MASK}
  CERT_ALT_NAME_VALUE_ERR_INDEX_SHIFT = 0;
  {$EXTERNALSYM CERT_ALT_NAME_VALUE_ERR_INDEX_SHIFT}

function GET_CERT_ALT_NAME_ENTRY_ERR_INDEX(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CERT_ALT_NAME_ENTRY_ERR_INDEX}
function GET_CERT_ALT_NAME_VALUE_ERR_INDEX(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CERT_ALT_NAME_VALUE_ERR_INDEX}


//+-------------------------------------------------------------------------
//  X509_BASIC_CONSTRAINTS
//  szOID_BASIC_CONSTRAINTS
//
//  pvStructInfo points to following CERT_BASIC_CONSTRAINTS_INFO.
//--------------------------------------------------------------------------
type
  PCertBasicConstraintsInfo = ^TCertBasicConstraintsInfo;
  _CERT_BASIC_CONSTRAINTS_INFO = record
    SubjectType: TCryptBitBlob;
    fPathLenConstraint: BOOL;
    dwPathLenConstraint: DWORD;
    cSubtreesConstraint: DWORD;
    rgSubtreesConstraint: PCertNameBlob;
  end;
  {$EXTERNALSYM _CERT_BASIC_CONSTRAINTS_INFO}
  CERT_BASIC_CONSTRAINTS_INFO = _CERT_BASIC_CONSTRAINTS_INFO;
  {$EXTERNALSYM CERT_BASIC_CONSTRAINTS_INFO}
  TCertBasicConstraintsInfo = _CERT_BASIC_CONSTRAINTS_INFO;
  PCERT_BASIC_CONSTRAINTS_INFO = PCertBasicConstraintsInfo;
  {$EXTERNALSYM PCERT_BASIC_CONSTRAINTS_INFO}

const
  CERT_CA_SUBJECT_FLAG         = $80;
  {$EXTERNALSYM CERT_CA_SUBJECT_FLAG}
  CERT_END_ENTITY_SUBJECT_FLAG = $40;
  {$EXTERNALSYM CERT_END_ENTITY_SUBJECT_FLAG}

//+-------------------------------------------------------------------------
//  X509_BASIC_CONSTRAINTS2
//  szOID_BASIC_CONSTRAINTS2
//
//  pvStructInfo points to following CERT_BASIC_CONSTRAINTS2_INFO.
//--------------------------------------------------------------------------
type
  PCertBasicConstraints2Info = ^TCertBasicConstraints2Info;
  _CERT_BASIC_CONSTRAINTS2_INFO = record
    fCA: BOOL;
    fPathLenConstraint: BOOL;
    dwPathLenConstraint: DWORD;
  end;
  {$EXTERNALSYM _CERT_BASIC_CONSTRAINTS2_INFO}
  CERT_BASIC_CONSTRAINTS2_INFO = _CERT_BASIC_CONSTRAINTS2_INFO;
  {$EXTERNALSYM CERT_BASIC_CONSTRAINTS2_INFO}
  TCertBasicConstraints2Info = _CERT_BASIC_CONSTRAINTS2_INFO;
  PCERT_BASIC_CONSTRAINTS2_INFO = PCertBasicConstraints2Info;
  {$EXTERNALSYM PCERT_BASIC_CONSTRAINTS2_INFO}

//+-------------------------------------------------------------------------
//  X509_KEY_USAGE
//  szOID_KEY_USAGE
//
//  pvStructInfo points to a CRYPT_BIT_BLOB. Has same bit definitions as
//  CERT_KEY_ATTRIBUTES_INFO's IntendedKeyUsage.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_CERT_POLICIES
//  szOID_CERT_POLICIES
//  szOID_CERT_POLICIES_95   NOTE--Only allowed for decoding!!!
//
//  pvStructInfo points to following CERT_POLICIES_INFO.
//
//  NOTE: when decoding using szOID_CERT_POLICIES_95 the pszPolicyIdentifier
//        may contain an empty string
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_POLICY_QUALIFIER_INFO
type
  PCertPolicyQualifierInfo = ^TCertPolicyQualifierInfo;
  _CERT_POLICY_QUALIFIER_INFO = record
    pszPolicyQualifierId: LPSTR;                          // pszObjId
    Qualifier: TCryptObjIDBlob;                           // optional
  end;
  {$EXTERNALSYM _CERT_POLICY_QUALIFIER_INFO}
  CERT_POLICY_QUALIFIER_INFO = _CERT_POLICY_QUALIFIER_INFO;
  {$EXTERNALSYM CERT_POLICY_QUALIFIER_INFO}
  TCertPolicyQualifierInfo = _CERT_POLICY_QUALIFIER_INFO;
  PCERT_POLICY_QUALIFIER_INFO = PCertPolicyQualifierInfo;
  {$EXTERNALSYM PCERT_POLICY_QUALIFIER_INFO}

type
  PCertPolicyInfo = ^TCertPolicyInfo;
  _CERT_POLICY_INFO = record
    pszPolicyIdentifier: LPSTR;                           // pszObjId
    cPolicyQualifier: DWORD;                              // optional
    rgPolicyQualifier: PCertPolicyQualifierInfo;
  end;
  {$EXTERNALSYM _CERT_POLICY_INFO}
  CERT_POLICY_INFO = _CERT_POLICY_INFO;
  {$EXTERNALSYM CERT_POLICY_INFO}
  TCertPolicyInfo = _CERT_POLICY_INFO;
  PCERT_POLICY_INFO = PCertPolicyInfo;
  {$EXTERNALSYM PCERT_POLICY_INFO}

type
  PCertPoliciesInfo = ^TCertPoliciesInfo;
  _CERT_POLICIES_INFO = record
    cPolicyInfo: DWORD;
    rgPolicyInfo: PCertPolicyInfo;
  end;
  {$EXTERNALSYM _CERT_POLICIES_INFO}
  CERT_POLICIES_INFO = _CERT_POLICIES_INFO;
  {$EXTERNALSYM CERT_POLICIES_INFO}
  TCertPoliciesInfo = _CERT_POLICIES_INFO;
  PCERT_POLICIES_INFO = PCertPoliciesInfo;
  {$EXTERNALSYM PCERT_POLICIES_INFO}
// certenrolls_end

//+-------------------------------------------------------------------------
//  X509_PKIX_POLICY_QUALIFIER_USERNOTICE
//  szOID_PKIX_POLICY_QUALIFIER_USERNOTICE
//
//  pvStructInfo points to following CERT_POLICY_QUALIFIER_USER_NOTICE.
//
//--------------------------------------------------------------------------
type
  PCertPolicyQualifierNoticeReference = ^TCertPolicyQualifierNoticeReference;
  _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE = record
    pszOrganization: LPSTR;
    cNoticeNumbers: DWORD;
    rgNoticeNumbers: ^Integer;
  end;
  {$EXTERNALSYM _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE}
  CERT_POLICY_QUALIFIER_NOTICE_REFERENCE = _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE;
  {$EXTERNALSYM CERT_POLICY_QUALIFIER_NOTICE_REFERENCE}
  TCertPolicyQualifierNoticeReference = _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE;
  PCERT_POLICY_QUALIFIER_NOTICE_REFERENCE = PCertPolicyQualifierNoticeReference;
  {$EXTERNALSYM PCERT_POLICY_QUALIFIER_NOTICE_REFERENCE}

type
  PCertPolicyQualifierUserNotice = ^TCertPolicyQualifierUserNotice;
  _CERT_POLICY_QUALIFIER_USER_NOTICE = record
    pNoticeReference: PCertPolicyQualifierNoticeReference;        // optional
    pszDisplayText: LPWSTR;                                       // optional
  end;
  {$EXTERNALSYM _CERT_POLICY_QUALIFIER_USER_NOTICE}
  CERT_POLICY_QUALIFIER_USER_NOTICE = _CERT_POLICY_QUALIFIER_USER_NOTICE;
  {$EXTERNALSYM CERT_POLICY_QUALIFIER_USER_NOTICE}
  TCertPolicyQualifierUserNotice = _CERT_POLICY_QUALIFIER_USER_NOTICE;
  PCERT_POLICY_QUALIFIER_USER_NOTICE = PCertPolicyQualifierUserNotice;
  {$EXTERNALSYM PCERT_POLICY_QUALIFIER_USER_NOTICE}

//+-------------------------------------------------------------------------
//  szOID_CERT_POLICIES_95_QUALIFIER1 - Decode Only!!!!
//
//  pvStructInfo points to following CERT_POLICY95_QUALIFIER1.
//
//--------------------------------------------------------------------------
type
  PCPSURLs = ^TCPSURLs;
  _CPS_URLS = record
    pszURL: LPWSTR;
    pAlgorithm: PCryptAlgorithmIdentifier;    // optional
    pDigest: PCryptDataBlob;                  // optional
  end;
  {$EXTERNALSYM _CPS_URLS}
  CPS_URLS = _CPS_URLS;
  {$EXTERNALSYM CPS_URLS}
  TCPSURLs = _CPS_URLS;
  PCPS_URLS = PCPSURLs;
  {$EXTERNALSYM PCPS_URLS}

type
  PCertPolicy95Qualifier1 = ^TCertPolicy95Qualifier1;
  _CERT_POLICY95_QUALIFIER1 = record
    pszPracticesReference: LPWSTR;            // optional
    pszNoticeIdentifier: LPSTR;               // optional
    pszNSINoticeIdentifier: LPSTR;            // optional
    cCPSURLs: DWORD;
    rgCPSURLs: PCPSURLs;                      // optional
  end;
  {$EXTERNALSYM _CERT_POLICY95_QUALIFIER1}
  CERT_POLICY95_QUALIFIER1 = _CERT_POLICY95_QUALIFIER1;
  {$EXTERNALSYM CERT_POLICY95_QUALIFIER1}
  TCertPolicy95Qualifier1 = _CERT_POLICY95_QUALIFIER1;
  PCERT_POLICY95_QUALIFIER1 = PCertPolicy95Qualifier1;
  {$EXTERNALSYM PCERT_POLICY95_QUALIFIER1}

//+-------------------------------------------------------------------------
//  szOID_INHIBIT_ANY_POLICY data structure
//
//  pvStructInfo points to an int.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
//  X509_POLICY_MAPPINGS
//  szOID_POLICY_MAPPINGS
//  szOID_LEGACY_POLICY_MAPPINGS
//
//  pvStructInfo points to following CERT_POLICY_MAPPINGS_INFO.
//--------------------------------------------------------------------------
type
  PCertPolicyMapping = ^TCertPolicyMapping;
  _CERT_POLICY_MAPPING = record
    pszIssuerDomainPolicy: LPSTR;                             // pszObjId
    pszSubjectDomainPolicy: LPSTR;                            // pszObjId
  end;
  {$EXTERNALSYM _CERT_POLICY_MAPPING}
  CERT_POLICY_MAPPING = _CERT_POLICY_MAPPING;
  {$EXTERNALSYM CERT_POLICY_MAPPING}
  TCertPolicyMapping = _CERT_POLICY_MAPPING;
  PCERT_POLICY_MAPPING = PCertPolicyMapping;
  {$EXTERNALSYM PCERT_POLICY_MAPPING}

type
  PCertPolicyMappingsInfo = ^TCertPolicyMappingsInfo;
  _CERT_POLICY_MAPPINGS_INFO = record
    cPolicyMapping: DWORD;
    rgPolicyMapping: PCertPolicyMapping;
  end;
  {$EXTERNALSYM _CERT_POLICY_MAPPINGS_INFO}
  CERT_POLICY_MAPPINGS_INFO = _CERT_POLICY_MAPPINGS_INFO;
  {$EXTERNALSYM CERT_POLICY_MAPPINGS_INFO}
  TCertPolicyMappingsInfo = _CERT_POLICY_MAPPINGS_INFO;
  PCERT_POLICY_MAPPINGS_INFO = PCertPolicyMappingsInfo;
  {$EXTERNALSYM PCERT_POLICY_MAPPINGS_INFO}

//+-------------------------------------------------------------------------
//  X509_POLICY_CONSTRAINTS
//  szOID_POLICY_CONSTRAINTS
//
//  pvStructInfo points to following CERT_POLICY_CONSTRAINTS_INFO.
//--------------------------------------------------------------------------
type
  PCertPolicyConstraintsInfo = ^TCertPolicyConstraintsInfo;
  _CERT_POLICY_CONSTRAINTS_INFO = record
    fRequireExplicitPolicy: BOOL;
    dwRequireExplicitPolicySkipCerts: DWORD;

    fInhibitPolicyMapping: BOOL;
    dwInhibitPolicyMappingSkipCerts: DWORD;
  end;
  {$EXTERNALSYM _CERT_POLICY_CONSTRAINTS_INFO}
  CERT_POLICY_CONSTRAINTS_INFO = _CERT_POLICY_CONSTRAINTS_INFO;
  {$EXTERNALSYM CERT_POLICY_CONSTRAINTS_INFO}
  TCertPolicyConstraintsInfo = _CERT_POLICY_CONSTRAINTS_INFO;
  PCERT_POLICY_CONSTRAINTS_INFO = PCertPolicyConstraintsInfo;
  {$EXTERNALSYM PCERT_POLICY_CONSTRAINTS_INFO}

//+-------------------------------------------------------------------------
//  RSA_CSP_PUBLICKEYBLOB
//
//  pvStructInfo points to a PUBLICKEYSTRUC immediately followed by a
//  RSAPUBKEY and the modulus bytes.
//
//  CryptExportKey outputs the above StructInfo for a dwBlobType of
//  PUBLICKEYBLOB. CryptImportKey expects the above StructInfo when
//  importing a public key.
//
//  For dwCertEncodingType = X509_ASN_ENCODING, the RSA_CSP_PUBLICKEYBLOB is
//  encoded as a PKCS #1 RSAPublicKey consisting of a SEQUENCE of a
//  modulus INTEGER and a publicExponent INTEGER. The modulus is encoded
//  as being a unsigned integer. When decoded, if the modulus was encoded
//  as unsigned integer with a leading 0 byte, the 0 byte is removed before
//  converting to the CSP modulus bytes.
//
//  For decode, the aiKeyAlg field of PUBLICKEYSTRUC is always set to
//  CALG_RSA_KEYX.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CNG_RSA_PUBLIC_KEY_BLOB
//
//  pvStructInfo points to a BCRYPT_RSAKEY_BLOB immediately followed by the
//  exponent and the modulus bytes. Both the exponent and modulus are
//  big endian. The private key fields consisting of cbPrime1 and cbPrime2
//  are set to zero.
//
//  For dwCertEncodingType = X509_ASN_ENCODING, the CNG_RSA_PUBLIC_KEY_BLOB is
//  encoded as a PKCS #1 RSAPublicKey consisting of a SEQUENCE of a
//  modulus HUGEINTEGER and a publicExponent HUGEINTEGER.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_KEYGEN_REQUEST_TO_BE_SIGNED
//
//  pvStructInfo points to CERT_KEYGEN_REQUEST_INFO.
//
//  For CryptDecodeObject(), the pbEncoded is the "to be signed" plus its
//  signature (output of a X509_CERT CryptEncodeObject()).
//
//  For CryptEncodeObject(), the pbEncoded is just the "to be signed".
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  PKCS_ATTRIBUTE data structure
//
//  pvStructInfo points to a CRYPT_ATTRIBUTE.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  PKCS_ATTRIBUTES data structure
//
//  pvStructInfo points to a CRYPT_ATTRIBUTES.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  PKCS_CONTENT_INFO_SEQUENCE_OF_ANY data structure
//
//  pvStructInfo points to following CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY.
//
//  For X509_ASN_ENCODING: encoded as a PKCS#7 ContentInfo structure wrapping
//  a sequence of ANY. The value of the contentType field is pszObjId,
//  while the content field is the following structure:
//      SequenceOfAny ::= SEQUENCE OF ANY
//
//  The CRYPT_DER_BLOBs point to the already encoded ANY content.
//--------------------------------------------------------------------------
type
  PCryptContentInfoSequenceOfAny = ^TCryptContentInfoSequenceOfAny;
  _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY = record
    pszObjId: LPSTR;
    cValue: DWORD;
    rgValue: PCryptDERBlob;
  end;
  {$EXTERNALSYM _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY}
  CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY = _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;
  {$EXTERNALSYM CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY}
  TCryptContentInfoSequenceOfAny = _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;
  PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY = PCryptContentInfoSequenceOfAny;
  {$EXTERNALSYM PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY}

//+-------------------------------------------------------------------------
//  PKCS_CONTENT_INFO data structure
//
//  pvStructInfo points to following CRYPT_CONTENT_INFO.
//
//  For X509_ASN_ENCODING: encoded as a PKCS#7 ContentInfo structure.
//  The CRYPT_DER_BLOB points to the already encoded ANY content.
//--------------------------------------------------------------------------
type
  PCryptContentInfo = ^TCryptContentInfo;
  _CRYPT_CONTENT_INFO = record
    pszObjId: LPSTR;
    Content: TCryptDERBlob;
  end;
  {$EXTERNALSYM _CRYPT_CONTENT_INFO}
  CRYPT_CONTENT_INFO = _CRYPT_CONTENT_INFO;
  {$EXTERNALSYM CRYPT_CONTENT_INFO}
  TCryptContentInfo = _CRYPT_CONTENT_INFO;
  PCRYPT_CONTENT_INFO = PCryptContentInfo;
  {$EXTERNALSYM PCRYPT_CONTENT_INFO}

//+-------------------------------------------------------------------------
//  X509_OCTET_STRING data structure
//
//  pvStructInfo points to a CRYPT_DATA_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_BITS data structure
//
//  pvStructInfo points to a CRYPT_BIT_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_BITS_WITHOUT_TRAILING_ZEROES data structure
//
//  pvStructInfo points to a CRYPT_BIT_BLOB.
//
//  The same as X509_BITS, except before encoding, the bit length is
//  decremented to exclude trailing zero bits.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_INTEGER data structure
//
//  pvStructInfo points to an int.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_MULTI_BYTE_INTEGER data structure
//
//  pvStructInfo points to a CRYPT_INTEGER_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_ENUMERATED data structure
//
//  pvStructInfo points to an int containing the enumerated value
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_CHOICE_OF_TIME data structure
//
//  pvStructInfo points to a FILETIME.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_SEQUENCE_OF_ANY data structure
//
//  pvStructInfo points to following CRYPT_SEQUENCE_OF_ANY.
//
//  The CRYPT_DER_BLOBs point to the already encoded ANY content.
//--------------------------------------------------------------------------
type
  PCryptSequenceOfAny = ^TCryptSequenceOfAny;
  _CRYPT_SEQUENCE_OF_ANY = record
    cValue: DWORD;
    rgValue: PCryptDERBlob;
  end;
  {$EXTERNALSYM _CRYPT_SEQUENCE_OF_ANY}
  CRYPT_SEQUENCE_OF_ANY = _CRYPT_SEQUENCE_OF_ANY;
  {$EXTERNALSYM CRYPT_SEQUENCE_OF_ANY}
  TCryptSequenceOfAny = _CRYPT_SEQUENCE_OF_ANY;
  PCRYPT_SEQUENCE_OF_ANY = PCryptSequenceOfAny;
  {$EXTERNALSYM PCRYPT_SEQUENCE_OF_ANY}

//+-------------------------------------------------------------------------
//  X509_AUTHORITY_KEY_ID2
//  szOID_AUTHORITY_KEY_IDENTIFIER2
//
//  pvStructInfo points to following CERT_AUTHORITY_KEY_ID2_INFO.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_AUTHORITY_KEY_ID2)
//
//  See X509_ALTERNATE_NAME for error location defines.
//--------------------------------------------------------------------------
type
  PCertAuthorityKeyID2Info = ^TCertAuthorityKeyID2Info;
  _CERT_AUTHORITY_KEY_ID2_INFO = record
    KeyId: TCryptDataBlob;
    AuthorityCertIssuer: TCertAltNameInfo;      // Optional, set cAltEntry
                                                // to 0 to omit.
    AuthorityCertSerialNumber: TCryptIntegerBlob;
  end;
  {$EXTERNALSYM _CERT_AUTHORITY_KEY_ID2_INFO}
  CERT_AUTHORITY_KEY_ID2_INFO = _CERT_AUTHORITY_KEY_ID2_INFO;
  {$EXTERNALSYM CERT_AUTHORITY_KEY_ID2_INFO}
  TCertAuthorityKeyID2Info = _CERT_AUTHORITY_KEY_ID2_INFO;
  PCERT_AUTHORITY_KEY_ID2_INFO = PCertAuthorityKeyID2Info;
  {$EXTERNALSYM PCERT_AUTHORITY_KEY_ID2_INFO}

//+-------------------------------------------------------------------------
//  szOID_SUBJECT_KEY_IDENTIFIER
//
//  pvStructInfo points to a CRYPT_DATA_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_AUTHORITY_INFO_ACCESS
//  szOID_AUTHORITY_INFO_ACCESS
//
//  X509_SUBJECT_INFO_ACCESS
//  szOID_SUBJECT_INFO_ACCESS
//
//  pvStructInfo points to following CERT_AUTHORITY_INFO_ACCESS.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_AUTHORITY_INFO_ACCESS)
//
//  Error location consists of:
//    ENTRY_INDEX   - 8 bits << 16
//    VALUE_INDEX   - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//
//  Note, the szOID_SUBJECT_INFO_ACCESS extension has the same ASN.1
//  encoding as the szOID_AUTHORITY_INFO_ACCESS extension.
//--------------------------------------------------------------------------
type
  PCertAccessDescription = ^TCertAccessDescription;
  _CERT_ACCESS_DESCRIPTION = record
    pszAccessMethod: LPSTR;                       // pszObjId
    AccessLocation: TCertAltNameEntry;
  end;
  {$EXTERNALSYM _CERT_ACCESS_DESCRIPTION}
  CERT_ACCESS_DESCRIPTION = _CERT_ACCESS_DESCRIPTION;
  {$EXTERNALSYM CERT_ACCESS_DESCRIPTION}
  TCertAccessDescription = _CERT_ACCESS_DESCRIPTION;
  PCERT_ACCESS_DESCRIPTION = PCertAccessDescription;
  {$EXTERNALSYM PCERT_ACCESS_DESCRIPTION}

type
  PCertAuthorityInfoAccess = ^TCertAuthorityInfoAccess;
  _CERT_AUTHORITY_INFO_ACCESS = record
    cAccDescr: DWORD;
    rgAccDescr: PCertAccessDescription;
  end;
  {$EXTERNALSYM _CERT_AUTHORITY_INFO_ACCESS}
  CERT_AUTHORITY_INFO_ACCESS = _CERT_AUTHORITY_INFO_ACCESS;
  {$EXTERNALSYM CERT_AUTHORITY_INFO_ACCESS}
  TCertAuthorityInfoAccess = _CERT_AUTHORITY_INFO_ACCESS;
  PCERT_AUTHORITY_INFO_ACCESS = PCertAuthorityInfoAccess;
  {$EXTERNALSYM PCERT_AUTHORITY_INFO_ACCESS}

  PCertSubjectInfoAccess = ^TCertSubjectInfoAccess;
  CERT_SUBJECT_INFO_ACCESS = _CERT_AUTHORITY_INFO_ACCESS;
  {$EXTERNALSYM CERT_SUBJECT_INFO_ACCESS}
  TCertSubjectInfoAccess = _CERT_AUTHORITY_INFO_ACCESS;
  PCERT_SUBJECT_INFO_ACCESS = PCertSubjectInfoAccess;
  {$EXTERNALSYM PCERT_SUBJECT_INFO_ACCESS}

//+-------------------------------------------------------------------------
//  PKIX Access Description: Access Method Object Identifiers
//--------------------------------------------------------------------------
const
  szOID_PKIX_ACC_DESCR           = '1.3.6.1.5.5.7.48';
  {$EXTERNALSYM szOID_PKIX_ACC_DESCR}

// For szOID_AUTHORITY_INFO_ACCESS
const
  szOID_PKIX_OCSP                = '1.3.6.1.5.5.7.48.1';
  {$EXTERNALSYM szOID_PKIX_OCSP}
  szOID_PKIX_CA_ISSUERS          = '1.3.6.1.5.5.7.48.2';
  {$EXTERNALSYM szOID_PKIX_CA_ISSUERS}

// For szOID_SUBJECT_INFO_ACCESS
const
  szOID_PKIX_TIME_STAMPING       = '1.3.6.1.5.5.7.48.3';
  {$EXTERNALSYM szOID_PKIX_TIME_STAMPING}
  szOID_PKIX_CA_REPOSITORY       = '1.3.6.1.5.5.7.48.5';
  {$EXTERNALSYM szOID_PKIX_CA_REPOSITORY}


//+-------------------------------------------------------------------------
//  X509_CRL_REASON_CODE
//  szOID_CRL_REASON_CODE
//
//  pvStructInfo points to an int which can be set to one of the following
//  enumerated values:
//--------------------------------------------------------------------------
const
  CRL_REASON_UNSPECIFIED             = 0;
  {$EXTERNALSYM CRL_REASON_UNSPECIFIED}
  CRL_REASON_KEY_COMPROMISE          = 1;
  {$EXTERNALSYM CRL_REASON_KEY_COMPROMISE}
  CRL_REASON_CA_COMPROMISE           = 2;
  {$EXTERNALSYM CRL_REASON_CA_COMPROMISE}
  CRL_REASON_AFFILIATION_CHANGED     = 3;
  {$EXTERNALSYM CRL_REASON_AFFILIATION_CHANGED}
  CRL_REASON_SUPERSEDED              = 4;
  {$EXTERNALSYM CRL_REASON_SUPERSEDED}
  CRL_REASON_CESSATION_OF_OPERATION  = 5;
  {$EXTERNALSYM CRL_REASON_CESSATION_OF_OPERATION}
  CRL_REASON_CERTIFICATE_HOLD        = 6;
  {$EXTERNALSYM CRL_REASON_CERTIFICATE_HOLD}
  CRL_REASON_REMOVE_FROM_CRL         = 8;
  {$EXTERNALSYM CRL_REASON_REMOVE_FROM_CRL}


//+-------------------------------------------------------------------------
//  X509_CRL_DIST_POINTS
//  szOID_CRL_DIST_POINTS
//
//  pvStructInfo points to following CRL_DIST_POINTS_INFO.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_CRL_DIST_POINTS)
//
//  Error location consists of:
//    CRL_ISSUER_BIT    - 1 bit  << 31 (0 for FullName, 1 for CRLIssuer)
//    POINT_INDEX       - 7 bits << 24
//    ENTRY_INDEX       - 8 bits << 16
//    VALUE_INDEX       - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
const
  CRL_DIST_POINT_NO_NAME         = 0;
  {$EXTERNALSYM CRL_DIST_POINT_NO_NAME}
  CRL_DIST_POINT_FULL_NAME       = 1;
  {$EXTERNALSYM CRL_DIST_POINT_FULL_NAME}
  CRL_DIST_POINT_ISSUER_RDN_NAME = 2;
  {$EXTERNALSYM CRL_DIST_POINT_ISSUER_RDN_NAME}

type
  PCRLDistPointName = ^TCRLDistPointName;
  _CRL_DIST_POINT_NAME = record
    case dwDistPointNameChoice: DWORD of
    CRL_DIST_POINT_FULL_NAME:
      (FullName: TCertAltNameInfo);              // 1
    CRL_DIST_POINT_ISSUER_RDN_NAME:
      (); // Not implemented      IssuerRDN;     // 2
  end;
  {$EXTERNALSYM _CRL_DIST_POINT_NAME}
  CRL_DIST_POINT_NAME = _CRL_DIST_POINT_NAME;
  {$EXTERNALSYM CRL_DIST_POINT_NAME}
  TCRLDistPointName = _CRL_DIST_POINT_NAME;
  PCRL_DIST_POINT_NAME = PCRLDistPointName;
  {$EXTERNALSYM PCRL_DIST_POINT_NAME}

type
  PCRLDistPoint = ^TCRLDistPoint;
  _CRL_DIST_POINT = record
    DistPointName: TCRLDistPointName;            // OPTIONAL
    ReasonFlags: TCryptBitBlob;                  // OPTIONAL
    CRLIssuer: TCertAltNameInfo;                 // OPTIONAL
  end;
  {$EXTERNALSYM _CRL_DIST_POINT}
  CRL_DIST_POINT = _CRL_DIST_POINT;
  {$EXTERNALSYM CRL_DIST_POINT}
  TCRLDistPoint = _CRL_DIST_POINT;
  PCRL_DIST_POINT = PCRLDistPoint;
  {$EXTERNALSYM PCRL_DIST_POINT}

const
  CRL_REASON_UNUSED_FLAG                 = $80;
  {$EXTERNALSYM CRL_REASON_UNUSED_FLAG}
  CRL_REASON_KEY_COMPROMISE_FLAG         = $40;
  {$EXTERNALSYM CRL_REASON_KEY_COMPROMISE_FLAG}
  CRL_REASON_CA_COMPROMISE_FLAG          = $20;
  {$EXTERNALSYM CRL_REASON_CA_COMPROMISE_FLAG}
  CRL_REASON_AFFILIATION_CHANGED_FLAG    = $10;
  {$EXTERNALSYM CRL_REASON_AFFILIATION_CHANGED_FLAG}
  CRL_REASON_SUPERSEDED_FLAG             = $08;
  {$EXTERNALSYM CRL_REASON_SUPERSEDED_FLAG}
  CRL_REASON_CESSATION_OF_OPERATION_FLAG = $04;
  {$EXTERNALSYM CRL_REASON_CESSATION_OF_OPERATION_FLAG}
  CRL_REASON_CERTIFICATE_HOLD_FLAG       = $02;
  {$EXTERNALSYM CRL_REASON_CERTIFICATE_HOLD_FLAG}

type
  PCRLDistPointsInfo = ^TCRLDistPointsInfo;
  _CRL_DIST_POINTS_INFO = record
    cDistPoint: DWORD;
    rgDistPoint: PCRLDistPoint;
  end;
  {$EXTERNALSYM _CRL_DIST_POINTS_INFO}
  CRL_DIST_POINTS_INFO = _CRL_DIST_POINTS_INFO;
  {$EXTERNALSYM CRL_DIST_POINTS_INFO}
  TCRLDistPointsInfo = _CRL_DIST_POINTS_INFO;
  PCRL_DIST_POINTS_INFO = PCRLDistPointsInfo;
  {$EXTERNALSYM PCRL_DIST_POINTS_INFO}

const
  CRL_DIST_POINT_ERR_INDEX_MASK         = $7F;
  {$EXTERNALSYM CRL_DIST_POINT_ERR_INDEX_MASK}
  CRL_DIST_POINT_ERR_INDEX_SHIFT        = 24;
  {$EXTERNALSYM CRL_DIST_POINT_ERR_INDEX_SHIFT}

function GET_CRL_DIST_POINT_ERR_INDEX(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CRL_DIST_POINT_ERR_INDEX}

const
  CRL_DIST_POINT_ERR_CRL_ISSUER_BIT     = $80000000;
  {$EXTERNALSYM CRL_DIST_POINT_ERR_CRL_ISSUER_BIT}

function IS_CRL_DIST_POINT_ERR_CRL_ISSUER(X: DWORD): Boolean; inline;
{$EXTERNALSYM IS_CRL_DIST_POINT_ERR_CRL_ISSUER}

//+-------------------------------------------------------------------------
//  X509_CROSS_CERT_DIST_POINTS
//  szOID_CROSS_CERT_DIST_POINTS
//
//  pvStructInfo points to following CROSS_CERT_DIST_POINTS_INFO.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_CRL_DIST_POINTS)
//
//  Error location consists of:
//    POINT_INDEX       - 8 bits << 24
//    ENTRY_INDEX       - 8 bits << 16
//    VALUE_INDEX       - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
type
  PCrossCertDistPointsInfo = ^TCrossCertDistPointsInfo;
  _CROSS_CERT_DIST_POINTS_INFO = record
    // Seconds between syncs. 0 implies use client default.
    dwSyncDeltaTime: DWORD;

    cDistPoint: DWORD;
    rgDistPoint: PCertAltNameInfo;
  end;
  {$EXTERNALSYM _CROSS_CERT_DIST_POINTS_INFO}
  CROSS_CERT_DIST_POINTS_INFO = _CROSS_CERT_DIST_POINTS_INFO;
  {$EXTERNALSYM CROSS_CERT_DIST_POINTS_INFO}
  TCrossCertDistPointsInfo = _CROSS_CERT_DIST_POINTS_INFO;
  PCROSS_CERT_DIST_POINTS_INFO = PCrossCertDistPointsInfo;
  {$EXTERNALSYM PCROSS_CERT_DIST_POINTS_INFO}

const
  CROSS_CERT_DIST_POINT_ERR_INDEX_MASK  = $FF;
  {$EXTERNALSYM CROSS_CERT_DIST_POINT_ERR_INDEX_MASK}
  CROSS_CERT_DIST_POINT_ERR_INDEX_SHIFT = 24;
  {$EXTERNALSYM CROSS_CERT_DIST_POINT_ERR_INDEX_SHIFT}

function GET_CROSS_CERT_DIST_POINT_ERR_INDEX(X: DWORD): DWORD; inline;
{$EXTERNALSYM GET_CROSS_CERT_DIST_POINT_ERR_INDEX}


//+-------------------------------------------------------------------------
//  X509_ENHANCED_KEY_USAGE
//  szOID_ENHANCED_KEY_USAGE
//
//  pvStructInfo points to a CERT_ENHKEY_USAGE, CTL_USAGE.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_CERT_PAIR
//
//  pvStructInfo points to the following CERT_PAIR.
//--------------------------------------------------------------------------
type
  PCertPair = ^TCertPair;
  _CERT_PAIR = record
   Forward: TCertBlob;            // OPTIONAL, if Forward.cbData == 0, omitted
   Reverse: TCertBlob;            // OPTIONAL, if Reverse.cbData == 0, omitted
  end;
  {$EXTERNALSYM _CERT_PAIR}
  CERT_PAIR = _CERT_PAIR;
  {$EXTERNALSYM CERT_PAIR}
  TCertPair = _CERT_PAIR;
  PCERT_PAIR = PCertPair;
  {$EXTERNALSYM PCERT_PAIR}

//+-------------------------------------------------------------------------
//  szOID_CRL_NUMBER
//
//  pvStructInfo points to an int.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_DELTA_CRL_INDICATOR
//
//  pvStructInfo points to an int.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_ISSUING_DIST_POINT
//  X509_ISSUING_DIST_POINT
//
//  pvStructInfo points to the following CRL_ISSUING_DIST_POINT.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_ISSUING_DIST_POINT)
//
//  Error location consists of:
//    ENTRY_INDEX       - 8 bits << 16
//    VALUE_INDEX       - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
type
  PCRLIssuingDistPoint = ^TCRLIssuingDistPoint;
  _CRL_ISSUING_DIST_POINT = record
    DistPointName: TCRLDistPointName;                    // OPTIONAL
    fOnlyContainsUserCerts: BOOL;
    fOnlyContainsCACerts: BOOL;
    OnlySomeReasonFlags: TCryptBitBlob;                  // OPTIONAL
    fIndirectCRL: BOOL;
  end;
  {$EXTERNALSYM _CRL_ISSUING_DIST_POINT}
  CRL_ISSUING_DIST_POINT = _CRL_ISSUING_DIST_POINT;
  {$EXTERNALSYM CRL_ISSUING_DIST_POINT}
  TCRLIssuingDistPoint = _CRL_ISSUING_DIST_POINT;
  PCRL_ISSUING_DIST_POINT = PCRLIssuingDistPoint;
  {$EXTERNALSYM PCRL_ISSUING_DIST_POINT}

//+-------------------------------------------------------------------------
//  szOID_FRESHEST_CRL
//
//  pvStructInfo points to CRL_DIST_POINTS_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NAME_CONSTRAINTS
//  X509_NAME_CONSTRAINTS
//
//  pvStructInfo points to the following CERT_NAME_CONSTRAINTS_INFO
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_NAME_CONSTRAINTS)
//
//  Error location consists of:
//    EXCLUDED_SUBTREE_BIT  - 1 bit  << 31 (0 for permitted, 1 for excluded)
//    ENTRY_INDEX           - 8 bits << 16
//    VALUE_INDEX           - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
type
  PCertGeneralSubtree = ^TCertGeneralSubtree;
  _CERT_GENERAL_SUBTREE = record
    Base: TCertAltNameEntry;
    dwMinimum: DWORD;
    fMaximum: BOOL;
    dwMaximum: DWORD;
  end;
  {$EXTERNALSYM _CERT_GENERAL_SUBTREE}
  CERT_GENERAL_SUBTREE = _CERT_GENERAL_SUBTREE;
  {$EXTERNALSYM CERT_GENERAL_SUBTREE}
  TCertGeneralSubtree = _CERT_GENERAL_SUBTREE;
  PCERT_GENERAL_SUBTREE = PCertGeneralSubtree;
  {$EXTERNALSYM PCERT_GENERAL_SUBTREE}

type
  PCertNameConstraintsInfo = ^TCertNameConstraintsInfo;
  _CERT_NAME_CONSTRAINTS_INFO = record
    cPermittedSubtree: DWORD;
    rgPermittedSubtree: PCertGeneralSubtree;
    cExcludedSubtree: DWORD;
    rgExcludedSubtree: PCertGeneralSubtree;
  end;
  {$EXTERNALSYM _CERT_NAME_CONSTRAINTS_INFO}
  CERT_NAME_CONSTRAINTS_INFO = _CERT_NAME_CONSTRAINTS_INFO;
  {$EXTERNALSYM CERT_NAME_CONSTRAINTS_INFO}
  TCertNameConstraintsInfo = _CERT_NAME_CONSTRAINTS_INFO;
  PCERT_NAME_CONSTRAINTS_INFO = PCertNameConstraintsInfo;
  {$EXTERNALSYM PCERT_NAME_CONSTRAINTS_INFO}

const
  CERT_EXCLUDED_SUBTREE_BIT      = $80000000;
  {$EXTERNALSYM CERT_EXCLUDED_SUBTREE_BIT}

function IS_CERT_EXCLUDED_SUBTREE(X: DWORD): Boolean; inline;
{$EXTERNALSYM IS_CERT_EXCLUDED_SUBTREE}

//+-------------------------------------------------------------------------
//  szOID_NEXT_UPDATE_LOCATION
//
//  pvStructInfo points to a CERT_ALT_NAME_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_REMOVE_CERTIFICATE
//
//  pvStructInfo points to an int which can be set to one of the following
//   0 - Add certificate
//   1 - Remove certificate
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  PKCS_CTL
//  szOID_CTL
//
//  pvStructInfo points to a CTL_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  PKCS_SORTED_CTL
//
//  pvStructInfo points to a CTL_INFO.
//
//  Same as for PKCS_CTL, except, the CTL entries are sorted. The following
//  extension containing the sort information is inserted as the first
//  extension in the encoded CTL.
//
//  Only supported for Encoding. CRYPT_ENCODE_ALLOC_FLAG flag must be
//  set.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
// Sorted CTL TrustedSubjects extension
//
//  Array of little endian DWORDs:
//   [0] - Flags
//   [1] - Count of HashBucket entry offsets
//   [2] - Maximum HashBucket entry collision count
//   [3 ..] (Count + 1) HashBucket entry offsets
//
//  When this extension is present in the CTL,
//  the ASN.1 encoded sequence of TrustedSubjects are HashBucket ordered.
//
//  The entry offsets point to the start of the first encoded TrustedSubject
//  sequence for the HashBucket. The encoded TrustedSubjects for a HashBucket
//  continue until the encoded offset of the next HashBucket. A HashBucket has
//  no entries if HashBucket[N] == HashBucket[N + 1].
//
//  The HashBucket offsets are from the start of the ASN.1 encoded CTL_INFO.
//--------------------------------------------------------------------------
const
  SORTED_CTL_EXT_FLAGS_OFFSET         = (0*4);
  {$EXTERNALSYM SORTED_CTL_EXT_FLAGS_OFFSET}
  SORTED_CTL_EXT_COUNT_OFFSET         = (1*4);
  {$EXTERNALSYM SORTED_CTL_EXT_COUNT_OFFSET}
  SORTED_CTL_EXT_MAX_COLLISION_OFFSET = (2*4);
  {$EXTERNALSYM SORTED_CTL_EXT_MAX_COLLISION_OFFSET}
  SORTED_CTL_EXT_HASH_BUCKET_OFFSET   = (3*4);
  {$EXTERNALSYM SORTED_CTL_EXT_HASH_BUCKET_OFFSET}

// If the SubjectIdentifiers are a MD5 or SHA1 hash, the following flag is
// set. When set, the first 4 bytes of the SubjectIdentifier are used as
// the dwhash. Otherwise, the SubjectIdentifier bytes are hashed into dwHash.
// In either case the HashBucket index = dwHash % cHashBucket.
const
  SORTED_CTL_EXT_HASHED_SUBJECT_IDENTIFIER_FLAG      = $1;
  {$EXTERNALSYM SORTED_CTL_EXT_HASHED_SUBJECT_IDENTIFIER_FLAG}

//+-------------------------------------------------------------------------
//  X509_MULTI_BYTE_UINT
//
//  pvStructInfo points to a CRYPT_UINT_BLOB. Before encoding, inserts a
//  leading 0x00. After decoding, removes a leading 0x00.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_DSS_PUBLICKEY
//
//  pvStructInfo points to a CRYPT_UINT_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_DSS_PARAMETERS
//
//  pvStructInfo points to following CERT_DSS_PARAMETERS data structure.
//--------------------------------------------------------------------------
type
  PCertDSSParameters = ^TCertDSSParameters;
  _CERT_DSS_PARAMETERS = record
    p: TCryptUIntBlob;
    q: TCryptUIntBlob;
    g: TCryptUIntBlob;
  end;
  {$EXTERNALSYM _CERT_DSS_PARAMETERS}
  CERT_DSS_PARAMETERS = _CERT_DSS_PARAMETERS;
  {$EXTERNALSYM CERT_DSS_PARAMETERS}
  TCertDSSParameters = _CERT_DSS_PARAMETERS;
  PCERT_DSS_PARAMETERS = PCertDSSParameters;
  {$EXTERNALSYM PCERT_DSS_PARAMETERS}

//+-------------------------------------------------------------------------
//  X509_DSS_SIGNATURE
//
//  pvStructInfo is a BYTE rgbSignature[CERT_DSS_SIGNATURE_LEN]. The
//  bytes are ordered as output by the DSS CSP's CryptSignHash().
//--------------------------------------------------------------------------
const
  CERT_DSS_R_LEN         = 20;
  {$EXTERNALSYM CERT_DSS_R_LEN}
  CERT_DSS_S_LEN         = 20;
  {$EXTERNALSYM CERT_DSS_S_LEN}
  CERT_DSS_SIGNATURE_LEN = (CERT_DSS_R_LEN + CERT_DSS_S_LEN);
  {$EXTERNALSYM CERT_DSS_SIGNATURE_LEN}

// Sequence of 2 unsigned integers (the extra +1 is for a potential leading
// 0x00 to make the integer unsigned)
const
  CERT_MAX_ASN_ENCODED_DSS_SIGNATURE_LEN = (2 + 2*(2 + 20 +1));
  {$EXTERNALSYM CERT_MAX_ASN_ENCODED_DSS_SIGNATURE_LEN}

//+-------------------------------------------------------------------------
//  X509_DH_PUBLICKEY
//
//  pvStructInfo points to a CRYPT_UINT_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_DH_PARAMETERS
//
//  pvStructInfo points to following CERT_DH_PARAMETERS data structure.
//--------------------------------------------------------------------------
type
  PCertDHParameters = ^TCertDHParameters;
  _CERT_DH_PARAMETERS = record
    p: TCryptUIntBlob;
    g: TCryptUIntBlob;
  end;
  {$EXTERNALSYM _CERT_DH_PARAMETERS}
  CERT_DH_PARAMETERS = _CERT_DH_PARAMETERS;
  {$EXTERNALSYM CERT_DH_PARAMETERS}
  TCertDHParameters = _CERT_DH_PARAMETERS;
  PCERT_DH_PARAMETERS = PCertDHParameters;
  {$EXTERNALSYM PCERT_DH_PARAMETERS}

//+-------------------------------------------------------------------------
//  X509_ECC_SIGNATURE
//
//  pvStructInfo points to following CERT_ECC_SIGNATURE data structure.
//
//  Note, identical to the above except for the names of the fields. Same
//  underlying encode/decode functions are used.
//--------------------------------------------------------------------------
type
  PCertECCSignature = ^TCertECCSignature;
  _CERT_ECC_SIGNATURE = record
    r: TCryptUIntBlob;
    s: TCryptUIntBlob;
  end;
  {$EXTERNALSYM _CERT_ECC_SIGNATURE}
  CERT_ECC_SIGNATURE = _CERT_ECC_SIGNATURE;
  {$EXTERNALSYM CERT_ECC_SIGNATURE}
  TCertECCSignature = _CERT_ECC_SIGNATURE;
  PCERT_ECC_SIGNATURE = PCertECCSignature;
  {$EXTERNALSYM PCERT_ECC_SIGNATURE}

//+-------------------------------------------------------------------------
//  X942_DH_PARAMETERS
//
//  pvStructInfo points to following CERT_X942_DH_PARAMETERS data structure.
//
//  If q.cbData == 0, then, the following fields are zero'ed.
//--------------------------------------------------------------------------
type
  PCertX942DHValidationParams = ^TCertX942DHValidationParams;
  _CERT_X942_DH_VALIDATION_PARAMS = record
    seed: TCryptBitBlob;
    pgenCounter: DWORD;
  end;
  {$EXTERNALSYM _CERT_X942_DH_VALIDATION_PARAMS}
  CERT_X942_DH_VALIDATION_PARAMS = _CERT_X942_DH_VALIDATION_PARAMS;
  {$EXTERNALSYM CERT_X942_DH_VALIDATION_PARAMS}
  TCertX942DHValidationParams = _CERT_X942_DH_VALIDATION_PARAMS;
  PCERT_X942_DH_VALIDATION_PARAMS = PCertX942DHValidationParams;
  {$EXTERNALSYM PCERT_X942_DH_VALIDATION_PARAMS}

type
  PCertX942DHParameters = ^TCertX942DHParameters;
  _CERT_X942_DH_PARAMETERS = record
    p: TCryptUIntBlob;               // odd prime, p = jq + 1
    g: TCryptUIntBlob;               // generator, g
    q: TCryptUIntBlob;               // factor of p - 1, OPTIONAL
    j: TCryptUIntBlob;               // subgroup factor, OPTIONAL
    pValidationParams: PCertX942DHValidationParams;   // OPTIONAL
  end;
  {$EXTERNALSYM _CERT_X942_DH_PARAMETERS}
  CERT_X942_DH_PARAMETERS = _CERT_X942_DH_PARAMETERS;
  {$EXTERNALSYM CERT_X942_DH_PARAMETERS}
  TCertX942DHParameters = _CERT_X942_DH_PARAMETERS;
  PCERT_X942_DH_PARAMETERS = PCertX942DHParameters;
  {$EXTERNALSYM PCERT_X942_DH_PARAMETERS}

//+-------------------------------------------------------------------------
//  X942_OTHER_INFO
//
//  pvStructInfo points to following CRYPT_X942_OTHER_INFO data structure.
//
//  rgbCounter and rgbKeyLength are in Little Endian order.
//--------------------------------------------------------------------------
const
  CRYPT_X942_COUNTER_BYTE_LENGTH     = 4;
  {$EXTERNALSYM CRYPT_X942_COUNTER_BYTE_LENGTH}
  CRYPT_X942_KEY_LENGTH_BYTE_LENGTH  = 4;
  {$EXTERNALSYM CRYPT_X942_KEY_LENGTH_BYTE_LENGTH}
  CRYPT_X942_PUB_INFO_BYTE_LENGTH    = (512/8);
  {$EXTERNALSYM CRYPT_X942_PUB_INFO_BYTE_LENGTH}

type
  PCryptX942OtherInfo = ^TCryptX942OtherInfo;
  _CRYPT_X942_OTHER_INFO = record
    pszContentEncryptionObjId: LPSTR;
    rgbCounter: array [0..CRYPT_X942_COUNTER_BYTE_LENGTH - 1] of Byte;
    rgbKeyLength: array [0..CRYPT_X942_KEY_LENGTH_BYTE_LENGTH - 1] of Byte;
    PubInfo: TCryptDataBlob;         // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_X942_OTHER_INFO}
  CRYPT_X942_OTHER_INFO = _CRYPT_X942_OTHER_INFO;
  {$EXTERNALSYM CRYPT_X942_OTHER_INFO}
  TCryptX942OtherInfo = _CRYPT_X942_OTHER_INFO;
  PCRYPT_X942_OTHER_INFO = PCryptX942OtherInfo;
  {$EXTERNALSYM PCRYPT_X942_OTHER_INFO}

//+-------------------------------------------------------------------------
//  ECC_CMS_SHARED_INFO
//
//  pvStructInfo points to following ECC_CMS_SHARED_INFO data structure.
//
//  rgbSuppPubInfo is in Little Endian order.
//--------------------------------------------------------------------------
const
  CRYPT_ECC_CMS_SHARED_INFO_SUPPPUBINFO_BYTE_LENGTH  = 4;
  {$EXTERNALSYM CRYPT_ECC_CMS_SHARED_INFO_SUPPPUBINFO_BYTE_LENGTH}

type
  PCryptECCCMSSharedInfo = ^TCryptECCCMSSharedInfo;
  _CRYPT_ECC_CMS_SHARED_INFO = record
    Algorithm: TCryptAlgorithmIdentifier;
    EntityUInfo: TCryptDataBlob;                 // OPTIONAL
    rgbSuppPubInfo: array [0..CRYPT_ECC_CMS_SHARED_INFO_SUPPPUBINFO_BYTE_LENGTH  - 1] of Byte;
  end;
  {$EXTERNALSYM _CRYPT_ECC_CMS_SHARED_INFO}
  CRYPT_ECC_CMS_SHARED_INFO = _CRYPT_ECC_CMS_SHARED_INFO;
  {$EXTERNALSYM CRYPT_ECC_CMS_SHARED_INFO}
  TCryptECCCMSSharedInfo = _CRYPT_ECC_CMS_SHARED_INFO;
  PCRYPT_ECC_CMS_SHARED_INFO = PCryptECCCMSSharedInfo;
  {$EXTERNALSYM PCRYPT_ECC_CMS_SHARED_INFO}

//+-------------------------------------------------------------------------
//  PKCS_RC2_CBC_PARAMETERS
//  szOID_RSA_RC2CBC
//
//  pvStructInfo points to following CRYPT_RC2_CBC_PARAMETERS data structure.
//--------------------------------------------------------------------------
type
  PCryptRC2CBCParameters = ^TCryptRC2CBCParameters;
  _CRYPT_RC2_CBC_PARAMETERS = record
    dwVersion: DWORD;
    fIV: BOOL;                            // set if has following IV
    rgbIV: array [0..7] of Byte;
  end;
  {$EXTERNALSYM _CRYPT_RC2_CBC_PARAMETERS}
  CRYPT_RC2_CBC_PARAMETERS = _CRYPT_RC2_CBC_PARAMETERS;
  {$EXTERNALSYM CRYPT_RC2_CBC_PARAMETERS}
  TCryptRC2CBCParameters = _CRYPT_RC2_CBC_PARAMETERS;
  PCRYPT_RC2_CBC_PARAMETERS = PCryptRC2CBCParameters;
  {$EXTERNALSYM PCRYPT_RC2_CBC_PARAMETERS}

const
  CRYPT_RC2_40BIT_VERSION    = 160;
  {$EXTERNALSYM CRYPT_RC2_40BIT_VERSION}
  CRYPT_RC2_56BIT_VERSION    = 52;
  {$EXTERNALSYM CRYPT_RC2_56BIT_VERSION}
  CRYPT_RC2_64BIT_VERSION    = 120;
  {$EXTERNALSYM CRYPT_RC2_64BIT_VERSION}
  CRYPT_RC2_128BIT_VERSION   = 58;
  {$EXTERNALSYM CRYPT_RC2_128BIT_VERSION}

//+-------------------------------------------------------------------------
//  PKCS_SMIME_CAPABILITIES
//  szOID_RSA_SMIMECapabilities
//
//  pvStructInfo points to following CRYPT_SMIME_CAPABILITIES data structure.
//
//  Note, for CryptEncodeObject(X509_ASN_ENCODING), Parameters.cbData == 0
//  causes the encoded parameters to be omitted and not encoded as a NULL
//  (05 00) as is done when encoding a CRYPT_ALGORITHM_IDENTIFIER. This
//  is per the SMIME specification for encoding capabilities.
//--------------------------------------------------------------------------
// certenrolls_begin -- CRYPT_SMIME_CAPABILITY
type
  PCryptSMIMECapability = ^TCryptSMIMECapability;
  _CRYPT_SMIME_CAPABILITY = record
    pszObjId: LPSTR;
    Parameters: TCryptObjIDBlob;
  end;
  {$EXTERNALSYM _CRYPT_SMIME_CAPABILITY}
  CRYPT_SMIME_CAPABILITY = _CRYPT_SMIME_CAPABILITY;
  {$EXTERNALSYM CRYPT_SMIME_CAPABILITY}
  TCryptSMIMECapability = _CRYPT_SMIME_CAPABILITY;
  PCRYPT_SMIME_CAPABILITY = PCryptSMIMECapability;
  {$EXTERNALSYM PCRYPT_SMIME_CAPABILITY}

type
  PCryptSMIMECapabilities = ^TCryptSMIMECapabilities;
  _CRYPT_SMIME_CAPABILITIES = record
    cCapability: DWORD;
    rgCapability: PCryptSMIMECapability;
  end;
  {$EXTERNALSYM _CRYPT_SMIME_CAPABILITIES}
  CRYPT_SMIME_CAPABILITIES = _CRYPT_SMIME_CAPABILITIES;
  {$EXTERNALSYM CRYPT_SMIME_CAPABILITIES}
  TCryptSMIMECapabilities = _CRYPT_SMIME_CAPABILITIES;
  PCRYPT_SMIME_CAPABILITIES = PCryptSMIMECapabilities;
  {$EXTERNALSYM PCRYPT_SMIME_CAPABILITIES}
// certenrolls_end


//+-------------------------------------------------------------------------
//  Qualified Certificate Statements Extension Data Structures
//
//  X509_QC_STATEMENTS_EXT
//  szOID_QC_STATEMENTS_EXT
//
//  pvStructInfo points to following CERT_QC_STATEMENTS_EXT_INFO
//  data structure.
//
//  Note, identical to the above except for the names of the fields. Same
//  underlying encode/decode functions are used.
//--------------------------------------------------------------------------
type
  PCertQCStatement = ^TCertQCStatement;
  _CERT_QC_STATEMENT = record
    pszStatementId: LPSTR;                    // pszObjId
    StatementInfo: TCryptObjIDBlob;           // OPTIONAL
  end;
  {$EXTERNALSYM _CERT_QC_STATEMENT}
  CERT_QC_STATEMENT = _CERT_QC_STATEMENT;
  {$EXTERNALSYM CERT_QC_STATEMENT}
  TCertQCStatement = _CERT_QC_STATEMENT;
  PCERT_QC_STATEMENT = PCertQCStatement;
  {$EXTERNALSYM PCERT_QC_STATEMENT}

type
  PCertQCStatementsExtInfo = ^TCertQCStatementsExtInfo;
  _CERT_QC_STATEMENTS_EXT_INFO = record
    cStatement: DWORD;
    rgStatement: PCertQCStatement;
  end;
  {$EXTERNALSYM _CERT_QC_STATEMENTS_EXT_INFO}
  CERT_QC_STATEMENTS_EXT_INFO = _CERT_QC_STATEMENTS_EXT_INFO;
  {$EXTERNALSYM CERT_QC_STATEMENTS_EXT_INFO}
  TCertQCStatementsExtInfo = _CERT_QC_STATEMENTS_EXT_INFO;
  PCERT_QC_STATEMENTS_EXT_INFO = PCertQCStatementsExtInfo;
  {$EXTERNALSYM PCERT_QC_STATEMENTS_EXT_INFO}

// QC Statment Ids

// European Union
const
  szOID_QC_EU_COMPLIANCE         = '0.4.0.1862.1.1';
  {$EXTERNALSYM szOID_QC_EU_COMPLIANCE}
// Secure Signature Creation Device
const
  szOID_QC_SSCD                  = '0.4.0.1862.1.4';
  {$EXTERNALSYM szOID_QC_SSCD}

//+-------------------------------------------------------------------------
//  X509_OBJECT_IDENTIFIER
//  szOID_ECC_PUBLIC_KEY
//
//  pvStructInfo points to a LPSTR of the dot representation.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  X509_ALGORITHM_IDENTIFIER
//  szOID_ECDSA_SPECIFIED
//
//  pvStructInfo points to a CRYPT_ALGORITHM_IDENTIFIER.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  PKCS_RSA_SSA_PSS_PARAMETERS
//  szOID_RSA_SSA_PSS
//
//  pvStructInfo points to the following CRYPT_RSA_SSA_PSS_PARAMETERS
//  data structure.
//
//  For encoding uses the following defaults if the corresponding field
//  is set to NULL or 0:
//      HashAlgorithm.pszObjId : szOID_OIWSEC_sha1
//      MaskGenAlgorithm.pszObjId : szOID_RSA_MGF1
//      MaskGenAlgorithm.HashAlgorithm.pszObjId : HashAlgorithm.pszObjId
//      dwSaltLength: cbHash
//      dwTrailerField : PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC
//
//  Normally for encoding, only the HashAlgorithm.pszObjId field will
//  need to be set.
//
//  For decoding, all of fields are explicitly set.
//--------------------------------------------------------------------------
type
  PCryptMaskGenAlgorithm = ^TCryptMaskGenAlgorithm;
  _CRYPT_MASK_GEN_ALGORITHM = record
    pszObjId: LPSTR;
    HashAlgorithm: TCryptAlgorithmIdentifier;
  end;
  {$EXTERNALSYM _CRYPT_MASK_GEN_ALGORITHM}
  CRYPT_MASK_GEN_ALGORITHM = _CRYPT_MASK_GEN_ALGORITHM;
  {$EXTERNALSYM CRYPT_MASK_GEN_ALGORITHM}
  TCryptMaskGenAlgorithm = _CRYPT_MASK_GEN_ALGORITHM;
  PCRYPT_MASK_GEN_ALGORITHM = PCryptMaskGenAlgorithm;
  {$EXTERNALSYM PCRYPT_MASK_GEN_ALGORITHM}

type
  PCryptRSASSAPSSParameters = ^TCryptRSASSAPSSParameters;
  _CRYPT_RSA_SSA_PSS_PARAMETERS = record
    HashAlgorithm: TCryptAlgorithmIdentifier;
    MaskGenAlgorithm: TCryptMaskGenAlgorithm;
    dwSaltLength: DWORD;
    dwTrailerField: DWORD;
  end;
  {$EXTERNALSYM _CRYPT_RSA_SSA_PSS_PARAMETERS}
  CRYPT_RSA_SSA_PSS_PARAMETERS = _CRYPT_RSA_SSA_PSS_PARAMETERS;
  {$EXTERNALSYM CRYPT_RSA_SSA_PSS_PARAMETERS}
  TCryptRSASSAPSSParameters = _CRYPT_RSA_SSA_PSS_PARAMETERS;
  PCRYPT_RSA_SSA_PSS_PARAMETERS = PCryptRSASSAPSSParameters;
  {$EXTERNALSYM PCRYPT_RSA_SSA_PSS_PARAMETERS}

const
  PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC      = 1;
  {$EXTERNALSYM PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC}

//+-------------------------------------------------------------------------
//  PKCS_RSAES_OAEP_PARAMETERS
//  szOID_RSAES_OAEP
//
//  pvStructInfo points to the following CRYPT_RSAES_OAEP_PARAMETERS
//  data structure.
//
//  For encoding uses the following defaults if the corresponding field
//  is set to NULL or 0:
//      HashAlgorithm.pszObjId : szOID_OIWSEC_sha1
//      MaskGenAlgorithm.pszObjId : szOID_RSA_MGF1
//      MaskGenAlgorithm.HashAlgorithm.pszObjId : HashAlgorithm.pszObjId
//      PSourceAlgorithm.pszObjId : szOID_RSA_PSPECIFIED
//      PSourceAlgorithm.EncodingParameters.cbData : 0
//      PSourceAlgorithm.EncodingParameters.pbData : NULL
//
//  Normally for encoding, only the HashAlgorithm.pszObjId field will
//  need to be set.
//
//  For decoding, all of fields are explicitly set.
//--------------------------------------------------------------------------
type
  PCryptPSourceAlgorithm = ^TCryptPSourceAlgorithm;
  _CRYPT_PSOURCE_ALGORITHM = record
    pszObjId: LPSTR;
    EncodingParameters: TCryptDataBlob;
  end;
  {$EXTERNALSYM _CRYPT_PSOURCE_ALGORITHM}
  CRYPT_PSOURCE_ALGORITHM = _CRYPT_PSOURCE_ALGORITHM;
  {$EXTERNALSYM CRYPT_PSOURCE_ALGORITHM}
  TCryptPSourceAlgorithm = _CRYPT_PSOURCE_ALGORITHM;
  PCRYPT_PSOURCE_ALGORITHM = PCryptPSourceAlgorithm;
  {$EXTERNALSYM PCRYPT_PSOURCE_ALGORITHM}

type
  PCryptRSAESOAEPParameters = ^TCryptRSAESOAEPParameters;
  _CRYPT_RSAES_OAEP_PARAMETERS = record
    HashAlgorithm: TCryptAlgorithmIdentifier;
    MaskGenAlgorithm: TCryptMaskGenAlgorithm;
    PSourceAlgorithm: TCryptPSourceAlgorithm;
  end;
  {$EXTERNALSYM _CRYPT_RSAES_OAEP_PARAMETERS}
  CRYPT_RSAES_OAEP_PARAMETERS = _CRYPT_RSAES_OAEP_PARAMETERS;
  {$EXTERNALSYM CRYPT_RSAES_OAEP_PARAMETERS}
  TCryptRSAESOAEPParameters = _CRYPT_RSAES_OAEP_PARAMETERS;
  PCRYPT_RSAES_OAEP_PARAMETERS = PCryptRSAESOAEPParameters;
  {$EXTERNALSYM PCRYPT_RSAES_OAEP_PARAMETERS}

//+-------------------------------------------------------------------------
//  PKCS7_SIGNER_INFO
//
//  pvStructInfo points to CMSG_SIGNER_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMS_SIGNER_INFO
//
//  pvStructInfo points to CMSG_CMS_SIGNER_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  Verisign Certificate Extension Object Identifiers
//--------------------------------------------------------------------------

// Octet String containing Boolean
const
  szOID_VERISIGN_PRIVATE_6_9       = '2.16.840.1.113733.1.6.9';
  {$EXTERNALSYM szOID_VERISIGN_PRIVATE_6_9}

// Octet String containing IA5 string: lower case 32 char hex string
const
  szOID_VERISIGN_ONSITE_JURISDICTION_HASH = '2.16.840.1.113733.1.6.11';
  {$EXTERNALSYM szOID_VERISIGN_ONSITE_JURISDICTION_HASH}

// Octet String containing Bit string
const
  szOID_VERISIGN_BITSTRING_6_13    = '2.16.840.1.113733.1.6.13';
  {$EXTERNALSYM szOID_VERISIGN_BITSTRING_6_13}

// EKU
const
  szOID_VERISIGN_ISS_STRONG_CRYPTO = '2.16.840.1.113733.1.8.1';
  {$EXTERNALSYM szOID_VERISIGN_ISS_STRONG_CRYPTO}


//+-------------------------------------------------------------------------
//  Netscape Certificate Extension Object Identifiers
//--------------------------------------------------------------------------
const
  szOID_NETSCAPE                   = '2.16.840.1.113730';
  {$EXTERNALSYM szOID_NETSCAPE}
  szOID_NETSCAPE_CERT_EXTENSION    = '2.16.840.1.113730.1';
  {$EXTERNALSYM szOID_NETSCAPE_CERT_EXTENSION}
  szOID_NETSCAPE_CERT_TYPE         = '2.16.840.1.113730.1.1';
  {$EXTERNALSYM szOID_NETSCAPE_CERT_TYPE}
  szOID_NETSCAPE_BASE_URL          = '2.16.840.1.113730.1.2';
  {$EXTERNALSYM szOID_NETSCAPE_BASE_URL}
  szOID_NETSCAPE_REVOCATION_URL    = '2.16.840.1.113730.1.3';
  {$EXTERNALSYM szOID_NETSCAPE_REVOCATION_URL}
  szOID_NETSCAPE_CA_REVOCATION_URL = '2.16.840.1.113730.1.4';
  {$EXTERNALSYM szOID_NETSCAPE_CA_REVOCATION_URL}
  szOID_NETSCAPE_CERT_RENEWAL_URL  = '2.16.840.1.113730.1.7';
  {$EXTERNALSYM szOID_NETSCAPE_CERT_RENEWAL_URL}
  szOID_NETSCAPE_CA_POLICY_URL     = '2.16.840.1.113730.1.8';
  {$EXTERNALSYM szOID_NETSCAPE_CA_POLICY_URL}
  szOID_NETSCAPE_SSL_SERVER_NAME   = '2.16.840.1.113730.1.12';
  {$EXTERNALSYM szOID_NETSCAPE_SSL_SERVER_NAME}
  szOID_NETSCAPE_COMMENT           = '2.16.840.1.113730.1.13';
  {$EXTERNALSYM szOID_NETSCAPE_COMMENT}

//+-------------------------------------------------------------------------
//  Netscape Certificate Data Type Object Identifiers
//--------------------------------------------------------------------------
const
  szOID_NETSCAPE_DATA_TYPE         = '2.16.840.1.113730.2';
  {$EXTERNALSYM szOID_NETSCAPE_DATA_TYPE}
  szOID_NETSCAPE_CERT_SEQUENCE     = '2.16.840.1.113730.2.5';
  {$EXTERNALSYM szOID_NETSCAPE_CERT_SEQUENCE}


//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_CERT_TYPE extension
//
//  Its value is a bit string. CryptDecodeObject/CryptEncodeObject using
//  X509_BITS or X509_BITS_WITHOUT_TRAILING_ZEROES.
//
//  The following bits are defined:
//--------------------------------------------------------------------------
const
  NETSCAPE_SSL_CLIENT_AUTH_CERT_TYPE = $80;
  {$EXTERNALSYM NETSCAPE_SSL_CLIENT_AUTH_CERT_TYPE}
  NETSCAPE_SSL_SERVER_AUTH_CERT_TYPE = $40;
  {$EXTERNALSYM NETSCAPE_SSL_SERVER_AUTH_CERT_TYPE}
  NETSCAPE_SMIME_CERT_TYPE           = $20;
  {$EXTERNALSYM NETSCAPE_SMIME_CERT_TYPE}
  NETSCAPE_SIGN_CERT_TYPE            = $10;
  {$EXTERNALSYM NETSCAPE_SIGN_CERT_TYPE}
  NETSCAPE_SSL_CA_CERT_TYPE          = $04;
  {$EXTERNALSYM NETSCAPE_SSL_CA_CERT_TYPE}
  NETSCAPE_SMIME_CA_CERT_TYPE        = $02;
  {$EXTERNALSYM NETSCAPE_SMIME_CA_CERT_TYPE}
  NETSCAPE_SIGN_CA_CERT_TYPE         = $01;
  {$EXTERNALSYM NETSCAPE_SIGN_CA_CERT_TYPE}

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_BASE_URL extension
//
//  Its value is an IA5_STRING. CryptDecodeObject/CryptEncodeObject using
//  X509_ANY_STRING or X509_UNICODE_ANY_STRING, where,
//  dwValueType = CERT_RDN_IA5_STRING.
//
//  When present this string is added to the beginning of all relative URLs
//  in the certificate.  This extension can be considered an optimization
//  to reduce the size of the URL extensions.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_REVOCATION_URL extension
//
//  Its value is an IA5_STRING. CryptDecodeObject/CryptEncodeObject using
//  X509_ANY_STRING or X509_UNICODE_ANY_STRING, where,
//  dwValueType = CERT_RDN_IA5_STRING.
//
//  It is a relative or absolute URL that can be used to check the
//  revocation status of a certificate. The revocation check will be
//  performed as an HTTP GET method using a url that is the concatenation of
//  revocation-url and certificate-serial-number.
//  Where the certificate-serial-number is encoded as a string of
//  ascii hexadecimal digits. For example, if the netscape-base-url is
//  https://www.certs-r-us.com/, the netscape-revocation-url is
//  cgi-bin/check-rev.cgi?, and the certificate serial number is 173420,
//  the resulting URL would be:
//  https://www.certs-r-us.com/cgi-bin/check-rev.cgi?02a56c
//
//  The server should return a document with a Content-Type of
//  application/x-netscape-revocation.  The document should contain
//  a single ascii digit, '1' if the certificate is not curently valid,
//  and '0' if it is curently valid.
//
//  Note: for all of the URLs that include the certificate serial number,
//  the serial number will be encoded as a string which consists of an even
//  number of hexadecimal digits.  If the number of significant digits is odd,
//  the string will have a single leading zero to ensure an even number of
//  digits is generated.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_CA_REVOCATION_URL extension
//
//  Its value is an IA5_STRING. CryptDecodeObject/CryptEncodeObject using
//  X509_ANY_STRING or X509_UNICODE_ANY_STRING, where,
//  dwValueType = CERT_RDN_IA5_STRING.
//
//  It is a relative or absolute URL that can be used to check the
//  revocation status of any certificates that are signed by the CA that
//  this certificate belongs to. This extension is only valid in CA
//  certificates.  The use of this extension is the same as the above
//  szOID_NETSCAPE_REVOCATION_URL extension.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_CERT_RENEWAL_URL extension
//
//  Its value is an IA5_STRING. CryptDecodeObject/CryptEncodeObject using
//  X509_ANY_STRING or X509_UNICODE_ANY_STRING, where,
//  dwValueType = CERT_RDN_IA5_STRING.
//
//  It is a relative or absolute URL that points to a certificate renewal
//  form. The renewal form will be accessed with an HTTP GET method using a
//  url that is the concatenation of renewal-url and
//  certificate-serial-number. Where the certificate-serial-number is
//  encoded as a string of ascii hexadecimal digits. For example, if the
//  netscape-base-url is https://www.certs-r-us.com/, the
//  netscape-cert-renewal-url is cgi-bin/check-renew.cgi?, and the
//  certificate serial number is 173420, the resulting URL would be:
//  https://www.certs-r-us.com/cgi-bin/check-renew.cgi?02a56c
//  The document returned should be an HTML form that will allow the user
//  to request a renewal of their certificate.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_CA_POLICY_URL extension
//
//  Its value is an IA5_STRING. CryptDecodeObject/CryptEncodeObject using
//  X509_ANY_STRING or X509_UNICODE_ANY_STRING, where,
//  dwValueType = CERT_RDN_IA5_STRING.
//
//  It is a relative or absolute URL that points to a web page that
//  describes the policies under which the certificate was issued.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_SSL_SERVER_NAME extension
//
//  Its value is an IA5_STRING. CryptDecodeObject/CryptEncodeObject using
//  X509_ANY_STRING or X509_UNICODE_ANY_STRING, where,
//  dwValueType = CERT_RDN_IA5_STRING.
//
//  It is a "shell expression" that can be used to match the hostname of the
//  SSL server that is using this certificate.  It is recommended that if
//  the server's hostname does not match this pattern the user be notified
//  and given the option to terminate the SSL connection.  If this extension
//  is not present then the CommonName in the certificate subject's
//  distinguished name is used for the same purpose.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_COMMENT extension
//
//  Its value is an IA5_STRING. CryptDecodeObject/CryptEncodeObject using
//  X509_ANY_STRING or X509_UNICODE_ANY_STRING, where,
//  dwValueType = CERT_RDN_IA5_STRING.
//
//  It is a comment that may be displayed to the user when the certificate
//  is viewed.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  szOID_NETSCAPE_CERT_SEQUENCE
//
//  Its value is a PKCS#7 ContentInfo structure wrapping a sequence of
//  certificates. The value of the contentType field is
//  szOID_NETSCAPE_CERT_SEQUENCE, while the content field is the following
//  structure:
//      CertificateSequence ::= SEQUENCE OF Certificate.
//
//  CryptDecodeObject/CryptEncodeObject using
//  PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, where,
//  pszObjId = szOID_NETSCAPE_CERT_SEQUENCE and the CRYPT_DER_BLOBs point
//  to encoded X509 certificates.
//--------------------------------------------------------------------------

//+=========================================================================
//  Certificate Management Messages over CMS (CMC) Data Structures
//==========================================================================

// Content Type (request)
const
  szOID_CT_PKI_DATA              = '1.3.6.1.5.5.7.12.2';
  {$EXTERNALSYM szOID_CT_PKI_DATA}

// Content Type (response)
const
  szOID_CT_PKI_RESPONSE          = '1.3.6.1.5.5.7.12.3';
  {$EXTERNALSYM szOID_CT_PKI_RESPONSE}

// Signature value that only contains the hash octets. The parameters for
// this algorithm must be present and must be encoded as NULL.
const
  szOID_PKIX_NO_SIGNATURE        = '1.3.6.1.5.5.7.6.2';
  {$EXTERNALSYM szOID_PKIX_NO_SIGNATURE}

  szOID_CMC                      = '1.3.6.1.5.5.7.7';
  {$EXTERNALSYM szOID_CMC}
  szOID_CMC_STATUS_INFO          = '1.3.6.1.5.5.7.7.1';
  {$EXTERNALSYM szOID_CMC_STATUS_INFO}
  szOID_CMC_IDENTIFICATION       = '1.3.6.1.5.5.7.7.2';
  {$EXTERNALSYM szOID_CMC_IDENTIFICATION}
  szOID_CMC_IDENTITY_PROOF       = '1.3.6.1.5.5.7.7.3';
  {$EXTERNALSYM szOID_CMC_IDENTITY_PROOF}
  szOID_CMC_DATA_RETURN          = '1.3.6.1.5.5.7.7.4';
  {$EXTERNALSYM szOID_CMC_DATA_RETURN}

// Transaction Id (integer)
const
  szOID_CMC_TRANSACTION_ID       = '1.3.6.1.5.5.7.7.5';
  {$EXTERNALSYM szOID_CMC_TRANSACTION_ID}

// Sender Nonce (octet string)
const
  szOID_CMC_SENDER_NONCE         = '1.3.6.1.5.5.7.7.6';
  {$EXTERNALSYM szOID_CMC_SENDER_NONCE}

// Recipient Nonce (octet string)
const
  szOID_CMC_RECIPIENT_NONCE      = '1.3.6.1.5.5.7.7.7';
  {$EXTERNALSYM szOID_CMC_RECIPIENT_NONCE}

  szOID_CMC_ADD_EXTENSIONS       = '1.3.6.1.5.5.7.7.8';
  {$EXTERNALSYM szOID_CMC_ADD_EXTENSIONS}
  szOID_CMC_ENCRYPTED_POP        = '1.3.6.1.5.5.7.7.9';
  {$EXTERNALSYM szOID_CMC_ENCRYPTED_POP}
  szOID_CMC_DECRYPTED_POP        = '1.3.6.1.5.5.7.7.10';
  {$EXTERNALSYM szOID_CMC_DECRYPTED_POP}
  szOID_CMC_LRA_POP_WITNESS      = '1.3.6.1.5.5.7.7.11';
  {$EXTERNALSYM szOID_CMC_LRA_POP_WITNESS}

// Issuer Name + Serial
const
  szOID_CMC_GET_CERT             = '1.3.6.1.5.5.7.7.15';
  {$EXTERNALSYM szOID_CMC_GET_CERT}

// Issuer Name [+ CRL Name] + Time [+ Reasons]
const
  szOID_CMC_GET_CRL              = '1.3.6.1.5.5.7.7.16';
  {$EXTERNALSYM szOID_CMC_GET_CRL}

// Issuer Name + Serial [+ Reason] [+ Effective Time] [+ Secret] [+ Comment]
const
  szOID_CMC_REVOKE_REQUEST       = '1.3.6.1.5.5.7.7.17';
  {$EXTERNALSYM szOID_CMC_REVOKE_REQUEST}

// (octet string) URL-style parameter list (IA5?)
const
  szOID_CMC_REG_INFO             = '1.3.6.1.5.5.7.7.18';
  {$EXTERNALSYM szOID_CMC_REG_INFO}

  szOID_CMC_RESPONSE_INFO        = '1.3.6.1.5.5.7.7.19';
  {$EXTERNALSYM szOID_CMC_RESPONSE_INFO}

// (octet string)
const
  szOID_CMC_QUERY_PENDING        = '1.3.6.1.5.5.7.7.21';
  {$EXTERNALSYM szOID_CMC_QUERY_PENDING}
  szOID_CMC_ID_POP_LINK_RANDOM   = '1.3.6.1.5.5.7.7.22';
  {$EXTERNALSYM szOID_CMC_ID_POP_LINK_RANDOM}
  szOID_CMC_ID_POP_LINK_WITNESS  = '1.3.6.1.5.5.7.7.23';
  {$EXTERNALSYM szOID_CMC_ID_POP_LINK_WITNESS}

// optional Name + Integer
const
  szOID_CMC_ID_CONFIRM_CERT_ACCEPTANCE = '1.3.6.1.5.5.7.7.24';
  {$EXTERNALSYM szOID_CMC_ID_CONFIRM_CERT_ACCEPTANCE}

  szOID_CMC_ADD_ATTRIBUTES       = '1.3.6.1.4.1.311.10.10.1';
  {$EXTERNALSYM szOID_CMC_ADD_ATTRIBUTES}

//+-------------------------------------------------------------------------
//  CMC_DATA
//  CMC_RESPONSE
//
//  Certificate Management Messages over CMS (CMC) PKIData and Response
//  messages.
//
//  For CMC_DATA, pvStructInfo points to a CMC_DATA_INFO.
//  CMC_DATA_INFO contains optional arrays of tagged attributes, requests,
//  content info and/or arbitrary other messages.
//
//  For CMC_RESPONSE, pvStructInfo points to a CMC_RESPONSE_INFO.
//  CMC_RESPONSE_INFO is the same as CMC_DATA_INFO without the tagged
//  requests.
//--------------------------------------------------------------------------
type
  PCMCTaggedAttribute = ^TCMCTaggedAttribute;
  _CMC_TAGGED_ATTRIBUTE = record
    dwBodyPartID: DWORD;
    Attribute: TCryptAttribute;
  end;
  {$EXTERNALSYM _CMC_TAGGED_ATTRIBUTE}
  CMC_TAGGED_ATTRIBUTE = _CMC_TAGGED_ATTRIBUTE;
  {$EXTERNALSYM CMC_TAGGED_ATTRIBUTE}
  TCMCTaggedAttribute = _CMC_TAGGED_ATTRIBUTE;
  PCMC_TAGGED_ATTRIBUTE = PCMCTaggedAttribute;
  {$EXTERNALSYM PCMC_TAGGED_ATTRIBUTE}

type
  PCMCTaggedCertRequest = ^TCMCTaggedCertRequest;
  _CMC_TAGGED_CERT_REQUEST = record
    dwBodyPartID: DWORD;
    SignedCertRequest: TCryptDERBlob;
  end;
  {$EXTERNALSYM _CMC_TAGGED_CERT_REQUEST}
  CMC_TAGGED_CERT_REQUEST = _CMC_TAGGED_CERT_REQUEST;
  {$EXTERNALSYM CMC_TAGGED_CERT_REQUEST}
  TCMCTaggedCertRequest = _CMC_TAGGED_CERT_REQUEST;
  PCMC_TAGGED_CERT_REQUEST = PCMCTaggedCertRequest;
  {$EXTERNALSYM PCMC_TAGGED_CERT_REQUEST}

const
  CMC_TAGGED_CERT_REQUEST_CHOICE     = 1;
  {$EXTERNALSYM CMC_TAGGED_CERT_REQUEST_CHOICE}

type
  PCMCTaggedRequest = ^TCMCTaggedRequest;
  _CMC_TAGGED_REQUEST = record
    case dwTaggedRequestChoice: DWORD of
    CMC_TAGGED_CERT_REQUEST_CHOICE:
      (pTaggedCertRequest: PCMCTaggedCertRequest);
  end;
  {$EXTERNALSYM _CMC_TAGGED_REQUEST}
  CMC_TAGGED_REQUEST = _CMC_TAGGED_REQUEST;
  {$EXTERNALSYM CMC_TAGGED_REQUEST}
  TCMCTaggedRequest = _CMC_TAGGED_REQUEST;
  PCMC_TAGGED_REQUEST = PCMCTaggedRequest;
  {$EXTERNALSYM PCMC_TAGGED_REQUEST}

type
  PCMCTaggedContentInfo = ^TCMCTaggedContentInfo;
  _CMC_TAGGED_CONTENT_INFO = record
    dwBodyPartID: DWORD;
    EncodedContentInfo: TCryptDERBlob;
  end;
  {$EXTERNALSYM _CMC_TAGGED_CONTENT_INFO}
  CMC_TAGGED_CONTENT_INFO = _CMC_TAGGED_CONTENT_INFO;
  {$EXTERNALSYM CMC_TAGGED_CONTENT_INFO}
  TCMCTaggedContentInfo = _CMC_TAGGED_CONTENT_INFO;
  PCMC_TAGGED_CONTENT_INFO = PCMCTaggedContentInfo;
  {$EXTERNALSYM PCMC_TAGGED_CONTENT_INFO}

type
  PCMCTaggedOtherMsg = ^TCMCTaggedOtherMsg;
  _CMC_TAGGED_OTHER_MSG = record
    dwBodyPartID: DWORD;
    pszObjId: LPSTR;
    Value: TCryptObjIDBlob;
  end;
  CMC_TAGGED_OTHER_MSG = _CMC_TAGGED_OTHER_MSG;
  TCMCTaggedOtherMsg = _CMC_TAGGED_OTHER_MSG;
  PCMC_TAGGED_OTHER_MSG = PCMCTaggedOtherMsg;

// All the tagged arrays are optional
type
  PCMCDataInfo = ^TCMCDataInfo;
  _CMC_DATA_INFO = record
    cTaggedAttribute: DWORD;
    rgTaggedAttribute: PCMCTaggedAttribute;
    cTaggedRequest: DWORD;
    rgTaggedRequest: PCMCTaggedRequest;
    cTaggedContentInfo: DWORD;
    rgTaggedContentInfo: PCMCTaggedContentInfo;
    cTaggedOtherMsg: DWORD;
    rgTaggedOtherMsg: PCMCTaggedOtherMsg;
  end;
  {$EXTERNALSYM _CMC_DATA_INFO}
  CMC_DATA_INFO = _CMC_DATA_INFO;
  {$EXTERNALSYM CMC_DATA_INFO}
  TCMCDataInfo = _CMC_DATA_INFO;
  PCMC_DATA_INFO = PCMCDataInfo;
  {$EXTERNALSYM PCMC_DATA_INFO}

// All the tagged arrays are optional
type
  PCMCResponseInfo = ^TCMCResponseInfo;
  _CMC_RESPONSE_INFO = record
    cTaggedAttribute: DWORD;
    rgTaggedAttribute: PCMCTaggedAttribute;
    cTaggedContentInfo: DWORD;
    rgTaggedContentInfo: PCMCTaggedContentInfo;
    cTaggedOtherMsg: DWORD;
    rgTaggedOtherMsg: PCMCTaggedOtherMsg;
  end;
  {$EXTERNALSYM _CMC_RESPONSE_INFO}
  CMC_RESPONSE_INFO = _CMC_RESPONSE_INFO;
  {$EXTERNALSYM CMC_RESPONSE_INFO}
  TCMCResponseInfo = _CMC_RESPONSE_INFO;
  PCMC_RESPONSE_INFO = PCMCResponseInfo;
  {$EXTERNALSYM PCMC_RESPONSE_INFO}

//+-------------------------------------------------------------------------
//  CMC_STATUS
//
//  Certificate Management Messages over CMS (CMC) Status.
//
//  pvStructInfo points to a CMC_STATUS_INFO.
//--------------------------------------------------------------------------
type
  PCMCPendInfo = ^TCMCPendInfo;
  _CMC_PEND_INFO = record
    PendToken: TCryptDataBlob;
    PendTime: TFileTime;
  end;
  {$EXTERNALSYM _CMC_PEND_INFO}
  CMC_PEND_INFO = _CMC_PEND_INFO;
  {$EXTERNALSYM CMC_PEND_INFO}
  TCMCPendInfo = _CMC_PEND_INFO;
  PCMC_PEND_INFO = PCMCPendInfo;
  {$EXTERNALSYM PCMC_PEND_INFO}

const
  CMC_OTHER_INFO_NO_CHOICE       = 0;
  {$EXTERNALSYM CMC_OTHER_INFO_NO_CHOICE}
  CMC_OTHER_INFO_FAIL_CHOICE     = 1;
  {$EXTERNALSYM CMC_OTHER_INFO_FAIL_CHOICE}
  CMC_OTHER_INFO_PEND_CHOICE     = 2;
  {$EXTERNALSYM CMC_OTHER_INFO_PEND_CHOICE}

type
  PCMCStatusInfo = ^TCMCStatusInfo;
  _CMC_STATUS_INFO = record
    dwStatus: DWORD;
    cBodyList: DWORD;
    rgdwBodyList: PDWORD;
    pwszStatusString: LPWSTR;   // OPTIONAL
    case dwOtherInfoChoice: DWORD of
    CMC_OTHER_INFO_NO_CHOICE:
      (); //  none
    CMC_OTHER_INFO_FAIL_CHOICE:
      (dwFailInfo: DWORD);
    CMC_OTHER_INFO_PEND_CHOICE:
      (pPendInfo: PCMCPendInfo);
  end;
  {$EXTERNALSYM _CMC_STATUS_INFO}
  CMC_STATUS_INFO = _CMC_STATUS_INFO;
  {$EXTERNALSYM CMC_STATUS_INFO}
  TCMCStatusInfo = _CMC_STATUS_INFO;
  PCMC_STATUS_INFO = PCMCStatusInfo;
  {$EXTERNALSYM PCMC_STATUS_INFO}

//
// dwStatus values
//

// Request was granted
const
  CMC_STATUS_SUCCESS          = 0;
  {$EXTERNALSYM CMC_STATUS_SUCCESS}

// Request failed, more information elsewhere in the message
const
  CMC_STATUS_FAILED           = 2;
  {$EXTERNALSYM CMC_STATUS_FAILED}

// The request body part has not yet been processed. Requester is responsible
// to poll back. May only be returned for certificate request operations.
const
  CMC_STATUS_PENDING          = 3;
  {$EXTERNALSYM CMC_STATUS_PENDING}

// The requested operation is not supported
const
  CMC_STATUS_NO_SUPPORT       = 4;
  {$EXTERNALSYM CMC_STATUS_NO_SUPPORT}

// Confirmation using the idConfirmCertAcceptance control is required
// before use of certificate
const
  CMC_STATUS_CONFIRM_REQUIRED = 5;
  {$EXTERNALSYM CMC_STATUS_CONFIRM_REQUIRED}

//
// dwFailInfo values
//

// Unrecognized or unsupported algorithm
const
  CMC_FAIL_BAD_ALG            = 0;
  {$EXTERNALSYM CMC_FAIL_BAD_ALG}

// Integrity check failed
const
  CMC_FAIL_BAD_MESSAGE_CHECK  = 1;
  {$EXTERNALSYM CMC_FAIL_BAD_MESSAGE_CHECK}

// Transaction not permitted or supported
const
  CMC_FAIL_BAD_REQUEST        = 2;
  {$EXTERNALSYM CMC_FAIL_BAD_REQUEST}

// Message time field was not sufficiently close to the system time
const
  CMC_FAIL_BAD_TIME           = 3;
  {$EXTERNALSYM CMC_FAIL_BAD_TIME}

// No certificate could be identified matching the provided criteria
const
  CMC_FAIL_BAD_CERT_ID        = 4;
  {$EXTERNALSYM CMC_FAIL_BAD_CERT_ID}

// A requested X.509 extension is not supported by the recipient CA.
const
  CMC_FAIL_UNSUPORTED_EXT     = 5;
  {$EXTERNALSYM CMC_FAIL_UNSUPORTED_EXT}

// Private key material must be supplied
const
  CMC_FAIL_MUST_ARCHIVE_KEYS  = 6;
  {$EXTERNALSYM CMC_FAIL_MUST_ARCHIVE_KEYS}

// Identification Attribute failed to verify
const
  CMC_FAIL_BAD_IDENTITY       = 7;
  {$EXTERNALSYM CMC_FAIL_BAD_IDENTITY}

// Server requires a POP proof before issuing certificate
const
  CMC_FAIL_POP_REQUIRED       = 8;
  {$EXTERNALSYM CMC_FAIL_POP_REQUIRED}

// POP processing failed
const
  CMC_FAIL_POP_FAILED         = 9;
  {$EXTERNALSYM CMC_FAIL_POP_FAILED}

// Server policy does not allow key re-use
const
  CMC_FAIL_NO_KEY_REUSE       = 10;
  {$EXTERNALSYM CMC_FAIL_NO_KEY_REUSE}

  CMC_FAIL_INTERNAL_CA_ERROR  = 11;
  {$EXTERNALSYM CMC_FAIL_INTERNAL_CA_ERROR}

  CMC_FAIL_TRY_LATER          = 12;
  {$EXTERNALSYM CMC_FAIL_TRY_LATER}


//+-------------------------------------------------------------------------
//  CMC_ADD_EXTENSIONS
//
//  Certificate Management Messages over CMS (CMC) Add Extensions control
//  attribute.
//
//  pvStructInfo points to a CMC_ADD_EXTENSIONS_INFO.
//--------------------------------------------------------------------------
type
  PCMCAddExtensionsInfo = ^TCMCAddExtensionsInfo;
  _CMC_ADD_EXTENSIONS_INFO = record
    dwCmcDataReference: DWORD;
    cCertReference: DWORD;
    rgdwCertReference: PDWORD;
    cExtension: DWORD;
    rgExtension: PCertExtension;
  end;
  {$EXTERNALSYM _CMC_ADD_EXTENSIONS_INFO}
  CMC_ADD_EXTENSIONS_INFO = _CMC_ADD_EXTENSIONS_INFO;
  {$EXTERNALSYM CMC_ADD_EXTENSIONS_INFO}
  TCMCAddExtensionsInfo = _CMC_ADD_EXTENSIONS_INFO;
  PCMC_ADD_EXTENSIONS_INFO = PCMCAddExtensionsInfo;
  {$EXTERNALSYM PCMC_ADD_EXTENSIONS_INFO}

//+-------------------------------------------------------------------------
//  CMC_ADD_ATTRIBUTES
//
//  Certificate Management Messages over CMS (CMC) Add Attributes control
//  attribute.
//
//  pvStructInfo points to a CMC_ADD_ATTRIBUTES_INFO.
//--------------------------------------------------------------------------
type
  PCMCAddAttributesInfo = ^TCMCAddAttributesInfo;
  _CMC_ADD_ATTRIBUTES_INFO = record
    dwCmcDataReference: DWORD;
    cCertReference: DWORD;
    rgdwCertReference: PDWORD;
    cAttribute: DWORD;
    rgAttribute: PCryptAttribute;
  end;
  {$EXTERNALSYM _CMC_ADD_ATTRIBUTES_INFO}
  CMC_ADD_ATTRIBUTES_INFO = _CMC_ADD_ATTRIBUTES_INFO;
  {$EXTERNALSYM CMC_ADD_ATTRIBUTES_INFO}
  TCMCAddAttributesInfo = _CMC_ADD_ATTRIBUTES_INFO;
  PCMC_ADD_ATTRIBUTES_INFO = PCMCAddAttributesInfo;
  {$EXTERNALSYM PCMC_ADD_ATTRIBUTES_INFO}

//+-------------------------------------------------------------------------
//  X509_CERTIFICATE_TEMPLATE
//  szOID_CERTIFICATE_TEMPLATE
//
//  pvStructInfo points to following CERT_TEMPLATE_EXT data structure.
//
//--------------------------------------------------------------------------
type
  PCertTemplateExt = ^TCertTemplateExt;
  _CERT_TEMPLATE_EXT = record
    pszObjId: LPSTR;
    dwMajorVersion: DWORD;
    fMinorVersion: BOOL;                      // TRUE for a minor version
    dwMinorVersion: DWORD;
  end;
  {$EXTERNALSYM _CERT_TEMPLATE_EXT}
  CERT_TEMPLATE_EXT = _CERT_TEMPLATE_EXT;
  {$EXTERNALSYM CERT_TEMPLATE_EXT}
  TCertTemplateExt = _CERT_TEMPLATE_EXT;
  PCERT_TEMPLATE_EXT = PCertTemplateExt;
  {$EXTERNALSYM PCERT_TEMPLATE_EXT}

//+=========================================================================
//  Logotype Extension Data Structures
//
//  X509_LOGOTYPE_EXT
//  szOID_LOGOTYPE_EXT
//
//  pvStructInfo points to a CERT_LOGOTYPE_EXT_INFO.
//==========================================================================
type
  PCertHashedURL = ^TCertHashedURL;
  _CERT_HASHED_URL = record
    HashAlgorithm: TCryptAlgorithmIdentifier;
    Hash: TCryptHashBlob;
    pwszUrl: LPWSTR;                          // Encoded as IA5, Optional for
                                              // biometric data
  end;
  {$EXTERNALSYM _CERT_HASHED_URL}
  CERT_HASHED_URL = _CERT_HASHED_URL;
  {$EXTERNALSYM CERT_HASHED_URL}
  TCertHashedURL = _CERT_HASHED_URL;
  PCERT_HASHED_URL = PCertHashedURL;
  {$EXTERNALSYM PCERT_HASHED_URL}

type
  PCertLogotypeDetials = ^TCertLogotypeDetials;
  _CERT_LOGOTYPE_DETAILS = record
    pwszMimeType: LPWSTR;                         // Encoded as IA5
    cHashedUrl: DWORD;
    rgHashedUrl: PCertHashedURL;
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_DETAILS}
  CERT_LOGOTYPE_DETAILS = _CERT_LOGOTYPE_DETAILS;
  {$EXTERNALSYM CERT_LOGOTYPE_DETAILS}
  TCertLogotypeDetials = _CERT_LOGOTYPE_DETAILS;
  PCERT_LOGOTYPE_DETAILS = PCertLogotypeDetials;
  {$EXTERNALSYM PCERT_LOGOTYPE_DETAILS}

type
  PCertLogotypeReference = ^TCertLogotypeReference;
  _CERT_LOGOTYPE_REFERENCE = record
    cHashedUrl: DWORD;
    rgHashedUrl: PCertHashedURL;
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_REFERENCE}
  CERT_LOGOTYPE_REFERENCE = _CERT_LOGOTYPE_REFERENCE;
  {$EXTERNALSYM CERT_LOGOTYPE_REFERENCE}
  TCertLogotypeReference = _CERT_LOGOTYPE_REFERENCE;
  PCERT_LOGOTYPE_REFERENCE = PCertLogotypeReference;
  {$EXTERNALSYM PCERT_LOGOTYPE_REFERENCE}

const
  CERT_LOGOTYPE_GRAY_SCALE_IMAGE_INFO_CHOICE         = 1;
  {$EXTERNALSYM CERT_LOGOTYPE_GRAY_SCALE_IMAGE_INFO_CHOICE}
  CERT_LOGOTYPE_COLOR_IMAGE_INFO_CHOICE              = 2;
  {$EXTERNALSYM CERT_LOGOTYPE_COLOR_IMAGE_INFO_CHOICE}

const
  CERT_LOGOTYPE_NO_IMAGE_RESOLUTION_CHOICE           = 0;
  {$EXTERNALSYM CERT_LOGOTYPE_NO_IMAGE_RESOLUTION_CHOICE}
  CERT_LOGOTYPE_BITS_IMAGE_RESOLUTION_CHOICE         = 1;
  {$EXTERNALSYM CERT_LOGOTYPE_BITS_IMAGE_RESOLUTION_CHOICE}
  CERT_LOGOTYPE_TABLE_SIZE_IMAGE_RESOLUTION_CHOICE   = 2;
  {$EXTERNALSYM CERT_LOGOTYPE_TABLE_SIZE_IMAGE_RESOLUTION_CHOICE}

type
  PCertLogotypeImageInfo = ^TCertLogotypeImageInfo;
  _CERT_LOGOTYPE_IMAGE_INFO = record
    // CERT_LOGOTYPE_GRAY_SCALE_IMAGE_INFO_CHOICE or
    // CERT_LOGOTYPE_COLOR_IMAGE_INFO_CHOICE
    dwLogotypeImageInfoChoice: DWORD;

    dwFileSize: DWORD;                            // In octets
    dwXSize: DWORD;                               // Horizontal size in pixels
    dwYSize: DWORD;                               // Vertical size in pixels

    case dwLogotypeImageResolutionChoice: DWORD of
    CERT_LOGOTYPE_NO_IMAGE_RESOLUTION_CHOICE:
      (); // No resolution value
    CERT_LOGOTYPE_BITS_IMAGE_RESOLUTION_CHOICE:
      (dwNumBits: DWORD);                             // Resolution in bits

    CERT_LOGOTYPE_TABLE_SIZE_IMAGE_RESOLUTION_CHOICE:
      (dwTableSize: DWORD;                            // Number of color or grey tones
    pwszLanguage: LPWSTR                          // Optional. Encoded as IA5.
    );                                            // RFC 3066 Language Tag
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_IMAGE_INFO}
  CERT_LOGOTYPE_IMAGE_INFO = _CERT_LOGOTYPE_IMAGE_INFO;
  {$EXTERNALSYM CERT_LOGOTYPE_IMAGE_INFO}
  TCertLogotypeImageInfo = _CERT_LOGOTYPE_IMAGE_INFO;
  PCERT_LOGOTYPE_IMAGE_INFO = PCertLogotypeImageInfo;
  {$EXTERNALSYM PCERT_LOGOTYPE_IMAGE_INFO}

type
  PCertLogotypeImage = ^TCertLogotypeImage;
  _CERT_LOGOTYPE_IMAGE = record
    LogotypeDetails: TCertLogotypeDetials;

    pLogotypeImageInfo: PCertLogotypeImageInfo;    // Optional
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_IMAGE}
  CERT_LOGOTYPE_IMAGE = _CERT_LOGOTYPE_IMAGE;
  {$EXTERNALSYM CERT_LOGOTYPE_IMAGE}
  TCertLogotypeImage = _CERT_LOGOTYPE_IMAGE;
  PCERT_LOGOTYPE_IMAGE = PCertLogotypeImage;
  {$EXTERNALSYM PCERT_LOGOTYPE_IMAGE}

type
  PCertLogotypeAudioInfo = ^TCertLogotypeAudioInfo;
  _CERT_LOGOTYPE_AUDIO_INFO = record
    dwFileSize: DWORD;                            // In octets
    dwPlayTime: DWORD;                            // In milliseconds
    dwChannels: DWORD;                            // 1=mono, 2=stereo, 4=quad
    dwSampleRate: DWORD;                          // Optional. 0 => not present.
                                                  // Samples per second
    pwszLanguage: LPWSTR;                         // Optional. Encoded as IA5.
                                                  // RFC 3066 Language Tag
 end;
 {$EXTERNALSYM _CERT_LOGOTYPE_AUDIO_INFO}
 CERT_LOGOTYPE_AUDIO_INFO = _CERT_LOGOTYPE_AUDIO_INFO;
 {$EXTERNALSYM CERT_LOGOTYPE_AUDIO_INFO}
 TCertLogotypeAudioInfo = _CERT_LOGOTYPE_AUDIO_INFO;
 PCERT_LOGOTYPE_AUDIO_INFO = PCertLogotypeAudioInfo;
 {$EXTERNALSYM PCERT_LOGOTYPE_AUDIO_INFO}

type
  PCertLogotypeAudio = ^TCertLogotypeAudio;
  _CERT_LOGOTYPE_AUDIO = record
    LogotypeDetails: TCertLogotypeDetials;

    pLogotypeAudioInfo: PCertLogotypeAudioInfo;  // Optional
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_AUDIO}
  CERT_LOGOTYPE_AUDIO = _CERT_LOGOTYPE_AUDIO;
  {$EXTERNALSYM CERT_LOGOTYPE_AUDIO}
  TCertLogotypeAudio = _CERT_LOGOTYPE_AUDIO;
  PCERT_LOGOTYPE_AUDIO = PCertLogotypeAudio;
  {$EXTERNALSYM PCERT_LOGOTYPE_AUDIO}

type
  PCertLogotypeData = ^TCertLogotypeData;
  _CERT_LOGOTYPE_DATA = record
    cLogotypeImage: DWORD;
    rgLogotypeImage: PCertLogotypeImage;

    cLogotypeAudio: DWORD;
    rgLogotypeAudio: PCertLogotypeAudio;
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_DATA}
  CERT_LOGOTYPE_DATA = _CERT_LOGOTYPE_DATA;
  {$EXTERNALSYM CERT_LOGOTYPE_DATA}
  TCertLogotypeData = _CERT_LOGOTYPE_DATA;
  PCERT_LOGOTYPE_DATA = PCertLogotypeData;
  {$EXTERNALSYM PCERT_LOGOTYPE_DATA}

const
  CERT_LOGOTYPE_DIRECT_INFO_CHOICE   = 1;
  {$EXTERNALSYM CERT_LOGOTYPE_DIRECT_INFO_CHOICE}
  CERT_LOGOTYPE_INDIRECT_INFO_CHOICE = 2;
  {$EXTERNALSYM CERT_LOGOTYPE_INDIRECT_INFO_CHOICE}

type
  PCertLogotypeInfo = ^TCertLogotypeInfo;
  _CERT_LOGOTYPE_INFO = record
    case dwLogotypeInfoChoice: DWORD of
    CERT_LOGOTYPE_DIRECT_INFO_CHOICE:
      (pLogotypeDirectInfo: PCertLogotypeData);

    CERT_LOGOTYPE_INDIRECT_INFO_CHOICE:
      (pLogotypeIndirectInfo: PCertLogotypeReference);
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_INFO}
  CERT_LOGOTYPE_INFO = _CERT_LOGOTYPE_INFO;
  {$EXTERNALSYM CERT_LOGOTYPE_INFO}
  TCertLogotypeInfo = _CERT_LOGOTYPE_INFO;
  PCERT_LOGOTYPE_INFO = PCertLogotypeInfo;
  {$EXTERNALSYM PCERT_LOGOTYPE_INFO}

type
  PCertOtherLogotypeInfo = ^TCertOtherLogotypeInfo;
  _CERT_OTHER_LOGOTYPE_INFO = record
    pszObjId: LPSTR;
    LogotypeInfo: TCertLogotypeInfo;
  end;
  {$EXTERNALSYM _CERT_OTHER_LOGOTYPE_INFO}
  CERT_OTHER_LOGOTYPE_INFO = _CERT_OTHER_LOGOTYPE_INFO;
  {$EXTERNALSYM CERT_OTHER_LOGOTYPE_INFO}
  TCertOtherLogotypeInfo = _CERT_OTHER_LOGOTYPE_INFO;
  PCERT_OTHER_LOGOTYPE_INFO = PCertOtherLogotypeInfo;
  {$EXTERNALSYM PCERT_OTHER_LOGOTYPE_INFO}

const
  szOID_LOYALTY_OTHER_LOGOTYPE               = '1.3.6.1.5.5.7.20.1';
  {$EXTERNALSYM szOID_LOYALTY_OTHER_LOGOTYPE}
  szOID_BACKGROUND_OTHER_LOGOTYPE            = '1.3.6.1.5.5.7.20.2';
  {$EXTERNALSYM szOID_BACKGROUND_OTHER_LOGOTYPE}

type
  PCertLogotypeExtInfo = ^TCertLogotypeExtInfo;
  _CERT_LOGOTYPE_EXT_INFO = record
    cCommunityLogo: DWORD;
    rgCommunityLogo: PCertLogotypeInfo;
    pIssuerLogo: PCertLogotypeInfo;                 // Optional
    pSubjectLogo: PCertLogotypeInfo;                // Optional
    cOtherLogo: DWORD;
    rgOtherLogo: PCertOtherLogotypeInfo;
  end;
  {$EXTERNALSYM _CERT_LOGOTYPE_EXT_INFO}
  CERT_LOGOTYPE_EXT_INFO = _CERT_LOGOTYPE_EXT_INFO;
  {$EXTERNALSYM CERT_LOGOTYPE_EXT_INFO}
  TCertLogotypeExtInfo = _CERT_LOGOTYPE_EXT_INFO;
  PCERT_LOGOTYPE_EXT_INFO = PCertLogotypeExtInfo;
  {$EXTERNALSYM PCERT_LOGOTYPE_EXT_INFO}

//+=========================================================================
//  Biometric Extension Data Structures
//
//  X509_BIOMETRIC_EXT
//  szOID_BIOMETRIC_EXT
//
//  pvStructInfo points to following CERT_BIOMETRIC_EXT_INFO data structure.
//==========================================================================
const
  CERT_BIOMETRIC_PREDEFINED_DATA_CHOICE  = 1;
  {$EXTERNALSYM CERT_BIOMETRIC_PREDEFINED_DATA_CHOICE}
  CERT_BIOMETRIC_OID_DATA_CHOICE         = 2;
  {$EXTERNALSYM CERT_BIOMETRIC_OID_DATA_CHOICE}

type
  PCertBiometricData = ^TCertBiometricData;
  _CERT_BIOMETRIC_DATA = record
    case dwTypeOfBiometricDataChoice: DWORD of
    CERT_BIOMETRIC_PREDEFINED_DATA_CHOICE:
      (dwPredefined: DWORD);

    CERT_BIOMETRIC_OID_DATA_CHOICE:
      (pszObjId: LPSTR;

    HashedUrl: TCertHashedURL                   // pwszUrl is Optional.
    );
  end;
  {$EXTERNALSYM _CERT_BIOMETRIC_DATA}
  CERT_BIOMETRIC_DATA = _CERT_BIOMETRIC_DATA;
  {$EXTERNALSYM CERT_BIOMETRIC_DATA}
  TCertBiometricData = _CERT_BIOMETRIC_DATA;
  PCERT_BIOMETRIC_DATA = PCertBiometricData;
  {$EXTERNALSYM PCERT_BIOMETRIC_DATA}

const
  CERT_BIOMETRIC_PICTURE_TYPE            = 0;
  {$EXTERNALSYM CERT_BIOMETRIC_PICTURE_TYPE}
  CERT_BIOMETRIC_SIGNATURE_TYPE          = 1;
  {$EXTERNALSYM CERT_BIOMETRIC_SIGNATURE_TYPE}

type
  PCertBiometricExtInfo= ^TCertBiometricExtInfo;
  _CERT_BIOMETRIC_EXT_INFO = record
    cBiometricData: DWORD;
    rgBiometricData: PCertBiometricData;
  end;
  {$EXTERNALSYM _CERT_BIOMETRIC_EXT_INFO}
  CERT_BIOMETRIC_EXT_INFO = _CERT_BIOMETRIC_EXT_INFO;
  {$EXTERNALSYM CERT_BIOMETRIC_EXT_INFO}
  TCertBiometricExtInfo = _CERT_BIOMETRIC_EXT_INFO;
  PCERT_BIOMETRIC_EXT_INFO = PCertBiometricExtInfo;
  {$EXTERNALSYM PCERT_BIOMETRIC_EXT_INFO}

//+=========================================================================
//  Online Certificate Status Protocol (OCSP) Data Structures
//==========================================================================

//+-------------------------------------------------------------------------
//  OCSP_SIGNED_REQUEST
//
//  OCSP signed request.
//
//  Note, in most instances, pOptionalSignatureInfo will be NULL indicating
//  no signature is present.
//--------------------------------------------------------------------------
type
  POCSPSignatureInfo = ^TOCSPSignatureInfo;
  _OCSP_SIGNATURE_INFO = record
    SignatureAlgorithm: TCryptAlgorithmIdentifier;
    Signature: TCryptBitBlob;
    cCertEncoded: DWORD;
    rgCertEncoded: PCertBlob;
  end;
  {$EXTERNALSYM _OCSP_SIGNATURE_INFO}
  OCSP_SIGNATURE_INFO = _OCSP_SIGNATURE_INFO;
  {$EXTERNALSYM OCSP_SIGNATURE_INFO}
  TOCSPSignatureInfo = _OCSP_SIGNATURE_INFO;
  POCSP_SIGNATURE_INFO = POCSPSignatureInfo;
  {$EXTERNALSYM POCSP_SIGNATURE_INFO}

type
  POCSPSignedRequestInfo = ^TOCSPSignedRequestInfo;
  _OCSP_SIGNED_REQUEST_INFO = record
    ToBeSigned: TCryptDERBlob;                           // Encoded OCSP_REQUEST
    pOptionalSignatureInfo: POCSPSignatureInfo;          // NULL, no signature
  end;
  {$EXTERNALSYM _OCSP_SIGNED_REQUEST_INFO}
  OCSP_SIGNED_REQUEST_INFO = _OCSP_SIGNED_REQUEST_INFO;
  {$EXTERNALSYM OCSP_SIGNED_REQUEST_INFO}
  TOCSPSignedRequestInfo = _OCSP_SIGNED_REQUEST_INFO;
  POCSP_SIGNED_REQUEST_INFO = POCSPSignedRequestInfo;
  {$EXTERNALSYM POCSP_SIGNED_REQUEST_INFO}

//+-------------------------------------------------------------------------
//  OCSP_REQUEST
//
//  ToBeSigned OCSP request.
//--------------------------------------------------------------------------
type
  POCSPCertID = ^TOCSPCertID;
  _OCSP_CERT_ID = record
    HashAlgorithm: TCryptAlgorithmIdentifier;    // Normally SHA1
    IssuerNameHash: TCryptHashBlob;              // Hash of encoded name
    IssuerKeyHash: TCryptHashBlob;               // Hash of PublicKey bits
    SerialNumber: TCryptIntegerBlob;
  end;
  {$EXTERNALSYM _OCSP_CERT_ID}
  OCSP_CERT_ID = _OCSP_CERT_ID;
  {$EXTERNALSYM OCSP_CERT_ID}
  TOCSPCertID = _OCSP_CERT_ID;
  POCSP_CERT_ID = POCSPCertID;
  {$EXTERNALSYM POCSP_CERT_ID}

type
  POCSPRequestEntry = ^TOCSPRequestEntry;
  _OCSP_REQUEST_ENTRY = record
    CertId: TOCSPCertID;
    cExtension: DWORD;
    rgExtension: PCertExtension;
  end;
  {$EXTERNALSYM _OCSP_REQUEST_ENTRY}
  OCSP_REQUEST_ENTRY = _OCSP_REQUEST_ENTRY;
  {$EXTERNALSYM OCSP_REQUEST_ENTRY}
  TOCSPRequestEntry = _OCSP_REQUEST_ENTRY;
  POCSP_REQUEST_ENTRY = POCSPRequestEntry;
  {$EXTERNALSYM POCSP_REQUEST_ENTRY}

type
  POCSPRequestInfo = ^TOCSPRequestInfo;
  _OCSP_REQUEST_INFO = record
    dwVersion: DWORD;
    pRequestorName: PCertAltNameInfo;             // OPTIONAL
    cRequestEntry: DWORD;
    rgRequestEntry: POCSPRequestEntry;
    cExtension: DWORD;
    rgExtension: PCertExtension;
  end;
  {$EXTERNALSYM _OCSP_REQUEST_INFO}
  OCSP_REQUEST_INFO = _OCSP_REQUEST_INFO;
  {$EXTERNALSYM OCSP_REQUEST_INFO}
  TOCSPRequestInfo = _OCSP_REQUEST_INFO;
  POCSP_REQUEST_INFO = POCSPRequestInfo;
  {$EXTERNALSYM POCSP_REQUEST_INFO}

const
  OCSP_REQUEST_V1    = 0;
  {$EXTERNALSYM OCSP_REQUEST_V1}

//+-------------------------------------------------------------------------
//  OCSP_RESPONSE
//
//  OCSP outer, unsigned response wrapper.
//--------------------------------------------------------------------------
type
  POCSPResponseInfo = ^TOCSPResponseInfo;
  _OCSP_RESPONSE_INFO = record
    dwStatus: DWORD;
    pszObjId: LPSTR;                          // OPTIONAL, may be NULL
    Value: TCryptObjIDBlob;                   // OPTIONAL
  end;
  {$EXTERNALSYM _OCSP_RESPONSE_INFO}
  OCSP_RESPONSE_INFO = _OCSP_RESPONSE_INFO;
  {$EXTERNALSYM OCSP_RESPONSE_INFO}
  TOCSPResponseInfo = _OCSP_RESPONSE_INFO;
  POCSP_RESPONSE_INFO = POCSPResponseInfo;
  {$EXTERNALSYM POCSP_RESPONSE_INFO}

const
  OCSP_SUCCESSFUL_RESPONSE           = 0;
  {$EXTERNALSYM OCSP_SUCCESSFUL_RESPONSE}
  OCSP_MALFORMED_REQUEST_RESPONSE    = 1;
  {$EXTERNALSYM OCSP_MALFORMED_REQUEST_RESPONSE}
  OCSP_INTERNAL_ERROR_RESPONSE       = 2;
  {$EXTERNALSYM OCSP_INTERNAL_ERROR_RESPONSE}
  OCSP_TRY_LATER_RESPONSE            = 3;
  {$EXTERNALSYM OCSP_TRY_LATER_RESPONSE}
// 4 is not used
const
  OCSP_SIG_REQUIRED_RESPONSE         = 5;
  {$EXTERNALSYM OCSP_SIG_REQUIRED_RESPONSE}
  OCSP_UNAUTHORIZED_RESPONSE         = 6;
  {$EXTERNALSYM OCSP_UNAUTHORIZED_RESPONSE}

const
  szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE  = '1.3.6.1.5.5.7.48.1.1';
  {$EXTERNALSYM szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE}

//+-------------------------------------------------------------------------
//  OCSP_BASIC_SIGNED_RESPONSE
//  szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE
//
//  OCSP basic signed response.
//--------------------------------------------------------------------------
type
  POCSPBasicSignedResponse = ^TOCSPBasicSignedResponse;
  _OCSP_BASIC_SIGNED_RESPONSE_INFO = record
    ToBeSigned: TCryptDERBlob;                   // Encoded OCSP_BASIC_RESPONSE
    SignatureInfo: TOCSPSignatureInfo;
  end;
  {$EXTERNALSYM _OCSP_BASIC_SIGNED_RESPONSE_INFO}
  OCSP_BASIC_SIGNED_RESPONSE_INFO = _OCSP_BASIC_SIGNED_RESPONSE_INFO;
  {$EXTERNALSYM OCSP_BASIC_SIGNED_RESPONSE_INFO}
  TOCSPBasicSignedResponse = _OCSP_BASIC_SIGNED_RESPONSE_INFO;
  POCSP_BASIC_SIGNED_RESPONSE_INFO = POCSPBasicSignedResponse;
  {$EXTERNALSYM POCSP_BASIC_SIGNED_RESPONSE_INFO}

//+-------------------------------------------------------------------------
//  OCSP_BASIC_RESPONSE
//
//  ToBeSigned OCSP basic response.
//--------------------------------------------------------------------------
type
  POCSPBasicRevokedInfo = ^TOCSPBasicRevokedInfo;
  _OCSP_BASIC_REVOKED_INFO = record
    RevocationDate: TFileTime;

    // See X509_CRL_REASON_CODE for list of reason codes
    dwCrlReasonCode: DWORD;
  end;
  {$EXTERNALSYM _OCSP_BASIC_REVOKED_INFO}
  OCSP_BASIC_REVOKED_INFO = _OCSP_BASIC_REVOKED_INFO;
  {$EXTERNALSYM OCSP_BASIC_REVOKED_INFO}
  TOCSPBasicRevokedInfo = _OCSP_BASIC_REVOKED_INFO;
  POCSP_BASIC_REVOKED_INFO = POCSPBasicRevokedInfo;
  {$EXTERNALSYM POCSP_BASIC_REVOKED_INFO}

const
  OCSP_BASIC_GOOD_CERT_STATUS        = 0;
  {$EXTERNALSYM OCSP_BASIC_GOOD_CERT_STATUS}
  OCSP_BASIC_REVOKED_CERT_STATUS     = 1;
  {$EXTERNALSYM OCSP_BASIC_REVOKED_CERT_STATUS}
  OCSP_BASIC_UNKNOWN_CERT_STATUS     = 2;
  {$EXTERNALSYM OCSP_BASIC_UNKNOWN_CERT_STATUS}

type
  POCSPBasicResponseEntry = ^TOCSPBasicResponseEntry;
  _OCSP_BASIC_RESPONSE_ENTRY = record
    CertId: TOCSPCertID;
    case dwCertStatus: DWORD of
    OCSP_BASIC_GOOD_CERT_STATUS,
    OCSP_BASIC_UNKNOWN_CERT_STATUS:
      ();  //  No additional information

    OCSP_BASIC_REVOKED_CERT_STATUS:
      (pRevokedInfo: POCSPBasicRevokedInfo;

    ThisUpdate: TFileTime;
    NextUpdate: TFileTime;                  // Optional, zero filetime implies
                                            // never expires
    cExtension: DWORD;
    rgExtension: PCertExtension
    )
  end;
  {$EXTERNALSYM _OCSP_BASIC_RESPONSE_ENTRY}
  OCSP_BASIC_RESPONSE_ENTRY = _OCSP_BASIC_RESPONSE_ENTRY;
  {$EXTERNALSYM OCSP_BASIC_RESPONSE_ENTRY}
  TOCSPBasicResponseEntry = _OCSP_BASIC_RESPONSE_ENTRY;
  POCSP_BASIC_RESPONSE_ENTRY = POCSPBasicResponseEntry;
  {$EXTERNALSYM POCSP_BASIC_RESPONSE_ENTRY}

const
  OCSP_BASIC_BY_NAME_RESPONDER_ID    = 1;
  {$EXTERNALSYM OCSP_BASIC_BY_NAME_RESPONDER_ID}
  OCSP_BASIC_BY_KEY_RESPONDER_ID     = 2;
  {$EXTERNALSYM OCSP_BASIC_BY_KEY_RESPONDER_ID}

type
  POCSPBasicResponseInfo = ^TOCSPBasicResponseInfo;
  _OCSP_BASIC_RESPONSE_INFO = record
    dwVersion: DWORD;
    case dwResponderIdChoice: DWORD of
    OCSP_BASIC_BY_NAME_RESPONDER_ID:
      (ByNameResponderId: TCertNameBlob);
    OCSP_BASIC_BY_KEY_RESPONDER_ID:
      (ByKeyResponderId: TCryptHashBlob;

    ProducedAt: TFileTime;
    cResponseEntry: DWORD;
    rgResponseEntry: POCSPBasicResponseEntry;
    cExtension: DWORD;
    rgExtension: PCertExtension
    )
  end;
  {$EXTERNALSYM _OCSP_BASIC_RESPONSE_INFO}
  OCSP_BASIC_RESPONSE_INFO = _OCSP_BASIC_RESPONSE_INFO;
  {$EXTERNALSYM OCSP_BASIC_RESPONSE_INFO}
  TOCSPBasicResponseInfo = _OCSP_BASIC_RESPONSE_INFO;
  POCSP_BASIC_RESPONSE_INFO = POCSPBasicResponseInfo;
  {$EXTERNALSYM POCSP_BASIC_RESPONSE_INFO}

const
  OCSP_BASIC_RESPONSE_V1 = 0;
  {$EXTERNALSYM OCSP_BASIC_RESPONSE_V1}

//+=========================================================================
//  Object IDentifier (OID) Installable Functions:  Data Structures and APIs
//==========================================================================
type
  HCRYPTOIDFUNCSET = Pointer;
  {$EXTERNALSYM HCRYPTOIDFUNCSET}
  HCRYPTOIDFUNCADDR = Pointer;
  {$EXTERNALSYM HCRYPTOIDFUNCADDR}

// Predefined OID Function Names
const
  CRYPT_OID_ENCODE_OBJECT_FUNC       = 'CryptDllEncodeObject';
  {$EXTERNALSYM CRYPT_OID_ENCODE_OBJECT_FUNC}
  CRYPT_OID_DECODE_OBJECT_FUNC       = 'CryptDllDecodeObject';
  {$EXTERNALSYM CRYPT_OID_DECODE_OBJECT_FUNC}
  CRYPT_OID_ENCODE_OBJECT_EX_FUNC    = 'CryptDllEncodeObjectEx';
  {$EXTERNALSYM CRYPT_OID_ENCODE_OBJECT_EX_FUNC}
  CRYPT_OID_DECODE_OBJECT_EX_FUNC    = 'CryptDllDecodeObjectEx';
  {$EXTERNALSYM CRYPT_OID_DECODE_OBJECT_EX_FUNC}
  CRYPT_OID_CREATE_COM_OBJECT_FUNC   = 'CryptDllCreateCOMObject';
  {$EXTERNALSYM CRYPT_OID_CREATE_COM_OBJECT_FUNC}
  CRYPT_OID_VERIFY_REVOCATION_FUNC   = 'CertDllVerifyRevocation';
  {$EXTERNALSYM CRYPT_OID_VERIFY_REVOCATION_FUNC}
  CRYPT_OID_VERIFY_CTL_USAGE_FUNC    = 'CertDllVerifyCTLUsage';
  {$EXTERNALSYM CRYPT_OID_VERIFY_CTL_USAGE_FUNC}
  CRYPT_OID_FORMAT_OBJECT_FUNC       = 'CryptDllFormatObject';
  {$EXTERNALSYM CRYPT_OID_FORMAT_OBJECT_FUNC}
  CRYPT_OID_FIND_OID_INFO_FUNC       = 'CryptDllFindOIDInfo';
  {$EXTERNALSYM CRYPT_OID_FIND_OID_INFO_FUNC}
  CRYPT_OID_FIND_LOCALIZED_NAME_FUNC = 'CryptDllFindLocalizedName';
  {$EXTERNALSYM CRYPT_OID_FIND_LOCALIZED_NAME_FUNC}

// CryptDllEncodeObject has same function signature as CryptEncodeObject.

// CryptDllDecodeObject has same function signature as CryptDecodeObject.

// CryptDllEncodeObjectEx has same function signature as CryptEncodeObjectEx.
// The Ex version MUST support the CRYPT_ENCODE_ALLOC_FLAG option.
//
// If an Ex function isn't installed or registered, then, attempts to find
// a non-EX version. If the ALLOC flag is set, then, CryptEncodeObjectEx,
// does the allocation and calls the non-EX version twice.

// CryptDllDecodeObjectEx has same function signature as CryptDecodeObjectEx.
// The Ex version MUST support the CRYPT_DECODE_ALLOC_FLAG option.
//
// If an Ex function isn't installed or registered, then, attempts to find
// a non-EX version. If the ALLOC flag is set, then, CryptDecodeObjectEx,
// does the allocation and calls the non-EX version twice.

// CryptDllCreateCOMObject has the following signature:
//      BOOL WINAPI CryptDllCreateCOMObject(
//          _In_ DWORD dwEncodingType,
//          _In_ LPCSTR pszOID,
//          __In PCRYPT_DATA_BLOB pEncodedContent,
//          _In_ DWORD dwFlags,
//          _In_ REFIID riid,
//          _Outptr_ void **ppvObj);

// CertDllVerifyRevocation has the same signature as CertVerifyRevocation
//  (See CertVerifyRevocation for details on when called)

// CertDllVerifyCTLUsage has the same signature as CertVerifyCTLUsage

// CryptDllFindOIDInfo currently is only used to store values used by
// CryptFindOIDInfo. See CryptFindOIDInfo() for more details.

// CryptDllFindLocalizedName is only used to store localized string
// values used by CryptFindLocalizedName. See CryptFindLocalizedName() for
// more details.

//  Example of a complete OID Function Registry Name:
//    HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\OID
//      Encoding Type 1\CryptDllEncodeObject\1.2.3
//
//  The key's L"Dll" value contains the name of the Dll.
//  The key's L"FuncName" value overrides the default function name
const
  CRYPT_OID_REGPATH = 'Software\Microsoft\Cryptography\OID';
  {$EXTERNALSYM CRYPT_OID_REGPATH}
  CRYPT_OID_REG_ENCODING_TYPE_PREFIX   = 'EncodingType ';
  {$EXTERNALSYM CRYPT_OID_REG_ENCODING_TYPE_PREFIX}
  CRYPT_OID_REG_DLL_VALUE_NAME         = 'Dll';
  {$EXTERNALSYM CRYPT_OID_REG_DLL_VALUE_NAME}
  CRYPT_OID_REG_FUNC_NAME_VALUE_NAME   = 'FuncName';
  {$EXTERNALSYM CRYPT_OID_REG_FUNC_NAME_VALUE_NAME}
  CRYPT_OID_REG_FUNC_NAME_VALUE_NAME_A = 'FuncName';
  {$EXTERNALSYM CRYPT_OID_REG_FUNC_NAME_VALUE_NAME_A}

// CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG can be set in the key's L"CryptFlags"
// value to register the functions before the installed functions.
//
// CryptSetOIDFunctionValue must be called to set this value. L"CryptFlags"
// must be set using a dwValueType of REG_DWORD.
const
  CRYPT_OID_REG_FLAGS_VALUE_NAME       = 'CryptFlags';
  {$EXTERNALSYM CRYPT_OID_REG_FLAGS_VALUE_NAME}

// OID used for Default OID functions
const
  CRYPT_DEFAULT_OID                    = 'DEFAULT';
  {$EXTERNALSYM CRYPT_DEFAULT_OID}

type
  PCryptOIDFuncEntry = ^TCryptOIDFuncEntry;
  _CRYPT_OID_FUNC_ENTRY = record
    pszOID: LPCSTR;
    pvFuncAddr: Pointer;
  end;
  {$EXTERNALSYM _CRYPT_OID_FUNC_ENTRY}
  CRYPT_OID_FUNC_ENTRY = _CRYPT_OID_FUNC_ENTRY;
  {$EXTERNALSYM CRYPT_OID_FUNC_ENTRY}
  TCryptOIDFuncEntry = _CRYPT_OID_FUNC_ENTRY;
  PCRYPT_OID_FUNC_ENTRY = PCryptOIDFuncEntry;
  {$EXTERNALSYM PCRYPT_OID_FUNC_ENTRY}

const
  CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG = 1;
  {$EXTERNALSYM CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG}

//+-------------------------------------------------------------------------
//  Install a set of callable OID function addresses.
//
//  By default the functions are installed at end of the list.
//  Set CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG to install at beginning of list.
//
//  hModule should be updated with the hModule passed to DllMain to prevent
//  the Dll containing the function addresses from being unloaded by
//  CryptGetOIDFuncAddress/CryptFreeOIDFunctionAddress. This would be the
//  case when the Dll has also regsvr32'ed OID functions via
//  CryptRegisterOIDFunction.
//
//  DEFAULT functions are installed by setting rgFuncEntry[].pszOID =
//  CRYPT_DEFAULT_OID.
//--------------------------------------------------------------------------
function CryptInstallOIDFunctionAddress(
  hModule: HMODULE;          // hModule passed to DllMain
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  cFuncEntry: DWORD;
  rgFuncEntry: PCryptOIDFuncEntry;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptInstallOIDFunctionAddress}

//+-------------------------------------------------------------------------
//  Initialize and return handle to the OID function set identified by its
//  function name.
//
//  If the set already exists, a handle to the existing set is returned.
//--------------------------------------------------------------------------
function CryptInitOIDFunctionSet(
  pszFuncName: LPCSTR;
  dwFlags: DWORD): HCRYPTOIDFUNCSET; winapi;
{$EXTERNALSYM CryptInitOIDFunctionSet}

//+-------------------------------------------------------------------------
//  Search the list of installed functions for an encoding type and OID match.
//  If not found, search the registry.
//
//  For success, returns TRUE with *ppvFuncAddr updated with the function's
//  address and *phFuncAddr updated with the function address's handle.
//  The function's handle is AddRef'ed. CryptFreeOIDFunctionAddress needs to
//  be called to release it.
//
//  For a registry match, the Dll containing the function is loaded.
//
//  By default, both the registered and installed function lists are searched.
//  Set CRYPT_GET_INSTALLED_OID_FUNC_FLAG to only search the installed list
//  of functions. This flag would be set by a registered function to get
//  the address of a pre-installed function it was replacing. For example,
//  the registered function might handle a new special case and call the
//  pre-installed function to handle the remaining cases.
//--------------------------------------------------------------------------
function CryptGetOIDFunctionAddress(
  hFuncSet: HCRYPTOIDFUNCSET;
  dwEncodingType: DWORD;
  pszOID: LPCSTR;
  dwFlags: DWORD;
  out ppvFuncAddr: Pointer;
  out phFuncAddr: HCRYPTOIDFUNCADDR): BOOL; winapi;
{$EXTERNALSYM CryptGetOIDFunctionAddress}

const
  CRYPT_GET_INSTALLED_OID_FUNC_FLAG      = $1;
  {$EXTERNALSYM CRYPT_GET_INSTALLED_OID_FUNC_FLAG}

//+-------------------------------------------------------------------------
//  Get the list of registered default Dll entries for the specified
//  function set and encoding type.
//
//  The returned list consists of none, one or more null terminated Dll file
//  names. The list is terminated with an empty (L"\0") Dll file name.
//  For example: L"first.dll" L"\0" L"second.dll" L"\0" L"\0"
//--------------------------------------------------------------------------
function CryptGetDefaultOIDDllList(
  hFuncSet: HCRYPTOIDFUNCSET;
  dwEncodingType: DWORD;
  pwszDllList: LPWSTR;
  var pcchDllList: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetDefaultOIDDllList}

//+-------------------------------------------------------------------------
//  Either: get the first or next installed DEFAULT function OR
//  load the Dll containing the DEFAULT function.
//
//  If pwszDll is NULL, search the list of installed DEFAULT functions.
//  *phFuncAddr must be set to NULL to get the first installed function.
//  Successive installed functions are returned by setting *phFuncAddr
//  to the hFuncAddr returned by the previous call.
//
//  If pwszDll is NULL, the input *phFuncAddr
//  is always CryptFreeOIDFunctionAddress'ed by this function, even for
//  an error.
//
//  If pwszDll isn't NULL, then, attempts to load the Dll and the DEFAULT
//  function. *phFuncAddr is ignored upon entry and isn't
//  CryptFreeOIDFunctionAddress'ed.
//
//  For success, returns TRUE with *ppvFuncAddr updated with the function's
//  address and *phFuncAddr updated with the function address's handle.
//  The function's handle is AddRef'ed. CryptFreeOIDFunctionAddress needs to
//  be called to release it or CryptGetDefaultOIDFunctionAddress can also
//  be called for a NULL pwszDll.
//--------------------------------------------------------------------------
function CryptGetDefaultOIDFunctionAddress(
  hFuncSet: HCRYPTOIDFUNCSET;
  dwEncodingType: DWORD;
  pwszDll: LPCWSTR;
  dwFlags: DWORD;
  out ppvFuncAddr: Pointer;
  var phFuncAddr: HCRYPTOIDFUNCADDR): BOOL; winapi;
{$EXTERNALSYM CryptGetDefaultOIDFunctionAddress}

//+-------------------------------------------------------------------------
//  Releases the handle AddRef'ed and returned by CryptGetOIDFunctionAddress
//  or CryptGetDefaultOIDFunctionAddress.
//
//  If a Dll was loaded for the function its unloaded. However, before doing
//  the unload, the DllCanUnloadNow function exported by the loaded Dll is
//  called. It should return S_FALSE to inhibit the unload or S_TRUE to enable
//  the unload. If the Dll doesn't export DllCanUnloadNow, the Dll is unloaded.
//
//  DllCanUnloadNow has the following signature:
//      STDAPI  DllCanUnloadNow(void);
//--------------------------------------------------------------------------
function CryptFreeOIDFunctionAddress(
  hFuncAddr: HCRYPTOIDFUNCADDR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptFreeOIDFunctionAddress}

//+-------------------------------------------------------------------------
//  Register the Dll containing the function to be called for the specified
//  encoding type, function name and OID.
//
//  pwszDll may contain environment-variable strings
//  which are ExpandEnvironmentStrings()'ed before loading the Dll.
//
//  In addition to registering the DLL, you may override the
//  name of the function to be called. For example,
//      pszFuncName = "CryptDllEncodeObject",
//      pszOverrideFuncName = "MyEncodeXyz".
//  This allows a Dll to export multiple OID functions for the same
//  function name without needing to interpose its own OID dispatcher function.
//--------------------------------------------------------------------------
function CryptRegisterOIDFunction(
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  pszOID: LPCSTR;
  pwszDll: LPCWSTR;
  pszOverrideFuncName: LPCSTR): BOOL; winapi;
{$EXTERNALSYM CryptRegisterOIDFunction}

//+-------------------------------------------------------------------------
//  Unregister the Dll containing the function to be called for the specified
//  encoding type, function name and OID.
//--------------------------------------------------------------------------
function CryptUnregisterOIDFunction(
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  pszOID: LPCSTR): BOOL; winapi;
{$EXTERNALSYM CryptUnregisterOIDFunction}

//+-------------------------------------------------------------------------
//  Register the Dll containing the default function to be called for the
//  specified encoding type and function name.
//
//  Unlike CryptRegisterOIDFunction, you can't override the function name
//  needing to be exported by the Dll.
//
//  The Dll is inserted before the entry specified by dwIndex.
//    dwIndex == 0, inserts at the beginning.
//    dwIndex == CRYPT_REGISTER_LAST_INDEX, appends at the end.
//
//  pwszDll may contain environment-variable strings
//  which are ExpandEnvironmentStrings()'ed before loading the Dll.
//--------------------------------------------------------------------------
function CryptRegisterDefaultOIDFunction(
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  dwIndex: DWORD;
  pwszDll: LPCWSTR): BOOL; winapi;
{$EXTERNALSYM CryptRegisterDefaultOIDFunction}

const
  CRYPT_REGISTER_FIRST_INDEX  = 0;
  {$EXTERNALSYM CRYPT_REGISTER_FIRST_INDEX}
  CRYPT_REGISTER_LAST_INDEX   = $FFFFFFFF;
  {$EXTERNALSYM CRYPT_REGISTER_LAST_INDEX}

//+-------------------------------------------------------------------------
//  Unregister the Dll containing the default function to be called for
//  the specified encoding type and function name.
//--------------------------------------------------------------------------
function CryptUnregisterDefaultOIDFunction(
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  pwszDll: LPCWSTR): BOOL; winapi;
{$EXTERNALSYM CryptUnregisterDefaultOIDFunction}

//+-------------------------------------------------------------------------
//  Set the value for the specified encoding type, function name, OID and
//  value name.
//
//  See RegSetValueEx for the possible value types.
//
//  String types are UNICODE.
//--------------------------------------------------------------------------
function CryptSetOIDFunctionValue(
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  pszOID: LPCSTR;
  pwszValueName: LPCWSTR;
  dwValueType: DWORD;
  pbValueData: PByte;
  cbValueData: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSetOIDFunctionValue}

//+-------------------------------------------------------------------------
//  Get the value for the specified encoding type, function name, OID and
//  value name.
//
//  See RegEnumValue for the possible value types.
//
//  String types are UNICODE.
//--------------------------------------------------------------------------
function CryptGetOIDFunctionValue(
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  pszOID: LPCSTR;
  pwszValueName: LPCWSTR;
  pdwValueType: PDWORD;
  pbValueData: PByte;
  var pcbValueData: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetOIDFunctionValue}

type
  PFN_CRYPT_ENUM_OID_FUNC =function(
    dwEncodingType: DWORD;
    pszFuncName: LPCSTR;
    pszOID: LPCSTR;
    cValue: DWORD;
    rgdwValueType: PDWORD;
    rgpwszValueName: PLPWSTR;
    rgpbValueData: LPByte;
    rgcbValueData: PDWORD;
    pvArg: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_ENUM_OID_FUNC}
  TFnCryptEnumOIDFunc = PFN_CRYPT_ENUM_OID_FUNC;

//+-------------------------------------------------------------------------
//  Enumerate the OID functions identified by their encoding type,
//  function name and OID.
//
//  pfnEnumOIDFunc is called for each registry key matching the input
//  parameters. Setting dwEncodingType to CRYPT_MATCH_ANY_ENCODING_TYPE matches
//  any. Setting pszFuncName or pszOID to NULL matches any.
//
//  Set pszOID == CRYPT_DEFAULT_OID to restrict the enumeration to only the
//  DEFAULT functions
//
//  String types are UNICODE.
//--------------------------------------------------------------------------
function CryptEnumOIDFunction(
  dwEncodingType: DWORD;
  pszFuncName: LPCSTR;
  pszOID: LPCSTR;
  dwFlags: DWORD;
  pvArg: Pointer;
  pfnEnumOIDFunc: TFnCryptEnumOIDFunc): BOOL; winapi;
{$EXTERNALSYM CryptEnumOIDFunction}

const
  CRYPT_MATCH_ANY_ENCODING_TYPE  = $FFFFFFFF;
  {$EXTERNALSYM CRYPT_MATCH_ANY_ENCODING_TYPE}

//+=========================================================================
//  Object IDentifier (OID) Information:  Data Structures and APIs
//==========================================================================

//+-------------------------------------------------------------------------
//  Special ALG_ID's used in CRYPT_OID_INFO
//--------------------------------------------------------------------------
// Algorithm is only implemented in CNG.
const
  CALG_OID_INFO_CNG_ONLY                  = $FFFFFFFF;
  {$EXTERNALSYM CALG_OID_INFO_CNG_ONLY}

// Algorithm is defined in the encoded parameters. Only supported
// using CNG.
const
  CALG_OID_INFO_PARAMETERS                = $FFFFFFFE;
  {$EXTERNALSYM CALG_OID_INFO_PARAMETERS}

// Macro to check for a special ALG_ID used in CRYPT_OID_INFO
function IS_SPECIAL_OID_INFO_ALGID(Algid: ALG_ID): Boolean; inline;
{$EXTERNALSYM IS_SPECIAL_OID_INFO_ALGID}

//+-------------------------------------------------------------------------
// Special CNG Algorithms used in CRYPT_OID_INFO
//--------------------------------------------------------------------------
const
  CRYPT_OID_INFO_HASH_PARAMETERS_ALGORITHM = 'CryptOIDInfoHashParameters';
  {$EXTERNALSYM CRYPT_OID_INFO_HASH_PARAMETERS_ALGORITHM}
  CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM  = 'CryptOIDInfoECCParameters';
  {$EXTERNALSYM CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM}
  CRYPT_OID_INFO_MGF1_PARAMETERS_ALGORITHM = 'CryptOIDInfoMgf1Parameters';
  {$EXTERNALSYM CRYPT_OID_INFO_MGF1_PARAMETERS_ALGORITHM}
  CRYPT_OID_INFO_NO_SIGN_ALGORITHM         = 'CryptOIDInfoNoSign';
  {$EXTERNALSYM CRYPT_OID_INFO_NO_SIGN_ALGORITHM}
  CRYPT_OID_INFO_OAEP_PARAMETERS_ALGORITHM = 'CryptOIDInfoOAEPParameters';
  {$EXTERNALSYM CRYPT_OID_INFO_OAEP_PARAMETERS_ALGORITHM}
  CRYPT_OID_INFO_ECC_WRAP_PARAMETERS_ALGORITHM = 'CryptOIDInfoECCWrapParameters';
  {$EXTERNALSYM CRYPT_OID_INFO_ECC_WRAP_PARAMETERS_ALGORITHM}
  CRYPT_OID_INFO_NO_PARAMETERS_ALGORITHM   = 'CryptOIDInfoNoParameters';
  {$EXTERNALSYM CRYPT_OID_INFO_NO_PARAMETERS_ALGORITHM}

//+-------------------------------------------------------------------------
//  OID Information
//--------------------------------------------------------------------------
type
  PCryptOIDInfo = ^TCryptOIDInfo;
  _CRYPT_OID_INFO = record
    cbSize: DWORD;
    pszOID: LPCSTR;
    pwszName: LPCWSTR;
    case dwGroupId: DWORD of
    0: (dwValue: DWORD);
    1: (Algid: ALG_ID);
    2: (dwLength: DWORD;
    ExtraInfo: TCryptDataBlob;

//{$IFDEF CRYPT_OID_INFO_HAS_EXTRA_FIELDS}
    // Note, if you #define CRYPT_OID_INFO_HAS_EXTRA_FIELDS, then, you
    // must zero all unused fields in this data structure.
    // More fields could be added in a future release.

    // The following 2 fields are set to an empty string, L"", if not defined.

    // This is the Algid string passed to the BCrypt* and NCrypt* APIs
    // defined in bcrypt.h and ncrypt.h.
    //
    // Its only applicable to the following groups:
    //  CRYPT_HASH_ALG_OID_GROUP_ID
    //  CRYPT_ENCRYPT_ALG_OID_GROUP_ID
    //  CRYPT_PUBKEY_ALG_OID_GROUP_ID
    //  CRYPT_SIGN_ALG_OID_GROUP_ID
    pwszCNGAlgid: LPCWSTR;

    // Following is only applicable to the following groups:
    //  CRYPT_SIGN_ALG_OID_GROUP_ID
    //      The public key pwszCNGAlgid. For ECC,
    //      CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM.
    //  CRYPT_PUBKEY_ALG_OID_GROUP_ID
    //      For the ECC algorithms, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM.
    pwszCNGExtraAlgid: LPCWSTR;
//{$ENDIF}
    );
  end;
  {$EXTERNALSYM _CRYPT_OID_INFO}
  CRYPT_OID_INFO = _CRYPT_OID_INFO;
  {$EXTERNALSYM CRYPT_OID_INFO}
  TCryptOIDInfo = _CRYPT_OID_INFO;
  PCRYPT_OID_INFO = PCryptOIDInfo;
  {$EXTERNALSYM PCRYPT_OID_INFO}

type
  PCCryptOIDInfo = ^TCCryptOIDInfo;
  CCRYPT_OID_INFO = CRYPT_OID_INFO;
  {$EXTERNALSYM CCRYPT_OID_INFO}
  TCCryptOIDInfo = CRYPT_OID_INFO;
  PCCRYPT_OID_INFO = PCCryptOIDInfo;
  {$EXTERNALSYM PCCRYPT_OID_INFO}

// certenrolld_begin -- CRYPT_*_OID_GROUP_ID
//+-------------------------------------------------------------------------
//  OID Group IDs
//--------------------------------------------------------------------------
const
  CRYPT_HASH_ALG_OID_GROUP_ID            = 1;
  {$EXTERNALSYM CRYPT_HASH_ALG_OID_GROUP_ID}
  CRYPT_ENCRYPT_ALG_OID_GROUP_ID         = 2;
  {$EXTERNALSYM CRYPT_ENCRYPT_ALG_OID_GROUP_ID}
  CRYPT_PUBKEY_ALG_OID_GROUP_ID          = 3;
  {$EXTERNALSYM CRYPT_PUBKEY_ALG_OID_GROUP_ID}
  CRYPT_SIGN_ALG_OID_GROUP_ID            = 4;
  {$EXTERNALSYM CRYPT_SIGN_ALG_OID_GROUP_ID}
  CRYPT_RDN_ATTR_OID_GROUP_ID            = 5;
  {$EXTERNALSYM CRYPT_RDN_ATTR_OID_GROUP_ID}
  CRYPT_EXT_OR_ATTR_OID_GROUP_ID         = 6;
  {$EXTERNALSYM CRYPT_EXT_OR_ATTR_OID_GROUP_ID}
  CRYPT_ENHKEY_USAGE_OID_GROUP_ID        = 7;
  {$EXTERNALSYM CRYPT_ENHKEY_USAGE_OID_GROUP_ID}
  CRYPT_POLICY_OID_GROUP_ID              = 8;
  {$EXTERNALSYM CRYPT_POLICY_OID_GROUP_ID}
  CRYPT_TEMPLATE_OID_GROUP_ID            = 9;
  {$EXTERNALSYM CRYPT_TEMPLATE_OID_GROUP_ID}
  CRYPT_KDF_OID_GROUP_ID                 = 10;
  {$EXTERNALSYM CRYPT_KDF_OID_GROUP_ID}
  CRYPT_LAST_OID_GROUP_ID                = 10;
  {$EXTERNALSYM CRYPT_LAST_OID_GROUP_ID}

  CRYPT_FIRST_ALG_OID_GROUP_ID           = CRYPT_HASH_ALG_OID_GROUP_ID;
  {$EXTERNALSYM CRYPT_FIRST_ALG_OID_GROUP_ID}
  CRYPT_LAST_ALG_OID_GROUP_ID            = CRYPT_SIGN_ALG_OID_GROUP_ID;
  {$EXTERNALSYM CRYPT_LAST_ALG_OID_GROUP_ID}
// certenrolld_end


// The CRYPT_*_ALG_OID_GROUP_ID's have an Algid. The CRYPT_RDN_ATTR_OID_GROUP_ID
// has a dwLength. The CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
// CRYPT_ENHKEY_USAGE_OID_GROUP_ID, CRYPT_POLICY_OID_GROUP_ID or
// CRYPT_TEMPLATE_OID_GROUP_ID don't have a dwValue.
//

// CRYPT_ENCRYPT_ALG_OID_GROUP_ID has the following optional ExtraInfo
// for AES algorithms:
//  DWORD[0] - dwBitLength

// CRYPT_PUBKEY_ALG_OID_GROUP_ID has the following optional ExtraInfo:
//  DWORD[0] - Flags. CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG can be set to
//             inhibit the reformatting of the signature before
//             CryptVerifySignature is called or after CryptSignHash
//             is called. CRYPT_OID_USE_PUBKEY_PARA_FOR_PKCS7_FLAG can
//             be set to include the public key algorithm's parameters
//             in the PKCS7's digestEncryptionAlgorithm's parameters.
//             CRYPT_OID_NO_NULL_ALGORITHM_PARA_FLAG can be set to omit
//             NULL parameters when encoding.
//
// For the ECC named curve public keys
//  DWORD[1] - BCRYPT_ECCKEY_BLOB dwMagic field value
//  DWORD[2] - dwBitLength. Where BCRYPT_ECCKEY_BLOB's
//             cbKey = dwBitLength / 8 + ((dwBitLength % 8) ? 1 : 0)
//
const
  CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG    = $00000001;
  {$EXTERNALSYM CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG}
  CRYPT_OID_USE_PUBKEY_PARA_FOR_PKCS7_FLAG   = $00000002;
  {$EXTERNALSYM CRYPT_OID_USE_PUBKEY_PARA_FOR_PKCS7_FLAG}
  CRYPT_OID_NO_NULL_ALGORITHM_PARA_FLAG      = $00000004;
  {$EXTERNALSYM CRYPT_OID_NO_NULL_ALGORITHM_PARA_FLAG}

  CRYPT_OID_PUBKEY_SIGN_ONLY_FLAG            = $80000000;
  {$EXTERNALSYM CRYPT_OID_PUBKEY_SIGN_ONLY_FLAG}
  CRYPT_OID_PUBKEY_ENCRYPT_ONLY_FLAG         = $40000000;
  {$EXTERNALSYM CRYPT_OID_PUBKEY_ENCRYPT_ONLY_FLAG}

// CRYPT_SIGN_ALG_OID_GROUP_ID has the following optional ExtraInfo:
//  DWORD[0] - Public Key Algid.
//  DWORD[1] - Flags. Same as above for CRYPT_PUBKEY_ALG_OID_GROUP_ID.
//  DWORD[2] - Optional CryptAcquireContext(CRYPT_VERIFYCONTEXT)'s dwProvType.
//             If omitted or 0, uses Public Key Algid to select
//             appropriate dwProvType for signature verification.

// CRYPT_RDN_ATTR_OID_GROUP_ID has the following optional ExtraInfo:
//  Array of DWORDs:
//   [0 ..] - Null terminated list of acceptable RDN attribute
//            value types. An empty list implies CERT_RDN_PRINTABLE_STRING,
//            CERT_RDN_UNICODE_STRING, 0.

//+-------------------------------------------------------------------------
//  Find OID information. Returns NULL if unable to find any information
//  for the specified key and group. Note, returns a pointer to a constant
//  data structure. The returned pointer MUST NOT be freed.
//
//  dwKeyType's:
//    CRYPT_OID_INFO_OID_KEY, pvKey points to a szOID
//    CRYPT_OID_INFO_NAME_KEY, pvKey points to a wszName
//    CRYPT_OID_INFO_ALGID_KEY, pvKey points to an ALG_ID
//    CRYPT_OID_INFO_SIGN_KEY, pvKey points to an array of two ALG_ID's:
//      ALG_ID[0] - Hash Algid
//      ALG_ID[1] - PubKey Algid
//    CRYPT_OID_INFO_CNG_ALGID_KEY, pvKey points to a wszCNGAlgid
//    CRYPT_OID_INFO_CNG_SIGN_KEY, pvKey is an array of two
//     pwszCNGAlgid's:
//      Algid[0] - Hash pwszCNGAlgid
//      Algid[1] - PubKey pwszCNGAlgid
//
//  For CRYPT_OID_INFO_NAME_KEY, CRYPT_OID_INFO_CNG_ALGID_KEY and
//  CRYPT_OID_INFO_CNG_SIGN_KEY the string comparison is case insensitive.
//
//  Setting dwGroupId to 0, searches all groups according to the dwKeyType.
//  Otherwise, only the dwGroupId is searched.
//--------------------------------------------------------------------------
function CryptFindOIDInfo(
  dwKeyType: DWORD;
  pvKey: Pointer;
  dwGroupId: DWORD): PCCryptOIDInfo; winapi;
{$EXTERNALSYM CryptFindOIDInfo}

const
  CRYPT_OID_INFO_OID_KEY          = 1;
  {$EXTERNALSYM CRYPT_OID_INFO_OID_KEY}
  CRYPT_OID_INFO_NAME_KEY         = 2;
  {$EXTERNALSYM CRYPT_OID_INFO_NAME_KEY}
  CRYPT_OID_INFO_ALGID_KEY        = 3;
  {$EXTERNALSYM CRYPT_OID_INFO_ALGID_KEY}
  CRYPT_OID_INFO_SIGN_KEY         = 4;
  {$EXTERNALSYM CRYPT_OID_INFO_SIGN_KEY}
  CRYPT_OID_INFO_CNG_ALGID_KEY    = 5;
  {$EXTERNALSYM CRYPT_OID_INFO_CNG_ALGID_KEY}
  CRYPT_OID_INFO_CNG_SIGN_KEY     = 6;
  {$EXTERNALSYM CRYPT_OID_INFO_CNG_SIGN_KEY}

// Set the following in the above dwKeyType parameter to restrict public keys
// valid for signing or encrypting
// certenrolld_begin -- CRYPT_*_KEY_FLAG
const
  CRYPT_OID_INFO_OID_KEY_FLAGS_MASK          = $FFFF0000;
  {$EXTERNALSYM CRYPT_OID_INFO_OID_KEY_FLAGS_MASK}
  CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG        = $80000000;
  {$EXTERNALSYM CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG}
  CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG     = $40000000;
  {$EXTERNALSYM CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG}

// The following flag can be set in above dwGroupId parameter to disable
// searching the directory server
const
  CRYPT_OID_DISABLE_SEARCH_DS_FLAG           = $80000000;
  {$EXTERNALSYM CRYPT_OID_DISABLE_SEARCH_DS_FLAG}

//{$IFDEF CRYPT_OID_INFO_HAS_EXTRA_FIELDS}

// The following flag can be set in above dwGroupId parameter to search
// through CRYPT_OID_INFO records. If there are multiple records that meet
// the search criteria, the first record with defined pwszCNGAlgid would be
// returned. If none of the records (meeting the search criteria) have
// pwszCNGAlgid defined, first record (meeting the search criteria) would be
// returned.
const
  CRYPT_OID_PREFER_CNG_ALGID_FLAG            = $40000000;
  {$EXTERNALSYM CRYPT_OID_PREFER_CNG_ALGID_FLAG}

//{$ENDIF}

// certenrolld_end -- CRYPT_*_KEY_FLAG

// The bit length shifted left 16 bits can be OR'ed into the above
// dwGroupId parameter. Only applicable to the CRYPT_ENCRYPT_ALG_OID_GROUP_ID.
// Also, only applicable to encryption algorithms having a dwBitLen ExtraInfo.
// Currently, only the AES encryption algorithms have this.
//
// For example, to find the OIDInfo for BCRYPT_AES_ALGORITHM, bit length 192,
// CryptFindOIDInfo would be called as follows:
//  PCCRYPT_OID_INFO pOIDInfo =
//      CryptFindOIDInfo(
//          CRYPT_OID_INFO_CNG_ALGID_KEY,
//          (void *) BCRYPT_AES_ALGORITHM,
//          CRYPT_ENCRYPT_ALG_OID_GROUP_ID |
//              (192 << CRYPT_OID_INFO_OID_GROUP_BIT_LEN_SHIFT)
//          );
const
  CRYPT_OID_INFO_OID_GROUP_BIT_LEN_MASK      = $0FFF0000;
  {$EXTERNALSYM CRYPT_OID_INFO_OID_GROUP_BIT_LEN_MASK}
  CRYPT_OID_INFO_OID_GROUP_BIT_LEN_SHIFT     = 16;
  {$EXTERNALSYM CRYPT_OID_INFO_OID_GROUP_BIT_LEN_SHIFT}

//+-------------------------------------------------------------------------
//  Register OID information. The OID information specified in the
//  CCRYPT_OID_INFO structure is persisted to the registry.
//
//  crypt32.dll contains information for the commonly known OIDs. This function
//  allows applications to augment crypt32.dll's OID information. During
//  CryptFindOIDInfo's first call, the registered OID information is installed.
//
//  By default the registered OID information is installed after crypt32.dll's
//  OID entries. Set CRYPT_INSTALL_OID_INFO_BEFORE_FLAG to install before.
//--------------------------------------------------------------------------
function CryptRegisterOIDInfo(
  pInfo: PCCryptOIDInfo;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptRegisterOIDInfo}

const
  CRYPT_INSTALL_OID_INFO_BEFORE_FLAG  = 1;
  {$EXTERNALSYM CRYPT_INSTALL_OID_INFO_BEFORE_FLAG}

//+-------------------------------------------------------------------------
//  Unregister OID information. Only the pszOID and dwGroupId fields are
//  used to identify the OID information to be unregistered.
//--------------------------------------------------------------------------
function CryptUnregisterOIDInfo(
  pInfo: PCCryptOIDInfo): BOOL; winapi;
{$EXTERNALSYM CryptUnregisterOIDInfo}

// If the callback returns FALSE, stops the enumeration.
type
  PFN_CRYPT_ENUM_OID_INFO = function(
    pInfo: PCCryptOIDInfo;
    pvArg: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_ENUM_OID_INFO}
  TFnCryptEnumOIDInfo = PFN_CRYPT_ENUM_OID_INFO;

//+-------------------------------------------------------------------------
//  Enumerate the OID information.
//
//  pfnEnumOIDInfo is called for each OID information entry.
//
//  Setting dwGroupId to 0 matches all groups. Otherwise, only enumerates
//  entries in the specified group.
//
//  dwFlags currently isn't used and must be set to 0.
//--------------------------------------------------------------------------
function CryptEnumOIDInfo(
  dwGroupId: DWORD;
  dwFlags: DWORD;
  pvArg: Pointer;
  pfnEnumOIDInfo: TFnCryptEnumOIDInfo): BOOL; winapi;
{$EXTERNALSYM CryptEnumOIDInfo}

//+-------------------------------------------------------------------------
//  Find the localized name for the specified name. For example, find the
//  localized name for the "Root" system store name. A case insensitive
//  string comparison is done.
//
//  Returns NULL if unable to find the the specified name.
//
//  Localized names for the predefined system stores ("Root", "My") and
//  predefined physical stores (".Default", ".LocalMachine") are pre-installed
//  as resource strings in crypt32.dll. CryptSetOIDFunctionValue can be called
//  as follows to register additional localized strings:
//      dwEncodingType = CRYPT_LOCALIZED_NAME_ENCODING_TYPE
//      pszFuncName = CRYPT_OID_FIND_LOCALIZED_NAME_FUNC
//      pszOID = CRYPT_LOCALIZED_NAME_OID
//      pwszValueName = Name to be localized, for example, L"ApplicationStore"
//      dwValueType = REG_SZ
//      pbValueData = pointer to the UNICODE localized string
//      cbValueData = (wcslen(UNICODE localized string) + 1) * sizeof(WCHAR)
//
//  To unregister, set pbValueData to NULL and cbValueData to 0.
//
//  The registered names are searched before the pre-installed names.
//--------------------------------------------------------------------------
function CryptFindLocalizedName(
  pwszCryptName: LPCWSTR): LPCWSTR; winapi;
{$EXTERNALSYM CryptFindLocalizedName}

const
  CRYPT_LOCALIZED_NAME_ENCODING_TYPE = 0;
  {$EXTERNALSYM CRYPT_LOCALIZED_NAME_ENCODING_TYPE}
  CRYPT_LOCALIZED_NAME_OID           = 'LocalizedNames';
  {$EXTERNALSYM CRYPT_LOCALIZED_NAME_OID}

//+=========================================================================
//  Certificate Strong Signature Defines and Data Structures
//==========================================================================
type
  PCertStrongSignSerializedInfo = ^TCertStrongSignSerializedInfo;
  _CERT_STRONG_SIGN_SERIALIZED_INFO = record
    dwFlags: DWORD;
    pwszCNGSignHashAlgids: LPWSTR;
    pwszCNGPubKeyMinBitLengths: LPWSTR;                   // Optional
  end;
  {$EXTERNALSYM _CERT_STRONG_SIGN_SERIALIZED_INFO}
  CERT_STRONG_SIGN_SERIALIZED_INFO = _CERT_STRONG_SIGN_SERIALIZED_INFO;
  {$EXTERNALSYM CERT_STRONG_SIGN_SERIALIZED_INFO}
  TCertStrongSignSerializedInfo = _CERT_STRONG_SIGN_SERIALIZED_INFO;
  PCERT_STRONG_SIGN_SERIALIZED_INFO = PCertStrongSignSerializedInfo;
  {$EXTERNALSYM PCERT_STRONG_SIGN_SERIALIZED_INFO}

const
  CERT_STRONG_SIGN_ECDSA_ALGORITHM         = 'ECDSA';
  {$EXTERNALSYM CERT_STRONG_SIGN_ECDSA_ALGORITHM}

//
// Following CNG Signature Algorithms are supported
//
//  #define BCRYPT_RSA_ALGORITHM                    L"RSA"
//  #define BCRYPT_DSA_ALGORITHM                    L"DSA"
//  #define CERT_STRONG_SIGN_ECDSA_ALGORITHM        L"ECDSA"
//


//
// Following CNG Hash Algorithms are supported
//
//  #define BCRYPT_MD5_ALGORITHM                    L"MD5"
//  #define BCRYPT_SHA1_ALGORITHM                   L"SHA1"
//  #define BCRYPT_SHA256_ALGORITHM                 L"SHA256"
//  #define BCRYPT_SHA384_ALGORITHM                 L"SHA384"
//  #define BCRYPT_SHA512_ALGORITHM                 L"SHA512"
//
const
  CERT_STRONG_SIGN_SERIALIZED_INFO_CHOICE    = 1;
  {$EXTERNALSYM CERT_STRONG_SIGN_SERIALIZED_INFO_CHOICE}
  CERT_STRONG_SIGN_OID_INFO_CHOICE           = 2;
  {$EXTERNALSYM CERT_STRONG_SIGN_OID_INFO_CHOICE}

type
  PCertStrongSignPara = ^TCertStrongSignPara;
  _CERT_STRONG_SIGN_PARA = record
    cbSize: DWORD;

    case dwInfoChoice: DWORD of
    0:
      (pvInfo: Pointer);

    CERT_STRONG_SIGN_SERIALIZED_INFO_CHOICE:
      (pSerializedInfo: PCertStrongSignSerializedInfo);

    CERT_STRONG_SIGN_OID_INFO_CHOICE:
      (pszOID: LPSTR);

  end;
  {$EXTERNALSYM _CERT_STRONG_SIGN_PARA}
  CERT_STRONG_SIGN_PARA = _CERT_STRONG_SIGN_PARA;
  {$EXTERNALSYM CERT_STRONG_SIGN_PARA}
  TCertStrongSignPara = _CERT_STRONG_SIGN_PARA;
  PCERT_STRONG_SIGN_PARA = PCertStrongSignPara;
  {$EXTERNALSYM PCERT_STRONG_SIGN_PARA}
  PCCERT_STRONG_SIGN_PARA = PCertStrongSignPara;
  {$EXTERNALSYM PCCERT_STRONG_SIGN_PARA}

// By default, strong signature checking isn't enabled for either
// CRLs or OCSP responses.
const
  CERT_STRONG_SIGN_ENABLE_CRL_CHECK          = $1;
  {$EXTERNALSYM CERT_STRONG_SIGN_ENABLE_CRL_CHECK}
  CERT_STRONG_SIGN_ENABLE_OCSP_CHECK         = $2;
  {$EXTERNALSYM CERT_STRONG_SIGN_ENABLE_OCSP_CHECK}


//
// OID Strong Sign Parameters used by Windows OS Components
//
const
  szOID_CERT_STRONG_SIGN_OS_PREFIX           = '1.3.6.1.4.1.311.72.1.';
  {$EXTERNALSYM szOID_CERT_STRONG_SIGN_OS_PREFIX}

// OS_1 was supported starting with Windows 8
//   Requires
//     RSA keys >= 2047 or ECDSA >= 256 (DSA not allowed)
//     SHA2 hashes (MD2, MD4, MD5 or SHA1 not allowed)
//   Both CERT_STRONG_SIGN_ENABLE_CRL_CHECK and
//        CERT_STRONG_SIGN_ENABLE_OCSP_CHECK are set
const
  szOID_CERT_STRONG_SIGN_OS_1                = '1.3.6.1.4.1.311.72.1.1';
  {$EXTERNALSYM szOID_CERT_STRONG_SIGN_OS_1}
  szOID_CERT_STRONG_SIGN_OS_CURRENT          = szOID_CERT_STRONG_SIGN_OS_1;
  {$EXTERNALSYM szOID_CERT_STRONG_SIGN_OS_CURRENT}

  CERT_STRONG_SIGN_PARA_OS_1: TCertStrongSignPara = (
    cbSize:SizeOf(TCertStrongSignPara);
    dwInfoChoice:CERT_STRONG_SIGN_OID_INFO_CHOICE;
    pszOID:szOID_CERT_STRONG_SIGN_OS_1);
  {$EXTERNALSYM CERT_STRONG_SIGN_PARA_OS_1}

  CERT_STRONG_SIGN_PARA_OS_CURRENT: TCertStrongSignPara = (
    cbSize:SizeOf(TCertStrongSignPara);
    dwInfoChoice:CERT_STRONG_SIGN_OID_INFO_CHOICE;
    pszOID:szOID_CERT_STRONG_SIGN_OS_CURRENT);
  {$EXTERNALSYM CERT_STRONG_SIGN_PARA_OS_CURRENT}

  szOID_CERT_STRONG_KEY_OS_PREFIX            = '1.3.6.1.4.1.311.72.2.';
  {$EXTERNALSYM szOID_CERT_STRONG_KEY_OS_PREFIX}

// OS_1 was supported starting with Windows 8
//   Requires
//     RSA keys >= 2047 or ECDSA >= 256 (DSA not allowed)
//     SHA1 or SHA2 hashes  (MD2, MD4 or MD5 not allowed)
//   Both CERT_STRONG_SIGN_ENABLE_CRL_CHECK and
//        CERT_STRONG_SIGN_ENABLE_OCSP_CHECK are set
const
  szOID_CERT_STRONG_KEY_OS_1                 = '1.3.6.1.4.1.311.72.2.1';
  {$EXTERNALSYM szOID_CERT_STRONG_KEY_OS_1}
  szOID_CERT_STRONG_KEY_OS_CURRENT           = szOID_CERT_STRONG_KEY_OS_1;
  {$EXTERNALSYM szOID_CERT_STRONG_KEY_OS_CURRENT}

  CERT_STRONG_KEY_PARA_OS_1: TCertStrongSignPara = (
    cbSize:SizeOf(TCertStrongSignPara);
    dwInfoChoice:CERT_STRONG_SIGN_OID_INFO_CHOICE;
    pszOID:szOID_CERT_STRONG_KEY_OS_1);
  {$EXTERNALSYM CERT_STRONG_KEY_PARA_OS_1}

  CERT_STRONG_KEY_PARA_OS_CURRENT: TCertStrongSignPara = (
    cbSize:SizeOf(TCertStrongSignPara);
    dwInfoChoice:CERT_STRONG_SIGN_OID_INFO_CHOICE;
    pszOID:szOID_CERT_STRONG_KEY_OS_CURRENT);
 {$EXTERNALSYM CERT_STRONG_KEY_PARA_OS_CURRENT}

//+=========================================================================
//  Low Level Cryptographic Message Data Structures and APIs
//==========================================================================
type
  HCRYPTMSG = Pointer;
  {$EXTERNALSYM HCRYPTMSG}

const
  szOID_PKCS_7_DATA               = '1.2.840.113549.1.7.1';
  {$EXTERNALSYM szOID_PKCS_7_DATA}
  szOID_PKCS_7_SIGNED             = '1.2.840.113549.1.7.2';
  {$EXTERNALSYM szOID_PKCS_7_SIGNED}
  szOID_PKCS_7_ENVELOPED          = '1.2.840.113549.1.7.3';
  {$EXTERNALSYM szOID_PKCS_7_ENVELOPED}
  szOID_PKCS_7_SIGNEDANDENVELOPED = '1.2.840.113549.1.7.4';
  {$EXTERNALSYM szOID_PKCS_7_SIGNEDANDENVELOPED}
  szOID_PKCS_7_DIGESTED           = '1.2.840.113549.1.7.5';
  {$EXTERNALSYM szOID_PKCS_7_DIGESTED}
  szOID_PKCS_7_ENCRYPTED          = '1.2.840.113549.1.7.6';
  {$EXTERNALSYM szOID_PKCS_7_ENCRYPTED}

  szOID_PKCS_9_CONTENT_TYPE       = '1.2.840.113549.1.9.3';
  {$EXTERNALSYM szOID_PKCS_9_CONTENT_TYPE}
  szOID_PKCS_9_MESSAGE_DIGEST     = '1.2.840.113549.1.9.4';
  {$EXTERNALSYM szOID_PKCS_9_MESSAGE_DIGEST}

//+-------------------------------------------------------------------------
//  Message types
//--------------------------------------------------------------------------
const
  CMSG_DATA                   = 1;
  {$EXTERNALSYM CMSG_DATA}
  CMSG_SIGNED                 = 2;
  {$EXTERNALSYM CMSG_SIGNED}
  CMSG_ENVELOPED              = 3;
  {$EXTERNALSYM CMSG_ENVELOPED}
  CMSG_SIGNED_AND_ENVELOPED   = 4;
  {$EXTERNALSYM CMSG_SIGNED_AND_ENVELOPED}
  CMSG_HASHED                 = 5;
  {$EXTERNALSYM CMSG_HASHED}
  CMSG_ENCRYPTED              = 6;
  {$EXTERNALSYM CMSG_ENCRYPTED}

//+-------------------------------------------------------------------------
//  Message Type Bit Flags
//--------------------------------------------------------------------------
const
  CMSG_ALL_FLAGS                  = not Cardinal(0);
  {$EXTERNALSYM CMSG_ALL_FLAGS}
  CMSG_DATA_FLAG                  = (1 shl CMSG_DATA);
  {$EXTERNALSYM CMSG_DATA_FLAG}
  CMSG_SIGNED_FLAG                = (1 shl CMSG_SIGNED);
  {$EXTERNALSYM CMSG_SIGNED_FLAG}
  CMSG_ENVELOPED_FLAG             = (1 shl CMSG_ENVELOPED);
  {$EXTERNALSYM CMSG_ENVELOPED_FLAG}
  CMSG_SIGNED_AND_ENVELOPED_FLAG  = (1 shl CMSG_SIGNED_AND_ENVELOPED);
  {$EXTERNALSYM CMSG_SIGNED_AND_ENVELOPED_FLAG}
  CMSG_HASHED_FLAG                = (1 shl CMSG_HASHED);
  {$EXTERNALSYM CMSG_HASHED_FLAG}
  CMSG_ENCRYPTED_FLAG             = (1 shl CMSG_ENCRYPTED);
  {$EXTERNALSYM CMSG_ENCRYPTED_FLAG}

//+-------------------------------------------------------------------------
//  Certificate Issuer and SerialNumber
//--------------------------------------------------------------------------
type
  PCertIssuerSerialNumber = ^TCertIssuerSerialNumber;
  _CERT_ISSUER_SERIAL_NUMBER = record
    Issuer: TCertNameBlob;
    SerialNumber: TCryptIntegerBlob;
  end;
  {$EXTERNALSYM _CERT_ISSUER_SERIAL_NUMBER}
  CERT_ISSUER_SERIAL_NUMBER = _CERT_ISSUER_SERIAL_NUMBER;
  {$EXTERNALSYM CERT_ISSUER_SERIAL_NUMBER}
  TCertIssuerSerialNumber = _CERT_ISSUER_SERIAL_NUMBER;
  PCERT_ISSUER_SERIAL_NUMBER = PCertIssuerSerialNumber;
  {$EXTERNALSYM PCERT_ISSUER_SERIAL_NUMBER}

//+-------------------------------------------------------------------------
//  Certificate Identifier
//--------------------------------------------------------------------------
const
  CERT_ID_ISSUER_SERIAL_NUMBER   = 1;
  {$EXTERNALSYM CERT_ID_ISSUER_SERIAL_NUMBER}
  CERT_ID_KEY_IDENTIFIER         = 2;
  {$EXTERNALSYM CERT_ID_KEY_IDENTIFIER}
  CERT_ID_SHA1_HASH              = 3;
  {$EXTERNALSYM CERT_ID_SHA1_HASH}

type
  PCertID = ^TCertID;
  _CERT_ID = record
    case dwIdChoice: DWORD of
    CERT_ID_ISSUER_SERIAL_NUMBER:
      (IssuerSerialNumber: TCertIssuerSerialNumber);
    CERT_ID_KEY_IDENTIFIER:
      (KeyId: TCryptHashBlob);
    CERT_ID_SHA1_HASH:
      (HashId: TCryptHashBlob);
  end;
  {$EXTERNALSYM _CERT_ID}
  CERT_ID = _CERT_ID;
  {$EXTERNALSYM CERT_ID}
  TCertID = _CERT_ID;
  PCERT_ID = PCertID;
  {$EXTERNALSYM PCERT_ID}

//+-------------------------------------------------------------------------
//  The message encode information (pvMsgEncodeInfo) is message type dependent
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_DATA: pvMsgEncodeInfo = NULL
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_SIGNED
//
//  The pCertInfo in the CMSG_SIGNER_ENCODE_INFO provides the Issuer, SerialNumber
//  and PublicKeyInfo.Algorithm. The PublicKeyInfo.Algorithm implicitly
//  specifies the HashEncryptionAlgorithm to be used.
//
//  If the SignerId is present with a nonzero dwIdChoice its used instead
//  of the Issuer and SerialNumber in pCertInfo.
//
//  CMS supports the KEY_IDENTIFIER and ISSUER_SERIAL_NUMBER CERT_IDs. PKCS #7
//  version 1.5 only supports the ISSUER_SERIAL_NUMBER CERT_ID choice.
//
//  If HashEncryptionAlgorithm is present and not NULL its used instead of
//  the PublicKeyInfo.Algorithm.
//
//  Note, for RSA, the hash encryption algorithm is normally the same as
//  the public key algorithm. For DSA, the hash encryption algorithm is
//  normally a DSS signature algorithm.
//
//  pvHashEncryptionAuxInfo currently isn't used and must be set to NULL if
//  present in the data structure.
//
//  The hCryptProv and dwKeySpec specify the private key to use. If dwKeySpec
//  == 0, then, defaults to AT_SIGNATURE.
//
//  If the HashEncryptionAlgorithm is set to szOID_PKIX_NO_SIGNATURE, then,
//  the signature value only contains the hash octets. hCryptProv must still
//  be specified. However, since a private key isn't used the hCryptProv can be
//  acquired using CRYPT_VERIFYCONTEXT.
//
//  If CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags
//  passed to CryptMsgOpenToEncode(), the signer hCryptProv's are released.
//
//  For CNG, this applies to the hNCryptKey.
//
//  pvHashAuxInfo currently isn't used and must be set to NULL.
//
//  CMS signed messages allow the inclusion of Attribute Certs.
//--------------------------------------------------------------------------
type
  PCMsgSignerEncodeInfo = ^TCMsgSignerEncodeInfo;
  _CMSG_SIGNER_ENCODE_INFO = record
    cbSize: DWORD;
    pCertInfo: PCertInfo;

    // NCryptIsKeyHandle() is called to determine the union choice.
    case Integer of
    0: (hCryptProv: HCRYPTPROV);
    1: (hNCryptKey: NCRYPT_KEY_HANDLE;
    // not applicable for hNCryptKey choice
    dwKeySpec: DWORD;

    HashAlgorithm: TCryptAlgorithmIdentifier;
    pvHashAuxInfo: Pointer;
    cAuthAttr: DWORD;
    rgAuthAttr: PCryptAttribute;
    cUnauthAttr: DWORD;
    rgUnauthAttr: PCryptAttribute;

//{$IFDEF CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS}
    SignerId: TCertID;

    // This is also referred to as the SignatureAlgorithm
    HashEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvHashEncryptionAuxInfo: Pointer
//{$ENDIF}
    );
  end;
  {$EXTERNALSYM _CMSG_SIGNER_ENCODE_INFO}
  CMSG_SIGNER_ENCODE_INFO = _CMSG_SIGNER_ENCODE_INFO;
  {$EXTERNALSYM CMSG_SIGNER_ENCODE_INFO}
  TCMsgSignerEncodeInfo = _CMSG_SIGNER_ENCODE_INFO;
  PCMSG_SIGNER_ENCODE_INFO = PCMsgSignerEncodeInfo;
  {$EXTERNALSYM PCMSG_SIGNER_ENCODE_INFO}

type
  PCMsgSignedEncodeInfo = ^TCMsgSignedEncodeInfo;
  _CMSG_SIGNED_ENCODE_INFO = record
    cbSize: DWORD;
    cSigners: DWORD;
    rgSigners: PCMsgSignerEncodeInfo;
    cCertEncoded: DWORD;
    rgCertEncoded: PCertBlob;
    cCrlEncoded: DWORD;
    rgCrlEncoded: PCRLBlob;

//{$IFDEF CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS}
    cAttrCertEncoded: DWORD;
    rgAttrCertEncoded: PCertBlob;
//{$ENDIF}
  end;
  {$EXTERNALSYM _CMSG_SIGNED_ENCODE_INFO}
  CMSG_SIGNED_ENCODE_INFO = _CMSG_SIGNED_ENCODE_INFO;
  {$EXTERNALSYM CMSG_SIGNED_ENCODE_INFO}
  TCMsgSignedEncodeInfo = _CMSG_SIGNED_ENCODE_INFO;
  PCMSG_SIGNED_ENCODE_INFO = PCMsgSignedEncodeInfo;
  {$EXTERNALSYM PCMSG_SIGNED_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  CMSG_ENVELOPED
//
//  The PCERT_INFO for the rgRecipients provides the Issuer, SerialNumber
//  and PublicKeyInfo. The PublicKeyInfo.Algorithm implicitly
//  specifies the KeyEncryptionAlgorithm to be used.
//
//  The PublicKeyInfo.PublicKey in PCERT_INFO is used to encrypt the content
//  encryption key for the recipient.
//
//  hCryptProv is used to do the content encryption, recipient key encryption
//  and export. The hCryptProv's private keys aren't used. If hCryptProv
//  is NULL, a default hCryptProv is chosen according to the
//  ContentEncryptionAlgorithm and the first recipient KeyEncryptionAlgorithm.
//
//  If CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags
//  passed to CryptMsgOpenToEncode(), the envelope's hCryptProv is released.
//
//  Note: CAPI currently doesn't support more than one KeyEncryptionAlgorithm
//  per provider. This will need to be fixed.
//
//  Currently, pvEncryptionAuxInfo is only defined for RC2 or RC4 encryption
//  algorithms. Otherwise, its not used and must be set to NULL.
//  See CMSG_RC2_AUX_INFO for the RC2 encryption algorithms.
//  See CMSG_RC4_AUX_INFO for the RC4 encryption algorithms.
//
//  To enable SP3 compatible encryption, pvEncryptionAuxInfo should point to
//  a CMSG_SP3_COMPATIBLE_AUX_INFO data structure.
//
//  To enable the CMS envelope enhancements, rgpRecipients must be set to
//  NULL, and rgCmsRecipients updated to point to an array of
//  CMSG_RECIPIENT_ENCODE_INFO's.
//
//  Also, CMS envelope enhancements support the inclusion of a bag of
//  Certs, CRLs, Attribute Certs and/or Unprotected Attributes.
//
//  AES ContentEncryption and ECC KeyAgreement recipients are only supported
//  via CNG. DH KeyAgreement or mail list recipients are only supported via
//  CAPI1. SP3 compatible encryption and RC4 are only supported via CAPI1.
//
//  For an RSA recipient identified via PCERT_INFO, for AES ContentEncryption,
//  szOID_RSAES_OAEP will be implicitly used for the KeyEncryptionAlgorithm.
//--------------------------------------------------------------------------

const
  CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE        = 1;
  {$EXTERNALSYM CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE}
  CMSG_KEY_AGREE_STATIC_KEY_CHOICE           = 2;
  {$EXTERNALSYM CMSG_KEY_AGREE_STATIC_KEY_CHOICE}

const
  CMSG_MAIL_LIST_HANDLE_KEY_CHOICE   = 1;
  {$EXTERNALSYM CMSG_MAIL_LIST_HANDLE_KEY_CHOICE}

const
  CMSG_KEY_TRANS_RECIPIENT        = 1;
  {$EXTERNALSYM CMSG_KEY_TRANS_RECIPIENT}
  CMSG_KEY_AGREE_RECIPIENT        = 2;
  {$EXTERNALSYM CMSG_KEY_AGREE_RECIPIENT}
  CMSG_MAIL_LIST_RECIPIENT        = 3;
  {$EXTERNALSYM CMSG_MAIL_LIST_RECIPIENT}

type
  PCMsgRecipientEncodeInfo = ^TCMsgRecipientEncodeInfo;

  PCMsgEnvelopedEncodeInfo = ^TCMsgEnvelopedEncodeInfo;
  _CMSG_ENVELOPED_ENCODE_INFO = record
    cbSize: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    ContentEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvEncryptionAuxInfo: Pointer;
    cRecipients: DWORD;

    // The following array may only be used for transport recipients identified
    // by their IssuereAndSerialNumber. If rgpRecipients != NULL, then,
    // the rgCmsRecipients must be NULL.
    rgpRecipients: ^PCertInfo;

//{$IFDEF CMSG_ENVELOPED_ENCODE_INFO_HAS_CMS_FIELDS}
    // If rgCmsRecipients != NULL, then, the above rgpRecipients must be
    // NULL.
    rgCmsRecipients: PCMsgRecipientEncodeInfo;
    cCertEncoded: DWORD;
    rgCertEncoded: PCertBlob;
    cCrlEncoded: DWORD;
    rgCrlEncoded: PCRLBlob;
    cAttrCertEncoded: DWORD;
    rgAttrCertEncoded: PCertBlob;
    cUnprotectedAttr: DWORD;
    rgUnprotectedAttr: PCryptAttribute;
//{$ENDIF}
  end;
  {$EXTERNALSYM _CMSG_ENVELOPED_ENCODE_INFO}
  CMSG_ENVELOPED_ENCODE_INFO = _CMSG_ENVELOPED_ENCODE_INFO;
  {$EXTERNALSYM CMSG_ENVELOPED_ENCODE_INFO}
  TCMsgEnvelopedEncodeInfo = _CMSG_ENVELOPED_ENCODE_INFO;
  PCMSG_ENVELOPED_ENCODE_INFO = PCMsgEnvelopedEncodeInfo;
  {$EXTERNALSYM PCMSG_ENVELOPED_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  Key Transport Recipient Encode Info
//
//  hCryptProv is used to do the recipient key encryption
//  and export. The hCryptProv's private keys aren't used.
//
//  If hCryptProv is NULL, then, the hCryptProv specified in
//  CMSG_ENVELOPED_ENCODE_INFO is used.
//
//  Note, even if CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags
//  passed to CryptMsgOpenToEncode(), this hCryptProv isn't released.
//
//  CMS supports the KEY_IDENTIFIER and ISSUER_SERIAL_NUMBER CERT_IDs. PKCS #7
//  version 1.5 only supports the ISSUER_SERIAL_NUMBER CERT_ID choice.
//
//  For RSA AES, KeyEncryptionAlgorithm.pszObjId should be set to
//  szOID_RSAES_OAEP. KeyEncryptionAlgorithm.Parameters should be set
//  to the encoded PKCS_RSAES_OAEP_PARAMETERS. If
//  KeyEncryptionAlgorithm.Parameters.cbData == 0, then, the default
//  parameters are used and encoded.
//--------------------------------------------------------------------------

  PCMsgKeyTransRecipientEncodeInfo = ^TCMsgKeyTransRecipientEncodeInfo;
  _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO = record
    cbSize: DWORD;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvKeyEncryptionAuxInfo: Pointer;
    hCryptProv: HCRYPTPROV_LEGACY;
    RecipientPublicKey: TCryptBitBlob;
    RecipientId: TCertID;
  end;
  {$EXTERNALSYM _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO}
  CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO = _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO;
  {$EXTERNALSYM CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO}
  TCMsgKeyTransRecipientEncodeInfo = _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO;
  PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO = PCMsgKeyTransRecipientEncodeInfo;
  {$EXTERNALSYM PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  Key Agreement Recipient Encode Info
//
//  If hCryptProv is NULL, then, the hCryptProv specified in
//  CMSG_ENVELOPED_ENCODE_INFO is used.
//
//  For the CMSG_KEY_AGREE_STATIC_KEY_CHOICE, both the hCryptProv and
//  dwKeySpec must be specified to select the sender's private key.
//
//  Note, even if CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags
//  passed to CryptMsgOpenToEncode(), this hCryptProv isn't released.
//
//  CMS supports the KEY_IDENTIFIER and ISSUER_SERIAL_NUMBER CERT_IDs.
//
//  There is 1 key choice, ephemeral originator. The originator's ephemeral
//  key is generated using the public key algorithm parameters shared
//  amongst all the recipients.
//
//  There are 2 key choices: ephemeral originator or static sender. The
//  originator's ephemeral key is generated using the public key algorithm
//  parameters shared amongst all the recipients. For the static sender its
//  private key is used. The hCryptProv and dwKeySpec specify the private key.
//  The pSenderId identifies the certificate containing the sender's public key.
//
//  Currently, pvKeyEncryptionAuxInfo isn't used and must be set to NULL.
//
//  If KeyEncryptionAlgorithm.Parameters.cbData == 0, then, its Parameters
//  are updated with the encoded KeyWrapAlgorithm.
//
//  Currently, pvKeyWrapAuxInfo is only defined for algorithms with
//  RC2. Otherwise, its not used and must be set to NULL.
//  When set for RC2 algorithms, points to a CMSG_RC2_AUX_INFO containing
//  the RC2 effective key length.
//
//  Note, key agreement recipients are not supported in PKCS #7 version 1.5.
//
//  For the ECC szOID_DH_SINGLE_PASS_STDDH_SHA1_KDF KeyEncryptionAlgorithm
//  the CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE must be specified.
//--------------------------------------------------------------------------

  PCMsgRecipientEncryptedKeyEncodeInfo = ^TCMsgRecipientEncryptedKeyEncodeInfo;
  _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO = record
    cbSize: DWORD;
    RecipientPublicKey: TCryptBitBlob;
    RecipientId: TCertID;

    // Following fields are optional and only applicable to KEY_IDENTIFIER
    // CERT_IDs.
    Date: TFileTime;
    pOtherAttr: PCryptAttributeTypeValue;
  end;
  {$EXTERNALSYM _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO}
  CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO = _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO;
  {$EXTERNALSYM CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO}
  TCMsgRecipientEncryptedKeyEncodeInfo = _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO;
  PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO = PCMsgRecipientEncryptedKeyEncodeInfo;
  {$EXTERNALSYM PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO}

  PCMsgKeyAgreeRecipientEncodeInfo = ^TCMsgKeyAgreeRecipientEncodeInfo;
  _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO = record
    cbSize: DWORD;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvKeyEncryptionAuxInfo: Pointer;
    KeyWrapAlgorithm: TCryptAlgorithmIdentifier;
    pvKeyWrapAuxInfo: Pointer;

    // The following hCryptProv and dwKeySpec must be specified for the
    // CMSG_KEY_AGREE_STATIC_KEY_CHOICE.
    //
    // For CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE, dwKeySpec isn't applicable
    // and hCryptProv is optional.

    hCryptProv: HCRYPTPROV_LEGACY;
    dwKeySpec: DWORD;

    case dwKeyChoice: DWORD of
    CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE:
      //
      // The ephemeral public key algorithm and parameters.
      (pEphemeralAlgorithm: PCryptAlgorithmIdentifier);

    CMSG_KEY_AGREE_STATIC_KEY_CHOICE:
      //
      // The CertId of the sender's certificate
      (pSenderId: PCertID;
    UserKeyingMaterial: TCryptDataBlob;                  // OPTIONAL

    cRecipientEncryptedKeys: DWORD;
    rgpRecipientEncryptedKeys: ^PCMsgRecipientEncryptedKeyEncodeInfo
    )
  end;
  {$EXTERNALSYM _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO}
  CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO = _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO;
  {$EXTERNALSYM CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO}
  TCMsgKeyAgreeRecipientEncodeInfo = _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO;
  PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO = PCMsgKeyAgreeRecipientEncodeInfo;
  {$EXTERNALSYM PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  Mail List Recipient Encode Info
//
//  There is 1 choice for the KeyEncryptionKey: an already created CSP key
//  handle. For the key handle choice, hCryptProv must be nonzero. This key
//  handle isn't destroyed.
//
//  Note, even if CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags
//  passed to CryptMsgOpenToEncode(), this hCryptProv isn't released.
//
//  Currently, pvKeyEncryptionAuxInfo is only defined for RC2 key wrap
//  algorithms. Otherwise, its not used and must be set to NULL.
//  When set for RC2 algorithms, points to a CMSG_RC2_AUX_INFO containing
//  the RC2 effective key length.
//
//  Note, mail list recipients are not supported in PKCS #7 version 1.5.
//
//  Mail list recipients aren't supported using CNG.
//--------------------------------------------------------------------------

  PCMsgMailListRecipientEncodeInfo = ^TCMsgMailListRecipientEncodeInfo;
  _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO = record
    cbSize: DWORD;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvKeyEncryptionAuxInfo: Pointer;
    hCryptProv:    HCRYPTPROV;
    case dwKeyChoice: DWORD of
    CMSG_MAIL_LIST_HANDLE_KEY_CHOICE:
      (hKeyEncryptionKey: HCRYPTKEY);
    0:
      // Reserve space for a potential pointer choice
      (pvKeyEncryptionKey: Pointer;
    KeyId: TCryptDataBlob;

    // Following fields are optional.
    Date: TFileTime;
    pOtherAttr: PCryptAttributeTypeValue)
  end;
  {$EXTERNALSYM _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO}
  CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO = _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO;
  {$EXTERNALSYM CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO}
  TCMsgMailListRecipientEncodeInfo = _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO;
  PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO = PCMsgMailListRecipientEncodeInfo;
  {$EXTERNALSYM PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  Recipient Encode Info
//
//  Note, only key transport recipients are supported in PKCS #7 version 1.5.
//--------------------------------------------------------------------------

  _CMSG_RECIPIENT_ENCODE_INFO = record
    case dwRecipientChoice: DWORD of
    CMSG_KEY_TRANS_RECIPIENT:
      (pKeyTrans: PCMsgKeyTransRecipientEncodeInfo);
    CMSG_KEY_AGREE_RECIPIENT:
      (pKeyAgree: PCMsgKeyAgreeRecipientEncodeInfo);
    CMSG_MAIL_LIST_RECIPIENT:
      (pMailList: PCMsgMailListRecipientEncodeInfo);
  end;
  {$EXTERNALSYM _CMSG_RECIPIENT_ENCODE_INFO}
  CMSG_RECIPIENT_ENCODE_INFO = _CMSG_RECIPIENT_ENCODE_INFO;
  {$EXTERNALSYM CMSG_RECIPIENT_ENCODE_INFO}
  TCMsgRecipientEncodeInfo = _CMSG_RECIPIENT_ENCODE_INFO;
  PCMSG_RECIPIENT_ENCODE_INFO = PCMsgRecipientEncodeInfo;
  {$EXTERNALSYM PCMSG_RECIPIENT_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  CMSG_RC2_AUX_INFO
//
//  AuxInfo for RC2 encryption algorithms. The pvEncryptionAuxInfo field
//  in CMSG_ENCRYPTED_ENCODE_INFO should be updated to point to this
//  structure. If not specified, defaults to 40 bit.
//
//  Note, this AuxInfo is only used when, the ContentEncryptionAlgorithm's
//  Parameter.cbData is zero. Otherwise, the Parameters is decoded to
//  get the bit length.
//
//  If CMSG_SP3_COMPATIBLE_ENCRYPT_FLAG is set in dwBitLen, then, SP3
//  compatible encryption is done and the bit length is ignored.
//--------------------------------------------------------------------------
type
  PCMsgRC2AuxInfo = ^TCMsgRC2AuxInfo;
  _CMSG_RC2_AUX_INFO = record
    cbSize: DWORD;
    dwBitLen: DWORD;
  end;
  {$EXTERNALSYM _CMSG_RC2_AUX_INFO}
  CMSG_RC2_AUX_INFO = _CMSG_RC2_AUX_INFO;
  {$EXTERNALSYM CMSG_RC2_AUX_INFO}
  TCMsgRC2AuxInfo = _CMSG_RC2_AUX_INFO;
  PCMSG_RC2_AUX_INFO = PCMsgRC2AuxInfo;
  {$EXTERNALSYM PCMSG_RC2_AUX_INFO}

//+-------------------------------------------------------------------------
//  CMSG_SP3_COMPATIBLE_AUX_INFO
//
//  AuxInfo for enabling SP3 compatible encryption.
//
//  The CMSG_SP3_COMPATIBLE_ENCRYPT_FLAG is set in dwFlags to enable SP3
//  compatible encryption. When set, uses zero salt instead of no salt,
//  the encryption algorithm parameters are NULL instead of containing the
//  encoded RC2 parameters or encoded IV octet string and the encrypted
//  symmetric key is encoded little endian instead of big endian.
//
//  SP3 compatible encryption isn't supported using CNG.
//--------------------------------------------------------------------------
type
  PCMsgSP3CompatibleAuxInfo = ^TCMsgSP3CompatibleAuxInfo;
  _CMSG_SP3_COMPATIBLE_AUX_INFO = record
    cbSize: DWORD;
    dwFlags: DWORD;
  end;
  {$EXTERNALSYM _CMSG_SP3_COMPATIBLE_AUX_INFO}
  CMSG_SP3_COMPATIBLE_AUX_INFO = _CMSG_SP3_COMPATIBLE_AUX_INFO;
  {$EXTERNALSYM CMSG_SP3_COMPATIBLE_AUX_INFO}
  TCMsgSP3CompatibleAuxInfo = _CMSG_SP3_COMPATIBLE_AUX_INFO;
  PCMSG_SP3_COMPATIBLE_AUX_INFO = PCMsgSP3CompatibleAuxInfo;
  {$EXTERNALSYM PCMSG_SP3_COMPATIBLE_AUX_INFO}

const
  CMSG_SP3_COMPATIBLE_ENCRYPT_FLAG   = $80000000;
  {$EXTERNALSYM CMSG_SP3_COMPATIBLE_ENCRYPT_FLAG}

//+-------------------------------------------------------------------------
//  CMSG_RC4_AUX_INFO
//
//  AuxInfo for RC4 encryption algorithms. The pvEncryptionAuxInfo field
//  in CMSG_ENCRYPTED_ENCODE_INFO should be updated to point to this
//  structure. If not specified, uses the CSP's default bit length with no
//  salt. Note, the base CSP has a 40 bit default and the enhanced CSP has
//  a 128 bit default.
//
//  If CMSG_RC4_NO_SALT_FLAG is set in dwBitLen, then, no salt is generated.
//  Otherwise, (128 - dwBitLen)/8 bytes of salt are generated and encoded
//  as an OCTET STRING in the algorithm parameters field.
//
//  RC4 isn't supported using CNG.
//--------------------------------------------------------------------------
type
  PCMsgRC4AuxInfo = ^TCMsgRC4AuxInfo;
  _CMSG_RC4_AUX_INFO = record
    cbSize: DWORD;
    dwBitLen: DWORD;
  end;
  {$EXTERNALSYM _CMSG_RC4_AUX_INFO}
  CMSG_RC4_AUX_INFO = _CMSG_RC4_AUX_INFO;
  {$EXTERNALSYM CMSG_RC4_AUX_INFO}
  TCMsgRC4AuxInfo = _CMSG_RC4_AUX_INFO;
  PCMSG_RC4_AUX_INFO = PCMsgRC4AuxInfo;
  {$EXTERNALSYM PCMSG_RC4_AUX_INFO}

const
  CMSG_RC4_NO_SALT_FLAG              = $40000000;
  {$EXTERNALSYM CMSG_RC4_NO_SALT_FLAG}

//+-------------------------------------------------------------------------
//  CMSG_SIGNED_AND_ENVELOPED
//
//  For PKCS #7, a signed and enveloped message doesn't have the
//  signer's authenticated or unauthenticated attributes. Otherwise, a
//  combination of the CMSG_SIGNED_ENCODE_INFO and CMSG_ENVELOPED_ENCODE_INFO.
//--------------------------------------------------------------------------
type
  PCMsgSignedAndEnvelopedEncodeInfo = ^TCMsgSignedAndEnvelopedEncodeInfo;
  _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO = record
    cbSize: DWORD;
    SignedInfo: TCMsgSignedEncodeInfo;
    EnvelopedInfo: TCMsgEnvelopedEncodeInfo;
  end;
  {$EXTERNALSYM _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO}
  CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO = _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO;
  {$EXTERNALSYM CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO}
  TCMsgSignedAndEnvelopedEncodeInfo = _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO;
  PCMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO = PCMsgSignedAndEnvelopedEncodeInfo;
  {$EXTERNALSYM PCMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  CMSG_HASHED
//
//  hCryptProv is used to do the hash. Doesn't need to use a private key.
//
//  If CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags
//  passed to CryptMsgOpenToEncode(), the hCryptProv is released.
//
//  IN LH, the hCryptProv isn't used. However, its still released if the
//  above flag is set.
//
//  If fDetachedHash is set, then, the encoded message doesn't contain
//  any content (its treated as NULL Data)
//
//  pvHashAuxInfo currently isn't used and must be set to NULL.
//--------------------------------------------------------------------------
type
  PCMsgHashedEncodeInfo = ^TCMsgHashedEncodeInfo;
  _CMSG_HASHED_ENCODE_INFO = record
    cbSize: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    HashAlgorithm: TCryptAlgorithmIdentifier;
    pvHashAuxInfo: Pointer;
  end;
  {$EXTERNALSYM _CMSG_HASHED_ENCODE_INFO}
  CMSG_HASHED_ENCODE_INFO = _CMSG_HASHED_ENCODE_INFO;
  {$EXTERNALSYM CMSG_HASHED_ENCODE_INFO}
  TCMsgHashedEncodeInfo = _CMSG_HASHED_ENCODE_INFO;
  PCMSG_HASHED_ENCODE_INFO = PCMsgHashedEncodeInfo;
  {$EXTERNALSYM PCMSG_HASHED_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  CMSG_ENCRYPTED
//
//  The key used to encrypt the message is identified outside of the message
//  content (for example, password).
//
//  The content input to CryptMsgUpdate has already been encrypted.
//
//  pvEncryptionAuxInfo currently isn't used and must be set to NULL.
//--------------------------------------------------------------------------
type
  PCMsgEncryptedEncodeInfo = ^TCMsgEncryptedEncodeInfo;
  _CMSG_ENCRYPTED_ENCODE_INFO = record
    cbSize: DWORD;
    ContentEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvEncryptionAuxInfo: Pointer;
  end;
  {$EXTERNALSYM _CMSG_ENCRYPTED_ENCODE_INFO}
  CMSG_ENCRYPTED_ENCODE_INFO = _CMSG_ENCRYPTED_ENCODE_INFO;
  {$EXTERNALSYM CMSG_ENCRYPTED_ENCODE_INFO}
  TCMsgEncryptedEncodeInfo = _CMSG_ENCRYPTED_ENCODE_INFO;
  PCMSG_ENCRYPTED_ENCODE_INFO = PCMsgEncryptedEncodeInfo;
  {$EXTERNALSYM PCMSG_ENCRYPTED_ENCODE_INFO}

//+-------------------------------------------------------------------------
//  This parameter allows messages to be of variable length with streamed
//  output.
//
//  By default, messages are of a definite length and
//  CryptMsgGetParam(CMSG_CONTENT_PARAM) is
//  called to get the cryptographically processed content. Until closed,
//  the handle keeps a copy of the processed content.
//
//  With streamed output, the processed content can be freed as its streamed.
//
//  If the length of the content to be updated is known at the time of the
//  open, then, ContentLength should be set to that length. Otherwise, it
//  should be set to CMSG_INDEFINITE_LENGTH.
//--------------------------------------------------------------------------
type
  PFN_CMSG_STREAM_OUTPUT = function(
    pvArg: Pointer;
    pbData: PByte;
    cbData: DWORD;
    fFinal: BOOL): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_STREAM_OUTPUT}
  TFnCMsgStreamOutput = PFN_CMSG_STREAM_OUTPUT;

const
  CMSG_INDEFINITE_LENGTH      = ($FFFFFFFF);
  {$EXTERNALSYM CMSG_INDEFINITE_LENGTH}

type
  PCMsgStreamInfo = ^TCMsgStreamInfo;
  _CMSG_STREAM_INFO = record
    cbContent: DWORD;
    pfnStreamOutput: TFnCMsgStreamOutput;
    pvArg: Pointer;
  end;
  {$EXTERNALSYM _CMSG_STREAM_INFO}
  CMSG_STREAM_INFO = _CMSG_STREAM_INFO;
  {$EXTERNALSYM CMSG_STREAM_INFO}
  TCMsgStreamInfo = _CMSG_STREAM_INFO;
  PCMSG_STREAM_INFO = PCMsgStreamInfo;
  {$EXTERNALSYM PCMSG_STREAM_INFO}

//+-------------------------------------------------------------------------
//  Open dwFlags
//--------------------------------------------------------------------------
const
  CMSG_BARE_CONTENT_FLAG             = $00000001;
  {$EXTERNALSYM CMSG_BARE_CONTENT_FLAG}
  CMSG_LENGTH_ONLY_FLAG              = $00000002;
  {$EXTERNALSYM CMSG_LENGTH_ONLY_FLAG}
  CMSG_DETACHED_FLAG                 = $00000004;
  {$EXTERNALSYM CMSG_DETACHED_FLAG}
  CMSG_AUTHENTICATED_ATTRIBUTES_FLAG = $00000008;
  {$EXTERNALSYM CMSG_AUTHENTICATED_ATTRIBUTES_FLAG}
  CMSG_CONTENTS_OCTETS_FLAG          = $00000010;
  {$EXTERNALSYM CMSG_CONTENTS_OCTETS_FLAG}
  CMSG_MAX_LENGTH_FLAG               = $00000020;
  {$EXTERNALSYM CMSG_MAX_LENGTH_FLAG}

// When set, nonData type inner content is encapsulated within an
// OCTET STRING. Applicable to both Signed and Enveloped messages.
const
  CMSG_CMS_ENCAPSULATED_CONTENT_FLAG = $00000040;
  {$EXTERNALSYM CMSG_CMS_ENCAPSULATED_CONTENT_FLAG}

// If set, then, the hCryptProv passed to CryptMsgOpenToEncode or
// CryptMsgOpenToDecode is released on the final CryptMsgClose.
// Not released if CryptMsgOpenToEncode or CryptMsgOpenToDecode fails.
//
// Also applies to hNCryptKey where applicable.
//
// Note, the envelope recipient hCryptProv's aren't released.
const
  CMSG_CRYPT_RELEASE_CONTEXT_FLAG    = $00008000;
  {$EXTERNALSYM CMSG_CRYPT_RELEASE_CONTEXT_FLAG}

//+-------------------------------------------------------------------------
//  Open a cryptographic message for encoding
//
//  If CMSG_BARE_CONTENT_FLAG is specified for a streamed message,
//  the streamed output will not have an outer ContentInfo wrapper. This
//  makes it suitable to be streamed into an enclosing message.
//
//  The pStreamInfo parameter needs to be set to stream the encoded message
//  output.
//--------------------------------------------------------------------------
function CryptMsgOpenToEncode(
  dwMsgEncodingType: DWORD;
  dwFlags: DWORD;
  dwMsgType: DWORD;
  pvMsgEncodeInfo: Pointer;
  pszInnerContentObjID: LPSTR;
  pStreamInfo: PCMsgStreamInfo): HCRYPTMSG; winapi;
{$EXTERNALSYM CryptMsgOpenToEncode}

//+-------------------------------------------------------------------------
//  Calculate the length of an encoded cryptographic message.
//
//  Calculates the length of the encoded message given the
//  message type, encoding parameters and total length of
//  the data to be updated. Note, this might not be the exact length. However,
//  it will always be greater than or equal to the actual length.
//--------------------------------------------------------------------------
function CryptMsgCalculateEncodedLength(
  dwMsgEncodingType: DWORD;
  dwFlags: DWORD;
  dwMsgType: DWORD;
  pvMsgEncodeInfo: Pointer;
  pszInnerContentObjID: LPSTR;
  cbData: DWORD): DWORD; winapi;
{$EXTERNALSYM CryptMsgCalculateEncodedLength}

//+-------------------------------------------------------------------------
//  Open a cryptographic message for decoding
//
//  hCryptProv specifies the crypto provider to use for hashing and/or
//  decrypting the message. If hCryptProv is NULL, a default crypt provider
//  is used.
//
//  Currently pRecipientInfo isn't used and should be set to NULL.
//
//  The pStreamInfo parameter needs to be set to stream the decoded content
//  output.
//--------------------------------------------------------------------------
function CryptMsgOpenToDecode(
  dwMsgEncodingType: DWORD;
  dwFlags: DWORD;
  dwMsgType: DWORD;
  hCryptProv: HCRYPTPROV_LEGACY;
  pRecipientInfo: PCertInfo;
  pStreamInfo: PCMsgStreamInfo): HCRYPTMSG; winapi;
{$EXTERNALSYM CryptMsgOpenToDecode}

//+-------------------------------------------------------------------------
//  Duplicate a cryptographic message handle
//--------------------------------------------------------------------------
function CryptMsgDuplicate(
  hCryptMsg: HCRYPTMSG): HCRYPTMSG; winapi;
{$EXTERNALSYM CryptMsgDuplicate}

//+-------------------------------------------------------------------------
//  Close a cryptographic message handle
//
//  LastError is preserved unless FALSE is returned.
//--------------------------------------------------------------------------
function CryptMsgClose(
  hCryptMsg: HCRYPTMSG): BOOL; winapi;
{$EXTERNALSYM CryptMsgClose}

//+-------------------------------------------------------------------------
//  Update the content of a cryptographic message. Depending on how the
//  message was opened, the content is either encoded or decoded.
//
//  This function is repetitively called to append to the message content.
//  fFinal is set to identify the last update. On fFinal, the encode/decode
//  is completed. The encoded/decoded content and the decoded parameters
//  are valid until the open and all duplicated handles are closed.
//--------------------------------------------------------------------------
function CryptMsgUpdate(
  hCryptMsg: HCRYPTMSG;
  pbData: PByte;
  cbData: DWORD;
  fFinal: BOOL): BOOL; winapi;
{$EXTERNALSYM CryptMsgUpdate}

//+-------------------------------------------------------------------------
//  Get a parameter after encoding/decoding a cryptographic message. Called
//  after the final CryptMsgUpdate. Only the CMSG_CONTENT_PARAM and
//  CMSG_COMPUTED_HASH_PARAM are valid for an encoded message.
//
//  For an encoded HASHED message, the CMSG_COMPUTED_HASH_PARAM can be got
//  before any CryptMsgUpdates to get its length.
//
//  The pvData type definition depends on the dwParamType value.
//
//  Elements pointed to by fields in the pvData structure follow the
//  structure. Therefore, *pcbData may exceed the size of the structure.
//
//  Upon input, if *pcbData == 0, then, *pcbData is updated with the length
//  of the data and the pvData parameter is ignored.
//
//  Upon return, *pcbData is updated with the length of the data.
//
//  The OBJID BLOBs returned in the pvData structures point to
//  their still encoded representation. The appropriate functions
//  must be called to decode the information.
//
//  See below for a list of the parameters to get.
//--------------------------------------------------------------------------
function CryptMsgGetParam(
  hCryptMsg: HCRYPTMSG;
  dwParamType: DWORD;
  dwIndex: DWORD;
  pvData: Pointer;
  var pcbData: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptMsgGetParam}

//+-------------------------------------------------------------------------
//  Get parameter types and their corresponding data structure definitions.
//--------------------------------------------------------------------------
const
  CMSG_TYPE_PARAM                              = 1;
  {$EXTERNALSYM CMSG_TYPE_PARAM}
  CMSG_CONTENT_PARAM                           = 2;
  {$EXTERNALSYM CMSG_CONTENT_PARAM}
  CMSG_BARE_CONTENT_PARAM                      = 3;
  {$EXTERNALSYM CMSG_BARE_CONTENT_PARAM}
  CMSG_INNER_CONTENT_TYPE_PARAM                = 4;
  {$EXTERNALSYM CMSG_INNER_CONTENT_TYPE_PARAM}
  CMSG_SIGNER_COUNT_PARAM                      = 5;
  {$EXTERNALSYM CMSG_SIGNER_COUNT_PARAM}
  CMSG_SIGNER_INFO_PARAM                       = 6;
  {$EXTERNALSYM CMSG_SIGNER_INFO_PARAM}
  CMSG_SIGNER_CERT_INFO_PARAM                  = 7;
  {$EXTERNALSYM CMSG_SIGNER_CERT_INFO_PARAM}
  CMSG_SIGNER_HASH_ALGORITHM_PARAM             = 8;
  {$EXTERNALSYM CMSG_SIGNER_HASH_ALGORITHM_PARAM}
  CMSG_SIGNER_AUTH_ATTR_PARAM                  = 9;
  {$EXTERNALSYM CMSG_SIGNER_AUTH_ATTR_PARAM}
  CMSG_SIGNER_UNAUTH_ATTR_PARAM                = 10;
  {$EXTERNALSYM CMSG_SIGNER_UNAUTH_ATTR_PARAM}
  CMSG_CERT_COUNT_PARAM                        = 11;
  {$EXTERNALSYM CMSG_CERT_COUNT_PARAM}
  CMSG_CERT_PARAM                              = 12;
  {$EXTERNALSYM CMSG_CERT_PARAM}
  CMSG_CRL_COUNT_PARAM                         = 13;
  {$EXTERNALSYM CMSG_CRL_COUNT_PARAM}
  CMSG_CRL_PARAM                               = 14;
  {$EXTERNALSYM CMSG_CRL_PARAM}
  CMSG_ENVELOPE_ALGORITHM_PARAM                = 15;
  {$EXTERNALSYM CMSG_ENVELOPE_ALGORITHM_PARAM}
  CMSG_RECIPIENT_COUNT_PARAM                   = 17;
  {$EXTERNALSYM CMSG_RECIPIENT_COUNT_PARAM}
  CMSG_RECIPIENT_INDEX_PARAM                   = 18;
  {$EXTERNALSYM CMSG_RECIPIENT_INDEX_PARAM}
  CMSG_RECIPIENT_INFO_PARAM                    = 19;
  {$EXTERNALSYM CMSG_RECIPIENT_INFO_PARAM}
  CMSG_HASH_ALGORITHM_PARAM                    = 20;
  {$EXTERNALSYM CMSG_HASH_ALGORITHM_PARAM}
  CMSG_HASH_DATA_PARAM                         = 21;
  {$EXTERNALSYM CMSG_HASH_DATA_PARAM}
  CMSG_COMPUTED_HASH_PARAM                     = 22;
  {$EXTERNALSYM CMSG_COMPUTED_HASH_PARAM}
  CMSG_ENCRYPT_PARAM                           = 26;
  {$EXTERNALSYM CMSG_ENCRYPT_PARAM}
  CMSG_ENCRYPTED_DIGEST                        = 27;
  {$EXTERNALSYM CMSG_ENCRYPTED_DIGEST}
  CMSG_ENCODED_SIGNER                          = 28;
  {$EXTERNALSYM CMSG_ENCODED_SIGNER}
  CMSG_ENCODED_MESSAGE                         = 29;
  {$EXTERNALSYM CMSG_ENCODED_MESSAGE}
  CMSG_VERSION_PARAM                           = 30;
  {$EXTERNALSYM CMSG_VERSION_PARAM}
  CMSG_ATTR_CERT_COUNT_PARAM                   = 31;
  {$EXTERNALSYM CMSG_ATTR_CERT_COUNT_PARAM}
  CMSG_ATTR_CERT_PARAM                         = 32;
  {$EXTERNALSYM CMSG_ATTR_CERT_PARAM}
  CMSG_CMS_RECIPIENT_COUNT_PARAM               = 33;
  {$EXTERNALSYM CMSG_CMS_RECIPIENT_COUNT_PARAM}
  CMSG_CMS_RECIPIENT_INDEX_PARAM               = 34;
  {$EXTERNALSYM CMSG_CMS_RECIPIENT_INDEX_PARAM}
  CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35;
  {$EXTERNALSYM CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM}
  CMSG_CMS_RECIPIENT_INFO_PARAM                = 36;
  {$EXTERNALSYM CMSG_CMS_RECIPIENT_INFO_PARAM}
  CMSG_UNPROTECTED_ATTR_PARAM                  = 37;
  {$EXTERNALSYM CMSG_UNPROTECTED_ATTR_PARAM}
  CMSG_SIGNER_CERT_ID_PARAM                    = 38;
  {$EXTERNALSYM CMSG_SIGNER_CERT_ID_PARAM}
  CMSG_CMS_SIGNER_INFO_PARAM                   = 39;
  {$EXTERNALSYM CMSG_CMS_SIGNER_INFO_PARAM}

//+-------------------------------------------------------------------------
//  CMSG_TYPE_PARAM
//
//  The type of the decoded message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CONTENT_PARAM
//
//  The encoded content of a cryptographic message. Depending on how the
//  message was opened, the content is either the whole PKCS#7
//  message (opened to encode) or the inner content (opened to decode).
//  In the decode case, the decrypted content is returned, if enveloped.
//  If not enveloped, and if the inner content is of type DATA, the returned
//  data is the contents octets of the inner content.
//
//  pvData points to the buffer receiving the content bytes
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_BARE_CONTENT_PARAM
//
//  The encoded content of an encoded cryptographic message, without the
//  outer layer of ContentInfo. That is, only the encoding of the
//  ContentInfo.content field is returned.
//
//  pvData points to the buffer receiving the content bytes
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_INNER_CONTENT_TYPE_PARAM
//
//  The type of the inner content of a decoded cryptographic message,
//  in the form of a NULL-terminated object identifier string
//  (eg. "1.2.840.113549.1.7.1").
//
//  pvData points to the buffer receiving the object identifier string
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_COUNT_PARAM
//
//  Count of signers in a SIGNED or SIGNED_AND_ENVELOPED message
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_CERT_INFO_PARAM
//
//  To get all the signers, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. SignerCount - 1.
//
//  pvData points to a CERT_INFO struct.
//
//  Only the following fields have been updated in the CERT_INFO struct:
//  Issuer and SerialNumber.
//
//  Note, if the KEYID choice was selected for a CMS SignerId, then, the
//  SerialNumber is 0 and the Issuer is encoded containing a single RDN with a
//  single Attribute whose OID is szOID_KEYID_RDN, value type is
//  CERT_RDN_OCTET_STRING and value is the KEYID. When the
//  CertGetSubjectCertificateFromStore and
//  CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) APIs see this
//  special KEYID Issuer and SerialNumber, they do a KEYID match.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_INFO_PARAM
//
//  To get all the signers, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. SignerCount - 1.
//
//  pvData points to a CMSG_SIGNER_INFO struct.
//
//  Note, if the KEYID choice was selected for a CMS SignerId, then, the
//  SerialNumber is 0 and the Issuer is encoded containing a single RDN with a
//  single Attribute whose OID is szOID_KEYID_RDN, value type is
//  CERT_RDN_OCTET_STRING and value is the KEYID. When the
//  CertGetSubjectCertificateFromStore and
//  CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) APIs see this
//  special KEYID Issuer and SerialNumber, they do a KEYID match.
//--------------------------------------------------------------------------
type
  PCMsgSignerInfo = ^TCMsgSignerInfo;
  _CMSG_SIGNER_INFO = record
    dwVersion: DWORD;
    Issuer: TCertNameBlob;
    SerialNumber: TCryptIntegerBlob;
    HashAlgorithm: TCryptAlgorithmIdentifier;

    // This is also referred to as the SignatureAlgorithm
    HashEncryptionAlgorithm: TCryptAlgorithmIdentifier;

    EncryptedHash: TCryptDataBlob;
    AuthAttrs: TCryptAttributes;
    UnauthAttrs: TCryptAttributes;
  end;
  {$EXTERNALSYM _CMSG_SIGNER_INFO}
  CMSG_SIGNER_INFO = _CMSG_SIGNER_INFO;
  {$EXTERNALSYM CMSG_SIGNER_INFO}
  TCMsgSignerInfo = _CMSG_SIGNER_INFO;
  PCMSG_SIGNER_INFO = PCMsgSignerInfo;
  {$EXTERNALSYM PCMSG_SIGNER_INFO}

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_CERT_ID_PARAM
//
//  To get all the signers, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. SignerCount - 1.
//
//  pvData points to a CERT_ID struct.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CMS_SIGNER_INFO_PARAM
//
//  Same as CMSG_SIGNER_INFO_PARAM, except, contains SignerId instead of
//  Issuer and SerialNumber.
//
//  To get all the signers, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. SignerCount - 1.
//
//  pvData points to a CMSG_CMS_SIGNER_INFO struct.
//--------------------------------------------------------------------------
type
  PCMsgCMSSignerInfo = ^TCMsgCMSSignerInfo;
  _CMSG_CMS_SIGNER_INFO = record
    dwVersion: DWORD;
    SignerId: TCertID;
    HashAlgorithm: TCryptAlgorithmIdentifier;

    // This is also referred to as the SignatureAlgorithm
    HashEncryptionAlgorithm: TCryptAlgorithmIdentifier;

    EncryptedHash: TCryptDataBlob;
    AuthAttrs: TCryptAttributes;
    UnauthAttrs: TCryptAttributes;
  end;
  {$EXTERNALSYM _CMSG_CMS_SIGNER_INFO}
  CMSG_CMS_SIGNER_INFO = _CMSG_CMS_SIGNER_INFO;
  {$EXTERNALSYM CMSG_CMS_SIGNER_INFO}
  TCMsgCMSSignerInfo = _CMSG_CMS_SIGNER_INFO;
  PCMSG_CMS_SIGNER_INFO = PCMsgCMSSignerInfo;
  {$EXTERNALSYM PCMSG_CMS_SIGNER_INFO}

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_HASH_ALGORITHM_PARAM
//
//  This parameter specifies the HashAlgorithm that was used for the signer.
//
//  Set dwIndex to iterate through all the signers.
//
//  pvData points to an CRYPT_ALGORITHM_IDENTIFIER struct.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_AUTH_ATTR_PARAM
//
//  The authenticated attributes for the signer.
//
//  Set dwIndex to iterate through all the signers.
//
//  pvData points to a CMSG_ATTR struct.
//--------------------------------------------------------------------------
type
  PCMsgAttr = ^TCMsgAttr;
  CMSG_ATTR = CRYPT_ATTRIBUTES;
  {$EXTERNALSYM CMSG_ATTR}
  TCMsgAttr = CRYPT_ATTRIBUTES;
  PCMSG_ATTR = PCMsgAttr;
  {$EXTERNALSYM PCMSG_ATTR}

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_UNAUTH_ATTR_PARAM
//
//  The unauthenticated attributes for the signer.
//
//  Set dwIndex to iterate through all the signers.
//
//  pvData points to a CMSG_ATTR struct.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CERT_COUNT_PARAM
//
//  Count of certificates in a SIGNED or SIGNED_AND_ENVELOPED message.
//
//  CMS, also supports certificates in an ENVELOPED message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CERT_PARAM
//
//  To get all the certificates, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. CertCount - 1.
//
//  pvData points to an array of the certificate's encoded bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CRL_COUNT_PARAM
//
//  Count of CRLs in a SIGNED or SIGNED_AND_ENVELOPED message.
//
//  CMS, also supports CRLs in an ENVELOPED message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CRL_PARAM
//
//  To get all the CRLs, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. CrlCount - 1.
//
//  pvData points to an array of the CRL's encoded bytes.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
//  CMSG_ENVELOPE_ALGORITHM_PARAM
//
//  The ContentEncryptionAlgorithm that was used in
//  an ENVELOPED or SIGNED_AND_ENVELOPED message.
//
//  For streaming you must be able to successfully get this parameter before
//  doing a CryptMsgControl decrypt.
//
//  pvData points to an CRYPT_ALGORITHM_IDENTIFIER struct.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_RECIPIENT_COUNT_PARAM
//
//  Count of recipients in an ENVELOPED or SIGNED_AND_ENVELOPED message.
//
//  Count of key transport recepients.
//
//  The CMSG_CMS_RECIPIENT_COUNT_PARAM has the total count of
//  recipients (it also includes key agree and mail list recipients).
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_RECIPIENT_INDEX_PARAM
//
//  Index of the recipient used to decrypt an ENVELOPED or SIGNED_AND_ENVELOPED
//  message.
//
//  Index of a key transport recipient. If a non key transport
//  recipient was used to decrypt, fails with LastError set to
//  CRYPT_E_INVALID_INDEX.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_RECIPIENT_INFO_PARAM
//
//  To get all the recipients, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. RecipientCount - 1.
//
//  Only returns the key transport recepients.
//
//  The CMSG_CMS_RECIPIENT_INFO_PARAM returns all recipients.
//
//  pvData points to a CERT_INFO struct.
//
//  Only the following fields have been updated in the CERT_INFO struct:
//  Issuer, SerialNumber and PublicKeyAlgorithm. The PublicKeyAlgorithm
//  specifies the KeyEncryptionAlgorithm that was used.
//
//  Note, if the KEYID choice was selected for a key transport recipient, then,
//  the SerialNumber is 0 and the Issuer is encoded containing a single RDN
//  with a single Attribute whose OID is szOID_KEYID_RDN, value type is
//  CERT_RDN_OCTET_STRING and value is the KEYID. When the
//  CertGetSubjectCertificateFromStore and
//  CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) APIs see this
//  special KEYID Issuer and SerialNumber, they do a KEYID match.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_HASH_ALGORITHM_PARAM
//
//  The HashAlgorithm in a HASHED message.
//
//  pvData points to an CRYPT_ALGORITHM_IDENTIFIER struct.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_HASH_DATA_PARAM
//
//  The hash in a HASHED message.
//
//  pvData points to an array of bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_COMPUTED_HASH_PARAM
//
//  The computed hash for a HASHED message.
//  This may be called for either an encoded or decoded message.
//
//  Also, the computed hash for one of the signer's in a SIGNED message.
//  It may be called for either an encoded or decoded message after the
//  final update.  Set dwIndex to iterate through all the signers.
//
//  pvData points to an array of bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_ENCRYPT_PARAM
//
//  The ContentEncryptionAlgorithm that was used in an ENCRYPTED message.
//
//  pvData points to an CRYPT_ALGORITHM_IDENTIFIER struct.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_ENCODED_MESSAGE
//
//  The full encoded message. This is useful in the case of a decoded
//  message which has been modified (eg. a signed-data or
//  signed-and-enveloped-data message which has been countersigned).
//
//  pvData points to an array of the message's encoded bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_VERSION_PARAM
//
//  The version of the decoded message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------
const
  CMSG_SIGNED_DATA_V1                    = 1;
  {$EXTERNALSYM CMSG_SIGNED_DATA_V1}
  CMSG_SIGNED_DATA_V3                    = 3;
  {$EXTERNALSYM CMSG_SIGNED_DATA_V3}
  CMSG_SIGNED_DATA_PKCS_1_5_VERSION      = CMSG_SIGNED_DATA_V1;
  {$EXTERNALSYM CMSG_SIGNED_DATA_PKCS_1_5_VERSION}
  CMSG_SIGNED_DATA_CMS_VERSION           = CMSG_SIGNED_DATA_V3;
  {$EXTERNALSYM CMSG_SIGNED_DATA_CMS_VERSION}

  CMSG_SIGNER_INFO_V1                    = 1;
  {$EXTERNALSYM CMSG_SIGNER_INFO_V1}
  CMSG_SIGNER_INFO_V3                    = 3;
  {$EXTERNALSYM CMSG_SIGNER_INFO_V3}
  CMSG_SIGNER_INFO_PKCS_1_5_VERSION      = CMSG_SIGNER_INFO_V1;
  {$EXTERNALSYM CMSG_SIGNER_INFO_PKCS_1_5_VERSION}
  CMSG_SIGNER_INFO_CMS_VERSION           = CMSG_SIGNER_INFO_V3;
  {$EXTERNALSYM CMSG_SIGNER_INFO_CMS_VERSION}

  CMSG_HASHED_DATA_V0                    = 0;
  {$EXTERNALSYM CMSG_HASHED_DATA_V0}
  CMSG_HASHED_DATA_V2                    = 2;
  {$EXTERNALSYM CMSG_HASHED_DATA_V2}
  CMSG_HASHED_DATA_PKCS_1_5_VERSION      = CMSG_HASHED_DATA_V0;
  {$EXTERNALSYM CMSG_HASHED_DATA_PKCS_1_5_VERSION}
  CMSG_HASHED_DATA_CMS_VERSION           = CMSG_HASHED_DATA_V2;
  {$EXTERNALSYM CMSG_HASHED_DATA_CMS_VERSION}

  CMSG_ENVELOPED_DATA_V0                 = 0;
  {$EXTERNALSYM CMSG_ENVELOPED_DATA_V0}
  CMSG_ENVELOPED_DATA_V2                 = 2;
  {$EXTERNALSYM CMSG_ENVELOPED_DATA_V2}
  CMSG_ENVELOPED_DATA_PKCS_1_5_VERSION   = CMSG_ENVELOPED_DATA_V0;
  {$EXTERNALSYM CMSG_ENVELOPED_DATA_PKCS_1_5_VERSION}
  CMSG_ENVELOPED_DATA_CMS_VERSION        = CMSG_ENVELOPED_DATA_V2;
  {$EXTERNALSYM CMSG_ENVELOPED_DATA_CMS_VERSION}

//+-------------------------------------------------------------------------
//  CMSG_ATTR_CERT_COUNT_PARAM
//
//  Count of attribute certificates in a SIGNED or ENVELOPED message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_ATTR_CERT_PARAM
//
//  To get all the attribute certificates, repetitively call CryptMsgGetParam,
//  with dwIndex set to 0 .. AttrCertCount - 1.
//
//  pvData points to an array of the attribute certificate's encoded bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CMS_RECIPIENT_COUNT_PARAM
//
//  Count of all CMS recipients in an ENVELOPED message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CMS_RECIPIENT_INDEX_PARAM
//
//  Index of the CMS recipient used to decrypt an ENVELOPED message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM
//
//  For a CMS key agreement recipient, the index of the encrypted key
//  used to decrypt an ENVELOPED message.
//
//  pvData points to a DWORD
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CMS_RECIPIENT_INFO_PARAM
//
//  To get all the CMS recipients, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. CmsRecipientCount - 1.
//
//  pvData points to a CMSG_CMS_RECIPIENT_INFO struct.
//--------------------------------------------------------------------------
type
  PCMsgKeyTransRecipientInfo = ^TCMsgKeyTransRecipientInfo;
  _CMSG_KEY_TRANS_RECIPIENT_INFO = record
    dwVersion: DWORD;

    // Currently, only ISSUER_SERIAL_NUMBER or KEYID choices
    RecipientId: TCertID;

    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    EncryptedKey: TCryptDataBlob;
  end;
  {$EXTERNALSYM _CMSG_KEY_TRANS_RECIPIENT_INFO}
  CMSG_KEY_TRANS_RECIPIENT_INFO = _CMSG_KEY_TRANS_RECIPIENT_INFO;
  {$EXTERNALSYM CMSG_KEY_TRANS_RECIPIENT_INFO}
  TCMsgKeyTransRecipientInfo = _CMSG_KEY_TRANS_RECIPIENT_INFO;
  PCMSG_KEY_TRANS_RECIPIENT_INFO = PCMsgKeyTransRecipientInfo;
  {$EXTERNALSYM PCMSG_KEY_TRANS_RECIPIENT_INFO}

type
  PCMsgRecipientEncryptedKeyInfo = ^TCMsgRecipientEncryptedKeyInfo;
  _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO = record
    // Currently, only ISSUER_SERIAL_NUMBER or KEYID choices
    RecipientId: TCertID;

    EncryptedKey: TCryptDataBlob;

    // The following optional fields are only applicable to KEYID choice
    Date: TFileTime;
    pOtherAttr: PCryptAttributeTypeValue;
  end;
  {$EXTERNALSYM _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO}
  CMSG_RECIPIENT_ENCRYPTED_KEY_INFO = _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO;
  {$EXTERNALSYM CMSG_RECIPIENT_ENCRYPTED_KEY_INFO}
  TCMsgRecipientEncryptedKeyInfo = _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO;
  PCMSG_RECIPIENT_ENCRYPTED_KEY_INFO = PCMsgRecipientEncryptedKeyInfo;
  {$EXTERNALSYM PCMSG_RECIPIENT_ENCRYPTED_KEY_INFO}

const
  CMSG_KEY_AGREE_ORIGINATOR_CERT        = 1;
  {$EXTERNALSYM CMSG_KEY_AGREE_ORIGINATOR_CERT}
  CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY  = 2;
  {$EXTERNALSYM CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY}

type
  PCMsgKeyAgreeRecipientInfo = ^TCMsgKeyAgreeRecipientInfo;
  _CMSG_KEY_AGREE_RECIPIENT_INFO = record
    dwVersion: DWORD;
    case dwOriginatorChoice: DWORD of
    CMSG_KEY_AGREE_ORIGINATOR_CERT:
      (OriginatorCertId: TCertID);
    CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY:
      (OriginatorPublicKeyInfo: TCertPublicKeyInfo;
    UserKeyingMaterial: TCryptDataBlob;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;

    cRecipientEncryptedKeys: DWORD;
    rgpRecipientEncryptedKeys: ^PCMsgRecipientEncryptedKeyInfo
    );
  end;
  {$EXTERNALSYM _CMSG_KEY_AGREE_RECIPIENT_INFO}
  CMSG_KEY_AGREE_RECIPIENT_INFO = _CMSG_KEY_AGREE_RECIPIENT_INFO;
  {$EXTERNALSYM CMSG_KEY_AGREE_RECIPIENT_INFO}
  TCMsgKeyAgreeRecipientInfo = _CMSG_KEY_AGREE_RECIPIENT_INFO;
  PCMSG_KEY_AGREE_RECIPIENT_INFO = PCMsgKeyAgreeRecipientInfo;
  {$EXTERNALSYM PCMSG_KEY_AGREE_RECIPIENT_INFO}

type
  PCMsgMailListRecipientInfo = ^TCMsgMailListRecipientInfo;
  _CMSG_MAIL_LIST_RECIPIENT_INFO = record
    dwVersion: DWORD;
    KeyId: TCryptDataBlob;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    EncryptedKey: TCryptDataBlob;

    // The following fields are optional
    Date: TFileTime;
    pOtherAttr: PCryptAttributeTypeValue;
  end;
  {$EXTERNALSYM _CMSG_MAIL_LIST_RECIPIENT_INFO}
  CMSG_MAIL_LIST_RECIPIENT_INFO = _CMSG_MAIL_LIST_RECIPIENT_INFO;
  {$EXTERNALSYM CMSG_MAIL_LIST_RECIPIENT_INFO}
  TCMsgMailListRecipientInfo = _CMSG_MAIL_LIST_RECIPIENT_INFO;
  PCMSG_MAIL_LIST_RECIPIENT_INFO = PCMsgMailListRecipientInfo;
  {$EXTERNALSYM PCMSG_MAIL_LIST_RECIPIENT_INFO}

type
  PCMsgCMSRecipientInfo = ^TCMsgCMSRecipientInfo;
  _CMSG_CMS_RECIPIENT_INFO = record
    case dwRecipientChoice: DWORD of
    CMSG_KEY_TRANS_RECIPIENT:
      (pKeyTrans: PCMsgKeyTransRecipientInfo);
    CMSG_KEY_AGREE_RECIPIENT:
      (pKeyAgree: PCMsgKeyAgreeRecipientInfo);
    CMSG_MAIL_LIST_RECIPIENT:
      (pMailList: PCMsgMailListRecipientInfo);
  end;
  {$EXTERNALSYM _CMSG_CMS_RECIPIENT_INFO}
  CMSG_CMS_RECIPIENT_INFO = _CMSG_CMS_RECIPIENT_INFO;
  {$EXTERNALSYM CMSG_CMS_RECIPIENT_INFO}
  TCMsgCMSRecipientInfo = _CMSG_CMS_RECIPIENT_INFO;
  PCMSG_CMS_RECIPIENT_INFO = PCMsgCMSRecipientInfo;
  {$EXTERNALSYM PCMSG_CMS_RECIPIENT_INFO}

// dwVersion numbers for the KeyTrans, KeyAgree and MailList recipients
const
  CMSG_ENVELOPED_RECIPIENT_V0            = 0;
  {$EXTERNALSYM CMSG_ENVELOPED_RECIPIENT_V0}
  CMSG_ENVELOPED_RECIPIENT_V2            = 2;
  {$EXTERNALSYM CMSG_ENVELOPED_RECIPIENT_V2}
  CMSG_ENVELOPED_RECIPIENT_V3            = 3;
  {$EXTERNALSYM CMSG_ENVELOPED_RECIPIENT_V3}
  CMSG_ENVELOPED_RECIPIENT_V4            = 4;
  {$EXTERNALSYM CMSG_ENVELOPED_RECIPIENT_V4}
  CMSG_KEY_TRANS_PKCS_1_5_VERSION        = CMSG_ENVELOPED_RECIPIENT_V0;
  {$EXTERNALSYM CMSG_KEY_TRANS_PKCS_1_5_VERSION}
  CMSG_KEY_TRANS_CMS_VERSION             = CMSG_ENVELOPED_RECIPIENT_V2;
  {$EXTERNALSYM CMSG_KEY_TRANS_CMS_VERSION}
  CMSG_KEY_AGREE_VERSION                 = CMSG_ENVELOPED_RECIPIENT_V3;
  {$EXTERNALSYM CMSG_KEY_AGREE_VERSION}
  CMSG_MAIL_LIST_VERSION                 = CMSG_ENVELOPED_RECIPIENT_V4;
  {$EXTERNALSYM CMSG_MAIL_LIST_VERSION}

//+-------------------------------------------------------------------------
//  CMSG_UNPROTECTED_ATTR_PARAM
//
//  The unprotected attributes in the envelped message.
//
//  pvData points to a CMSG_ATTR struct.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
//  Perform a special "control" function after the final CryptMsgUpdate of a
//  encoded/decoded cryptographic message.
//
//  The dwCtrlType parameter specifies the type of operation to be performed.
//
//  The pvCtrlPara definition depends on the dwCtrlType value.
//
//  See below for a list of the control operations and their pvCtrlPara
//  type definition.
//--------------------------------------------------------------------------
function CryptMsgControl(
  hCryptMsg: HCRYPTMSG;
  dwFlags: DWORD;
  dwCtrlType: DWORD;
  pvCtrlPara: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptMsgControl}

//+-------------------------------------------------------------------------
//  Message control types
//--------------------------------------------------------------------------
const
  CMSG_CTRL_VERIFY_SIGNATURE        = 1;
  {$EXTERNALSYM CMSG_CTRL_VERIFY_SIGNATURE}
  CMSG_CTRL_DECRYPT                 = 2;
  {$EXTERNALSYM CMSG_CTRL_DECRYPT}
  CMSG_CTRL_VERIFY_HASH             = 5;
  {$EXTERNALSYM CMSG_CTRL_VERIFY_HASH}
  CMSG_CTRL_ADD_SIGNER              = 6;
  {$EXTERNALSYM CMSG_CTRL_ADD_SIGNER}
  CMSG_CTRL_DEL_SIGNER              = 7;
  {$EXTERNALSYM CMSG_CTRL_DEL_SIGNER}
  CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR  = 8;
  {$EXTERNALSYM CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR}
  CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR  = 9;
  {$EXTERNALSYM CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR}
  CMSG_CTRL_ADD_CERT                = 10;
  {$EXTERNALSYM CMSG_CTRL_ADD_CERT}
  CMSG_CTRL_DEL_CERT                = 11;
  {$EXTERNALSYM CMSG_CTRL_DEL_CERT}
  CMSG_CTRL_ADD_CRL                 = 12;
  {$EXTERNALSYM CMSG_CTRL_ADD_CRL}
  CMSG_CTRL_DEL_CRL                 = 13;
  {$EXTERNALSYM CMSG_CTRL_DEL_CRL}
  CMSG_CTRL_ADD_ATTR_CERT           = 14;
  {$EXTERNALSYM CMSG_CTRL_ADD_ATTR_CERT}
  CMSG_CTRL_DEL_ATTR_CERT           = 15;
  {$EXTERNALSYM CMSG_CTRL_DEL_ATTR_CERT}
  CMSG_CTRL_KEY_TRANS_DECRYPT       = 16;
  {$EXTERNALSYM CMSG_CTRL_KEY_TRANS_DECRYPT}
  CMSG_CTRL_KEY_AGREE_DECRYPT       = 17;
  {$EXTERNALSYM CMSG_CTRL_KEY_AGREE_DECRYPT}
  CMSG_CTRL_MAIL_LIST_DECRYPT       = 18;
  {$EXTERNALSYM CMSG_CTRL_MAIL_LIST_DECRYPT}
  CMSG_CTRL_VERIFY_SIGNATURE_EX     = 19;
  {$EXTERNALSYM CMSG_CTRL_VERIFY_SIGNATURE_EX}
  CMSG_CTRL_ADD_CMS_SIGNER_INFO     = 20;
  {$EXTERNALSYM CMSG_CTRL_ADD_CMS_SIGNER_INFO}
  CMSG_CTRL_ENABLE_STRONG_SIGNATURE = 21;
  {$EXTERNALSYM CMSG_CTRL_ENABLE_STRONG_SIGNATURE}

//+-------------------------------------------------------------------------
//  CMSG_CTRL_VERIFY_SIGNATURE
//
//  Verify the signature of a SIGNED or SIGNED_AND_ENVELOPED
//  message after it has been decoded.
//
//  For a SIGNED_AND_ENVELOPED message, called after
//  CryptMsgControl(CMSG_CTRL_DECRYPT), if CryptMsgOpenToDecode was called
//  with a NULL pRecipientInfo.
//
//  pvCtrlPara points to a CERT_INFO struct.
//
//  The CERT_INFO contains the Issuer and SerialNumber identifying
//  the Signer of the message. The CERT_INFO also contains the
//  PublicKeyInfo
//  used to verify the signature. The cryptographic provider specified
//  in CryptMsgOpenToDecode is used.
//
//  Note, if the message contains CMS signers identified by KEYID, then,
//  the CERT_INFO's Issuer and SerialNumber is ignored and only the public
//  key is used to find a signer whose signature verifies.
//
//  The following CMSG_CTRL_VERIFY_SIGNATURE_EX should be used instead.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_VERIFY_SIGNATURE_EX
//
//  Verify the signature of a SIGNED message after it has been decoded.
//
//  pvCtrlPara points to the following CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA.
//
//  If hCryptProv is NULL, uses the cryptographic provider specified in
//  CryptMsgOpenToDecode. If CryptMsgOpenToDecode's hCryptProv is also NULL,
//  gets default provider according to the signer's public key OID.
//
//  dwSignerIndex is the index of the signer to use to verify the signature.
//
//  The signer can be a pointer to a CERT_PUBLIC_KEY_INFO, certificate
//  context or a chain context.
//
//  If the signer's HashEncryptionAlgorithm is szOID_PKIX_NO_SIGNATURE, then,
//  the signature is expected to contain the hash octets. Only dwSignerType
//  of CMSG_VERIFY_SIGNER_NULL may be specified to verify this no signature
//  case.
//--------------------------------------------------------------------------
type
  PCMsgCtrlVerifySignatureExPara = ^TCMsgCtrlVerifySignatureExPara;
  _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA = record
    cbSize: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    dwSignerIndex: DWORD;
    dwSignerType: DWORD;
    pvSigner: Pointer;
  end;
  {$EXTERNALSYM _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA}
  CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA = _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA;
  {$EXTERNALSYM CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA}
  TCMsgCtrlVerifySignatureExPara = _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA;
  PCMSG_CTRL_VERIFY_SIGNATURE_EX_PARA = PCMsgCtrlVerifySignatureExPara;
  {$EXTERNALSYM PCMSG_CTRL_VERIFY_SIGNATURE_EX_PARA}

// Signer Types
const
  CMSG_VERIFY_SIGNER_PUBKEY                  = 1;
  {$EXTERNALSYM CMSG_VERIFY_SIGNER_PUBKEY}
    // pvSigner :: PCERT_PUBLIC_KEY_INFO
  CMSG_VERIFY_SIGNER_CERT                    = 2;
  {$EXTERNALSYM CMSG_VERIFY_SIGNER_CERT}
    // pvSigner :: PCCERT_CONTEXT
  CMSG_VERIFY_SIGNER_CHAIN                   = 3;
  {$EXTERNALSYM CMSG_VERIFY_SIGNER_CHAIN}
    // pvSigner :: PCCERT_CHAIN_CONTEXT
  CMSG_VERIFY_SIGNER_NULL                    = 4;
  {$EXTERNALSYM CMSG_VERIFY_SIGNER_NULL}
    // pvSigner :: NULL


//+-------------------------------------------------------------------------
//  CMSG_CTRL_ENABLE_STRONG_SIGNATURE
//
//  Enables Strong Signature Checking for subsequent verifies.
//
//  pvCtrlPara points to a const CERT_STRONG_SIGN_PARA struct.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
//  CMSG_CTRL_DECRYPT
//
//  Decrypt an ENVELOPED or SIGNED_AND_ENVELOPED message after it has been
//  decoded.
//
//  This decrypt is only applicable to key transport recipients.
//
//  hCryptProv and dwKeySpec specify the private key to use. For dwKeySpec ==
//  0, defaults to AT_KEYEXCHANGE.
//
//  hNCryptKey can be set to decrypt using a CNG private key.
//
//  If CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags passed
//  to CryptMsgControl, then, the hCryptProv is released on the final
//  CryptMsgClose. Not released if CryptMsgControl fails. Also applies
//  to freeing the hNCryptKey.
//
//  dwRecipientIndex is the index of the recipient in the message associated
//  with the hCryptProv's or hNCryptKey's private key.
//
//  The dwRecipientIndex is the index of a key transport recipient.
//
//  Note, the message can only be decrypted once.
//--------------------------------------------------------------------------
type
  PCMsgCtrlDecryptPara = ^TCMsgCtrlDecryptPara;
  _CMSG_CTRL_DECRYPT_PARA = record
    cbSize: DWORD;

    // NCryptIsKeyHandle() is called to determine the union choice.
    case Integer of
    0: (hCryptProv: HCRYPTPROV);
    1: (hNCryptKey: NCRYPT_KEY_HANDLE;

    // not applicable for hNCryptKey choice
    dwKeySpec: DWORD;

    dwRecipientIndex: DWORD
    )
  end;
  {$EXTERNALSYM _CMSG_CTRL_DECRYPT_PARA}
  CMSG_CTRL_DECRYPT_PARA = _CMSG_CTRL_DECRYPT_PARA;
  {$EXTERNALSYM CMSG_CTRL_DECRYPT_PARA}
  TCMsgCtrlDecryptPara = _CMSG_CTRL_DECRYPT_PARA;
  PCMSG_CTRL_DECRYPT_PARA = PCMsgCtrlDecryptPara;
  {$EXTERNALSYM PCMSG_CTRL_DECRYPT_PARA}

//+-------------------------------------------------------------------------
//  CMSG_CTRL_KEY_TRANS_DECRYPT
//
//  Decrypt an ENVELOPED message after it has been decoded for a key
//  transport recipient.
//
//  hCryptProv and dwKeySpec specify the private key to use. For dwKeySpec ==
//  0, defaults to AT_KEYEXCHANGE.
//
//  hNCryptKey can be set to decrypt using a CNG private key.
//
//  If CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags passed
//  to CryptMsgControl, then, the hCryptProv is released on the final
//  CryptMsgClose. Not released if CryptMsgControl fails. Also applies
//  to freeing the hNCryptKey.
//
//  pKeyTrans points to the CMSG_KEY_TRANS_RECIPIENT_INFO obtained via
//  CryptMsgGetParam(CMSG_CMS_RECIPIENT_INFO_PARAM)
//
//  dwRecipientIndex is the index of the recipient in the message associated
//  with the hCryptProv's or hNCryptKey's private key.
//
//  Note, the message can only be decrypted once.
//--------------------------------------------------------------------------
type
  PCMsgCtrlKeyTransDecryptPara = ^TCMsgCtrlKeyTransDecryptPara;
  _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA = record
    cbSize: DWORD;
    // NCryptIsKeyHandle() is called to determine the union choice.
    case Integer of
    0: (hCryptProv: HCRYPTPROV);
    1: (hNCryptKey: NCRYPT_KEY_HANDLE;

    // not applicable for hNCryptKey choice
    dwKeySpec: DWORD;

    pKeyTrans: PCMsgKeyTransRecipientInfo;
    dwRecipientIndex: DWORD
    );
  end;
  {$EXTERNALSYM _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA}
  CMSG_CTRL_KEY_TRANS_DECRYPT_PARA = _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA;
  {$EXTERNALSYM CMSG_CTRL_KEY_TRANS_DECRYPT_PARA}
  TCMsgCtrlKeyTransDecryptPara = _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA;
  PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA = PCMsgCtrlKeyTransDecryptPara;
  {$EXTERNALSYM PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA}

//+-------------------------------------------------------------------------
//  CMSG_CTRL_KEY_AGREE_DECRYPT
//
//  Decrypt an ENVELOPED message after it has been decoded for a key
//  agreement recipient.
//
//  hCryptProv and dwKeySpec specify the private key to use. For dwKeySpec ==
//  0, defaults to AT_KEYEXCHANGE.
//
//  hNCryptKey can be set to decrypt using a CNG private key.
//
//  If CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags passed
//  to CryptMsgControl, then, the hCryptProv is released on the final
//  CryptMsgClose. Not released if CryptMsgControl fails. Also applies
//  to freeing the hNCryptKey.
//
//  pKeyAgree points to the CMSG_KEY_AGREE_RECIPIENT_INFO obtained via
//  CryptMsgGetParam(CMSG_CMS_RECIPIENT_INFO_PARAM) for dwRecipientIndex.
//
//  dwRecipientIndex, dwRecipientEncryptedKeyIndex are the indices of the
//  recipient's encrypted key in the message associated with the hCryptProv's
//  or hNCryptKey's private key.
//
//  OriginatorPublicKey is the originator's public key obtained from either
//  the originator's certificate or the CMSG_KEY_AGREE_RECIPIENT_INFO obtained
//  via the CMSG_CMS_RECIPIENT_INFO_PARAM.
//
//  Note, the message can only be decrypted once.
//--------------------------------------------------------------------------
type
  PCMsgCtrlKeyAgreeDecryptPara = ^TCMsgCtrlKeyAgreeDecryptPara;
  _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA = record
    cbSize: DWORD;

    // NCryptIsKeyHandle() is called to determine the union choice.
    case Integer of
    0: (hCryptProv: HCRYPTPROV);
    1: (hNCryptKey: NCRYPT_KEY_HANDLE;

    // not applicable for hNCryptKey choice
    dwKeySpec: DWORD;

    pKeyAgree: PCMsgKeyAgreeRecipientInfo;
    dwRecipientIndex: DWORD;
    dwRecipientEncryptedKeyIndex: DWORD;
    OriginatorPublicKey: TCryptBitBlob
    );
  end;
  {$EXTERNALSYM _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA}
  CMSG_CTRL_KEY_AGREE_DECRYPT_PARA = _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA;
  {$EXTERNALSYM CMSG_CTRL_KEY_AGREE_DECRYPT_PARA}
  TCMsgCtrlKeyAgreeDecryptPara = _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA;
  PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA = PCMsgCtrlKeyAgreeDecryptPara;
  {$EXTERNALSYM PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA}

//+-------------------------------------------------------------------------
//  CMSG_CTRL_MAIL_LIST_DECRYPT
//
//  Decrypt an ENVELOPED message after it has been decoded for a mail
//  list recipient.
//
//  pMailList points to the CMSG_MAIL_LIST_RECIPIENT_INFO obtained via
//  CryptMsgGetParam(CMSG_CMS_RECIPIENT_INFO_PARAM) for dwRecipientIndex.
//
//  There is 1 choice for the KeyEncryptionKey: an already created CSP key
//  handle. For the key handle choice, hCryptProv must be nonzero. This key
//  handle isn't destroyed.
//
//  If CMSG_CRYPT_RELEASE_CONTEXT_FLAG is set in the dwFlags passed
//  to CryptMsgControl, then, the hCryptProv is released on the final
//  CryptMsgClose. Not released if CryptMsgControl fails.
//
//  For RC2 wrap, the effective key length is obtained from the
//  KeyEncryptionAlgorithm parameters and set on the hKeyEncryptionKey before
//  decrypting.
//
//  Note, the message can only be decrypted once.
//
//  Mail list recipients aren't supported using CNG.
//--------------------------------------------------------------------------
type
  PCMsgCtrlMailListDecryptPara = ^TCMsgCtrlMailListDecryptPara;
  _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA = record
    cbSize: DWORD;
    hCryptProv: HCRYPTPROV;
    pMailList: PCMsgMailListRecipientInfo;
    dwRecipientIndex: DWORD;
    case dwKeyChoice: DWORD of
    CMSG_MAIL_LIST_HANDLE_KEY_CHOICE:
      (hKeyEncryptionKey: HCRYPTKEY);
    0: // Reserve space for a potential pointer choice
      (pvKeyEncryptionKey: Pointer);
  end;
  {$EXTERNALSYM _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA}
  CMSG_CTRL_MAIL_LIST_DECRYPT_PARA = _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA;
  {$EXTERNALSYM CMSG_CTRL_MAIL_LIST_DECRYPT_PARA}
  TCMsgCtrlMailListDecryptPara = _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA;
  PCMSG_CTRL_MAIL_LIST_DECRYPT_PARA = PCMsgCtrlMailListDecryptPara;
  {$EXTERNALSYM PCMSG_CTRL_MAIL_LIST_DECRYPT_PARA}

//+-------------------------------------------------------------------------
//  CMSG_CTRL_VERIFY_HASH
//
//  Verify the hash of a HASHED message after it has been decoded.
//
//  Only the hCryptMsg parameter is used, to specify the message whose
//  hash is being verified.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_ADD_SIGNER
//
//  Add a signer to a signed-data message.
//
//  pvCtrlPara points to a CMSG_SIGNER_ENCODE_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_ADD_CMS_SIGNER_INFO
//
//  Add a signer to a signed-data message.
//
//  Differs from the above, CMSG_CTRL_ADD_SIGNER, wherein, the signer info
//  already contains the signature.
//
//  pvCtrlPara points to a CMSG_CMS_SIGNER_INFO.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_DEL_SIGNER
//
//  Remove a signer from a signed-data or signed-and-enveloped-data message.
//
//  pvCtrlPara points to a DWORD containing the 0-based index of the
//  signer to be removed.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR
//
//  Add an unauthenticated attribute to the SignerInfo of a signed-data or
//  signed-and-enveloped-data message.
//
//  The unauthenticated attribute is input in the form of an encoded blob.
//--------------------------------------------------------------------------
type
  PCMsgCtrlAddSignerUnauthAttrPara = ^TCMsgCtrlAddSignerUnauthAttrPara;
  _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA = record
    cbSize: DWORD;
    dwSignerIndex: DWORD;
    blob: TCryptDataBlob;
  end;
  {$EXTERNALSYM _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA}
  CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA = _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA;
  {$EXTERNALSYM CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA}
  TCMsgCtrlAddSignerUnauthAttrPara = _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA;
  PCMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA = PCMsgCtrlAddSignerUnauthAttrPara;
  {$EXTERNALSYM PCMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA}

//+-------------------------------------------------------------------------
//  CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR
//
//  Delete an unauthenticated attribute from the SignerInfo of a signed-data
//  or signed-and-enveloped-data message.
//
//  The unauthenticated attribute to be removed is specified by
//  a 0-based index.
//--------------------------------------------------------------------------
type
  PCMsgCtrlDelSignerUnauthAttrPara = ^TCMsgCtrlDelSignerUnauthAttrPara;
  _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA = record
    cbSize: DWORD;
    dwSignerIndex: DWORD;
    dwUnauthAttrIndex: DWORD;
  end;
  {$EXTERNALSYM _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA}
  CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA = _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA;
  {$EXTERNALSYM CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA}
  TCMsgCtrlDelSignerUnauthAttrPara = _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA;
  PCMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA = PCMsgCtrlDelSignerUnauthAttrPara;
  {$EXTERNALSYM PCMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA}

//+-------------------------------------------------------------------------
//  CMSG_CTRL_ADD_CERT
//
//  Add a certificate to a signed-data or signed-and-enveloped-data message.
//
//  pvCtrlPara points to a CRYPT_DATA_BLOB containing the certificate's
//  encoded bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_DEL_CERT
//
//  Delete a certificate from a signed-data or signed-and-enveloped-data
//  message.
//
//  pvCtrlPara points to a DWORD containing the 0-based index of the
//  certificate to be removed.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_ADD_CRL
//
//  Add a CRL to a signed-data or signed-and-enveloped-data message.
//
//  pvCtrlPara points to a CRYPT_DATA_BLOB containing the CRL's
//  encoded bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_DEL_CRL
//
//  Delete a CRL from a signed-data or signed-and-enveloped-data message.
//
//  pvCtrlPara points to a DWORD containing the 0-based index of the CRL
//  to be removed.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_ADD_ATTR_CERT
//
//  Add an attribute certificate to a signed-data message.
//
//  pvCtrlPara points to a CRYPT_DATA_BLOB containing the attribute
//  certificate's encoded bytes.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CTRL_DEL_ATTR_CERT
//
//  Delete an attribute certificate from a signed-data message.
//
//  pvCtrlPara points to a DWORD containing the 0-based index of the
//  attribute certificate to be removed.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
//  Verify a countersignature, at the SignerInfo level.
//  ie. verify that pbSignerInfoCountersignature contains the encrypted
//  hash of the encryptedDigest field of pbSignerInfo.
//
//  hCryptProv is used to hash the encryptedDigest field of pbSignerInfo.
//  The only fields referenced from pciCountersigner are SerialNumber, Issuer,
//  and SubjectPublicKeyInfo.
//--------------------------------------------------------------------------
function CryptMsgVerifyCountersignatureEncoded(
  hCryptProv: HCRYPTPROV_LEGACY;
  dwEncodingType: DWORD;
  pbSignerInfo: PByte;
  cbSignerInfo: DWORD;
  pbSignerInfoCountersignature: PByte;
  cbSignerInfoCountersignature: DWORD;
  pciCountersigner: PCertInfo): BOOL; winapi;
{$EXTERNALSYM CryptMsgVerifyCountersignatureEncoded}

//+-------------------------------------------------------------------------
//  Verify a countersignature, at the SignerInfo level.
//  ie. verify that pbSignerInfoCountersignature contains the encrypted
//  hash of the encryptedDigest field of pbSignerInfo.
//
//  hCryptProv is used to hash the encryptedDigest field of pbSignerInfo.
//
//  The signer can be a CERT_PUBLIC_KEY_INFO, certificate context or a
//  chain context.
//--------------------------------------------------------------------------
function CryptMsgVerifyCountersignatureEncodedEx(
  hCryptProv: HCRYPTPROV_LEGACY;
  dwEncodingType: DWORD;
  pbSignerInfo: PByte;
  cbSignerInfo: DWORD;
  pbSignerInfoCountersignature: PByte;
  cbSignerInfoCountersignature: DWORD;
  dwSignerType: DWORD;
  pvSigner: Pointer;
  dwFlags: DWORD;
  pvExtra: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptMsgVerifyCountersignatureEncodedEx}

// See CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA for dwSignerType definitions

// When set, pvExtra points to const CERT_STRONG_SIGN_PARA struct
const
  CMSG_VERIFY_COUNTER_SIGN_ENABLE_STRONG_FLAG        = $00000001;
  {$EXTERNALSYM CMSG_VERIFY_COUNTER_SIGN_ENABLE_STRONG_FLAG}

//+-------------------------------------------------------------------------
//  Countersign an already-existing signature in a message
//
//  dwIndex is a zero-based index of the SignerInfo to be countersigned.
//--------------------------------------------------------------------------
function CryptMsgCountersign(
  hCryptMsg: HCRYPTMSG;
  dwIndex: DWORD;
  cCountersigners: DWORD;
  rgCountersigners: PCMsgSignerEncodeInfo): BOOL; winapi;
{$EXTERNALSYM CryptMsgCountersign}

//+-------------------------------------------------------------------------
//  Countersign an already-existing signature (encoded SignerInfo).
//  Output an encoded SignerInfo blob, suitable for use as a countersignature
//  attribute in the unauthenticated attributes of a signed-data or
//  signed-and-enveloped-data message.
//--------------------------------------------------------------------------
function CryptMsgCountersignEncoded(
  dwEncodingType: DWORD;
  pbSignerInfo: PByte;
  cbSignerInfo: DWORD;
  cCountersigners: DWORD;
  rgCountersigners: PCMsgSignerEncodeInfo;
  pbCountersignature: PByte;
  var pcbCountersignature: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptMsgCountersignEncoded}

//+-------------------------------------------------------------------------
//  CryptMsg OID installable functions
//--------------------------------------------------------------------------
type
  PFN_CMSG_ALLOC = function(
    cb: size_t): Pointer; winapi;
  {$EXTERNALSYM PFN_CMSG_ALLOC}
  TFnCMsgAlloc = PFN_CMSG_ALLOC;

type
  PFN_CMSG_FREE = procedure(
    pv: Pointer); winapi;
  {$EXTERNALSYM PFN_CMSG_FREE}
  TFnCMsgFree = PFN_CMSG_FREE;

// Note, the following 3 installable functions are obsolete and have been
// replaced with GenContentEncryptKey, ExportKeyTrans, ExportKeyAgree,
// ExportMailList, ImportKeyTrans, ImportKeyAgree and ImportMailList
// installable functions.

// If *phCryptProv is NULL upon entry, then, if supported, the installable
// function should acquire a default provider and return. Note, its up
// to the installable function to release at process detach.
//
// If paiEncrypt->Parameters.cbData is 0, then, the callback may optionally
// return default encoded parameters in *ppbEncryptParameters and
// *pcbEncryptParameters. pfnAlloc must be called for the allocation.
const
  CMSG_OID_GEN_ENCRYPT_KEY_FUNC  = 'CryptMsgDllGenEncryptKey';
  {$EXTERNALSYM CMSG_OID_GEN_ENCRYPT_KEY_FUNC}

type
  PFN_CMSG_GEN_ENCRYPT_KEY = function(
    var phCryptProv: HCRYPTPROV;
    paiEncrypt: PCryptAlgorithmIdentifier;
    pvEncryptAuxInfo: PVOID;
    pPublicKeyInfo: PCertPublicKeyInfo;
    pfnAlloc: TFnCMsgAlloc;
    out phEncryptKey: HCRYPTKEY;
    out ppbEncryptParameters: PByte;
    out pcbEncryptParameters: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_GEN_ENCRYPT_KEY}
  TFnCMsgGenEncryptKey = PFN_CMSG_GEN_ENCRYPT_KEY;

const
  CMSG_OID_EXPORT_ENCRYPT_KEY_FUNC  = 'CryptMsgDllExportEncryptKey';
  {$EXTERNALSYM CMSG_OID_EXPORT_ENCRYPT_KEY_FUNC}

type
  PFN_CMSG_EXPORT_ENCRYPT_KEY = function(
    hCryptProv: HCRYPTPROV;
    hEncryptKey: HCRYPTKEY;
    pPublicKeyInfo: PCertPublicKeyInfo;
    pbData: PByte;
    pcbData: PDWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_EXPORT_ENCRYPT_KEY}
  TFnCMsgExportEncryptKey = PFN_CMSG_EXPORT_ENCRYPT_KEY;

const
  CMSG_OID_IMPORT_ENCRYPT_KEY_FUNC  = 'CryptMsgDllImportEncryptKey';
  {$EXTERNALSYM CMSG_OID_IMPORT_ENCRYPT_KEY_FUNC}

type
  PFN_CMSG_IMPORT_ENCRYPT_KEY = function(
    hCryptProv: HCRYPTPROV;
    dwKeySpec: DWORD;
    paiEncrypt: PCryptAlgorithmIdentifier;
    paiPubKey: PCryptAlgorithmIdentifier;
    pbEncodedKey: PByte;
    cbEncodedKey: DWORD;
    out phEncryptKey: HCRYPTKEY): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_IMPORT_ENCRYPT_KEY}
  TFnCMsgImportEncryptKey = PFN_CMSG_IMPORT_ENCRYPT_KEY;

// To get the default installable function for GenContentEncryptKey,
// ExportKeyTrans, ExportKeyAgree, ExportMailList, ImportKeyTrans,
// ImportKeyAgree or ImportMailList call CryptGetOIDFunctionAddress()
// with the pszOID argument set to the following constant. dwEncodingType
// should be set to CRYPT_ASN_ENCODING or X509_ASN_ENCODING.
const
  CMSG_DEFAULT_INSTALLABLE_FUNC_OID  = LPCSTR(1);
  {$EXTERNALSYM CMSG_DEFAULT_INSTALLABLE_FUNC_OID}

//+-------------------------------------------------------------------------
//  Content Encrypt Info
//
//  The following data structure contains the information shared between
//  the GenContentEncryptKey and the ExportKeyTrans, ExportKeyAgree and
//  ExportMailList installable functions.
//
//  For a ContentEncryptionAlgorithm.pszObjId having a "Special" algid, only
//  supported via CNG, for example, AES, then, fCNG will be set.
//  fCNG will also be set to TRUE for any ECC agreement or OAEP RSA transport
//  recipients.
//
//  When, fCNG is TRUE, the hCNGContentEncryptKey choice is selected and
//  pbCNGContentEncryptKeyObject and pbContentEncryptKey will be pfnAlloc'ed.
//--------------------------------------------------------------------------
type
  PCMsgContentEncryptInfo = ^TCMsgContentEncryptInfo;
  _CMSG_CONTENT_ENCRYPT_INFO = record
    cbSize: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    ContentEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvEncryptionAuxInfo: Pointer;
    cRecipients: DWORD;
    rgCmsRecipients: PCMsgRecipientEncodeInfo;
    pfnAlloc: TFnCMsgAlloc;
    pfnFree: TFnCMsgFree;
    dwEncryptFlags: DWORD;
    case Integer of
    0:  // fCNG == FALSE
      (hContentEncryptKey: HCRYPTKEY);
    1:  // fCNG == TRUE
      (hCNGContentEncryptKey: BCRYPT_KEY_HANDLE;
    dwFlags: DWORD;

    fCNG: BOOL;
    // When fCNG == TRUE, pfnAlloc'ed
    pbCNGContentEncryptKeyObject: PByte;
    pbContentEncryptKey: PByte;
    cbContentEncryptKey: DWORD
    );
  end;
  {$EXTERNALSYM _CMSG_CONTENT_ENCRYPT_INFO}
  CMSG_CONTENT_ENCRYPT_INFO = _CMSG_CONTENT_ENCRYPT_INFO;
  {$EXTERNALSYM CMSG_CONTENT_ENCRYPT_INFO}
  TCMsgContentEncryptInfo = _CMSG_CONTENT_ENCRYPT_INFO;
  PCMSG_CONTENT_ENCRYPT_INFO = PCMsgContentEncryptInfo;
  {$EXTERNALSYM PCMSG_CONTENT_ENCRYPT_INFO}

const
  CMSG_CONTENT_ENCRYPT_PAD_ENCODED_LEN_FLAG  = $00000001;
  {$EXTERNALSYM CMSG_CONTENT_ENCRYPT_PAD_ENCODED_LEN_FLAG}

  CMSG_CONTENT_ENCRYPT_FREE_PARA_FLAG        = $00000001;
  {$EXTERNALSYM CMSG_CONTENT_ENCRYPT_FREE_PARA_FLAG}
  CMSG_CONTENT_ENCRYPT_FREE_OBJID_FLAG       = $00000002;
  {$EXTERNALSYM CMSG_CONTENT_ENCRYPT_FREE_OBJID_FLAG}
  CMSG_CONTENT_ENCRYPT_RELEASE_CONTEXT_FLAG  = $00008000;
  {$EXTERNALSYM CMSG_CONTENT_ENCRYPT_RELEASE_CONTEXT_FLAG}

//+-------------------------------------------------------------------------
// Upon input, ContentEncryptInfo has been initialized from the
// EnvelopedEncodeInfo.
//
// Note, if rgpRecipients instead of rgCmsRecipients are set in the
// EnvelopedEncodeInfo, then, the rgpRecipients have been converted
// to rgCmsRecipients in the ContentEncryptInfo.
//
// For fCNG == FALSE, the following fields may be changed in ContentEncryptInfo:
//      hContentEncryptKey
//      hCryptProv
//      ContentEncryptionAlgorithm.pszObjId
//      ContentEncryptionAlgorithm.Parameters
//      dwFlags
//
// For fCNG == TRUE, the following fields may be changed in ContentEncryptInfo:
//      hCNGContentEncryptKey
//      pbCNGContentEncryptKeyObject
//      pbContentEncryptKey
//      cbContentEncryptKey
//      ContentEncryptionAlgorithm.pszObjId
//      ContentEncryptionAlgorithm.Parameters
//      dwFlags
//
// All other fields in the ContentEncryptInfo are READONLY.
//
// If CMSG_CONTENT_ENCRYPT_PAD_ENCODED_LEN_FLAG is set upon entry
// in dwEncryptFlags, then, any potentially variable length encoded
// output should be padded with zeroes to always obtain the
// same maximum encoded length. This is necessary for
// CryptMsgCalculateEncodedLength() or CryptMsgOpenToEncode() with
// definite length streaming.
//
// For fCNG == FALSE:
//      The hContentEncryptKey must be updated.
//
//      If hCryptProv is NULL upon input, then, it must be updated.
//      If a HCRYPTPROV is acquired that must be released, then, the
//      CMSG_CONTENT_ENCRYPT_RELEASE_CONTEXT_FLAG must be set in dwFlags.
// Otherwise, for fCNG == TRUE:
//      The hCNGContentEncryptKey and cbContentEncryptKey must be updated and
//      pbCNGContentEncryptKeyObject and pbContentEncryptKey pfnAlloc'ed.
//      This key will be freed and destroyed when hCryptMsg is closed.
//
// If ContentEncryptionAlgorithm.pszObjId is changed, then, the
// CMSG_CONTENT_ENCRYPT_FREE_OBJID_FLAG must be set in dwFlags.
// If ContentEncryptionAlgorithm.Parameters is updated, then, the
// CMSG_CONTENT_ENCRYPT_FREE_PARA_FLAG must be set in dwFlags. pfnAlloc and
// pfnFree must be used for doing the allocation.
//
// ContentEncryptionAlgorithm.pszObjId is used to get the OIDFunctionAddress.
//--------------------------------------------------------------------------

// The following CAPI1 installable function is called when fCNG == FALSE.
const
  CMSG_OID_GEN_CONTENT_ENCRYPT_KEY_FUNC = 'CryptMsgDllGenContentEncryptKey';
  {$EXTERNALSYM CMSG_OID_GEN_CONTENT_ENCRYPT_KEY_FUNC}
  CMSG_OID_CAPI1_GEN_CONTENT_ENCRYPT_KEY_FUNC = CMSG_OID_GEN_CONTENT_ENCRYPT_KEY_FUNC;
  {$EXTERNALSYM CMSG_OID_CAPI1_GEN_CONTENT_ENCRYPT_KEY_FUNC}

type
  PFN_CMSG_GEN_CONTENT_ENCRYPT_KEY = function(
    pContentEncryptInfo: PCMsgContentEncryptInfo;
    dwFlags: DWORD;
    pvReserved: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_GEN_CONTENT_ENCRYPT_KEY}
  TFnCMsgGenContentEncryptKey = PFN_CMSG_GEN_CONTENT_ENCRYPT_KEY;

// The following installable function is called when fCNG == TRUE. It has the
// same API signature as for the above
// CMSG_OID_CAPI1_GEN_CONTENT_ENCRYPT_KEY_FUNC.
const
  CMSG_OID_CNG_GEN_CONTENT_ENCRYPT_KEY_FUNC = 'CryptMsgDllCNGGenContentEncryptKey';
  {$EXTERNALSYM CMSG_OID_CNG_GEN_CONTENT_ENCRYPT_KEY_FUNC}

//+-------------------------------------------------------------------------
//  Key Transport Encrypt Info
//
//  The following data structure contains the information updated by the
//  ExportKeyTrans installable function.
//--------------------------------------------------------------------------
type
  PCMsgKeyTransEncryptInfo = ^TCMsgKeyTransEncryptInfo;
  _CMSG_KEY_TRANS_ENCRYPT_INFO = record
    cbSize: DWORD;
    dwRecipientIndex: DWORD;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    EncryptedKey: TCryptDataBlob;
    dwFlags: DWORD;
  end;
  {$EXTERNALSYM _CMSG_KEY_TRANS_ENCRYPT_INFO}
  CMSG_KEY_TRANS_ENCRYPT_INFO = _CMSG_KEY_TRANS_ENCRYPT_INFO;
  {$EXTERNALSYM CMSG_KEY_TRANS_ENCRYPT_INFO}
  TCMsgKeyTransEncryptInfo = _CMSG_KEY_TRANS_ENCRYPT_INFO;
  PCMSG_KEY_TRANS_ENCRYPT_INFO = PCMsgKeyTransEncryptInfo;
  {$EXTERNALSYM PCMSG_KEY_TRANS_ENCRYPT_INFO}

const
  CMSG_KEY_TRANS_ENCRYPT_FREE_PARA_FLAG      = $00000001;
  {$EXTERNALSYM CMSG_KEY_TRANS_ENCRYPT_FREE_PARA_FLAG}
  CMSG_KEY_TRANS_ENCRYPT_FREE_OBJID_FLAG     = $00000002;
  {$EXTERNALSYM CMSG_KEY_TRANS_ENCRYPT_FREE_OBJID_FLAG}

//+-------------------------------------------------------------------------
// Upon input, KeyTransEncryptInfo has been initialized from the
// KeyTransEncodeInfo.
//
// The following fields may be changed in KeyTransEncryptInfo:
//      EncryptedKey
//      KeyEncryptionAlgorithm.pszObjId
//      KeyEncryptionAlgorithm.Parameters
//      dwFlags
//
// All other fields in the KeyTransEncryptInfo are READONLY.
//
// The EncryptedKey must be updated. The pfnAlloc and pfnFree specified in
// ContentEncryptInfo must be used for doing the allocation.
//
// If the KeyEncryptionAlgorithm.pszObjId is changed, then, the
// CMSG_KEY_TRANS_ENCRYPT_FREE_OBJID_FLAG  must be set in dwFlags.
// If the KeyEncryptionAlgorithm.Parameters is updated, then, the
// CMSG_KEY_TRANS_ENCRYPT_FREE_PARA_FLAG must be set in dwFlags.
// The pfnAlloc and pfnFree specified in ContentEncryptInfo must be used
// for doing the allocation.
//
// KeyEncryptionAlgorithm.pszObjId is used to get the OIDFunctionAddress.
//--------------------------------------------------------------------------

// The following CAPI1 installable function is called when
// pContentEncryptInfo->fCNG == FALSE.
const
  CMSG_OID_EXPORT_KEY_TRANS_FUNC = 'CryptMsgDllExportKeyTrans';
  {$EXTERNALSYM CMSG_OID_EXPORT_KEY_TRANS_FUNC}
  CMSG_OID_CAPI1_EXPORT_KEY_TRANS_FUNC = CMSG_OID_EXPORT_KEY_TRANS_FUNC;
  {$EXTERNALSYM CMSG_OID_CAPI1_EXPORT_KEY_TRANS_FUNC}

type
  PFN_CMSG_EXPORT_KEY_TRANS = function(
    pContentEncryptInfo: PCMsgContentEncryptInfo;
    pKeyTransEncodeInfo: PCMsgKeyTransRecipientEncodeInfo;
    pKeyTransEncryptInfo: PCMsgKeyTransEncryptInfo;
    dwFlags: DWORD;
    pvReserved: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_EXPORT_KEY_TRANS}
  TFnCMsgExportKeyTrans = PFN_CMSG_EXPORT_KEY_TRANS;

// The following CNG installable function is called when
// pContentEncryptInfo->fCNG == TRUE. It has the same API signature as for
// the above CMSG_OID_CAPI1_EXPORT_KEY_TRANS_FUNC.
const
  CMSG_OID_CNG_EXPORT_KEY_TRANS_FUNC = 'CryptMsgDllCNGExportKeyTrans';
  {$EXTERNALSYM CMSG_OID_CNG_EXPORT_KEY_TRANS_FUNC}

//+-------------------------------------------------------------------------
//  Key Agree Key Encrypt Info
//
//  The following data structure contains the information updated by the
//  ExportKeyAgree installable function for each encrypted key agree
//  recipient.
//--------------------------------------------------------------------------
type
  PCMsgKeyAgreeKeyEncryptInfo= ^TCMsgKeyAgreeKeyEncryptInfo;
  _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO = record
    cbSize: DWORD;
    EncryptedKey: TCryptDataBlob;
  end;
  {$EXTERNALSYM _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO}
  CMSG_KEY_AGREE_KEY_ENCRYPT_INFO = _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO;
  {$EXTERNALSYM CMSG_KEY_AGREE_KEY_ENCRYPT_INFO}
  TCMsgKeyAgreeKeyEncryptInfo = _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO;
  PCMSG_KEY_AGREE_KEY_ENCRYPT_INFO = PCMsgKeyAgreeKeyEncryptInfo;
  {$EXTERNALSYM PCMSG_KEY_AGREE_KEY_ENCRYPT_INFO}

//+-------------------------------------------------------------------------
//  Key Agree Encrypt Info
//
//  The following data structure contains the information applicable to
//  all recipients. Its updated by the ExportKeyAgree installable function.
//--------------------------------------------------------------------------
type
  PCMsgKeyAgreeEncryptInfo = ^TCMsgKeyAgreeEncryptInfo;
  _CMSG_KEY_AGREE_ENCRYPT_INFO = record
    cbSize: DWORD;
    dwRecipientIndex: DWORD;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    UserKeyingMaterial: TCryptDataBlob;
    case dwOriginatorChoice: DWORD of
    CMSG_KEY_AGREE_ORIGINATOR_CERT:
      (OriginatorCertId: TCertID);
    CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY:
      (OriginatorPublicKeyInfo: TCertPublicKeyInfo;
    cKeyAgreeKeyEncryptInfo: DWORD;
    rgpKeyAgreeKeyEncryptInfo: ^PCMsgKeyAgreeKeyEncryptInfo;
    dwFlags: DWORD
    );
  end;
  {$EXTERNALSYM _CMSG_KEY_AGREE_ENCRYPT_INFO}
  CMSG_KEY_AGREE_ENCRYPT_INFO = _CMSG_KEY_AGREE_ENCRYPT_INFO;
  {$EXTERNALSYM CMSG_KEY_AGREE_ENCRYPT_INFO}
  TCMsgKeyAgreeEncryptInfo = _CMSG_KEY_AGREE_ENCRYPT_INFO;
  PCMSG_KEY_AGREE_ENCRYPT_INFO = PCMsgKeyAgreeEncryptInfo;
  {$EXTERNALSYM PCMSG_KEY_AGREE_ENCRYPT_INFO}

const
  CMSG_KEY_AGREE_ENCRYPT_FREE_PARA_FLAG          = $00000001;
  {$EXTERNALSYM CMSG_KEY_AGREE_ENCRYPT_FREE_PARA_FLAG}
  CMSG_KEY_AGREE_ENCRYPT_FREE_MATERIAL_FLAG      = $00000002;
  {$EXTERNALSYM CMSG_KEY_AGREE_ENCRYPT_FREE_MATERIAL_FLAG}
  CMSG_KEY_AGREE_ENCRYPT_FREE_PUBKEY_ALG_FLAG    = $00000004;
  {$EXTERNALSYM CMSG_KEY_AGREE_ENCRYPT_FREE_PUBKEY_ALG_FLAG}
  CMSG_KEY_AGREE_ENCRYPT_FREE_PUBKEY_PARA_FLAG   = $00000008;
  {$EXTERNALSYM CMSG_KEY_AGREE_ENCRYPT_FREE_PUBKEY_PARA_FLAG}
  CMSG_KEY_AGREE_ENCRYPT_FREE_PUBKEY_BITS_FLAG   = $00000010;
  {$EXTERNALSYM CMSG_KEY_AGREE_ENCRYPT_FREE_PUBKEY_BITS_FLAG}
  CMSG_KEY_AGREE_ENCRYPT_FREE_OBJID_FLAG         = $00000020;
  {$EXTERNALSYM CMSG_KEY_AGREE_ENCRYPT_FREE_OBJID_FLAG}

//+-------------------------------------------------------------------------
// Upon input, KeyAgreeEncryptInfo has been initialized from the
// KeyAgreeEncodeInfo.
//
// The following fields may be changed in KeyAgreeEncryptInfo:
//      KeyEncryptionAlgorithm.pszObjId
//      KeyEncryptionAlgorithm.Parameters
//      UserKeyingMaterial
//      dwOriginatorChoice
//      OriginatorCertId
//      OriginatorPublicKeyInfo
//      dwFlags
//
// All other fields in the KeyAgreeEncryptInfo are READONLY.
//
// If the KeyEncryptionAlgorithm.pszObjId is changed, then, the
// CMSG_KEY_AGREE_ENCRYPT_FREE_OBJID_FLAG  must be set in dwFlags.
// If the KeyEncryptionAlgorithm.Parameters is updated, then, the
// CMSG_KEY_AGREE_ENCRYPT_FREE_PARA_FLAG must be set in dwFlags.
// The pfnAlloc and pfnFree specified in ContentEncryptInfo must be used
// for doing the allocation.
//
// If the UserKeyingMaterial is updated, then, the
// CMSG_KEY_AGREE_ENCRYPT_FREE_MATERIAL_FLAG must be set in dwFlags.
// pfnAlloc and pfnFree must be used for doing the allocation.
//
// The dwOriginatorChoice must be updated to either
// CMSG_KEY_AGREE_ORIGINATOR_CERT or CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY.
//
// If the OriginatorPublicKeyInfo is updated, then, the appropriate
// CMSG_KEY_AGREE_ENCRYPT_FREE_PUBKEY_*_FLAG must be set in dwFlags and
// pfnAlloc and pfnFree must be used for doing the allocation.
//
// If CMSG_CONTENT_ENCRYPT_PAD_ENCODED_LEN_FLAG is set upon entry
// in pContentEncryptInfo->dwEncryptFlags, then, the OriginatorPublicKeyInfo's
// Ephemeral PublicKey should be padded with zeroes to always obtain the
// same maximum encoded length. Note, the length of the generated ephemeral Y
// public key can vary depending on the number of leading zero bits.
//
// Upon input, the array of *rgpKeyAgreeKeyEncryptInfo has been initialized.
// The EncryptedKey must be updated for each recipient key.
// The pfnAlloc and pfnFree specified in
// ContentEncryptInfo must be used for doing the allocation.
//
// KeyEncryptionAlgorithm.pszObjId is used to get the OIDFunctionAddress.
//--------------------------------------------------------------------------

// The following CAPI1 installable function is called when
// pContentEncryptInfo->fCNG == FALSE.
const
  CMSG_OID_EXPORT_KEY_AGREE_FUNC = 'CryptMsgDllExportKeyAgree';
  {$EXTERNALSYM CMSG_OID_EXPORT_KEY_AGREE_FUNC}
  CMSG_OID_CAPI1_EXPORT_KEY_AGREE_FUNC = CMSG_OID_EXPORT_KEY_AGREE_FUNC;
  {$EXTERNALSYM CMSG_OID_CAPI1_EXPORT_KEY_AGREE_FUNC}

type
  PFN_CMSG_EXPORT_KEY_AGREE = function(
    pContentEncryptInfo: PCMsgContentEncryptInfo;
    pKeyAgreeEncodeInfo: PCMsgKeyAgreeRecipientEncodeInfo;
    pKeyAgreeEncryptInfo: PCMsgKeyAgreeEncryptInfo;
    dwFlags: DWORD;
    pvReserved: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_EXPORT_KEY_AGREE}
  TFnCMsgExportKeyAgree = PFN_CMSG_EXPORT_KEY_AGREE;

// The following CNG installable function is called when
// pContentEncryptInfo->fCNG == TRUE. It has the same API signature as for
// the above CMSG_OID_CAPI1_EXPORT_KEY_AGREE_FUNC.
const
  CMSG_OID_CNG_EXPORT_KEY_AGREE_FUNC = 'CryptMsgDllCNGExportKeyAgree';
  {$EXTERNALSYM CMSG_OID_CNG_EXPORT_KEY_AGREE_FUNC}

//+-------------------------------------------------------------------------
//  Mail List Encrypt Info
//
//  The following data structure contains the information updated by the
//  ExportMailList installable function.
//--------------------------------------------------------------------------
type
  PCMsgMailListEncryptInfo = ^TCMsgMailListEncryptInfo;
  _CMSG_MAIL_LIST_ENCRYPT_INFO = record
    cbSize: DWORD;
    dwRecipientIndex: DWORD;
    KeyEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    EncryptedKey: TCryptDataBlob;
    dwFlags: DWORD;
  end;
  {$EXTERNALSYM _CMSG_MAIL_LIST_ENCRYPT_INFO}
  CMSG_MAIL_LIST_ENCRYPT_INFO = _CMSG_MAIL_LIST_ENCRYPT_INFO;
  {$EXTERNALSYM CMSG_MAIL_LIST_ENCRYPT_INFO}
  TCMsgMailListEncryptInfo = _CMSG_MAIL_LIST_ENCRYPT_INFO;
  PCMSG_MAIL_LIST_ENCRYPT_INFO = PCMsgMailListEncryptInfo;
  {$EXTERNALSYM PCMSG_MAIL_LIST_ENCRYPT_INFO}

const
  CMSG_MAIL_LIST_ENCRYPT_FREE_PARA_FLAG      = $00000001;
  {$EXTERNALSYM CMSG_MAIL_LIST_ENCRYPT_FREE_PARA_FLAG}
  CMSG_MAIL_LIST_ENCRYPT_FREE_OBJID_FLAG     = $00000002;
  {$EXTERNALSYM CMSG_MAIL_LIST_ENCRYPT_FREE_OBJID_FLAG}

//+-------------------------------------------------------------------------
// Upon input, MailListEncryptInfo has been initialized from the
// MailListEncodeInfo.
//
// The following fields may be changed in MailListEncryptInfo:
//      EncryptedKey
//      KeyEncryptionAlgorithm.pszObjId
//      KeyEncryptionAlgorithm.Parameters
//      dwFlags
//
// All other fields in the MailListEncryptInfo are READONLY.
//
// The EncryptedKey must be updated. The pfnAlloc and pfnFree specified in
// ContentEncryptInfo must be used for doing the allocation.
//
// If the KeyEncryptionAlgorithm.pszObjId is changed, then, the
// CMSG_MAIL_LIST_ENCRYPT_FREE_OBJID_FLAG must be set in dwFlags.
// If the KeyEncryptionAlgorithm.Parameters is updated, then, the
// CMSG_MAIL_LIST_ENCRYPT_FREE_PARA_FLAG must be set in dwFlags.
// The pfnAlloc and pfnFree specified in ContentEncryptInfo must be used
// for doing the allocation.
//
// KeyEncryptionAlgorithm.pszObjId is used to get the OIDFunctionAddress.
//
// Note, only has a CAPI1 installable function. No CNG installable function.
//--------------------------------------------------------------------------
// The following CAPI1 installable function is called when
// pContentEncryptInfo->fCNG == FALSE.
const
  CMSG_OID_EXPORT_MAIL_LIST_FUNC = 'CryptMsgDllExportMailList';
  {$EXTERNALSYM CMSG_OID_EXPORT_MAIL_LIST_FUNC}
  CMSG_OID_CAPI1_EXPORT_MAIL_LIST_FUNC = CMSG_OID_EXPORT_MAIL_LIST_FUNC;
  {$EXTERNALSYM CMSG_OID_CAPI1_EXPORT_MAIL_LIST_FUNC}

type
  PFN_CMSG_EXPORT_MAIL_LIST = function(
    pContentEncryptInfo: PCMsgContentEncryptInfo;
    pMailListEncodeInfo: PCMsgMailListRecipientEncodeInfo;
    pMailListEncryptInfo: PCMsgMailListEncryptInfo;
    dwFlags: DWORD;
    pvReserved: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_EXPORT_MAIL_LIST}
  TFnCMsgExportMailList = PFN_CMSG_EXPORT_MAIL_LIST;

//+-------------------------------------------------------------------------
// CAPI1 OID Installable functions for importing an encoded and encrypted
// content encryption key.
//
// There's a different installable function for each CMS Recipient choice:
//  ImportKeyTrans
//  ImportKeyAgree
//  ImportMailList
//
// Iterates through the following OIDs to get the OID installable function:
//   KeyEncryptionOID!ContentEncryptionOID
//   KeyEncryptionOID
//   ContentEncryptionOID
//
// If the OID installable function doesn't support the specified
// KeyEncryption and ContentEncryption OIDs, then, return FALSE with
// LastError set to E_NOTIMPL.
//--------------------------------------------------------------------------
const
  CMSG_OID_IMPORT_KEY_TRANS_FUNC  = 'CryptMsgDllImportKeyTrans';
  {$EXTERNALSYM CMSG_OID_IMPORT_KEY_TRANS_FUNC}
  CMSG_OID_CAPI1_IMPORT_KEY_TRANS_FUNC = CMSG_OID_IMPORT_KEY_TRANS_FUNC;
  {$EXTERNALSYM CMSG_OID_CAPI1_IMPORT_KEY_TRANS_FUNC}

type
  PFN_CMSG_IMPORT_KEY_TRANS= function(
    pContentEncryptionAlgorithm: PCryptAlgorithmIdentifier;
    pKeyTransDecryptPara: PCMsgCtrlKeyTransDecryptPara;
    dwFlags: DWORD;
    pvReserved: Pointer;
    out phContentEncryptKey: HCRYPTKEY): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_IMPORT_KEY_TRANS}
  TFnCMsgImportKeyTrans = PFN_CMSG_IMPORT_KEY_TRANS;

const
  CMSG_OID_IMPORT_KEY_AGREE_FUNC  = 'CryptMsgDllImportKeyAgree';
  {$EXTERNALSYM CMSG_OID_IMPORT_KEY_AGREE_FUNC}
  CMSG_OID_CAPI1_IMPORT_KEY_AGREE_FUNC = CMSG_OID_IMPORT_KEY_AGREE_FUNC;
  {$EXTERNALSYM CMSG_OID_CAPI1_IMPORT_KEY_AGREE_FUNC}

type
  PFN_CMSG_IMPORT_KEY_AGREE = function(
    pContentEncryptionAlgorithm: PCryptAlgorithmIdentifier;
    pKeyAgreeDecryptPara: PCMsgCtrlKeyAgreeDecryptPara;
    dwFlags: DWORD;
    pvReserved: Pointer;
    out phContentEncryptKey: HCRYPTKEY): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_IMPORT_KEY_AGREE}
  TFnCMsgImportKeyAgree = PFN_CMSG_IMPORT_KEY_AGREE;

const
  CMSG_OID_IMPORT_MAIL_LIST_FUNC  = 'CryptMsgDllImportMailList';
  {$EXTERNALSYM CMSG_OID_IMPORT_MAIL_LIST_FUNC}
  CMSG_OID_CAPI1_IMPORT_MAIL_LIST_FUNC = CMSG_OID_IMPORT_MAIL_LIST_FUNC;
  {$EXTERNALSYM CMSG_OID_CAPI1_IMPORT_MAIL_LIST_FUNC}

type
  PFN_CMSG_IMPORT_MAIL_LIST = function(
    pContentEncryptionAlgorithm: PCryptAlgorithmIdentifier;
    pMailListDecryptPara: PCMsgCtrlMailListDecryptPara;
    dwFlags: DWORD;
    pvReserved: Pointer;
    out phContentEncryptKey: HCRYPTKEY): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_IMPORT_MAIL_LIST}
  TFnCMsgImportMailList = PFN_CMSG_IMPORT_MAIL_LIST;

//+-------------------------------------------------------------------------
//  CNG Content Decrypt Info
//
//  The following data structure contains the information shared between
//  CNGImportKeyTrans, CNGImportKeyAgree and CNGImportContentEncryptKey
//  installable functions.
//
//  pbContentEncryptKey and pbCNGContentEncryptKeyObject are allocated
//  and freed via pfnAlloc and pfnFree.
//--------------------------------------------------------------------------
type
  PCMsgCNGContentDecryptInfo = ^TCMsgCNGContentDecryptInfo;
  _CMSG_CNG_CONTENT_DECRYPT_INFO = record
    cbSize: DWORD;
    ContentEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pfnAlloc: TFnCMsgAlloc;
    pfnFree: TFnCMsgFree;

    // This key must be used over the one in the DecryptPara. An
    // HCRYPTPROV in the DecryptPara may have been converted to a
    // NCRYPT_KEY_HANDLE.
    hNCryptKey: NCRYPT_KEY_HANDLE;

    pbContentEncryptKey: PByte;
    cbContentEncryptKey: DWORD;

    hCNGContentEncryptKey: BCRYPT_KEY_HANDLE;
    pbCNGContentEncryptKeyObject: PByte;
  end;
  {$EXTERNALSYM _CMSG_CNG_CONTENT_DECRYPT_INFO}
  CMSG_CNG_CONTENT_DECRYPT_INFO = _CMSG_CNG_CONTENT_DECRYPT_INFO;
  {$EXTERNALSYM CMSG_CNG_CONTENT_DECRYPT_INFO}
  TCMsgCNGContentDecryptInfo = _CMSG_CNG_CONTENT_DECRYPT_INFO;
  PCMSG_CNG_CONTENT_DECRYPT_INFO = PCMsgCNGContentDecryptInfo;
  {$EXTERNALSYM PCMSG_CNG_CONTENT_DECRYPT_INFO}

//+-------------------------------------------------------------------------
// CNG OID Installable function for importing and decrypting a key transport
// recipient encrypted content encryption key.
//
// Upon input, CNGContentDecryptInfo has been initialized.
//
// The following fields must be updated using hNCryptKey to decrypt
// pKeyTransDecryptPara->pKeyTrans->EncryptedKey.
//      pbContentEncryptKey (pfnAlloc'ed)
//      cbContentEncryptKey
//
// All other fields in the CNGContentEncryptInfo are READONLY.
//
// pKeyTransDecryptPara->pKeyTrans->KeyEncryptionAlgorithm.pszObjId is used
// to get the OIDFunctionAddress.
//--------------------------------------------------------------------------
const
  CMSG_OID_CNG_IMPORT_KEY_TRANS_FUNC = 'CryptMsgDllCNGImportKeyTrans';
  {$EXTERNALSYM CMSG_OID_CNG_IMPORT_KEY_TRANS_FUNC}

type
  PFN_CMSG_CNG_IMPORT_KEY_TRANS = function(
    pCNGContentDecryptInfo: PCMsgCNGContentDecryptInfo;
    pKeyTransDecryptPara: PCMsgCtrlKeyTransDecryptPara;
    dwFlags: DWORD;
    pvReserved: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_CNG_IMPORT_KEY_TRANS}

//+-------------------------------------------------------------------------
// CNG OID Installable function for importing and decrypting a key agreement
// recipient encrypted content encryption key.
//
// Upon input, CNGContentDecryptInfo has been initialized.
//
// The following fields must be updated using hNCryptKey to decrypt
// pKeyAgreeDecryptPara->pKeyAgree->rgpRecipientEncryptedKeys[
//  pKeyAgreeDecryptPara->dwRecipientEncryptedKeyIndex]->EncryptedKey.
//      pbContentEncryptKey (pfnAlloc'ed)
//      cbContentEncryptKey
//
// All other fields in the CNGContentEncryptInfo are READONLY.
//
// pKeyAgreeDecryptPara->pKeyAgree->KeyEncryptionAlgorithm.pszObjId is used
// to get the OIDFunctionAddress.
//--------------------------------------------------------------------------
const
  CMSG_OID_CNG_IMPORT_KEY_AGREE_FUNC  = 'CryptMsgDllCNGImportKeyAgree';
  {$EXTERNALSYM CMSG_OID_CNG_IMPORT_KEY_AGREE_FUNC}

type
  PFN_CMSG_CNG_IMPORT_KEY_AGREE = function(
    pCNGContentDecryptInfo: PCMsgCNGContentDecryptInfo;
    pKeyAgreeDecryptPara: PCMsgCtrlKeyAgreeDecryptPara;
    dwFlags: DWORD;
    pvReserved: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_CNG_IMPORT_KEY_AGREE}
  TFnCMsgCNGImportKeyAgree = PFN_CMSG_CNG_IMPORT_KEY_AGREE;

//+-------------------------------------------------------------------------
// CNG OID Installable function for importing an already decrypted
// content encryption key.
//
// Upon input, CNGContentDecryptInfo has been initialized.
//
// The following fields must be updated using pbContentEncryptKey and
// cbContentEncryptKey:
//      hCNGContentEncryptKey
//      pbCNGContentEncryptKeyObject (pfnAlloc'ed)
//
// The hCNGContentEncryptKey will be destroyed when hCryptMsg is closed.
//
// All other fields in the CNGContentEncryptInfo are READONLY.
//
// ContentEncryptionAlgorithm.pszObjId is used to get the OIDFunctionAddress.
//--------------------------------------------------------------------------
const
  CMSG_OID_CNG_IMPORT_CONTENT_ENCRYPT_KEY_FUNC = 'CryptMsgDllCNGImportContentEncryptKey';
  {$EXTERNALSYM CMSG_OID_CNG_IMPORT_CONTENT_ENCRYPT_KEY_FUNC}

type
  PFN_CMSG_CNG_IMPORT_CONTENT_ENCRYPT_KEY = function(
    pCNGContentDecryptInfo: PCMsgCNGContentDecryptInfo;
    dwFlags: DWORD;
    pvReserved: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CMSG_CNG_IMPORT_CONTENT_ENCRYPT_KEY}
  TFnCMsgCNGImportContentEncryptKey = PFN_CMSG_CNG_IMPORT_CONTENT_ENCRYPT_KEY;

//+=========================================================================
//  Certificate Store Data Structures and APIs
//==========================================================================

//+-------------------------------------------------------------------------
//              In its most basic implementation, a cert store is simply a
//              collection of certificates and/or CRLs. This is the case when
//              a cert store is opened with all of its certificates and CRLs
//              coming from a PKCS #7 encoded cryptographic message.
//
//              Nonetheless, all cert stores have the following properties:
//               - A public key may have more than one certificate in the store.
//                 For example, a private/public key used for signing may have a
//                 certificate issued for VISA and another issued for
//                 Mastercard. Also, when a certificate is renewed there might
//                 be more than one certificate with the same subject and
//                 issuer.
//               - However, each certificate in the store is uniquely
//                 identified by its Issuer and SerialNumber.
//               - There's an issuer of subject certificate relationship. A
//                 certificate's issuer is found by doing a match of
//                 pSubjectCert->Issuer with pIssuerCert->Subject.
//                 The relationship is verified by using
//                 the issuer's public key to verify the subject certificate's
//                 signature. Note, there might be X.509 v3 extensions
//                 to assist in finding the issuer certificate.
//               - Since issuer certificates might be renewed, a subject
//                 certificate might have more than one issuer certificate.
//               - There's an issuer of CRL relationship. An
//                 issuer's CRL is found by doing a match of
//                 pIssuerCert->Subject with pCrl->Issuer.
//                 The relationship is verified by using
//                 the issuer's public key to verify the CRL's
//                 signature. Note, there might be X.509 v3 extensions
//                 to assist in finding the CRL.
//               - Since some issuers might support the X.509 v3 delta CRL
//                 extensions, an issuer might have more than one CRL.
//               - The store shouldn't have any redundant certificates or
//                 CRLs. There shouldn't be two certificates with the same
//                 Issuer and SerialNumber. There shouldn't be two CRLs with
//                 the same Issuer, ThisUpdate and NextUpdate.
//               - The store has NO policy or trust information. No
//                 certificates are tagged as being "root". Its up to
//                 the application to maintain a list of CertIds (Issuer +
//                 SerialNumber) for certificates it trusts.
//               - The store might contain bad certificates and/or CRLs.
//                 The issuer's signature of a subject certificate or CRL may
//                 not verify. Certificates or CRLs may not satisfy their
//                 time validity requirements. Certificates may be
//                 revoked.
//
//              In addition to the certificates and CRLs, properties can be
//              stored. There are two predefined property IDs for a user
//              certificate: CERT_KEY_PROV_HANDLE_PROP_ID and
//              CERT_KEY_PROV_INFO_PROP_ID. The CERT_KEY_PROV_HANDLE_PROP_ID
//              is a HCRYPTPROV handle to the private key assoicated
//              with the certificate. The CERT_KEY_PROV_INFO_PROP_ID contains
//              information to be used to call
//              CryptAcquireContext and CryptSetProvParam to get a handle
//              to the private key associated with the certificate.
//
//              There exists two more predefined property IDs for certificates
//              and CRLs, CERT_SHA1_HASH_PROP_ID and CERT_MD5_HASH_PROP_ID.
//              If these properties don't already exist, then, a hash of the
//              content is computed. (CERT_HASH_PROP_ID maps to the default
//              hash algorithm, currently, CERT_SHA1_HASH_PROP_ID).
//
//              There are additional APIs for creating certificate and CRL
//      contexts not in a store (CertCreateCertificateContext and
//      CertCreateCRLContext).
//
//--------------------------------------------------------------------------

type
  HCERTSTORE = Pointer;
  {$EXTERNALSYM HCERTSTORE}

//+-------------------------------------------------------------------------
//  Certificate context.
//
//  A certificate context contains both the encoded and decoded representation
//  of a certificate. A certificate context returned by a cert store function
//  must be freed by calling the CertFreeCertificateContext function. The
//  CertDuplicateCertificateContext function can be called to make a duplicate
//  copy (which also must be freed by calling CertFreeCertificateContext).
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_CONTEXT
type
  PPCertContext = ^PCertContext;
  PCertContext = ^TCertContext;
  _CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: PCertInfo;
    hCertStore: HCERTSTORE;
  end;
  {$EXTERNALSYM _CERT_CONTEXT}
  CERT_CONTEXT = _CERT_CONTEXT;
  {$EXTERNALSYM CERT_CONTEXT}
  TCertContext = _CERT_CONTEXT;
  PCERT_CONTEXT = PCertContext;
  {$EXTERNALSYM PCERT_CONTEXT}
  PCCERT_CONTEXT = PCertContext;
  {$EXTERNALSYM PCCERT_CONTEXT}

// certenrolls_end

//+-------------------------------------------------------------------------
//  CRL context.
//
//  A CRL context contains both the encoded and decoded representation
//  of a CRL. A CRL context returned by a cert store function
//  must be freed by calling the CertFreeCRLContext function. The
//  CertDuplicateCRLContext function can be called to make a duplicate
//  copy (which also must be freed by calling CertFreeCRLContext).
//--------------------------------------------------------------------------
type
  PPCRLContext = ^PCRLContext;
  PCRLContext = ^TCRLContext;
  _CRL_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCrlEncoded: PByte;
    cbCrlEncoded: DWORD;
    pCrlInfo: PCRLInfo;
    hCertStore: HCERTSTORE;
  end;
  {$EXTERNALSYM _CRL_CONTEXT}
  CRL_CONTEXT = _CRL_CONTEXT;
  {$EXTERNALSYM CRL_CONTEXT}
  TCRLContext = _CRL_CONTEXT;
  PCRL_CONTEXT = PCRLContext;
  {$EXTERNALSYM PCRL_CONTEXT}
  PCCRL_CONTEXT = PCRLContext;
  {$EXTERNALSYM PCCRL_CONTEXT}

//+-------------------------------------------------------------------------
//  Certificate Trust List (CTL) context.
//
//  A CTL context contains both the encoded and decoded representation
//  of a CTL. Also contains an opened HCRYPTMSG handle to the decoded
//  cryptographic signed message containing the CTL_INFO as its inner content.
//  pbCtlContent is the encoded inner content of the signed message.
//
//  The CryptMsg APIs can be used to extract additional signer information.
//--------------------------------------------------------------------------
type
  PPCTLContext = ^PCTLContext;
  PCTLContext = ^TCTLContext;
  _CTL_CONTEXT = record
    dwMsgAndCertEncodingType: DWORD;
    pbCtlEncoded: PByte;
    cbCtlEncoded: DWORD;
    pCtlInfo: PCTLInfo;
    hCertStore: HCERTSTORE;
    hCryptMsg: HCRYPTMSG;
    pbCtlContent: PByte;
    cbCtlContent: DWORD;
  end;
  {$EXTERNALSYM _CTL_CONTEXT}
  CTL_CONTEXT = _CTL_CONTEXT;
  {$EXTERNALSYM CTL_CONTEXT}
  TCTLContext = _CTL_CONTEXT;
  PCTL_CONTEXT = PCTLContext;
  {$EXTERNALSYM PCTL_CONTEXT}
  PCCTL_CONTEXT = PCTLContext;
  {$EXTERNALSYM PCCTL_CONTEXT}

// certenrolld_begin -- CERT_*_PROP_ID
//+-------------------------------------------------------------------------
//  Certificate, CRL and CTL property IDs
//
//  See CertSetCertificateContextProperty or CertGetCertificateContextProperty
//  for usage information.
//--------------------------------------------------------------------------
const
  CERT_KEY_PROV_HANDLE_PROP_ID        = 1;
  {$EXTERNALSYM CERT_KEY_PROV_HANDLE_PROP_ID}
  CERT_KEY_PROV_INFO_PROP_ID          = 2; // CRYPT_KEY_PROV_INFO
  {$EXTERNALSYM CERT_KEY_PROV_INFO_PROP_ID}
  CERT_SHA1_HASH_PROP_ID              = 3;
  {$EXTERNALSYM CERT_SHA1_HASH_PROP_ID}
  CERT_MD5_HASH_PROP_ID               = 4;
  {$EXTERNALSYM CERT_MD5_HASH_PROP_ID}
  CERT_HASH_PROP_ID                   = CERT_SHA1_HASH_PROP_ID;
  {$EXTERNALSYM CERT_HASH_PROP_ID}
  CERT_KEY_CONTEXT_PROP_ID            = 5;
  {$EXTERNALSYM CERT_KEY_CONTEXT_PROP_ID}
  CERT_KEY_SPEC_PROP_ID               = 6;
  {$EXTERNALSYM CERT_KEY_SPEC_PROP_ID}
  CERT_IE30_RESERVED_PROP_ID          = 7;
  {$EXTERNALSYM CERT_IE30_RESERVED_PROP_ID}
  CERT_PUBKEY_HASH_RESERVED_PROP_ID   = 8;
  {$EXTERNALSYM CERT_PUBKEY_HASH_RESERVED_PROP_ID}
  CERT_ENHKEY_USAGE_PROP_ID           = 9;
  {$EXTERNALSYM CERT_ENHKEY_USAGE_PROP_ID}
  CERT_CTL_USAGE_PROP_ID              = CERT_ENHKEY_USAGE_PROP_ID;
  {$EXTERNALSYM CERT_CTL_USAGE_PROP_ID}
  CERT_NEXT_UPDATE_LOCATION_PROP_ID   = 10;
  {$EXTERNALSYM CERT_NEXT_UPDATE_LOCATION_PROP_ID}
  CERT_FRIENDLY_NAME_PROP_ID          = 11; // string
  {$EXTERNALSYM CERT_FRIENDLY_NAME_PROP_ID}
  CERT_PVK_FILE_PROP_ID               = 12;
  {$EXTERNALSYM CERT_PVK_FILE_PROP_ID}
  CERT_DESCRIPTION_PROP_ID            = 13; // string
  {$EXTERNALSYM CERT_DESCRIPTION_PROP_ID}
  CERT_ACCESS_STATE_PROP_ID           = 14;
  {$EXTERNALSYM CERT_ACCESS_STATE_PROP_ID}
  CERT_SIGNATURE_HASH_PROP_ID         = 15;
  {$EXTERNALSYM CERT_SIGNATURE_HASH_PROP_ID}
  CERT_SMART_CARD_DATA_PROP_ID        = 16;
  {$EXTERNALSYM CERT_SMART_CARD_DATA_PROP_ID}
  CERT_EFS_PROP_ID                    = 17;
  {$EXTERNALSYM CERT_EFS_PROP_ID}
  CERT_FORTEZZA_DATA_PROP_ID          = 18;
  {$EXTERNALSYM CERT_FORTEZZA_DATA_PROP_ID}
  CERT_ARCHIVED_PROP_ID               = 19;
  {$EXTERNALSYM CERT_ARCHIVED_PROP_ID}
  CERT_KEY_IDENTIFIER_PROP_ID         = 20;
  {$EXTERNALSYM CERT_KEY_IDENTIFIER_PROP_ID}
  CERT_AUTO_ENROLL_PROP_ID            = 21; // string:Template name
  {$EXTERNALSYM CERT_AUTO_ENROLL_PROP_ID}
  CERT_PUBKEY_ALG_PARA_PROP_ID        = 22;
  {$EXTERNALSYM CERT_PUBKEY_ALG_PARA_PROP_ID}
  CERT_CROSS_CERT_DIST_POINTS_PROP_ID = 23;
  {$EXTERNALSYM CERT_CROSS_CERT_DIST_POINTS_PROP_ID}
  CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID    = 24;
  {$EXTERNALSYM CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID}
  CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID   = 25;
  {$EXTERNALSYM CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID}
  CERT_ENROLLMENT_PROP_ID             = 26; // RequestId+CADNS+CACN+Friendly Name
  {$EXTERNALSYM CERT_ENROLLMENT_PROP_ID}
  CERT_DATE_STAMP_PROP_ID             = 27; // FILETIME
  {$EXTERNALSYM CERT_DATE_STAMP_PROP_ID}
  CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = 28;
  {$EXTERNALSYM CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID}
  CERT_SUBJECT_NAME_MD5_HASH_PROP_ID  = 29;
  {$EXTERNALSYM CERT_SUBJECT_NAME_MD5_HASH_PROP_ID}
  CERT_EXTENDED_ERROR_INFO_PROP_ID    = 30; // string
  {$EXTERNALSYM CERT_EXTENDED_ERROR_INFO_PROP_ID}

// Note, 32 - 35 are reserved for the CERT, CRL, CTL and KeyId file element IDs.
//       36 - 62 are reserved for future element IDs.

  CERT_RENEWAL_PROP_ID                = 64;
  {$EXTERNALSYM CERT_RENEWAL_PROP_ID}
  CERT_ARCHIVED_KEY_HASH_PROP_ID      = 65; // Encrypted key hash
  {$EXTERNALSYM CERT_ARCHIVED_KEY_HASH_PROP_ID}
  CERT_AUTO_ENROLL_RETRY_PROP_ID      = 66; // AE_RETRY_INFO:cb+cRetry+FILETIME
  {$EXTERNALSYM CERT_AUTO_ENROLL_RETRY_PROP_ID}
  CERT_AIA_URL_RETRIEVED_PROP_ID      = 67;
  {$EXTERNALSYM CERT_AIA_URL_RETRIEVED_PROP_ID}
  CERT_AUTHORITY_INFO_ACCESS_PROP_ID  = 68;
  {$EXTERNALSYM CERT_AUTHORITY_INFO_ACCESS_PROP_ID}
  CERT_BACKED_UP_PROP_ID              = 69; // VARIANT_BOOL+FILETIME
  {$EXTERNALSYM CERT_BACKED_UP_PROP_ID}
  CERT_OCSP_RESPONSE_PROP_ID          = 70;
  {$EXTERNALSYM CERT_OCSP_RESPONSE_PROP_ID}
  CERT_REQUEST_ORIGINATOR_PROP_ID     = 71; // string:machine DNS name
  {$EXTERNALSYM CERT_REQUEST_ORIGINATOR_PROP_ID}
  CERT_SOURCE_LOCATION_PROP_ID        = 72; // string
  {$EXTERNALSYM CERT_SOURCE_LOCATION_PROP_ID}
  CERT_SOURCE_URL_PROP_ID             = 73; // string
  {$EXTERNALSYM CERT_SOURCE_URL_PROP_ID}
  CERT_NEW_KEY_PROP_ID                = 74;
  {$EXTERNALSYM CERT_NEW_KEY_PROP_ID}
  CERT_OCSP_CACHE_PREFIX_PROP_ID      = 75; // string
  {$EXTERNALSYM CERT_OCSP_CACHE_PREFIX_PROP_ID}
  CERT_SMART_CARD_ROOT_INFO_PROP_ID   = 76; // CRYPT_SMART_CARD_ROOT_INFO
  {$EXTERNALSYM CERT_SMART_CARD_ROOT_INFO_PROP_ID}
  CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID   = 77;
  {$EXTERNALSYM CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID}
  CERT_NCRYPT_KEY_HANDLE_PROP_ID      = 78;
  {$EXTERNALSYM CERT_NCRYPT_KEY_HANDLE_PROP_ID}
  CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID  = 79;
  {$EXTERNALSYM CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID}

  CERT_SUBJECT_INFO_ACCESS_PROP_ID    = 80;
  {$EXTERNALSYM CERT_SUBJECT_INFO_ACCESS_PROP_ID}
  CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID = 81;
  {$EXTERNALSYM CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID}
  CERT_CA_DISABLE_CRL_PROP_ID         = 82;
  {$EXTERNALSYM CERT_CA_DISABLE_CRL_PROP_ID}
  CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID    = 83;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID}
  CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID = 84;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID}
  CERT_SUBJECT_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID = 85;
  {$EXTERNALSYM CERT_SUBJECT_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID}
  CERT_SUBJECT_DISABLE_CRL_PROP_ID    = 86;
  {$EXTERNALSYM CERT_SUBJECT_DISABLE_CRL_PROP_ID}
  CERT_CEP_PROP_ID                    = 87; // Version+PropFlags+AuthType+UrlFlags+CESAuthType+Url+Id+CESUrl+ReqId
  {$EXTERNALSYM CERT_CEP_PROP_ID}
// 88 reserved, originally used for CERT_CEP_PROP_ID
  CERT_SIGN_HASH_CNG_ALG_PROP_ID      = 89;
  {$EXTERNALSYM CERT_SIGN_HASH_CNG_ALG_PROP_ID}

  CERT_SCARD_PIN_ID_PROP_ID           = 90;
  {$EXTERNALSYM CERT_SCARD_PIN_ID_PROP_ID}
  CERT_SCARD_PIN_INFO_PROP_ID         = 91;
  {$EXTERNALSYM CERT_SCARD_PIN_INFO_PROP_ID}

  CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID = 92;
  {$EXTERNALSYM CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID}
  CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID = 93;
  {$EXTERNALSYM CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID}
  CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID = 94;
  {$EXTERNALSYM CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID}
  CERT_ISSUER_CHAIN_SIGN_HASH_CNG_ALG_PROP_ID = 95;
  {$EXTERNALSYM CERT_ISSUER_CHAIN_SIGN_HASH_CNG_ALG_PROP_ID}
  CERT_ISSUER_CHAIN_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID = 96;
  {$EXTERNALSYM CERT_ISSUER_CHAIN_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID}

  CERT_NO_EXPIRE_NOTIFICATION_PROP_ID = 97;
  {$EXTERNALSYM CERT_NO_EXPIRE_NOTIFICATION_PROP_ID}

// Following property isn't implicitly created via a GetProperty.
  CERT_AUTH_ROOT_SHA256_HASH_PROP_ID  = 98;
  {$EXTERNALSYM CERT_AUTH_ROOT_SHA256_HASH_PROP_ID}

  CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID = 99;
  {$EXTERNALSYM CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID}
  CERT_HCRYPTPROV_TRANSFER_PROP_ID    = 100;
  {$EXTERNALSYM CERT_HCRYPTPROV_TRANSFER_PROP_ID}

// Smart card reader image path
  CERT_SMART_CARD_READER_PROP_ID      = 101; //string
  {$EXTERNALSYM CERT_SMART_CARD_READER_PROP_ID}

// Send as trusted issuer
  CERT_SEND_AS_TRUSTED_ISSUER_PROP_ID = 102; //boolean
  {$EXTERNALSYM CERT_SEND_AS_TRUSTED_ISSUER_PROP_ID}

  CERT_KEY_REPAIR_ATTEMPTED_PROP_ID   = 103; // FILETME
  {$EXTERNALSYM CERT_KEY_REPAIR_ATTEMPTED_PROP_ID}

  CERT_DISALLOWED_FILETIME_PROP_ID    = 104;
  {$EXTERNALSYM CERT_DISALLOWED_FILETIME_PROP_ID}
  CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID = 105;
  {$EXTERNALSYM CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID}

// Smart card reader removable capabilities
  CERT_SMART_CARD_READER_NON_REMOVABLE_PROP_ID     = 106; // boolean
  {$EXTERNALSYM CERT_SMART_CARD_READER_NON_REMOVABLE_PROP_ID}

  CERT_FIRST_RESERVED_PROP_ID         = 107;
  {$EXTERNALSYM CERT_FIRST_RESERVED_PROP_ID}

  CERT_LAST_RESERVED_PROP_ID          = $00007FFF;
  {$EXTERNALSYM CERT_LAST_RESERVED_PROP_ID}
  CERT_FIRST_USER_PROP_ID             = $00008000;
  {$EXTERNALSYM CERT_FIRST_USER_PROP_ID}
  CERT_LAST_USER_PROP_ID              = $0000FFFF;
  {$EXTERNALSYM CERT_LAST_USER_PROP_ID}
// certenrolld_end

function IS_CERT_HASH_PROP_ID(X: DWORD): Boolean; inline;
{$EXTERNALSYM IS_CERT_HASH_PROP_ID}

function IS_PUBKEY_HASH_PROP_ID(X: DWORD): Boolean; inline;
{$EXTERNALSYM IS_PUBKEY_HASH_PROP_ID}

function IS_CHAIN_HASH_PROP_ID(X: DWORD): Boolean; inline;
{$EXTERNALSYM IS_CHAIN_HASH_PROP_ID}

function IS_STRONG_SIGN_PROP_ID(X: DWORD): Boolean; inline;
{$EXTERNALSYM IS_STRONG_SIGN_PROP_ID}

//+-------------------------------------------------------------------------
//  Property OIDs
//--------------------------------------------------------------------------
// The OID component following the prefix contains the PROP_ID (decimal)
const
  szOID_CERT_PROP_ID_PREFIX                        = '1.3.6.1.4.1.311.10.11.';
  {$EXTERNALSYM szOID_CERT_PROP_ID_PREFIX}

//#define _szPROP_ID(PropId)       #PropId

// Ansi OID string from Property Id:
//#define szOID_CERT_PROP_ID(PropId) szOID_CERT_PROP_ID_PREFIX _szPROP_ID(PropId)

// Unicode OID string from Property Id:
//#define __CRYPT32WTEXT(quote)           L##quote
//#define _CRYPT32WTEXT(quote)            __CRYPT32WTEXT(quote)
//#define wszOID_CERT_PROP_ID(PropId) \
//        _CRYPT32WTEXT(szOID_CERT_PROP_ID_PREFIX) _CRYPT32WTEXT(_szPROP_ID(PropId))

// Use szOID_CERT_PROP_ID(CERT_KEY_IDENTIFIER_PROP_ID) instead:
const
  szOID_CERT_KEY_IDENTIFIER_PROP_ID                = '1.3.6.1.4.1.311.10.11.20';
  {$EXTERNALSYM szOID_CERT_KEY_IDENTIFIER_PROP_ID}

// Use szOID_CERT_PROP_ID(CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID) instead:
const
  szOID_CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = '1.3.6.1.4.1.311.10.11.28';
  {$EXTERNALSYM szOID_CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID}

// Use szOID_CERT_PROP_ID(CERT_SUBJECT_NAME_MD5_HASH_PROP_ID) instead:
const
  szOID_CERT_SUBJECT_NAME_MD5_HASH_PROP_ID         = '1.3.6.1.4.1.311.10.11.29';
  {$EXTERNALSYM szOID_CERT_SUBJECT_NAME_MD5_HASH_PROP_ID}

// Use szOID_CERT_PROP_ID(CERT_MD5_HASH_PROP_ID) instead:
const
  szOID_CERT_MD5_HASH_PROP_ID                      = '1.3.6.1.4.1.311.10.11.4';
  {$EXTERNALSYM szOID_CERT_MD5_HASH_PROP_ID}

// Use szOID_CERT_PROP_ID(CERT_SIGNATURE_HASH_PROP_ID) instead:
const
  szOID_CERT_SIGNATURE_HASH_PROP_ID                = '1.3.6.1.4.1.311.10.11.15';
  {$EXTERNALSYM szOID_CERT_SIGNATURE_HASH_PROP_ID}


// The CERT_SIGNATURE_HASH_PROP_ID and CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID
// properties are used for disallowed hashes.
const
  szOID_DISALLOWED_HASH                            = szOID_CERT_SIGNATURE_HASH_PROP_ID;
  {$EXTERNALSYM szOID_DISALLOWED_HASH}

// Use szOID_CERT_PROP_ID(CERT_DISALLOWED_FILETIME_PROP_ID) instead:
const
  szOID_CERT_DISALLOWED_FILETIME_PROP_ID          = '1.3.6.1.4.1.311.10.11.104';
  {$EXTERNALSYM szOID_CERT_DISALLOWED_FILETIME_PROP_ID}

//+-------------------------------------------------------------------------
//  Access State flags returned by CERT_ACCESS_STATE_PROP_ID. Note,
//  CERT_ACCESS_PROP_ID is read only.
//--------------------------------------------------------------------------

// Set if context property writes are persisted. For instance, not set for
// memory store contexts. Set for registry based stores opened as read or write.
// Not set for registry based stores opened as read only.
const
  CERT_ACCESS_STATE_WRITE_PERSIST_FLAG   = $1;
  {$EXTERNALSYM CERT_ACCESS_STATE_WRITE_PERSIST_FLAG}

// Set if context resides in a SYSTEM or SYSTEM_REGISTRY store.
const
  CERT_ACCESS_STATE_SYSTEM_STORE_FLAG    = $2;
  {$EXTERNALSYM CERT_ACCESS_STATE_SYSTEM_STORE_FLAG}

// Set if context resides in a LocalMachine SYSTEM or SYSTEM_REGISTRY store.
const
  CERT_ACCESS_STATE_LM_SYSTEM_STORE_FLAG = $4;
  {$EXTERNALSYM CERT_ACCESS_STATE_LM_SYSTEM_STORE_FLAG}

// Set if context resides in a GroupPolicy SYSTEM or SYSTEM_REGISTRY store.
const
  CERT_ACCESS_STATE_GP_SYSTEM_STORE_FLAG = $8;
  {$EXTERNALSYM CERT_ACCESS_STATE_GP_SYSTEM_STORE_FLAG}

// Set if context resides in a SHARED_USER physical store.
const
  CERT_ACCESS_STATE_SHARED_USER_FLAG     = $10;
  {$EXTERNALSYM CERT_ACCESS_STATE_SHARED_USER_FLAG}

//+-------------------------------------------------------------------------
//  CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID Property
//
//  Encoded as an X509_ENHANCED_KEY_USAGE: sequence of Policy OIDs.
//--------------------------------------------------------------------------

// Supported Root Program Chain Policies:
const
  szOID_ROOT_PROGRAM_AUTO_UPDATE_CA_REVOCATION   = '1.3.6.1.4.1.311.60.3.1';
  {$EXTERNALSYM szOID_ROOT_PROGRAM_AUTO_UPDATE_CA_REVOCATION}
  szOID_ROOT_PROGRAM_AUTO_UPDATE_END_REVOCATION  = '1.3.6.1.4.1.311.60.3.2';
  {$EXTERNALSYM szOID_ROOT_PROGRAM_AUTO_UPDATE_END_REVOCATION}
  szOID_ROOT_PROGRAM_NO_OCSP_FAILOVER_TO_CRL     = '1.3.6.1.4.1.311.60.3.3';
  {$EXTERNALSYM szOID_ROOT_PROGRAM_NO_OCSP_FAILOVER_TO_CRL}

//+-------------------------------------------------------------------------
//  Cryptographic Key Provider Information
//
//  CRYPT_KEY_PROV_INFO defines the CERT_KEY_PROV_INFO_PROP_ID's pvData.
//
//  The CRYPT_KEY_PROV_INFO fields are passed to CryptAcquireContext
//  to get a HCRYPTPROV handle. The optional CRYPT_KEY_PROV_PARAM fields are
//  passed to CryptSetProvParam to further initialize the provider.
//
//  The dwKeySpec field identifies the private key to use from the container
//  For example, AT_KEYEXCHANGE or AT_SIGNATURE.
//--------------------------------------------------------------------------
type
  PCryptKeyProvParam = ^TCryptKeyProvParam;
  _CRYPT_KEY_PROV_PARAM = record
    dwParam: DWORD;
    pbData: PByte;
    cbData: DWORD;
    dwFlags: DWORD;
  end;
  {$EXTERNALSYM _CRYPT_KEY_PROV_PARAM}
  CRYPT_KEY_PROV_PARAM = _CRYPT_KEY_PROV_PARAM;
  {$EXTERNALSYM CRYPT_KEY_PROV_PARAM}
  TCryptKeyProvParam = _CRYPT_KEY_PROV_PARAM;
  PCRYPT_KEY_PROV_PARAM = PCryptKeyProvParam;
  {$EXTERNALSYM PCRYPT_KEY_PROV_PARAM}

type
  PCryptKeyProvInfo = ^TCryptKeyProvInfo;
  _CRYPT_KEY_PROV_INFO = record
    pwszContainerName: LPWSTR;
    pwszProvName: LPWSTR;
    dwProvType: DWORD;
    dwFlags: DWORD;
    cProvParam: DWORD;
    rgProvParam: PCryptKeyProvParam;
    dwKeySpec: DWORD;
  end;
  {$EXTERNALSYM _CRYPT_KEY_PROV_INFO}
  CRYPT_KEY_PROV_INFO = _CRYPT_KEY_PROV_INFO;
  {$EXTERNALSYM CRYPT_KEY_PROV_INFO}
  TCryptKeyProvInfo = _CRYPT_KEY_PROV_INFO;
  PCRYPT_KEY_PROV_INFO = PCryptKeyProvInfo;
  {$EXTERNALSYM PCRYPT_KEY_PROV_INFO}

//+-------------------------------------------------------------------------
//  The following flag should be set in the above dwFlags to enable
//  a CertSetCertificateContextProperty(CERT_KEY_CONTEXT_PROP_ID) after a
//  CryptAcquireContext is done in the Sign or Decrypt Message functions.
//
//  The following define must not collide with any of the
//  CryptAcquireContext dwFlag defines.
//--------------------------------------------------------------------------
const
  CERT_SET_KEY_PROV_HANDLE_PROP_ID   = $00000001;
  {$EXTERNALSYM CERT_SET_KEY_PROV_HANDLE_PROP_ID}
  CERT_SET_KEY_CONTEXT_PROP_ID       = $00000001;
  {$EXTERNALSYM CERT_SET_KEY_CONTEXT_PROP_ID}

// Special dwKeySpec indicating a CNG NCRYPT_KEY_HANDLE instead of a CAPI1
// HCRYPTPROV
const
  CERT_NCRYPT_KEY_SPEC               = $FFFFFFFF;
  {$EXTERNALSYM CERT_NCRYPT_KEY_SPEC}

//+-------------------------------------------------------------------------
//  Certificate Key Context
//
//  CERT_KEY_CONTEXT defines the CERT_KEY_CONTEXT_PROP_ID's pvData.
//
//  dwKeySpec is set to the special CERT_NCRYPT_KEY_SPEC to select the
//  hNCryptKey choice.
//--------------------------------------------------------------------------
type
  PCertKeyContext = ^TCertKeyContext;
  _CERT_KEY_CONTEXT = record
    cbSize: DWORD;           // sizeof(CERT_KEY_CONTEXT)
    case Integer of
    0: (hCryptProv: HCRYPTPROV);
    1: (// dwKeySpec == CERT_NCRYPT_KEY_SPEC
        hNCryptKey: NCRYPT_KEY_HANDLE;
    dwKeySpec: DWORD);
  end;
  {$EXTERNALSYM _CERT_KEY_CONTEXT}
  CERT_KEY_CONTEXT = _CERT_KEY_CONTEXT;
  {$EXTERNALSYM CERT_KEY_CONTEXT}
  TCertKeyContext = _CERT_KEY_CONTEXT;
  PCERT_KEY_CONTEXT = PCertKeyContext;
  {$EXTERNALSYM PCERT_KEY_CONTEXT}

//+-------------------------------------------------------------------------
//  Cryptographic Smart Card Root Information
//
//  CRYPT_SMART_CARD_ROOT_INFO defines the
//  CERT_SMART_CARD_ROOT_INFO_PROP_ID's pvData.
//--------------------------------------------------------------------------
type
  PRootInfoLUID = ^TRootInfoLUID;
  _ROOT_INFO_LUID = record
    LowPart: DWORD;
    HighPart: LONG;
  end;
  {$EXTERNALSYM _ROOT_INFO_LUID}
  ROOT_INFO_LUID = _ROOT_INFO_LUID;
  {$EXTERNALSYM ROOT_INFO_LUID}
  TRootInfoLUID = _ROOT_INFO_LUID;
  PROOT_INFO_LUID = PRootInfoLUID;
  {$EXTERNALSYM PROOT_INFO_LUID}

type
  PCryptSmartCardRootInfo = ^TCryptSmartCardRootInfo;
  _CRYPT_SMART_CARD_ROOT_INFO = record
    rgbCardID: array [0..15] of BYTE;
    luid: TRootInfoLUID;
  end;
  {$EXTERNALSYM _CRYPT_SMART_CARD_ROOT_INFO}
  CRYPT_SMART_CARD_ROOT_INFO = _CRYPT_SMART_CARD_ROOT_INFO;
  {$EXTERNALSYM CRYPT_SMART_CARD_ROOT_INFO}
  TCryptSmartCardRootInfo = _CRYPT_SMART_CARD_ROOT_INFO;
  PCRYPT_SMART_CARD_ROOT_INFO = PCryptSmartCardRootInfo;
  {$EXTERNALSYM PCRYPT_SMART_CARD_ROOT_INFO}

//+-------------------------------------------------------------------------
//  Certificate Store Provider Types
//--------------------------------------------------------------------------
const
  CERT_STORE_PROV_MSG                = LPCSTR(1);
  {$EXTERNALSYM CERT_STORE_PROV_MSG}
  CERT_STORE_PROV_MEMORY             = LPCSTR(2);
  {$EXTERNALSYM CERT_STORE_PROV_MEMORY}
  CERT_STORE_PROV_FILE               = LPCSTR(3);
  {$EXTERNALSYM CERT_STORE_PROV_FILE}
  CERT_STORE_PROV_REG                = LPCSTR(4);
  {$EXTERNALSYM CERT_STORE_PROV_REG}

  CERT_STORE_PROV_PKCS7              = LPCSTR(5);
  {$EXTERNALSYM CERT_STORE_PROV_PKCS7}
  CERT_STORE_PROV_SERIALIZED         = LPCSTR(6);
  {$EXTERNALSYM CERT_STORE_PROV_SERIALIZED}
  CERT_STORE_PROV_FILENAME_A         = LPCSTR(7);
  {$EXTERNALSYM CERT_STORE_PROV_FILENAME_A}
  CERT_STORE_PROV_FILENAME_W         = LPCSTR(8);
  {$EXTERNALSYM CERT_STORE_PROV_FILENAME_W}
  CERT_STORE_PROV_FILENAME           = CERT_STORE_PROV_FILENAME_W;
  {$EXTERNALSYM CERT_STORE_PROV_FILENAME}
  CERT_STORE_PROV_SYSTEM_A           = LPCSTR(9);
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_A}
  CERT_STORE_PROV_SYSTEM_W           = LPCSTR(10);
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_W}
  CERT_STORE_PROV_SYSTEM             = CERT_STORE_PROV_SYSTEM_W;
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM}

  CERT_STORE_PROV_COLLECTION         = LPCSTR(11);
  {$EXTERNALSYM CERT_STORE_PROV_COLLECTION}
  CERT_STORE_PROV_SYSTEM_REGISTRY_A  = LPCSTR(12);
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_REGISTRY_A}
  CERT_STORE_PROV_SYSTEM_REGISTRY_W  = LPCSTR(13);
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_REGISTRY_W}
  CERT_STORE_PROV_SYSTEM_REGISTRY    = CERT_STORE_PROV_SYSTEM_REGISTRY_W;
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_REGISTRY}
  CERT_STORE_PROV_PHYSICAL_W         = LPCSTR(14);
  {$EXTERNALSYM CERT_STORE_PROV_PHYSICAL_W}
  CERT_STORE_PROV_PHYSICAL           = CERT_STORE_PROV_PHYSICAL_W;
  {$EXTERNALSYM CERT_STORE_PROV_PHYSICAL}

// SmartCard Store Provider isn't supported
const
  CERT_STORE_PROV_SMART_CARD_W       = LPCSTR(15);
  {$EXTERNALSYM CERT_STORE_PROV_SMART_CARD_W}
  CERT_STORE_PROV_SMART_CARD         = CERT_STORE_PROV_SMART_CARD_W;
  {$EXTERNALSYM CERT_STORE_PROV_SMART_CARD}

  CERT_STORE_PROV_LDAP_W             = LPCSTR(16);
  {$EXTERNALSYM CERT_STORE_PROV_LDAP_W}
  CERT_STORE_PROV_LDAP               = CERT_STORE_PROV_LDAP_W;
  {$EXTERNALSYM CERT_STORE_PROV_LDAP}
  CERT_STORE_PROV_PKCS12             = LPCSTR(17);
  {$EXTERNALSYM CERT_STORE_PROV_PKCS12}

  sz_CERT_STORE_PROV_MEMORY          = 'Memory';
  {$EXTERNALSYM sz_CERT_STORE_PROV_MEMORY}
  sz_CERT_STORE_PROV_FILENAME_W      = 'File';
  {$EXTERNALSYM sz_CERT_STORE_PROV_FILENAME_W}
  sz_CERT_STORE_PROV_FILENAME        = sz_CERT_STORE_PROV_FILENAME_W;
  {$EXTERNALSYM sz_CERT_STORE_PROV_FILENAME}
  sz_CERT_STORE_PROV_SYSTEM_W        = 'System';
  {$EXTERNALSYM sz_CERT_STORE_PROV_SYSTEM_W}
  sz_CERT_STORE_PROV_SYSTEM          = sz_CERT_STORE_PROV_SYSTEM_W;
  {$EXTERNALSYM sz_CERT_STORE_PROV_SYSTEM}
  sz_CERT_STORE_PROV_PKCS7           = 'PKCS7';
  {$EXTERNALSYM sz_CERT_STORE_PROV_PKCS7}
  sz_CERT_STORE_PROV_PKCS12          = 'PKCS12';
  {$EXTERNALSYM sz_CERT_STORE_PROV_PKCS12}
  sz_CERT_STORE_PROV_SERIALIZED      = 'Serialized';
  {$EXTERNALSYM sz_CERT_STORE_PROV_SERIALIZED}

  sz_CERT_STORE_PROV_COLLECTION      = 'Collection';
  {$EXTERNALSYM sz_CERT_STORE_PROV_COLLECTION}
  sz_CERT_STORE_PROV_SYSTEM_REGISTRY_W = 'SystemRegistry';
  {$EXTERNALSYM sz_CERT_STORE_PROV_SYSTEM_REGISTRY_W}
  sz_CERT_STORE_PROV_SYSTEM_REGISTRY = sz_CERT_STORE_PROV_SYSTEM_REGISTRY_W;
  {$EXTERNALSYM sz_CERT_STORE_PROV_SYSTEM_REGISTRY}
  sz_CERT_STORE_PROV_PHYSICAL_W      = 'Physical';
  {$EXTERNALSYM sz_CERT_STORE_PROV_PHYSICAL_W}
  sz_CERT_STORE_PROV_PHYSICAL        = sz_CERT_STORE_PROV_PHYSICAL_W;
  {$EXTERNALSYM sz_CERT_STORE_PROV_PHYSICAL}

// SmartCard Store Provider isn't supported
const
  sz_CERT_STORE_PROV_SMART_CARD_W    = 'SmartCard';
  {$EXTERNALSYM sz_CERT_STORE_PROV_SMART_CARD_W}
  sz_CERT_STORE_PROV_SMART_CARD      = sz_CERT_STORE_PROV_SMART_CARD_W;
  {$EXTERNALSYM sz_CERT_STORE_PROV_SMART_CARD}

  sz_CERT_STORE_PROV_LDAP_W          = 'Ldap';
  {$EXTERNALSYM sz_CERT_STORE_PROV_LDAP_W}
  sz_CERT_STORE_PROV_LDAP            = sz_CERT_STORE_PROV_LDAP_W;
  {$EXTERNALSYM sz_CERT_STORE_PROV_LDAP}

//+-------------------------------------------------------------------------
//  Certificate Store verify/results flags
//--------------------------------------------------------------------------
const
  CERT_STORE_SIGNATURE_FLAG          = $00000001;
  {$EXTERNALSYM CERT_STORE_SIGNATURE_FLAG}
  CERT_STORE_TIME_VALIDITY_FLAG      = $00000002;
  {$EXTERNALSYM CERT_STORE_TIME_VALIDITY_FLAG}
  CERT_STORE_REVOCATION_FLAG         = $00000004;
  {$EXTERNALSYM CERT_STORE_REVOCATION_FLAG}
  CERT_STORE_NO_CRL_FLAG             = $00010000;
  {$EXTERNALSYM CERT_STORE_NO_CRL_FLAG}
  CERT_STORE_NO_ISSUER_FLAG          = $00020000;
  {$EXTERNALSYM CERT_STORE_NO_ISSUER_FLAG}

  CERT_STORE_BASE_CRL_FLAG           = $00000100;
  {$EXTERNALSYM CERT_STORE_BASE_CRL_FLAG}
  CERT_STORE_DELTA_CRL_FLAG          = $00000200;
  {$EXTERNALSYM CERT_STORE_DELTA_CRL_FLAG}


//+-------------------------------------------------------------------------
//  Certificate Store open/property flags
//--------------------------------------------------------------------------
const
  CERT_STORE_NO_CRYPT_RELEASE_FLAG               = $00000001;
  {$EXTERNALSYM CERT_STORE_NO_CRYPT_RELEASE_FLAG}
  CERT_STORE_SET_LOCALIZED_NAME_FLAG             = $00000002;
  {$EXTERNALSYM CERT_STORE_SET_LOCALIZED_NAME_FLAG}
  CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG    = $00000004;
  {$EXTERNALSYM CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG}
  CERT_STORE_DELETE_FLAG                         = $00000010;
  {$EXTERNALSYM CERT_STORE_DELETE_FLAG}
  CERT_STORE_UNSAFE_PHYSICAL_FLAG                = $00000020;
  {$EXTERNALSYM CERT_STORE_UNSAFE_PHYSICAL_FLAG}
  CERT_STORE_SHARE_STORE_FLAG                    = $00000040;
  {$EXTERNALSYM CERT_STORE_SHARE_STORE_FLAG}
  CERT_STORE_SHARE_CONTEXT_FLAG                  = $00000080;
  {$EXTERNALSYM CERT_STORE_SHARE_CONTEXT_FLAG}
  CERT_STORE_MANIFOLD_FLAG                       = $00000100;
  {$EXTERNALSYM CERT_STORE_MANIFOLD_FLAG}
  CERT_STORE_ENUM_ARCHIVED_FLAG                  = $00000200;
  {$EXTERNALSYM CERT_STORE_ENUM_ARCHIVED_FLAG}
  CERT_STORE_UPDATE_KEYID_FLAG                   = $00000400;
  {$EXTERNALSYM CERT_STORE_UPDATE_KEYID_FLAG}
  CERT_STORE_BACKUP_RESTORE_FLAG                 = $00000800;
  {$EXTERNALSYM CERT_STORE_BACKUP_RESTORE_FLAG}
  CERT_STORE_READONLY_FLAG                       = $00008000;
  {$EXTERNALSYM CERT_STORE_READONLY_FLAG}
  CERT_STORE_OPEN_EXISTING_FLAG                  = $00004000;
  {$EXTERNALSYM CERT_STORE_OPEN_EXISTING_FLAG}
  CERT_STORE_CREATE_NEW_FLAG                     = $00002000;
  {$EXTERNALSYM CERT_STORE_CREATE_NEW_FLAG}
  CERT_STORE_MAXIMUM_ALLOWED_FLAG                = $00001000;
  {$EXTERNALSYM CERT_STORE_MAXIMUM_ALLOWED_FLAG}

//+-------------------------------------------------------------------------
//  Certificate Store Provider flags are in the HiWord (0xFFFF0000)
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  Certificate System Store Flag Values
//--------------------------------------------------------------------------
// Includes flags and location
const
  CERT_SYSTEM_STORE_MASK                 = $FFFF0000;
  {$EXTERNALSYM CERT_SYSTEM_STORE_MASK}

// Set if pvPara points to a CERT_SYSTEM_STORE_RELOCATE_PARA structure
const
  CERT_SYSTEM_STORE_RELOCATE_FLAG        = $80000000;
  {$EXTERNALSYM CERT_SYSTEM_STORE_RELOCATE_FLAG}

type
  PCertSystemStoreRelocatePara = ^TCertSystemStoreRelocatePara;
  _CERT_SYSTEM_STORE_RELOCATE_PARA = record
   (* union {
        HKEY                hKeyBase;
        void                *pvBase;
    } DUMMYUNIONNAME;
    union {
        void                *pvSystemStore;
        LPCSTR              pszSystemStore;
        LPCWSTR             pwszSystemStore;
    } DUMMYUNIONNAME2;*)
  end;
  {$EXTERNALSYM _CERT_SYSTEM_STORE_RELOCATE_PARA}
  CERT_SYSTEM_STORE_RELOCATE_PARA = _CERT_SYSTEM_STORE_RELOCATE_PARA;
  {$EXTERNALSYM CERT_SYSTEM_STORE_RELOCATE_PARA}
  TCertSystemStoreRelocatePara = _CERT_SYSTEM_STORE_RELOCATE_PARA;
  PCERT_SYSTEM_STORE_RELOCATE_PARA = PCertSystemStoreRelocatePara;
  {$EXTERNALSYM PCERT_SYSTEM_STORE_RELOCATE_PARA}

// By default, when the CurrentUser "Root" store is opened, any SystemRegistry
// roots not also on the protected root list are deleted from the cache before
// CertOpenStore() returns. Set the following flag to return all the roots
// in the SystemRegistry without checking the protected root list.
const
  CERT_SYSTEM_STORE_UNPROTECTED_FLAG     = $40000000;
  {$EXTERNALSYM CERT_SYSTEM_STORE_UNPROTECTED_FLAG}

  CERT_SYSTEM_STORE_DEFER_READ_FLAG      = $20000000;
  {$EXTERNALSYM CERT_SYSTEM_STORE_DEFER_READ_FLAG}

// Location of the system store:
const
  CERT_SYSTEM_STORE_LOCATION_MASK        = $00FF0000;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCATION_MASK}
  CERT_SYSTEM_STORE_LOCATION_SHIFT       = 16;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCATION_SHIFT}


//  Registry: HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE
const
  CERT_SYSTEM_STORE_CURRENT_USER_ID      = 1;
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER_ID}
  CERT_SYSTEM_STORE_LOCAL_MACHINE_ID     = 2;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_ID}
//  Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Services
const
  CERT_SYSTEM_STORE_CURRENT_SERVICE_ID   = 4;
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_SERVICE_ID}
  CERT_SYSTEM_STORE_SERVICES_ID          = 5;
  {$EXTERNALSYM CERT_SYSTEM_STORE_SERVICES_ID}
//  Registry: HKEY_USERS
const
  CERT_SYSTEM_STORE_USERS_ID             = 6;
  {$EXTERNALSYM CERT_SYSTEM_STORE_USERS_ID}

//  Registry: HKEY_CURRENT_USER\Software\Policies\Microsoft\SystemCertificates
const
  CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID   = 7;
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID}
//  Registry: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates
const
  CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID  = 8;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID}

//  Registry: HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseCertificates
const
  CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID    = 9;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID}

  CERT_SYSTEM_STORE_CURRENT_USER         = (CERT_SYSTEM_STORE_CURRENT_USER_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER}
  CERT_SYSTEM_STORE_LOCAL_MACHINE        = (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE}
  CERT_SYSTEM_STORE_CURRENT_SERVICE      = (CERT_SYSTEM_STORE_CURRENT_SERVICE_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_SERVICE}
  CERT_SYSTEM_STORE_SERVICES             = (CERT_SYSTEM_STORE_SERVICES_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_SERVICES}
  CERT_SYSTEM_STORE_USERS                = (CERT_SYSTEM_STORE_USERS_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_USERS}

  CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY   = (CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY}
  CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY  = (CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY}

  CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE  = (CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE}


//+-------------------------------------------------------------------------
//  Group Policy Store Defines
//--------------------------------------------------------------------------
// Registry path to the Group Policy system stores
const
  CERT_GROUP_POLICY_SYSTEM_STORE_REGPATH =
    'Software\Policies\Microsoft\SystemCertificates';
  {$EXTERNALSYM CERT_GROUP_POLICY_SYSTEM_STORE_REGPATH}

//+-------------------------------------------------------------------------
//  EFS Defines
//--------------------------------------------------------------------------
// Registry path to the EFS EFSBlob SubKey - Value type is REG_BINARY
const
  CERT_EFSBLOB_REGPATH =
    CERT_GROUP_POLICY_SYSTEM_STORE_REGPATH + '\EFS';
  {$EXTERNALSYM CERT_EFSBLOB_REGPATH}
  CERT_EFSBLOB_VALUE_NAME = 'EFSBlob';
  {$EXTERNALSYM CERT_EFSBLOB_VALUE_NAME}

//+-------------------------------------------------------------------------
//  Protected Root Defines
//--------------------------------------------------------------------------
// Registry path to the Protected Roots Flags SubKey
const
  CERT_PROT_ROOT_FLAGS_REGPATH =
    CERT_GROUP_POLICY_SYSTEM_STORE_REGPATH + '\Root\ProtectedRoots';
  {$EXTERNALSYM CERT_PROT_ROOT_FLAGS_REGPATH}

// The following is a REG_DWORD. The bit definitions follow.
const
  CERT_PROT_ROOT_FLAGS_VALUE_NAME = 'Flags';
  {$EXTERNALSYM CERT_PROT_ROOT_FLAGS_VALUE_NAME}

// Set the following flag to inhibit the opening of the CurrentUser's
// .Default physical store when opening the CurrentUser's "Root" system store.
// The .Default physical store open's the CurrentUser SystemRegistry "Root"
// store.
const
  CERT_PROT_ROOT_DISABLE_CURRENT_USER_FLAG   = $1;
  {$EXTERNALSYM CERT_PROT_ROOT_DISABLE_CURRENT_USER_FLAG}

// Set the following flag to inhibit the adding of roots from the
// CurrentUser SystemRegistry "Root" store to the protected root list
// when the "Root" store is initially protected.
const
  CERT_PROT_ROOT_INHIBIT_ADD_AT_INIT_FLAG    = $2;
  {$EXTERNALSYM CERT_PROT_ROOT_INHIBIT_ADD_AT_INIT_FLAG}

// Set the following flag to inhibit the purging of protected roots from the
// CurrentUser SystemRegistry "Root" store that are
// also in the LocalMachine SystemRegistry "Root" store. Note, when not
// disabled, the purging is done silently without UI.
const
  CERT_PROT_ROOT_INHIBIT_PURGE_LM_FLAG       = $4;
  {$EXTERNALSYM CERT_PROT_ROOT_INHIBIT_PURGE_LM_FLAG}

// Set the following flag to inhibit the opening of the LocalMachine's
// .AuthRoot physical store when opening the LocalMachine's "Root" system store.
// The .AuthRoot physical store open's the LocalMachine SystemRegistry
// "AuthRoot" store. The "AuthRoot" store contains the pre-installed
// SSL ServerAuth and the ActiveX Authenticode "root" certificates.
const
  CERT_PROT_ROOT_DISABLE_LM_AUTH_FLAG        = $8;
  {$EXTERNALSYM CERT_PROT_ROOT_DISABLE_LM_AUTH_FLAG}

// The semantics for the following legacy definition has been changed to be
// the same as for the CERT_PROT_ROOT_DISABLE_LM_AUTH_FLAG.
const
  CERT_PROT_ROOT_ONLY_LM_GPT_FLAG            = $8;
  {$EXTERNALSYM CERT_PROT_ROOT_ONLY_LM_GPT_FLAG}

// Set the following flag to disable the requiring of the issuing CA
// certificate being in the "NTAuth" system registry store found in the
// CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE store location.
//
// When set, CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_NT_AUTH)
// will check that the chain has a valid name constraint for all name
// spaces, including UPN if the issuing CA isn't in the "NTAuth" store.
const
  CERT_PROT_ROOT_DISABLE_NT_AUTH_REQUIRED_FLAG = $10;
  {$EXTERNALSYM CERT_PROT_ROOT_DISABLE_NT_AUTH_REQUIRED_FLAG}

// Set the following flag to disable checking for not defined name
// constraints.
//
// When set, CertGetCertificateChain won't check for or set the following
// dwErrorStatus: CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT.
//
// In LH, checking for not defined name constraints is always disabled.
const
  CERT_PROT_ROOT_DISABLE_NOT_DEFINED_NAME_CONSTRAINT_FLAG = $20;
  {$EXTERNALSYM CERT_PROT_ROOT_DISABLE_NOT_DEFINED_NAME_CONSTRAINT_FLAG}

// Set the following flag to disallow the users to trust peer-trust
const
  CERT_PROT_ROOT_DISABLE_PEER_TRUST                       = $10000;
  {$EXTERNALSYM CERT_PROT_ROOT_DISABLE_PEER_TRUST}

// The following is a REG_MULTI_SZ containing the list of user allowed
// Enhanced Key Usages for peer trust.
const
  CERT_PROT_ROOT_PEER_USAGES_VALUE_NAME    = 'PeerUsages';
  {$EXTERNALSYM CERT_PROT_ROOT_PEER_USAGES_VALUE_NAME}
  CERT_PROT_ROOT_PEER_USAGES_VALUE_NAME_A  = 'PeerUsages';
  {$EXTERNALSYM CERT_PROT_ROOT_PEER_USAGES_VALUE_NAME_A}

// If the above REG_MULTI_SZ isn't defined or is empty, defaults to
// the following multi-string value
const
  CERT_PROT_ROOT_PEER_USAGES_DEFAULT_A =
    szOID_PKIX_KP_CLIENT_AUTH + #0 + szOID_PKIX_KP_EMAIL_PROTECTION + #0 + szOID_KP_EFS + #0;
  {$EXTERNALSYM CERT_PROT_ROOT_PEER_USAGES_DEFAULT_A}

//+-------------------------------------------------------------------------
//  Trusted Publisher Definitions
//--------------------------------------------------------------------------
// Registry path to the trusted publisher "Safer" group policy subkey
const
  CERT_TRUST_PUB_SAFER_GROUP_POLICY_REGPATH =
    CERT_GROUP_POLICY_SYSTEM_STORE_REGPATH + '\TrustedPublisher\Safer';
  {$EXTERNALSYM CERT_TRUST_PUB_SAFER_GROUP_POLICY_REGPATH}


// Registry path to the Local Machine system stores
const
  CERT_LOCAL_MACHINE_SYSTEM_STORE_REGPATH =
    'Software\Microsoft\SystemCertificates';
  {$EXTERNALSYM CERT_LOCAL_MACHINE_SYSTEM_STORE_REGPATH}

// Registry path to the trusted publisher "Safer" local machine subkey
const
  CERT_TRUST_PUB_SAFER_LOCAL_MACHINE_REGPATH =
    CERT_LOCAL_MACHINE_SYSTEM_STORE_REGPATH + '\TrustedPublisher\Safer';
  {$EXTERNALSYM CERT_TRUST_PUB_SAFER_LOCAL_MACHINE_REGPATH}


// "Safer" subkey value names. All values are DWORDs.
const
  CERT_TRUST_PUB_AUTHENTICODE_FLAGS_VALUE_NAME   = 'AuthenticodeFlags';
  {$EXTERNALSYM CERT_TRUST_PUB_AUTHENTICODE_FLAGS_VALUE_NAME}


// AuthenticodeFlags definitions

// Definition of who is allowed to trust publishers
//
// Setting allowed trust to MACHINE_ADMIN or ENTERPRISE_ADMIN disables UI,
// only trusts publishers in the "TrustedPublisher" system store and
// inhibits the opening of the CurrentUser's .Default physical store when
// opening the CurrentUsers's "TrustedPublisher" system store.
//
// The .Default physical store open's the CurrentUser SystemRegistry
// "TrustedPublisher" store.
//
// Setting allowed trust to ENTERPRISE_ADMIN only opens the
// LocalMachine's .GroupPolicy and .Enterprise physical stores when opening
// the CurrentUser's "TrustedPublisher" system store or when opening the
// LocalMachine's "TrustedPublisher" system store.
const
  CERT_TRUST_PUB_ALLOW_TRUST_MASK                = $00000003;
  {$EXTERNALSYM CERT_TRUST_PUB_ALLOW_TRUST_MASK}
  CERT_TRUST_PUB_ALLOW_END_USER_TRUST            = $00000000;
  {$EXTERNALSYM CERT_TRUST_PUB_ALLOW_END_USER_TRUST}
  CERT_TRUST_PUB_ALLOW_MACHINE_ADMIN_TRUST       = $00000001;
  {$EXTERNALSYM CERT_TRUST_PUB_ALLOW_MACHINE_ADMIN_TRUST}
  CERT_TRUST_PUB_ALLOW_ENTERPRISE_ADMIN_TRUST    = $00000002;
  {$EXTERNALSYM CERT_TRUST_PUB_ALLOW_ENTERPRISE_ADMIN_TRUST}

// Set the following flag to enable revocation checking of the publisher
// chain.
const
  CERT_TRUST_PUB_CHECK_PUBLISHER_REV_FLAG        = $00000100;
  {$EXTERNALSYM CERT_TRUST_PUB_CHECK_PUBLISHER_REV_FLAG}

// Set the following flag to enable revocation checking of the time stamp
// chain.
const
  CERT_TRUST_PUB_CHECK_TIMESTAMP_REV_FLAG        = $00000200;
  {$EXTERNALSYM CERT_TRUST_PUB_CHECK_TIMESTAMP_REV_FLAG}


//+-------------------------------------------------------------------------
//  OCM Subcomponents Definitions
//
//  Reading of the following registry key has been deprecated on Vista.
//--------------------------------------------------------------------------

// Registry path to the OCM Subcomponents local machine subkey
const
  CERT_OCM_SUBCOMPONENTS_LOCAL_MACHINE_REGPATH =
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OC Manager\Subcomponents';
  {$EXTERNALSYM CERT_OCM_SUBCOMPONENTS_LOCAL_MACHINE_REGPATH}

// REG_DWORD, 1 is installed, 0 is NOT installed
const
  CERT_OCM_SUBCOMPONENTS_ROOT_AUTO_UPDATE_VALUE_NAME = 'RootAutoUpdate';
  {$EXTERNALSYM CERT_OCM_SUBCOMPONENTS_ROOT_AUTO_UPDATE_VALUE_NAME}


//+-------------------------------------------------------------------------
//  DisableRootAutoUpdate Defines
//--------------------------------------------------------------------------
// Registry path to the DisableRootAutoUpdate SubKey
const
  CERT_DISABLE_ROOT_AUTO_UPDATE_REGPATH =
    CERT_GROUP_POLICY_SYSTEM_STORE_REGPATH + '\AuthRoot';
  {$EXTERNALSYM CERT_DISABLE_ROOT_AUTO_UPDATE_REGPATH}

// REG_DWORD Value Name, 1 - disables, 0 - enables
const
  CERT_DISABLE_ROOT_AUTO_UPDATE_VALUE_NAME = 'DisableRootAutoUpdate';
  {$EXTERNALSYM CERT_DISABLE_ROOT_AUTO_UPDATE_VALUE_NAME}

//+-------------------------------------------------------------------------
//  Auto Update Definitions
//--------------------------------------------------------------------------

// Registry path to the "Auto Update" local machine subkey
const
  CERT_AUTO_UPDATE_LOCAL_MACHINE_REGPATH =
    CERT_LOCAL_MACHINE_SYSTEM_STORE_REGPATH + '\AuthRoot\AutoUpdate';
  {$EXTERNALSYM CERT_AUTO_UPDATE_LOCAL_MACHINE_REGPATH}

// Auto Update subkey value names.

// REG_SZ, URL to the directory containing the AutoUpdate files
const
  CERT_AUTO_UPDATE_ROOT_DIR_URL_VALUE_NAME               = 'RootDirUrl';
  {$EXTERNALSYM CERT_AUTO_UPDATE_ROOT_DIR_URL_VALUE_NAME}


//+-------------------------------------------------------------------------
//  AuthRoot Auto Update Definitions
//--------------------------------------------------------------------------

// Registry path to the AuthRoot "Auto Update" local machine subkey
const
  CERT_AUTH_ROOT_AUTO_UPDATE_LOCAL_MACHINE_REGPATH       = CERT_AUTO_UPDATE_LOCAL_MACHINE_REGPATH;
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_LOCAL_MACHINE_REGPATH}


// AuthRoot Auto Update subkey value names.

// REG_SZ, URL to the directory containing the AuthRoots, CTL and Seq files
const
  CERT_AUTH_ROOT_AUTO_UPDATE_ROOT_DIR_URL_VALUE_NAME     = CERT_AUTO_UPDATE_ROOT_DIR_URL_VALUE_NAME;
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_ROOT_DIR_URL_VALUE_NAME}

// REG_DWORD, seconds between syncs. 0 implies use default.
const
  CERT_AUTH_ROOT_AUTO_UPDATE_SYNC_DELTA_TIME_VALUE_NAME  = 'SyncDeltaTime';
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_SYNC_DELTA_TIME_VALUE_NAME}

// REG_DWORD, misc flags
const
  CERT_AUTH_ROOT_AUTO_UPDATE_FLAGS_VALUE_NAME            = 'Flags';
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_FLAGS_VALUE_NAME}

  CERT_AUTH_ROOT_AUTO_UPDATE_DISABLE_UNTRUSTED_ROOT_LOGGING_FLAG = $1;
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_DISABLE_UNTRUSTED_ROOT_LOGGING_FLAG}
  CERT_AUTH_ROOT_AUTO_UPDATE_DISABLE_PARTIAL_CHAIN_LOGGING_FLAG  = $2;
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_DISABLE_PARTIAL_CHAIN_LOGGING_FLAG}

// By default a random query string is appended to the Auto Update URLs
// passed to CryptRetrieveObjectByUrlW. See the
// CRYPT_RANDOM_QUERY_STRING_RETRIEVAL flag for more details. Set
// this flag to not set this random query string. This might be the
// case when setting CERT_AUTO_UPDATE_ROOT_DIR_URL_VALUE_NAME where the
// server doesn't strip off the query string.
const
  CERT_AUTO_UPDATE_DISABLE_RANDOM_QUERY_STRING_FLAG              = $4;
  {$EXTERNALSYM CERT_AUTO_UPDATE_DISABLE_RANDOM_QUERY_STRING_FLAG}

// REG_BINARY, updated with FILETIME of last wire retrieval of authroot cab/ctl
const
  CERT_AUTH_ROOT_AUTO_UPDATE_LAST_SYNC_TIME_VALUE_NAME   = 'LastSyncTime';
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_LAST_SYNC_TIME_VALUE_NAME}

// REG_BINARY, updated with last retrieved and verified authroot ctl
const
  CERT_AUTH_ROOT_AUTO_UPDATE_ENCODED_CTL_VALUE_NAME      = 'EncodedCtl';
  {$EXTERNALSYM CERT_AUTH_ROOT_AUTO_UPDATE_ENCODED_CTL_VALUE_NAME}


// AuthRoot Auto Update filenames

// CTL containing the list of certs in the AuthRoot store
const
  CERT_AUTH_ROOT_CTL_FILENAME                            = 'authroot.stl';
  {$EXTERNALSYM CERT_AUTH_ROOT_CTL_FILENAME}
  CERT_AUTH_ROOT_CTL_FILENAME_A                          = 'authroot.stl';
  {$EXTERNALSYM CERT_AUTH_ROOT_CTL_FILENAME_A}

// Cab containing the above CTL
const
  CERT_AUTH_ROOT_CAB_FILENAME                            = 'authrootstl.cab';
  {$EXTERNALSYM CERT_AUTH_ROOT_CAB_FILENAME}

// SequenceNumber (Formatted as big endian ascii hex)
const
  CERT_AUTH_ROOT_SEQ_FILENAME                            = 'authrootseq.txt';
  {$EXTERNALSYM CERT_AUTH_ROOT_SEQ_FILENAME}

// Root certs extension
const
  CERT_AUTH_ROOT_CERT_EXT                                = '.crt';
  {$EXTERNALSYM CERT_AUTH_ROOT_CERT_EXT}


//+-------------------------------------------------------------------------
//  DisallowedCert Auto Update Definitions
//--------------------------------------------------------------------------

//
// DisallowedCert Auto Update subkey value names.
//


// REG_DWORD, seconds between syncs. 0 implies use default.
const
  CERT_DISALLOWED_CERT_AUTO_UPDATE_SYNC_DELTA_TIME_VALUE_NAME = 'DisallowedCertSyncDeltaTime';
  {$EXTERNALSYM CERT_DISALLOWED_CERT_AUTO_UPDATE_SYNC_DELTA_TIME_VALUE_NAME}

// REG_BINARY, updated with FILETIME of last wire retrieval of disallowed cert
// CTL
const
  CERT_DISALLOWED_CERT_AUTO_UPDATE_LAST_SYNC_TIME_VALUE_NAME  = 'DisallowedCertLastSyncTime';
  {$EXTERNALSYM CERT_DISALLOWED_CERT_AUTO_UPDATE_LAST_SYNC_TIME_VALUE_NAME}

// REG_BINARY, updated with last retrieved and verified disallowed cert ctl
const
  CERT_DISALLOWED_CERT_AUTO_UPDATE_ENCODED_CTL_VALUE_NAME     = 'DisallowedCertEncodedCtl';
  {$EXTERNALSYM CERT_DISALLOWED_CERT_AUTO_UPDATE_ENCODED_CTL_VALUE_NAME}

//
// DisallowedCert Auto Update filenames
//

// CTL containing the list of disallowed certs
const
  CERT_DISALLOWED_CERT_CTL_FILENAME              = 'disallowedcert.stl';
  {$EXTERNALSYM CERT_DISALLOWED_CERT_CTL_FILENAME}
  CERT_DISALLOWED_CERT_CTL_FILENAME_A            = 'disallowedcert.stl';
  {$EXTERNALSYM CERT_DISALLOWED_CERT_CTL_FILENAME_A}

// Cab containing disallowed certs  CTL
const
  CERT_DISALLOWED_CERT_CAB_FILENAME              = 'disallowedcertstl.cab';
  {$EXTERNALSYM CERT_DISALLOWED_CERT_CAB_FILENAME}

//
// DisallowedCert Auto Update CTL List Identifiers
//

// Disallowed Cert CTL List Identifier
const
  CERT_DISALLOWED_CERT_AUTO_UPDATE_LIST_IDENTIFIER            = 'DisallowedCert_AutoUpdate_1';
  {$EXTERNALSYM CERT_DISALLOWED_CERT_AUTO_UPDATE_LIST_IDENTIFIER}



//+-------------------------------------------------------------------------
//  Certificate Registry Store Flag Values (CERT_STORE_REG)
//--------------------------------------------------------------------------

// Set this flag if the HKEY passed in pvPara points to a remote computer
// registry key.
const
  CERT_REGISTRY_STORE_REMOTE_FLAG        = $10000;
  {$EXTERNALSYM CERT_REGISTRY_STORE_REMOTE_FLAG}

// Set this flag if the contexts are to be persisted as a single serialized
// store in the registry. Mainly used for stores downloaded from the GPT.
// Such as the CurrentUserGroupPolicy or LocalMachineGroupPolicy stores.
const
  CERT_REGISTRY_STORE_SERIALIZED_FLAG    = $20000;
  {$EXTERNALSYM CERT_REGISTRY_STORE_SERIALIZED_FLAG}

// The following flags are for internal use. When set, the
// pvPara parameter passed to CertOpenStore is a pointer to the following
// data structure and not the HKEY. The above CERT_REGISTRY_STORE_REMOTE_FLAG
// is also set if hKeyBase was obtained via RegConnectRegistry().
const
  CERT_REGISTRY_STORE_CLIENT_GPT_FLAG    = $80000000;
  {$EXTERNALSYM CERT_REGISTRY_STORE_CLIENT_GPT_FLAG}
  CERT_REGISTRY_STORE_LM_GPT_FLAG        = $01000000;
  {$EXTERNALSYM CERT_REGISTRY_STORE_LM_GPT_FLAG}

type
  PCertRegistryStoreClientGPTPara = ^TCertRegistryStoreClientGPTPara;
  _CERT_REGISTRY_STORE_CLIENT_GPT_PARA = record
    hKeyBase: HKEY;
    pwszRegPath: LPWSTR;
  end;
  {$EXTERNALSYM _CERT_REGISTRY_STORE_CLIENT_GPT_PARA}
  CERT_REGISTRY_STORE_CLIENT_GPT_PARA = _CERT_REGISTRY_STORE_CLIENT_GPT_PARA;
  {$EXTERNALSYM CERT_REGISTRY_STORE_CLIENT_GPT_PARA}
  TCertRegistryStoreClientGPTPara = _CERT_REGISTRY_STORE_CLIENT_GPT_PARA;
  PCERT_REGISTRY_STORE_CLIENT_GPT_PARA = PCertRegistryStoreClientGPTPara;
  {$EXTERNALSYM PCERT_REGISTRY_STORE_CLIENT_GPT_PARA}

// The following flag is for internal use. When set, the contexts are
// persisted into roaming files instead of the registry. Such as, the
// CurrentUser "My" store. When this flag is set, the following data structure
// is passed to CertOpenStore instead of HKEY.
const
  CERT_REGISTRY_STORE_ROAMING_FLAG       = $40000;
  {$EXTERNALSYM CERT_REGISTRY_STORE_ROAMING_FLAG}

// hKey may be NULL or non-NULL. When non-NULL, existing contexts are
// moved from the registry to roaming files.
type
  PCertRegistryStoreRoamingPara = ^TCertRegistryStoreRoamingPara;
  _CERT_REGISTRY_STORE_ROAMING_PARA = record
    hKey: HKEY;
    pwszStoreDirectory: LPWSTR;
  end;
  {$EXTERNALSYM _CERT_REGISTRY_STORE_ROAMING_PARA}
  CERT_REGISTRY_STORE_ROAMING_PARA = _CERT_REGISTRY_STORE_ROAMING_PARA;
  {$EXTERNALSYM CERT_REGISTRY_STORE_ROAMING_PARA}
  TCertRegistryStoreRoamingPara = _CERT_REGISTRY_STORE_ROAMING_PARA;
  PCERT_REGISTRY_STORE_ROAMING_PARA = PCertRegistryStoreRoamingPara;
  {$EXTERNALSYM PCERT_REGISTRY_STORE_ROAMING_PARA}

// The following flag is for internal use. When set, the "My" DWORD value
// at HKLM\Software\Microsoft\Cryptography\IEDirtyFlags is set to 0x1
// whenever a certificate is added to the registry store.
//
// Legacy definition, no longer supported after 01-May-02 (Server 2003)
const
  CERT_REGISTRY_STORE_MY_IE_DIRTY_FLAG   = $80000;
  {$EXTERNALSYM CERT_REGISTRY_STORE_MY_IE_DIRTY_FLAG}

  CERT_REGISTRY_STORE_EXTERNAL_FLAG     = $100000;
  {$EXTERNALSYM CERT_REGISTRY_STORE_EXTERNAL_FLAG}

// Registry path to the subkey containing the "My" DWORD value to be set
//
// Legacy definition, no longer supported after 01-May-02 (Server 2003)
const
  CERT_IE_DIRTY_FLAGS_REGPATH = 'Software\Microsoft\Cryptography\IEDirtyFlags';
  {$EXTERNALSYM CERT_IE_DIRTY_FLAGS_REGPATH}


//+-------------------------------------------------------------------------
//  Certificate File Store Flag Values for the providers:
//      CERT_STORE_PROV_FILE
//      CERT_STORE_PROV_FILENAME
//      CERT_STORE_PROV_FILENAME_A
//      CERT_STORE_PROV_FILENAME_W
//      sz_CERT_STORE_PROV_FILENAME_W
//--------------------------------------------------------------------------

// Set this flag if any store changes are to be committed to the file.
// The changes are committed at CertCloseStore or by calling
// CertControlStore(CERT_STORE_CTRL_COMMIT).
//
// The open fails with E_INVALIDARG if both CERT_FILE_STORE_COMMIT_ENABLE_FLAG
// and CERT_STORE_READONLY_FLAG are set in dwFlags.
//
// For the FILENAME providers:  if the file contains an X509 encoded
// certificate, the open fails with ERROR_ACCESS_DENIED.
//
// For the FILENAME providers: if CERT_STORE_CREATE_NEW_FLAG is set, the
// CreateFile uses CREATE_NEW. If CERT_STORE_OPEN_EXISTING is set, uses
// OPEN_EXISTING. Otherwise, defaults to OPEN_ALWAYS.
//
// For the FILENAME providers:  the file is committed as either a PKCS7 or
// serialized store depending on the type read at open. However, if the
// file is empty then, if the filename has either a ".p7c" or ".spc"
// extension its committed as a PKCS7. Otherwise, its committed as a
// serialized store.
//
// For CERT_STORE_PROV_FILE, the file handle is duplicated. Its always
// committed as a serialized store.
//
const
  CERT_FILE_STORE_COMMIT_ENABLE_FLAG     = $10000;
  {$EXTERNALSYM CERT_FILE_STORE_COMMIT_ENABLE_FLAG}


//+-------------------------------------------------------------------------
//  Certificate LDAP Store Flag Values for the providers:
//      CERT_STORE_PROV_LDAP
//      CERT_STORE_PROV_LDAP_W
//      sz_CERT_STORE_PROV_LDAP_W
//      sz_CERT_STORE_PROV_LDAP
//--------------------------------------------------------------------------

// Set this flag to digitally sign all of the ldap traffic to and from a
// Windows 2000 LDAP server using the Kerberos authentication protocol.
// This feature provides integrity required by some applications.
//
const
  CERT_LDAP_STORE_SIGN_FLAG              = $10000;
  {$EXTERNALSYM CERT_LDAP_STORE_SIGN_FLAG}

// Performs an A-Record only DNS lookup on the supplied host string.
// This prevents bogus DNS queries from being generated when resolving host
// names. Use this flag whenever passing a hostname as opposed to a
// domain name for the hostname parameter.
//
// See LDAP_OPT_AREC_EXCLUSIVE defined in winldap.h for more details.
const
  CERT_LDAP_STORE_AREC_EXCLUSIVE_FLAG    = $20000;
  {$EXTERNALSYM CERT_LDAP_STORE_AREC_EXCLUSIVE_FLAG}

// Set this flag if the LDAP session handle has already been opened. When
// set, pvPara points to the following CERT_LDAP_STORE_OPENED_PARA structure.
const
  CERT_LDAP_STORE_OPENED_FLAG            = $40000;
  {$EXTERNALSYM CERT_LDAP_STORE_OPENED_FLAG}

type
  PCertLDAPStoreOpenedPara = ^TCertLDAPStoreOpenedPara;
  _CERT_LDAP_STORE_OPENED_PARA = record
    pvLdapSessionHandle: Pointer;   // The (LDAP *) handle returned by
                                    // ldap_init
    pwszLdapUrl: LPCWSTR;
  end;
  {$EXTERNALSYM _CERT_LDAP_STORE_OPENED_PARA}
  CERT_LDAP_STORE_OPENED_PARA = _CERT_LDAP_STORE_OPENED_PARA;
  {$EXTERNALSYM CERT_LDAP_STORE_OPENED_PARA}
  TCertLDAPStoreOpenedPara = _CERT_LDAP_STORE_OPENED_PARA;
  PCERT_LDAP_STORE_OPENED_PARA = PCertLDAPStoreOpenedPara;
  {$EXTERNALSYM PCERT_LDAP_STORE_OPENED_PARA}

// Set this flag if the above CERT_LDAP_STORE_OPENED_FLAG is set and
// you want an ldap_unbind() of the above pvLdapSessionHandle when the
// store is closed. Note, if CertOpenStore() fails, then, ldap_unbind()
// isn't called.
const
  CERT_LDAP_STORE_UNBIND_FLAG            = $80000;
  {$EXTERNALSYM CERT_LDAP_STORE_UNBIND_FLAG}

//+-------------------------------------------------------------------------
//  Open the cert store using the specified store provider.
//
//  If CERT_STORE_DELETE_FLAG is set, then, the store is deleted. NULL is
//  returned for both success and failure. However, GetLastError() returns 0
//  for success and nonzero for failure.
//
//  If CERT_STORE_SET_LOCALIZED_NAME_FLAG is set, then, if supported, the
//  provider sets the store's CERT_STORE_LOCALIZED_NAME_PROP_ID property.
//  The store's localized name can be retrieved by calling
//  CertSetStoreProperty(dwPropID = CERT_STORE_LOCALIZED_NAME_PROP_ID).
//  This flag is supported by the following providers (and their sz_
//  equivalent):
//      CERT_STORE_PROV_FILENAME_A
//      CERT_STORE_PROV_FILENAME_W
//      CERT_STORE_PROV_SYSTEM_A
//      CERT_STORE_PROV_SYSTEM_W
//      CERT_STORE_PROV_SYSTEM_REGISTRY_A
//      CERT_STORE_PROV_SYSTEM_REGISTRY_W
//      CERT_STORE_PROV_PHYSICAL_W
//
//  If CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG is set, then, the
//  closing of the store's provider is deferred until all certificate,
//  CRL and CTL contexts obtained from the store are freed. Also,
//  if a non NULL HCRYPTPROV was passed, then, it will continue to be used.
//  By default, the store's provider is closed on the final CertCloseStore.
//  If this flag isn't set, then, any property changes made to previously
//  duplicated contexts after the final CertCloseStore will not be persisted.
//  By setting this flag, property changes made
//  after the CertCloseStore will be persisted. Note, setting this flag
//  causes extra overhead in doing context duplicates and frees.
//  If CertCloseStore is called with CERT_CLOSE_STORE_FORCE_FLAG, then,
//  the CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG flag is ignored.
//
//  CERT_STORE_MANIFOLD_FLAG can be set to check for certificates having the
//  manifold extension and archive the "older" certificates with the same
//  manifold extension value. A certificate is archived by setting the
//  CERT_ARCHIVED_PROP_ID.
//
//  By default, contexts having the CERT_ARCHIVED_PROP_ID, are skipped
//  during enumeration. CERT_STORE_ENUM_ARCHIVED_FLAG can be set to include
//  archived contexts when enumerating. Note, contexts having the
//  CERT_ARCHIVED_PROP_ID are still found for explicit finds, such as,
//  finding a context with a specific hash or finding a certificate having
//  a specific issuer and serial number.
//
//  CERT_STORE_UPDATE_KEYID_FLAG can be set to also update the Key Identifier's
//  CERT_KEY_PROV_INFO_PROP_ID property whenever a certificate's
//  CERT_KEY_IDENTIFIER_PROP_ID or CERT_KEY_PROV_INFO_PROP_ID property is set
//  and the other property already exists. If the Key Identifier's
//  CERT_KEY_PROV_INFO_PROP_ID already exists, it isn't updated. Any
//  errors encountered are silently ignored.
//
//  By default, this flag is implicitly set for the "My\.Default" CurrentUser
//  and LocalMachine physical stores.
//
//  CERT_STORE_READONLY_FLAG can be set to open the store as read only.
//  Otherwise, the store is opened as read/write.
//
//  CERT_STORE_OPEN_EXISTING_FLAG can be set to only open an existing
//  store. CERT_STORE_CREATE_NEW_FLAG can be set to create a new store and
//  fail if the store already exists. Otherwise, the default is to open
//  an existing store or create a new store if it doesn't already exist.
//
//  hCryptProv specifies the crypto provider to use to create the hash
//  properties or verify the signature of a subject certificate or CRL.
//  The store doesn't need to use a private
//  key. If the CERT_STORE_NO_CRYPT_RELEASE_FLAG isn't set, hCryptProv is
//  CryptReleaseContext'ed on the final CertCloseStore.
//
//  Note, if the open fails, hCryptProv is released if it would have been
//  released when the store was closed.
//
//  If hCryptProv is zero, then, the default provider and container for the
//  PROV_RSA_FULL provider type is CryptAcquireContext'ed with
//  CRYPT_VERIFYCONTEXT access. The CryptAcquireContext is deferred until
//  the first create hash or verify signature. In addition, once acquired,
//  the default provider isn't released until process exit when crypt32.dll
//  is unloaded. The acquired default provider is shared across all stores
//  and threads.
//
//  After initializing the store's data structures and optionally acquiring a
//  default crypt provider, CertOpenStore calls CryptGetOIDFunctionAddress to
//  get the address of the CRYPT_OID_OPEN_STORE_PROV_FUNC specified by
//  lpszStoreProvider. Since a store can contain certificates with different
//  encoding types, CryptGetOIDFunctionAddress is called with dwEncodingType
//  set to 0 and not the dwEncodingType passed to CertOpenStore.
//  PFN_CERT_DLL_OPEN_STORE_FUNC specifies the signature of the provider's
//  open function. This provider open function is called to load the
//  store's certificates and CRLs. Optionally, the provider may return an
//  array of functions called before a certificate or CRL is added or deleted
//  or has a property that is set.
//
//  Use of the dwEncodingType parameter is provider dependent. The type
//  definition for pvPara also depends on the provider.
//
//  Store providers are installed or registered via
//  CryptInstallOIDFunctionAddress or CryptRegisterOIDFunction, where,
//  dwEncodingType is 0 and pszFuncName is CRYPT_OID_OPEN_STORE_PROV_FUNC.
//
//  Here's a list of the predefined provider types (implemented in crypt32.dll):
//
//  CERT_STORE_PROV_MSG:
//      Gets the certificates and CRLs from the specified cryptographic message.
//      dwEncodingType contains the message and certificate encoding types.
//      The message's handle is passed in pvPara. Given,
//          HCRYPTMSG hCryptMsg; pvPara = (const void *) hCryptMsg;
//
//  CERT_STORE_PROV_MEMORY
//  sz_CERT_STORE_PROV_MEMORY:
//      Opens a store without any initial certificates or CRLs. pvPara
//      isn't used.
//
//  CERT_STORE_PROV_FILE:
//      Reads the certificates and CRLs from the specified file. The file's
//      handle is passed in pvPara. Given,
//          HANDLE hFile; pvPara = (const void *) hFile;
//
//      For a successful open, the file pointer is advanced past
//      the certificates and CRLs and their properties read from the file.
//      Note, only expects a serialized store and not a file containing
//      either a PKCS #7 signed message or a single encoded certificate.
//
//      The hFile isn't closed.
//
//  CERT_STORE_PROV_REG:
//      Reads the certificates and CRLs from the registry. The registry's
//      key handle is passed in pvPara. Given,
//          HKEY hKey; pvPara = (const void *) hKey;
//
//      The input hKey isn't closed by the provider. Before returning, the
//      provider opens it own copy of the hKey.
//
//      If CERT_STORE_READONLY_FLAG is set, then, the registry subkeys are
//      RegOpenKey'ed with KEY_READ_ACCESS. Otherwise, the registry subkeys
//      are RegCreateKey'ed with KEY_ALL_ACCESS.
//
//      This provider returns the array of functions for reading, writing,
//      deleting and property setting certificates and CRLs.
//      Any changes to the opened store are immediately pushed through to
//      the registry. However, if CERT_STORE_READONLY_FLAG is set, then,
//      writing, deleting or property setting results in a
//      SetLastError(E_ACCESSDENIED).
//
//      Note, all the certificates and CRLs are read from the registry
//      when the store is opened. The opened store serves as a write through
//      cache.
//
//      If CERT_REGISTRY_STORE_SERIALIZED_FLAG is set, then, the
//      contexts are persisted as a single serialized store subkey in the
//      registry.
//
//  CERT_STORE_PROV_PKCS7:
//  sz_CERT_STORE_PROV_PKCS7:
//      Gets the certificates and CRLs from the encoded PKCS #7 signed message.
//      dwEncodingType specifies the message and certificate encoding types.
//      The pointer to the encoded message's blob is passed in pvPara. Given,
//          CRYPT_DATA_BLOB EncodedMsg; pvPara = (const void *) &EncodedMsg;
//
//      Note, also supports the IE3.0 special version of a
//      PKCS #7 signed message referred to as a "SPC" formatted message.
//
//  CERT_STORE_PROV_SERIALIZED:
//  sz_CERT_STORE_PROV_SERIALIZED:
//      Gets the certificates and CRLs from memory containing a serialized
//      store.  The pointer to the serialized memory blob is passed in pvPara.
//      Given,
//          CRYPT_DATA_BLOB Serialized; pvPara = (const void *) &Serialized;
//
//  CERT_STORE_PROV_FILENAME_A:
//  CERT_STORE_PROV_FILENAME_W:
//  CERT_STORE_PROV_FILENAME:
//  sz_CERT_STORE_PROV_FILENAME_W:
//  sz_CERT_STORE_PROV_FILENAME:
//      Opens the file and first attempts to read as a serialized store. Then,
//      as a PKCS #7 signed message. Finally, as a single encoded certificate.
//      The filename is passed in pvPara. The filename is UNICODE for the
//      "_W" provider and ASCII for the "_A" provider. For "_W": given,
//          LPCWSTR pwszFilename; pvPara = (const void *) pwszFilename;
//      For "_A": given,
//          LPCSTR pszFilename; pvPara = (const void *) pszFilename;
//
//      Note, the default (without "_A" or "_W") is unicode.
//
//      Note, also supports the reading of the IE3.0 special version of a
//      PKCS #7 signed message file referred to as a "SPC" formatted file.
//
//  CERT_STORE_PROV_SYSTEM_A:
//  CERT_STORE_PROV_SYSTEM_W:
//  CERT_STORE_PROV_SYSTEM:
//  sz_CERT_STORE_PROV_SYSTEM_W:
//  sz_CERT_STORE_PROV_SYSTEM:
//      Opens the specified logical "System" store. The upper word of the
//      dwFlags parameter is used to specify the location of the system store.
//
//      A "System" store is a collection consisting of one or more "Physical"
//      stores. A "Physical" store is registered via the
//      CertRegisterPhysicalStore API. Each of the registered physical stores
//      is CertStoreOpen'ed and added to the collection via
//      CertAddStoreToCollection.
//
//      The CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
//      CERT_SYSTEM_STORE_CURRENT_SERVICE, CERT_SYSTEM_STORE_SERVICES,
//      CERT_SYSTEM_STORE_USERS, CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY,
//      CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY and
//      CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRSE
//      system stores by default have a "SystemRegistry" store that is
//      opened and added to the collection.
//
//      The system store name is passed in pvPara. The name is UNICODE for the
//      "_W" provider and ASCII for the "_A" provider. For "_W": given,
//          LPCWSTR pwszSystemName; pvPara = (const void *) pwszSystemName;
//      For "_A": given,
//          LPCSTR pszSystemName; pvPara = (const void *) pszSystemName;
//
//      Note, the default (without "_A" or "_W") is UNICODE.
//
//      The system store name can't contain any backslashes.
//
//      If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvPara
//      points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure instead
//      of pointing to a null terminated UNICODE or ASCII string.
//      Sibling physical stores are also opened as relocated using
//      pvPara's hKeyBase.
//
//      The CERT_SYSTEM_STORE_SERVICES or CERT_SYSTEM_STORE_USERS system
//      store name must be prefixed with the ServiceName or UserName.
//      For example, "ServiceName\Trust".
//
//      Stores on remote computers can be accessed for the
//      CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_SYSTEM_STORE_SERVICES,
//      CERT_SYSTEM_STORE_USERS, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
//      or CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
//      locations by prepending the computer name. For example, a remote
//      local machine store is accessed via "\\ComputerName\Trust" or
//      "ComputerName\Trust". A remote service store is accessed via
//      "\\ComputerName\ServiceName\Trust". The leading "\\" backslashes are
//      optional in the ComputerName.
//
//      If CERT_STORE_READONLY_FLAG is set, then, the registry is
//      RegOpenKey'ed with KEY_READ_ACCESS. Otherwise, the registry is
//      RegCreateKey'ed with KEY_ALL_ACCESS.
//
//      The "root" store is treated differently from the other system
//      stores. Before a certificate is added to or deleted from the "root"
//      store, a pop up message box is displayed. The certificate's subject,
//      issuer, serial number, time validity, sha1 and md5 thumbprints are
//      displayed. The user is given the option to do the add or delete.
//      If they don't allow the operation, LastError is set to E_ACCESSDENIED.
//
//  CERT_STORE_PROV_SYSTEM_REGISTRY_A
//  CERT_STORE_PROV_SYSTEM_REGISTRY_W
//  CERT_STORE_PROV_SYSTEM_REGISTRY
//  sz_CERT_STORE_PROV_SYSTEM_REGISTRY_W
//  sz_CERT_STORE_PROV_SYSTEM_REGISTRY
//      Opens the "System" store's default "Physical" store residing in the
//      registry. The upper word of the dwFlags
//      parameter is used to specify the location of the system store.
//
//      After opening the registry key associated with the system name,
//      the CERT_STORE_PROV_REG provider is called to complete the open.
//
//      The system store name is passed in pvPara. The name is UNICODE for the
//      "_W" provider and ASCII for the "_A" provider. For "_W": given,
//          LPCWSTR pwszSystemName; pvPara = (const void *) pwszSystemName;
//      For "_A": given,
//          LPCSTR pszSystemName; pvPara = (const void *) pszSystemName;
//
//      Note, the default (without "_A" or "_W") is UNICODE.
//
//      If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvPara
//      points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure instead
//      of pointing to a null terminated UNICODE or ASCII string.
//
//      See above for details on prepending a ServiceName and/or ComputerName
//      to the store name.
//
//      If CERT_STORE_READONLY_FLAG is set, then, the registry is
//      RegOpenKey'ed with KEY_READ_ACCESS. Otherwise, the registry is
//      RegCreateKey'ed with KEY_ALL_ACCESS.
//
//      The "root" store is treated differently from the other system
//      stores. Before a certificate is added to or deleted from the "root"
//      store, a pop up message box is displayed. The certificate's subject,
//      issuer, serial number, time validity, sha1 and md5 thumbprints are
//      displayed. The user is given the option to do the add or delete.
//      If they don't allow the operation, LastError is set to E_ACCESSDENIED.
//
//  CERT_STORE_PROV_PHYSICAL_W
//  CERT_STORE_PROV_PHYSICAL
//  sz_CERT_STORE_PROV_PHYSICAL_W
//  sz_CERT_STORE_PROV_PHYSICAL
//      Opens the specified "Physical" store in the "System" store.
//
//      Both the system store and physical names are passed in pvPara. The
//      names are separated with an intervening "\". For example,
//      "Root\.Default". The string is UNICODE.
//
//      The system and physical store names can't contain any backslashes.
//
//      If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvPara
//      points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure instead
//      of pointing to a null terminated UNICODE string.
//      The specified physical store is opened as relocated using pvPara's
//      hKeyBase.
//
//      For CERT_SYSTEM_STORE_SERVICES or CERT_SYSTEM_STORE_USERS,
//      the system and physical store names
//      must be prefixed with the ServiceName or UserName. For example,
//      "ServiceName\Root\.Default".
//
//      Physical stores on remote computers can be accessed for the
//      CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_SYSTEM_STORE_SERVICES,
//      CERT_SYSTEM_STORE_USERS, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
//      or CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
//      locations by prepending the computer name. For example, a remote
//      local machine store is accessed via "\\ComputerName\Root\.Default"
//      or "ComputerName\Root\.Default". A remote service store is
//      accessed via "\\ComputerName\ServiceName\Root\.Default". The
//      leading "\\" backslashes are optional in the ComputerName.
//
//  CERT_STORE_PROV_COLLECTION
//  sz_CERT_STORE_PROV_COLLECTION
//      Opens a store that is a collection of other stores. Stores are
//      added or removed to/from the collection via the CertAddStoreToCollection
//      and CertRemoveStoreFromCollection APIs.
//
//  CERT_STORE_PROV_SMART_CARD_W
//  CERT_STORE_PROV_SMART_CARD
//  sz_CERT_STORE_PROV_SMART_CARD_W
//  sz_CERT_STORE_PROV_SMART_CARD
//      Opens a store instantiated over a particular smart card storage.  pvPara
//      identifies where on the card the store is located and is of the
//      following format:
//
//                Card Name\Provider Name\Provider Type[\Container Name]
//
//      Container Name is optional and if NOT specified the Card Name is used
//      as the Container Name.  Future versions of the provider will support
//      instantiating the store over the entire card in which case just
//      Card Name ( or id ) will be sufficient.
//
//  Here's a list of the predefined provider types (implemented in
//  cryptnet.dll):
//
//  CERT_STORE_PROV_LDAP_W
//  CERT_STORE_PROV_LDAP
//  sz_CERT_STORE_PROV_LDAP_W
//  sz_CERT_STORE_PROV_LDAP
//      Opens a store over the results of the query specified by and LDAP
//      URL which is passed in via pvPara.  In order to do writes to the
//      store the URL must specify a BASE query, no filter and a single
//      attribute.
//
//--------------------------------------------------------------------------
function CertOpenStore(
  lpszStoreProvider: LPCSTR;
  dwEncodingType: DWORD;
  hCryptProv: HCRYPTPROV_LEGACY;
  dwFlags: DWORD;
  pvPara: Pointer): HCERTSTORE; winapi;
{$EXTERNALSYM CertOpenStore}

//+-------------------------------------------------------------------------
//  OID Installable Certificate Store Provider Data Structures
//--------------------------------------------------------------------------

// Handle returned by the store provider when opened.
type
  HCERTSTOREPROV = Pointer;
  {$EXTERNALSYM HCERTSTOREPROV}

// Store Provider OID function's pszFuncName.
const
  CRYPT_OID_OPEN_STORE_PROV_FUNC  = 'CertDllOpenStoreProv';
  {$EXTERNALSYM CRYPT_OID_OPEN_STORE_PROV_FUNC}

// Note, the Store Provider OID function's dwEncodingType is always 0.

// The following information is returned by the provider when opened. Its
// zeroed with cbSize set before the provider is called. If the provider
// doesn't need to be called again after the open it doesn't need to
// make any updates to the CERT_STORE_PROV_INFO.
type
  PCertStoreProvInfo = ^TCertStoreProvInfo;
  _CERT_STORE_PROV_INFO = record
    cbSize: DWORD;
    cStoreProvFunc: DWORD;
    rgpvStoreProvFunc: PPointer;
    hStoreProv: HCERTSTOREPROV;
    dwStoreProvFlags: DWORD;
    hStoreProvFuncAddr2: HCRYPTOIDFUNCADDR;
  end;
  {$EXTERNALSYM _CERT_STORE_PROV_INFO}
  CERT_STORE_PROV_INFO = _CERT_STORE_PROV_INFO;
  {$EXTERNALSYM CERT_STORE_PROV_INFO}
  TCertStoreProvInfo = _CERT_STORE_PROV_INFO;
  PCERT_STORE_PROV_INFO = PCertStoreProvInfo;
  {$EXTERNALSYM PCERT_STORE_PROV_INFO}

// Definition of the store provider's open function.
//
// *pStoreProvInfo has been zeroed before the call.
//
// Note, pStoreProvInfo->cStoreProvFunc should be set last.  Once set,
// all subsequent store calls, such as CertAddSerializedElementToStore will
// call the appropriate provider callback function.
type
  PFN_CERT_DLL_OPEN_STORE_PROV_FUNC = function(
    lpszStoreProvider: LPCSTR;
    dwEncodingType: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    dwFlags: DWORD;
    pvPara: Pointer;
    hCertStore: HCERTSTORE;
    pStoreProvInfo: PCertStoreProvInfo): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_DLL_OPEN_STORE_PROV_FUNC}
  TFnCertDllOpenStoreProvFunc = PFN_CERT_DLL_OPEN_STORE_PROV_FUNC;

// The open callback sets the following flag, if it maintains its
// contexts externally and not in the cached store.
const
  CERT_STORE_PROV_EXTERNAL_FLAG          = $1;
  {$EXTERNALSYM CERT_STORE_PROV_EXTERNAL_FLAG}

// The open callback sets the following flag for a successful delete.
// When set, the close callback isn't called.
const
  CERT_STORE_PROV_DELETED_FLAG           = $2;
  {$EXTERNALSYM CERT_STORE_PROV_DELETED_FLAG}

// The open callback sets the following flag if it doesn't persist store
// changes.
const
  CERT_STORE_PROV_NO_PERSIST_FLAG        = $4;
  {$EXTERNALSYM CERT_STORE_PROV_NO_PERSIST_FLAG}

// The open callback sets the following flag if the contexts are persisted
// to a system store.
const
  CERT_STORE_PROV_SYSTEM_STORE_FLAG      = $8;
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_STORE_FLAG}

// The open callback sets the following flag if the contexts are persisted
// to a LocalMachine system store.
const
  CERT_STORE_PROV_LM_SYSTEM_STORE_FLAG   = $10;
  {$EXTERNALSYM CERT_STORE_PROV_LM_SYSTEM_STORE_FLAG}

// The open callback sets the following flag if the contexts are persisted
// to a GroupPolicy system store.
const
  CERT_STORE_PROV_GP_SYSTEM_STORE_FLAG   = $20;
  {$EXTERNALSYM CERT_STORE_PROV_GP_SYSTEM_STORE_FLAG}

// The open callback sets the following flag if the contexts are from
// a Shared User physical store.
const
  CERT_STORE_PROV_SHARED_USER_FLAG       = $40;
  {$EXTERNALSYM CERT_STORE_PROV_SHARED_USER_FLAG}

// Indices into the store provider's array of callback functions.
//
// The provider can implement any subset of the following functions. It
// sets pStoreProvInfo->cStoreProvFunc to the last index + 1 and any
// preceding not implemented functions to NULL.
const
  CERT_STORE_PROV_CLOSE_FUNC             = 0;
  {$EXTERNALSYM CERT_STORE_PROV_CLOSE_FUNC}
  CERT_STORE_PROV_READ_CERT_FUNC         = 1;
  {$EXTERNALSYM CERT_STORE_PROV_READ_CERT_FUNC}
  CERT_STORE_PROV_WRITE_CERT_FUNC        = 2;
  {$EXTERNALSYM CERT_STORE_PROV_WRITE_CERT_FUNC}
  CERT_STORE_PROV_DELETE_CERT_FUNC       = 3;
  {$EXTERNALSYM CERT_STORE_PROV_DELETE_CERT_FUNC}
  CERT_STORE_PROV_SET_CERT_PROPERTY_FUNC = 4;
  {$EXTERNALSYM CERT_STORE_PROV_SET_CERT_PROPERTY_FUNC}
  CERT_STORE_PROV_READ_CRL_FUNC          = 5;
  {$EXTERNALSYM CERT_STORE_PROV_READ_CRL_FUNC}
  CERT_STORE_PROV_WRITE_CRL_FUNC         = 6;
  {$EXTERNALSYM CERT_STORE_PROV_WRITE_CRL_FUNC}
  CERT_STORE_PROV_DELETE_CRL_FUNC        = 7;
  {$EXTERNALSYM CERT_STORE_PROV_DELETE_CRL_FUNC}
  CERT_STORE_PROV_SET_CRL_PROPERTY_FUNC  = 8;
  {$EXTERNALSYM CERT_STORE_PROV_SET_CRL_PROPERTY_FUNC}
  CERT_STORE_PROV_READ_CTL_FUNC          = 9;
  {$EXTERNALSYM CERT_STORE_PROV_READ_CTL_FUNC}
  CERT_STORE_PROV_WRITE_CTL_FUNC         = 10;
  {$EXTERNALSYM CERT_STORE_PROV_WRITE_CTL_FUNC}
  CERT_STORE_PROV_DELETE_CTL_FUNC        = 11;
  {$EXTERNALSYM CERT_STORE_PROV_DELETE_CTL_FUNC}
  CERT_STORE_PROV_SET_CTL_PROPERTY_FUNC  = 12;
  {$EXTERNALSYM CERT_STORE_PROV_SET_CTL_PROPERTY_FUNC}
  CERT_STORE_PROV_CONTROL_FUNC           = 13;
  {$EXTERNALSYM CERT_STORE_PROV_CONTROL_FUNC}
  CERT_STORE_PROV_FIND_CERT_FUNC         = 14;
  {$EXTERNALSYM CERT_STORE_PROV_FIND_CERT_FUNC}
  CERT_STORE_PROV_FREE_FIND_CERT_FUNC    = 15;
  {$EXTERNALSYM CERT_STORE_PROV_FREE_FIND_CERT_FUNC}
  CERT_STORE_PROV_GET_CERT_PROPERTY_FUNC = 16;
  {$EXTERNALSYM CERT_STORE_PROV_GET_CERT_PROPERTY_FUNC}
  CERT_STORE_PROV_FIND_CRL_FUNC          = 17;
  {$EXTERNALSYM CERT_STORE_PROV_FIND_CRL_FUNC}
  CERT_STORE_PROV_FREE_FIND_CRL_FUNC     = 18;
  {$EXTERNALSYM CERT_STORE_PROV_FREE_FIND_CRL_FUNC}
  CERT_STORE_PROV_GET_CRL_PROPERTY_FUNC  = 19;
  {$EXTERNALSYM CERT_STORE_PROV_GET_CRL_PROPERTY_FUNC}
  CERT_STORE_PROV_FIND_CTL_FUNC          = 20;
  {$EXTERNALSYM CERT_STORE_PROV_FIND_CTL_FUNC}
  CERT_STORE_PROV_FREE_FIND_CTL_FUNC     = 21;
  {$EXTERNALSYM CERT_STORE_PROV_FREE_FIND_CTL_FUNC}
  CERT_STORE_PROV_GET_CTL_PROPERTY_FUNC  = 22;
  {$EXTERNALSYM CERT_STORE_PROV_GET_CTL_PROPERTY_FUNC}


// Called by CertCloseStore when the store's reference count is
// decremented to 0.
type
  PFN_CERT_STORE_PROV_CLOSE = procedure(
    hStoreProv: HCERTSTOREPROV;
    dwFlags: DWORD); winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_CLOSE}
  TFnCertStoreProvClose = PFN_CERT_STORE_PROV_CLOSE;

// Currently not called directly by the store APIs. However, may be exported
// to support other providers based on it.
//
// Reads the provider's copy of the certificate context. If it exists,
// creates a new certificate context.
type
  PFN_CERT_STORE_PROV_READ_CERT = function(
    hStoreProv: HCERTSTOREPROV;
    pStoreCertContext: PCertContext;
    dwFlags: DWORD;
    out ppProvCertContext: PCertContext): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_READ_CERT}
  TFnCertStoreProvReadCert = PFN_CERT_STORE_PROV_READ_CERT;

const
  CERT_STORE_PROV_WRITE_ADD_FLAG     = $1;
  {$EXTERNALSYM CERT_STORE_PROV_WRITE_ADD_FLAG}

// Called by CertAddEncodedCertificateToStore,
// CertAddCertificateContextToStore or CertAddSerializedElementToStore before
// adding to the store. The CERT_STORE_PROV_WRITE_ADD_FLAG is set. In
// addition to the encoded certificate, the added pCertContext might also
// have properties.
//
// Returns TRUE if its OK to update the the store.
type
  PFN_CERT_STORE_PROV_WRITE_CERT = function(
    hStoreProv: HCERTSTOREPROV;
    pCertContext: PCertContext;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_WRITE_CERT}
  TFnCertStoreProvWriteCert = PFN_CERT_STORE_PROV_WRITE_CERT;

// Called by CertDeleteCertificateFromStore before deleting from the
// store.
//
// Returns TRUE if its OK to delete from the store.
type
  PFN_CERT_STORE_PROV_DELETE_CERT = function(
    hStoreProv: HCERTSTOREPROV;
    pCertContext: PCertContext;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_DELETE_CERT}
  TFnCertStoreProvDeleteCert = PFN_CERT_STORE_PROV_DELETE_CERT;

// Called by CertSetCertificateContextProperty before setting the
// certificate's property. Also called by CertGetCertificateContextProperty,
// when getting a hash property that needs to be created and then persisted
// via the set.
//
// Upon input, the property hasn't been set for the pCertContext parameter.
//
// Returns TRUE if its OK to set the property.
type
  PFN_CERT_STORE_PROV_SET_CERT_PROPERTY = function(
    hStoreProv: HCERTSTOREPROV;
    pCertContext: PCertContext;
    dwPropId: DWORD;
    dwFlags: DWORD;
    pvData: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_SET_CERT_PROPERTY}
  TFnCertStoreProvSetCertProperty = PFN_CERT_STORE_PROV_SET_CERT_PROPERTY;

// Currently not called directly by the store APIs. However, may be exported
// to support other providers based on it.
//
// Reads the provider's copy of the CRL context. If it exists,
// creates a new CRL context.
type
  PFN_CERT_STORE_PROV_READ_CRL = function(
    hStoreProv: HCERTSTOREPROV;
    pStoreCrlContext: PCRLContext;
    dwFlags: DWORD;
    out ppProvCrlContext: PCRLContext): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_READ_CRL}
  TFnCertStoreProvReadCRL = PFN_CERT_STORE_PROV_READ_CRL;

// Called by CertAddEncodedCRLToStore,
// CertAddCRLContextToStore or CertAddSerializedElementToStore before
// adding to the store. The CERT_STORE_PROV_WRITE_ADD_FLAG is set. In
// addition to the encoded CRL, the added pCertContext might also
// have properties.
//
// Returns TRUE if its OK to update the the store.
type
  PFN_CERT_STORE_PROV_WRITE_CRL = function(
    hStoreProv: HCERTSTOREPROV;
    pCrlContext: PCRLContext;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_WRITE_CRL}
  TFnCertStoreProvWriteCRL = PFN_CERT_STORE_PROV_WRITE_CRL;

// Called by CertDeleteCRLFromStore before deleting from the store.
//
// Returns TRUE if its OK to delete from the store.
type
  PFN_CERT_STORE_PROV_DELETE_CRL = function(
    hStoreProv: HCERTSTOREPROV;
    pCrlContext: PCRLContext;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_DELETE_CRL}
  TFnCertStoreProvDeleteCRL = PFN_CERT_STORE_PROV_DELETE_CRL;

// Called by CertSetCRLContextProperty before setting the
// CRL's property. Also called by CertGetCRLContextProperty,
// when getting a hash property that needs to be created and then persisted
// via the set.
//
// Upon input, the property hasn't been set for the pCrlContext parameter.
//
// Returns TRUE if its OK to set the property.
type
  PFN_CERT_STORE_PROV_SET_CRL_PROPERTY = function(
    hStoreProv: HCERTSTOREPROV;
    pCrlContext: PCRLContext;
    dwPropId: DWORD;
    dwFlags: DWORD;
    pvData: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_SET_CRL_PROPERTY}
  TFnCertStoreProvSetCRLProperty = PFN_CERT_STORE_PROV_SET_CRL_PROPERTY;

// Currently not called directly by the store APIs. However, may be exported
// to support other providers based on it.
//
// Reads the provider's copy of the CTL context. If it exists,
// creates a new CTL context.
type
  PFN_CERT_STORE_PROV_READ_CTL = function(
    hStoreProv: HCERTSTOREPROV;
    pStoreCtlContext: PCTLContext;
    dwFlags: DWORD;
    out ppProvCtlContext: PCTLContext): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_READ_CTL}
  TFnCertStoreProvReadCTL = PFN_CERT_STORE_PROV_READ_CTL;

// Called by CertAddEncodedCTLToStore,
// CertAddCTLContextToStore or CertAddSerializedElementToStore before
// adding to the store. The CERT_STORE_PROV_WRITE_ADD_FLAG is set. In
// addition to the encoded CTL, the added pCertContext might also
// have properties.
//
// Returns TRUE if its OK to update the the store.
type
  PFN_CERT_STORE_PROV_WRITE_CTL = function(
    hStoreProv: HCERTSTOREPROV;
    pCtlContext: PCTLContext;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_WRITE_CTL}
  TFnCertStoreProvWriteCTL = PFN_CERT_STORE_PROV_WRITE_CTL;

// Called by CertDeleteCTLFromStore before deleting from the store.
//
// Returns TRUE if its OK to delete from the store.
type
  PFN_CERT_STORE_PROV_DELETE_CTL = function(
    hStoreProv: HCERTSTOREPROV;
    pCtlContext: PCTLContext;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_DELETE_CTL}
  TFnCertStoreProvDeleteCTL = PFN_CERT_STORE_PROV_DELETE_CTL;

// Called by CertSetCTLContextProperty before setting the
// CTL's property. Also called by CertGetCTLContextProperty,
// when getting a hash property that needs to be created and then persisted
// via the set.
//
// Upon input, the property hasn't been set for the pCtlContext parameter.
//
// Returns TRUE if its OK to set the property.
type
  PFN_CERT_STORE_PROV_SET_CTL_PROPERTY = function(
    hStoreProv: HCERTSTOREPROV;
    pCtlContext: PCTLContext;
    dwPropId: DWORD;
    dwFlags: DWORD;
    pvData: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_SET_CTL_PROPERTY}
  TFnCertStoreProvSetCTLProperty = PFN_CERT_STORE_PROV_SET_CTL_PROPERTY;

type
  PFN_CERT_STORE_PROV_CONTROL = function(
    hStoreProv: HCERTSTOREPROV;
    dwFlags: DWORD;
    dwCtrlType: DWORD;
    pvCtrlPara: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_CONTROL}
  TFnCertStoreProvControl = PFN_CERT_STORE_PROV_CONTROL;

type
  PCertStoreProvFindInfo = ^TCertStoreProvFindInfo;
  _CERT_STORE_PROV_FIND_INFO = record
    cbSize: DWORD;
    dwMsgAndCertEncodingType: DWORD;
    dwFindFlags: DWORD;
    dwFindType: DWORD;
    pvFindPara: Pointer;
  end;
  {$EXTERNALSYM _CERT_STORE_PROV_FIND_INFO}
  CERT_STORE_PROV_FIND_INFO = _CERT_STORE_PROV_FIND_INFO;
  {$EXTERNALSYM CERT_STORE_PROV_FIND_INFO}
  TCertStoreProvFindInfo = _CERT_STORE_PROV_FIND_INFO;
  PCERT_STORE_PROV_FIND_INFO = PCertStoreProvFindInfo;
  {$EXTERNALSYM PCERT_STORE_PROV_FIND_INFO}

  CCERT_STORE_PROV_FIND_INFO = _CERT_STORE_PROV_FIND_INFO;
  {$EXTERNALSYM CCERT_STORE_PROV_FIND_INFO}
  PCCERT_STORE_PROV_FIND_INFO = PCertStoreProvFindInfo;
  {$EXTERNALSYM PCCERT_STORE_PROV_FIND_INFO}

type
  PFN_CERT_STORE_PROV_FIND_CERT = function(
    hStoreProv: HCERTSTOREPROV;
    pFindInfo: PCertStoreProvFindInfo;
    pPrevCertContext: PCertContext;
    dwFlags: DWORD;
    out ppvStoreProvFindInfo: Pointer;
    out ppProvCertContext: PCertContext): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_FIND_CERT}
  TFnCertStoreProvFindCert = PFN_CERT_STORE_PROV_FIND_CERT;

type
  PFN_CERT_STORE_PROV_FREE_FIND_CERT = function(
    hStoreProv: HCERTSTOREPROV;
    pCertContext: PCertContext;
    pvStoreProvFindInfo: Pointer;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_FREE_FIND_CERT}
  TFnCertStoreProvFreeFindCert = PFN_CERT_STORE_PROV_FREE_FIND_CERT;

type
  PFN_CERT_STORE_PROV_GET_CERT_PROPERTY = function(
    hStoreProv: HCERTSTOREPROV;
    pCertContext: PCertContext;
    dwPropId: DWORD;
    dwFlags: DWORD;
    pvData: Pointer;
    var pcbData: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_GET_CERT_PROPERTY}
  TFnCertStoreProvGetCertProperty = PFN_CERT_STORE_PROV_GET_CERT_PROPERTY;

type
  PFN_CERT_STORE_PROV_FIND_CRL = function(
    hStoreProv: HCERTSTOREPROV;
    pFindInfo: PCertStoreProvFindInfo;
    pPrevCrlContext: PCRLContext;
    dwFlags: DWORD;
    out ppvStoreProvFindInfo: Pointer;
    out ppProvCrlContext: PCRLContext): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_FIND_CRL}
  TFnCertStoreProvFindCRL = PFN_CERT_STORE_PROV_FIND_CRL;

type
  PFN_CERT_STORE_PROV_FREE_FIND_CRL = function(
    hStoreProv: HCERTSTOREPROV;
    pCrlContext: PCRLContext;
    pvStoreProvFindInfo: Pointer;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_FREE_FIND_CRL}
  TFnCertStoreProvFreeFindCRL = PFN_CERT_STORE_PROV_FREE_FIND_CRL;

type
  PFN_CERT_STORE_PROV_GET_CRL_PROPERTY = function(
    hStoreProv: HCERTSTOREPROV;
    pCrlContext: PCRLContext;
    dwPropId: DWORD;
    dwFlags: DWORD;
    pvData: Pointer;
    var pcbData: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_GET_CRL_PROPERTY}
  TFnCertStoreProvGetCRLProperty = PFN_CERT_STORE_PROV_GET_CRL_PROPERTY;

type
  PFN_CERT_STORE_PROV_FIND_CTL = function(
    hStoreProv: HCERTSTOREPROV;
    pFindInfo: PCertStoreProvFindInfo;
    pPrevCtlContext: PCTLContext;
    dwFlags: DWORD;
    out ppvStoreProvFindInfo: Pointer;
    out ppProvCtlContext: PCTLContext): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_FIND_CTL}
  TFnCertStoreProvFindCTL = PFN_CERT_STORE_PROV_FIND_CTL;

type
  PFN_CERT_STORE_PROV_FREE_FIND_CTL = function(
    hStoreProv: HCERTSTOREPROV;
    pCtlContext: PCTLContext;
    pvStoreProvFindInfo: Pointer;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_FREE_FIND_CTL}
  TFnCertStoreProvFreeFindCTL = PFN_CERT_STORE_PROV_FREE_FIND_CTL;

type
  PFN_CERT_STORE_PROV_GET_CTL_PROPERTY = function(
    hStoreProv: HCERTSTOREPROV;
    pCtlContext: PCTLContext;
    dwPropId: DWORD;
    dwFlags: DWORD;
    pvData: Pointer;
    var pcbData: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_STORE_PROV_GET_CTL_PROPERTY}
  TFnCertStoreProvGetCTLProperty = PFN_CERT_STORE_PROV_GET_CTL_PROPERTY;

//+-------------------------------------------------------------------------
//  Duplicate a cert store handle
//--------------------------------------------------------------------------
function CertDuplicateStore(
  hCertStore: HCERTSTORE): HCERTSTORE; winapi;
{$EXTERNALSYM CertDuplicateStore}

const
  CERT_STORE_SAVE_AS_STORE       = 1;
  {$EXTERNALSYM CERT_STORE_SAVE_AS_STORE}
  CERT_STORE_SAVE_AS_PKCS7       = 2;
  {$EXTERNALSYM CERT_STORE_SAVE_AS_PKCS7}
  CERT_STORE_SAVE_AS_PKCS12      = 3;
  {$EXTERNALSYM CERT_STORE_SAVE_AS_PKCS12}

  CERT_STORE_SAVE_TO_FILE        = 1;
  {$EXTERNALSYM CERT_STORE_SAVE_TO_FILE}
  CERT_STORE_SAVE_TO_MEMORY      = 2;
  {$EXTERNALSYM CERT_STORE_SAVE_TO_MEMORY}
  CERT_STORE_SAVE_TO_FILENAME_A  = 3;
  {$EXTERNALSYM CERT_STORE_SAVE_TO_FILENAME_A}
  CERT_STORE_SAVE_TO_FILENAME_W  = 4;
  {$EXTERNALSYM CERT_STORE_SAVE_TO_FILENAME_W}
  CERT_STORE_SAVE_TO_FILENAME    = CERT_STORE_SAVE_TO_FILENAME_W;
  {$EXTERNALSYM CERT_STORE_SAVE_TO_FILENAME}

//+-------------------------------------------------------------------------
//  Save the cert store. Extended version with lots of options.
//
//  According to the dwSaveAs parameter, the store can be saved as a
//  serialized store (CERT_STORE_SAVE_AS_STORE) containing properties in
//  addition to encoded certificates, CRLs and CTLs or the store can be saved
//  as a PKCS #7 signed message (CERT_STORE_SAVE_AS_PKCS7) which doesn't
//  include the properties or CTLs.
//
//  Note, the CERT_KEY_CONTEXT_PROP_ID property (and its
//  CERT_KEY_PROV_HANDLE_PROP_ID or CERT_KEY_SPEC_PROP_ID) isn't saved into
//  a serialized store.
//
//  For CERT_STORE_SAVE_AS_PKCS7, the dwEncodingType specifies the message
//  encoding type. The dwEncodingType parameter isn't used for
//  CERT_STORE_SAVE_AS_STORE.
//
//  The dwFlags parameter currently isn't used and should be set to 0.
//
//  The dwSaveTo and pvSaveToPara parameters specify where to save the
//  store as follows:
//    CERT_STORE_SAVE_TO_FILE:
//      Saves to the specified file. The file's handle is passed in
//      pvSaveToPara. Given,
//          HANDLE hFile; pvSaveToPara = (void *) hFile;
//
//      For a successful save, the file pointer is positioned after the
//      last write.
//
//    CERT_STORE_SAVE_TO_MEMORY:
//      Saves to the specified memory blob. The pointer to
//      the memory blob is passed in pvSaveToPara. Given,
//          CRYPT_DATA_BLOB SaveBlob; pvSaveToPara = (void *) &SaveBlob;
//      Upon entry, the SaveBlob's pbData and cbData need to be initialized.
//      Upon return, cbData is updated with the actual length.
//      For a length only calculation, pbData should be set to NULL. If
//      pbData is non-NULL and cbData isn't large enough, FALSE is returned
//      with a last error of ERRROR_MORE_DATA.
//
//    CERT_STORE_SAVE_TO_FILENAME_A:
//    CERT_STORE_SAVE_TO_FILENAME_W:
//    CERT_STORE_SAVE_TO_FILENAME:
//      Opens the file and saves to it. The filename is passed in pvSaveToPara.
//      The filename is UNICODE for the "_W" option and ASCII for the "_A"
//      option. For "_W": given,
//          LPCWSTR pwszFilename; pvSaveToPara = (void *) pwszFilename;
//      For "_A": given,
//          LPCSTR pszFilename; pvSaveToPara = (void *) pszFilename;
//
//      Note, the default (without "_A" or "_W") is UNICODE.
//
//--------------------------------------------------------------------------
function CertSaveStore(
  hCertStore: HCERTSTORE;
  dwEncodingType: DWORD;
  dwSaveAs: DWORD;
  dwSaveTo: DWORD;
  pvSaveToPara: Pointer;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CertSaveStore}

//+-------------------------------------------------------------------------
//  Certificate Store close flags
//--------------------------------------------------------------------------
const
  CERT_CLOSE_STORE_FORCE_FLAG        = $00000001;
  {$EXTERNALSYM CERT_CLOSE_STORE_FORCE_FLAG}
  CERT_CLOSE_STORE_CHECK_FLAG        = $00000002;
  {$EXTERNALSYM CERT_CLOSE_STORE_CHECK_FLAG}

//+-------------------------------------------------------------------------
//  Close a cert store handle.
//
//  There needs to be a corresponding close for each open and duplicate.
//
//  Even on the final close, the cert store isn't freed until all of its
//  certificate and CRL contexts have also been freed.
//
//  On the final close, the hCryptProv passed to CertStoreOpen is
//  CryptReleaseContext'ed.
//
//  To force the closure of the store with all of its memory freed, set the
//  CERT_STORE_CLOSE_FORCE_FLAG. This flag should be set when the caller does
//  its own reference counting and wants everything to vanish.
//
//  To check if all the store's certificates and CRLs have been freed and that
//  this is the last CertCloseStore, set the CERT_CLOSE_STORE_CHECK_FLAG. If
//  set and certs, CRLs or stores still need to be freed/closed, FALSE is
//  returned with LastError set to CRYPT_E_PENDING_CLOSE. Note, for FALSE,
//  the store is still closed. This is a diagnostic flag.
//
//  LastError is preserved unless CERT_CLOSE_STORE_CHECK_FLAG is set and FALSE
//  is returned.
//--------------------------------------------------------------------------
function CertCloseStore(
  hCertStore: HCERTSTORE;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CertCloseStore}

//+-------------------------------------------------------------------------
//  Get the subject certificate context uniquely identified by its Issuer and
//  SerialNumber from the store.
//
//  If the certificate isn't found, NULL is returned. Otherwise, a pointer to
//  a read only CERT_CONTEXT is returned. CERT_CONTEXT must be freed by calling
//  CertFreeCertificateContext. CertDuplicateCertificateContext can be called to make a
//  duplicate.
//
//  The returned certificate might not be valid. Normally, it would be
//  verified when getting its issuer certificate (CertGetIssuerCertificateFromStore).
//--------------------------------------------------------------------------
function CertGetSubjectCertificateFromStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  pCertId: PCertInfo             // Only the Issuer and SerialNumber
                                 // fields are used
  ): PCertContext; winapi;
{$EXTERNALSYM CertGetSubjectCertificateFromStore}


//+-------------------------------------------------------------------------
//  Enumerate the certificate contexts in the store.
//
//  If a certificate isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CERT_CONTEXT is returned. CERT_CONTEXT
//  must be freed by calling CertFreeCertificateContext or is freed when passed as the
//  pPrevCertContext on a subsequent call. CertDuplicateCertificateContext
//  can be called to make a duplicate.
//
//  pPrevCertContext MUST BE NULL to enumerate the first
//  certificate in the store. Successive certificates are enumerated by setting
//  pPrevCertContext to the CERT_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevCertContext is always CertFreeCertificateContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertEnumCertificatesInStore(
  hCertStore: HCERTSTORE;
  pPrevCertContext: PCertContext): PCertContext; winapi;
{$EXTERNALSYM CertEnumCertificatesInStore}

//+-------------------------------------------------------------------------
//  Find the first or next certificate context in the store.
//
//  The certificate is found according to the dwFindType and its pvFindPara.
//  See below for a list of the find types and its parameters.
//
//  Currently dwFindFlags is only used for CERT_FIND_SUBJECT_ATTR,
//  CERT_FIND_ISSUER_ATTR or CERT_FIND_CTL_USAGE. Otherwise, must be set to 0.
//
//  Usage of dwCertEncodingType depends on the dwFindType.
//
//  If the first or next certificate isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CERT_CONTEXT is returned. CERT_CONTEXT
//  must be freed by calling CertFreeCertificateContext or is freed when passed as the
//  pPrevCertContext on a subsequent call. CertDuplicateCertificateContext
//  can be called to make a duplicate.
//
//  pPrevCertContext MUST BE NULL on the first
//  call to find the certificate. To find the next certificate, the
//  pPrevCertContext is set to the CERT_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevCertContext is always CertFreeCertificateContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertFindCertificateInStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  dwFindFlags: DWORD;
  dwFindType: DWORD;
  pvFindPara: Pointer;
  pPrevCertContext: PCertContext): PCertContext; winapi;
{$EXTERNALSYM CertFindCertificateInStore}

//+-------------------------------------------------------------------------
// Certificate comparison functions
//--------------------------------------------------------------------------
const
  CERT_COMPARE_MASK           = $FFFF;
  {$EXTERNALSYM CERT_COMPARE_MASK}
  CERT_COMPARE_SHIFT          = 16;
  {$EXTERNALSYM CERT_COMPARE_SHIFT}
  CERT_COMPARE_ANY            = 0;
  {$EXTERNALSYM CERT_COMPARE_ANY}
  CERT_COMPARE_SHA1_HASH      = 1;
  {$EXTERNALSYM CERT_COMPARE_SHA1_HASH}
  CERT_COMPARE_NAME           = 2;
  {$EXTERNALSYM CERT_COMPARE_NAME}
  CERT_COMPARE_ATTR           = 3;
  {$EXTERNALSYM CERT_COMPARE_ATTR}
  CERT_COMPARE_MD5_HASH       = 4;
  {$EXTERNALSYM CERT_COMPARE_MD5_HASH}
  CERT_COMPARE_PROPERTY       = 5;
  {$EXTERNALSYM CERT_COMPARE_PROPERTY}
  CERT_COMPARE_PUBLIC_KEY     = 6;
  {$EXTERNALSYM CERT_COMPARE_PUBLIC_KEY}
  CERT_COMPARE_HASH           = CERT_COMPARE_SHA1_HASH;
  {$EXTERNALSYM CERT_COMPARE_HASH}
  CERT_COMPARE_NAME_STR_A     = 7;
  {$EXTERNALSYM CERT_COMPARE_NAME_STR_A}
  CERT_COMPARE_NAME_STR_W     = 8;
  {$EXTERNALSYM CERT_COMPARE_NAME_STR_W}
  CERT_COMPARE_KEY_SPEC       = 9;
  {$EXTERNALSYM CERT_COMPARE_KEY_SPEC}
  CERT_COMPARE_ENHKEY_USAGE   = 10;
  {$EXTERNALSYM CERT_COMPARE_ENHKEY_USAGE}
  CERT_COMPARE_CTL_USAGE      = CERT_COMPARE_ENHKEY_USAGE;
  {$EXTERNALSYM CERT_COMPARE_CTL_USAGE}
  CERT_COMPARE_SUBJECT_CERT   = 11;
  {$EXTERNALSYM CERT_COMPARE_SUBJECT_CERT}
  CERT_COMPARE_ISSUER_OF      = 12;
  {$EXTERNALSYM CERT_COMPARE_ISSUER_OF}
  CERT_COMPARE_EXISTING       = 13;
  {$EXTERNALSYM CERT_COMPARE_EXISTING}
  CERT_COMPARE_SIGNATURE_HASH = 14;
  {$EXTERNALSYM CERT_COMPARE_SIGNATURE_HASH}
  CERT_COMPARE_KEY_IDENTIFIER = 15;
  {$EXTERNALSYM CERT_COMPARE_KEY_IDENTIFIER}
  CERT_COMPARE_CERT_ID        = 16;
  {$EXTERNALSYM CERT_COMPARE_CERT_ID}
  CERT_COMPARE_CROSS_CERT_DIST_POINTS = 17;
  {$EXTERNALSYM CERT_COMPARE_CROSS_CERT_DIST_POINTS}

  CERT_COMPARE_PUBKEY_MD5_HASH = 18;
  {$EXTERNALSYM CERT_COMPARE_PUBKEY_MD5_HASH}

  CERT_COMPARE_SUBJECT_INFO_ACCESS = 19;
  {$EXTERNALSYM CERT_COMPARE_SUBJECT_INFO_ACCESS}
  CERT_COMPARE_HASH_STR       = 20;
  {$EXTERNALSYM CERT_COMPARE_HASH_STR}
  CERT_COMPARE_HAS_PRIVATE_KEY = 21;
  {$EXTERNALSYM CERT_COMPARE_HAS_PRIVATE_KEY}

//+-------------------------------------------------------------------------
//  dwFindType
//
//  The dwFindType definition consists of two components:
//   - comparison function
//   - certificate information flag
//--------------------------------------------------------------------------
const
  CERT_FIND_ANY           = (CERT_COMPARE_ANY shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_ANY}
  CERT_FIND_SHA1_HASH     = (CERT_COMPARE_SHA1_HASH shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_SHA1_HASH}
  CERT_FIND_MD5_HASH      = (CERT_COMPARE_MD5_HASH shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_MD5_HASH}
  CERT_FIND_SIGNATURE_HASH = (CERT_COMPARE_SIGNATURE_HASH shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_SIGNATURE_HASH}
  CERT_FIND_KEY_IDENTIFIER = (CERT_COMPARE_KEY_IDENTIFIER shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_KEY_IDENTIFIER}
  CERT_FIND_HASH          = CERT_FIND_SHA1_HASH;
  {$EXTERNALSYM CERT_FIND_HASH}
  CERT_FIND_PROPERTY      = (CERT_COMPARE_PROPERTY shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_PROPERTY}
  CERT_FIND_PUBLIC_KEY    = (CERT_COMPARE_PUBLIC_KEY shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_PUBLIC_KEY}
  CERT_FIND_SUBJECT_NAME  = (CERT_COMPARE_NAME shl CERT_COMPARE_SHIFT or CERT_INFO_SUBJECT_FLAG);
  {$EXTERNALSYM CERT_FIND_SUBJECT_NAME}
  CERT_FIND_SUBJECT_ATTR  = (CERT_COMPARE_ATTR shl CERT_COMPARE_SHIFT or CERT_INFO_SUBJECT_FLAG);
  {$EXTERNALSYM CERT_FIND_SUBJECT_ATTR}
  CERT_FIND_ISSUER_NAME   = (CERT_COMPARE_NAME shl CERT_COMPARE_SHIFT or CERT_INFO_ISSUER_FLAG);
  {$EXTERNALSYM CERT_FIND_ISSUER_NAME}
  CERT_FIND_ISSUER_ATTR   = (CERT_COMPARE_ATTR shl CERT_COMPARE_SHIFT or CERT_INFO_ISSUER_FLAG);
  {$EXTERNALSYM CERT_FIND_ISSUER_ATTR}
  CERT_FIND_SUBJECT_STR_A = (CERT_COMPARE_NAME_STR_A shl CERT_COMPARE_SHIFT or CERT_INFO_SUBJECT_FLAG);
  {$EXTERNALSYM CERT_FIND_SUBJECT_STR_A}
  CERT_FIND_SUBJECT_STR_W = (CERT_COMPARE_NAME_STR_W shl CERT_COMPARE_SHIFT or CERT_INFO_SUBJECT_FLAG);
  {$EXTERNALSYM CERT_FIND_SUBJECT_STR_W}
  CERT_FIND_SUBJECT_STR   = CERT_FIND_SUBJECT_STR_W;
  {$EXTERNALSYM CERT_FIND_SUBJECT_STR}
  CERT_FIND_ISSUER_STR_A  = (CERT_COMPARE_NAME_STR_A shl CERT_COMPARE_SHIFT or CERT_INFO_ISSUER_FLAG);
  {$EXTERNALSYM CERT_FIND_ISSUER_STR_A}
  CERT_FIND_ISSUER_STR_W  = (CERT_COMPARE_NAME_STR_W shl CERT_COMPARE_SHIFT or CERT_INFO_ISSUER_FLAG);
  {$EXTERNALSYM CERT_FIND_ISSUER_STR_W}
  CERT_FIND_ISSUER_STR    = CERT_FIND_ISSUER_STR_W;
  {$EXTERNALSYM CERT_FIND_ISSUER_STR}
  CERT_FIND_KEY_SPEC      = (CERT_COMPARE_KEY_SPEC shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_KEY_SPEC}
  CERT_FIND_ENHKEY_USAGE  = (CERT_COMPARE_ENHKEY_USAGE shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_ENHKEY_USAGE}
  CERT_FIND_CTL_USAGE     = CERT_FIND_ENHKEY_USAGE;
  {$EXTERNALSYM CERT_FIND_CTL_USAGE}

  CERT_FIND_SUBJECT_CERT  = (CERT_COMPARE_SUBJECT_CERT shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_SUBJECT_CERT}
  CERT_FIND_ISSUER_OF     = (CERT_COMPARE_ISSUER_OF shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_ISSUER_OF}
  CERT_FIND_EXISTING      = (CERT_COMPARE_EXISTING shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_EXISTING}
  CERT_FIND_CERT_ID       = (CERT_COMPARE_CERT_ID shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_CERT_ID}
  CERT_FIND_CROSS_CERT_DIST_POINTS = (CERT_COMPARE_CROSS_CERT_DIST_POINTS shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_CROSS_CERT_DIST_POINTS}


  CERT_FIND_PUBKEY_MD5_HASH = (CERT_COMPARE_PUBKEY_MD5_HASH shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_PUBKEY_MD5_HASH}

  CERT_FIND_SUBJECT_INFO_ACCESS = (CERT_COMPARE_SUBJECT_INFO_ACCESS shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_SUBJECT_INFO_ACCESS}

  CERT_FIND_HASH_STR      = (CERT_COMPARE_HASH_STR shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_HASH_STR}
  CERT_FIND_HAS_PRIVATE_KEY = (CERT_COMPARE_HAS_PRIVATE_KEY shl CERT_COMPARE_SHIFT);
  {$EXTERNALSYM CERT_FIND_HAS_PRIVATE_KEY}

//+-------------------------------------------------------------------------
//  CERT_FIND_ANY
//
//  Find any certificate.
//
//  pvFindPara isn't used.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_HASH
//
//  Find a certificate with the specified hash.
//
//  pvFindPara points to a CRYPT_HASH_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_KEY_IDENTIFIER
//
//  Find a certificate with the specified KeyIdentifier. Gets the
//  CERT_KEY_IDENTIFIER_PROP_ID property and compares with the input
//  CRYPT_HASH_BLOB.
//
//  pvFindPara points to a CRYPT_HASH_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_PROPERTY
//
//  Find a certificate having the specified property.
//
//  pvFindPara points to a DWORD containing the PROP_ID
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_PUBLIC_KEY
//
//  Find a certificate matching the specified public key.
//
//  pvFindPara points to a CERT_PUBLIC_KEY_INFO containing the public key
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_SUBJECT_NAME
//  CERT_FIND_ISSUER_NAME
//
//  Find a certificate with the specified subject/issuer name. Does an exact
//  match of the entire name.
//
//  Restricts search to certificates matching the dwCertEncodingType.
//
//  pvFindPara points to a CERT_NAME_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_SUBJECT_ATTR
//  CERT_FIND_ISSUER_ATTR
//
//  Find a certificate with the specified subject/issuer attributes.
//
//  Compares the attributes in the subject/issuer name with the
//  Relative Distinguished Name's (CERT_RDN) array of attributes specified in
//  pvFindPara. The comparison iterates through the CERT_RDN attributes and looks
//  for an attribute match in any of the subject/issuer's RDNs.
//
//  The CERT_RDN_ATTR fields can have the following special values:
//    pszObjId == NULL              - ignore the attribute object identifier
//    dwValueType == RDN_ANY_TYPE   - ignore the value type
//    Value.pbData == NULL          - match any value
//
//  CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG should be set in dwFindFlags to do
//  a case insensitive match. Otherwise, defaults to an exact, case sensitive
//  match.
//
//  CERT_UNICODE_IS_RDN_ATTRS_FLAG should be set in dwFindFlags if the RDN was
//  initialized with unicode strings as for
//  CryptEncodeObject(X509_UNICODE_NAME).
//
//  Restricts search to certificates matching the dwCertEncodingType.
//
//  pvFindPara points to a CERT_RDN (defined in wincert.h).
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_SUBJECT_STR_A
//  CERT_FIND_SUBJECT_STR_W | CERT_FIND_SUBJECT_STR
//  CERT_FIND_ISSUER_STR_A
//  CERT_FIND_ISSUER_STR_W  | CERT_FIND_ISSUER_STR
//
//  Find a certificate containing the specified subject/issuer name string.
//
//  First, the certificate's subject/issuer is converted to a name string
//  via CertNameToStrA/CertNameToStrW(CERT_SIMPLE_NAME_STR). Then, a
//  case insensitive substring within string match is performed.
//
//  Restricts search to certificates matching the dwCertEncodingType.
//
//  For *_STR_A, pvFindPara points to a null terminated character string.
//  For *_STR_W, pvFindPara points to a null terminated wide character string.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_KEY_SPEC
//
//  Find a certificate having a CERT_KEY_SPEC_PROP_ID property matching
//  the specified KeySpec.
//
//  pvFindPara points to a DWORD containing the KeySpec.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_ENHKEY_USAGE
//
//  Find a certificate having the szOID_ENHANCED_KEY_USAGE extension or
//  the CERT_ENHKEY_USAGE_PROP_ID and matching the specified pszUsageIdentifers.
//
//  pvFindPara points to a CERT_ENHKEY_USAGE data structure. If pvFindPara
//  is NULL or CERT_ENHKEY_USAGE's cUsageIdentifier is 0, then, matches any
//  certificate having enhanced key usage.
//
//  If the CERT_FIND_VALID_ENHKEY_USAGE_FLAG is set, then, only does a match
//  for certificates that are valid for the specified usages. By default,
//  the ceriticate must be valid for all usages. CERT_FIND_OR_ENHKEY_USAGE_FLAG
//  can be set, if the certificate only needs to be valid for one of the
//  specified usages. Note, CertGetValidUsages() is called to get the
//  certificate's list of valid usages. Only the CERT_FIND_OR_ENHKEY_USAGE_FLAG
//  is applicable when this flag is set.
//
//  The CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG can be set in dwFindFlags to
//  also match a certificate without either the extension or property.
//
//  If CERT_FIND_NO_ENHKEY_USAGE_FLAG is set in dwFindFlags, finds
//  certificates without the key usage extension or property. Setting this
//  flag takes precedence over pvFindPara being NULL.
//
//  If the CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG is set, then, only does a match
//  using the extension. If pvFindPara is NULL or cUsageIdentifier is set to
//  0, finds certificates having the extension. If
//  CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG is set, also matches a certificate
//  without the extension. If CERT_FIND_NO_ENHKEY_USAGE_FLAG is set, finds
//  certificates without the extension.
//
//  If the CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG is set, then, only does a match
//  using the property. If pvFindPara is NULL or cUsageIdentifier is set to
//  0, finds certificates having the property. If
//  CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG is set, also matches a certificate
//  without the property. If CERT_FIND_NO_ENHKEY_USAGE_FLAG is set, finds
//  certificates without the property.
//
//  If CERT_FIND_OR_ENHKEY_USAGE_FLAG is set, does an "OR" match of any of
//  the specified pszUsageIdentifiers. If not set, then, does an "AND" match
//  of all of the specified pszUsageIdentifiers.
//--------------------------------------------------------------------------
const
  CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG  = $1;
  {$EXTERNALSYM CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG}
  CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG  = $2;
  {$EXTERNALSYM CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG}
  CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG = $4;
  {$EXTERNALSYM CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG}
  CERT_FIND_NO_ENHKEY_USAGE_FLAG        = $8;
  {$EXTERNALSYM CERT_FIND_NO_ENHKEY_USAGE_FLAG}
  CERT_FIND_OR_ENHKEY_USAGE_FLAG        = $10;
  {$EXTERNALSYM CERT_FIND_OR_ENHKEY_USAGE_FLAG}
  CERT_FIND_VALID_ENHKEY_USAGE_FLAG     = $20;
  {$EXTERNALSYM CERT_FIND_VALID_ENHKEY_USAGE_FLAG}

  CERT_FIND_OPTIONAL_CTL_USAGE_FLAG  = CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG;
  {$EXTERNALSYM CERT_FIND_OPTIONAL_CTL_USAGE_FLAG}

  CERT_FIND_EXT_ONLY_CTL_USAGE_FLAG = CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG;
  {$EXTERNALSYM CERT_FIND_EXT_ONLY_CTL_USAGE_FLAG}

  CERT_FIND_PROP_ONLY_CTL_USAGE_FLAG = CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG;
  {$EXTERNALSYM CERT_FIND_PROP_ONLY_CTL_USAGE_FLAG}

  CERT_FIND_NO_CTL_USAGE_FLAG        = CERT_FIND_NO_ENHKEY_USAGE_FLAG;
  {$EXTERNALSYM CERT_FIND_NO_CTL_USAGE_FLAG}
  CERT_FIND_OR_CTL_USAGE_FLAG        = CERT_FIND_OR_ENHKEY_USAGE_FLAG;
  {$EXTERNALSYM CERT_FIND_OR_CTL_USAGE_FLAG}
  CERT_FIND_VALID_CTL_USAGE_FLAG     = CERT_FIND_VALID_ENHKEY_USAGE_FLAG;
  {$EXTERNALSYM CERT_FIND_VALID_CTL_USAGE_FLAG}

//+-------------------------------------------------------------------------
//  CERT_FIND_CERT_ID
//
//  Find a certificate with the specified CERT_ID.
//
//  pvFindPara points to a CERT_ID.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_CROSS_CERT_DIST_POINTS
//
//  Find a certificate having either a cross certificate distribution
//  point extension or property.
//
//  pvFindPara isn't used.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_SUBJECT_INFO_ACCESS
//
//  Find a certificate having either a SubjectInfoAccess extension or
//  property.
//
//  pvFindPara isn't used.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_FIND_HASH_STR
//
//  Find a certificate with the specified hash.
//
//  pvFindPara points to a null terminated wide character string, containing
//  40 hexadecimal digits that CryptStringToBinary(CRYPT_STRING_HEXRAW) can
//  convert to a 20 byte SHA1 CRYPT_HASH_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  Get the certificate context from the store for the first or next issuer
//  of the specified subject certificate. Perform the enabled
//  verification checks on the subject. (Note, the checks are on the subject
//  using the returned issuer certificate.)
//
//  If the first or next issuer certificate isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CERT_CONTEXT is returned. CERT_CONTEXT
//  must be freed by calling CertFreeCertificateContext or is freed when passed as the
//  pPrevIssuerContext on a subsequent call. CertDuplicateCertificateContext
//  can be called to make a duplicate.
//
//  For a self signed subject certificate, NULL is returned with LastError set
//  to CERT_STORE_SELF_SIGNED. The enabled verification checks are still done.
//
//  The pSubjectContext may have been obtained from this store, another store
//  or created by the caller application. When created by the caller, the
//  CertCreateCertificateContext function must have been called.
//
//  An issuer may have multiple certificates. This may occur when the validity
//  period is about to change. pPrevIssuerContext MUST BE NULL on the first
//  call to get the issuer. To get the next certificate for the issuer, the
//  pPrevIssuerContext is set to the CERT_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevIssuerContext is always CertFreeCertificateContext'ed by
//  this function, even for an error.
//
//  The following flags can be set in *pdwFlags to enable verification checks
//  on the subject certificate context:
//      CERT_STORE_SIGNATURE_FLAG     - use the public key in the returned
//                                      issuer certificate to verify the
//                                      signature on the subject certificate.
//                                      Note, if pSubjectContext->hCertStore ==
//                                      hCertStore, the store provider might
//                                      be able to eliminate a redo of
//                                      the signature verify.
//      CERT_STORE_TIME_VALIDITY_FLAG - get the current time and verify that
//                                      its within the subject certificate's
//                                      validity period
//      CERT_STORE_REVOCATION_FLAG    - check if the subject certificate is on
//                                      the issuer's revocation list
//
//  If an enabled verification check fails, then, its flag is set upon return.
//  If CERT_STORE_REVOCATION_FLAG was enabled and the issuer doesn't have a
//  CRL in the store, then, CERT_STORE_NO_CRL_FLAG is set in addition to
//  the CERT_STORE_REVOCATION_FLAG.
//
//  If CERT_STORE_SIGNATURE_FLAG or CERT_STORE_REVOCATION_FLAG is set, then,
//  CERT_STORE_NO_ISSUER_FLAG is set if it doesn't have an issuer certificate
//  in the store.
//
//  For a verification check failure, a pointer to the issuer's CERT_CONTEXT
//  is still returned and SetLastError isn't updated.
//--------------------------------------------------------------------------
function CertGetIssuerCertificateFromStore(
  hCertStore: HCERTSTORE;
  pSubjectContext: PCertContext;
  pPrevIssuerContext: PCertContext;
  var pdwFlags: DWORD): PCertContext; winapi;
{$EXTERNALSYM CertGetIssuerCertificateFromStore}

//+-------------------------------------------------------------------------
//  Perform the enabled verification checks on the subject certificate
//  using the issuer. Same checks and flags definitions as for the above
//  CertGetIssuerCertificateFromStore.
//
//  If you are only checking CERT_STORE_TIME_VALIDITY_FLAG, then, the
//  issuer can be NULL.
//
//  For a verification check failure, SUCCESS is still returned.
//--------------------------------------------------------------------------
function CertVerifySubjectCertificateContext(
  pSubject: PCertContext;
  pIssuer: PCertContext;
  var pdwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CertVerifySubjectCertificateContext}

//+-------------------------------------------------------------------------
//  Duplicate a certificate context
//--------------------------------------------------------------------------
function CertDuplicateCertificateContext(
  pCertContext: PCertContext): PCertContext; winapi;
{$EXTERNALSYM CertDuplicateCertificateContext}

//+-------------------------------------------------------------------------
//  Create a certificate context from the encoded certificate. The created
//  context isn't put in a store.
//
//  Makes a copy of the encoded certificate in the created context.
//
//  If unable to decode and create the certificate context, NULL is returned.
//  Otherwise, a pointer to a read only CERT_CONTEXT is returned.
//  CERT_CONTEXT must be freed by calling CertFreeCertificateContext.
//  CertDuplicateCertificateContext can be called to make a duplicate.
//
//  CertSetCertificateContextProperty and CertGetCertificateContextProperty can be called
//  to store properties for the certificate.
//--------------------------------------------------------------------------
function CertCreateCertificateContext(
  dwCertEncodingType: DWORD;
  pbCertEncoded: PByte;
  cbCertEncoded: DWORD): PCertContext; winapi;
{$EXTERNALSYM CertCreateCertificateContext}

//+-------------------------------------------------------------------------
//  Free a certificate context
//
//  There needs to be a corresponding free for each context obtained by a
//  get, find, duplicate or create.
//--------------------------------------------------------------------------
function CertFreeCertificateContext(
  pCertContext: PCertContext): BOOL; winapi;
{$EXTERNALSYM CertFreeCertificateContext}

//+-------------------------------------------------------------------------
//  Set the property for the specified certificate context.
//
//  The type definition for pvData depends on the dwPropId value. There are
//  five predefined types:
//      CERT_KEY_PROV_HANDLE_PROP_ID - a HCRYPTPROV for the certificate's
//      private key is passed in pvData. Updates the hCryptProv field
//      of the CERT_KEY_CONTEXT_PROP_ID. If the CERT_KEY_CONTEXT_PROP_ID
//      doesn't exist, its created with all the other fields zeroed out. If
//      CERT_STORE_NO_CRYPT_RELEASE_FLAG isn't set, HCRYPTPROV is implicitly
//      released when either the property is set to NULL or on the final
//      free of the CertContext.
//
//      CERT_NCRYPT_KEY_HANDLE_PROP_ID - a NCRYPT_KEY_HANDLE for the
//      certificate's private key is passed in pvData. The dwKeySpec is
//      set to CERT_NCRYPT_KEY_SPEC.
//
//      CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID - a
//      HCRYPTPROV_OR_NCRYPT_KEY_HANDLE for the certificates's private
//      key is passed in pvData.  NCryptIsKeyHandle()
//      is called to determine if this is a CNG NCRYPT_KEY_HANDLE.
//      For a NCRYPT_KEY_HANDLE does a CERT_NCRYPT_KEY_HANDLE_PROP_ID set.
//      Otherwise, does a CERT_KEY_PROV_HANDLE_PROP_ID set.
//
//      CERT_KEY_PROV_INFO_PROP_ID - a PCRYPT_KEY_PROV_INFO for the certificate's
//      private key is passed in pvData.
//
//      CERT_SHA1_HASH_PROP_ID       -
//      CERT_MD5_HASH_PROP_ID        -
//      CERT_SIGNATURE_HASH_PROP_ID  - normally, a hash property is implicitly
//      set by doing a CertGetCertificateContextProperty. pvData points to a
//      CRYPT_HASH_BLOB.
//
//      CERT_KEY_CONTEXT_PROP_ID - a PCERT_KEY_CONTEXT for the certificate's
//      private key is passed in pvData. The CERT_KEY_CONTEXT contains both the
//      hCryptProv and dwKeySpec for the private key. A dwKeySpec of
//      CERT_NCRYPT_KEY_SPEC selects the hNCryptKey choice.
//      See the CERT_KEY_PROV_HANDLE_PROP_ID for more information about
//      the hCryptProv field and dwFlags settings. Note, more fields may
//      be added for this property. The cbSize field value will be adjusted
//      accordingly.
//
//      CERT_KEY_SPEC_PROP_ID - the dwKeySpec for the private key. pvData
//      points to a DWORD containing the KeySpec
//
//      CERT_ENHKEY_USAGE_PROP_ID - enhanced key usage definition for the
//      certificate. pvData points to a CRYPT_DATA_BLOB containing an
//      ASN.1 encoded CERT_ENHKEY_USAGE (encoded via
//      CryptEncodeObject(X509_ENHANCED_KEY_USAGE).
//
//      CERT_NEXT_UPDATE_LOCATION_PROP_ID - location of the next update.
//      Currently only applicable to CTLs. pvData points to a CRYPT_DATA_BLOB
//      containing an ASN.1 encoded CERT_ALT_NAME_INFO (encoded via
//      CryptEncodeObject(X509_ALTERNATE_NAME)).
//
//      CERT_FRIENDLY_NAME_PROP_ID - friendly name for the cert, CRL or CTL.
//      pvData points to a CRYPT_DATA_BLOB. pbData is a pointer to a NULL
//      terminated unicode, wide character string.
//      cbData = (wcslen((LPWSTR) pbData) + 1) * sizeof(WCHAR).
//
//      CERT_DESCRIPTION_PROP_ID - description for the cert, CRL or CTL.
//      pvData points to a CRYPT_DATA_BLOB. pbData is a pointer to a NULL
//      terminated unicode, wide character string.
//      cbData = (wcslen((LPWSTR) pbData) + 1) * sizeof(WCHAR).
//
//      CERT_ARCHIVED_PROP_ID - when this property is set, the certificate
//      is skipped during enumeration. Note, certificates having this property
//      are still found for explicit finds, such as, finding a certificate
//      with a specific hash or finding a certificate having a specific issuer
//      and serial number. pvData points to a CRYPT_DATA_BLOB. This blob
//      can be NULL (pbData = NULL, cbData = 0).
//
//      CERT_PUBKEY_ALG_PARA_PROP_ID - for public keys supporting
//      algorithm parameter inheritance. pvData points to a CRYPT_OBJID_BLOB
//      containing the ASN.1 encoded PublicKey Algorithm Parameters. For
//      DSS this would be the parameters encoded via
//      CryptEncodeObject(X509_DSS_PARAMETERS). This property may be set
//      by CryptVerifyCertificateSignatureEx().
//
//      CERT_CROSS_CERT_DIST_POINTS_PROP_ID - location of the cross certs.
//      Currently only applicable to certs. pvData points to a CRYPT_DATA_BLOB
//      containing an ASN.1 encoded CROSS_CERT_DIST_POINTS_INFO (encoded via
//      CryptEncodeObject(X509_CROSS_CERT_DIST_POINTS)).
//
//      CERT_ENROLLMENT_PROP_ID - enrollment information of the pending request.
//      It contains RequestID, CADNSName, CAName, and FriendlyName.
//      The data format is defined as: the first 4 bytes - pending request ID,
//      next 4 bytes - CADNSName size in characters including null-terminator
//      followed by CADNSName string with null-terminator,
//      next 4 bytes - CAName size in characters including null-terminator
//      followed by CAName string with null-terminator,
//      next 4 bytes - FriendlyName size in characters including null-terminator
//      followed by FriendlyName string with null-terminator.
//
//      CERT_DATE_STAMP_PROP_ID - contains the time when added to the store
//      by an admin tool. pvData points to a CRYPT_DATA_BLOB containing
//      the FILETIME.
//
//      CERT_RENEWAL_PROP_ID - contains the hash of renewed certificate
//
//      CERT_OCSP_RESPONSE_PROP_ID - contains the encoded OCSP response.
//      CryptDecodeObject/CryptEncodeObject using
//      lpszStructType = OCSP_RESPONSE.
//      pvData points to a CRYPT_DATA_BLOB containing the encoded OCSP response.
//      If this property is present, CertVerifyRevocation() will first attempt
//      to use before doing an URL retrieval.
//
//      CERT_SOURCE_LOCATION_PROP_ID - contains source location of the CRL or
//      OCSP. pvData points to a CRYPT_DATA_BLOB. pbData is a pointer to a NULL
//      terminated unicode, wide character string. Where,
//      cbData = (wcslen((LPWSTR) pbData) + 1) * sizeof(WCHAR).
//
//      CERT_SOURCE_URL_PROP_ID - contains URL for the CRL or OCSP. pvData
//      is the same as for CERT_SOURCE_LOCATION_PROP_ID.
//
//      CERT_CEP_PROP_ID - contains Version, PropertyFlags, AuthType,
//      UrlFlags and CESAuthType, followed by the CEPUrl, CEPId, CESUrl and
//      RequestId strings
//      The data format is defined as: the first 4 bytes - property version,
//      next 4 bytes - Property Flags
//      next 4 bytes - Authentication Type
//      next 4 bytes - Url Flags
//      next 4 bytes - CES Authentication Type
//      followed by Url string with null-terminator,
//      followed by Id string with null-terminator,
//      followed by CES Url string with null-terminator,
//      followed by RequestId string with null-terminator.
//      a single null-terminator indicates no string is present.
//
//      CERT_KEY_REPAIR_ATTEMPTED_PROP_ID - contains the time when repair of
//      a missing CERT_KEY_PROV_INFO_PROP_ID property was attempted and failed.
//      pvData points to a CRYPT_DATA_BLOB containing the FILETIME.
//
//  For all the other PROP_IDs: an encoded PCRYPT_DATA_BLOB is passed in pvData.
//
//  If the property already exists, then, the old value is deleted and silently
//  replaced. Setting, pvData to NULL, deletes the property.
//
//  CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG can be set to ignore any
//  provider write errors and always update the cached context's property.
//--------------------------------------------------------------------------
function CertSetCertificateContextProperty(
  pCertContext: PCertContext;
  dwPropId: DWORD;
  dwFlags: DWORD;
  pvData: Pointer): BOOL; winapi;
{$EXTERNALSYM CertSetCertificateContextProperty}

// Set this flag to ignore any store provider write errors and always update
// the cached context's property
const
  CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG    = $80000000;
  {$EXTERNALSYM CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG}

// Set this flag to inhibit the persisting of this property
const
  CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG         = $40000000;
  {$EXTERNALSYM CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG}

//+-------------------------------------------------------------------------
//  Get the property for the specified certificate context.
//
//  For CERT_KEY_PROV_HANDLE_PROP_ID, pvData points to a HCRYPTPROV.
//  The CERT_NCRYPT_KEY_SPEC NCRYPT_KEY_HANDLE choice isn't returned.
//
//  For CERT_NCRYPT_KEY_HANDLE_PROP_ID, pvData points to a NCRYPT_KEY_HANDLE.
//  Only returned for the CERT_NCRYPT_KEY_SPEC choice.
//
//  For CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID, pvData points to a
//  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE. Returns either the HCRYPTPROV or
//  NCRYPT_KEY_HANDLE choice.
//
//  For CERT_KEY_PROV_INFO_PROP_ID, pvData points to a CRYPT_KEY_PROV_INFO structure.
//  Elements pointed to by fields in the pvData structure follow the
//  structure. Therefore, *pcbData may exceed the size of the structure.
//
//  For CERT_KEY_CONTEXT_PROP_ID, pvData points to a CERT_KEY_CONTEXT structure.
//
//  For CERT_KEY_SPEC_PROP_ID, pvData points to a DWORD containing the KeySpec.
//  If the CERT_KEY_CONTEXT_PROP_ID exists, the KeySpec is obtained from there.
//  Otherwise, if the CERT_KEY_PROV_INFO_PROP_ID exists, its the source
//  of the KeySpec. CERT_NCRYPT_KEY_SPEC is returned if the
//  CERT_NCRYPT_KEY_HANDLE_PROP_ID has been set.
//
//  For CERT_SHA1_HASH_PROP_ID or CERT_MD5_HASH_PROP_ID, if the hash
//  doesn't already exist, then, its computed via CryptHashCertificate()
//  and then set. pvData points to the computed hash. Normally, the length
//  is 20 bytes for SHA and 16 for MD5.
//
//  For CERT_SIGNATURE_HASH_PROP_ID, if the hash
//  doesn't already exist, then, its computed via CryptHashToBeSigned()
//  and then set. pvData points to the computed hash. Normally, the length
//  is 20 bytes for SHA and 16 for MD5.
//
//  For CERT_ACCESS_STATE_PROP_ID, pvData points to a DWORD containing the
//  access state flags. The appropriate CERT_ACCESS_STATE_*_FLAG's are set
//  in the returned DWORD. See the CERT_ACCESS_STATE_*_FLAG definitions
//  above. Note, this property is read only. It can't be set.
//
//  For CERT_KEY_IDENTIFIER_PROP_ID, if property doesn't already exist,
//  first searches for the szOID_SUBJECT_KEY_IDENTIFIER extension. Next,
//  does SHA1 hash of the certficate's SubjectPublicKeyInfo. pvData
//  points to the key identifier bytes. Normally, the length is 20 bytes.
//
//  For CERT_PUBKEY_ALG_PARA_PROP_ID, pvPara points to the ASN.1 encoded
//  PublicKey Algorithm Parameters. This property will only be set
//  for public keys supporting algorithm parameter inheritance and when the
//  parameters have been omitted from the encoded and signed certificate.
//
//  For CERT_DATE_STAMP_PROP_ID, pvPara points to a FILETIME updated by
//  an admin tool to indicate when the certificate was added to the store.
//
//  For CERT_OCSP_RESPONSE_PROP_ID, pvPara points to an encoded OCSP response.
//
//  For CERT_SOURCE_LOCATION_PROP_ID and CERT_SOURCE_URL_PROP_ID,
//  pvPara points to a NULL terminated unicode, wide character string.
//
//  For all other PROP_IDs, pvData points to an encoded array of bytes.
//--------------------------------------------------------------------------
function CertGetCertificateContextProperty(
  pCertContext: PCertContext;
  dwPropId: DWORD;
  pvData: Pointer;
  var pcbData: DWORD): BOOL; winapi;
{$EXTERNALSYM CertGetCertificateContextProperty}

//+-------------------------------------------------------------------------
//  Enumerate the properties for the specified certificate context.
//
//  To get the first property, set dwPropId to 0. The ID of the first
//  property is returned. To get the next property, set dwPropId to the
//  ID returned by the last call. To enumerate all the properties continue
//  until 0 is returned.
//
//  CertGetCertificateContextProperty is called to get the property's data.
//
//  Note, since, the CERT_KEY_PROV_HANDLE_PROP_ID and CERT_KEY_SPEC_PROP_ID
//  properties are stored as fields in the CERT_KEY_CONTEXT_PROP_ID
//  property, they aren't enumerated individually.
//--------------------------------------------------------------------------
function CertEnumCertificateContextProperties(
  pCertContext: PCertContext;
  dwPropId: DWORD): DWORD; winapi;
{$EXTERNALSYM CertEnumCertificateContextProperties}

//+-------------------------------------------------------------------------
//  Creates a CTL entry whose attributes are the certificate context's
//  properties.
//
//  The SubjectIdentifier in the CTL entry is the SHA1 hash of the certificate.
//
//  The certificate properties are added as attributes. The property attribute
//  OID is the decimal PROP_ID preceded by szOID_CERT_PROP_ID_PREFIX. Each
//  property value is copied as a single attribute value.
//
//  Any additional attributes to be included in the CTL entry can be passed
//  in via the cOptAttr and rgOptAttr parameters.
//
//  CTL_ENTRY_FROM_PROP_CHAIN_FLAG can be set in dwFlags, to force the
//  inclusion of the chain building hash properties as attributes.
//--------------------------------------------------------------------------
function CertCreateCTLEntryFromCertificateContextProperties(
  pCertContext: PCertContext;
  cOptAttr: DWORD;
  rgOptAttr: PCryptAttribute;
  dwFlags: DWORD;
  pvReserved: Pointer;
  pCtlEntry: PCTLEntry;
  var pcbCtlEntry: DWORD): BOOL; winapi;
{$EXTERNALSYM CertCreateCTLEntryFromCertificateContextProperties}

// Set this flag to get and include the chain building hash properties
// as attributes in the CTL entry
const
  CTL_ENTRY_FROM_PROP_CHAIN_FLAG                 = $1;
  {$EXTERNALSYM CTL_ENTRY_FROM_PROP_CHAIN_FLAG}


//+-------------------------------------------------------------------------
//  Sets properties on the certificate context using the attributes in
//  the CTL entry.
//
//  The property attribute OID is the decimal PROP_ID preceded by
//  szOID_CERT_PROP_ID_PREFIX. Only attributes containing such an OID are
//  copied.
//
//  CERT_SET_PROPERTY_IGNORE_PERSIST_ERROR_FLAG may be set in dwFlags.
//--------------------------------------------------------------------------
function CertSetCertificateContextPropertiesFromCTLEntry(
  pCertContext: PCertContext;
  pCtlEntry: PCTLEntry;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CertSetCertificateContextPropertiesFromCTLEntry}

//+-------------------------------------------------------------------------
//  Get the first or next CRL context from the store for the specified
//  issuer certificate. Perform the enabled verification checks on the CRL.
//
//  If the first or next CRL isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CRL_CONTEXT is returned. CRL_CONTEXT
//  must be freed by calling CertFreeCRLContext. However, the free must be
//  pPrevCrlContext on a subsequent call. CertDuplicateCRLContext
//  can be called to make a duplicate.
//
//  The pIssuerContext may have been obtained from this store, another store
//  or created by the caller application. When created by the caller, the
//  CertCreateCertificateContext function must have been called.
//
//  If pIssuerContext == NULL, finds all the CRLs in the store.
//
//  An issuer may have multiple CRLs. For example, it generates delta CRLs
//  using a X.509 v3 extension. pPrevCrlContext MUST BE NULL on the first
//  call to get the CRL. To get the next CRL for the issuer, the
//  pPrevCrlContext is set to the CRL_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevCrlContext is always CertFreeCRLContext'ed by
//  this function, even for an error.
//
//  The following flags can be set in *pdwFlags to enable verification checks
//  on the returned CRL:
//      CERT_STORE_SIGNATURE_FLAG     - use the public key in the
//                                      issuer's certificate to verify the
//                                      signature on the returned CRL.
//                                      Note, if pIssuerContext->hCertStore ==
//                                      hCertStore, the store provider might
//                                      be able to eliminate a redo of
//                                      the signature verify.
//      CERT_STORE_TIME_VALIDITY_FLAG - get the current time and verify that
//                                      its within the CRL's ThisUpdate and
//                                      NextUpdate validity period.
//      CERT_STORE_BASE_CRL_FLAG      - get base CRL.
//      CERT_STORE_DELTA_CRL_FLAG     - get delta CRL.
//
//  If only one of CERT_STORE_BASE_CRL_FLAG or CERT_STORE_DELTA_CRL_FLAG is
//  set, then, only returns either a base or delta CRL. In any case, the
//  appropriate base or delta flag will be cleared upon returned. If both
//  flags are set, then, only one of flags will be cleared.
//
//  If an enabled verification check fails, then, its flag is set upon return.
//
//  If pIssuerContext == NULL, then, an enabled CERT_STORE_SIGNATURE_FLAG
//  always fails and the CERT_STORE_NO_ISSUER_FLAG is also set.
//
//  For a verification check failure, a pointer to the first or next
//  CRL_CONTEXT is still returned and SetLastError isn't updated.
//--------------------------------------------------------------------------
function CertGetCRLFromStore(
  hCertStore: HCERTSTORE;
  pIssuerContext: PCertContext;
  pPrevCrlContext: PCRLContext;
  var pdwFlags: DWORD): PCRLContext; winapi;
{$EXTERNALSYM CertGetCRLFromStore}

//+-------------------------------------------------------------------------
//  Enumerate the CRL contexts in the store.
//
//  If a CRL isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CRL_CONTEXT is returned. CRL_CONTEXT
//  must be freed by calling CertFreeCRLContext or is freed when passed as the
//  pPrevCrlContext on a subsequent call. CertDuplicateCRLContext
//  can be called to make a duplicate.
//
//  pPrevCrlContext MUST BE NULL to enumerate the first
//  CRL in the store. Successive CRLs are enumerated by setting
//  pPrevCrlContext to the CRL_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevCrlContext is always CertFreeCRLContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertEnumCRLsInStore(
  hCertStore: HCERTSTORE;
  pPrevCrlContext: PCRLContext): PCRLContext; winapi;
{$EXTERNALSYM CertEnumCRLsInStore}

//+-------------------------------------------------------------------------
//  Find the first or next CRL context in the store.
//
//  The CRL is found according to the dwFindType and its pvFindPara.
//  See below for a list of the find types and its parameters.
//
//  Currently dwFindFlags isn't used and must be set to 0.
//
//  Usage of dwCertEncodingType depends on the dwFindType.
//
//  If the first or next CRL isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CRL_CONTEXT is returned. CRL_CONTEXT
//  must be freed by calling CertFreeCRLContext or is freed when passed as the
//  pPrevCrlContext on a subsequent call. CertDuplicateCRLContext
//  can be called to make a duplicate.
//
//  pPrevCrlContext MUST BE NULL on the first
//  call to find the CRL. To find the next CRL, the
//  pPrevCrlContext is set to the CRL_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevCrlContext is always CertFreeCRLContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertFindCRLInStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  dwFindFlags: DWORD;
  dwFindType: DWORD;
  pvFindPara: Pointer;
  pPrevCrlContext: PCRLContext): PCRLContext; winapi;
{$EXTERNALSYM CertFindCRLInStore}

const
  CRL_FIND_ANY               = 0;
  {$EXTERNALSYM CRL_FIND_ANY}
  CRL_FIND_ISSUED_BY         = 1;
  {$EXTERNALSYM CRL_FIND_ISSUED_BY}
  CRL_FIND_EXISTING          = 2;
  {$EXTERNALSYM CRL_FIND_EXISTING}
  CRL_FIND_ISSUED_FOR        = 3;
  {$EXTERNALSYM CRL_FIND_ISSUED_FOR}

//+-------------------------------------------------------------------------
//  CRL_FIND_ANY
//
//  Find any CRL.
//
//  pvFindPara isn't used.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CRL_FIND_ISSUED_BY
//
//  Find CRL matching the specified issuer.
//
//  pvFindPara is the PCCERT_CONTEXT of the CRL issuer. May be NULL to
//  match any issuer.
//
//  By default, only does issuer name matching. The following flags can be
//  set in dwFindFlags to do additional filtering.
//
//  If CRL_FIND_ISSUED_BY_AKI_FLAG is set in dwFindFlags, then, checks if the
//  CRL has an Authority Key Identifier (AKI) extension. If the CRL has an
//  AKI, then, only returns a CRL whose AKI matches the issuer.
//
//  Note, the AKI extension has the following OID:
//  szOID_AUTHORITY_KEY_IDENTIFIER2 and its corresponding data structure.
//
//  If CRL_FIND_ISSUED_BY_SIGNATURE_FLAG is set in dwFindFlags, then,
//  uses the public key in the issuer's certificate to verify the
//  signature on the CRL. Only returns a CRL having a valid signature.
//
//  If CRL_FIND_ISSUED_BY_DELTA_FLAG is set in dwFindFlags, then, only
//  returns a delta CRL.
//
//  If CRL_FIND_ISSUED_BY_BASE_FLAG is set in dwFindFlags, then, only
//  returns a base CRL.
//--------------------------------------------------------------------------
const
  CRL_FIND_ISSUED_BY_AKI_FLAG        = $1;
  {$EXTERNALSYM CRL_FIND_ISSUED_BY_AKI_FLAG}
  CRL_FIND_ISSUED_BY_SIGNATURE_FLAG  = $2;
  {$EXTERNALSYM CRL_FIND_ISSUED_BY_SIGNATURE_FLAG}
  CRL_FIND_ISSUED_BY_DELTA_FLAG      = $4;
  {$EXTERNALSYM CRL_FIND_ISSUED_BY_DELTA_FLAG}
  CRL_FIND_ISSUED_BY_BASE_FLAG       = $8;
  {$EXTERNALSYM CRL_FIND_ISSUED_BY_BASE_FLAG}


//+-------------------------------------------------------------------------
//  CRL_FIND_EXISTING
//
//  Find existing CRL in the store.
//
//  pvFindPara is the PCCRL_CONTEXT of the CRL to check if it already
//  exists in the store.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CRL_FIND_ISSUED_FOR
//
//  Find CRL for the specified subject and its issuer.
//
//  pvFindPara points to the following CRL_FIND_ISSUED_FOR_PARA which contains
//  both the subject and issuer certificates. Not optional.
//
//  The subject's issuer name is used to match the CRL's issuer name. Otherwise,
//  the issuer's certificate is used the same as in the above
//  CRL_FIND_ISSUED_BY.
//
//  Note, when cross certificates are used, the subject name in the issuer's
//  certificate may not match the issuer name in the subject certificate and
//  its corresponding CRL.
//
//  All of the above CRL_FIND_ISSUED_BY_*_FLAGS apply to this find type.
//--------------------------------------------------------------------------
type
  PCRLFindIssuedForPara = ^TCRLFindIssuedForPara;
  _CRL_FIND_ISSUED_FOR_PARA = record
    pSubjectCert: PCertContext;
    pIssuerCert: PCertContext;
  end;
  {$EXTERNALSYM _CRL_FIND_ISSUED_FOR_PARA}
  CRL_FIND_ISSUED_FOR_PARA = _CRL_FIND_ISSUED_FOR_PARA;
  {$EXTERNALSYM CRL_FIND_ISSUED_FOR_PARA}
  TCRLFindIssuedForPara = _CRL_FIND_ISSUED_FOR_PARA;
  PCRL_FIND_ISSUED_FOR_PARA = PCRLFindIssuedForPara;
  {$EXTERNALSYM PCRL_FIND_ISSUED_FOR_PARA}

//
// When the following flag is set, the strong signature properties
// are also set on the returned CRL.
//
//  The strong signature properties are:
//    - CERT_SIGN_HASH_CNG_ALG_PROP_ID
//    - CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID
//
const
  CRL_FIND_ISSUED_FOR_SET_STRONG_PROPERTIES_FLAG       = $10;
  {$EXTERNALSYM CRL_FIND_ISSUED_FOR_SET_STRONG_PROPERTIES_FLAG}


//+-------------------------------------------------------------------------
//  Duplicate a CRL context
//--------------------------------------------------------------------------
function CertDuplicateCRLContext(
  pCrlContext: PCRLContext): PCRLContext; winapi;
{$EXTERNALSYM CertDuplicateCRLContext}

//+-------------------------------------------------------------------------
//  Create a CRL context from the encoded CRL. The created
//  context isn't put in a store.
//
//  Makes a copy of the encoded CRL in the created context.
//
//  If unable to decode and create the CRL context, NULL is returned.
//  Otherwise, a pointer to a read only CRL_CONTEXT is returned.
//  CRL_CONTEXT must be freed by calling CertFreeCRLContext.
//  CertDuplicateCRLContext can be called to make a duplicate.
//
//  CertSetCRLContextProperty and CertGetCRLContextProperty can be called
//  to store properties for the CRL.
//--------------------------------------------------------------------------
function CertCreateCRLContext(
  dwCertEncodingType: DWORD;
  pbCrlEncoded: PByte;
  cbCrlEncoded: DWORD): PCRLContext;
{$EXTERNALSYM CertCreateCRLContext}

//+-------------------------------------------------------------------------
//  Free a CRL context
//
//  There needs to be a corresponding free for each context obtained by a
//  get, duplicate or create.
//--------------------------------------------------------------------------
function CertFreeCRLContext(
  pCrlContext: PCRLContext): BOOL; winapi;
{$EXTERNALSYM CertFreeCRLContext}

//+-------------------------------------------------------------------------
//  Set the property for the specified CRL context.
//
//  Same Property Ids and semantics as CertSetCertificateContextProperty.
//--------------------------------------------------------------------------
function CertSetCRLContextProperty(
  pCrlContext: PCRLContext;
  dwPropId: DWORD;
  dwFlags: DWORD;
  pvData: Pointer): BOOL; winapi;
{$EXTERNALSYM CertSetCRLContextProperty}

//+-------------------------------------------------------------------------
//  Get the property for the specified CRL context.
//
//  Same Property Ids and semantics as CertGetCertificateContextProperty.
//
//  CERT_SHA1_HASH_PROP_ID, CERT_MD5_HASH_PROP_ID or
//  CERT_SIGNATURE_HASH_PROP_ID is the predefined property of most interest.
//--------------------------------------------------------------------------
function CertGetCRLContextProperty(
  pCrlContext: PCRLContext;
  dwPropId: DWORD;
  pvData: Pointer;
  var pcbData: DWORD): BOOL; winapi;
{$EXTERNALSYM CertGetCRLContextProperty}

//+-------------------------------------------------------------------------
//  Enumerate the properties for the specified CRL context.
//
//  To get the first property, set dwPropId to 0. The ID of the first
//  property is returned. To get the next property, set dwPropId to the
//  ID returned by the last call. To enumerate all the properties continue
//  until 0 is returned.
//
//  CertGetCRLContextProperty is called to get the property's data.
//--------------------------------------------------------------------------
function CertEnumCRLContextProperties(
  pCrlContext: PCRLContext;
  dwPropId: DWORD): DWORD; winapi;
{$EXTERNALSYM CertEnumCRLContextProperties}

//+-------------------------------------------------------------------------
//  Search the CRL's list of entries for the specified certificate.
//
//  TRUE is returned if we were able to search the list. Otherwise, FALSE is
//  returned,
//
//  For success, if the certificate was found in the list, *ppCrlEntry is
//  updated with a pointer to the entry. Otherwise, *ppCrlEntry is set to NULL.
//  The returned entry isn't allocated and must not be freed.
//
//  dwFlags and pvReserved currently aren't used and must be set to 0 or NULL.
//--------------------------------------------------------------------------
function CertFindCertificateInCRL(
  pCert: PCertContext;
  pCrlContext: PCRLContext;
  dwFlags: DWORD;
  pvReserved: Pointer;
  out ppCrlEntry: PCRLEntry): BOOL; winapi;
{$EXTERNALSYM CertFindCertificateInCRL}

//+-------------------------------------------------------------------------
//  Is the specified CRL valid for the certificate.
//
//  Returns TRUE if the CRL's list of entries would contain the certificate
//  if it was revoked. Note, doesn't check that the certificate is in the
//  list of entries.
//
//  If the CRL has an Issuing Distribution Point (IDP) extension, checks
//  that it's valid for the subject certificate.
//
//  dwFlags and pvReserved currently aren't used and must be set to 0 and NULL.
//--------------------------------------------------------------------------
function CertIsValidCRLForCertificate(
  pCert: PCertContext;
  pCrl: PCRLContext;
  dwFlags: DWORD;
  pvReserved: Pointer): BOOL; winapi;
{$EXTERNALSYM CertIsValidCRLForCertificate}


//+-------------------------------------------------------------------------
// Add certificate/CRL, encoded, context or element disposition values.
//--------------------------------------------------------------------------
const
  CERT_STORE_ADD_NEW                                 = 1;
  {$EXTERNALSYM CERT_STORE_ADD_NEW}
  CERT_STORE_ADD_USE_EXISTING                        = 2;
  {$EXTERNALSYM CERT_STORE_ADD_USE_EXISTING}
  CERT_STORE_ADD_REPLACE_EXISTING                    = 3;
  {$EXTERNALSYM CERT_STORE_ADD_REPLACE_EXISTING}
  CERT_STORE_ADD_ALWAYS                              = 4;
  {$EXTERNALSYM CERT_STORE_ADD_ALWAYS}
  CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5;
  {$EXTERNALSYM CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES}
  CERT_STORE_ADD_NEWER                               = 6;
  {$EXTERNALSYM CERT_STORE_ADD_NEWER}
  CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES            = 7;
  {$EXTERNALSYM CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES}


//+-------------------------------------------------------------------------
//  Add the encoded certificate to the store according to the specified
//  disposition action.
//
//  Makes a copy of the encoded certificate before adding to the store.
//
//  dwAddDispostion specifies the action to take if the certificate
//  already exists in the store. This parameter must be one of the following
//  values:
//    CERT_STORE_ADD_NEW
//      Fails if the certificate already exists in the store. LastError
//      is set to CRYPT_E_EXISTS.
//    CERT_STORE_ADD_USE_EXISTING
//      If the certifcate already exists, then, its used and if ppCertContext
//      is non-NULL, the existing context is duplicated.
//    CERT_STORE_ADD_REPLACE_EXISTING
//      If the certificate already exists, then, the existing certificate
//      context is deleted before creating and adding the new context.
//    CERT_STORE_ADD_ALWAYS
//      No check is made to see if the certificate already exists. A
//      new certificate context is always created. This may lead to
//      duplicates in the store.
//    CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES
//      If the certificate already exists, then, its used.
//    CERT_STORE_ADD_NEWER
//      Fails if the certificate already exists in the store AND the NotBefore
//      time of the existing certificate is equal to or greater than the
//      NotBefore time of the new certificate being added. LastError
//      is set to CRYPT_E_EXISTS.
//
//      If an older certificate is replaced, same as
//      CERT_STORE_ADD_REPLACE_EXISTING.
//
//      For CRLs or CTLs compares the ThisUpdate times.
//
//    CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES
//      Same as CERT_STORE_ADD_NEWER. However, if an older certificate is
//      replaced, same as CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES.
//
//  CertGetSubjectCertificateFromStore is called to determine if the
//  certificate already exists in the store.
//
//  ppCertContext can be NULL, indicating the caller isn't interested
//  in getting the CERT_CONTEXT of the added or existing certificate.
//--------------------------------------------------------------------------
function CertAddEncodedCertificateToStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  pbCertEncoded: PByte;
  cbCertEncoded: DWORD;
  dwAddDisposition: DWORD;
  ppCertContext: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CertAddEncodedCertificateToStore}

//+-------------------------------------------------------------------------
//  Add the certificate context to the store according to the specified
//  disposition action.
//
//  In addition to the encoded certificate, the context's properties are
//  also copied.  Note, the CERT_KEY_CONTEXT_PROP_ID property (and its
//  CERT_KEY_PROV_HANDLE_PROP_ID or CERT_KEY_SPEC_PROP_ID) isn't copied.
//
//  Makes a copy of the certificate context before adding to the store.
//
//  dwAddDispostion specifies the action to take if the certificate
//  already exists in the store. This parameter must be one of the following
//  values:
//    CERT_STORE_ADD_NEW
//      Fails if the certificate already exists in the store. LastError
//      is set to CRYPT_E_EXISTS.
//    CERT_STORE_ADD_USE_EXISTING
//      If the certifcate already exists, then, its used and if ppStoreContext
//      is non-NULL, the existing context is duplicated. Iterates
//      through pCertContext's properties and only copies the properties
//      that don't already exist. The SHA1 and MD5 hash properties aren't
//      copied.
//    CERT_STORE_ADD_REPLACE_EXISTING
//      If the certificate already exists, then, the existing certificate
//      context is deleted before creating and adding a new context.
//      Properties are copied before doing the add.
//    CERT_STORE_ADD_ALWAYS
//      No check is made to see if the certificate already exists. A
//      new certificate context is always created and added. This may lead to
//      duplicates in the store. Properties are
//      copied before doing the add.
//    CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES
//      If the certificate already exists, then, the existing certificate
//      context is used. Properties from the added context are copied and
//      replace existing properties. However, any existing properties not
//      in the added context remain and aren't deleted.
//    CERT_STORE_ADD_NEWER
//      Fails if the certificate already exists in the store AND the NotBefore
//      time of the existing context is equal to or greater than the
//      NotBefore time of the new context being added. LastError
//      is set to CRYPT_E_EXISTS.
//
//      If an older context is replaced, same as
//      CERT_STORE_ADD_REPLACE_EXISTING.
//
//      For CRLs or CTLs compares the ThisUpdate times.
//
//    CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES
//      Same as CERT_STORE_ADD_NEWER. However, if an older context is
//      replaced, same as CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES.
//
//  CertGetSubjectCertificateFromStore is called to determine if the
//  certificate already exists in the store.
//
//  ppStoreContext can be NULL, indicating the caller isn't interested
//  in getting the CERT_CONTEXT of the added or existing certificate.
//--------------------------------------------------------------------------
function CertAddCertificateContextToStore(
  hCertStore: HCERTSTORE;
  pCertContext: PCertContext;
  dwAddDisposition: DWORD;
  ppStoreContext: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CertAddCertificateContextToStore}


//+-------------------------------------------------------------------------
//  Certificate Store Context Types
//--------------------------------------------------------------------------
const
  CERT_STORE_CERTIFICATE_CONTEXT = 1;
  {$EXTERNALSYM CERT_STORE_CERTIFICATE_CONTEXT}
  CERT_STORE_CRL_CONTEXT         = 2;
  {$EXTERNALSYM CERT_STORE_CRL_CONTEXT}
  CERT_STORE_CTL_CONTEXT         = 3;
  {$EXTERNALSYM CERT_STORE_CTL_CONTEXT}

//+-------------------------------------------------------------------------
//  Certificate Store Context Bit Flags
//--------------------------------------------------------------------------
const
  CERT_STORE_ALL_CONTEXT_FLAG            = not Longword(0);
  {$EXTERNALSYM CERT_STORE_ALL_CONTEXT_FLAG}
  CERT_STORE_CERTIFICATE_CONTEXT_FLAG    = (1 shl CERT_STORE_CERTIFICATE_CONTEXT);
  {$EXTERNALSYM CERT_STORE_CERTIFICATE_CONTEXT_FLAG}
  CERT_STORE_CRL_CONTEXT_FLAG            = (1 shl CERT_STORE_CRL_CONTEXT);
  {$EXTERNALSYM CERT_STORE_CRL_CONTEXT_FLAG}
  CERT_STORE_CTL_CONTEXT_FLAG            = (1 shl CERT_STORE_CTL_CONTEXT);
  {$EXTERNALSYM CERT_STORE_CTL_CONTEXT_FLAG}

//+-------------------------------------------------------------------------
//  Add the serialized certificate or CRL element to the store.
//
//  The serialized element contains the encoded certificate, CRL or CTL and
//  its properties, such as, CERT_KEY_PROV_INFO_PROP_ID.
//
//  If hCertStore is NULL, creates a certificate, CRL or CTL context not
//  residing in any store.
//
//  dwAddDispostion specifies the action to take if the certificate or CRL
//  already exists in the store. See CertAddCertificateContextToStore for a
//  list of and actions taken.
//
//  dwFlags currently isn't used and should be set to 0.
//
//  dwContextTypeFlags specifies the set of allowable contexts. For example, to
//  add either a certificate or CRL, set dwContextTypeFlags to:
//      CERT_STORE_CERTIFICATE_CONTEXT_FLAG | CERT_STORE_CRL_CONTEXT_FLAG
//
//  *pdwContextType is updated with the type of the context returned in
//  *ppvContxt. pdwContextType or ppvContext can be NULL, indicating the
//  caller isn't interested in getting the output. If *ppvContext is
//  returned it must be freed by calling CertFreeCertificateContext or
//  CertFreeCRLContext.
//--------------------------------------------------------------------------
function CertAddSerializedElementToStore(
  hCertStore: HCERTSTORE;
  pbElement: PByte;
  cbElement: DWORD;
  dwAddDisposition: DWORD;
  dwFlags: DWORD;
  dwContextTypeFlags: DWORD;
  pdwContextType: PDWORD;
  ppvContext: PPointer): BOOL; winapi;
{$EXTERNALSYM CertAddSerializedElementToStore}

//+-------------------------------------------------------------------------
//  Delete the specified certificate from the store.
//
//  All subsequent gets or finds for the certificate will fail. However,
//  memory allocated for the certificate isn't freed until all of its contexts
//  have also been freed.
//
//  The pCertContext is obtained from a get, enum, find or duplicate.
//
//  Some store provider implementations might also delete the issuer's CRLs
//  if this is the last certificate for the issuer in the store.
//
//  NOTE: the pCertContext is always CertFreeCertificateContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertDeleteCertificateFromStore(
  pCertContext: PCertContext): BOOL; winapi;
{$EXTERNALSYM CertDeleteCertificateFromStore}

//+-------------------------------------------------------------------------
//  Add the encoded CRL to the store according to the specified
//  disposition option.
//
//  Makes a copy of the encoded CRL before adding to the store.
//
//  dwAddDispostion specifies the action to take if the CRL
//  already exists in the store. See CertAddEncodedCertificateToStore for a
//  list of and actions taken.
//
//  Compares the CRL's Issuer to determine if the CRL already exists in the
//  store.
//
//  ppCrlContext can be NULL, indicating the caller isn't interested
//  in getting the CRL_CONTEXT of the added or existing CRL.
//--------------------------------------------------------------------------
function CertAddEncodedCRLToStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  pbCrlEncoded: PByte;
  cbCrlEncoded: DWORD;
  dwAddDisposition: DWORD;
  ppCrlContext: PPCRLContext): BOOL; winapi;
{$EXTERNALSYM CertAddEncodedCRLToStore}

//+-------------------------------------------------------------------------
//  Add the CRL context to the store according to the specified
//  disposition option.
//
//  In addition to the encoded CRL, the context's properties are
//  also copied.  Note, the CERT_KEY_CONTEXT_PROP_ID property (and its
//  CERT_KEY_PROV_HANDLE_PROP_ID or CERT_KEY_SPEC_PROP_ID) isn't copied.
//
//  Makes a copy of the encoded CRL before adding to the store.
//
//  dwAddDispostion specifies the action to take if the CRL
//  already exists in the store. See CertAddCertificateContextToStore for a
//  list of and actions taken.
//
//  Compares the CRL's Issuer, ThisUpdate and NextUpdate to determine
//  if the CRL already exists in the store.
//
//  ppStoreContext can be NULL, indicating the caller isn't interested
//  in getting the CRL_CONTEXT of the added or existing CRL.
//--------------------------------------------------------------------------
function CertAddCRLContextToStore(
  hCertStore: HCERTSTORE;
  pCrlContext: PCRLContext;
  dwAddDisposition: DWORD;
  ppStoreContext: PPCRLContext): BOOL; winapi;
{$EXTERNALSYM CertAddCRLContextToStore}

//+-------------------------------------------------------------------------
//  Delete the specified CRL from the store.
//
//  All subsequent gets for the CRL will fail. However,
//  memory allocated for the CRL isn't freed until all of its contexts
//  have also been freed.
//
//  The pCrlContext is obtained from a get or duplicate.
//
//  NOTE: the pCrlContext is always CertFreeCRLContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertDeleteCRLFromStore(
  pCrlContext: PCRLContext): BOOL; winapi;
{$EXTERNALSYM CertDeleteCRLFromStore}

//+-------------------------------------------------------------------------
//  Serialize the certificate context's encoded certificate and its
//  properties.
//--------------------------------------------------------------------------
function CertSerializeCertificateStoreElement(
  pCertContext: PCertContext;
  dwFlags: DWORD;
  pbElement: PByte;
  var pcbElement: DWORD): BOOL; winapi;
{$EXTERNALSYM CertSerializeCertificateStoreElement}

//+-------------------------------------------------------------------------
//  Serialize the CRL context's encoded CRL and its properties.
//--------------------------------------------------------------------------
function CertSerializeCRLStoreElement(
  pCrlContext: PCRLContext;
  dwFlags: DWORD;
  pbElement: PByte;
  var pcbElement: DWORD): BOOL; winapi;
{$EXTERNALSYM CertSerializeCRLStoreElement}


//+=========================================================================
//  Certificate Trust List (CTL) Store Data Structures and APIs
//==========================================================================

//+-------------------------------------------------------------------------
//  Duplicate a CTL context
//--------------------------------------------------------------------------
function CertDuplicateCTLContext(
  pCtlContext: PCTLContext): PCTLContext; winapi;
{$EXTERNALSYM CertDuplicateCTLContext}

//+-------------------------------------------------------------------------
//  Create a CTL context from the encoded CTL. The created
//  context isn't put in a store.
//
//  Makes a copy of the encoded CTL in the created context.
//
//  If unable to decode and create the CTL context, NULL is returned.
//  Otherwise, a pointer to a read only CTL_CONTEXT is returned.
//  CTL_CONTEXT must be freed by calling CertFreeCTLContext.
//  CertDuplicateCTLContext can be called to make a duplicate.
//
//  CertSetCTLContextProperty and CertGetCTLContextProperty can be called
//  to store properties for the CTL.
//--------------------------------------------------------------------------
function CertCreateCTLContext(
  dwMsgAndCertEncodingType: DWORD;
  pbCtlEncoded: PByte;
  cbCtlEncoded: DWORD): PCTLContext; winapi;
{$EXTERNALSYM CertCreateCTLContext}

//+-------------------------------------------------------------------------
//  Free a CTL context
//
//  There needs to be a corresponding free for each context obtained by a
//  get, duplicate or create.
//--------------------------------------------------------------------------
function CertFreeCTLContext(
  pCtlContext: PCTLContext): BOOL; winapi;
{$EXTERNALSYM CertFreeCTLContext}

//+-------------------------------------------------------------------------
//  Set the property for the specified CTL context.
//
//  Same Property Ids and semantics as CertSetCertificateContextProperty.
//--------------------------------------------------------------------------
function CertSetCTLContextProperty(
  pCtlContext: PCTLContext;
  dwPropId: DWORD;
  dwFlags: DWORD;
  pvData: Pointer): BOOL; winapi;
{$EXTERNALSYM CertSetCTLContextProperty}

//+-------------------------------------------------------------------------
//  Get the property for the specified CTL context.
//
//  Same Property Ids and semantics as CertGetCertificateContextProperty.
//
//  CERT_SHA1_HASH_PROP_ID or CERT_NEXT_UPDATE_LOCATION_PROP_ID are the
//  predefined properties of most interest.
//--------------------------------------------------------------------------
function CertGetCTLContextProperty(
  pCtlContext: PCTLContext;
  dwPropId: DWORD;
  pvData: Pointer;
  var pcbData: DWORD): BOOL; winapi;
{$EXTERNALSYM CertGetCTLContextProperty}

//+-------------------------------------------------------------------------
//  Enumerate the properties for the specified CTL context.
//--------------------------------------------------------------------------
function CertEnumCTLContextProperties(
  pCtlContext: PCTLContext;
  dwPropId: DWORD): DWORD; winapi;
{$EXTERNALSYM CertEnumCTLContextProperties}

//+-------------------------------------------------------------------------
//  Enumerate the CTL contexts in the store.
//
//  If a CTL isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CTL_CONTEXT is returned. CTL_CONTEXT
//  must be freed by calling CertFreeCTLContext or is freed when passed as the
//  pPrevCtlContext on a subsequent call. CertDuplicateCTLContext
//  can be called to make a duplicate.
//
//  pPrevCtlContext MUST BE NULL to enumerate the first
//  CTL in the store. Successive CTLs are enumerated by setting
//  pPrevCtlContext to the CTL_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevCtlContext is always CertFreeCTLContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertEnumCTLsInStore(
  hCertStore: HCERTSTORE;
  pPrevCtlContext: PCTLContext): PCTLContext; winapi;
{$EXTERNALSYM CertEnumCTLsInStore}

//+-------------------------------------------------------------------------
//  Attempt to find the specified subject in the CTL.
//
//  For CTL_CERT_SUBJECT_TYPE, pvSubject points to a CERT_CONTEXT. The CTL's
//  SubjectAlgorithm is examined to determine the representation of the
//  subject's identity. Initially, only SHA1 or MD5 hash will be supported.
//  The appropriate hash property is obtained from the CERT_CONTEXT.
//
//  For CTL_ANY_SUBJECT_TYPE, pvSubject points to the CTL_ANY_SUBJECT_INFO
//  structure which contains the SubjectAlgorithm to be matched in the CTL
//  and the SubjectIdentifer to be matched in one of the CTL entries.
//
//  The certificate's hash or the CTL_ANY_SUBJECT_INFO's SubjectIdentifier
//  is used as the key in searching the subject entries. A binary
//  memory comparison is done between the key and the entry's SubjectIdentifer.
//
//  dwEncodingType isn't used for either of the above SubjectTypes.
//--------------------------------------------------------------------------
function CertFindSubjectInCTL(
  dwEncodingType: DWORD;
  dwSubjectType: DWORD;
  pvSubject: Pointer;
  pCtlContext: PCTLContext;
  dwFlags: DWORD): PCTLEntry; winapi;
{$EXTERNALSYM CertFindSubjectInCTL}

// Subject Types:
//  CTL_ANY_SUBJECT_TYPE, pvSubject points to following CTL_ANY_SUBJECT_INFO.
//  CTL_CERT_SUBJECT_TYPE, pvSubject points to CERT_CONTEXT.
const
  CTL_ANY_SUBJECT_TYPE           = 1;
  {$EXTERNALSYM CTL_ANY_SUBJECT_TYPE}
  CTL_CERT_SUBJECT_TYPE          = 2;
  {$EXTERNALSYM CTL_CERT_SUBJECT_TYPE}

type
  PCTLAnySubjectInfo = ^TCTLAnySubjectInfo;
  _CTL_ANY_SUBJECT_INFO = record
    SubjectAlgorithm: TCryptAlgorithmIdentifier;
    SubjectIdentifier: TCryptDataBlob;
  end;
  {$EXTERNALSYM _CTL_ANY_SUBJECT_INFO}
  CTL_ANY_SUBJECT_INFO = _CTL_ANY_SUBJECT_INFO;
  {$EXTERNALSYM CTL_ANY_SUBJECT_INFO}
  TCTLAnySubjectInfo = _CTL_ANY_SUBJECT_INFO;
  PCTL_ANY_SUBJECT_INFO = PCTLAnySubjectInfo;
  {$EXTERNALSYM PCTL_ANY_SUBJECT_INFO}

//+-------------------------------------------------------------------------
//  Find the first or next CTL context in the store.
//
//  The CTL is found according to the dwFindType and its pvFindPara.
//  See below for a list of the find types and its parameters.
//
//  Currently dwFindFlags isn't used and must be set to 0.
//
//  Usage of dwMsgAndCertEncodingType depends on the dwFindType.
//
//  If the first or next CTL isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CTL_CONTEXT is returned. CTL_CONTEXT
//  must be freed by calling CertFreeCTLContext or is freed when passed as the
//  pPrevCtlContext on a subsequent call. CertDuplicateCTLContext
//  can be called to make a duplicate.
//
//  pPrevCtlContext MUST BE NULL on the first
//  call to find the CTL. To find the next CTL, the
//  pPrevCtlContext is set to the CTL_CONTEXT returned by a previous call.
//
//  NOTE: a NON-NULL pPrevCtlContext is always CertFreeCTLContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertFindCTLInStore(
  hCertStore: HCERTSTORE;
  dwMsgAndCertEncodingType: DWORD;
  dwFindFlags: DWORD;
  dwFindType: DWORD;
  pvFindPara: Pointer;
  pPrevCtlContext: PCTLContext): PCTLContext; winapi;
{$EXTERNALSYM CertFindCTLInStore}

const
  CTL_FIND_ANY               = 0;
  {$EXTERNALSYM CTL_FIND_ANY}
  CTL_FIND_SHA1_HASH         = 1;
  {$EXTERNALSYM CTL_FIND_SHA1_HASH}
  CTL_FIND_MD5_HASH          = 2;
  {$EXTERNALSYM CTL_FIND_MD5_HASH}
  CTL_FIND_USAGE             = 3;
  {$EXTERNALSYM CTL_FIND_USAGE}
  CTL_FIND_SUBJECT           = 4;
  {$EXTERNALSYM CTL_FIND_SUBJECT}
  CTL_FIND_EXISTING          = 5;
  {$EXTERNALSYM CTL_FIND_EXISTING}

type
  PCTLFindUsagePara = ^TCTLFindUsagePara;
  _CTL_FIND_USAGE_PARA = record
    cbSize: DWORD;
    SubjectUsage: TCTLUsage;            // optional
    ListIdentifier: TCryptDataBlob;     // optional
    pSigner: PCertInfo;                 // optional
  end;
  {$EXTERNALSYM _CTL_FIND_USAGE_PARA}
  CTL_FIND_USAGE_PARA = _CTL_FIND_USAGE_PARA;
  {$EXTERNALSYM CTL_FIND_USAGE_PARA}
  TCTLFindUsagePara = _CTL_FIND_USAGE_PARA;
  PCTL_FIND_USAGE_PARA = PCTLFindUsagePara;
  {$EXTERNALSYM PCTL_FIND_USAGE_PARA}

const
  CTL_FIND_NO_LIST_ID_CBDATA = $FFFFFFFF;
  {$EXTERNALSYM CTL_FIND_NO_LIST_ID_CBDATA}
  CTL_FIND_NO_SIGNER_PTR     = PCertInfo(-1);
  {$EXTERNALSYM CTL_FIND_NO_SIGNER_PTR}

  CTL_FIND_SAME_USAGE_FLAG   = $1;
  {$EXTERNALSYM CTL_FIND_SAME_USAGE_FLAG}


type
  PCTLFindSubjectPara = ^TCTLFindSubjectPara;
  _CTL_FIND_SUBJECT_PARA = record
    cbSize: DWORD;
    pUsagePara: PCTLFindUsagePara;      // optional
    dwSubjectType: DWORD;
    pvSubject: Pointer;
  end;
  {$EXTERNALSYM _CTL_FIND_SUBJECT_PARA}
  CTL_FIND_SUBJECT_PARA = _CTL_FIND_SUBJECT_PARA;
  {$EXTERNALSYM CTL_FIND_SUBJECT_PARA}
  TCTLFindSubjectPara = _CTL_FIND_SUBJECT_PARA;
  PCTL_FIND_SUBJECT_PARA = PCTLFindSubjectPara;
  {$EXTERNALSYM PCTL_FIND_SUBJECT_PARA}


//+-------------------------------------------------------------------------
//  CTL_FIND_ANY
//
//  Find any CTL.
//
//  pvFindPara isn't used.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CTL_FIND_SHA1_HASH
//  CTL_FIND_MD5_HASH
//
//  Find a CTL with the specified hash.
//
//  pvFindPara points to a CRYPT_HASH_BLOB.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CTL_FIND_USAGE
//
//  Find a CTL having the specified usage identifiers, list identifier or
//  signer. The CertEncodingType of the signer is obtained from the
//  dwMsgAndCertEncodingType parameter.
//
//  pvFindPara points to a CTL_FIND_USAGE_PARA data structure. The
//  SubjectUsage.cUsageIdentifer can be 0 to match any usage. The
//  ListIdentifier.cbData can be 0 to match any list identifier. To only match
//  CTLs without a ListIdentifier, cbData must be set to
//  CTL_FIND_NO_LIST_ID_CBDATA. pSigner can be NULL to match any signer. Only
//  the Issuer and SerialNumber fields of the pSigner's PCERT_INFO are used.
//  To only match CTLs without a signer, pSigner must be set to
//  CTL_FIND_NO_SIGNER_PTR.
//
//  The CTL_FIND_SAME_USAGE_FLAG can be set in dwFindFlags to
//  only match CTLs with the same usage identifiers. CTLs having additional
//  usage identifiers aren't matched. For example, if only "1.2.3" is specified
//  in CTL_FIND_USAGE_PARA, then, for a match, the CTL must only contain
//  "1.2.3" and not any additional usage identifers.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CTL_FIND_SUBJECT
//
//  Find a CTL having the specified subject. CertFindSubjectInCTL can be
//  called to get a pointer to the subject's entry in the CTL.  pUsagePara can
//  optionally be set to enable the above CTL_FIND_USAGE matching.
//
//  pvFindPara points to a CTL_FIND_SUBJECT_PARA data structure.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  Add the encoded CTL to the store according to the specified
//  disposition option.
//
//  Makes a copy of the encoded CTL before adding to the store.
//
//  dwAddDispostion specifies the action to take if the CTL
//  already exists in the store. See CertAddEncodedCertificateToStore for a
//  list of and actions taken.
//
//  Compares the CTL's SubjectUsage, ListIdentifier and any of its signers
//  to determine if the CTL already exists in the store.
//
//  ppCtlContext can be NULL, indicating the caller isn't interested
//  in getting the CTL_CONTEXT of the added or existing CTL.
//--------------------------------------------------------------------------
function CertAddEncodedCTLToStore(
  hCertStore: HCERTSTORE;
  dwMsgAndCertEncodingType: DWORD;
  pbCtlEncoded: PByte;
  cbCtlEncoded: DWORD;
  dwAddDisposition: DWORD;
  ppCtlContext: PPCTLContext): BOOL; winapi;
{$EXTERNALSYM CertAddEncodedCTLToStore}

//+-------------------------------------------------------------------------
//  Add the CTL context to the store according to the specified
//  disposition option.
//
//  In addition to the encoded CTL, the context's properties are
//  also copied.  Note, the CERT_KEY_CONTEXT_PROP_ID property (and its
//  CERT_KEY_PROV_HANDLE_PROP_ID or CERT_KEY_SPEC_PROP_ID) isn't copied.
//
//  Makes a copy of the encoded CTL before adding to the store.
//
//  dwAddDispostion specifies the action to take if the CTL
//  already exists in the store. See CertAddCertificateContextToStore for a
//  list of and actions taken.
//
//  Compares the CTL's SubjectUsage, ListIdentifier and any of its signers
//  to determine if the CTL already exists in the store.
//
//  ppStoreContext can be NULL, indicating the caller isn't interested
//  in getting the CTL_CONTEXT of the added or existing CTL.
//--------------------------------------------------------------------------
function CertAddCTLContextToStore(
  hCertStore: HCERTSTORE;
  pCtlContext: PCTLContext;
  dwAddDisposition: DWORD;
  ppStoreContext: PPCTLContext): BOOL; winapi;
{$EXTERNALSYM CertAddCTLContextToStore}

//+-------------------------------------------------------------------------
//  Serialize the CTL context's encoded CTL and its properties.
//--------------------------------------------------------------------------
function CertSerializeCTLStoreElement(
  pCtlContext: PCTLContext;
  dwFlags: DWORD;
  pbElement: PByte;
  var pcbElement: DWORD): BOOL; winapi;
{$EXTERNALSYM CertSerializeCTLStoreElement}

//+-------------------------------------------------------------------------
//  Delete the specified CTL from the store.
//
//  All subsequent gets for the CTL will fail. However,
//  memory allocated for the CTL isn't freed until all of its contexts
//  have also been freed.
//
//  The pCtlContext is obtained from a get or duplicate.
//
//  NOTE: the pCtlContext is always CertFreeCTLContext'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertDeleteCTLFromStore(
  pCtlContext: PCTLContext): BOOL; winapi;
{$EXTERNALSYM CertDeleteCTLFromStore}

function CertAddCertificateLinkToStore(
  hCertStore: HCERTSTORE;
  pCertContext: PCertContext;
  dwAddDisposition: DWORD;
  ppStoreContext: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CertAddCertificateLinkToStore}

function CertAddCRLLinkToStore(
  hCertStore: HCERTSTORE;
  pCrlContext: PCRLContext;
  dwAddDisposition: DWORD;
  ppStoreContext: PPCRLContext): BOOL; winapi;
{$EXTERNALSYM CertAddCRLLinkToStore}

function CertAddCTLLinkToStore(
  hCertStore: HCERTSTORE;
  pCtlContext: PCTLContext;
  dwAddDisposition: DWORD;
  ppStoreContext: PPCTLContext): BOOL; winapi;
{$EXTERNALSYM CertAddCTLLinkToStore}

function CertAddStoreToCollection(
  hCollectionStore: HCERTSTORE;
  hSiblingStore: HCERTSTORE;
  dwUpdateFlags: DWORD;
  dwPriority: DWORD): BOOL; winapi;
{$EXTERNALSYM CertAddStoreToCollection}

procedure CertRemoveStoreFromCollection(
  hCollectionStore: HCERTSTORE;
  hSiblingStore: HCERTSTORE); winapi;
{$EXTERNALSYM CertRemoveStoreFromCollection}

function CertControlStore(
  hCertStore: HCERTSTORE;
  dwFlags: DWORD;
  dwCtrlType: DWORD;
  pvCtrlPara: Pointer): BOOL; winapi;
{$EXTERNALSYM CertControlStore}

//+-------------------------------------------------------------------------
//  Certificate Store control types
//--------------------------------------------------------------------------
const
  CERT_STORE_CTRL_RESYNC             = 1;
  {$EXTERNALSYM CERT_STORE_CTRL_RESYNC}
  CERT_STORE_CTRL_NOTIFY_CHANGE      = 2;
  {$EXTERNALSYM CERT_STORE_CTRL_NOTIFY_CHANGE}
  CERT_STORE_CTRL_COMMIT             = 3;
  {$EXTERNALSYM CERT_STORE_CTRL_COMMIT}
  CERT_STORE_CTRL_AUTO_RESYNC        = 4;
  {$EXTERNALSYM CERT_STORE_CTRL_AUTO_RESYNC}
  CERT_STORE_CTRL_CANCEL_NOTIFY      = 5;
  {$EXTERNALSYM CERT_STORE_CTRL_CANCEL_NOTIFY}

  CERT_STORE_CTRL_INHIBIT_DUPLICATE_HANDLE_FLAG  = $1;
  {$EXTERNALSYM CERT_STORE_CTRL_INHIBIT_DUPLICATE_HANDLE_FLAG}

//+-------------------------------------------------------------------------
//  CERT_STORE_CTRL_RESYNC
//
//  Re-synchronize the store.
//
//  The pvCtrlPara points to the event HANDLE to be signaled on
//  the next store change. Normally, this would be the same
//  event HANDLE passed to CERT_STORE_CTRL_NOTIFY_CHANGE during initialization.
//
//  If pvCtrlPara is NULL, no events are re-armed.
//
//  By default the event HANDLE is DuplicateHandle'd.
//  CERT_STORE_CTRL_INHIBIT_DUPLICATE_HANDLE_FLAG can be set in dwFlags
//  to inhibit a DupicateHandle of the event HANDLE. If this flag
//  is set, then, CertControlStore(CERT_STORE_CTRL_CANCEL_NOTIFY) must be
//  called for this event HANDLE before closing the hCertStore.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_STORE_CTRL_NOTIFY_CHANGE
//
//  Signal the event when the underlying store is changed.
//
//  pvCtrlPara points to the event HANDLE to be signaled.
//
//  pvCtrlPara can be NULL to inform the store of a subsequent
//  CERT_STORE_CTRL_RESYNC and allow it to optimize by only doing a resync
//  if the store has changed. For the registry based stores, an internal
//  notify change event is created and registered to be signaled.
//
//  Recommend calling CERT_STORE_CTRL_NOTIFY_CHANGE once for each event to
//  be passed to CERT_STORE_CTRL_RESYNC. This should only happen after
//  the event has been created. Not after each time the event is signaled.
//
//  By default the event HANDLE is DuplicateHandle'd.
//  CERT_STORE_CTRL_INHIBIT_DUPLICATE_HANDLE_FLAG can be set in dwFlags
//  to inhibit a DupicateHandle of the event HANDLE. If this flag
//  is set, then, CertControlStore(CERT_STORE_CTRL_CANCEL_NOTIFY) must be
//  called for this event HANDLE before closing the hCertStore.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_STORE_CTRL_CANCEL_NOTIFY
//
//  Cancel notification signaling of the event HANDLE passed in a previous
//  CERT_STORE_CTRL_NOTIFY_CHANGE or CERT_STORE_CTRL_RESYNC.
//
//  pvCtrlPara points to the event HANDLE to be canceled.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_STORE_CTRL_AUTO_RESYNC
//
//  At the start of every enumeration or find store API call, check if the
//  underlying store has changed. If it has changed, re-synchronize.
//
//  This check is only done in the enumeration or find APIs when the
//  pPrevContext is NULL.
//
//  The pvCtrlPara isn't used and must be set to NULL.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_STORE_CTRL_COMMIT
//
//  If any changes have been to the cached store, they are committed to
//  persisted storage. If no changes have been made since the store was
//  opened or the last commit, this call is ignored. May also be ignored by
//  store providers that persist changes immediately.
//
//  CERT_STORE_CTRL_COMMIT_FORCE_FLAG can be set to force the store
//  to be committed even if it hasn't been touched.
//
//  CERT_STORE_CTRL_COMMIT_CLEAR_FLAG can be set to inhibit a commit on
//  store close.
//--------------------------------------------------------------------------
const
  CERT_STORE_CTRL_COMMIT_FORCE_FLAG  = $1;
  {$EXTERNALSYM CERT_STORE_CTRL_COMMIT_FORCE_FLAG}
  CERT_STORE_CTRL_COMMIT_CLEAR_FLAG  = $2;
  {$EXTERNALSYM CERT_STORE_CTRL_COMMIT_CLEAR_FLAG}


//+=========================================================================
//  Cert Store Property Defines and APIs
//==========================================================================

//+-------------------------------------------------------------------------
//  Store property IDs. This is a property applicable to the entire store.
//  Its not a property on an individual certificate, CRL or CTL context.
//
//  Currently, no store properties are persisted. (This differs from
//  most context properties which are persisted.)
//
//  See CertSetStoreProperty or CertGetStoreProperty for usage information.
//
//  Note, the range for predefined store properties should be outside
//  the range of predefined context properties. We will start at 4096.
//--------------------------------------------------------------------------
// certenrolld_begin -- CERT_*_PROP_ID
const
  CERT_STORE_LOCALIZED_NAME_PROP_ID  = $1000;
  {$EXTERNALSYM CERT_STORE_LOCALIZED_NAME_PROP_ID}
// certenrolld_end

//+-------------------------------------------------------------------------
//  Set a store property.
//
//  The type definition for pvData depends on the dwPropId value.
//      CERT_STORE_LOCALIZED_NAME_PROP_ID - localized name of the store.
//      pvData points to a CRYPT_DATA_BLOB. pbData is a pointer to a NULL
//      terminated unicode, wide character string.
//      cbData = (wcslen((LPWSTR) pbData) + 1) * sizeof(WCHAR).
//
//  For all the other PROP_IDs: an encoded PCRYPT_DATA_BLOB is passed in pvData.
//
//  If the property already exists, then, the old value is deleted and silently
//  replaced. Setting, pvData to NULL, deletes the property.
//--------------------------------------------------------------------------
function CertSetStoreProperty(
  hCertStore: HCERTSTORE;
  dwPropId: DWORD;
  dwFlags: DWORD;
  pvData: Pointer): BOOL; winapi;
{$EXTERNALSYM CertSetStoreProperty}

//+-------------------------------------------------------------------------
//  Get a store property.
//
//  The type definition for pvData depends on the dwPropId value.
//      CERT_STORE_LOCALIZED_NAME_PROP_ID - localized name of the store.
//      pvData points to a NULL terminated unicode, wide character string.
//      cbData = (wcslen((LPWSTR) pvData) + 1) * sizeof(WCHAR).
//
//  For all other PROP_IDs, pvData points to an array of bytes.
//
//  If the property doesn't exist, returns FALSE and sets LastError to
//  CRYPT_E_NOT_FOUND.
//--------------------------------------------------------------------------
function CertGetStoreProperty(
  hCertStore: HCERTSTORE;
  dwPropId: DWORD;
  pvData: Pointer;
  var pcbData: DWORD): BOOL; winapi;
{$EXTERNALSYM CertGetStoreProperty}

//+-------------------------------------------------------------------------
// If the callback returns FALSE, stops the sort. CertCreateContext
// will return FALSE and set last error to ERROR_CANCELLED if the sort
// was stopped.
//
// Where:
//  cbTotalEncoded  - total byte count of the encoded entries.
//  cbRemainEncoded - remaining byte count of the encoded entries.
//  cEntry          - running count of sorted entries
//  pvSort          - value passed in pCreatePara
//--------------------------------------------------------------------------
type
  PFN_CERT_CREATE_CONTEXT_SORT_FUNC = function(
    cbTotalEncoded: DWORD;
    cbRemainEncoded: DWORD;
    cEntry: DWORD;
    pvSort: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_CREATE_CONTEXT_SORT_FUNC}
  TFnCertCreateContextSortFunc = PFN_CERT_CREATE_CONTEXT_SORT_FUNC;

type
  PCertCreateContextPara = ^TCertCreateContextPara;
  _CERT_CREATE_CONTEXT_PARA = record
    cbSize: DWORD;
    pfnFree: TFnCryptFree;                    // OPTIONAL
    pvFree: Pointer;                          // OPTIONAL

    // Only applicable to CERT_STORE_CTL_CONTEXT when
    // CERT_CREATE_CONTEXT_SORTED_FLAG is set in dwFlags.
    pfnSort: TFnCertCreateContextSortFunc;    // OPTIONAL
    pvSort: Pointer;                          // OPTIONAL
  end;
  {$EXTERNALSYM _CERT_CREATE_CONTEXT_PARA}
  CERT_CREATE_CONTEXT_PARA = _CERT_CREATE_CONTEXT_PARA;
  {$EXTERNALSYM CERT_CREATE_CONTEXT_PARA}
  TCertCreateContextPara = _CERT_CREATE_CONTEXT_PARA;
  PCERT_CREATE_CONTEXT_PARA = PCertCreateContextPara;
  {$EXTERNALSYM PCERT_CREATE_CONTEXT_PARA}

//+-------------------------------------------------------------------------
//  Creates the specified context from the encoded bytes. The created
//  context isn't put in a store.
//
//  dwContextType values:
//      CERT_STORE_CERTIFICATE_CONTEXT
//      CERT_STORE_CRL_CONTEXT
//      CERT_STORE_CTL_CONTEXT
//
//  If CERT_CREATE_CONTEXT_NOCOPY_FLAG is set, the created context points
//  directly to the pbEncoded instead of an allocated copy. See flag
//  definition for more details.
//
//  If CERT_CREATE_CONTEXT_SORTED_FLAG is set, the context is created
//  with sorted entries. This flag may only be set for CERT_STORE_CTL_CONTEXT.
//  Setting this flag implicitly sets CERT_CREATE_CONTEXT_NO_HCRYPTMSG_FLAG and
//  CERT_CREATE_CONTEXT_NO_ENTRY_FLAG. See flag definition for
//  more details.
//
//  If CERT_CREATE_CONTEXT_NO_HCRYPTMSG_FLAG is set, the context is created
//  without creating a HCRYPTMSG handle for the context. This flag may only be
//  set for CERT_STORE_CTL_CONTEXT.  See flag definition for more details.
//
//  If CERT_CREATE_CONTEXT_NO_ENTRY_FLAG is set, the context is created
//  without decoding the entries. This flag may only be set for
//  CERT_STORE_CTL_CONTEXT.  See flag definition for more details.
//
//  If unable to decode and create the context, NULL is returned.
//  Otherwise, a pointer to a read only CERT_CONTEXT, CRL_CONTEXT or
//  CTL_CONTEXT is returned. The context must be freed by the appropriate
//  free context API. The context can be duplicated by calling the
//  appropriate duplicate context API.
//--------------------------------------------------------------------------
function CertCreateContext(
  dwContextType: DWORD;
  dwEncodingType: DWORD;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  dwFlags: DWORD;
  pCreatePara: PCertCreateContextPara): Pointer; winapi;
{$EXTERNALSYM CertCreateContext}

// When the following flag is set, the created context points directly to the
// pbEncoded instead of an allocated copy. If pCreatePara and
// pCreatePara->pfnFree are non-NULL, then, pfnFree is called to free
// the pbEncoded when the context is last freed. Otherwise, no attempt is
// made to free the pbEncoded. If pCreatePara->pvFree is non-NULL, then its
// passed to pfnFree instead of pbEncoded.
//
// Note, if CertCreateContext fails, pfnFree is still called.
const
  CERT_CREATE_CONTEXT_NOCOPY_FLAG    = $1;
  {$EXTERNALSYM CERT_CREATE_CONTEXT_NOCOPY_FLAG}

// When the following flag is set, a context with sorted entries is created.
// Currently only applicable to a CTL context.
//
// For CTLs: the cCTLEntry in the returned CTL_INFO is always
// 0. CertFindSubjectInSortedCTL and CertEnumSubjectInSortedCTL must be called
// to find or enumerate the CTL entries.
//
// The Sorted CTL TrustedSubjects extension isn't returned in the created
// context's CTL_INFO.
//
// pfnSort and pvSort can be set in the pCreatePara parameter to be called for
// each sorted entry. pfnSort can return FALSE to stop the sorting.
const
  CERT_CREATE_CONTEXT_SORTED_FLAG    = $2;
  {$EXTERNALSYM CERT_CREATE_CONTEXT_SORTED_FLAG}

// By default when a CTL context is created, a HCRYPTMSG handle to its
// SignedData message is created. This flag can be set to improve performance
// by not creating the HCRYPTMSG handle.
//
// This flag is only applicable to a CTL context.
const
  CERT_CREATE_CONTEXT_NO_HCRYPTMSG_FLAG  = $4;
  {$EXTERNALSYM CERT_CREATE_CONTEXT_NO_HCRYPTMSG_FLAG}

// By default when a CTL context is created, its entries are decoded.
// This flag can be set to improve performance by not decoding the
// entries.
//
// This flag is only applicable to a CTL context.
const
  CERT_CREATE_CONTEXT_NO_ENTRY_FLAG      = $8;
  {$EXTERNALSYM CERT_CREATE_CONTEXT_NO_ENTRY_FLAG}


//+=========================================================================
//  Certificate System Store Data Structures and APIs
//==========================================================================

//+-------------------------------------------------------------------------
//  System Store Information
//
//  Currently, no system store information is persisted.
//--------------------------------------------------------------------------
type
  PCertSystemStoreInfo = ^TCertSystemStoreInfo;
  _CERT_SYSTEM_STORE_INFO = record
    cbSize: DWORD;
  end;
  {$EXTERNALSYM _CERT_SYSTEM_STORE_INFO}
  CERT_SYSTEM_STORE_INFO = _CERT_SYSTEM_STORE_INFO;
  {$EXTERNALSYM CERT_SYSTEM_STORE_INFO}
  TCertSystemStoreInfo = _CERT_SYSTEM_STORE_INFO;
  PCERT_SYSTEM_STORE_INFO = PCertSystemStoreInfo;
  {$EXTERNALSYM PCERT_SYSTEM_STORE_INFO}

//+-------------------------------------------------------------------------
//  Physical Store Information
//
//  The Open fields are passed directly to CertOpenStore() to open
//  the physical store.
//
//  By default all system stores located in the registry have an
//  implicit SystemRegistry physical store that is opened. To disable the
//  opening of this store, the SystemRegistry
//  physical store corresponding to the System store must be registered with
//  CERT_PHYSICAL_STORE_OPEN_DISABLE_FLAG set in dwFlags. Alternatively,
//  a physical store with the name of ".Default" may be registered.
//
//  Depending on the store location and store name, additional predefined
//  physical stores may be opened. For example, system stores in
//  CURRENT_USER have the predefined physical store, .LocalMachine.
//  To disable the opening of these predefined physical stores, the
//  corresponding physical store must be registered with
//  CERT_PHYSICAL_STORE_OPEN_DISABLE_FLAG set in dwFlags.
//
//  The CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG must be set in dwFlags
//  to enable the adding of a context to the store.
//
//  When a system store is opened via the SERVICES or USERS store location,
//  the ServiceName\ is prepended to the OpenParameters
//  for CERT_SYSTEM_STORE_CURRENT_USER or CERT_SYSTEM_STORE_CURRENT_SERVICE
//  physical stores and the dwOpenFlags store location is changed to
//  CERT_SYSTEM_STORE_USERS or CERT_SYSTEM_STORE_SERVICES.
//
//  By default the SYSTEM, SYSTEM_REGISTRY and PHYSICAL provider
//  stores are also opened remotely when the outer system store is opened.
//  The CERT_PHYSICAL_STORE_REMOTE_OPEN_DISABLE_FLAG may be set in dwFlags
//  to disable remote opens.
//
//  When opened remotely, the \\ComputerName is implicitly prepended to the
//  OpenParameters for the SYSTEM, SYSTEM_REGISTRY and PHYSICAL provider types.
//  To also prepend the \\ComputerName to other provider types, set the
//  CERT_PHYSICAL_STORE_INSERT_COMPUTER_NAME_ENABLE_FLAG in dwFlags.
//
//  When the system store is opened, its physical stores are ordered
//  according to the dwPriority. A larger dwPriority indicates higher priority.
//--------------------------------------------------------------------------
type
  PCertPhysicalStoreInfo = ^TCertPhysicalStoreInfo;
  _CERT_PHYSICAL_STORE_INFO = record
    cbSize: DWORD;
    pszOpenStoreProvider: LPSTR;                 // REG_SZ
    dwOpenEncodingType: DWORD;                   // REG_DWORD
    dwOpenFlags: DWORD;                          // REG_DWORD
    OpenParameters: TCryptDataBlob;              // REG_BINARY
    dwFlags: DWORD;                              // REG_DWORD
    dwPriority: DWORD;                           // REG_DWORD
  end;
  {$EXTERNALSYM _CERT_PHYSICAL_STORE_INFO}
  CERT_PHYSICAL_STORE_INFO = _CERT_PHYSICAL_STORE_INFO;
  {$EXTERNALSYM CERT_PHYSICAL_STORE_INFO}
  TCertPhysicalStoreInfo = _CERT_PHYSICAL_STORE_INFO;
  PCERT_PHYSICAL_STORE_INFO = PCertPhysicalStoreInfo;
  {$EXTERNALSYM PCERT_PHYSICAL_STORE_INFO}

//+-------------------------------------------------------------------------
//  Physical Store Information dwFlags
//--------------------------------------------------------------------------
const
  CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG                    = $1;
  {$EXTERNALSYM CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG}
  CERT_PHYSICAL_STORE_OPEN_DISABLE_FLAG                  = $2;
  {$EXTERNALSYM CERT_PHYSICAL_STORE_OPEN_DISABLE_FLAG}
  CERT_PHYSICAL_STORE_REMOTE_OPEN_DISABLE_FLAG           = $4;
  {$EXTERNALSYM CERT_PHYSICAL_STORE_REMOTE_OPEN_DISABLE_FLAG}
  CERT_PHYSICAL_STORE_INSERT_COMPUTER_NAME_ENABLE_FLAG   = $8;
  {$EXTERNALSYM CERT_PHYSICAL_STORE_INSERT_COMPUTER_NAME_ENABLE_FLAG}


//+-------------------------------------------------------------------------
//  Register a system store.
//
//  The upper word of the dwFlags parameter is used to specify the location of
//  the system store.
//
//  If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvSystemStore
//  points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure. Otherwise,
//  pvSystemStore points to a null terminated UNICODE string.
//
//  The CERT_SYSTEM_STORE_SERVICES or CERT_SYSTEM_STORE_USERS system store
//  name must be prefixed with the ServiceName or UserName. For example,
//  "ServiceName\Trust".
//
//  Stores on remote computers can be registered for the
//  CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_SYSTEM_STORE_SERVICES,
//  CERT_SYSTEM_STORE_USERS, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
//  or CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
//  locations by prepending the computer name. For example, a remote
//  local machine store is registered via "\\ComputerName\Trust" or
//  "ComputerName\Trust". A remote service store is registered via
//  "\\ComputerName\ServiceName\Trust". The leading "\\" backslashes are
//  optional in the ComputerName.
//
//  Set CERT_STORE_CREATE_NEW_FLAG to cause a failure if the system store
//  already exists in the store location.
//--------------------------------------------------------------------------
function CertRegisterSystemStore(
  pvSystemStore: Pointer;
  dwFlags: DWORD;
  pStoreInfo: PCertSystemStoreInfo;
  pvReserved: Pointer): BOOL; winapi;
{$EXTERNALSYM CertRegisterSystemStore}

//+-------------------------------------------------------------------------
//  Register a physical store for the specified system store.
//
//  The upper word of the dwFlags parameter is used to specify the location of
//  the system store.
//
//  If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvSystemStore
//  points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure. Otherwise,
//  pvSystemStore points to a null terminated UNICODE string.
//
//  See CertRegisterSystemStore for details on prepending a ServiceName
//  and/or ComputerName to the system store name.
//
//  Set CERT_STORE_CREATE_NEW_FLAG to cause a failure if the physical store
//  already exists in the system store.
//--------------------------------------------------------------------------
function CertRegisterPhysicalStore(
  pvSystemStore: Pointer;
  dwFlags: DWORD;
  pwszStoreName: LPCWSTR;
  pStoreInfo: PCertPhysicalStoreInfo;
  pvReserved: Pointer): BOOL; winapi;
{$EXTERNALSYM CertRegisterPhysicalStore}

//+-------------------------------------------------------------------------
//  Unregister the specified system store.
//
//  The upper word of the dwFlags parameter is used to specify the location of
//  the system store.
//
//  If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvSystemStore
//  points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure. Otherwise,
//  pvSystemStore points to a null terminated UNICODE string.
//
//  See CertRegisterSystemStore for details on prepending a ServiceName
//  and/or ComputerName to the system store name.
//
//  CERT_STORE_DELETE_FLAG can optionally be set in dwFlags.
//--------------------------------------------------------------------------
function CertUnregisterSystemStore(
  pvSystemStore: Pointer;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM CertUnregisterSystemStore}

//+-------------------------------------------------------------------------
//  Unregister the physical store from the specified system store.
//
//  The upper word of the dwFlags parameter is used to specify the location of
//  the system store.
//
//  If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvSystemStore
//  points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure. Otherwise,
//  pvSystemStore points to a null terminated UNICODE string.
//
//  See CertRegisterSystemStore for details on prepending a ServiceName
//  and/or ComputerName to the system store name.
//
//  CERT_STORE_DELETE_FLAG can optionally be set in dwFlags.
//--------------------------------------------------------------------------
function CertUnregisterPhysicalStore(
  pvSystemStore: Pointer;
  dwFlags: DWORD;
  pwszStoreName: LPCWSTR): BOOL; winapi;
{$EXTERNALSYM CertUnregisterPhysicalStore}

//+-------------------------------------------------------------------------
//  Enum callbacks
//
//  The CERT_SYSTEM_STORE_LOCATION_MASK bits in the dwFlags parameter
//  specifies the location of the system store
//
//  If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvSystemStore
//  points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure. Otherwise,
//  pvSystemStore points to a null terminated UNICODE string.
//
//  The callback returns FALSE and sets LAST_ERROR to stop the enumeration.
//  The LAST_ERROR is returned to the caller of the enumeration.
//
//  The pvSystemStore passed to the callback has leading ComputerName and/or
//  ServiceName prefixes where appropriate.
//--------------------------------------------------------------------------

type
  PFN_CERT_ENUM_SYSTEM_STORE_LOCATION = function(
    pwszStoreLocation: LPCWSTR;
    dwFlags: DWORD;
    pvReserved: Pointer;
    pvArg: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_ENUM_SYSTEM_STORE_LOCATION}
  TFnCertEnumSystemStoreLocation = PFN_CERT_ENUM_SYSTEM_STORE_LOCATION;

type
  PFN_CERT_ENUM_SYSTEM_STORE = function(
    pvSystemStore: Pointer;
    dwFlags: DWORD;
    pStoreInfo: PCertSystemStoreInfo;
    pvReserved: Pointer;
    pvArg: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_ENUM_SYSTEM_STORE}
  TFnCertEnumSystemStore = PFN_CERT_ENUM_SYSTEM_STORE;

type
  PFN_CERT_ENUM_PHYSICAL_STORE = function(
    pvSystemStore: Pointer;
    dwFlags: DWORD;
    pwszStoreName: LPCWSTR;
    pStoreInfo: PCertPhysicalStoreInfo;
    pvReserved: Pointer;
    pvArg: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_ENUM_PHYSICAL_STORE}
  TFnCertEnumPhysicalStore = PFN_CERT_ENUM_PHYSICAL_STORE;

// In the PFN_CERT_ENUM_PHYSICAL_STORE callback the following flag is
// set if the physical store wasn't registered and is an implicitly created
// predefined physical store.
const
  CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG   = $1;
  {$EXTERNALSYM CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG}

// Names of implicitly created predefined physical stores
const
  CERT_PHYSICAL_STORE_DEFAULT_NAME             = '.Default';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_DEFAULT_NAME}
  CERT_PHYSICAL_STORE_GROUP_POLICY_NAME        = '.GroupPolicy';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_GROUP_POLICY_NAME}
  CERT_PHYSICAL_STORE_LOCAL_MACHINE_NAME       = '.LocalMachine';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_LOCAL_MACHINE_NAME}
  CERT_PHYSICAL_STORE_DS_USER_CERTIFICATE_NAME = '.UserCertificate';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_DS_USER_CERTIFICATE_NAME}
  CERT_PHYSICAL_STORE_LOCAL_MACHINE_GROUP_POLICY_NAME = '.LocalMachineGroupPolicy';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_LOCAL_MACHINE_GROUP_POLICY_NAME}
  CERT_PHYSICAL_STORE_ENTERPRISE_NAME          = '.Enterprise';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_ENTERPRISE_NAME}
  CERT_PHYSICAL_STORE_AUTH_ROOT_NAME           = '.AuthRoot';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_AUTH_ROOT_NAME}
  CERT_PHYSICAL_STORE_SMART_CARD_NAME          = '.SmartCard';
  {$EXTERNALSYM CERT_PHYSICAL_STORE_SMART_CARD_NAME}

//+-------------------------------------------------------------------------
//  Enumerate the system store locations.
//--------------------------------------------------------------------------
function CertEnumSystemStoreLocation(
  dwFlags: DWORD;
  pvArg: Pointer;
  pfnEnum: TFnCertEnumSystemStoreLocation): BOOL; winapi;
{$EXTERNALSYM CertEnumSystemStoreLocation}

//+-------------------------------------------------------------------------
//  Enumerate the system stores.
//
//  The upper word of the dwFlags parameter is used to specify the location of
//  the system store.
//
//  If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags,
//  pvSystemStoreLocationPara points to a CERT_SYSTEM_STORE_RELOCATE_PARA
//  data structure. Otherwise, pvSystemStoreLocationPara points to a null
//  terminated UNICODE string.
//
//  For CERT_SYSTEM_STORE_LOCAL_MACHINE,
//  CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY or
//  CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE, pvSystemStoreLocationPara can
//  optionally be set to a unicode computer name for enumerating local machine
//  stores on a remote computer. For example, "\\ComputerName" or
//  "ComputerName".  The leading "\\" backslashes are optional in the
//  ComputerName.
//
//  For CERT_SYSTEM_STORE_SERVICES or CERT_SYSTEM_STORE_USERS,
//  if pvSystemStoreLocationPara is NULL, then,
//  enumerates both the service/user names and the stores for each service/user
//  name. Otherwise, pvSystemStoreLocationPara is a unicode string specifying a
//  remote computer name and/or service/user name. For example:
//      "ServiceName"
//      "\\ComputerName" or "ComputerName\"
//      "ComputerName\ServiceName"
//  Note, if only the ComputerName is specified, then, it must have either
//  the leading "\\" backslashes or a trailing backslash. Otherwise, its
//  interpretted as the ServiceName or UserName.
//--------------------------------------------------------------------------
function CertEnumSystemStore(
  dwFlags: DWORD;
  pvSystemStoreLocationPara: Pointer;
  pvArg: Pointer;
  pfnEnum: TFnCertEnumSystemStore): BOOL; winapi;
{$EXTERNALSYM CertEnumSystemStore}

//+-------------------------------------------------------------------------
//  Enumerate the physical stores for the specified system store.
//
//  The upper word of the dwFlags parameter is used to specify the location of
//  the system store.
//
//  If CERT_SYSTEM_STORE_RELOCATE_FLAG is set in dwFlags, pvSystemStore
//  points to a CERT_SYSTEM_STORE_RELOCATE_PARA data structure. Otherwise,
//  pvSystemStore points to a null terminated UNICODE string.
//
//  See CertRegisterSystemStore for details on prepending a ServiceName
//  and/or ComputerName to the system store name.
//
//  If the system store location only supports system stores and doesn't
//  support physical stores, LastError is set to ERROR_CALL_NOT_IMPLEMENTED.
//--------------------------------------------------------------------------
function CertEnumPhysicalStore(
  pvSystemStore: Pointer;
  dwFlags: DWORD;
  pvArg: Pointer;
  pfnEnum: TFnCertEnumPhysicalStore): BOOL; winapi;
{$EXTERNALSYM CertEnumPhysicalStore}

//+-------------------------------------------------------------------------
//  Certificate System Store Installable Functions
//
//  The CERT_SYSTEM_STORE_LOCATION_MASK bits in the dwFlags parameter passed
//  to the CertOpenStore(for "System", "SystemRegistry" or "Physical"
//  Provider), CertRegisterSystemStore,
//  CertUnregisterSystemStore, CertEnumSystemStore, CertRegisterPhysicalStore,
//  CertUnregisterPhysicalStore and CertEnumPhysicalStore APIs is used as the
//  constant pszOID value passed to the OID installable functions.
//  Therefore, the pszOID is restricted to a constant <= (LPCSTR) 0x0FFF.
//
//  The EncodingType is 0.
//--------------------------------------------------------------------------

// Installable System Store Provider OID pszFuncNames.
const
  CRYPT_OID_OPEN_SYSTEM_STORE_PROV_FUNC    = 'CertDllOpenSystemStoreProv';
  {$EXTERNALSYM CRYPT_OID_OPEN_SYSTEM_STORE_PROV_FUNC}
  CRYPT_OID_REGISTER_SYSTEM_STORE_FUNC     = 'CertDllRegisterSystemStore';
  {$EXTERNALSYM CRYPT_OID_REGISTER_SYSTEM_STORE_FUNC}
  CRYPT_OID_UNREGISTER_SYSTEM_STORE_FUNC   = 'CertDllUnregisterSystemStore';
  {$EXTERNALSYM CRYPT_OID_UNREGISTER_SYSTEM_STORE_FUNC}
  CRYPT_OID_ENUM_SYSTEM_STORE_FUNC         = 'CertDllEnumSystemStore';
  {$EXTERNALSYM CRYPT_OID_ENUM_SYSTEM_STORE_FUNC}
  CRYPT_OID_REGISTER_PHYSICAL_STORE_FUNC   = 'CertDllRegisterPhysicalStore';
  {$EXTERNALSYM CRYPT_OID_REGISTER_PHYSICAL_STORE_FUNC}
  CRYPT_OID_UNREGISTER_PHYSICAL_STORE_FUNC = 'CertDllUnregisterPhysicalStore';
  {$EXTERNALSYM CRYPT_OID_UNREGISTER_PHYSICAL_STORE_FUNC}
  CRYPT_OID_ENUM_PHYSICAL_STORE_FUNC       = 'CertDllEnumPhysicalStore';
  {$EXTERNALSYM CRYPT_OID_ENUM_PHYSICAL_STORE_FUNC}

// CertDllOpenSystemStoreProv has the same function signature as the
// installable "CertDllOpenStoreProv" function. See CertOpenStore for
// more details.

// CertDllRegisterSystemStore has the same function signature as
// CertRegisterSystemStore.
//
// The "SystemStoreLocation" REG_SZ value must also be set for registered
// CertDllEnumSystemStore OID functions.
const
  CRYPT_OID_SYSTEM_STORE_LOCATION_VALUE_NAME = 'SystemStoreLocation';
  {$EXTERNALSYM CRYPT_OID_SYSTEM_STORE_LOCATION_VALUE_NAME}

// The remaining Register, Enum and Unregister OID installable functions
// have the same signature as their Cert Store API counterpart.


//+=========================================================================
//  Enhanced Key Usage Helper Functions
//==========================================================================

//+-------------------------------------------------------------------------
//  Get the enhanced key usage extension or property from the certificate
//  and decode.
//
//  If the CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG is set, then, only get the
//  extension.
//
//  If the CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG is set, then, only get the
//  property.
//--------------------------------------------------------------------------
function CertGetEnhancedKeyUsage(
  pCertContext: PCertContext;
  dwFlags: DWORD;
  pUsage: PCertEnhKeyUsage;
  var pcbUsage: DWORD): BOOL; winapi;
{$EXTERNALSYM CertGetEnhancedKeyUsage}

//+-------------------------------------------------------------------------
//  Set the enhanced key usage property for the certificate.
//--------------------------------------------------------------------------
function CertSetEnhancedKeyUsage(
  pCertContext: PCertContext;
  pUsage: PCertEnhKeyUsage): BOOL; winapi;
{$EXTERNALSYM CertSetEnhancedKeyUsage}

//+-------------------------------------------------------------------------
//  Add the usage identifier to the certificate's enhanced key usage property.
//--------------------------------------------------------------------------
function CertAddEnhancedKeyUsageIdentifier(
  pCertContext: PCertContext;
  pszUsageIdentifier: LPCSTR): BOOL; winapi;
{$EXTERNALSYM CertAddEnhancedKeyUsageIdentifier}

//+-------------------------------------------------------------------------
//  Remove the usage identifier from the certificate's enhanced key usage
//  property.
//--------------------------------------------------------------------------
function CertRemoveEnhancedKeyUsageIdentifier(
  pCertContext: PCertContext;
  pszUsageIdentifier: LPCSTR): BOOL; winapi;
{$EXTERNALSYM CertRemoveEnhancedKeyUsageIdentifier}

//+---------------------------------------------------------------------------
//
//
//  Takes an array of certs and returns an array of usages
//  which consists of the intersection of the valid usages for each cert.
//  If each cert is good for all possible usages then the cNumOIDs is set to -1.
//
//----------------------------------------------------------------------------
function CertGetValidUsages(
  cCerts: DWORD;
  var rghCerts: PCertContext;
  out cNumOIDs: Integer;
  out rghOIDs: LPSTR;
  var pcbOIDs: DWORD): BOOL; winapi;
{$EXTERNALSYM CertGetValidUsages}

//+=========================================================================
//  Cryptographic Message helper functions for verifying and signing a
//  CTL.
//==========================================================================

//+-------------------------------------------------------------------------
//  Get and verify the signer of a cryptographic message.
//
//  To verify a CTL, the hCryptMsg is obtained from the CTL_CONTEXT's
//  hCryptMsg field.
//
//  If CMSG_TRUSTED_SIGNER_FLAG is set, then, treat the Signer stores as being
//  trusted and only search them to find the certificate corresponding to the
//  signer's issuer and serial number.  Otherwise, the SignerStores are
//  optionally provided to supplement the message's store of certificates.
//  If a signer certificate is found, its public key is used to verify
//  the message signature. The CMSG_SIGNER_ONLY_FLAG can be set to
//  return the signer without doing the signature verify.
//
//  If CMSG_USE_SIGNER_INDEX_FLAG is set, then, only get the signer specified
//  by *pdwSignerIndex. Otherwise, iterate through all the signers
//  until a signer verifies or no more signers.
//
//  For a verified signature, *ppSigner is updated with certificate context
//  of the signer and *pdwSignerIndex is updated with the index of the signer.
//  ppSigner and/or pdwSignerIndex can be NULL, indicating the caller isn't
//  interested in getting the CertContext and/or index of the signer.
//--------------------------------------------------------------------------
function CryptMsgGetAndVerifySigner(
  hCryptMsg: HCRYPTMSG;
  cSignerStore: DWORD;
  var rghSignerStore: HCERTSTORE;
  dwFlags: DWORD;
  ppSigner: PPCertContext;
  pdwSignerIndex: PDWORD): BOOL; winapi;
{$EXTERNALSYM CryptMsgGetAndVerifySigner}

const
  CMSG_TRUSTED_SIGNER_FLAG           = $1;
  {$EXTERNALSYM CMSG_TRUSTED_SIGNER_FLAG}
  CMSG_SIGNER_ONLY_FLAG              = $2;
  {$EXTERNALSYM CMSG_SIGNER_ONLY_FLAG}
  CMSG_USE_SIGNER_INDEX_FLAG         = $4;
  {$EXTERNALSYM CMSG_USE_SIGNER_INDEX_FLAG}


//+-------------------------------------------------------------------------
//  Sign an encoded CTL.
//
//  The pbCtlContent can be obtained via a CTL_CONTEXT's pbCtlContent
//  field or via a CryptEncodeObject(PKCS_CTL or PKCS_SORTED_CTL).
//
//  CMSG_CMS_ENCAPSULATED_CTL_FLAG can be set to encode a CMS compatible
//  V3 SignedData message.
//--------------------------------------------------------------------------
function CryptMsgSignCTL(
  dwMsgEncodingType: DWORD;
  pbCtlContent: PByte;
  cbCtlContent: DWORD;
  pSignInfo: PCMsgSignedEncodeInfo;
  dwFlags: DWORD;
  pbEncoded: PByte;
  var pcbEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptMsgSignCTL}

// When set, CTL inner content is encapsulated within an OCTET STRING
const
  CMSG_CMS_ENCAPSULATED_CTL_FLAG = $00008000;
  {$EXTERNALSYM CMSG_CMS_ENCAPSULATED_CTL_FLAG}

//+-------------------------------------------------------------------------
//  Encode the CTL and create a signed message containing the encoded CTL.
//
//  Set CMSG_ENCODE_SORTED_CTL_FLAG if the CTL entries are to be sorted
//  before encoding. This flag should be set, if the
//  CertFindSubjectInSortedCTL or CertEnumSubjectInSortedCTL APIs will
//  be called. If the identifier for the CTL entries is a hash, such as,
//  MD5 or SHA1, then, CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG should
//  also be set.
//
//  CMSG_CMS_ENCAPSULATED_CTL_FLAG can be set to encode a CMS compatible
//  V3 SignedData message.
//--------------------------------------------------------------------------
function CryptMsgEncodeAndSignCTL(
  dwMsgEncodingType: DWORD;
  pCtlInfo: PCTLInfo;
  pSignInfo: PCMsgSignedEncodeInfo;
  dwFlags: DWORD;
  pbEncoded: PByte;
  var pcbEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptMsgEncodeAndSignCTL}

//  The following flag is set if the CTL is to be encoded with sorted
//  trusted subjects and the szOID_SORTED_CTL extension is inserted containing
//  sorted offsets to the encoded subjects.
const
  CMSG_ENCODE_SORTED_CTL_FLAG                    = $1;
  {$EXTERNALSYM CMSG_ENCODE_SORTED_CTL_FLAG}

//  If the above sorted flag is set, then, the following flag should also
//  be set if the identifier for the TrustedSubjects is a hash,
//  such as, MD5 or SHA1.
const
  CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG     = $2;
  {$EXTERNALSYM CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG}


//+-------------------------------------------------------------------------
//  Returns TRUE if the SubjectIdentifier exists in the CTL. Optionally
//  returns a pointer to and byte count of the Subject's encoded attributes.
//--------------------------------------------------------------------------
function CertFindSubjectInSortedCTL(
  pSubjectIdentifier: PCryptDataBlob;
  pCtlContext: PCTLContext;
  dwFlags: DWORD;
  pvReserved: Pointer;
  pEncodedAttributes: PCryptDERBlob): BOOL; winapi;
{$EXTERNALSYM CertFindSubjectInSortedCTL}

//+-------------------------------------------------------------------------
//  Enumerates through the sequence of TrustedSubjects in a CTL context
//  created with CERT_CREATE_CONTEXT_SORTED_FLAG set.
//
//  To start the enumeration, *ppvNextSubject must be NULL. Upon return,
//  *ppvNextSubject is updated to point to the next TrustedSubject in
//  the encoded sequence.
//
//  Returns FALSE for no more subjects or invalid arguments.
//
//  Note, the returned DER_BLOBs point directly into the encoded
//  bytes (not allocated, and must not be freed).
//--------------------------------------------------------------------------
function CertEnumSubjectInSortedCTL(
  pCtlContext: PCTLContext;
  var ppvNextSubject: Pointer;
  pSubjectIdentifier: PCryptDERBlob;
  pEncodedAttributes: PCryptDERBlob): BOOL; winapi;
{$EXTERNALSYM CertEnumSubjectInSortedCTL}

//+=========================================================================
//  Certificate Verify CTL Usage Data Structures and APIs
//==========================================================================

type
  PCTLVerifyUsagePara = ^TCTLVerifyUsagePara;
  _CTL_VERIFY_USAGE_PARA = record
    cbSize: DWORD;
    ListIdentifier: TCryptDataBlob;             // OPTIONAL
    cCtlStore: DWORD;
    rghCtlStore: ^HCERTSTORE;                   // OPTIONAL
    cSignerStore: DWORD;
    rghSignerStore: ^HCERTSTORE;                // OPTIONAL
  end;
  {$EXTERNALSYM _CTL_VERIFY_USAGE_PARA}
  CTL_VERIFY_USAGE_PARA = _CTL_VERIFY_USAGE_PARA;
  {$EXTERNALSYM CTL_VERIFY_USAGE_PARA}
  TCTLVerifyUsagePara = _CTL_VERIFY_USAGE_PARA;
  PCTL_VERIFY_USAGE_PARA = PCTLVerifyUsagePara;
  {$EXTERNALSYM PCTL_VERIFY_USAGE_PARA}

type
  PCTLVerfiyUsageStatus = ^TCTLVerfiyUsageStatus;
  _CTL_VERIFY_USAGE_STATUS = record
    cbSize: DWORD;
    dwError: DWORD;
    dwFlags: DWORD;
    ppCtl: ^PCTLContext;                        // IN OUT OPTIONAL
    dwCtlEntryIndex: DWORD;
    ppSigner: ^PCertContext;                    // IN OUT OPTIONAL
    dwSignerIndex: DWORD;
  end;
  {$EXTERNALSYM _CTL_VERIFY_USAGE_STATUS}
  CTL_VERIFY_USAGE_STATUS = _CTL_VERIFY_USAGE_STATUS;
  {$EXTERNALSYM CTL_VERIFY_USAGE_STATUS}
  TCTLVerfiyUsageStatus = _CTL_VERIFY_USAGE_STATUS;
  PCTL_VERIFY_USAGE_STATUS = PCTLVerfiyUsageStatus;
  {$EXTERNALSYM PCTL_VERIFY_USAGE_STATUS}

const
  CERT_VERIFY_INHIBIT_CTL_UPDATE_FLAG    = $1;
  {$EXTERNALSYM CERT_VERIFY_INHIBIT_CTL_UPDATE_FLAG}
  CERT_VERIFY_TRUSTED_SIGNERS_FLAG       = $2;
  {$EXTERNALSYM CERT_VERIFY_TRUSTED_SIGNERS_FLAG}
  CERT_VERIFY_NO_TIME_CHECK_FLAG         = $4;
  {$EXTERNALSYM CERT_VERIFY_NO_TIME_CHECK_FLAG}
  CERT_VERIFY_ALLOW_MORE_USAGE_FLAG      = $8;
  {$EXTERNALSYM CERT_VERIFY_ALLOW_MORE_USAGE_FLAG}

  CERT_VERIFY_UPDATED_CTL_FLAG           = $1;
  {$EXTERNALSYM CERT_VERIFY_UPDATED_CTL_FLAG}

//+-------------------------------------------------------------------------
//  Verify that a subject is trusted for the specified usage by finding a
//  signed and time valid CTL with the usage identifiers and containing the
//  the subject. A subject can be identified by either its certificate context
//  or any identifier such as its SHA1 hash.
//
//  See CertFindSubjectInCTL for definition of dwSubjectType and pvSubject
//  parameters.
//
//  Via pVerifyUsagePara, the caller can specify the stores to be searched
//  to find the CTL. The caller can also specify the stores containing
//  acceptable CTL signers. By setting the ListIdentifier, the caller
//  can also restrict to a particular signer CTL list.
//
//  Via pVerifyUsageStatus, the CTL containing the subject, the subject's
//  index into the CTL's array of entries, and the signer of the CTL
//  are returned. If the caller is not interested, ppCtl and ppSigner can be set
//  to NULL. Returned contexts must be freed via the store's free context APIs.
//
//  If the CERT_VERIFY_INHIBIT_CTL_UPDATE_FLAG isn't set, then, a time
//  invalid CTL in one of the CtlStores may be replaced. When replaced, the
//  CERT_VERIFY_UPDATED_CTL_FLAG is set in pVerifyUsageStatus->dwFlags.
//
//  If the CERT_VERIFY_TRUSTED_SIGNERS_FLAG is set, then, only the
//  SignerStores specified in pVerifyUsageStatus are searched to find
//  the signer. Otherwise, the SignerStores provide additional sources
//  to find the signer's certificate.
//
//  If CERT_VERIFY_NO_TIME_CHECK_FLAG is set, then, the CTLs aren't checked
//  for time validity.
//
//  If CERT_VERIFY_ALLOW_MORE_USAGE_FLAG is set, then, the CTL may contain
//  additional usage identifiers than specified by pSubjectUsage. Otherwise,
//  the found CTL will contain the same usage identifers and no more.
//
//  CertVerifyCTLUsage will be implemented as a dispatcher to OID installable
//  functions. First, it will try to find an OID function matching the first
//  usage object identifier in the pUsage sequence. Next, it will dispatch
//  to the default CertDllVerifyCTLUsage functions.
//
//  If the subject is trusted for the specified usage, then, TRUE is
//  returned. Otherwise, FALSE is returned with dwError set to one of the
//  following:
//      CRYPT_E_NO_VERIFY_USAGE_DLL
//      CRYPT_E_NO_VERIFY_USAGE_CHECK
//      CRYPT_E_VERIFY_USAGE_OFFLINE
//      CRYPT_E_NOT_IN_CTL
//      CRYPT_E_NO_TRUSTED_SIGNER
//--------------------------------------------------------------------------
function CertVerifyCTLUsage(
  dwEncodingType: DWORD;
  dwSubjectType: DWORD;
  pvSubject: Pointer;
  pSubjectUsage: PCTLUsage;
  dwFlags: DWORD;
  pVerifyUsagePara: PCTLVerifyUsagePara;
  pVerifyUsageStatus: PCTLVerfiyUsageStatus): BOOL; winapi;
{$EXTERNALSYM CertVerifyCTLUsage}

//+=========================================================================
//  Certificate Revocation Data Structures and APIs
//==========================================================================

//+-------------------------------------------------------------------------
//  This data structure is updated by a CRL revocation type handler
//  with the base and possibly the delta CRL used.
//--------------------------------------------------------------------------
type
  PCertRevocationCRLInfo = ^TCertRevocationCRLInfo;
  _CERT_REVOCATION_CRL_INFO = record
    cbSize: DWORD;
    pBaseCrlContext: PCRLContext;
    pDeltaCrlContext: PCRLContext;

    // When revoked, points to entry in either of the above CRL contexts.
    // Don't free.
    pCrlEntry: PCRLEntry;
    fDeltaCrlEntry: BOOL;                     // TRUE if in pDeltaCrlContext
  end;
  {$EXTERNALSYM _CERT_REVOCATION_CRL_INFO}
  CERT_REVOCATION_CRL_INFO = _CERT_REVOCATION_CRL_INFO;
  {$EXTERNALSYM CERT_REVOCATION_CRL_INFO}
  TCertRevocationCRLInfo = _CERT_REVOCATION_CRL_INFO;
  PCERT_REVOCATION_CRL_INFO = PCertRevocationCRLInfo;
  {$EXTERNALSYM PCERT_REVOCATION_CRL_INFO}

type
  HCERTCHAINENGINE = THandle;
  {$EXTERNALSYM HCERTCHAINENGINE}
//+-------------------------------------------------------------------------
//  This data structure is optionally pointed to by the pChainPara field
//  in the CERT_REVOCATION_PARA and CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO
//  data structures.
//
//  Its struct definition follows the CertGetCertificateChain() API
//  definition below.
//--------------------------------------------------------------------------
type
  PCertRevocationChainPara = ^TCertRevocationChainPara;
  _CERT_REVOCATION_CHAIN_PARA = record
    cbSize: DWORD;
    hChainEngine: HCERTCHAINENGINE;
    hAdditionalStore: HCERTSTORE;
    dwChainFlags: DWORD;
    dwUrlRetrievalTimeout: DWORD;     // milliseconds
    pftCurrentTime: PFileTime;
    pftCacheResync: PFileTime;

    // Max size of the URL object to download, in bytes.
    // 0 value means no limit.
    cbMaxUrlRetrievalByteCount: DWORD;
  end;
  {$EXTERNALSYM _CERT_REVOCATION_CHAIN_PARA}
  CERT_REVOCATION_CHAIN_PARA = _CERT_REVOCATION_CHAIN_PARA;
  {$EXTERNALSYM CERT_REVOCATION_CHAIN_PARA}
  TCertRevocationChainPara = _CERT_REVOCATION_CHAIN_PARA;
  PCERT_REVOCATION_CHAIN_PARA = PCertRevocationChainPara;
  {$EXTERNALSYM PCERT_REVOCATION_CHAIN_PARA}

//+-------------------------------------------------------------------------
//  The following data structure may be passed to CertVerifyRevocation to
//  assist in finding the issuer of the context to be verified.
//
//  When pIssuerCert is specified, pIssuerCert is the issuer of
//  rgpvContext[cContext - 1].
//
//  When cCertStore and rgCertStore are specified, these stores may contain
//  an issuer certificate.
//
//  When hCrlStore is specified then a handler which uses CRLs can search this
//  store for them
//
//  When pftTimeToUse is specified then the handler (if possible) must determine
//  revocation status relative to the time given otherwise the answer may be
//  independent of time or relative to current time
//--------------------------------------------------------------------------
type
  PCertRevocationPara = ^TCertRevocationPara;
  _CERT_REVOCATION_PARA = record
    cbSize: DWORD;
    pIssuerCert: PCertContext;
    cCertStore: DWORD;
    rgCertStore: ^HCERTSTORE;
    hCrlStore: HCERTSTORE;
    pftTimeToUse: PFileTime;

//{$IFDEF CERT_REVOCATION_PARA_HAS_EXTRA_FIELDS}
    // Note, if you #define CERT_REVOCATION_PARA_HAS_EXTRA_FIELDS, then, you
    // must zero all unused fields in this data structure.
    // More fields could be added in a future release.

    // 0 uses revocation handler's default timeout.
    dwUrlRetrievalTimeout: DWORD;                       // milliseconds

    // When set, checks and attempts to retrieve a CRL where
    // ThisUpdate >= (CurrentTime - dwFreshnessTime). Otherwise, defaults
    // to using the CRL's NextUpdate.
    fCheckFreshnessTime: BOOL;
    dwFreshnessTime: DWORD;                             // seconds

    // If NULL, revocation handler gets the current time
    pftCurrentTime: PFileTime;

    // If nonNULL, a CRL revocation type handler updates with the base and
    // possibly the delta CRL used. Note, *pCrlInfo must be initialized
    // by the caller. Any nonNULL CRL contexts are freed. Any updated
    // CRL contexts must be freed by the caller.
    //
    // The CRL info is only applicable to the last context checked. If
    // interested in this information, then, CertVerifyRevocation should be
    // called with cContext = 1.
    pCrlInfo: PCertRevocationCRLInfo;

    // If nonNULL, any cached information before this time is considered
    // time invalid and forces a wire retrieval.
    pftCacheResync: PFileTime;

    // If nonNULL, CertGetCertificateChain() parameters used by the caller.
    // Enables independent OCSP signer certificate chain verification.
    pChainPara: PCertRevocationChainPara;
//{$ENDIF}
  end;
  {$EXTERNALSYM _CERT_REVOCATION_PARA}
  CERT_REVOCATION_PARA = _CERT_REVOCATION_PARA;
  {$EXTERNALSYM CERT_REVOCATION_PARA}
  TCertRevocationPara = _CERT_REVOCATION_PARA;
  PCERT_REVOCATION_PARA = PCertRevocationPara;
  {$EXTERNALSYM PCERT_REVOCATION_PARA}

//+-------------------------------------------------------------------------
//  The following data structure is returned by CertVerifyRevocation to
//  specify the status of the revoked or unchecked context. Review the
//  following CertVerifyRevocation comments for details.
//
//  Upon input to CertVerifyRevocation, cbSize must be set to a size
//  >= (offsetof(CERT_REVOCATION_STATUS, dwReason) + sizeof(DWORD) ).
//  Otherwise, CertVerifyRevocation returns FALSE and sets LastError to
//  E_INVALIDARG.
//
//  Upon input to the installed or registered CRYPT_OID_VERIFY_REVOCATION_FUNC
//  functions, the dwIndex, dwError and dwReason have been zero'ed.
//  If present, fHasFreshnessTime and dwFreshnessTime have been zero'ed.
//--------------------------------------------------------------------------
type
  PCertRevocationStatus = ^TCertRevocationStatus;
  _CERT_REVOCATION_STATUS = record
    cbSize: DWORD;
    dwIndex: DWORD;
    dwError: DWORD;
    dwReason: DWORD;

    // Depending on cbSize, the following fields may optionally be returned.

    // The Freshness time is only applicable to the last context checked. If
    // interested in this information, then, CertVerifyRevocation should be
    // called with cContext = 1.
    //
    // fHasFreshnessTime is only set if we are able to retrieve revocation
    // information. For a CRL its CurrentTime - ThisUpdate.
    fHasFreshnessTime: BOOL;
    dwFreshnessTime: DWORD;                       // seconds
  end;
  {$EXTERNALSYM _CERT_REVOCATION_STATUS}
  CERT_REVOCATION_STATUS = _CERT_REVOCATION_STATUS;
  {$EXTERNALSYM CERT_REVOCATION_STATUS}
  TCertRevocationStatus = _CERT_REVOCATION_STATUS;
  PCERT_REVOCATION_STATUS = PCertRevocationStatus;
  {$EXTERNALSYM PCERT_REVOCATION_STATUS}

//+-------------------------------------------------------------------------
//  Verifies the array of contexts for revocation. The dwRevType parameter
//  indicates the type of the context data structure passed in rgpvContext.
//  Currently only the revocation of certificates is defined.
//
//  If the CERT_VERIFY_REV_CHAIN_FLAG flag is set, then, CertVerifyRevocation
//  is verifying a chain of certs where, rgpvContext[i + 1] is the issuer
//  of rgpvContext[i]. Otherwise, CertVerifyRevocation makes no assumptions
//  about the order of the contexts.
//
//  To assist in finding the issuer, the pRevPara may optionally be set. See
//  the CERT_REVOCATION_PARA data structure for details.
//
//  The contexts must contain enough information to allow the
//  installable or registered revocation DLLs to find the revocation server. For
//  certificates, this information would normally be conveyed in an
//  extension such as the IETF's AuthorityInfoAccess extension.
//
//  CertVerifyRevocation returns TRUE if all of the contexts were successfully
//  checked and none were revoked. Otherwise, returns FALSE and updates the
//  returned pRevStatus data structure as follows:
//    dwIndex
//      Index of the first context that was revoked or unable to
//      be checked for revocation
//    dwError
//      Error status. LastError is also set to this error status.
//      dwError can be set to one of the following error codes defined
//      in winerror.h:
//        ERROR_SUCCESS - good context
//        CRYPT_E_REVOKED - context was revoked. dwReason contains the
//           reason for revocation
//        CRYPT_E_REVOCATION_OFFLINE - unable to connect to the
//           revocation server
//        CRYPT_E_NOT_IN_REVOCATION_DATABASE - the context to be checked
//           was not found in the revocation server's database.
//        CRYPT_E_NO_REVOCATION_CHECK - the called revocation function
//           wasn't able to do a revocation check on the context
//        CRYPT_E_NO_REVOCATION_DLL - no installed or registered Dll was
//           found to verify revocation
//    dwReason
//      The dwReason is currently only set for CRYPT_E_REVOKED and contains
//      the reason why the context was revoked. May be one of the following
//      CRL reasons defined by the CRL Reason Code extension ("2.5.29.21")
//          CRL_REASON_UNSPECIFIED              0
//          CRL_REASON_KEY_COMPROMISE           1
//          CRL_REASON_CA_COMPROMISE            2
//          CRL_REASON_AFFILIATION_CHANGED      3
//          CRL_REASON_SUPERSEDED               4
//          CRL_REASON_CESSATION_OF_OPERATION   5
//          CRL_REASON_CERTIFICATE_HOLD         6
//
//  For each entry in rgpvContext, CertVerifyRevocation iterates
//  through the CRYPT_OID_VERIFY_REVOCATION_FUNC
//  function set's list of installed DEFAULT functions.
//  CryptGetDefaultOIDFunctionAddress is called with pwszDll = NULL. If no
//  installed functions are found capable of doing the revocation verification,
//  CryptVerifyRevocation iterates through CRYPT_OID_VERIFY_REVOCATION_FUNC's
//  list of registered DEFAULT Dlls. CryptGetDefaultOIDDllList is called to
//  get the list. CryptGetDefaultOIDFunctionAddress is called to load the Dll.
//
//  The called functions have the same signature as CertVerifyRevocation. A
//  called function returns TRUE if it was able to successfully check all of
//  the contexts and none were revoked. Otherwise, the called function returns
//  FALSE and updates pRevStatus. dwIndex is set to the index of
//  the first context that was found to be revoked or unable to be checked.
//  dwError and LastError are updated. For CRYPT_E_REVOKED, dwReason
//  is updated. Upon input to the called function, dwIndex, dwError and
//  dwReason have been zero'ed. cbSize has been checked to be >=
//  sizeof(CERT_REVOCATION_STATUS).
//
//  If the called function returns FALSE, and dwError isn't set to
//  CRYPT_E_REVOKED, then, CertVerifyRevocation either continues on to the
//  next DLL in the list for a returned dwIndex of 0 or for a returned
//  dwIndex > 0, restarts the process of finding a verify function by
//  advancing the start of the context array to the returned dwIndex and
//  decrementing the count of remaining contexts.
//--------------------------------------------------------------------------
function CertVerifyRevocation(
  dwEncodingType: DWORD;
  dwRevType: DWORD;
  cContext: DWORD;
  var rgpvContext: Pointer;
  dwFlags: DWORD;
  pRevPara: PCertRevocationPara;
  pRevStatus: PCertRevocationStatus): BOOL; winapi;
{$EXTERNALSYM CertVerifyRevocation}

//+-------------------------------------------------------------------------
//  Revocation types
//--------------------------------------------------------------------------
const
  CERT_CONTEXT_REVOCATION_TYPE       = 1;
  {$EXTERNALSYM CERT_CONTEXT_REVOCATION_TYPE}

//+-------------------------------------------------------------------------
//  When the following flag is set, rgpvContext[] consists of a chain
//  of certificates, where rgpvContext[i + 1] is the issuer of rgpvContext[i].
//--------------------------------------------------------------------------
const
  CERT_VERIFY_REV_CHAIN_FLAG                     = $00000001;
  {$EXTERNALSYM CERT_VERIFY_REV_CHAIN_FLAG}

//+-------------------------------------------------------------------------
// CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION prevents the revocation handler from
// accessing any network based resources for revocation checking
//--------------------------------------------------------------------------
const
  CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION        = $00000002;
  {$EXTERNALSYM CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION}

//+-------------------------------------------------------------------------
//  By default, the dwUrlRetrievalTimeout in pRevPara is the timeout used
//  for each URL wire retrieval. When the following flag is set,
//  dwUrlRetrievalTimeout is the accumulative timeout across all URL wire
//  retrievals.
//--------------------------------------------------------------------------
const
  CERT_VERIFY_REV_ACCUMULATIVE_TIMEOUT_FLAG      = $00000004;
  {$EXTERNALSYM CERT_VERIFY_REV_ACCUMULATIVE_TIMEOUT_FLAG}

//+-------------------------------------------------------------------------
//  When the following flag is set, only OCSP responses are used for
//  doing revocation checking. If the certificate doesn't have any
//  OCSP AIA URLs, dwError is set to CRYPT_E_NOT_IN_REVOCATION_DATABASE.
//--------------------------------------------------------------------------
const
  CERT_VERIFY_REV_SERVER_OCSP_FLAG               = $00000008;
  {$EXTERNALSYM CERT_VERIFY_REV_SERVER_OCSP_FLAG}

//+-------------------------------------------------------------------------
//  When the following flag is set, only the OCSP AIA URL is used if
//  present in the subject. If the subject doesn't have an OCSP AIA URL, then,
//  the CDP URLs are used.
//--------------------------------------------------------------------------
const
  CERT_VERIFY_REV_NO_OCSP_FAILOVER_TO_CRL_FLAG   = $00000010;
  {$EXTERNALSYM CERT_VERIFY_REV_NO_OCSP_FAILOVER_TO_CRL_FLAG}


//+-------------------------------------------------------------------------
//  CERT_CONTEXT_REVOCATION_TYPE
//
//  pvContext points to a const CERT_CONTEXT.
//--------------------------------------------------------------------------

//+=========================================================================
//  Certificate Helper APIs
//==========================================================================


//+-------------------------------------------------------------------------
//  Compare two multiple byte integer blobs to see if they are identical.
//
//  Before doing the comparison, leading zero bytes are removed from a
//  positive number and leading 0xFF bytes are removed from a negative
//  number.
//
//  The multiple byte integers are treated as Little Endian. pbData[0] is the
//  least significant byte and pbData[cbData - 1] is the most significant
//  byte.
//
//  Returns TRUE if the integer blobs are identical after removing leading
//  0 or 0xFF bytes.
//--------------------------------------------------------------------------
function CertCompareIntegerBlob(
  pInt1: PCryptIntegerBlob;
  pInt2: PCryptIntegerBlob): BOOL; winapi;
{$EXTERNALSYM CertCompareIntegerBlob}

//+-------------------------------------------------------------------------
//  Compare two certificates to see if they are identical.
//
//  Since a certificate is uniquely identified by its Issuer and SerialNumber,
//  these are the only fields needing to be compared.
//
//  Returns TRUE if the certificates are identical.
//--------------------------------------------------------------------------
function CertCompareCertificate(
  dwCertEncodingType: DWORD;
  pCertId1: PCertInfo;
  pCertId2: PCertInfo): BOOL; winapi;
{$EXTERNALSYM CertCompareCertificate}

//+-------------------------------------------------------------------------
//  Compare two certificate names to see if they are identical.
//
//  Returns TRUE if the names are identical.
//--------------------------------------------------------------------------
function CertCompareCertificateName(
  dwCertEncodingType: DWORD;
  pCertName1: PCertNameBlob;
  pCertName2: PCertNameBlob): BOOL; winapi;
{$EXTERNALSYM CertCompareCertificateName}

//+-------------------------------------------------------------------------
//  Compare the attributes in the certificate name with the specified
//  Relative Distinguished Name's (CERT_RDN) array of attributes.
//  The comparison iterates through the CERT_RDN attributes and looks for an
//  attribute match in any of the certificate name's RDNs.
//  Returns TRUE if all the attributes are found and match.
//
//  The CERT_RDN_ATTR fields can have the following special values:
//    pszObjId == NULL              - ignore the attribute object identifier
//    dwValueType == RDN_ANY_TYPE   - ignore the value type
//
//  CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG should be set to do
//  a case insensitive match. Otherwise, defaults to an exact, case sensitive
//  match.
//
//  CERT_UNICODE_IS_RDN_ATTRS_FLAG should be set if the pRDN was initialized
//  with unicode strings as for CryptEncodeObject(X509_UNICODE_NAME).
//--------------------------------------------------------------------------
function CertIsRDNAttrsInCertificateName(
  dwCertEncodingType: DWORD;
  dwFlags: DWORD;
  pCertName: PCertNameBlob;
  pRDN: PCertRDN): BOOL; winapi;
{$EXTERNALSYM CertIsRDNAttrsInCertificateName}

const
  CERT_UNICODE_IS_RDN_ATTRS_FLAG             = $1;
  {$EXTERNALSYM CERT_UNICODE_IS_RDN_ATTRS_FLAG}
  CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG    = $2;
  {$EXTERNALSYM CERT_CASE_INSENSITIVE_IS_RDN_ATTRS_FLAG}

//+-------------------------------------------------------------------------
//  Compare two public keys to see if they are identical.
//
//  Returns TRUE if the keys are identical.
//--------------------------------------------------------------------------
function CertComparePublicKeyInfo(
  dwCertEncodingType: DWORD;
  pPublicKey1: PCertPublicKeyInfo;
  xpPublicKey2: PCertPublicKeyInfo): BOOL; winapi;
{$EXTERNALSYM CertComparePublicKeyInfo}

//+-------------------------------------------------------------------------
//  Get the public/private key's bit length.
//
//  Returns 0 if unable to determine the key's length.
//--------------------------------------------------------------------------
function CertGetPublicKeyLength(
  dwCertEncodingType: DWORD;
  pPublicKey: PCertPublicKeyInfo): DWORD; winapi;
{$EXTERNALSYM CertGetPublicKeyLength}

//+-------------------------------------------------------------------------
//  Verify the signature of a subject certificate or a CRL using the
//  public key info
//
//  Returns TRUE for a valid signature.
//
//  hCryptProv specifies the crypto provider to use to verify the signature.
//  It doesn't need to use a private key.
//--------------------------------------------------------------------------
function CryptVerifyCertificateSignature(
  hCryptProv: HCRYPTPROV_LEGACY;
  dwCertEncodingType: DWORD;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  pPublicKey: PCertPublicKeyInfo): BOOL; winapi;
{$EXTERNALSYM CryptVerifyCertificateSignature}

//+-------------------------------------------------------------------------
//  Verify the signature of a subject certificate, CRL, certificate request
//  or keygen request using the issuer's public key.
//
//  Returns TRUE for a valid signature.
//
//  The subject can be an encoded blob or a context for a certificate or CRL.
//  For a subject certificate context, if the certificate is missing
//  inheritable PublicKey Algorithm Parameters, the context's
//  CERT_PUBKEY_ALG_PARA_PROP_ID is updated with the issuer's public key
//  algorithm parameters for a valid signature.
//
//  The issuer can be a pointer to a CERT_PUBLIC_KEY_INFO, certificate
//  context or a chain context.
//
//  hCryptProv specifies the crypto provider to use to verify the signature.
//  Its private key isn't used. If hCryptProv is NULL, a default
//  provider is picked according to the PublicKey Algorithm OID.
//
//  If the signature algorithm is a hashing algorithm, then, the
//  signature is expected to contain the hash octets. Only dwIssuerType
//  of CRYPT_VERIFY_CERT_SIGN_ISSUER_NULL may be specified
//  to verify this no signature case. If any other dwIssuerType is
//  specified, the verify will fail with LastError set to E_INVALIDARG.
//--------------------------------------------------------------------------
function CryptVerifyCertificateSignatureEx(
  hCryptProv: HCRYPTPROV_LEGACY;
  dwCertEncodingType: DWORD;
  dwSubjectType: DWORD;
  pvSubject: Pointer;
  dwIssuerType: DWORD;
  pvIssuer: Pointer;
  dwFlags: DWORD;
  pvExtra: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptVerifyCertificateSignatureEx}

// Subject Types
const
  CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB        = 1;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB}
    // pvSubject :: PCRYPT_DATA_BLOB
  CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT        = 2;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT}
    // pvSubject :: PCCERT_CONTEXT
  CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL         = 3;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL}
    // pvSubject :: PCCRL_CONTEXT
  CRYPT_VERIFY_CERT_SIGN_SUBJECT_OCSP_BASIC_SIGNED_RESPONSE  = 4;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_SUBJECT_OCSP_BASIC_SIGNED_RESPONSE}
    // pvSubject :: POCSP_BASIC_SIGNED_RESPONSE_INFO

// Issuer Types
const
  CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY       = 1;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY}
    // pvIssuer :: PCERT_PUBLIC_KEY_INFO
  CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT         = 2;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT}
    // pvIssuer :: PCCERT_CONTEXT
  CRYPT_VERIFY_CERT_SIGN_ISSUER_CHAIN        = 3;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_ISSUER_CHAIN}
    // pvIssuer :: PCCERT_CHAIN_CONTEXT
  CRYPT_VERIFY_CERT_SIGN_ISSUER_NULL         = 4;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_ISSUER_NULL}
    // pvIssuer :: NULL

//
// If the following flag is set and a MD2 or MD4 signature hash is
// detected, then, this API fails and sets LastError to NTE_BAD_ALGID
//
// This API first does the signature verification check. If the signature
// verification succeeds and the following flag is set, it then checks for a
// MD2 or MD4 hash. For a MD2 or MD4 hash FALSE is returned with LastError set
// to NTE_BAD_ALGID. This error will only be set if MD2 or MD4 is detected.
// If NTE_BAD_ALGID is returned, then, the MD2 or MD4 signature verified.
// This allows the caller to conditionally allow MD2 or MD4.
//
const
  CRYPT_VERIFY_CERT_SIGN_DISABLE_MD2_MD4_FLAG    = $00000001;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_DISABLE_MD2_MD4_FLAG}



//
// When the following flag is set, the strong signature properties are
// also set on the Subject. Only applicable to the
// CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL Subject Type.
//
//  The strong signature properties are:
//    - CERT_SIGN_HASH_CNG_ALG_PROP_ID
//    - CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID
//
const
  CRYPT_VERIFY_CERT_SIGN_SET_STRONG_PROPERTIES_FLAG = $00000002;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_SET_STRONG_PROPERTIES_FLAG}

//
// When the following flag is set, the strong signature properties are also
// returned. Only applicable to the
// CRYPT_VERIFY_CERT_SIGN_SUBJECT_OCSP_BASIC_SIGNED_RESPONSE Subject Type.
//
// pvExtra points to a pointer to CRYPT_VERIFY_CERT_SIGN_VERIFY_PROPERTIES_INFO.
//  ie, PCRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO *ppStrongPropertiesInfo.
// The returned pointer is freed via CryptMemFree().
//
//  The strong signature properties are:
//    - CERT_SIGN_HASH_CNG_ALG_PROP_ID
//    - CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID
//
const
  CRYPT_VERIFY_CERT_SIGN_RETURN_STRONG_PROPERTIES_FLAG = $00000004;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_RETURN_STRONG_PROPERTIES_FLAG}

type
  PCryptVerifyCertSignStrongPropertiesInfo = ^TCryptVerifyCertSignStrongPropertiesInfo;
  _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO = record
    // CERT_SIGN_HASH_CNG_ALG_PROP_ID
    CertSignHashCNGAlgPropData: TCryptDataBlob;

    // CERT_ISSUER_PUB_KEY_BIT_LENGTH_PROP_ID
    CertIssuerPubKeyBitLengthPropData: TCryptDataBlob;
  end;
  {$EXTERNALSYM _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO}
  CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO = _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO;
  {$EXTERNALSYM CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO}
  TCryptVerifyCertSignStrongPropertiesInfo = _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO;
  PCRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO = PCryptVerifyCertSignStrongPropertiesInfo;
  {$EXTERNALSYM PCRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO}


//+-------------------------------------------------------------------------
//  Checks if the specified hash algorithm and the signing certificate's
//  public key algorithm can be used to do a strong signature.
//
//  Returns TRUE if the hash algorithm and certificate public key algorithm
//  satisfy the strong signature requirements.
//
//  pwszCNGHashAlgid is the CNG hash algorithm identifier string, for example,
//  BCRYPT_SHA256_ALGORITHM (L"SHA256")
//
//  The CNG hash algorithm identifier string can be empty (L"") to only check
//  if the certificate's public key is strong.
//
//  The SigningCert can be NULL to only check if the CNG hash algorithm is
//  strong.
//--------------------------------------------------------------------------
function CertIsStrongHashToSign(
  pStrongSignPara: PCertStrongSignPara;
  pwszCNGHashAlgid: LPCWSTR;
  pSigningCert: PCertContext): BOOL; winapi;
{$EXTERNALSYM CertIsStrongHashToSign}

//+-------------------------------------------------------------------------
//  Compute the hash of the "to be signed" information in the encoded
//  signed content (CERT_SIGNED_CONTENT_INFO).
//
//  hCryptProv specifies the crypto provider to use to compute the hash.
//  It doesn't need to use a private key.
//--------------------------------------------------------------------------
function CryptHashToBeSigned(
  hCryptProv: HCRYPTPROV_LEGACY;
  dwCertEncodingType: DWORD;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  pbComputedHash: PByte;
  var pcbComputedHash: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptHashToBeSigned}

//+-------------------------------------------------------------------------
//  Hash the encoded content.
//
//  hCryptProv specifies the crypto provider to use to compute the hash.
//  It doesn't need to use a private key.
//
//  Algid specifies the CAPI hash algorithm to use. If Algid is 0, then, the
//  default hash algorithm (currently SHA1) is used.
//--------------------------------------------------------------------------
function CryptHashCertificate(
  hCryptProv: HCRYPTPROV_LEGACY;
  Algid: ALG_ID;
  dwFlags: DWORD;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  pbComputedHash: PByte;
  var pcbComputedHash: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptHashCertificate}

//+-------------------------------------------------------------------------
//  Hash the encoded content using the CNG hash algorithm provider.
//--------------------------------------------------------------------------
function CryptHashCertificate2(
  pwszCNGHashAlgid: LPCWSTR;
  dwFlags: DWORD;
  pvReserved: Pointer;
  pbEncoded: PByte;
  cbEncoded: DWORD;
  pbComputedHash: PByte;
  var pcbComputedHash: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptHashCertificate2}

//+-------------------------------------------------------------------------
//  Sign the "to be signed" information in the encoded signed content.
//
//  hCryptProvOrNCryptKey specifies the crypto provider to use to do the
//  signature.  It uses the specified private key.
//
//  If the SignatureAlgorithm is a hash algorithm, then, the signature
//  contains the hash octets. A private key isn't used to encrypt the hash.
//  dwKeySpec isn't used and hCryptProvOrNCryptKey can be NULL where an
//  appropriate default provider will be used for hashing.
//--------------------------------------------------------------------------
function CryptSignCertificate(
  hCryptProvOrNCryptKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
  dwKeySpec: DWORD;        // not applicable for NCRYPT_KEY_HANDLE
  dwCertEncodingType: DWORD;
  pbEncodedToBeSigned: PByte;
  cbEncodedToBeSigned: DWORD;
  pSignatureAlgorithm: PCryptAlgorithmIdentifier;
  pvHashAuxInfo: Pointer;
  pbSignature: PByte;
  var pcbSignature: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignCertificate}

//+-------------------------------------------------------------------------
//  Encode the "to be signed" information. Sign the encoded "to be signed".
//  Encode the "to be signed" and the signature.
//
//  hCryptProv specifies the crypto provider to use to do the signature.
//  It uses the specified private key.
//
//  If the SignatureAlgorithm is a hash algorithm, then, the signature
//  contains the hash octets. A private key isn't used to encrypt the hash.
//  dwKeySpec isn't used and hCryptProv can be NULL where an appropriate
//  default provider will be used for hashing.
//--------------------------------------------------------------------------
function CryptSignAndEncodeCertificate(
  hCryptProvOrNCryptKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
  dwKeySpec: DWORD;        // not applicable for NCRYPT_KEY_HANDLE
  dwCertEncodingType: DWORD;
  lpszStructType: LPCSTR;        // "to be signed"
  pvStructInfo: Pointer;
  pSignatureAlgorithm: PCryptAlgorithmIdentifier;
  pvHashAuxInfo: Pointer;
  pbEncoded: PByte;
  var pcbEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignAndEncodeCertificate}

//+-------------------------------------------------------------------------
//  Certificate and CryptMsg encoded signature OID installable functions
//--------------------------------------------------------------------------


// The dwCertEncodingType and pSignatureAlgorithm->pszObjId are used
// to call the signature OID installable functions.
//
// If the OID installable function doesn't support the signature,
// it should return FALSE with LastError set to ERROR_NOT_SUPPORTED.


// Called if the signature has encoded parameters. Returns the CNG
// hash algorithm identifier string. Optionally returns the decoded
// signature parameters passed to either the SignAndEncodeHash or
// VerifyEncodedSignature OID installable function.
//
// Returned allocated parameters are freed via LocalFree().
const
  CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC = 'CryptDllExtractEncodedSignatureParameters';
  {$EXTERNALSYM CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC}
type
  PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC = function(
    dwCertEncodingType: DWORD;
    pSignatureAlgorithm: PCryptAlgorithmIdentifier;
    out ppvDecodedSignPara: Pointer;   // LocalFree()
    out ppwszCNGHashAlgid: LPWSTR      // LocalFree()
    ): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC}
  TFnCryptExtractEncodedSignatureParametersFunc = PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC;

// Called to sign the computed hash and encode it.
const
  CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC = 'CryptDllSignAndEncodeHash';
  {$EXTERNALSYM CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC}
type
  PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC = function(
    hKey: NCRYPT_KEY_HANDLE;
    dwCertEncodingType: DWORD;
    pSignatureAlgorithm: PCryptAlgorithmIdentifier;
    pvDecodedSignPara: Pointer;
    pwszCNGPubKeyAlgid: LPCWSTR;     // obtained from signature OID
    pwszCNGHashAlgid: LPCWSTR;
    pbComputedHash: PByte;
    cbComputedHash: DWORD;
    pbSignature: PByte;
    var pcbSignature: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC}
  TFnCryptSignAndEncodeHashFunc = PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC;

// Called to decode and decrypt the encoded signature and compare it with the
// computed hash.
const
  CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC = 'CryptDllVerifyEncodedSignature';
  {$EXTERNALSYM CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC}
type
  PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC = function(
    dwCertEncodingType: DWORD;
    pPubKeyInfo: PCertPublicKeyInfo;
    pSignatureAlgorithm: PCryptAlgorithmIdentifier;
    pvDecodedSignPara: Pointer;
    pwszCNGPubKeyAlgid: LPCWSTR;     // obtained from signature OID
    pwszCNGHashAlgid: LPCWSTR;
    pbComputedHash: PByte;
    cbComputedHash: DWORD;
    pbSignature: PByte;
    cbSignature: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC}
  TFnCryptVerifyEncodedSignatureFunc = PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC;


//+-------------------------------------------------------------------------
//  Verify the time validity of a certificate.
//
//  Returns -1 if before NotBefore, +1 if after NotAfter and otherwise 0 for
//  a valid certificate
//
//  If pTimeToVerify is NULL, uses the current time.
//--------------------------------------------------------------------------
function CertVerifyTimeValidity(
  pTimeToVerify: PFileTime;
  pCertInfo: PCertInfo): LONG; winapi;
{$EXTERNALSYM CertVerifyTimeValidity}

//+-------------------------------------------------------------------------
//  Verify the time validity of a CRL.
//
//  Returns -1 if before ThisUpdate, +1 if after NextUpdate and otherwise 0 for
//  a valid CRL
//
//  If pTimeToVerify is NULL, uses the current time.
//--------------------------------------------------------------------------
function CertVerifyCRLTimeValidity(
  pTimeToVerify: PFileTime;
  pCrlInfo: PCRLInfo): LONG; winapi;
{$EXTERNALSYM CertVerifyCRLTimeValidity}

//+-------------------------------------------------------------------------
//  Verify that the subject's time validity nests within the issuer's time
//  validity.
//
//  Returns TRUE if it nests. Otherwise, returns FALSE.
//--------------------------------------------------------------------------
function CertVerifyValidityNesting(
  pSubjectInfo: PCertInfo;
  pIssuerInfo: PCertInfo): BOOL; winapi;
{$EXTERNALSYM CertVerifyValidityNesting}

//+-------------------------------------------------------------------------
//  Verify that the subject certificate isn't on its issuer CRL.
//
//  Returns true if the certificate isn't on the CRL.
//--------------------------------------------------------------------------
function CertVerifyCRLRevocation(
  dwCertEncodingType: DWORD;
  pCertId: PCertInfo;                 // Only the Issuer and SerialNumber
                                      // fields are used
  cCrlInfo: DWORD;
  var rgpCrlInfo: PCRLInfo): BOOL; winapi;
{$EXTERNALSYM CertVerifyCRLRevocation}

//+-------------------------------------------------------------------------
//  Convert the CAPI AlgId to the ASN.1 Object Identifier string
//
//  Returns NULL if there isn't an ObjId corresponding to the AlgId.
//--------------------------------------------------------------------------
function CertAlgIdToOID(
  dwAlgId: DWORD): LPCSTR; winapi;
{$EXTERNALSYM CertAlgIdToOID}

//+-------------------------------------------------------------------------
//  Convert the ASN.1 Object Identifier string to the CAPI AlgId.
//
//  Returns 0 if there isn't an AlgId corresponding to the ObjId.
//--------------------------------------------------------------------------
function CertOIDToAlgId(
  pszObjId: LPCSTR): DWORD; winapi;
{$EXTERNALSYM CertOIDToAlgId}

//+-------------------------------------------------------------------------
//  Find an extension identified by its Object Identifier.
//
//  If found, returns pointer to the extension. Otherwise, returns NULL.
//--------------------------------------------------------------------------
function CertFindExtension(
  pszObjId: LPCSTR;
  cExtensions: DWORD;
  var rgExtensions: TCertExtension): PCertExtension; winapi;
{$EXTERNALSYM CertFindExtension}

//+-------------------------------------------------------------------------
//  Find the first attribute identified by its Object Identifier.
//
//  If found, returns pointer to the attribute. Otherwise, returns NULL.
//--------------------------------------------------------------------------
function CertFindAttribute(
  pszObjId: LPCSTR;
  cAttr: DWORD;
  var rgAttr: TCryptAttribute): PCryptAttribute;
{$EXTERNALSYM CertFindAttribute}

//+-------------------------------------------------------------------------
//  Find the first CERT_RDN attribute identified by its Object Identifier in
//  the name's list of Relative Distinguished Names.
//
//  If found, returns pointer to the attribute. Otherwise, returns NULL.
//--------------------------------------------------------------------------
function CertFindRDNAttr(
  pszObjId: LPCSTR;
  pName: PCertNameInfo): PCertRDNAttr;
{$EXTERNALSYM CertFindRDNAttr}

//+-------------------------------------------------------------------------
//  Get the intended key usage bytes from the certificate.
//
//  If the certificate doesn't have any intended key usage bytes, returns FALSE
//  and *pbKeyUsage is zeroed. Otherwise, returns TRUE and up through
//  cbKeyUsage bytes are copied into *pbKeyUsage. Any remaining uncopied
//  bytes are zeroed.
//--------------------------------------------------------------------------
function CertGetIntendedKeyUsage(
  dwCertEncodingType: DWORD;
  pCertInfo: PCertInfo;
  pbKeyUsage: PByte;
  cbKeyUsage: DWORD): BOOL;
{$EXTERNALSYM CertGetIntendedKeyUsage}

type
  HCRYPTDEFAULTCONTEXT = Pointer;
  {$EXTERNALSYM HCRYPTDEFAULTCONTEXT}

//+-------------------------------------------------------------------------
//  Install a previously CryptAcquiredContext'ed HCRYPTPROV to be used as
//  a default context.
//
//  dwDefaultType and pvDefaultPara specify where the default context is used.
//  For example, install the HCRYPTPROV to be used to verify certificate's
//  having szOID_OIWSEC_md5RSA signatures.
//
//  By default, the installed HCRYPTPROV is only applicable to the current
//  thread. Set CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG to allow the HCRYPTPROV
//  to be used by all threads in the current process.
//
//  For a successful install, TRUE is returned and *phDefaultContext is
//  updated with the HANDLE to be passed to CryptUninstallDefaultContext.
//
//  The installed HCRYPTPROVs are stack ordered (the last installed
//  HCRYPTPROV is checked first). All thread installed HCRYPTPROVs are
//  checked before any process HCRYPTPROVs.
//
//  The installed HCRYPTPROV remains available for default usage until
//  CryptUninstallDefaultContext is called or the thread or process exits.
//
//  If CRYPT_DEFAULT_CONTEXT_AUTO_RELEASE_FLAG is set, then, the HCRYPTPROV
//  is CryptReleaseContext'ed at thread or process exit. However,
//  not CryptReleaseContext'ed if CryptUninstallDefaultContext is
//  called.
//--------------------------------------------------------------------------
function CryptInstallDefaultContext(
  hCryptProv: HCRYPTPROV;
  dwDefaultType: DWORD;
  pvDefaultPara: Pointer;
  dwFlags: DWORD;
  pvReserved: Pointer;
  out phDefaultContext: HCRYPTDEFAULTCONTEXT): BOOL; winapi;
{$EXTERNALSYM CryptInstallDefaultContext}

// dwFlags
const
  CRYPT_DEFAULT_CONTEXT_AUTO_RELEASE_FLAG            = $00000001;
  {$EXTERNALSYM CRYPT_DEFAULT_CONTEXT_AUTO_RELEASE_FLAG}
  CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG                 = $00000002;
  {$EXTERNALSYM CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG}

// List of dwDefaultType's
const
  CRYPT_DEFAULT_CONTEXT_CERT_SIGN_OID        = 1;
  {$EXTERNALSYM CRYPT_DEFAULT_CONTEXT_CERT_SIGN_OID}
  CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID  = 2;
  {$EXTERNALSYM CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID}


//+-------------------------------------------------------------------------
//  CRYPT_DEFAULT_CONTEXT_CERT_SIGN_OID
//
//  Install a default HCRYPTPROV used to verify a certificate
//  signature. pvDefaultPara points to the szOID of the certificate
//  signature algorithm, for example, szOID_OIWSEC_md5RSA. If
//  pvDefaultPara is NULL, then, the HCRYPTPROV is used to verify all
//  certificate signatures. Note, pvDefaultPara can't be NULL when
//  CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG is set.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CRYPT_DEFAULT_CONTEXT_MULTI_CERT_SIGN_OID
//
//  Same as CRYPT_DEFAULT_CONTEXT_CERT_SIGN_OID. However, the default
//  HCRYPTPROV is to be used for multiple signature szOIDs. pvDefaultPara
//  points to a CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA structure containing
//  an array of szOID pointers.
//--------------------------------------------------------------------------

type
  PCryptDefaultContextMultiOIDPara = ^TCryptDefaultContextMultiOIDPara;
  _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA = record
    cOID: DWORD;
    rgpszOID: ^LPSTR;
  end;
  {$EXTERNALSYM _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA}
  CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA = _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA;
  {$EXTERNALSYM CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA}
  TCryptDefaultContextMultiOIDPara  = _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA;
  PCRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA = PCryptDefaultContextMultiOIDPara;
  {$EXTERNALSYM PCRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA}

//+-------------------------------------------------------------------------
//  Uninstall a default context previously installed by
//  CryptInstallDefaultContext.
//
//  For a default context installed with CRYPT_DEFAULT_CONTEXT_PROCESS_FLAG
//  set, if any other threads are currently using this context,
//  this function will block until they finish.
//--------------------------------------------------------------------------
function CryptUninstallDefaultContext(
  hDefaultContext: HCRYPTDEFAULTCONTEXT;
  dwFlags: DWORD;
  pvReserved: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptUninstallDefaultContext}

//+-------------------------------------------------------------------------
//  Export the public key info associated with the provider's corresponding
//  private key.
//
//  Calls CryptExportPublicKeyInfoEx with pszPublicKeyObjId = NULL,
//  dwFlags = 0 and pvAuxInfo = NULL.
//--------------------------------------------------------------------------
function CryptExportPublicKeyInfo(
  hCryptProvOrNCryptKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
  dwKeySpec: DWORD;       // not applicable for NCRYPT_KEY_HANDLE
  dwCertEncodingType: DWORD;
  pInfo: PCertPublicKeyInfo;
  var pcbInfo: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptExportPublicKeyInfo}

//+-------------------------------------------------------------------------
//  Export the public key info associated with the provider's corresponding
//  private key.
//
//  Uses the dwCertEncodingType and pszPublicKeyObjId to call the
//  installable CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FUNC. The called function
//  has the same signature as CryptExportPublicKeyInfoEx.
//
//  If unable to find an installable OID function for the pszPublicKeyObjId,
//  attempts to export as a RSA Public Key (szOID_RSA_RSA).
//
//  The dwFlags and pvAuxInfo aren't used for szOID_RSA_RSA.
//
//  dwFlags can be set with the following 2 flags passed directly to
//  CryptFindOIDInfo:
//      CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG
//      CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG
//--------------------------------------------------------------------------

function CryptExportPublicKeyInfoEx(
  hCryptProvOrNCryptKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
  dwKeySpec: DWORD;        // not applicable for NCRYPT_KEY_HANDLE
  dwCertEncodingType: DWORD;
  pszPublicKeyObjId: LPSTR;
  dwFlags: DWORD;
  pvAuxInfo: Pointer;
  pInfo: PCertPublicKeyInfo;
  var pcbInfo: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptExportPublicKeyInfoEx}

// Legacy define used for exporting CAPI1 HCRYPTPROV public keys.
const
  CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FUNC  = 'CryptDllExportPublicKeyInfoEx';
  {$EXTERNALSYM CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FUNC}

//+-------------------------------------------------------------------------
//  Export CNG PublicKeyInfo OID installable function. Note, not called
//  for a HCRYPTPROV choice.
//--------------------------------------------------------------------------
const
  CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC = 'CryptDllExportPublicKeyInfoEx2';
  {$EXTERNALSYM CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC}
type
  PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC = function(
    hNCryptKey: NCRYPT_KEY_HANDLE;
    dwCertEncodingType: DWORD;
    pszPublicKeyObjId: LPSTR;
    dwFlags: DWORD;
    pvAuxInfo: Pointer;
    pInfo: PCertPublicKeyInfo;
    var pcbInfo: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC}
  TFnCryptExportPublicKeyInfoEx2Func = PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC;


//+-------------------------------------------------------------------------
//  Export the public key info associated with the provider's corresponding
//  private key.
//
//  Uses the dwCertEncodingType and pszPublicKeyObjId to call the
//  installable CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC. The
//  called function has the same signature as
//  CryptExportPublicKeyInfoFromBCryptKeyHandle.
//
//  If unable to find an installable OID function for the pszPublicKeyObjId,
//  attempts to export as a RSA Public Key (szOID_RSA_RSA).
//
//  The dwFlags and pvAuxInfo aren't used for szOID_RSA_RSA.
//
//  In addition dwFlags can be set with the following 2 flags passed directly
//  to CryptFindOIDInfo:
//      CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG
//      CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG
//--------------------------------------------------------------------------

function CryptExportPublicKeyInfoFromBCryptKeyHandle(
  hBCryptKey: BCRYPT_KEY_HANDLE;
  dwCertEncodingType: DWORD;
  pszPublicKeyObjId: LPSTR;
  dwFlags: DWORD;
  pvAuxInfo: Pointer;
  pInfo: PCertPublicKeyInfo;
  var pcbInfo: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptExportPublicKeyInfoFromBCryptKeyHandle}

//+-------------------------------------------------------------------------
//  Export CNG PublicKeyInfo OID installable function. Note, not called
//  for a HCRYPTPROV or NCRYPT_KEY_HANDLE choice.
//--------------------------------------------------------------------------
const
  CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC = 'CryptDllExportPublicKeyInfoFromBCryptKeyHandle';
  {$EXTERNALSYM CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC}
type
  PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC = function(
    hBCryptKey: BCRYPT_KEY_HANDLE;
    dwCertEncodingType: DWORD;
    pszPublicKeyObjId: LPSTR;
    dwFlags: DWORD;
    pvAuxInfo: Pointer;
    pInfo: PCertPublicKeyInfo;
    var pcbInfo: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC}
  TFnCryptExportPublicKeyInfoFromBCryptHandleFunc = PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC;

//+-------------------------------------------------------------------------
//  Convert and import the public key info into the provider and return a
//  handle to the public key.
//
//  Calls CryptImportPublicKeyInfoEx with aiKeyAlg = 0, dwFlags = 0 and
//  pvAuxInfo = NULL.
//--------------------------------------------------------------------------
function CryptImportPublicKeyInfo(
  hCryptProv: HCRYPTPROV;
  dwCertEncodingType: DWORD;
  pInfo: PCertPublicKeyInfo;
  out phKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptImportPublicKeyInfo}

//+-------------------------------------------------------------------------
//  Convert and import the public key info into the provider and return a
//  handle to the public key.
//
//  Uses the dwCertEncodingType and pInfo->Algorithm.pszObjId to call the
//  installable CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_FUNC. The called function
//  has the same signature as CryptImportPublicKeyInfoEx.
//
//  If unable to find an installable OID function for the pszObjId,
//  attempts to import as a RSA Public Key (szOID_RSA_RSA).
//
//  For szOID_RSA_RSA: aiKeyAlg may be set to CALG_RSA_SIGN or CALG_RSA_KEYX.
//  Defaults to CALG_RSA_KEYX. The dwFlags and pvAuxInfo aren't used.
//--------------------------------------------------------------------------
const
  CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_FUNC  = 'CryptDllImportPublicKeyInfoEx';
  {$EXTERNALSYM CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_FUNC}

function CryptImportPublicKeyInfoEx(
  hCryptProv: HCRYPTPROV;
  dwCertEncodingType: DWORD;
  pInfo: PCertPublicKeyInfo;
  aiKeyAlg: ALG_ID;
  dwFlags: DWORD;
  pvAuxInfo: Pointer;
  out phKey: HCRYPTKEY): BOOL; winapi;
{$EXTERNALSYM CryptImportPublicKeyInfoEx}

//+-------------------------------------------------------------------------
//  Convert and import the public key info into the CNG asymmetric or
//  signature algorithm provider and return a BCRYPT_KEY_HANDLE to it.
//
//  Uses the dwCertEncodingType and pInfo->Algorithm.pszObjId to call the
//  installable CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC. The called function
//  has the same signature as CryptImportPublicKeyInfoEx2.
//
//  dwFlags can be set with the following 2 flags passed directly to
//  CryptFindOIDInfo:
//      CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG
//      CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG
//  dwFlags can also have BCRYPT_NO_KEY_VALIDATION OR'd in. This flag is
//  passed to BCryptImportKeyPair.
//--------------------------------------------------------------------------
function CryptImportPublicKeyInfoEx2(
  dwCertEncodingType: DWORD;
  pInfo: PCertPublicKeyInfo;
  dwFlags: DWORD;
  pvAuxInfo: Pointer;
  out phKey: BCRYPT_KEY_HANDLE): BOOL; winapi;
{$EXTERNALSYM CryptImportPublicKeyInfoEx2}

//+-------------------------------------------------------------------------
//  Import CNG PublicKeyInfo OID installable function
//--------------------------------------------------------------------------
const
  CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC = 'CryptDllImportPublicKeyInfoEx2';
  {$EXTERNALSYM CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC}
type
  PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC = function(
    dwCertEncodingType: DWORD;
    pInfo: PCertPublicKeyInfo;
    dwFlags: DWORD;
    pvAuxInfo: Pointer;
    out phKey: BCRYPT_KEY_HANDLE): BOOL; winapi;
  {$EXTERNALSYM PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC}
  TFnImportPublicKeyInfoEx2Func = PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC;

//+-------------------------------------------------------------------------
//  Acquire a HCRYPTPROV and dwKeySpec or NCRYPT_KEY_HANDLE for the
//  specified certificate context. Uses the certificate's
//  CERT_KEY_PROV_INFO_PROP_ID property.
//  The returned HCRYPTPROV or NCRYPT_KEY_HANDLE handle may optionally be
//  cached using the certificate's CERT_KEY_CONTEXT_PROP_ID property.
//
//  If CRYPT_ACQUIRE_CACHE_FLAG is set, then, if an already acquired and
//  cached HCRYPTPROV or NCRYPT_KEY_HANDLE exists for the certificate, its
//  returned. Otherwise, a HCRYPTPROV or NCRYPT_KEY_HANDLE is acquired and
//  then cached via the certificate's CERT_KEY_CONTEXT_PROP_ID.
//
//  The CRYPT_ACQUIRE_USE_PROV_INFO_FLAG can be set to use the dwFlags field of
//  the certificate's CERT_KEY_PROV_INFO_PROP_ID property's CRYPT_KEY_PROV_INFO
//  data structure to determine if the returned HCRYPTPROV or
//  NCRYPT_KEY_HANDLE should be cached.
//  Caching is enabled if the CERT_SET_KEY_CONTEXT_PROP_ID flag was
//  set.
//
//  If CRYPT_ACQUIRE_COMPARE_KEY_FLAG is set, then,
//  the public key in the certificate is compared with the public
//  key returned by the cryptographic provider. If the keys don't match, the
//  acquire fails and LastError is set to NTE_BAD_PUBLIC_KEY. Note, if
//  a cached HCRYPTPROV or NCRYPT_KEY_HANDLE is returned, the comparison isn't
//  done. We assume the comparison was done on the initial acquire.
//
//  The CRYPT_ACQUIRE_NO_HEALING flags prohibits this function from
//  attempting to recreate the CERT_KEY_PROV_INFO_PROP_ID in the certificate
//  context if it fails to retrieve this property.
//
//  The CRYPT_ACQUIRE_SILENT_FLAG can be set to suppress any UI by the CSP.
//  See CryptAcquireContext's CRYPT_SILENT flag for more details.
//
//  The CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG can be set when a pointer to a window handle (HWND*)
//  is passed in as the pvParameters. The window handle will be used
//  by calling CryptSetProvParam with a NULL HCRYPTPROV and dwParam
//  is PP_CLIENT_HWND before the call to CryptAcquireContext.
//  This will set the window handle for all CAPI calls in this process.
//  The caller should make sure the window handle is valid or clear it out by
//  calling CryptSetProvParam with PP_CLIENT_HWND with a NULL hWnd.
//  Or for cng, the hwnd will be used by calling NCryptSetProperty on the storage provider
//  handle provider with property NCRYPT_WINDOW_HANDLE_PROPERTY and
//  by calling NCryptSetPRoperty on the key handle with property NCRYPT_WINDOW_HANDLE_PROPERTY.
//  If both calls to NCryptSetProperty fail then the function will return the failure of
//  setting the NCRYPT_WINDOW_HANDLE_PROPERTY on the key handle.
//  Do not use this flag with CRYPT_ACQUIRE_SILENT_FLAG.
//
//  The following flags can be set to optionally open and return a CNG
//  NCRYPT_KEY_HANDLE instead of a HCRYPTPROV. *pdwKeySpec is set to
//  CERT_NCRYPT_KEY_SPEC when a NCRYPT_KEY_HANDLE is returned.
//      CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG - if the CryptAcquireContext
//      fails, then, an NCryptOpenKey is attempted.
//
//      CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG - the NCryptOpenKey is
//      first attempted and its handle returned for success.
//
//      CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG - only the NCryptOpenKey is
//      attempted.
//
//  *pfCallerFreeProvOrNCryptKey is returned set to FALSE for:
//    - Acquire or public key comparison fails.
//    - CRYPT_ACQUIRE_CACHE_FLAG is set.
//    - CRYPT_ACQUIRE_USE_PROV_INFO_FLAG is set AND
//      CERT_SET_KEY_CONTEXT_PROP_ID flag is set in the dwFlags field of the
//      certificate's CERT_KEY_PROV_INFO_PROP_ID property's
//      CRYPT_KEY_PROV_INFO data structure.
//  When *pfCallerFreeProvOrNCryptKey is FALSE, the caller must not release. The
//  returned HCRYPTPROV or NCRYPT_KEY_HANDLE will be released on the last
//  free of the certificate context.
//
//  Otherwise, *pfCallerFreeProvOrNCryptKey is TRUE and a returned
//  HCRYPTPROV must be released by the caller by calling CryptReleaseContext.
//  A returned NCRYPT_KEY_HANDLE is freed by calling NCryptFreeObject.
//  *pdwKeySpec MUST be checked when CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG
//  or CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG is set.
//
//--------------------------------------------------------------------------
function CryptAcquireCertificatePrivateKey(
  pCert: PCertContext;
  dwFlags: DWORD;
  pvParameters: Pointer;
  out phCryptProvOrNCryptKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
  pdwKeySpec: PDWORD;
  pfCallerFreeProvOrNCryptKey: PBOOL): BOOL; winapi;
{$EXTERNALSYM CryptAcquireCertificatePrivateKey}

const
  CRYPT_ACQUIRE_CACHE_FLAG               = $00000001;
  {$EXTERNALSYM CRYPT_ACQUIRE_CACHE_FLAG}
  CRYPT_ACQUIRE_USE_PROV_INFO_FLAG       = $00000002;
  {$EXTERNALSYM CRYPT_ACQUIRE_USE_PROV_INFO_FLAG}
  CRYPT_ACQUIRE_COMPARE_KEY_FLAG         = $00000004;
  {$EXTERNALSYM CRYPT_ACQUIRE_COMPARE_KEY_FLAG}
  CRYPT_ACQUIRE_NO_HEALING               = $00000008;
  {$EXTERNALSYM CRYPT_ACQUIRE_NO_HEALING}

  CRYPT_ACQUIRE_SILENT_FLAG              = $00000040;
  {$EXTERNALSYM CRYPT_ACQUIRE_SILENT_FLAG}
  CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG       = $00000080;
  {$EXTERNALSYM CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG}

  CRYPT_ACQUIRE_NCRYPT_KEY_FLAGS_MASK    = $00070000;
  {$EXTERNALSYM CRYPT_ACQUIRE_NCRYPT_KEY_FLAGS_MASK}
  CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG    = $00010000;
  {$EXTERNALSYM CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG}
  CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG   = $00020000;
  {$EXTERNALSYM CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG}
  CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG     = $00040000;
  {$EXTERNALSYM CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG}



//+-------------------------------------------------------------------------
//  Enumerates the cryptographic providers and their containers to find the
//  private key corresponding to the certificate's public key. For a match,
//  the certificate's CERT_KEY_PROV_INFO_PROP_ID property is updated.
//
//  If the CERT_KEY_PROV_INFO_PROP_ID is already set, then, its checked to
//  see if it matches the provider's public key. For a match, the above
//  enumeration is skipped.
//
//  By default both the user and machine key containers are searched.
//  The CRYPT_FIND_USER_KEYSET_FLAG or CRYPT_FIND_MACHINE_KEYSET_FLAG
//  can be set in dwFlags to restrict the search to either of the containers.
//
//  The CRYPT_FIND_SILENT_KEYSET_FLAG can be set to suppress any UI by the CSP.
//  See CryptAcquireContext's CRYPT_SILENT flag for more details.
//
//  If a container isn't found, returns FALSE with LastError set to
//  NTE_NO_KEY.
//
//  The above CRYPT_ACQUIRE_NCRYPT_KEY_FLAGS can also be set. The default
//  is CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG.
//--------------------------------------------------------------------------
function CryptFindCertificateKeyProvInfo(
  pCert: PCertContext;
  dwFlags: DWORD;
  pvReserved: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptFindCertificateKeyProvInfo}

const
  CRYPT_FIND_USER_KEYSET_FLAG       = $00000001;
  {$EXTERNALSYM CRYPT_FIND_USER_KEYSET_FLAG}
  CRYPT_FIND_MACHINE_KEYSET_FLAG    = $00000002;
  {$EXTERNALSYM CRYPT_FIND_MACHINE_KEYSET_FLAG}
  CRYPT_FIND_SILENT_KEYSET_FLAG     = $00000040;
  {$EXTERNALSYM CRYPT_FIND_SILENT_KEYSET_FLAG}


//+-------------------------------------------------------------------------
//  This is the prototype for the installable function which is called to
//  actually import a key into a CSP.  an installable of this type is called
//  from CryptImportPKCS8.  the algorithm OID of the private key is used
//  to look up the proper installable function to call.
//
//  hCryptProv - the provider to import the key to
//  pPrivateKeyInfo - describes the key to be imported
//  dwFlags - The available flags are:
//              CRYPT_EXPORTABLE
//              this flag is used when importing private keys, for a full
//              explanation please see the documentation for CryptImportKey.
//  pvAuxInfo - reserved for future, must be NULL
//--------------------------------------------------------------------------
type
  PFN_IMPORT_PRIV_KEY_FUNC = function(
    hCryptProv: HCRYPTPROV;                         // in
    pPrivateKeyInfo: PCryptPrivateKeyInfo;          // in
    dwFlags: DWORD;                                 // in
    pvAuxInfo: Pointer                              // in, optional
    ): BOOL; winapi;
  {$EXTERNALSYM PFN_IMPORT_PRIV_KEY_FUNC}

const
  CRYPT_OID_IMPORT_PRIVATE_KEY_INFO_FUNC  = 'CryptDllImportPrivateKeyInfoEx';
  {$EXTERNALSYM CRYPT_OID_IMPORT_PRIVATE_KEY_INFO_FUNC}

//+-------------------------------------------------------------------------
// Convert (from PKCS8 format) and import the private key into a provider
// and return a handle to the provider as well as the KeySpec used to import to.
//
// This function will call the PRESOLVE_HCRYPTPROV_FUNC in the
// privateKeyAndParams to obtain a handle of provider to import the key to.
// if the PRESOLVE_HCRYPTPROV_FUNC is NULL then the default provider will be used.
//
// privateKeyAndParams - private key blob and corresponding parameters
// dwFlags - The available flags are:
//              CRYPT_EXPORTABLE
//              this flag is used when importing private keys, for a full
//              explanation please see the documentation for CryptImportKey.
// phCryptProv - filled in with the handle of the provider the key was
//               imported to, the caller is responsible for freeing it
// pvAuxInfo - This parameter is reserved for future use and should be set
//             to NULL in the interim.
//--------------------------------------------------------------------------
function CryptImportPKCS8(
  sPrivateKeyAndParams: TCryptPKCS8ImportParams;            // in
  dwFlags: DWORD;                                           // in
  out phCryptProv: HCRYPTPROV;                              // out, optional
  pvAuxInfo: Pointer                                        // in, optional
  ): BOOL; winapi;
{$EXTERNALSYM CryptImportPKCS8}

//+-------------------------------------------------------------------------
// this is the prototype for installable functions for exporting the private key
//--------------------------------------------------------------------------
type
  PFN_EXPORT_PRIV_KEY_FUNC = function(
    hCryptProv: HCRYPTPROV;             // in
    dwKeySpec: DWORD;                   // in
    pszPrivateKeyObjId: LPSTR;          // in
    dwFlags: DWORD;                     // in
    pvAuxInfo: Pointer;                 // in
    pPrivateKeyInfo: PCryptPrivateKeyInfo;   // out
    var pcbPrivateKeyInfo: DWORD        // in, out
    ): BOOL; winapi;
  {$EXTERNALSYM PFN_EXPORT_PRIV_KEY_FUNC}
  TFnExportPrivKeyFunc = PFN_EXPORT_PRIV_KEY_FUNC;

const
  CRYPT_OID_EXPORT_PRIVATE_KEY_INFO_FUNC  = 'CryptDllExportPrivateKeyInfoEx';
  {$EXTERNALSYM CRYPT_OID_EXPORT_PRIVATE_KEY_INFO_FUNC}

  CRYPT_DELETE_KEYSET = CRYPT_DELETEKEYSET;
  {$EXTERNALSYM CRYPT_DELETE_KEYSET}
//+-------------------------------------------------------------------------
//  CryptExportPKCS8 -- superseded by CryptExportPKCS8Ex
//
//  Export the private key in PKCS8 format
//--------------------------------------------------------------------------
function CryptExportPKCS8(
  hCryptProv: HCRYPTPROV;                                      // in
  dwKeySpec: DWORD;                                            // in
  pszPrivateKeyObjId: LPSTR;                                   // in
  dwFlags: DWORD;                                              // in
  pvAuxInfo: Pointer;                                          // in
  pbPrivateKeyBlob: PByte;                                     // out
  var pcbPrivateKeyBlob: DWORD                                 // in, out
  ): BOOL; winapi;
{$EXTERNALSYM CryptExportPKCS8}

//+-------------------------------------------------------------------------
// CryptExportPKCS8Ex
//
//  Export the private key in PKCS8 format
//
//
//  Uses the pszPrivateKeyObjId to call the
//  installable CRYPT_OID_EXPORT_PRIVATE_KEY_INFO_FUNC. The called function
//  has the signature defined by PFN_EXPORT_PRIV_KEY_FUNC.
//
//  If unable to find an installable OID function for the pszPrivateKeyObjId,
//  attempts to export as a RSA Private Key (szOID_RSA_RSA).
//
// psExportParams - specifies information about the key to export
// dwFlags - The flag values. None currently supported
// pvAuxInfo - This parameter is reserved for future use and should be set to
//                         NULL in the interim.
// pbPrivateKeyBlob - A pointer to the private key blob.  It will be encoded
//                                        as a PKCS8 PrivateKeyInfo.
// pcbPrivateKeyBlob - A pointer to a DWORD that contains the size, in bytes,
//                                         of the private key blob being exported.
//+-------------------------------------------------------------------------
function CryptExportPKCS8Ex(
  const psExportParams: TCryptPKCS8ExportParams;               // in
  dwFlags: DWORD;                                              // in
  pvAuxInfo: Pointer;                                          // in
  pbPrivateKeyBlob: PByte;                                     // out
  var pcbPrivateKeyBlob: DWORD                                 // in, out
  ): BOOL; winapi;
{$EXTERNALSYM CryptExportPKCS8Ex}

//+-------------------------------------------------------------------------
//  Compute the hash of the encoded public key info.
//
//  The public key info is encoded and then hashed.
//--------------------------------------------------------------------------
function CryptHashPublicKeyInfo(
  hCryptProv: HCRYPTPROV_LEGACY;
  Algid: ALG_ID;
  dwFlags: DWORD;
  dwCertEncodingType: DWORD;
  pInfo: PCertPublicKeyInfo;
  pbComputedHash: PByte;
  var pcbComputedHash: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptHashPublicKeyInfo}

//+-------------------------------------------------------------------------
//  Convert a Name Value to a null terminated char string
//
//  Returns the number of characters converted including the terminating null
//  character. If psz is NULL or csz is 0, returns the required size of the
//  destination string (including the terminating null char).
//
//  If psz != NULL && csz != 0, returned psz is always NULL terminated.
//
//  Note: csz includes the NULL char.
//--------------------------------------------------------------------------
function CertRDNValueToStrA(
  dwValueType: DWORD;
  pValue: PCertRDNValueBlob;
  psz: LPSTR;
  csz: DWORD): DWORD; winapi;
{$EXTERNALSYM CertRDNValueToStrA}

//+-------------------------------------------------------------------------
//  Convert a Name Value to a null terminated char string
//
//  Returns the number of characters converted including the terminating null
//  character. If psz is NULL or csz is 0, returns the required size of the
//  destination string (including the terminating null char).
//
//  If psz != NULL && csz != 0, returned psz is always NULL terminated.
//
//  Note: csz includes the NULL char.
//--------------------------------------------------------------------------
function CertRDNValueToStrW(
  dwValueType: DWORD;
  pValue: PCertRDNValueBlob;
  psz: LPWSTR;
  csz: DWORD): DWORD; winapi;
{$EXTERNALSYM CertRDNValueToStrW}

function CertRDNValueToStr(
  dwValueType: DWORD;
  pValue: PCertRDNValueBlob;
  psz: LPWSTR;
  csz: DWORD): DWORD; winapi;
{$EXTERNALSYM CertRDNValueToStr}

//+-------------------------------------------------------------------------
//  Convert the certificate name blob to a null terminated char string.
//
//  Follows the string representation of distinguished names specified in
//  RFC 1779. (Note, added double quoting "" for embedded quotes, quote
//  empty strings and don't quote strings containing consecutive spaces).
//  RDN values of type CERT_RDN_ENCODED_BLOB or CERT_RDN_OCTET_STRING are
//  formatted in hexadecimal (e.g. #0A56CF).
//
//  The name string is formatted according to the dwStrType:
//    CERT_SIMPLE_NAME_STR
//      The object identifiers are discarded. CERT_RDN entries are separated
//      by ", ". Multiple attributes per CERT_RDN are separated by " + ".
//      For example:
//          Microsoft, Joe Cool + Programmer
//    CERT_OID_NAME_STR
//      The object identifiers are included with a "=" separator from their
//      attribute value. CERT_RDN entries are separated by ", ".
//      Multiple attributes per CERT_RDN are separated by " + ". For example:
//          2.5.4.11=Microsoft, 2.5.4.3=Joe Cool + 2.5.4.12=Programmer
//    CERT_X500_NAME_STR
//      The object identifiers are converted to their X500 key name. Otherwise,
//      same as CERT_OID_NAME_STR. If the object identifier doesn't have
//      a corresponding X500 key name, then, the object identifier is used with
//      a "OID." prefix. For example:
//          OU=Microsoft, CN=Joe Cool + T=Programmer, OID.1.2.3.4.5.6=Unknown
//    CERT_XML_NAME_STR
//      The object identifiers are converted the same as the above
//      CERT_X500_NAME_STR. However, formatted as sequence of XML elements.
//      Here's an example:
//          <CN>cart.barnesandnoble.com</CN>
//          <OU>Terms of use at www.verisign.com/rpa (c)00</OU>
//          <OU rDNAttribute="true">IT Operations</OU>
//          <O>Barnesandnoble.com</O>
//          <L>New York</L>
//          <S>New York</S>
//          <C>US</C>
//          <RDN oid="1.2.3.4" type="string">name</RDN>
//          <RDN rDNAttribute="true" oid="1.2.1.3" type="encoded">0500</RDN>
//          <RDN oid="1.2.1.4" type="encoded">020135</RDN>
//          <RDN oid="1.2.2.5.3" type="octet">01FF7F</RDN>
//      Where:
//          Any XML markup characters are escaped:
//             L'&'   - L"&amp;"
//             L'<'   - L"&lt;"
//             L'>'   - L"&gt;"
//             L'\''  - L"&apos;"
//             L'\"'  - L"&quot;"
//          Will escape characters > 0x7F via chararacter references,
//          L"&#xXXXX;"
//
//          CERT_NAME_STR_REVERSE_FLAG and CERT_NAME_STR_CRLF_FLAG can be set.
//          The following quoting, semicolon and plus semantics aren't
//          applicable. The "+" is replaced with rDNAttribute="true".
//
//
//  We quote the RDN value if it contains leading or trailing whitespace
//  or one of the following characters: ",", "+", "=", """, "\n",  "<", ">",
//  "#" or ";". The quoting character is ". If the the RDN Value contains
//  a " it is double quoted (""). For example:
//      OU="  Microsoft", CN="Joe ""Cool""" + T="Programmer, Manager"
//
//  CERT_NAME_STR_SEMICOLON_FLAG can be or'ed into dwStrType to replace
//  the ", " separator with a "; " separator.
//
//  CERT_NAME_STR_CRLF_FLAG can be or'ed into dwStrType to replace
//  the ", " separator with a "\r\n" separator.
//
//  CERT_NAME_STR_NO_PLUS_FLAG can be or'ed into dwStrType to replace the
//  " + " separator with a single space, " ".
//
//  CERT_NAME_STR_NO_QUOTING_FLAG can be or'ed into dwStrType to inhibit
//  the above quoting.
//
//  CERT_NAME_STR_REVERSE_FLAG can be or'ed into dwStrType to reverse the
//  order of the RDNs before converting to the string.
//
//  By default, CERT_RDN_T61_STRING encoded values are initially decoded
//  as UTF8. If the UTF8 decoding fails, then, decoded as 8 bit characters.
//  CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG can be or'ed into dwStrType to
//  skip the initial attempt to decode as UTF8.
//
//  CERT_NAME_STR_ENABLE_PUNYCODE_FLAG can be or'ed into dwStrType to enable
//  encoding/decoding of unicode characters in email RDN value.
//
//  Returns the number of characters converted including the terminating null
//  character. If psz is NULL or csz is 0, returns the required size of the
//  destination string (including the terminating null char).
//
//  If psz != NULL && csz != 0, returned psz is always NULL terminated.
//
//  Note: csz includes the NULL char.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//--------------------------------------------------------------------------
function CertNameToStrA(
  dwCertEncodingType: DWORD;
  pName: PCertNameBlob;
  dwStrType: DWORD;
  psz: LPSTR;
  csz: DWORD): DWORD; winapi;
{$EXTERNALSYM CertNameToStrA}

//+-------------------------------------------------------------------------
//--------------------------------------------------------------------------
function CertNameToStrW(
  dwCertEncodingType: DWORD;
  pName: PCertNameBlob;
  dwStrType: DWORD;
  psz: LPWSTR;
  csz: DWORD): DWORD; winapi;
{$EXTERNALSYM CertNameToStrW}

function CertNameToStr(
  dwCertEncodingType: DWORD;
  pName: PCertNameBlob;
  dwStrType: DWORD;
  psz: LPWSTR;
  csz: DWORD): DWORD; winapi;
{$EXTERNALSYM CertNameToStr}

// certenrolld_begin -- CERT_NAME_STR_*_FLAG
//+-------------------------------------------------------------------------
//  Certificate name string types
//--------------------------------------------------------------------------
const
  CERT_SIMPLE_NAME_STR       = 1;
  {$EXTERNALSYM CERT_SIMPLE_NAME_STR}
  CERT_OID_NAME_STR          = 2;
  {$EXTERNALSYM CERT_OID_NAME_STR}
  CERT_X500_NAME_STR         = 3;
  {$EXTERNALSYM CERT_X500_NAME_STR}
  CERT_XML_NAME_STR          = 4;
  {$EXTERNALSYM CERT_XML_NAME_STR}

//+-------------------------------------------------------------------------
//  Certificate name string type flags OR'ed with the above types
//--------------------------------------------------------------------------
const
  CERT_NAME_STR_SEMICOLON_FLAG   = $40000000;
  {$EXTERNALSYM CERT_NAME_STR_SEMICOLON_FLAG}
  CERT_NAME_STR_NO_PLUS_FLAG     = $20000000;
  {$EXTERNALSYM CERT_NAME_STR_NO_PLUS_FLAG}
  CERT_NAME_STR_NO_QUOTING_FLAG  = $10000000;
  {$EXTERNALSYM CERT_NAME_STR_NO_QUOTING_FLAG}
  CERT_NAME_STR_CRLF_FLAG        = $08000000;
  {$EXTERNALSYM CERT_NAME_STR_CRLF_FLAG}
  CERT_NAME_STR_COMMA_FLAG       = $04000000;
  {$EXTERNALSYM CERT_NAME_STR_COMMA_FLAG
  CERT_NAME_STR_REVERSE_FLAG     = $02000000;
  {$EXTERNALSYM CERT_NAME_STR_REVERSE_FLAG}
  CERT_NAME_STR_FORWARD_FLAG     = $01000000;
  {$EXTERNALSYM CERT_NAME_STR_FORWARD_FLAG}

  CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG     = $00010000;
  {$EXTERNALSYM CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG}
  CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG   = $00020000;
  {$EXTERNALSYM CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG}
  CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG  = $00040000;
  {$EXTERNALSYM CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG}
  CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG   = $00080000;
  {$EXTERNALSYM CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG}
  CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG = $00100000;
  {$EXTERNALSYM CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG}
  CERT_NAME_STR_ENABLE_PUNYCODE_FLAG      = $00200000;
  {$EXTERNALSYM CERT_NAME_STR_ENABLE_PUNYCODE_FLAG}
// certenrolld_end


//+-------------------------------------------------------------------------
//  Convert the null terminated X500 string to an encoded certificate name.
//
//  The input string is expected to be formatted the same as the output
//  from the above CertNameToStr API.
//
//  The CERT_SIMPLE_NAME_STR type and CERT_XML_NAME_STR aren't supported.
//  Otherwise, when dwStrType
//  is set to 0, CERT_OID_NAME_STR or CERT_X500_NAME_STR, allow either a
//  case insensitive X500 key (CN=), case insensitive "OID." prefixed
//  object identifier (OID.1.2.3.4.5.6=) or an object identifier (1.2.3.4=).
//
//  If no flags are OR'ed into dwStrType, then, allow "," or ";" as RDN
//  separators and "+" as the multiple RDN value separator. Quoting is
//  supported. A quote may be included in a quoted value by double quoting,
//  for example (CN="Joe ""Cool"""). A value starting with a "#" is treated
//  as ascii hex and converted to a CERT_RDN_OCTET_STRING. Embedded whitespace
//  is skipped (1.2.3 = # AB CD 01  is the same as 1.2.3=#ABCD01).
//
//  Whitespace surrounding the keys, object identifers and values is removed.
//
//  CERT_NAME_STR_COMMA_FLAG can be or'ed into dwStrType to only allow the
//  "," as the RDN separator.
//
//  CERT_NAME_STR_SEMICOLON_FLAG can be or'ed into dwStrType to only allow the
//  ";" as the RDN separator.
//
//  CERT_NAME_STR_CRLF_FLAG can be or'ed into dwStrType to only allow
//  "\r" or "\n" as the RDN separator.
//
//  CERT_NAME_STR_NO_PLUS_FLAG can be or'ed into dwStrType to ignore "+"
//  as a separator and not allow multiple values per RDN.
//
//  CERT_NAME_STR_NO_QUOTING_FLAG can be or'ed into dwStrType to inhibit
//  quoting.
//
//  CERT_NAME_STR_REVERSE_FLAG can be or'ed into dwStrType to reverse the
//  order of the RDNs after converting from the string and before encoding.
//
//  CERT_NAME_STR_FORWARD_FLAG can be or'ed into dwStrType to defeat setting
//  CERT_NAME_STR_REVERSE_FLAG, if reverse order becomes the default.
//
//  CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG can be or'ed into dwStrType to
//  to select the CERT_RDN_T61_STRING encoded value type instead of
//  CERT_RDN_UNICODE_STRING if all the UNICODE characters are <= 0xFF.
//
//  CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG can be or'ed into dwStrType to
//  to select the CERT_RDN_UTF8_STRING encoded value type instead of
//  CERT_RDN_UNICODE_STRING.
//
//  CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG can be or'ed into dwStrType
//  to force the CERT_RDN_UTF8_STRING encoded value type instead of
//  allowing CERT_RDN_PRINTABLE_STRING for DirectoryString types.
//  Applies to the X500 Keys below which allow "Printable, Unicode".
//  Also, enables CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG.
//
//  CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG can be or'ed into dwStrType to
//  defeat setting CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG, if forcing UTF-8
//  becomes the default.
//
//  Support the following X500 Keys:
//
//  Key         Object Identifier               RDN Value Type(s)
//  ---         -----------------               -----------------
//  CN          szOID_COMMON_NAME               Printable, Unicode
//  L           szOID_LOCALITY_NAME             Printable, Unicode
//  O           szOID_ORGANIZATION_NAME         Printable, Unicode
//  OU          szOID_ORGANIZATIONAL_UNIT_NAME  Printable, Unicode
//  E           szOID_RSA_emailAddr             Only IA5
//  Email       szOID_RSA_emailAddr             Only IA5
//  C           szOID_COUNTRY_NAME              Only Printable
//  S           szOID_STATE_OR_PROVINCE_NAME    Printable, Unicode
//  ST          szOID_STATE_OR_PROVINCE_NAME    Printable, Unicode
//  STREET      szOID_STREET_ADDRESS            Printable, Unicode
//  T           szOID_TITLE                     Printable, Unicode
//  Title       szOID_TITLE                     Printable, Unicode
//  G           szOID_GIVEN_NAME                Printable, Unicode
//  GN          szOID_GIVEN_NAME                Printable, Unicode
//  GivenName   szOID_GIVEN_NAME                Printable, Unicode
//  I           szOID_INITIALS                  Printable, Unicode
//  Initials    szOID_INITIALS                  Printable, Unicode
//  SN          szOID_SUR_NAME                  Printable, Unicode
//  DC          szOID_DOMAIN_COMPONENT          IA5, UTF8
//  SERIALNUMBER szOID_DEVICE_SERIAL_NUMBER     Only Printable
//
//  Note, T61 is selected instead of Unicode if
//  CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG is set and all the unicode
//  characters are <= 0xFF.
//
//  Note, UTF8 is selected instead of Unicode if
//  CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG is set.
//
//  Returns TRUE if successfully parsed the input string and encoded
//  the name.
//
//  If the input string is detected to be invalid, *ppszError is updated
//  to point to the beginning of the invalid character sequence. Otherwise,
//  *ppszError is set to NULL. *ppszError is updated with a non-NULL pointer
//  for the following errors:
//      CRYPT_E_INVALID_X500_STRING
//      CRYPT_E_INVALID_NUMERIC_STRING
//      CRYPT_E_INVALID_PRINTABLE_STRING
//      CRYPT_E_INVALID_IA5_STRING
//
//  ppszError can be set to NULL if not interested in getting a pointer
//  to the invalid character sequence.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//--------------------------------------------------------------------------
function CertStrToNameA(
  dwCertEncodingType: DWORD;
  pszX500: LPCSTR;
  dwStrType: DWORD;
  pvReserved: Pointer;
  pbEncoded: PByte;
  var pcbEncoded: DWORD;
  out ppszError: LPCSTR): BOOL; winapi;
{$EXTERNALSYM CertStrToNameA}

//+-------------------------------------------------------------------------
//--------------------------------------------------------------------------
function CertStrToNameW(
  dwCertEncodingType: DWORD;
  pszX500: LPCWSTR;
  dwStrType: DWORD;
  pvReserved: Pointer;
  pbEncoded: PByte;
  var pcbEncoded: DWORD;
  out ppszError: LPCWSTR): BOOL; winapi;
{$EXTERNALSYM CertStrToNameW}

function CertStrToName(
  dwCertEncodingType: DWORD;
  pszX500: LPCWSTR;
  dwStrType: DWORD;
  pvReserved: Pointer;
  pbEncoded: PByte;
  var pcbEncoded: DWORD;
  out ppszError: LPCWSTR): BOOL; winapi;
{$EXTERNALSYM CertStrToName}

//+-------------------------------------------------------------------------
//  Get the subject or issuer name from the certificate and
//  according to the specified format type, convert to a null terminated
//  character string.
//
//  CERT_NAME_ISSUER_FLAG can be set to get the issuer's name. Otherwise,
//  gets the subject's name.
//
//  By default, CERT_RDN_T61_STRING encoded values are initially decoded
//  as UTF8. If the UTF8 decoding fails, then, decoded as 8 bit characters.
//  CERT_NAME_DISABLE_IE4_UTF8_FLAG can be set in dwFlags to
//  skip the initial attempt to decode as UTF8.
//
//  The name string is formatted according to the dwType:
//    CERT_NAME_EMAIL_TYPE
//      If the certificate has a Subject Alternative Name extension (for
//      issuer, Issuer Alternative Name), searches for first rfc822Name choice.
//      If the rfc822Name choice isn't found in the extension, searches the
//      Subject Name field for the Email OID, "1.2.840.113549.1.9.1".
//      If the rfc822Name or Email OID is found, returns the string. Otherwise,
//      returns an empty string (returned character count is 1).
//    CERT_NAME_DNS_TYPE
//      If the certificate has a Subject Alternative Name extension (for
//      issuer, Issuer Alternative Name), searches for first DNSName choice.
//      If the DNSName choice isn't found in the extension, searches the
//      Subject Name field for the CN OID, "2.5.4.3".
//      If the DNSName or CN OID is found, returns the string. Otherwise,
//      returns an empty string.
//    CERT_NAME_URL_TYPE
//      If the certificate has a Subject Alternative Name extension (for
//      issuer, Issuer Alternative Name), searches for first URL choice.
//      If the URL choice is found, returns the string. Otherwise,
//      returns an empty string.
//    CERT_NAME_UPN_TYPE
//      If the certificate has a Subject Alternative Name extension,
//      searches the OtherName choices looking for a
//      pszObjId == szOID_NT_PRINCIPAL_NAME, "1.3.6.1.4.1.311.20.2.3".
//      If the UPN OID is found, the blob is decoded as a
//      X509_UNICODE_ANY_STRING and the decoded string is returned.
//      Otherwise, returns an empty string.
//    CERT_NAME_RDN_TYPE
//      Converts the Subject Name blob by calling CertNameToStr. pvTypePara
//      points to a DWORD containing the dwStrType passed to CertNameToStr.
//      If the Subject Name field is empty and the certificate has a
//      Subject Alternative Name extension, searches for and converts
//      the first directoryName choice.
//    CERT_NAME_ATTR_TYPE
//      pvTypePara points to the Object Identifier specifying the name attribute
//      to be returned. For example, to get the CN,
//      pvTypePara = szOID_COMMON_NAME ("2.5.4.3"). Searches, the Subject Name
//      field for the attribute.
//      If the Subject Name field is empty and the certificate has a
//      Subject Alternative Name extension, checks for
//      the first directoryName choice and searches it.
//
//      Note, searches the RDNs in reverse order.
//
//    CERT_NAME_SIMPLE_DISPLAY_TYPE
//      Iterates through the following list of name attributes and searches
//      the Subject Name and then the Subject Alternative Name extension
//      for the first occurrence of:
//          szOID_COMMON_NAME ("2.5.4.3")
//          szOID_ORGANIZATIONAL_UNIT_NAME ("2.5.4.11")
//          szOID_ORGANIZATION_NAME ("2.5.4.10")
//          szOID_RSA_emailAddr ("1.2.840.113549.1.9.1")
//
//      If none of the above attributes is found, then, searches the
//      Subject Alternative Name extension for a rfc822Name choice.
//
//      If still no match, then, returns the first attribute.
//
//      Note, like CERT_NAME_ATTR_TYPE, searches the RDNs in reverse order.
//
//    CERT_NAME_FRIENDLY_DISPLAY_TYPE
//      First checks if the certificate has a CERT_FRIENDLY_NAME_PROP_ID
//      property. If it does, then, this property is returned. Otherwise,
//      returns the above CERT_NAME_SIMPLE_DISPLAY_TYPE.
//
//  Returns the number of characters converted including the terminating null
//  character. If pwszNameString is NULL or cchNameString is 0, returns the
//  required size of the destination string (including the terminating null
//  char). If the specified name type isn't found. returns an empty string
//  with a returned character count of 1.
//
//  If pwszNameString != NULL && cwszNameString != 0, returned pwszNameString
//  is always NULL terminated.
//
//  Note: cchNameString includes the NULL char.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//--------------------------------------------------------------------------
function CertGetNameStringA(
  pCertContext: PCertContext;
  dwType: DWORD;
  dwFlags: DWORD;
  pvTypePara: Pointer;
  pszNameString: LPSTR;
  cchNameString: DWORD): DWORD; winapi;
{$EXTERNALSYM CertGetNameStringA}

//+-------------------------------------------------------------------------
//--------------------------------------------------------------------------
function CertGetNameStringW(
  pCertContext: PCertContext;
  dwType: DWORD;
  dwFlags: DWORD;
  pvTypePara: Pointer;
  pszNameString: LPWSTR;
  cchNameString: DWORD): DWORD; winapi;
{$EXTERNALSYM CertGetNameStringW}

function CertGetNameString(
  pCertContext: PCertContext;
  dwType: DWORD;
  dwFlags: DWORD;
  pvTypePara: Pointer;
  pszNameString: LPWSTR;
  cchNameString: DWORD): DWORD; winapi;
{$EXTERNALSYM CertGetNameString}

//+-------------------------------------------------------------------------
//  Certificate name types
//--------------------------------------------------------------------------
const
  CERT_NAME_EMAIL_TYPE            = 1;
  {$EXTERNALSYM CERT_NAME_EMAIL_TYPE}
  CERT_NAME_RDN_TYPE              = 2;
  {$EXTERNALSYM CERT_NAME_RDN_TYPE}
  CERT_NAME_ATTR_TYPE             = 3;
  {$EXTERNALSYM CERT_NAME_ATTR_TYPE}
  CERT_NAME_SIMPLE_DISPLAY_TYPE   = 4;
  {$EXTERNALSYM CERT_NAME_SIMPLE_DISPLAY_TYPE}
  CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5;
  {$EXTERNALSYM CERT_NAME_FRIENDLY_DISPLAY_TYPE}
  CERT_NAME_DNS_TYPE              = 6;
  {$EXTERNALSYM CERT_NAME_DNS_TYPE}
  CERT_NAME_URL_TYPE              = 7;
  {$EXTERNALSYM CERT_NAME_URL_TYPE}
  CERT_NAME_UPN_TYPE              = 8;
  {$EXTERNALSYM CERT_NAME_UPN_TYPE}

//+-------------------------------------------------------------------------
//  Certificate name flags
//--------------------------------------------------------------------------
const
  CERT_NAME_ISSUER_FLAG           = $1;
  {$EXTERNALSYM CERT_NAME_ISSUER_FLAG}
  CERT_NAME_DISABLE_IE4_UTF8_FLAG = $00010000;
  {$EXTERNALSYM CERT_NAME_DISABLE_IE4_UTF8_FLAG}


// Following is only applicable to CERT_NAME_DNS_TYPE. When set returns
// all names not just the first one. Returns a multi-string. Each string
// will be null terminated. The last string will be double null terminated.
const
  CERT_NAME_SEARCH_ALL_NAMES_FLAG = $2;
  {$EXTERNALSYM CERT_NAME_SEARCH_ALL_NAMES_FLAG}


//+=========================================================================
//  Simplified Cryptographic Message Data Structures and APIs
//==========================================================================


//+-------------------------------------------------------------------------
//              Conventions for the *pb and *pcb output parameters:
//
//              Upon entry to the function:
//                  if pcb is OPTIONAL && pcb == NULL, then,
//                      No output is returned
//                  else if pb == NULL && pcb != NULL, then,
//                      Length only determination. No length error is
//                      returned.
//                  otherwise where (pb != NULL && pcb != NULL && *pcb != 0)
//                      Output is returned. If *pcb isn't big enough a
//                      length error is returned. In all cases *pcb is updated
//                      with the actual length needed/returned.
//--------------------------------------------------------------------------


//+-------------------------------------------------------------------------
//  Type definitions of the parameters used for doing the cryptographic
//  operations.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  Callback to get and verify the signer's certificate.
//
//  Passed the CertId of the signer (its Issuer and SerialNumber) and a
//  handle to its cryptographic signed message's cert store.
//
//  For CRYPT_E_NO_SIGNER, called with pSignerId == NULL.
//
//  For a valid signer certificate, returns a pointer to a read only
//  CERT_CONTEXT. The returned CERT_CONTEXT is either obtained from a
//  cert store or was created via CertCreateCertificateContext. For either case,
//  its freed via CertFreeCertificateContext.
//
//  If a valid certificate isn't found, this callback returns NULL with
//  LastError set via SetLastError().
//
//  The NULL implementation tries to get the Signer certificate from the
//  message cert store. It doesn't verify the certificate.
//
//  Note, if the KEYID choice was selected for a CMS SignerId, then, the
//  SerialNumber is 0 and the Issuer is encoded containing a single RDN with a
//  single Attribute whose OID is szOID_KEYID_RDN, value type is
//  CERT_RDN_OCTET_STRING and value is the KEYID. When the
//  CertGetSubjectCertificateFromStore and
//  CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) APIs see this
//  special KEYID Issuer and SerialNumber, they do a KEYID match.
//--------------------------------------------------------------------------
type
  PFN_CRYPT_GET_SIGNER_CERTIFICATE = function(
    pvGetArg: Pointer;
    dwCertEncodingType: DWORD;
    pSignerId: PCertInfo;       // Only the Issuer and SerialNumber
                                // fields have been updated
    hMsgCertStore: HCERTSTORE): PCertContext; winapi;
  {$EXTERNALSYM PFN_CRYPT_GET_SIGNER_CERTIFICATE}
  TFnCryptGetSignerCertificate = PFN_CRYPT_GET_SIGNER_CERTIFICATE;

//+-------------------------------------------------------------------------
//  The CRYPT_SIGN_MESSAGE_PARA are used for signing messages using the
//  specified signing certificate context.
//
//  Either the CERT_KEY_PROV_HANDLE_PROP_ID or CERT_KEY_PROV_INFO_PROP_ID must
//  be set for each rgpSigningCert[]. Either one specifies the private
//  signature key to use.
//
//  If any certificates and/or CRLs are to be included in the signed message,
//  then, the MsgCert and MsgCrl parameters need to be updated. If the
//  rgpSigningCerts are to be included, then, they must also be in the
//  rgpMsgCert array.
//
//  cbSize must be set to the sizeof(CRYPT_SIGN_MESSAGE_PARA) or else
//  LastError will be updated with E_INVALIDARG.
//
//  pvHashAuxInfo currently isn't used and must be set to NULL.
//
//  dwFlags normally is set to 0. However, if the encoded output
//  is to be a CMSG_SIGNED inner content of an outer cryptographic message,
//  such as a CMSG_ENVELOPED, then, the CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG
//  should be set. If not set, then it would be encoded as an inner content
//  type of CMSG_DATA.
//
//  dwInnerContentType is normally set to 0. It needs to be set if the
//  ToBeSigned input is the encoded output of another cryptographic
//  message, such as, an CMSG_ENVELOPED. When set, it's one of the cryptographic
//  message types, for example, CMSG_ENVELOPED.
//
//  If the inner content of a nested cryptographic message is data (CMSG_DATA
//  the default), then, neither dwFlags or dwInnerContentType need to be set.
//
//  For CMS messages, CRYPT_MESSAGE_ENCAPSULATED_CONTENT_OUT_FLAG may be
//  set to encapsulate nonData inner content within an OCTET STRING.
//
//  For CMS messages, CRYPT_MESSAGE_KEYID_SIGNER_FLAG may be set to identify
//  signers by their Key Identifier and not their Issuer and Serial Number.
//
//  The CRYPT_MESSAGE_SILENT_KEYSET_FLAG can be set to suppress any UI by the
//  CSP. See CryptAcquireContext's CRYPT_SILENT flag for more details.
//
//  If HashEncryptionAlgorithm is present and not NULL its used instead of
//  the SigningCert's PublicKeyInfo.Algorithm.
//
//  Note, for RSA, the hash encryption algorithm is normally the same as
//  the public key algorithm. For DSA, the hash encryption algorithm is
//  normally a DSS signature algorithm.
//
//  pvHashEncryptionAuxInfo currently isn't used and must be set to NULL if
//  present in the data structure.
//--------------------------------------------------------------------------
type
  PCryptSignMessagePara = ^TCryptSignMessagePara;
  _CRYPT_SIGN_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgEncodingType: DWORD;
    pSigningCert: PCertContext;
    HashAlgorithm: TCryptAlgorithmIdentifier;
    pvHashAuxInfo: Pointer;
    cMsgCert: DWORD;
    rgpMsgCert: ^PCertContext;
    cMsgCrl: DWORD;
    rgpMsgCrl: ^PCRLContext;
    cAuthAttr: DWORD;
    rgAuthAttr: PCryptAttribute;
    cUnauthAttr: DWORD;
    rgUnauthAttr: PCryptAttribute;
    dwFlags: DWORD;
    dwInnerContentType: DWORD;

//{$IFDEF CRYPT_SIGN_MESSAGE_PARA_HAS_CMS_FIELDS}
    // This is also referred to as the SignatureAlgorithm
    HashEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvHashEncryptionAuxInfo: Pointer;
//{$ENDIF}
  end;
  {$EXTERNALSYM _CRYPT_SIGN_MESSAGE_PARA}
  CRYPT_SIGN_MESSAGE_PARA = _CRYPT_SIGN_MESSAGE_PARA;
  {$EXTERNALSYM CRYPT_SIGN_MESSAGE_PARA}
  TCryptSignMessagePara = _CRYPT_SIGN_MESSAGE_PARA;
  PCRYPT_SIGN_MESSAGE_PARA = PCryptSignMessagePara;
  {$EXTERNALSYM PCRYPT_SIGN_MESSAGE_PARA}

const
  CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG         = $00000001;
  {$EXTERNALSYM CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG}

// When set, nonData type inner content is encapsulated within an
// OCTET STRING
const
  CRYPT_MESSAGE_ENCAPSULATED_CONTENT_OUT_FLAG = $00000002;
  {$EXTERNALSYM CRYPT_MESSAGE_ENCAPSULATED_CONTENT_OUT_FLAG}

// When set, signers are identified by their Key Identifier and not
// their Issuer and Serial Number.
const
  CRYPT_MESSAGE_KEYID_SIGNER_FLAG             = $00000004;
  {$EXTERNALSYM CRYPT_MESSAGE_KEYID_SIGNER_FLAG}

// When set, suppresses any UI by the CSP.
// See CryptAcquireContext's CRYPT_SILENT flag for more details.
const
  CRYPT_MESSAGE_SILENT_KEYSET_FLAG            = $00000040;
  {$EXTERNALSYM CRYPT_MESSAGE_SILENT_KEYSET_FLAG}

//+-------------------------------------------------------------------------
//  The CRYPT_VERIFY_MESSAGE_PARA are used to verify signed messages.
//
//  hCryptProv is used to do hashing and signature verification.
//
//  The dwCertEncodingType specifies the encoding type of the certificates
//  and/or CRLs in the message.
//
//  pfnGetSignerCertificate is called to get and verify the message signer's
//  certificate.
//
//  cbSize must be set to the sizeof(CRYPT_VERIFY_MESSAGE_PARA) or else
//  LastError will be updated with E_INVALIDARG.
//--------------------------------------------------------------------------
type
  PCryptVerfiyMessagePara = ^TCryptVerfiyMessagePara;
  _CRYPT_VERIFY_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgAndCertEncodingType: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    pfnGetSignerCertificate: TFnCryptGetSignerCertificate;
    pvGetArg: Pointer;

//{$IFDEF CRYPT_VERIFY_MESSAGE_PARA_HAS_EXTRA_FIELDS}

    // Note, if you #define CRYPT_VERIFY_MESSAGE_PARA_HAS_EXTRA_FIELDS,
    // then, you must zero all unused fields in this data structure.
    // More fields could be added in a future release.

    //
    // The following is set to check for Strong and Restricted Signatures
    //
    pStrongSignPara: PCertStrongSignPara;

//{$ENDIF}
  end;
  {$EXTERNALSYM _CRYPT_VERIFY_MESSAGE_PARA}
  CRYPT_VERIFY_MESSAGE_PARA = _CRYPT_VERIFY_MESSAGE_PARA;
  {$EXTERNALSYM CRYPT_VERIFY_MESSAGE_PARA}
  TCryptVerfiyMessagePara = _CRYPT_VERIFY_MESSAGE_PARA;
  PCRYPT_VERIFY_MESSAGE_PARA = PCryptVerfiyMessagePara;
  {$EXTERNALSYM PCRYPT_VERIFY_MESSAGE_PARA}

//+-------------------------------------------------------------------------
//  The CRYPT_ENCRYPT_MESSAGE_PARA are used for encrypting messages.
//
//  hCryptProv is used to do content encryption, recipient key
//  encryption, and recipient key export. Its private key
//  isn't used.
//
//  Currently, pvEncryptionAuxInfo is only defined for RC2 or RC4 encryption
//  algorithms. Otherwise, its not used and must be set to NULL.
//  See CMSG_RC2_AUX_INFO for the RC2 encryption algorithms.
//  See CMSG_RC4_AUX_INFO for the RC4 encryption algorithms.
//
//  To enable SP3 compatible encryption, pvEncryptionAuxInfo should point to
//  a CMSG_SP3_COMPATIBLE_AUX_INFO data structure.
//
//  cbSize must be set to the sizeof(CRYPT_ENCRYPT_MESSAGE_PARA) or else
//  LastError will be updated with E_INVALIDARG.
//
//  dwFlags normally is set to 0. However, if the encoded output
//  is to be a CMSG_ENVELOPED inner content of an outer cryptographic message,
//  such as a CMSG_SIGNED, then, the CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG
//  should be set. If not set, then it would be encoded as an inner content
//  type of CMSG_DATA.
//
//  dwInnerContentType is normally set to 0. It needs to be set if the
//  ToBeEncrypted input is the encoded output of another cryptographic
//  message, such as, an CMSG_SIGNED. When set, it's one of the cryptographic
//  message types, for example, CMSG_SIGNED.
//
//  If the inner content of a nested cryptographic message is data (CMSG_DATA
//  the default), then, neither dwFlags or dwInnerContentType need to be set.
//
//  For CMS messages, CRYPT_MESSAGE_ENCAPSULATED_CONTENT_OUT_FLAG may be
//  set to encapsulate nonData inner content within an OCTET STRING before
//  encrypting.
//
//  For CMS messages, CRYPT_MESSAGE_KEYID_RECIPIENT_FLAG may be set to identify
//  recipients by their Key Identifier and not their Issuer and Serial Number.
//--------------------------------------------------------------------------
type
  PCryptEncryptMessagePara = ^TCryptEncryptMessagePara;
  _CRYPT_ENCRYPT_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgEncodingType: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    ContentEncryptionAlgorithm: TCryptAlgorithmIdentifier;
    pvEncryptionAuxInfo: Pointer;
    dwFlags: DWORD;
    dwInnerContentType: DWORD;
  end;
  {$EXTERNALSYM _CRYPT_ENCRYPT_MESSAGE_PARA}
  CRYPT_ENCRYPT_MESSAGE_PARA = _CRYPT_ENCRYPT_MESSAGE_PARA;
  {$EXTERNALSYM CRYPT_ENCRYPT_MESSAGE_PARA}
  TCryptEncryptMessagePara = _CRYPT_ENCRYPT_MESSAGE_PARA;
  PCRYPT_ENCRYPT_MESSAGE_PARA = PCryptEncryptMessagePara;
  {$EXTERNALSYM PCRYPT_ENCRYPT_MESSAGE_PARA}

// When set, recipients are identified by their Key Identifier and not
// their Issuer and Serial Number.
const
  CRYPT_MESSAGE_KEYID_RECIPIENT_FLAG         = $4;
  {$EXTERNALSYM CRYPT_MESSAGE_KEYID_RECIPIENT_FLAG}

//+-------------------------------------------------------------------------
//  The CRYPT_DECRYPT_MESSAGE_PARA are used for decrypting messages.
//
//  The CertContext to use for decrypting a message is obtained from one
//  of the specified cert stores. An encrypted message can have one or
//  more recipients. The recipients are identified by their CertId (Issuer
//  and SerialNumber). The cert stores are searched to find the CertContext
//  corresponding to the CertId.
//
//  For CMS, the recipients may also be identified by their KeyId.
//  CMS also allows Key Agreement (Diffie Hellman) in addition to
//  Key Transport (RSA) recipients.
//
//  Only CertContexts in the store with either
//  the CERT_KEY_PROV_HANDLE_PROP_ID or CERT_KEY_PROV_INFO_PROP_ID set
//  can be used. Either property specifies the private exchange key to use.
//
//  cbSize must be set to the sizeof(CRYPT_DECRYPT_MESSAGE_PARA) or else
//  LastError will be updated with E_INVALIDARG.
//--------------------------------------------------------------------------
type
  PCryptDecryptMessagePara = ^TCryptDecryptMessagePara;
  _CRYPT_DECRYPT_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgAndCertEncodingType: DWORD;
    cCertStore: DWORD;
    rghCertStore: ^HCERTSTORE;

//{$IFDEF CRYPT_DECRYPT_MESSAGE_PARA_HAS_EXTRA_FIELDS}
// The above defined, CRYPT_MESSAGE_SILENT_KEYSET_FLAG, can be set to
// suppress UI by the CSP.  See CryptAcquireContext's CRYPT_SILENT
// flag for more details.

    dwFlags: DWORD;
//{$ENDIF}

  end;
  {$EXTERNALSYM _CRYPT_DECRYPT_MESSAGE_PARA}
  CRYPT_DECRYPT_MESSAGE_PARA = _CRYPT_DECRYPT_MESSAGE_PARA;
  {$EXTERNALSYM CRYPT_DECRYPT_MESSAGE_PARA}
  TCryptDecryptMessagePara = _CRYPT_DECRYPT_MESSAGE_PARA;
  PCRYPT_DECRYPT_MESSAGE_PARA = PCryptDecryptMessagePara;
  {$EXTERNALSYM PCRYPT_DECRYPT_MESSAGE_PARA}

//+-------------------------------------------------------------------------
//  The CRYPT_HASH_MESSAGE_PARA are used for hashing or unhashing
//  messages.
//
//  hCryptProv is used to compute the hash.
//
//  pvHashAuxInfo currently isn't used and must be set to NULL.
//
//  cbSize must be set to the sizeof(CRYPT_HASH_MESSAGE_PARA) or else
//  LastError will be updated with E_INVALIDARG.
//--------------------------------------------------------------------------
type
  PCryptHashMessagePara = ^TCryptHashMessagePara;
  _CRYPT_HASH_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgEncodingType: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
    HashAlgorithm: TCryptAlgorithmIdentifier;
    pvHashAuxInfo: Pointer;
  end;
  {$EXTERNALSYM _CRYPT_HASH_MESSAGE_PARA}
  CRYPT_HASH_MESSAGE_PARA = _CRYPT_HASH_MESSAGE_PARA;
  {$EXTERNALSYM CRYPT_HASH_MESSAGE_PARA}
  TCryptHashMessagePara = _CRYPT_HASH_MESSAGE_PARA;
  PCRYPT_HASH_MESSAGE_PARA = PCryptHashMessagePara;
  {$EXTERNALSYM PCRYPT_HASH_MESSAGE_PARA}


//+-------------------------------------------------------------------------
//  The CRYPT_KEY_SIGN_MESSAGE_PARA are used for signing messages until a
//  certificate has been created for the signature key.
//
//  pvHashAuxInfo currently isn't used and must be set to NULL.
//
//  If PubKeyAlgorithm isn't set, defaults to szOID_RSA_RSA.
//
//  cbSize must be set to the sizeof(CRYPT_KEY_SIGN_MESSAGE_PARA) or else
//  LastError will be updated with E_INVALIDARG.
//--------------------------------------------------------------------------
type
  PCryptKeySignMessagePara = ^TCryptKeySignMessagePara;
  _CRYPT_KEY_SIGN_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgAndCertEncodingType: DWORD;

    // NCryptIsKeyHandle() is called to determine the union choice.
    case Integer of
    0: (hCryptProv: HCRYPTPROV);
    1: (hNCryptKey: NCRYPT_KEY_HANDLE;

    // not applicable for hNCryptKey choice
    dwKeySpec: DWORD;

    HashAlgorithm: TCryptAlgorithmIdentifier;
    pvHashAuxInfo: Pointer;
    // This is also referred to as the SignatureAlgorithm
    PubKeyAlgorithm: TCryptAlgorithmIdentifier);
  end;
  {$EXTERNALSYM _CRYPT_KEY_SIGN_MESSAGE_PARA}
  CRYPT_KEY_SIGN_MESSAGE_PARA = _CRYPT_KEY_SIGN_MESSAGE_PARA;
  {$EXTERNALSYM CRYPT_KEY_SIGN_MESSAGE_PARA}
  TCryptKeySignMessagePara = _CRYPT_KEY_SIGN_MESSAGE_PARA;
  PCRYPT_KEY_SIGN_MESSAGE_PARA = PCryptKeySignMessagePara;
  {$EXTERNALSYM PCRYPT_KEY_SIGN_MESSAGE_PARA}

//+-------------------------------------------------------------------------
//  The CRYPT_KEY_VERIFY_MESSAGE_PARA are used to verify signed messages without
//  a certificate for the signer.
//
//  Normally used until a certificate has been created for the key.
//
//  hCryptProv is used to do hashing and signature verification.
//
//  cbSize must be set to the sizeof(CRYPT_KEY_VERIFY_MESSAGE_PARA) or else
//  LastError will be updated with E_INVALIDARG.
//--------------------------------------------------------------------------
type
  PCryptKeyVerifyMessagePara = ^TCryptKeyVerifyMessagePara;
  _CRYPT_KEY_VERIFY_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgEncodingType: DWORD;
    hCryptProv: HCRYPTPROV_LEGACY;
  end;
  {$EXTERNALSYM _CRYPT_KEY_VERIFY_MESSAGE_PARA}
  CRYPT_KEY_VERIFY_MESSAGE_PARA = _CRYPT_KEY_VERIFY_MESSAGE_PARA;
  {$EXTERNALSYM CRYPT_KEY_VERIFY_MESSAGE_PARA}
  TCryptKeyVerifyMessagePara = _CRYPT_KEY_VERIFY_MESSAGE_PARA;
  PCRYPT_KEY_VERIFY_MESSAGE_PARA = PCryptKeyVerifyMessagePara;
  {$EXTERNALSYM PCRYPT_KEY_VERIFY_MESSAGE_PARA}


//+-------------------------------------------------------------------------
//  Sign the message.
//
//  If fDetachedSignature is TRUE, the "to be signed" content isn't included
//  in the encoded signed blob.
//--------------------------------------------------------------------------
function CryptSignMessage(
  pSignPara: PCryptSignMessagePara;
  fDetachedSignature: BOOL;
  cToBeSigned: DWORD;
  var rgpbToBeSigned: PByte;
  var rgcbToBeSigned: DWORD;
  pbSignedBlob: PByte;
  var pcbSignedBlob: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignMessage}

//+-------------------------------------------------------------------------
//  Verify a signed message.
//
//  If pbDecoded == NULL, then, *pcbDecoded is implicitly set to 0 on input.
//  For *pcbDecoded == 0 && ppSignerCert == NULL on input, the signer isn't
//  verified.
//
//  A message might have more than one signer. Set dwSignerIndex to iterate
//  through all the signers. dwSignerIndex == 0 selects the first signer.
//
//  pVerifyPara's pfnGetSignerCertificate is called to get the signer's
//  certificate.
//
//  For a verified signer and message, *ppSignerCert is updated
//  with the CertContext of the signer. It must be freed by calling
//  CertFreeCertificateContext. Otherwise, *ppSignerCert is set to NULL.
//
//  ppSignerCert can be NULL, indicating the caller isn't interested
//  in getting the CertContext of the signer.
//
//  pcbDecoded can be NULL, indicating the caller isn't interested in getting
//  the decoded content. Furthermore, if the message doesn't contain any
//  content or signers, then, pcbDecoded must be set to NULL, to allow the
//  pVerifyPara->pfnGetCertificate to be called. Normally, this would be
//  the case when the signed message contains only certficates and CRLs.
//  If pcbDecoded is NULL and the message doesn't have the indicated signer,
//  pfnGetCertificate is called with pSignerId set to NULL.
//
//  If the message doesn't contain any signers || dwSignerIndex > message's
//  SignerCount, then, an error is returned with LastError set to
//  CRYPT_E_NO_SIGNER. Also, for CRYPT_E_NO_SIGNER, pfnGetSignerCertificate
//  is still called with pSignerId set to NULL.
//
//  Note, an alternative way to get the certificates and CRLs from a
//  signed message is to call CryptGetMessageCertificates.
//--------------------------------------------------------------------------
function CryptVerifyMessageSignature(
  pVerifyPara: PCryptVerfiyMessagePara;
  dwSignerIndex: DWORD;
  pbSignedBlob: PByte;
  cbSignedBlob: DWORD;
  pbDecoded: PByte;
  pcbDecoded: PDWORD;
  ppSignerCert: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CryptVerifyMessageSignature}

//+-------------------------------------------------------------------------
//  Returns the count of signers in the signed message. For no signers, returns
//  0. For an error returns -1 with LastError updated accordingly.
//--------------------------------------------------------------------------
function CryptGetMessageSignerCount(
  dwMsgEncodingType: DWORD;
  pbSignedBlob: PByte;
  cbSignedBlob: DWORD): LONG; winapi;
{$EXTERNALSYM CryptGetMessageSignerCount}

//+-------------------------------------------------------------------------
//  Returns the cert store containing the message's certs and CRLs.
//  For an error, returns NULL with LastError updated.
//--------------------------------------------------------------------------
function CryptGetMessageCertificates(
  dwMsgAndCertEncodingType: DWORD;
  hCryptProv: HCRYPTPROV_LEGACY;            // passed to CertOpenStore
  dwFlags: DWORD;                   // passed to CertOpenStore
  pbSignedBlob: PByte;
  cbSignedBlob: DWORD): HCERTSTORE; winapi;
{$EXTERNALSYM CryptGetMessageCertificates}

//+-------------------------------------------------------------------------
//  Verify a signed message containing detached signature(s).
//  The "to be signed" content is passed in separately. No
//  decoded output. Otherwise, identical to CryptVerifyMessageSignature.
//--------------------------------------------------------------------------
function CryptVerifyDetachedMessageSignature(
  pVerifyPara: PCryptVerfiyMessagePara;
  dwSignerIndex: DWORD;
  pbDetachedSignBlob: PByte;
  cbDetachedSignBlob: DWORD;
  cToBeSigned: DWORD;
  var rgpbToBeSigned: PByte;
  var rgcbToBeSigned: DWORD;
  ppSignerCert: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CryptVerifyDetachedMessageSignature}

//+-------------------------------------------------------------------------
//  Encrypts the message for the recipient(s).
//--------------------------------------------------------------------------
function CryptEncryptMessage(
  pEncryptPara: PCryptEncryptMessagePara;
  cRecipientCert: DWORD;
  var rgpRecipientCert: PCertContext;
  pbToBeEncrypted: PByte;
  cbToBeEncrypted: DWORD;
  pbEncryptedBlob: PByte;
  var pcbEncryptedBlob: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptEncryptMessage}

//+-------------------------------------------------------------------------
//  Decrypts the message.
//
//  If pbDecrypted == NULL, then, *pcbDecrypted is implicitly set to 0 on input.
//  For *pcbDecrypted == 0 && ppXchgCert == NULL on input, the message isn't
//  decrypted.
//
//  For a successfully decrypted message, *ppXchgCert is updated
//  with the CertContext used to decrypt. It must be freed by calling
//  CertStoreFreeCert. Otherwise, *ppXchgCert is set to NULL.
//
//  ppXchgCert can be NULL, indicating the caller isn't interested
//  in getting the CertContext used to decrypt.
//--------------------------------------------------------------------------
function CryptDecryptMessage(
  pDecryptPara: PCryptDecryptMessagePara;
  pbEncryptedBlob: PByte;
  cbEncryptedBlob: DWORD;
  pbDecrypted: PByte;
  pcbDecrypted: PDWORD;
  ppXchgCert: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CryptDecryptMessage}

//+-------------------------------------------------------------------------
//  Sign the message and encrypt for the recipient(s). Does a CryptSignMessage
//  followed with a CryptEncryptMessage.
//
//  Note: this isn't the CMSG_SIGNED_AND_ENVELOPED. Its a CMSG_SIGNED
//  inside of an CMSG_ENVELOPED.
//--------------------------------------------------------------------------
function CryptSignAndEncryptMessage(
  pSignPara: PCryptSignMessagePara;
  pEncryptPara: PCryptEncryptMessagePara;
  cRecipientCert: DWORD;
  var rgpRecipientCert: PCertContext;
  pbToBeSignedAndEncrypted: PByte;
  cbToBeSignedAndEncrypted: DWORD;
  pbSignedAndEncryptedBlob: PByte;
  var pcbSignedAndEncryptedBlob: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignAndEncryptMessage}

//+-------------------------------------------------------------------------
//  Decrypts the message and verifies the signer. Does a CryptDecryptMessage
//  followed with a CryptVerifyMessageSignature.
//
//  If pbDecrypted == NULL, then, *pcbDecrypted is implicitly set to 0 on input.
//  For *pcbDecrypted == 0 && ppSignerCert == NULL on input, the signer isn't
//  verified.
//
//  A message might have more than one signer. Set dwSignerIndex to iterate
//  through all the signers. dwSignerIndex == 0 selects the first signer.
//
//  The pVerifyPara's VerifySignerPolicy is called to verify the signer's
//  certificate.
//
//  For a successfully decrypted and verified message, *ppXchgCert and
//  *ppSignerCert are updated. They must be freed by calling
//  CertStoreFreeCert. Otherwise, they are set to NULL.
//
//  ppXchgCert and/or ppSignerCert can be NULL, indicating the
//  caller isn't interested in getting the CertContext.
//
//  Note: this isn't the CMSG_SIGNED_AND_ENVELOPED. Its a CMSG_SIGNED
//  inside of an CMSG_ENVELOPED.
//
//  The message always needs to be decrypted to allow access to the
//  signed message. Therefore, if ppXchgCert != NULL, its always updated.
//--------------------------------------------------------------------------
function CryptDecryptAndVerifyMessageSignature(
  pDecryptPara: PCryptDecryptMessagePara;
  pVerifyPara: PCryptVerfiyMessagePara;
  dwSignerIndex: DWORD;
  pbEncryptedBlob: PByte;
  cbEncryptedBlob: DWORD;
  pbDecrypted: PByte;
  pcbDecrypted: PDWORD;
  ppXchgCert: PPCertContext;
  ppSignerCert: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CryptDecryptAndVerifyMessageSignature}

//+-------------------------------------------------------------------------
//  Decodes a cryptographic message which may be one of the following types:
//    CMSG_DATA
//    CMSG_SIGNED
//    CMSG_ENVELOPED
//    CMSG_SIGNED_AND_ENVELOPED
//    CMSG_HASHED
//
//  dwMsgTypeFlags specifies the set of allowable messages. For example, to
//  decode either SIGNED or ENVELOPED messages, set dwMsgTypeFlags to:
//      CMSG_SIGNED_FLAG | CMSG_ENVELOPED_FLAG.
//
//  dwProvInnerContentType is only applicable when processing nested
//  crytographic messages. When processing an outer crytographic message
//  it must be set to 0. When decoding a nested cryptographic message
//  its the dwInnerContentType returned by a previous CryptDecodeMessage
//  of the outer message. The InnerContentType can be any of the CMSG types,
//  for example, CMSG_DATA, CMSG_SIGNED, ...
//
//  The optional *pdwMsgType is updated with the type of message.
//
//  The optional *pdwInnerContentType is updated with the type of the inner
//  message. Unless there is cryptographic message nesting, CMSG_DATA
//  is returned.
//
//  For CMSG_DATA: returns decoded content.
//  For CMSG_SIGNED: same as CryptVerifyMessageSignature.
//  For CMSG_ENVELOPED: same as CryptDecryptMessage.
//  For CMSG_SIGNED_AND_ENVELOPED: same as CryptDecryptMessage plus
//      CryptVerifyMessageSignature.
//  For CMSG_HASHED: verifies the hash and returns decoded content.
//--------------------------------------------------------------------------
function CryptDecodeMessage(
  dwMsgTypeFlags: DWORD;
  pDecryptPara: PCryptDecryptMessagePara;
  pVerifyPara: PCryptVerfiyMessagePara;
  dwSignerIndex: DWORD;
  pbEncodedBlob: PByte;
  cbEncodedBlob: DWORD;
  dwPrevInnerContentType: DWORD;
  pdwMsgType: PDWORD;
  pdwInnerContentType: PDWORD;
  pbDecoded: PByte;
  pcbDecoded: PDWORD;
  ppXchgCert: PPCertContext;
  ppSignerCert: PPCertContext): BOOL; winapi;
{$EXTERNALSYM CryptDecodeMessage}

//+-------------------------------------------------------------------------
//  Hash the message.
//
//  If fDetachedHash is TRUE, only the ComputedHash is encoded in the
//  pbHashedBlob. Otherwise, both the ToBeHashed and ComputedHash
//  are encoded.
//
//  pcbHashedBlob or pcbComputedHash can be NULL, indicating the caller
//  isn't interested in getting the output.
//--------------------------------------------------------------------------
function CryptHashMessage(
  pHashPara: PCryptHashMessagePara;
  fDetachedHash: BOOL;
  cToBeHashed: DWORD;
  var rgpbToBeHashed: PByte;
  var rgcbToBeHashed: DWORD;
  pbHashedBlob: PByte;
  pcbHashedBlob: PDWORD;
  pbComputedHash: PByte;
  pcbComputedHash: PDWORD): BOOL; winapi;
{$EXTERNALSYM CryptHashMessage}

//+-------------------------------------------------------------------------
//  Verify a hashed message.
//
//  pcbToBeHashed or pcbComputedHash can be NULL,
//  indicating the caller isn't interested in getting the output.
//--------------------------------------------------------------------------
function CryptVerifyMessageHash(
  pHashPara: PCryptHashMessagePara;
  pbHashedBlob: PByte;
  cbHashedBlob: DWORD;
  pbToBeHashed: PByte;
  pcbToBeHashed: PDWORD;
  pbComputedHash: PByte;
  pcbComputedHash: PDWORD): BOOL; winapi;
{$EXTERNALSYM CryptVerifyMessageHash}

//+-------------------------------------------------------------------------
//  Verify a hashed message containing a detached hash.
//  The "to be hashed" content is passed in separately. No
//  decoded output. Otherwise, identical to CryptVerifyMessageHash.
//
//  pcbComputedHash can be NULL, indicating the caller isn't interested
//  in getting the output.
//--------------------------------------------------------------------------
function CryptVerifyDetachedMessageHash(
  pHashPara: PCryptHashMessagePara;
  pbDetachedHashBlob: PByte;
  cbDetachedHashBlob: DWORD;
  cToBeHashed: DWORD;
  var rgpbToBeHashed: PByte;
  var rgcbToBeHashed: DWORD;
  pbComputedHash: PByte;
  pcbComputedHash: PDWORD): BOOL; winapi;

//+-------------------------------------------------------------------------
//  Sign the message using the provider's private key specified in the
//  parameters. A dummy SignerId is created and stored in the message.
//
//  Normally used until a certificate has been created for the key.
//--------------------------------------------------------------------------
function CryptSignMessageWithKey(
  pSignPara: PCryptKeySignMessagePara;
  pbToBeSigned: PByte;
  cbToBeSigned: DWORD;
  pbSignedBlob: PByte;
  var pcbSignedBlob: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptSignMessageWithKey}

//+-------------------------------------------------------------------------
//  Verify a signed message using the specified public key info.
//
//  Normally called by a CA until it has created a certificate for the
//  key.
//
//  pPublicKeyInfo contains the public key to use to verify the signed
//  message. If NULL, the signature isn't verified (for instance, the decoded
//  content may contain the PublicKeyInfo).
//
//  pcbDecoded can be NULL, indicating the caller isn't interested
//  in getting the decoded content.
//--------------------------------------------------------------------------
function CryptVerifyMessageSignatureWithKey(
  pVerifyPara: PCryptKeyVerifyMessagePara;
  pPublicKeyInfo: PCertPublicKeyInfo;
  pbSignedBlob: PByte;
  cbSignedBlob: DWORD;
  pbDecoded: PByte;
  pcbDecoded: PDWORD): BOOL; winapi;
{$EXTERNALSYM CryptVerifyMessageSignatureWithKey}

//+=========================================================================
//  System Certificate Store Data Structures and APIs
//==========================================================================


//+-------------------------------------------------------------------------
//  Get a system certificate store based on a subsystem protocol.
//
//  Current examples of subsystems protocols are:
//      "MY"    Cert Store hold certs with associated Private Keys
//      "CA"    Certifying Authority certs
//      "ROOT"  Root Certs
//      "SPC"   Software publisher certs
//
//
//  If hProv is NULL the default provider "1" is opened for you.
//  When the store is closed the provider is release. Otherwise
//  if hProv is not NULL, no provider is created or released.
//
//  The returned Cert Store can be searched for an appropriate Cert
//  using the Cert Store API's (see certstor.h)
//
//  When done, the cert store should be closed using CertStoreClose
//--------------------------------------------------------------------------


function CertOpenSystemStoreA(
  hProv: HCRYPTPROV_LEGACY;
  szSubsystemProtocol: LPCSTR): HCERTSTORE; winapi;
{$EXTERNALSYM CertOpenSystemStoreA}

function CertOpenSystemStoreW(
  hProv: HCRYPTPROV_LEGACY;
  szSubsystemProtocol: LPCWSTR): HCERTSTORE; winapi;
{$EXTERNALSYM CertOpenSystemStoreW}

function CertOpenSystemStore(
  hProv: HCRYPTPROV_LEGACY;
  szSubsystemProtocol: LPCWSTR): HCERTSTORE; winapi;
{$EXTERNALSYM CertOpenSystemStore}

function CertAddEncodedCertificateToSystemStoreA(
  szCertStoreName: LPCSTR;
  pbCertEncoded: PByte;
  cbCertEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CertAddEncodedCertificateToSystemStoreA}

function CertAddEncodedCertificateToSystemStoreW(
  szCertStoreName: LPCWSTR;
  pbCertEncoded: PByte;
  cbCertEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CertAddEncodedCertificateToSystemStoreW}

function CertAddEncodedCertificateToSystemStore(
  szCertStoreName: LPCWSTR;
  pbCertEncoded: PByte;
  cbCertEncoded: DWORD): BOOL; winapi;
{$EXTERNALSYM CertAddEncodedCertificateToSystemStore}

//+-------------------------------------------------------------------------
//  Find all certificate chains tying the given issuer name to any certificate
//  that the current user has a private key for.
//
//  If no certificate chain is found, FALSE is returned with LastError set
//  to CRYPT_E_NOT_FOUND and the counts zeroed.
//
//  IE 3.0 ASSUMPTION:
//   The client certificates are in the "My" system store. The issuer
//   cerificates may be in the "Root", "CA" or "My" system stores.
//--------------------------------------------------------------------------
type
  PCertChain = ^TCertChain;
  _CERT_CHAIN = record
    cCerts: DWORD;                      // number of certs in chain
    certs: PCertBlob;                   // pointer to array of cert chain blobs
                                        // representing the certs
    keyLocatorInfo: TCryptKeyProvInfo;      // key locator for cert
  end;
  {$EXTERNALSYM _CERT_CHAIN}
  CERT_CHAIN = _CERT_CHAIN;
  {$EXTERNALSYM CERT_CHAIN}
  TCertChain = _CERT_CHAIN;
  PCERT_CHAIN = PCertChain;
  {$EXTERNALSYM PCERT_CHAIN}


// WINCRYPT32API    This is not exported by crypt32, it is exported by softpub
function FindCertsByIssuer(
  pCertChains: PCertChain;
  var pcbCertChains: DWORD;
  out pcCertChains: DWORD;            // count of certificates chains returned
  pbEncodedIssuerName: PByte;         // DER encoded issuer name
  cbEncodedIssuerName: DWORD;         // count in bytes of encoded issuer name
  pwszPurpose: LPCWSTR;               // "ClientAuth" or "CodeSigning"
  dwKeySpec: DWORD                    // only return signers supporting this
                                      // keyspec
  ): HRESULT; winapi;
{$EXTERNALSYM FindCertsByIssuer}

//-------------------------------------------------------------------------
//
//  CryptQueryObject takes a CERT_BLOB or a file name and returns the
//  information about the content in the blob or in the file.
//
//  Parameters:
//  INPUT   dwObjectType:
//                       Indicate the type of the object.  Should be one of the
//                       following:
//                          CERT_QUERY_OBJECT_FILE
//                          CERT_QUERY_OBJECT_BLOB
//
//  INPUT   pvObject:
//                        If dwObjectType == CERT_QUERY_OBJECT_FILE, it is a
//                        LPWSTR, that is, the pointer to a wchar file name
//                        if dwObjectType == CERT_QUERY_OBJECT_BLOB, it is a
//                        PCERT_BLOB, that is, a pointer to a CERT_BLOB
//
//  INPUT   dwExpectedContentTypeFlags:
//                        Indicate the expected contenet type.
//                        Can be one of the following:
//                              CERT_QUERY_CONTENT_FLAG_ALL  (the content can be any type)
//                              CERT_QUERY_CONTENT_FLAG_CERT
//                              CERT_QUERY_CONTENT_FLAG_CTL
//                              CERT_QUERY_CONTENT_FLAG_CRL
//                              CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE
//                              CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT
//                              CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL
//                              CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL
//                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED
//                              CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED
//                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
//                              CERT_QUERY_CONTENT_FLAG_PKCS10
//                              CERT_QUERY_CONTENT_FLAG_PFX
//                              CERT_QUERY_CONTENT_FLAG_CERT_PAIR
//                              CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD
//
//  INPUT   dwExpectedFormatTypeFlags:
//                        Indicate the expected format type.
//                        Can be one of the following:
//                              CERT_QUERY_FORMAT_FLAG_ALL (the content can be any format)
//                              CERT_QUERY_FORMAT_FLAG_BINARY
//                              CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED
//                              CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED
//
//
//  INPUT   dwFlags
//                        Reserved flag.  Should always set to 0
//
//  OUTPUT  pdwMsgAndCertEncodingType
//                        Optional output.  If NULL != pdwMsgAndCertEncodingType,
//                        it contains the encoding type of the content as any
//                        combination of the following:
//                              X509_ASN_ENCODING
//                              PKCS_7_ASN_ENCODING
//
//  OUTPUT  pdwContentType
//                        Optional output.  If NULL!=pdwContentType, it contains
//                        the content type as one of the the following:
//                              CERT_QUERY_CONTENT_CERT
//                              CERT_QUERY_CONTENT_CTL
//                              CERT_QUERY_CONTENT_CRL
//                              CERT_QUERY_CONTENT_SERIALIZED_STORE
//                              CERT_QUERY_CONTENT_SERIALIZED_CERT
//                              CERT_QUERY_CONTENT_SERIALIZED_CTL
//                              CERT_QUERY_CONTENT_SERIALIZED_CRL
//                              CERT_QUERY_CONTENT_PKCS7_SIGNED
//                              CERT_QUERY_CONTENT_PKCS7_UNSIGNED
//                              CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED
//                              CERT_QUERY_CONTENT_PKCS10
//                              CERT_QUERY_CONTENT_PFX
//                              CERT_QUERY_CONTENT_CERT_PAIR
//                              CERT_QUERY_CONTENT_PFX_AND_LOAD
//
//  OUTPUT  pdwFormatType
//                        Optional output.  If NULL !=pdwFormatType, it
//                        contains the format type of the content as one of the
//                        following:
//                              CERT_QUERY_FORMAT_BINARY
//                              CERT_QUERY_FORMAT_BASE64_ENCODED
//                              CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED
//
//
//  OUTPUT  phCertStore
//                        Optional output.  If NULL !=phStore,
//                        it contains a cert store that includes all of certificates,
//                        CRL, and CTL in the object if the object content type is
//                        one of the following:
//                              CERT_QUERY_CONTENT_CERT
//                              CERT_QUERY_CONTENT_CTL
//                              CERT_QUERY_CONTENT_CRL
//                              CERT_QUERY_CONTENT_SERIALIZED_STORE
//                              CERT_QUERY_CONTENT_SERIALIZED_CERT
//                              CERT_QUERY_CONTENT_SERIALIZED_CTL
//                              CERT_QUERY_CONTENT_SERIALIZED_CRL
//                              CERT_QUERY_CONTENT_PKCS7_SIGNED
//                              CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED
//                              CERT_QUERY_CONTENT_CERT_PAIR
//
//                       Caller should free *phCertStore via CertCloseStore.
//
//
//  OUTPUT  phMsg        Optional output.  If NULL != phMsg,
//                        it contains a handle to a opened message if
//                        the content type is one of the following:
//                              CERT_QUERY_CONTENT_PKCS7_SIGNED
//                              CERT_QUERY_CONTENT_PKCS7_UNSIGNED
//                              CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED
//
//                       Caller should free *phMsg via CryptMsgClose.
//
//  OUTPUT pContext     Optional output.  If NULL != pContext,
//                      it contains either a PCCERT_CONTEXT or PCCRL_CONTEXT,
//                      or PCCTL_CONTEXT based on the content type.
//
//                      If the content type is CERT_QUERY_CONTENT_CERT or
//                      CERT_QUERY_CONTENT_SERIALIZED_CERT, it is a PCCERT_CONTEXT;
//                      Caller should free the pContext via CertFreeCertificateContext.
//
//                      If the content type is CERT_QUERY_CONTENT_CRL or
//                      CERT_QUERY_CONTENT_SERIALIZED_CRL, it is a PCCRL_CONTEXT;
//                      Caller should free the pContext via CertFreeCRLContext.
//
//                      If the content type is CERT_QUERY_CONTENT_CTL or
//                      CERT_QUERY_CONTENT_SERIALIZED_CTL, it is a PCCTL_CONTEXT;
//                      Caller should free the pContext via CertFreeCTLContext.
//
//  If the *pbObject is of type CERT_QUERY_CONTENT_PKCS10 or CERT_QUERY_CONTENT_PFX, CryptQueryObject
//  will not return anything in *phCertstore, *phMsg, or *ppvContext.
//--------------------------------------------------------------------------
function CryptQueryObject(
  dwObjectType: DWORD;
  pvObject: Pointer;
  dwExpectedContentTypeFlags: DWORD;
  dwExpectedFormatTypeFlags: DWORD;
  dwFlags: DWORD;
  pdwMsgAndCertEncodingType: PDWORD;
  pdwContentType: PDWORD;
  pdwFormatType: PDWORD;
  out phCertStore: HCERTSTORE;
  out phMsg: HCRYPTMSG;
  ppvContext: PPointer): BOOL; winapi;
{$EXTERNALSYM CryptQueryObject}


//-------------------------------------------------------------------------
//dwObjectType for CryptQueryObject
//-------------------------------------------------------------------------
const
  CERT_QUERY_OBJECT_FILE        = $00000001;
  {$EXTERNALSYM CERT_QUERY_OBJECT_FILE}
  CERT_QUERY_OBJECT_BLOB        = $00000002;
  {$EXTERNALSYM CERT_QUERY_OBJECT_BLOB}

//-------------------------------------------------------------------------
//dwContentType for CryptQueryObject
//-------------------------------------------------------------------------
//encoded single certificate
const
  CERT_QUERY_CONTENT_CERT                = 1;
  {$EXTERNALSYM CERT_QUERY_CONTENT_CERT}
//encoded single CTL
const
  CERT_QUERY_CONTENT_CTL                 = 2;
  {$EXTERNALSYM CERT_QUERY_CONTENT_CTL}
//encoded single CRL
const
  CERT_QUERY_CONTENT_CRL                 = 3;
  {$EXTERNALSYM CERT_QUERY_CONTENT_CRL}
//serialized store
const
  CERT_QUERY_CONTENT_SERIALIZED_STORE    = 4;
  {$EXTERNALSYM CERT_QUERY_CONTENT_SERIALIZED_STORE}
//serialized single certificate
const
  CERT_QUERY_CONTENT_SERIALIZED_CERT     = 5;
  {$EXTERNALSYM CERT_QUERY_CONTENT_SERIALIZED_CERT}
//serialized single CTL
const
  CERT_QUERY_CONTENT_SERIALIZED_CTL      = 6;
  {$EXTERNALSYM CERT_QUERY_CONTENT_SERIALIZED_CTL}
//serialized single CRL
const
  CERT_QUERY_CONTENT_SERIALIZED_CRL      = 7;
  {$EXTERNALSYM CERT_QUERY_CONTENT_SERIALIZED_CRL}
//a PKCS#7 signed message
const
  CERT_QUERY_CONTENT_PKCS7_SIGNED        = 8;
  {$EXTERNALSYM CERT_QUERY_CONTENT_PKCS7_SIGNED}
//a PKCS#7 message, such as enveloped message.  But it is not a signed message,
const
  CERT_QUERY_CONTENT_PKCS7_UNSIGNED      = 9;
  {$EXTERNALSYM CERT_QUERY_CONTENT_PKCS7_UNSIGNED}
//a PKCS7 signed message embedded in a file
const
  CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED  = 10;
  {$EXTERNALSYM CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED}
//an encoded PKCS#10
const
  CERT_QUERY_CONTENT_PKCS10              = 11;
  {$EXTERNALSYM CERT_QUERY_CONTENT_PKCS10}
//an encoded PFX BLOB
const
  CERT_QUERY_CONTENT_PFX                 = 12;
  {$EXTERNALSYM CERT_QUERY_CONTENT_PFX}
//an encoded CertificatePair (contains forward and/or reverse cross certs)
const
  CERT_QUERY_CONTENT_CERT_PAIR           = 13;
  {$EXTERNALSYM CERT_QUERY_CONTENT_CERT_PAIR}
//an encoded PFX BLOB, which was loaded to phCertStore
const
  CERT_QUERY_CONTENT_PFX_AND_LOAD        = 14;
  {$EXTERNALSYM CERT_QUERY_CONTENT_PFX_AND_LOAD}


//-------------------------------------------------------------------------
//dwExpectedConentTypeFlags for CryptQueryObject
//-------------------------------------------------------------------------

//encoded single certificate
const
  CERT_QUERY_CONTENT_FLAG_CERT = (1 shl CERT_QUERY_CONTENT_CERT);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_CERT}

//encoded single CTL
const
  CERT_QUERY_CONTENT_FLAG_CTL = (1 shl CERT_QUERY_CONTENT_CTL);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_CTL}

//encoded single CRL
const
  CERT_QUERY_CONTENT_FLAG_CRL = (1 shl CERT_QUERY_CONTENT_CRL);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_CRL}

//serialized store
const
  CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE = (1 shl CERT_QUERY_CONTENT_SERIALIZED_STORE);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE}

//serialized single certificate
const
  CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT = (1 shl CERT_QUERY_CONTENT_SERIALIZED_CERT);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT}

//serialized single CTL
const
  CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL = (1 shl CERT_QUERY_CONTENT_SERIALIZED_CTL);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL}

//serialized single CRL
const
  CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL = (1 shl CERT_QUERY_CONTENT_SERIALIZED_CRL);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL}

//an encoded PKCS#7 signed message
const
  CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = (1 shl CERT_QUERY_CONTENT_PKCS7_SIGNED);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED}

//an encoded PKCS#7 message.  But it is not a signed message
const
  CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED = (1 shl CERT_QUERY_CONTENT_PKCS7_UNSIGNED);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED}

//the content includes an embedded PKCS7 signed message
const
  CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = (1 shl CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED}

//an encoded PKCS#10
const
  CERT_QUERY_CONTENT_FLAG_PKCS10 = (1 shl CERT_QUERY_CONTENT_PKCS10);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_PKCS10}

//an encoded PFX BLOB
const
  CERT_QUERY_CONTENT_FLAG_PFX = (1 shl CERT_QUERY_CONTENT_PFX);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_PFX}

//an encoded CertificatePair (contains forward and/or reverse cross certs)
const
  CERT_QUERY_CONTENT_FLAG_CERT_PAIR = (1 shl CERT_QUERY_CONTENT_CERT_PAIR);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_CERT_PAIR}

//an encoded PFX BLOB, and we do want to load it (not included in
//CERT_QUERY_CONTENT_FLAG_ALL)
const
  CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD = (1 shl CERT_QUERY_CONTENT_PFX_AND_LOAD);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_PFX_AND_LOAD}

//content can be any type
const
  CERT_QUERY_CONTENT_FLAG_ALL = (
    CERT_QUERY_CONTENT_FLAG_CERT or
    CERT_QUERY_CONTENT_FLAG_CTL or
    CERT_QUERY_CONTENT_FLAG_CRL or
    CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE or
    CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT or
    CERT_QUERY_CONTENT_FLAG_SERIALIZED_CTL or
    CERT_QUERY_CONTENT_FLAG_SERIALIZED_CRL or
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED or
    CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED or
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED or
    CERT_QUERY_CONTENT_FLAG_PKCS10 or
    CERT_QUERY_CONTENT_FLAG_PFX or
    CERT_QUERY_CONTENT_FLAG_CERT_PAIR);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_ALL}

//content types allowed for Issuer certificates
const
  CERT_QUERY_CONTENT_FLAG_ALL_ISSUER_CERT = (
    CERT_QUERY_CONTENT_FLAG_CERT             or
    CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE or
    CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT  or
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED     or
    CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED);
  {$EXTERNALSYM CERT_QUERY_CONTENT_FLAG_ALL_ISSUER_CERT}


//-------------------------------------------------------------------------
//dwFormatType for CryptQueryObject
//-------------------------------------------------------------------------
//the content is in binary format
const
  CERT_QUERY_FORMAT_BINARY                = 1;
  {$EXTERNALSYM CERT_QUERY_FORMAT_BINARY}

//the content is base64 encoded
const
  CERT_QUERY_FORMAT_BASE64_ENCODED        = 2;
  {$EXTERNALSYM CERT_QUERY_FORMAT_BASE64_ENCODED}

//the content is ascii hex encoded with "{ASN}" prefix
const
  CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED = 3;
  {$EXTERNALSYM CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED}
//-------------------------------------------------------------------------
//dwExpectedFormatTypeFlags for CryptQueryObject
//-------------------------------------------------------------------------
//the content is in binary format
const
  CERT_QUERY_FORMAT_FLAG_BINARY = (1 shl CERT_QUERY_FORMAT_BINARY);
  {$EXTERNALSYM CERT_QUERY_FORMAT_FLAG_BINARY}

//the content is base64 encoded
const
  CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED = (1 shl CERT_QUERY_FORMAT_BASE64_ENCODED);
  {$EXTERNALSYM CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED}

//the content is ascii hex encoded with "{ASN}" prefix
const
  CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED = (1 shl CERT_QUERY_FORMAT_ASN_ASCII_HEX_ENCODED);
  {$EXTERNALSYM CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED}

//the content can be of any format
const
  CERT_QUERY_FORMAT_FLAG_ALL = (
    CERT_QUERY_FORMAT_FLAG_BINARY or
    CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED or
    CERT_QUERY_FORMAT_FLAG_ASN_ASCII_HEX_ENCODED);
 {$EXTERNALSYM CERT_QUERY_FORMAT_FLAG_BINARY}


//
// Crypt32 Memory Management Routines.  All Crypt32 API which return allocated
// buffers will do so via CryptMemAlloc, CryptMemRealloc.  Clients can free
// those buffers using CryptMemFree.  Also included is CryptMemSize
//

function CryptMemAlloc(
  cbSize: ULONG): LPVOID; winapi;
{$EXTERNALSYM CryptMemAlloc}

function CryptMemRealloc(
  pv: LPVOID;
  cbSize: ULONG): LPVOID; winapi;
{$EXTERNALSYM CryptMemRealloc}

procedure CryptMemFree(
  pv: LPVOID); winapi;
{$EXTERNALSYM CryptMemFree}

//
// Crypt32 Asynchronous Parameter Management Routines.  All Crypt32 API which
// expose asynchronous mode operation use a Crypt32 Async Handle to pass
// around information about the operation e.g. callback routines.  The
// following API are used for manipulation of the async handle
//

// Following functions were never used. If called, will fail with LastError
// set to ERROR_CALL_NOT_IMPLEMENTED.

type
  HCRYPTASYNC = THandle;
  {$EXTERNALSYM HCRYPTASYNC}
  PHCRYPTASYNC = PHandle;
  {$EXTERNALSYM PHCRYPTASYNC}

type
  PFnCryptAsyncParamFreeFunc = ^TFnCryptAsyncParamFreeFunc;
  PFN_CRYPT_ASYNC_PARAM_FREE_FUNC = procedure(
    pszParamOid: LPSTR;
    pvParam: LPVOID); winapi;
  {$EXTERNALSYM PFN_CRYPT_ASYNC_PARAM_FREE_FUNC}
  TFnCryptAsyncParamFreeFunc = PFN_CRYPT_ASYNC_PARAM_FREE_FUNC;

function CryptCreateAsyncHandle(
  dwFlags: DWORD;
  out phAsync: HCRYPTASYNC): BOOL; winapi;
{$EXTERNALSYM CryptCreateAsyncHandle}

function CryptSetAsyncParam(
  hAsync: HCRYPTASYNC;
  pszParamOid: LPSTR;
  pvParam: LPVOID;
  pfnFree: TFnCryptAsyncParamFreeFunc): BOOL; winapi;
{$EXTERNALSYM CryptSetAsyncParam}

function CryptGetAsyncParam(
  hAsync: HCRYPTASYNC;
  pszParamOid: LPSTR;
  ppvParam: PPointer;
  ppfnFree: PFnCryptAsyncParamFreeFunc): BOOL; winapi;
{$EXTERNALSYM CryptGetAsyncParam}

function CryptCloseAsyncHandle(
  hAsync: HCRYPTASYNC): BOOL; winapi;
{$EXTERNALSYM CryptCloseAsyncHandle}

//
// Crypt32 Remote Object Retrieval Routines.  This API allows retrieval of
// remote PKI objects where the location is given by an URL.  The remote
// object retrieval manager exposes two provider models.  One is the "Scheme
// Provider" model which allows for installable protocol providers as defined
// by the URL scheme e.g. ldap, http, ftp.  The scheme provider entry point is
// the same as the CryptRetrieveObjectByUrl however the *ppvObject returned
// is ALWAYS a counted array of encoded bits (one per object retrieved).  The
// second provider model is the "Context Provider" model which allows for
// installable creators of CAPI2 context handles (objects) based on the
// retrieved encoded bits.  These are dispatched based on the object OID given
// in the call to CryptRetrieveObjectByUrl.
//

type
  PCryptBlobArray = ^TCryptBlobArray;
  _CRYPT_BLOB_ARRAY = record
    cBlob: DWORD;
    rgBlob: PCryptDataBlob;
  end;
  {$EXTERNALSYM _CRYPT_BLOB_ARRAY}
  CRYPT_BLOB_ARRAY = _CRYPT_BLOB_ARRAY;
  {$EXTERNALSYM CRYPT_BLOB_ARRAY}
  TCryptBlobArray = _CRYPT_BLOB_ARRAY;
  PCRYPT_BLOB_ARRAY = PCryptBlobArray;
  {$EXTERNALSYM PCRYPT_BLOB_ARRAY}

type
  PCryptCredentials = ^TCryptCredentials;
  _CRYPT_CREDENTIALS = record
    cbSize: DWORD;
    pszCredentialsOid: LPCSTR;
    pvCredentials: LPVOID;
  end;
  {$EXTERNALSYM _CRYPT_CREDENTIALS}
  CRYPT_CREDENTIALS = _CRYPT_CREDENTIALS;
  {$EXTERNALSYM CRYPT_CREDENTIALS}
  TCryptCredentials = _CRYPT_CREDENTIALS;
  PCRYPT_CREDENTIALS = PCryptCredentials;
  {$EXTERNALSYM PCRYPT_CREDENTIALS}

const
  CREDENTIAL_OID_PASSWORD_CREDENTIALS_A = LPCSTR(1);
  {$EXTERNALSYM CREDENTIAL_OID_PASSWORD_CREDENTIALS_A}
  CREDENTIAL_OID_PASSWORD_CREDENTIALS_W = LPCSTR(2);
  {$EXTERNALSYM CREDENTIAL_OID_PASSWORD_CREDENTIALS_W}

  CREDENTIAL_OID_PASSWORD_CREDENTIALS = CREDENTIAL_OID_PASSWORD_CREDENTIALS_W;
  {$EXTERNALSYM CREDENTIAL_OID_PASSWORD_CREDENTIALS}

type
  PCryptPasswordCredentialsA = ^TCryptPasswordCredentialsA;
  _CRYPT_PASSWORD_CREDENTIALSA = record
    cbSize: DWORD;
    pszUsername: LPSTR;
    pszPassword: LPSTR;
  end;
  {$EXTERNALSYM _CRYPT_PASSWORD_CREDENTIALSA}
  CRYPT_PASSWORD_CREDENTIALSA = _CRYPT_PASSWORD_CREDENTIALSA;
  {$EXTERNALSYM CRYPT_PASSWORD_CREDENTIALSA}
  TCryptPasswordCredentialsA = _CRYPT_PASSWORD_CREDENTIALSA;
  PCRYPT_PASSWORD_CREDENTIALSA = PCryptPasswordCredentialsA;
  {$EXTERNALSYM PCRYPT_PASSWORD_CREDENTIALSA}

type
  PCryptPasswordCredentialsW = ^TCryptPasswordCredentialsW;
  _CRYPT_PASSWORD_CREDENTIALSW = record
    cbSize: DWORD;
    pszUsername: LPWSTR;
    pszPassword: LPWSTR;
  end;
  {$EXTERNALSYM _CRYPT_PASSWORD_CREDENTIALSW}
  CRYPT_PASSWORD_CREDENTIALSW = _CRYPT_PASSWORD_CREDENTIALSW;
  {$EXTERNALSYM CRYPT_PASSWORD_CREDENTIALSW}
  TCryptPasswordCredentialsW = _CRYPT_PASSWORD_CREDENTIALSW;
  PCRYPT_PASSWORD_CREDENTIALSW = PCryptPasswordCredentialsW;
  {$EXTERNALSYM PCRYPT_PASSWORD_CREDENTIALSW}

type
  PCryptPasswordCredentials = PCryptPasswordCredentialsW;
  CRYPT_PASSWORD_CREDENTIALS = _CRYPT_PASSWORD_CREDENTIALSW ;
  {$EXTERNALSYM CRYPT_PASSWORD_CREDENTIALS}
  TCryptPasswordCredentials = _CRYPT_PASSWORD_CREDENTIALSW;
  PCRYPT_PASSWORD_CREDENTIALS = PCryptPasswordCredentials;
  {$EXTERNALSYM PCRYPT_PASSWORD_CREDENTIALS}

//
// Scheme Provider Signatures
//

// The following is obsolete and has been replaced with the following
// definition
const
  SCHEME_OID_RETRIEVE_ENCODED_OBJECT_FUNC = 'SchemeDllRetrieveEncodedObject';
  {$EXTERNALSYM SCHEME_OID_RETRIEVE_ENCODED_OBJECT_FUNC}

// 2-8-02 Server 2003 changed to use UNICODE Url strings instead of multibyte
const
  SCHEME_OID_RETRIEVE_ENCODED_OBJECTW_FUNC = 'SchemeDllRetrieveEncodedObjectW';
  {$EXTERNALSYM SCHEME_OID_RETRIEVE_ENCODED_OBJECTW_FUNC}

type
  PFN_FREE_ENCODED_OBJECT_FUNC = procedure(
    pszObjectOid: LPCSTR;
    pObject: PCryptBlobArray;
    pvFreeContext: LPVOID); winapi;
  {$EXTERNALSYM PFN_FREE_ENCODED_OBJECT_FUNC}
  TFnFreeEncodedObjectFunc = PFN_FREE_ENCODED_OBJECT_FUNC;

//
// SchemeDllRetrieveEncodedObject was replaced in Server 2003 with
// the following. (Changed to use UNICODE Url Strings.)
//

//
// SchemeDllRetrieveEncodedObjectW has the following signature:
//
// _Success_(return != FALSE)
// BOOL WINAPI SchemeDllRetrieveEncodedObjectW (
//                   _In_ LPCWSTR pwszUrl,
//                   _In_opt_ LPCSTR pszObjectOid,
//                   _In_ DWORD dwRetrievalFlags,
//                   _In_ DWORD dwTimeout,                // milliseconds
//                   _Out_ PCRYPT_BLOB_ARRAY pObject,
//                   _Outptr_ __callback PFN_FREE_ENCODED_OBJECT_FUNC* ppfnFreeObject,
//                   _Outptr_result_maybenull_ LPVOID* ppvFreeContext,
//                   _In_opt_ HCRYPTASYNC hAsyncRetrieve,
//                   _In_opt_ PCRYPT_CREDENTIALS pCredentials,
//                   _Inout_opt_ PCRYPT_RETRIEVE_AUX_INFO pAuxInfo
//                   )
//

//
// Context Provider Signatures
//
const
  CONTEXT_OID_CREATE_OBJECT_CONTEXT_FUNC = 'ContextDllCreateObjectContext';
  {$EXTERNALSYM CONTEXT_OID_CREATE_OBJECT_CONTEXT_FUNC}

  CONTEXT_OID_CERTIFICATE = LPCSTR(1);
  {$EXTERNALSYM CONTEXT_OID_CERTIFICATE}
  CONTEXT_OID_CRL         = LPCSTR(2);
  {$EXTERNALSYM CONTEXT_OID_CRL}
  CONTEXT_OID_CTL         = LPCSTR(3);
  {$EXTERNALSYM CONTEXT_OID_CTL}
  CONTEXT_OID_PKCS7       = LPCSTR(4);
  {$EXTERNALSYM CONTEXT_OID_PKCS7}
  CONTEXT_OID_CAPI2_ANY   = LPCSTR(5);
  {$EXTERNALSYM CONTEXT_OID_CAPI2_ANY}
  CONTEXT_OID_OCSP_RESP   = LPCSTR(6);
  {$EXTERNALSYM CONTEXT_OID_OCSP_RESP}

//
// ContextDllCreateObjectContext has the following signature:
//
// _Success_(return != FALSE)
// BOOL WINAPI ContextDllCreateObjectContext (
//                    _In_opt_ LPCSTR pszObjectOid,
//                    _In_ DWORD dwRetrievalFlags,
//                    _In_ PCRYPT_BLOB_ARRAY pObject,
//                    _Outptr_ LPVOID* ppvContext
//                    )
//

//
// Remote Object Retrieval API
//

//
// Retrieval flags
//
const
  CRYPT_RETRIEVE_MULTIPLE_OBJECTS        = $00000001;
  {$EXTERNALSYM CRYPT_RETRIEVE_MULTIPLE_OBJECTS}
  CRYPT_CACHE_ONLY_RETRIEVAL             = $00000002;
  {$EXTERNALSYM CRYPT_CACHE_ONLY_RETRIEVAL}
  CRYPT_WIRE_ONLY_RETRIEVAL              = $00000004;
  {$EXTERNALSYM CRYPT_WIRE_ONLY_RETRIEVAL}
  CRYPT_DONT_CACHE_RESULT                = $00000008;
  {$EXTERNALSYM CRYPT_DONT_CACHE_RESULT}
  CRYPT_ASYNC_RETRIEVAL                  = $00000010;
  {$EXTERNALSYM CRYPT_ASYNC_RETRIEVAL}
  CRYPT_STICKY_CACHE_RETRIEVAL           = $00001000;
  {$EXTERNALSYM CRYPT_STICKY_CACHE_RETRIEVAL}
  CRYPT_LDAP_SCOPE_BASE_ONLY_RETRIEVAL   = $00002000;
  {$EXTERNALSYM CRYPT_LDAP_SCOPE_BASE_ONLY_RETRIEVAL}
  CRYPT_OFFLINE_CHECK_RETRIEVAL          = $00004000;
  {$EXTERNALSYM CRYPT_OFFLINE_CHECK_RETRIEVAL}

// When the following flag is set, the following 2 NULL terminated ascii
// strings are inserted at the beginning of each returned blob:
//  "%d\0%s\0", dwEntryIndex, pszAttribute
//
//  The first dwEntryIndex is 0, "0\0".
//
// When set, pszObjectOid must be NULL, so that a PCRYPT_BLOB_ARRAY is returned.
const
  CRYPT_LDAP_INSERT_ENTRY_ATTRIBUTE      = $00008000;
  {$EXTERNALSYM CRYPT_LDAP_INSERT_ENTRY_ATTRIBUTE}

// Set this flag to digitally sign all of the ldap traffic to and from a
// Windows 2000 LDAP server using the Kerberos authentication protocol.
// This feature provides integrity required by some applications.
const
  CRYPT_LDAP_SIGN_RETRIEVAL              = $00010000;
  {$EXTERNALSYM CRYPT_LDAP_SIGN_RETRIEVAL}

// Set this flag to inhibit automatic authentication handling. See the
// wininet flag, INTERNET_FLAG_NO_AUTH, for more details.
const
  CRYPT_NO_AUTH_RETRIEVAL                = $00020000;
  {$EXTERNALSYM CRYPT_NO_AUTH_RETRIEVAL}

// Performs an A-Record only DNS lookup on the supplied host string.
// This prevents bogus DNS queries from being generated when resolving host
// names. Use this flag whenever passing a hostname as opposed to a
// domain name for the hostname parameter.
//
// See LDAP_OPT_AREC_EXCLUSIVE defined in winldap.h for more details.
const
  CRYPT_LDAP_AREC_EXCLUSIVE_RETRIEVAL    = $00040000;
  {$EXTERNALSYM CRYPT_LDAP_AREC_EXCLUSIVE_RETRIEVAL}

// Apply AIA URL restrictions, such as, validate retrieved content before
// writing to cache.
const
  CRYPT_AIA_RETRIEVAL                    = $00080000;
  {$EXTERNALSYM CRYPT_AIA_RETRIEVAL}

// For HTTP: use POST instead of the default GET
//
// The POST additional binary data and header strings are appended to
// the host name and path URL as follows:
//  + L'/'<Optional url escaped and base64 encoded additional data>
//  + L'?'<Optional additional headers>
//
// Here's an example of an OCSP POST URL:
//  http://ocsp.openvalidation.org/MEIwQDA%2BMDwwOjAJBgUrDgMCGgUABBQdKNE
//      wjytjKBQADcgM61jfflNpyQQUv1NDgnjQnsOA5RtnygUA37lIg6UCA
//      QI%3D?Content-Type: application/ocsp-request
//
//
// When this flag is set, CryptRetrieveObjectByUrl, searches for the
// last L'/' and L'?' POST marker characters in the URL string.
// These are removed from the URL before it is passed to the WinHttp
// APIs. The L'?' string is passed as the AdditionHeaders to
// WinHttpSendRequest. The L'/' string is url unescaped (%xx converted
// to appropriate character) and base64 decoded into binary. This
// decoded binary is passed as the additional data to WinHttpSendRequest.
const
  CRYPT_HTTP_POST_RETRIEVAL              = $00100000;
  {$EXTERNALSYM CRYPT_HTTP_POST_RETRIEVAL}

// When this flag is set we won't attempt to bypass any potential proxy caches.
// If a proxy cache wasn't explicitly bypassed, fProxyCacheRetrieval will be
// set in pAuxInfo. Only applicable to http URL retrievals.
const
  CRYPT_PROXY_CACHE_RETRIEVAL            = $00200000;
  {$EXTERNALSYM CRYPT_PROXY_CACHE_RETRIEVAL}

// When this flag is set, for a conditional retrieval returning not modified,
// TRUE is returned and *ppvObject is set to NULL. For a nonNULL pAuxInfo,
// dwHttpStatusCode is set to winhttp.h's HTTP_STATUS_NOT_MODIFIED. Otherwise,
// *ppvObject is updated for a successful retrieval. Only applicable to
// http URL retrievals.
const
  CRYPT_NOT_MODIFIED_RETRIEVAL           = $00400000;
  {$EXTERNALSYM CRYPT_NOT_MODIFIED_RETRIEVAL}

// When this flag is set, revocation checking is enabled for https URLs.
// If the server's certificate is revoked, then, LastError is set to
// CRYPT_E_REVOKED. For no other errors, LastError is set to
// CRYPT_E_REVOCATION_OFFLINE for any offline revocation error.
//
// To ignore offline revocation errors, this API can be called again without
// setting this flag.
const
  CRYPT_ENABLE_SSL_REVOCATION_RETRIEVAL  = $00800000;
  {$EXTERNALSYM CRYPT_ENABLE_SSL_REVOCATION_RETRIEVAL}

// Set this flag to append a random query string to the URL passed to
// WinHttpOpenRequest. This should only be set on URL's accessing Windows
// Update content. The random query string ensures that cached proxy content
// isn't used and the HTTP request will always reach the Content Delivery
// Network (CDN) used by Windows Update which removes a query string
// before doing a cache lookup.
const
  CRYPT_RANDOM_QUERY_STRING_RETRIEVAL    = $04000000;
  {$EXTERNALSYM CRYPT_RANDOM_QUERY_STRING_RETRIEVAL}


//
// Data verification retrieval flags
//
// CRYPT_VERIFY_CONTEXT_SIGNATURE is used to get signature verification
// on the context created.  In this case pszObjectOid must be non-NULL and
// pvVerify points to the signer certificate context
//
// CRYPT_VERIFY_DATA_HASH is used to get verification of the blob data
// retrieved by the protocol.  The pvVerify points to an URL_DATA_HASH
// structure (TBD)
//
const
  CRYPT_VERIFY_CONTEXT_SIGNATURE          = $00000020;
  {$EXTERNALSYM CRYPT_VERIFY_CONTEXT_SIGNATURE}
  CRYPT_VERIFY_DATA_HASH                  = $00000040;
  {$EXTERNALSYM CRYPT_VERIFY_DATA_HASH}

//
// Time Valid Object flags
//
const
  CRYPT_KEEP_TIME_VALID                   = $00000080;
  {$EXTERNALSYM CRYPT_KEEP_TIME_VALID}
  CRYPT_DONT_VERIFY_SIGNATURE             = $00000100;
  {$EXTERNALSYM CRYPT_DONT_VERIFY_SIGNATURE}
  CRYPT_DONT_CHECK_TIME_VALIDITY          = $00000200;
  {$EXTERNALSYM CRYPT_DONT_CHECK_TIME_VALIDITY}

// The default checks if ftNextUpdate >= ftValidFor. Set this flag to
// check if ftThisUpdate >= ftValidFor.
const
  CRYPT_CHECK_FRESHNESS_TIME_VALIDITY     = $00000400;
  {$EXTERNALSYM CRYPT_CHECK_FRESHNESS_TIME_VALIDITY}

  CRYPT_ACCUMULATIVE_TIMEOUT              = $00000800;
  {$EXTERNALSYM CRYPT_ACCUMULATIVE_TIMEOUT}

// Set this flag to only use OCSP AIA URLs.
const
  CRYPT_OCSP_ONLY_RETRIEVAL               = $01000000;
  {$EXTERNALSYM CRYPT_OCSP_ONLY_RETRIEVAL}

// Set this flag to only use the OCSP AIA URL if present. If the subject
// doesn't have an OCSP AIA URL, then, the CDP URLs are used.
const
  CRYPT_NO_OCSP_FAILOVER_TO_CRL_RETRIEVAL = $02000000;
  {$EXTERNALSYM CRYPT_NO_OCSP_FAILOVER_TO_CRL_RETRIEVAL}


//
// Cryptnet URL Cache Pre-Fetch Info
//
type
  PCryptnetURLCachePreFetchInfo = ^TCryptnetURLCachePreFetchInfo;
  _CRYPTNET_URL_CACHE_PRE_FETCH_INFO = record
    cbSize: DWORD;
    dwObjectType: DWORD;

    // Possible errors:
    //  S_OK                - Pending
    //  ERROR_MEDIA_OFFLINE - CRL pre-fetch disabled due to OCSP offline.
    //  ERROR_FILE_OFFLINE  - Unchanged pre-fetch content
    //  ERROR_INVALID_DATA  - Invalid pre-fetch content
    //  Other errors        - Unable to retrieve pre-fetch content
    dwError: DWORD;
    dwReserved: DWORD;

    ThisUpdateTime: TFileTime;
    NextUpdateTime: TFileTime;
    PublishTime: TFileTime;    // May be zero
  end;
  {$EXTERNALSYM _CRYPTNET_URL_CACHE_PRE_FETCH_INFO}
  CRYPTNET_URL_CACHE_PRE_FETCH_INFO = _CRYPTNET_URL_CACHE_PRE_FETCH_INFO;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_PRE_FETCH_INFO}
  TCryptnetURLCachePreFetchInfo = _CRYPTNET_URL_CACHE_PRE_FETCH_INFO;
  PCRYPTNET_URL_CACHE_PRE_FETCH_INFO = PCryptnetURLCachePreFetchInfo;
  {$EXTERNALSYM PCRYPTNET_URL_CACHE_PRE_FETCH_INFO}

// Pre-fetch ObjectTypes
const
  CRYPTNET_URL_CACHE_PRE_FETCH_NONE                  = 0;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_PRE_FETCH_NONE}
  CRYPTNET_URL_CACHE_PRE_FETCH_BLOB                  = 1;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_PRE_FETCH_BLOB}
  CRYPTNET_URL_CACHE_PRE_FETCH_CRL                   = 2;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_PRE_FETCH_CRL}
  CRYPTNET_URL_CACHE_PRE_FETCH_OCSP                  = 3;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_PRE_FETCH_OCSP}
  CRYPTNET_URL_CACHE_PRE_FETCH_AUTOROOT_CAB          = 5;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_PRE_FETCH_AUTOROOT_CAB}
  CRYPTNET_URL_CACHE_PRE_FETCH_DISALLOWED_CERT_CAB   = 6;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_PRE_FETCH_DISALLOWED_CERT_CAB}



//
// Cryptnet URL Cache Flush Info
//
type
  PCryptnetURLCacheFlushInfo = ^TCryptnetURLCacheFlushInfo;
  _CRYPTNET_URL_CACHE_FLUSH_INFO = record
    cbSize: DWORD;
    // If pre-fetching is enabled, following is ignored
    //
    // 0          - use default flush exempt seconds (2 weeks)
    // 0xFFFFFFFF - disable flushing
    dwExemptSeconds: DWORD;

    // Time the object expires. The above dwExemptSeconds is added to
    // to determine the flush time. The LastSyncTime is used if
    // after this time.
    ExpireTime: TFileTime;
  end;
  {$EXTERNALSYM _CRYPTNET_URL_CACHE_FLUSH_INFO}
  CRYPTNET_URL_CACHE_FLUSH_INFO = _CRYPTNET_URL_CACHE_FLUSH_INFO;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_FLUSH_INFO}
  TCryptnetURLCacheFlushInfo = _CRYPTNET_URL_CACHE_FLUSH_INFO;
  PCRYPTNET_URL_CACHE_FLUSH_INFO = PCryptnetURLCacheFlushInfo;
  {$EXTERNALSYM PCRYPTNET_URL_CACHE_FLUSH_INFO}

const
  CRYPTNET_URL_CACHE_DEFAULT_FLUSH               = 0;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_DEFAULT_FLUSH}
  CRYPTNET_URL_CACHE_DISABLE_FLUSH               = $FFFFFFFF;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_DISABLE_FLUSH}


//
// Cryptnet URL Cache Response Info
//
type
  PCryptnetURLCacheResponseInfo = ^TCryptnetURLCacheResponseInfo;
  _CRYPTNET_URL_CACHE_RESPONSE_INFO = record
    cbSize: DWORD;
    wResponseType: WORD;
    wResponseFlags: WORD;

    // The following are zero if not present
    LastModifiedTime: TFileTime;
    dwMaxAge: DWORD;
    pwszETag: LPCWSTR;
    dwProxyId: DWORD;
  end;
  {$EXTERNALSYM _CRYPTNET_URL_CACHE_RESPONSE_INFO}
  CRYPTNET_URL_CACHE_RESPONSE_INFO = _CRYPTNET_URL_CACHE_RESPONSE_INFO;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_RESPONSE_INFO}
  TCryptnetURLCacheResponseInfo = _CRYPTNET_URL_CACHE_RESPONSE_INFO;
  PCRYPTNET_URL_CACHE_RESPONSE_INFO = PCryptnetURLCacheResponseInfo;
  {$EXTERNALSYM PCRYPTNET_URL_CACHE_RESPONSE_INFO}


// ResponseTypes
const
  CRYPTNET_URL_CACHE_RESPONSE_NONE           = 0;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_RESPONSE_NONE}
  CRYPTNET_URL_CACHE_RESPONSE_HTTP           = 1;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_RESPONSE_HTTP}

// ResponseFlags
const
  CRYPTNET_URL_CACHE_RESPONSE_VALIDATED      = $8000;
  {$EXTERNALSYM CRYPTNET_URL_CACHE_RESPONSE_VALIDATED}

//
// CryptRetrieveObjectByUrl Auxilliary Info
//
//
// All unused fields in this data structure must be zeroed. More fields
// could be added in a future release.
//
type
  PCryptRetrieveAuxInfo = ^TCryptRetrieveAuxInfo;
  _CRYPT_RETRIEVE_AUX_INFO = record
    cbSize: DWORD;
    pLastSyncTime: PFileTime;

    // 0 => implies no limit
    dwMaxUrlRetrievalByteCount: DWORD;

    // To get any PreFetchInfo, set the following pointer to a
    // CRYPTNET_URL_CACHE_PRE_FETCH_INFO structure with its cbSize set
    // upon input. For no PreFetchInfo, except for cbSize, the data
    // structure is zeroed upon return.
    pPreFetchInfo: PCryptnetURLCachePreFetchInfo;

    // To get any FlushInfo, set the following pointer to a
    // CRYPTNET_URL_CACHE_FLUSH_INFO structure with its cbSize set
    // upon input. For no FlushInfo, except for cbSize, the data structure
    // is zeroed upon return.
    pFlushInfo: PCryptnetURLCacheFlushInfo;

    // To get any ResponseInfo, set the following pointer to the address
    // of a PCRYPTNET_URL_CACHE_RESPONSE_INFO pointer updated with
    // the allocated structure. For no ResponseInfo, *ppResponseInfo is set
    // to NULL. Otherwise, *ppResponseInfo must be free via CryptMemFree().
    ppResponseInfo: ^PCryptnetURLCacheResponseInfo;

    // If nonNULL, the specified prefix string is prepended to the
    // cached filename.
    pwszCacheFileNamePrefix: LPWSTR;

    // If nonNULL, any cached information before this time is considered
    // time invalid. For CRYPT_CACHE_ONLY_RETRIEVAL, if there is a
    // cached entry before this time, LastError is set to ERROR_INVALID_TIME.
    // Also used to set max-age for http retrievals.
    pftCacheResync: PFileTime;

    // The following flag is set upon return if CRYPT_PROXY_CACHE_RETRIEVAL
    // was set in dwRetrievalFlags and the proxy cache wasn't explicitly
    // bypassed for the retrieval. This flag won't be explicitly cleared.
    // This flag will only be set for http URL retrievals.
    fProxyCacheRetrieval: BOOL;

    // This value is only updated upon return for a nonSuccessful status code
    // returned in a HTTP response header. This value won't be explicitly
    // cleared. This value will only be updated for http or https URL
    // retrievals.
    //
    // If CRYPT_NOT_MODIFIED_RETRIEVAL was set in dwFlags, set to winhttp.h's
    // HTTP_STATUS_NOT_MODIFIED if the retrieval returned not modified. In
    // this case TRUE is returned with *ppvObject set to NULL.
    dwHttpStatusCode: DWORD;
  end;
  {$EXTERNALSYM _CRYPT_RETRIEVE_AUX_INFO}
  CRYPT_RETRIEVE_AUX_INFO = _CRYPT_RETRIEVE_AUX_INFO;
  {$EXTERNALSYM CRYPT_RETRIEVE_AUX_INFO}
  TCryptRetrieveAuxInfo = _CRYPT_RETRIEVE_AUX_INFO;
  PCRYPT_RETRIEVE_AUX_INFO = PCryptRetrieveAuxInfo;
  {$EXTERNALSYM PCRYPT_RETRIEVE_AUX_INFO}


function CryptRetrieveObjectByUrlA(
  pszUrl: LPCSTR;
  pszObjectOid: LPCSTR;
  dwRetrievalFlags: DWORD;
  dwTimeout: DWORD;                      // milliseconds
  out ppvObject: LPVOID;
  hAsyncRetrieve: HCRYPTASYNC;
  pCredentials: PCryptCredentials;
  pvVerify: LPVOID;
  pAuxInfo: PCryptRetrieveAuxInfo): BOOL; winapi;
{$EXTERNALSYM CryptRetrieveObjectByUrlA}

function CryptRetrieveObjectByUrlW(
  pszUrl: LPCWSTR;
  pszObjectOid: LPCSTR;
  dwRetrievalFlags: DWORD;
  dwTimeout: DWORD;                      // milliseconds
  out ppvObject: LPVOID;
  hAsyncRetrieve: HCRYPTASYNC;
  pCredentials: PCryptCredentials;
  pvVerify: LPVOID;
  pAuxInfo: PCryptRetrieveAuxInfo): BOOL; winapi;
{$EXTERNALSYM CryptRetrieveObjectByUrlW}

function CryptRetrieveObjectByUrl(
  pszUrl: LPCWSTR;
  pszObjectOid: LPCSTR;
  dwRetrievalFlags: DWORD;
  dwTimeout: DWORD;                      // milliseconds
  out ppvObject: LPVOID;
  hAsyncRetrieve: HCRYPTASYNC;
  pCredentials: PCryptCredentials;
  pvVerify: LPVOID;
  pAuxInfo: PCryptRetrieveAuxInfo): BOOL; winapi;
{$EXTERNALSYM CryptRetrieveObjectByUrl}

//
// Call back function to cancel object retrieval
//
// The function can be installed on a per thread basis.
// If CryptInstallCancelRetrieval is called for multiple times, only the most recent
// installation will be kept.
//
// This is only effective for http, https, gopher, and ftp protocol.
// It is ignored by the rest of the protocols.


type
  PFN_CRYPT_CANCEL_RETRIEVAL = function(
    dwFlags: DWORD;
    pvArg: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_CANCEL_RETRIEVAL}
  TFnCryptCancelRetrieval = PFN_CRYPT_CANCEL_RETRIEVAL;


//
// PFN_CRYPT_CANCEL_RETRIEVAL
//
// This function should return FALSE when the object retrieval should be continued
// and return TRUE when the object retrieval should be cancelled.
//

function CryptInstallCancelRetrieval(
  pfnCancel: TFnCryptCancelRetrieval;
  pvArg: Pointer;
  dwFlags: DWORD;
  pvReserved: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptInstallCancelRetrieval}

function CryptUninstallCancelRetrieval(
  dwFlags: DWORD;
  pvReserved: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptUninstallCancelRetrieval}

function CryptCancelAsyncRetrieval(
  hAsyncRetrieval: HCRYPTASYNC): BOOL; winapi;
{$EXTERNALSYM CryptCancelAsyncRetrieval}

//
// Remote Object Async Retrieval parameters
//

//
// A client that wants to be notified of asynchronous object retrieval
// completion sets this parameter on the async handle
//
const
  CRYPT_PARAM_ASYNC_RETRIEVAL_COMPLETION = LPCSTR(1);
  {$EXTERNALSYM CRYPT_PARAM_ASYNC_RETRIEVAL_COMPLETION}

type
  PFN_CRYPT_ASYNC_RETRIEVAL_COMPLETION_FUNC = procedure(
    pvCompletion: LPVOID;
    dwCompletionCode: DWORD;
    pszUrl: LPCSTR;
    pszObjectOid: LPSTR;
    pvObject: LPVOID); winapi;
  {$EXTERNALSYM PFN_CRYPT_ASYNC_RETRIEVAL_COMPLETION_FUNC}
  TFnCryptAsyncRetrievalCompletionFunc = PFN_CRYPT_ASYNC_RETRIEVAL_COMPLETION_FUNC;

type
  PCryptAsyncRetrievalCompletion = ^TCryptAsyncRetrievalCompletion;
  _CRYPT_ASYNC_RETRIEVAL_COMPLETION = record
    pfnCompletion: TFnCryptAsyncRetrievalCompletionFunc;
    pvCompletion: LPVOID;
  end;
  {$EXTERNALSYM _CRYPT_ASYNC_RETRIEVAL_COMPLETION}
  CRYPT_ASYNC_RETRIEVAL_COMPLETION = _CRYPT_ASYNC_RETRIEVAL_COMPLETION;
  {$EXTERNALSYM CRYPT_ASYNC_RETRIEVAL_COMPLETION}
  TCryptAsyncRetrievalCompletion = _CRYPT_ASYNC_RETRIEVAL_COMPLETION;
  PCRYPT_ASYNC_RETRIEVAL_COMPLETION = PCryptAsyncRetrievalCompletion;
  {$EXTERNALSYM PCRYPT_ASYNC_RETRIEVAL_COMPLETION}

//
// This function is set on the async handle by a scheme provider that
// supports asynchronous retrieval
//
const
  CRYPT_PARAM_CANCEL_ASYNC_RETRIEVAL = LPCSTR(2);
  {$EXTERNALSYM CRYPT_PARAM_CANCEL_ASYNC_RETRIEVAL}

type
  PFN_CANCEL_ASYNC_RETRIEVAL_FUNC = function(
    hAsyncRetrieve: HCRYPTASYNC): BOOL; winapi;
  {$EXTERNALSYM PFN_CANCEL_ASYNC_RETRIEVAL_FUNC}
  TFnCancelAsyncRetrievalFunc = PFN_CANCEL_ASYNC_RETRIEVAL_FUNC;

//
// Get the locator for a CAPI object
//
const
  CRYPT_GET_URL_FROM_PROPERTY         = $00000001;
  {$EXTERNALSYM CRYPT_GET_URL_FROM_PROPERTY}
  CRYPT_GET_URL_FROM_EXTENSION        = 400000002;
  {$EXTERNALSYM CRYPT_GET_URL_FROM_EXTENSION}
  CRYPT_GET_URL_FROM_UNAUTH_ATTRIBUTE = $00000004;
  {$EXTERNALSYM CRYPT_GET_URL_FROM_UNAUTH_ATTRIBUTE}
  CRYPT_GET_URL_FROM_AUTH_ATTRIBUTE   = $00000008;
  {$EXTERNALSYM CRYPT_GET_URL_FROM_AUTH_ATTRIBUTE}

type
  PCryptURLArray = ^TCryptURLArray;
  _CRYPT_URL_ARRAY = record
    cUrl: DWORD;
    rgwszUrl: ^LPWSTR;
  end;
  {$EXTERNALSYM _CRYPT_URL_ARRAY}
  CRYPT_URL_ARRAY = _CRYPT_URL_ARRAY;
  {$EXTERNALSYM CRYPT_URL_ARRAY}
  TCryptURLArray = _CRYPT_URL_ARRAY;
  PCRYPT_URL_ARRAY = PCryptURLArray;
  {$EXTERNALSYM PCRYPT_URL_ARRAY}

type
  PCryptURLInfo = ^TCryptURLInfo;
  _CRYPT_URL_INFO = record
    cbSize: DWORD;

    // Seconds between syncs
    dwSyncDeltaTime: DWORD;

    // Returned URLs may be grouped. For instance, groups of cross cert
    // distribution points. Each distribution point may have multiple
    // URLs, (LDAP and HTTP scheme).
    cGroup: DWORD;
    rgcGroupEntry: PDWORD;
  end;
  {$EXTERNALSYM _CRYPT_URL_INFO}
  CRYPT_URL_INFO = _CRYPT_URL_INFO;
  {$EXTERNALSYM CRYPT_URL_INFO}
  TCryptURLInfo = _CRYPT_URL_INFO;
  PCRYPT_URL_INFO = PCryptURLInfo;
  {$EXTERNALSYM PCRYPT_URL_INFO}

function CryptGetObjectUrl(
  pszUrlOid: LPCSTR;
  pvPara: LPVOID;
  dwFlags: DWORD;
  pUrlArray: PCryptURLArray;
  var pcbUrlArray: DWORD;
  pUrlInfo: PCryptURLInfo;
  pcbUrlInfo: PDWORD;
  pvReserved: LPVOID): BOOL; winapi;
{$EXTERNALSYM CryptGetObjectUrl}

const
  URL_OID_GET_OBJECT_URL_FUNC = 'UrlDllGetObjectUrl';
  {$EXTERNALSYM URL_OID_GET_OBJECT_URL_FUNC}

//
// UrlDllGetObjectUrl has the same signature as CryptGetObjectUrl
//

//
// URL_OID_CERTIFICATE_ISSUER
//
// pvPara == PCCERT_CONTEXT, certificate whose issuer's URL is being requested
//
// This will be retrieved from the authority info access extension or property
// on the certificate
//
// URL_OID_CERTIFICATE_CRL_DIST_POINT
//
// pvPara == PCCERT_CONTEXT, certificate whose CRL distribution point is being
// requested
//
// This will be retrieved from the CRL distribution point extension or property
// on the certificate
//
// URL_OID_CTL_ISSUER
//
// pvPara == PCCTL_CONTEXT, Signer Index, CTL whose issuer's URL (identified
// by the signer index) is being requested
//
// This will be retrieved from an authority info access attribute method encoded
// in each signer info in the PKCS7 (CTL)
//
// URL_OID_CTL_NEXT_UPDATE
//
// pvPara == PCCTL_CONTEXT, Signer Index, CTL whose next update URL is being
// requested and an optional signer index in case we need to check signer
// info attributes
//
// This will be retrieved from an authority info access CTL extension, property,
// or signer info attribute method
//
// URL_OID_CRL_ISSUER
//
// pvPara == PCCRL_CONTEXT, CRL whose issuer's URL is being requested
//
// This will be retrieved from a property on the CRL which has been inherited
// from the subject cert (either from the subject cert issuer or the subject
// cert distribution point extension).  It will be encoded as an authority
// info access extension method.
//
// URL_OID_CERTIFICATE_FRESHEST_CRL
//
// pvPara == PCCERT_CONTEXT, certificate whose freshest CRL distribution point
// is being requested
//
// This will be retrieved from the freshest CRL extension or property
// on the certificate
//
// URL_OID_CRL_FRESHEST_CRL
//
// pvPara == PCCERT_CRL_CONTEXT_PAIR, certificate's base CRL whose
// freshest CRL distribution point is being requested
//
// This will be retrieved from the freshest CRL extension or property
// on the CRL
//
// URL_OID_CROSS_CERT_DIST_POINT
//
// pvPara == PCCERT_CONTEXT, certificate whose cross certificate distribution
// point is being requested
//
// This will be retrieved from the cross certificate distribution point
// extension or property on the certificate
//
// URL_OID_CERTIFICATE_OCSP
//
// pvPara == PCCERT_CONTEXT, certificate whose OCSP URL is being requested
//
// This will be retrieved from the authority info access extension or property
// on the certificate
//
// URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT
//
// pvPara == PCCERT_CONTEXT, certificate whose OCSP URL and
// CRL distribution point are being requested
//
// This will be retrieved from the authority info access and
// CRL distribution point extension or property on the certificate.
// If any OCSP URLs are present, they will be first with each URL prefixed
// with L"ocsp:". The L"ocsp:" prefix should be removed before using.
//
// URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP
//
// Same as URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, except,
// the CRL URLs will be first
//
// URL_OID_CERTIFICATE_ONLY_OCSP
//
// Same as URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, except,
// only OCSP URLs are retrieved.
//
// URL_OID_CROSS_CERT_SUBJECT_INFO_ACCESS
//
// pvPara == PCCERT_CONTEXT, certificate whose cross certificates
// are being requested
//
// This will be retrieved from the Authority Info Access
// extension or property on the certificate. Only access methods
// matching szOID_PKIX_CA_REPOSITORY will be returned.
const
  URL_OID_CERTIFICATE_ISSUER         = LPCSTR(1);
  {$EXTERNALSYM URL_OID_CERTIFICATE_ISSUER}
  URL_OID_CERTIFICATE_CRL_DIST_POINT = LPCSTR(2);
  {$EXTERNALSYM URL_OID_CERTIFICATE_CRL_DIST_POINT}
  URL_OID_CTL_ISSUER                 = LPCSTR(3);
  {$EXTERNALSYM URL_OID_CTL_ISSUER}
  URL_OID_CTL_NEXT_UPDATE            = LPCSTR(4);
  {$EXTERNALSYM URL_OID_CTL_NEXT_UPDATE}
  URL_OID_CRL_ISSUER                 = LPCSTR(5);
  {$EXTERNALSYM URL_OID_CRL_ISSUER}
  URL_OID_CERTIFICATE_FRESHEST_CRL   = LPCSTR(6);
  {$EXTERNALSYM URL_OID_CERTIFICATE_FRESHEST_CRL}
  URL_OID_CRL_FRESHEST_CRL           = LPCSTR(7);
  {$EXTERNALSYM URL_OID_CRL_FRESHEST_CRL}
  URL_OID_CROSS_CERT_DIST_POINT      = LPCSTR(8);
  {$EXTERNALSYM URL_OID_CROSS_CERT_DIST_POINT}
  URL_OID_CERTIFICATE_OCSP           = LPCSTR(9);
  {$EXTERNALSYM URL_OID_CERTIFICATE_OCSP}
  URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT = LPCSTR(10);
  {$EXTERNALSYM URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT}
  URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP = LPCSTR(11);
  {$EXTERNALSYM URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP}
  URL_OID_CROSS_CERT_SUBJECT_INFO_ACCESS = LPCSTR(12);
  {$EXTERNALSYM URL_OID_CROSS_CERT_SUBJECT_INFO_ACCESS}
  URL_OID_CERTIFICATE_ONLY_OCSP      = LPCSTR(13);
  {$EXTERNALSYM URL_OID_CERTIFICATE_ONLY_OCSP}

type
  PCertCRLContextPair = ^TCertCRLContextPair;
  _CERT_CRL_CONTEXT_PAIR = record
    pCertContext: PCertContext;
    pCrlContext: PCRLContext;
  end;
  {$EXTERNALSYM _CERT_CRL_CONTEXT_PAIR}
  CERT_CRL_CONTEXT_PAIR = _CERT_CRL_CONTEXT_PAIR;
  {$EXTERNALSYM CERT_CRL_CONTEXT_PAIR}
  TCertCRLContextPair = _CERT_CRL_CONTEXT_PAIR;
  PCERT_CRL_CONTEXT_PAIR = PCertCRLContextPair;
  {$EXTERNALSYM PCERT_CRL_CONTEXT_PAIR}
  PCCERT_CRL_CONTEXT_PAIR = PCertCRLContextPair;
  {$EXTERNALSYM PCCERT_CRL_CONTEXT_PAIR}

//
// Get a time valid CAPI2 object
//

//+-------------------------------------------------------------------------
//  The following optional Extra Info may be passed to
//  CryptGetTimeValidObject().
//
//  All unused fields in this data structure must be zeroed. More fields
//  could be added in a future release.
//--------------------------------------------------------------------------
type
  PCryptGetTimeValidObjectExtraInfo = ^TCryptGetTimeValidObjectExtraInfo;
  _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO = record
    cbSize: DWORD;

    // If > 0, check that the CRL's number is >=
    // Should be 0x7fffffff if pDeltaCrlIndicator is nonNull
    iDeltaCrlIndicator: Integer;

    // If nonNULL, any cached information before this time is considered
    // time invalid and forces a wire retrieval.
    pftCacheResync: PFileTime;

    // If nonNull, returns the cache's LastSyncTime
    pLastSyncTime: PFileTime;

    // If nonNull, returns the internal MaxAge expiration time
    // for the object. If the object doesn't have a MaxAge expiration, set
    // to zero.
    pMaxAgeTime: PFileTime;

    // If nonNULL, CertGetCertificateChain() parameters used by the caller.
    // Enables independent OCSP signer certificate chain verification.
    pChainPara: PCertRevocationChainPara;

    // Should be used if the DeltaCrlIndicator value is more than 4 bytes
    // If nonNull and iDeltaCrlIndicator == MAXLONG, check that the CRL's number is >=
    pDeltaCrlIndicator: PCryptIntegerBlob;

  end;
  {$EXTERNALSYM _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO}
  CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO = _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO;
  {$EXTERNALSYM CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO}
  TCryptGetTimeValidObjectExtraInfo = _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO;
  PCRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO = PCryptGetTimeValidObjectExtraInfo;
  {$EXTERNALSYM PCRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO}

function CryptGetTimeValidObject(
  pszTimeValidOid: LPCSTR;
  pvPara: LPVOID;
  pIssuer: PCertContext;
  pftValidFor: PFileTime;
  dwFlags: DWORD;
  dwTimeout: DWORD;                          // milliseconds
  ppvObject: PPointer;
  pCredentials: PCryptCredentials;
  pExtraInfo: PCryptGetTimeValidObjectExtraInfo): BOOL; winapi;
{$EXTERNALSYM CryptGetTimeValidObject}

const
  TIME_VALID_OID_GET_OBJECT_FUNC = 'TimeValidDllGetObject';
  {$EXTERNALSYM TIME_VALID_OID_GET_OBJECT_FUNC}

//
// TimeValidDllGetObject has the same signature as CryptGetTimeValidObject
//

//
// TIME_VALID_OID_GET_CTL
//
// pvPara == PCCTL_CONTEXT, the current CTL
//
// TIME_VALID_OID_GET_CRL
//
// pvPara == PCCRL_CONTEXT, the current CRL
//
// TIME_VALID_OID_GET_CRL_FROM_CERT
//
// pvPara == PCCERT_CONTEXT, the subject cert
//
// TIME_VALID_OID_GET_FRESHEST_CRL_FROM_CERT
//
// pvPara == PCCERT_CONTEXT, the subject cert
//
// TIME_VALID_OID_GET_FRESHEST_CRL_FROM_CRL
//
// pvPara == PCCERT_CRL_CONTEXT_PAIR, the subject cert and its base CRL
//
const
  TIME_VALID_OID_GET_CTL           = LPCSTR(1);
  {$EXTERNALSYM TIME_VALID_OID_GET_CTL}
  TIME_VALID_OID_GET_CRL           = LPCSTR(2);
  {$EXTERNALSYM TIME_VALID_OID_GET_CRL}
  TIME_VALID_OID_GET_CRL_FROM_CERT = LPCSTR(3);
  {$EXTERNALSYM TIME_VALID_OID_GET_CRL_FROM_CERT}

  TIME_VALID_OID_GET_FRESHEST_CRL_FROM_CERT  = LPCSTR(4);
  {$EXTERNALSYM TIME_VALID_OID_GET_FRESHEST_CRL_FROM_CERT}
  TIME_VALID_OID_GET_FRESHEST_CRL_FROM_CRL   = LPCSTR(5);
  {$EXTERNALSYM TIME_VALID_OID_GET_FRESHEST_CRL_FROM_CRL}

function CryptFlushTimeValidObject(
  pszFlushTimeValidOid: LPCSTR;
  pvPara: LPVOID;
  pIssuer: PCertContext;
  dwFlags: DWORD;
  pvReserved: LPVOID): BOOL; winapi;
{$EXTERNALSYM CryptFlushTimeValidObject}

const
  TIME_VALID_OID_FLUSH_OBJECT_FUNC = 'TimeValidDllFlushObject';
  {$EXTERNALSYM TIME_VALID_OID_FLUSH_OBJECT_FUNC}

//
// TimeValidDllFlushObject has the same signature as CryptFlushTimeValidObject
//

//
// TIME_VALID_OID_FLUSH_CTL
//
// pvPara == PCCTL_CONTEXT, the CTL to flush
//
// TIME_VALID_OID_FLUSH_CRL
//
// pvPara == PCCRL_CONTEXT, the CRL to flush
//
// TIME_VALID_OID_FLUSH_CRL_FROM_CERT
//
// pvPara == PCCERT_CONTEXT, the subject cert's CRL to flush
//
// TIME_VALID_OID_FLUSH_FRESHEST_CRL_FROM_CERT
//
// pvPara == PCCERT_CONTEXT, the subject cert's freshest CRL to flush
//
// TIME_VALID_OID_FLUSH_FRESHEST_CRL_FROM_CRL
//
// pvPara == PCCERT_CRL_CONTEXT_PAIR, the subject cert and its base CRL's
// freshest CRL to flush
//
const
  TIME_VALID_OID_FLUSH_CTL           = LPCSTR(1);
  {$EXTERNALSYM TIME_VALID_OID_FLUSH_CTL}
  TIME_VALID_OID_FLUSH_CRL           = LPCSTR(2);
  {$EXTERNALSYM TIME_VALID_OID_FLUSH_CRL}
  TIME_VALID_OID_FLUSH_CRL_FROM_CERT = LPCSTR(3);
  {$EXTERNALSYM TIME_VALID_OID_FLUSH_CRL_FROM_CERT}

  TIME_VALID_OID_FLUSH_FRESHEST_CRL_FROM_CERT = LPCSTR(4);
  {$EXTERNALSYM TIME_VALID_OID_FLUSH_FRESHEST_CRL_FROM_CERT}
  TIME_VALID_OID_FLUSH_FRESHEST_CRL_FROM_CRL  = LPCSTR(5);
  {$EXTERNALSYM TIME_VALID_OID_FLUSH_FRESHEST_CRL_FROM_CRL}

//+=========================================================================
//  Helper functions to build certificates
//==========================================================================

//+-------------------------------------------------------------------------
//
// Builds a self-signed certificate and returns a PCCERT_CONTEXT representing
// the certificate. A hProv may be specified to build the cert context.
//
// pSubjectIssuerBlob is the DN for the certifcate. If an alternate subject
// name is desired it must be specified as an extension in the pExtensions
// parameter. pSubjectIssuerBlob can NOT be NULL, so minimually an empty DN
// must be specified.
//
// By default:
// pKeyProvInfo - The CSP is queried for the KeyProvInfo parameters. Only the Provider,
// Provider Type and Container is queried. Many CSPs don't support these
// queries and will cause a failure. In such cases the pKeyProvInfo
// must be specified (RSA BASE works fine).
//
// pSignatureAlgorithm - will default to SHA1RSA
// pStartTime will default to the current time
// pEndTime will default to 1 year
// pEntensions will be empty.
//
// The returned PCCERT_CONTEXT will reference the private keys by setting the
// CERT_KEY_PROV_INFO_PROP_ID. However, if this property is not desired specify the
// CERT_CREATE_SELFSIGN_NO_KEY_INFO in dwFlags.
//
// If the cert being built is only a dummy placeholder cert for speed it may not
// need to be signed. Signing of the cert is skipped if CERT_CREATE_SELFSIGN_NO_SIGN
// is specified in dwFlags.
//
//--------------------------------------------------------------------------
function CertCreateSelfSignCertificate(
  hCryptProvOrNCryptKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
  pSubjectIssuerBlob: PCertNameBlob;
  dwFlags: DWORD;
  pKeyProvInfo: PCryptKeyProvInfo;
  pSignatureAlgorithm: PCryptAlgorithmIdentifier;
  pStartTime: PSystemTime;
  pEndTime: PSystemTime;
  pExtensions: PCertExtensions): PCertContext; winapi;
{$EXTERNALSYM CertCreateSelfSignCertificate}

const
  CERT_CREATE_SELFSIGN_NO_SIGN     = 1;
  {$EXTERNALSYM CERT_CREATE_SELFSIGN_NO_SIGN}
  CERT_CREATE_SELFSIGN_NO_KEY_INFO = 2;
  {$EXTERNALSYM CERT_CREATE_SELFSIGN_NO_KEY_INFO}


//+=========================================================================
//  Key Identifier Property Data Structures and APIs
//==========================================================================

//+-------------------------------------------------------------------------
//  Get the property for the specified Key Identifier.
//
//  The Key Identifier is the SHA1 hash of the encoded CERT_PUBLIC_KEY_INFO.
//  The Key Identifier for a certificate can be obtained by getting the
//  certificate's CERT_KEY_IDENTIFIER_PROP_ID. The
//  CryptCreateKeyIdentifierFromCSP API can be called to create the Key
//  Identifier from a CSP Public Key Blob.
//
//  A Key Identifier can have the same properties as a certificate context.
//  CERT_KEY_PROV_INFO_PROP_ID is the property of most interest.
//  For CERT_KEY_PROV_INFO_PROP_ID, pvData points to a CRYPT_KEY_PROV_INFO
//  structure. Elements pointed to by fields in the pvData structure follow the
//  structure. Therefore, *pcbData will exceed the size of the structure.
//
//  If CRYPT_KEYID_ALLOC_FLAG is set, then, *pvData is updated with a
//  pointer to allocated memory. LocalFree() must be called to free the
//  allocated memory.
//
//  By default, searches the CurrentUser's list of Key Identifiers.
//  CRYPT_KEYID_MACHINE_FLAG can be set to search the LocalMachine's list
//  of Key Identifiers. When CRYPT_KEYID_MACHINE_FLAG is set, pwszComputerName
//  can also be set to specify the name of a remote computer to be searched
//  instead of the local machine.
//--------------------------------------------------------------------------
function CryptGetKeyIdentifierProperty(
  var pKeyIdentifier: TCryptHashBlob;
  dwPropId: DWORD;
  dwFlags: DWORD;
  pwszComputerName: LPCWSTR;
  pvReserved: Pointer;
  pvData: Pointer;
  var pcbData: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptGetKeyIdentifierProperty}

// When the following flag is set, searches the LocalMachine instead of the
// CurrentUser. This flag is applicable to all the KeyIdentifierProperty APIs.
const
  CRYPT_KEYID_MACHINE_FLAG       = $00000020;
  {$EXTERNALSYM CRYPT_KEYID_MACHINE_FLAG}

// When the following flag is set, *pvData is updated with a pointer to
// allocated memory. LocalFree() must be called to free the allocated memory.
const
  CRYPT_KEYID_ALLOC_FLAG         = $00008000;
  {$EXTERNALSYM CRYPT_KEYID_ALLOC_FLAG}


//+-------------------------------------------------------------------------
//  Set the property for the specified Key Identifier.
//
//  For CERT_KEY_PROV_INFO_PROP_ID pvData points to the
//  CRYPT_KEY_PROV_INFO data structure. For all other properties, pvData
//  points to a CRYPT_DATA_BLOB.
//
//  Setting pvData == NULL, deletes the property.
//
//  Set CRYPT_KEYID_MACHINE_FLAG to set the property for a LocalMachine
//  Key Identifier. Set pwszComputerName, to select a remote computer.
//
//  If CRYPT_KEYID_DELETE_FLAG is set, the Key Identifier and all its
//  properties is deleted.
//
//  If CRYPT_KEYID_SET_NEW_FLAG is set, the set fails if the property already
//  exists. For an existing property, FALSE is returned with LastError set to
//  CRYPT_E_EXISTS.
//--------------------------------------------------------------------------
function CryptSetKeyIdentifierProperty(
  var pKeyIdentifier: TCryptHashBlob;
  dwPropId: DWORD;
  dwFlags: DWORD;
  pwszComputerName: LPCWSTR;
  pvReserved: Pointer;
  pvData: Pointer): BOOL; winapi;
{$EXTERNALSYM CryptSetKeyIdentifierProperty}

// When the following flag is set, the Key Identifier and all its properties
// are deleted.
const
  CRYPT_KEYID_DELETE_FLAG        = $00000010;
  {$EXTERNALSYM CRYPT_KEYID_DELETE_FLAG}

// When the following flag is set, the set fails if the property already
// exists.
const
  CRYPT_KEYID_SET_NEW_FLAG       = $00002000;
  {$EXTERNALSYM CRYPT_KEYID_SET_NEW_FLAG}


//+-------------------------------------------------------------------------
//  For CERT_KEY_PROV_INFO_PROP_ID, rgppvData[] points to a
//  CRYPT_KEY_PROV_INFO.
//
//  Return FALSE to stop the enumeration.
//--------------------------------------------------------------------------
type
  PFN_CRYPT_ENUM_KEYID_PROP = function(
    var pKeyIdentifier: TCryptHashBlob;
    dwFlags: DWORD;
    pvReserved: Pointer;
    pvArg: Pointer;
    cProp: DWORD;
    rgdwPropId: PDWORD;
    rgpvData: PPointer;
    rgcbData: PDWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_ENUM_KEYID_PROP}
  TFnCryptEnumKeyIDProp = PFN_CRYPT_ENUM_KEYID_PROP;

//+-------------------------------------------------------------------------
//  Enumerate the Key Identifiers.
//
//  If pKeyIdentifier is NULL, enumerates all Key Identifers. Otherwise,
//  calls the callback for the specified KeyIdentifier. If dwPropId is
//  0, calls the callback with all the properties. Otherwise, only calls
//  the callback with the specified property (cProp = 1).
//  Furthermore, when dwPropId is specified, skips KeyIdentifiers not
//  having the property.
//
//  Set CRYPT_KEYID_MACHINE_FLAG to enumerate the LocalMachine
//  Key Identifiers. Set pwszComputerName, to enumerate Key Identifiers on
//  a remote computer.
//--------------------------------------------------------------------------
function CryptEnumKeyIdentifierProperties(
  pKeyIdentifier: PCryptHashBlob;
  dwPropId: DWORD;
  dwFlags: DWORD;
  pwszComputerName: LPCWSTR;
  pvReserved: Pointer;
  pvArg: Pointer;
  pfnEnum: TFnCryptEnumKeyIDProp): BOOL; winapi;
{$EXTERNALSYM CryptEnumKeyIdentifierProperties}

//+-------------------------------------------------------------------------
//  Create a KeyIdentifier from the CSP Public Key Blob.
//
//  Converts the CSP PUBLICKEYSTRUC into a X.509 CERT_PUBLIC_KEY_INFO and
//  encodes. The encoded CERT_PUBLIC_KEY_INFO is SHA1 hashed to obtain
//  the Key Identifier.
//
//  By default, the pPubKeyStruc->aiKeyAlg is used to find the appropriate
//  public key Object Identifier. pszPubKeyOID can be set to override
//  the default OID obtained from the aiKeyAlg.
//--------------------------------------------------------------------------
function CryptCreateKeyIdentifierFromCSP(
  dwCertEncodingType: DWORD;
  pszPubKeyOID: LPCSTR;
  var pPubKeyStruc: TPublicKeyStruc;
  cbPubKeyStruc: DWORD;
  dwFlags: DWORD;
  pvReserved: Pointer;
  pbHash: PByte;
  var pcbHash: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptCreateKeyIdentifierFromCSP}


//+=========================================================================
//  Certificate Chaining Infrastructure
//==========================================================================
const
  CERT_CHAIN_CONFIG_REGPATH =
    'Software\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config';
  {$EXTERNALSYM CERT_CHAIN_CONFIG_REGPATH}

// max size of the cryptographic object to download, in bytes
// NOTE: AIA has different configuration
const
  CERT_CHAIN_MAX_URL_RETRIEVAL_BYTE_COUNT_VALUE_NAME      =
    'MaxUrlRetrievalByteCount';
  {$EXTERNALSYM CERT_CHAIN_MAX_URL_RETRIEVAL_BYTE_COUNT_VALUE_NAME}
  CERT_CHAIN_MAX_URL_RETRIEVAL_BYTE_COUNT_DEFAULT         = (100*1024*1024);
  {$EXTERNALSYM CERT_CHAIN_MAX_URL_RETRIEVAL_BYTE_COUNT_DEFAULT}

// The following is a REG_BINARY. It contains the cache resync FILETIME.
// Any cached information before this time is considered time invalid
// and forces a wire retrieval. By default this is disabled.
const
  CERT_CHAIN_CACHE_RESYNC_FILETIME_VALUE_NAME    =
    'ChainCacheResyncFiletime';
  {$EXTERNALSYM CERT_CHAIN_CACHE_RESYNC_FILETIME_VALUE_NAME}

// The following are REG_DWORD's. These configuration parameters are used
// to disable different chain building semantics enabled by default. Set
// the appropriate registry value to nonzero to disable.
const
  CERT_CHAIN_DISABLE_MANDATORY_BASIC_CONSTRAINTS_VALUE_NAME  =
    'DisableMandatoryBasicConstraints';
  {$EXTERNALSYM CERT_CHAIN_DISABLE_MANDATORY_BASIC_CONSTRAINTS_VALUE_NAME}
// By default the BasicConstraints extension must be present with CA enabled
// for non-Root intermediate CA certificates.
const
  CERT_CHAIN_DISABLE_CA_NAME_CONSTRAINTS_VALUE_NAME  =
    'DisableCANameConstraints';
  {$EXTERNALSYM CERT_CHAIN_DISABLE_CA_NAME_CONSTRAINTS_VALUE_NAME}
// By default the NameConstraints extension is applied to the intermediate
// CA certificates in addition to the end entity certificate.
const
  CERT_CHAIN_DISABLE_UNSUPPORTED_CRITICAL_EXTENSIONS_VALUE_NAME  =
    'DisableUnsupportedCriticalExtensions';
  {$EXTERNALSYM CERT_CHAIN_DISABLE_UNSUPPORTED_CRITICAL_EXTENSIONS_VALUE_NAME}
// By default any unsupported extension marked critical sets the following
// dwErrorStatus bit: CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT.

// The following are REG_DWORD's. These configuration parameters are used
// to restrict Authority Info Access (AIA) URL retrieval.
const
  CERT_CHAIN_MAX_AIA_URL_COUNT_IN_CERT_VALUE_NAME             =
    'MaxAIAUrlCountInCert';
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_COUNT_IN_CERT_VALUE_NAME}
  CERT_CHAIN_MAX_AIA_URL_COUNT_IN_CERT_DEFAULT                = 5;
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_COUNT_IN_CERT_DEFAULT}

  CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_COUNT_PER_CHAIN_VALUE_NAME =
    'MaxAIAUrlRetrievalCountPerChain';
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_COUNT_PER_CHAIN_VALUE_NAME}
  CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_COUNT_PER_CHAIN_DEFAULT    = 3;
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_COUNT_PER_CHAIN_DEFAULT}

// max size of the object to download, specified by a URL in AIA extention, in bytes
const
  CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_BYTE_COUNT_VALUE_NAME      =
    'MaxAIAUrlRetrievalByteCount';
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_BYTE_COUNT_VALUE_NAME}
  CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_BYTE_COUNT_DEFAULT         = 100000;
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_BYTE_COUNT_DEFAULT}

  CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_CERT_COUNT_VALUE_NAME      =
    'MaxAIAUrlRetrievalCertCount';
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_CERT_COUNT_VALUE_NAME}
  CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_CERT_COUNT_DEFAULT         = 10;
  {$EXTERNALSYM CERT_CHAIN_MAX_AIA_URL_RETRIEVAL_CERT_COUNT_DEFAULT}

// The following is a REG_DWORD. If the OCSP response NextUpdate is zero,
// this value is added to the ThisUpdate to get a nonzero NextUpdate.
const
  CERT_CHAIN_OCSP_VALIDITY_SECONDS_VALUE_NAME                 =
    'OcspValiditySeconds';
  {$EXTERNALSYM CERT_CHAIN_OCSP_VALIDITY_SECONDS_VALUE_NAME}
// 12 hours
const
  CERT_CHAIN_OCSP_VALIDITY_SECONDS_DEFAULT   = (12 * 60 * 60);
  {$EXTERNALSYM CERT_CHAIN_OCSP_VALIDITY_SECONDS_DEFAULT}


// The following is a REG_DWORD. Flags can be set to enable weak
// signature hash algorithms and/or weak public key lengths that
// are disabled by default. Also, has flags to enable logging of weak
// certificates.
//
const
  CERT_CHAIN_ENABLE_WEAK_SIGNATURE_FLAGS_VALUE_NAME  =
    'EnableWeakSignatureFlags';
  {$EXTERNALSYM CERT_CHAIN_ENABLE_WEAK_SIGNATURE_FLAGS_VALUE_NAME}

// The following flag is set to enable MD2 or MD4 hashes that are
// disabled by default. If none, code signing, driver signing
// or time stamping requested EKUs are passed to CertGetCertificateChain API,
// then MD2 or MD4 isn't disabled by default.
const
  CERT_CHAIN_ENABLE_MD2_MD4_FLAG             = $00000001;
  {$EXTERNALSYM CERT_CHAIN_ENABLE_MD2_MD4_FLAG}

// The following flag is set to enable weak RSA public key lengths
// for trusted roots that are disabled by default.
const
  CERT_CHAIN_ENABLE_WEAK_RSA_ROOT_FLAG       = $00000002;
  {$EXTERNALSYM CERT_CHAIN_ENABLE_WEAK_RSA_ROOT_FLAG}

// The following flag is set to enable the logging of weak certificates
// to the directory identified by CERT_CHAIN_WEAK_SIGNATURE_LOG_DIR_VALUE_NAME.
// Not applicable to MD2 or MD4 certificates.
const
  CERT_CHAIN_ENABLE_WEAK_LOGGING_FLAG        = $00000004;
  {$EXTERNALSYM CERT_CHAIN_ENABLE_WEAK_LOGGING_FLAG}

// The following flag is set to only log weak certificates. Disables
// weak signature errors from being returned. Not applicable
// to MD2 or MD4 certificates.
const
  CERT_CHAIN_ENABLE_ONLY_WEAK_LOGGING_FLAG   = $00000008;
  {$EXTERNALSYM CERT_CHAIN_ENABLE_ONLY_WEAK_LOGGING_FLAG}


// The following is a REG_DWORD that specifies the minimum RSA public
// key length in bits. If not defined or a value of 0, uses the
// default value.
const
  CERT_CHAIN_MIN_RSA_PUB_KEY_BIT_LENGTH_VALUE_NAME    =
    'MinRsaPubKeyBitLength';
  {$EXTERNALSYM CERT_CHAIN_MIN_RSA_PUB_KEY_BIT_LENGTH_VALUE_NAME}
  CERT_CHAIN_MIN_RSA_PUB_KEY_BIT_LENGTH_DEFAULT       = 1023;
  {$EXTERNALSYM CERT_CHAIN_MIN_RSA_PUB_KEY_BIT_LENGTH_DEFAULT}

// The following value disables checking for weak RSA public key lengths.
const
  CERT_CHAIN_MIN_RSA_PUB_KEY_BIT_LENGTH_DISABLE       =
    $FFFFFFFF;
  {$EXTERNALSYM CERT_CHAIN_MIN_RSA_PUB_KEY_BIT_LENGTH_DISABLE}

// The following is a REG_BINARY containing the 8 byte FILETIME. The weak
// RSA public key length check is disabled for timestamped files before
// this time. If not defined or a zero FILETIME, uses the default value.
const
  CERT_CHAIN_WEAK_RSA_PUB_KEY_TIME_VALUE_NAME         =
    'WeakRsaPubKeyTime';
  {$EXTERNALSYM CERT_CHAIN_WEAK_RSA_PUB_KEY_TIME_VALUE_NAME}

// The default time: UTC: Fri Jan 01 00:00:00 2010
const
  CERT_CHAIN_WEAK_RSA_PUB_KEY_TIME_DEFAULT            =
    $01CA8A755C6E0000;
  {$EXTERNALSYM CERT_CHAIN_WEAK_RSA_PUB_KEY_TIME_DEFAULT}

// The following is a REG_SZ. When defined, weak certificates are
// written to this directory. This directory should be ACL'ed to allow
// modify access by Authenticated Users and All Application Packages.
const
  CERT_CHAIN_WEAK_SIGNATURE_LOG_DIR_VALUE_NAME        =
    'WeakSignatureLogDir';
  {$EXTERNALSYM CERT_CHAIN_WEAK_SIGNATURE_LOG_DIR_VALUE_NAME}



// The following are REG_DWORD's. These configuration parameters are
// used by the following APIs to get a non-blocking, time valid OCSP
// response for a server certificate chain:
//   CertOpenServerOcspResponse
//   CertAddRefServerOcspResponse
//   CertCloseServerOcspResponse
//   CertGetServerOcspResponseContext
//   CertAddRefServerOcspResponseContext
//   CertFreeServerOcspResponseContext

// This is the minimum validity of the server OCSP response to be
// returned by CertGetServerOcspResponseContext(). Since this OCSP
// response will be returned to the client, it must be sufficiently long
// so that the client will treat it as being time valid.
const
  CERT_SRV_OCSP_RESP_MIN_VALIDITY_SECONDS_VALUE_NAME =
    'SrvOcspRespMinValiditySeconds';
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MIN_VALIDITY_SECONDS_VALUE_NAME}
// 10 minutes
const
  CERT_SRV_OCSP_RESP_MIN_VALIDITY_SECONDS_DEFAULT =
    (10 * 60);
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MIN_VALIDITY_SECONDS_DEFAULT}

// This is the maximum number of milliseconds for each server OCSP response
// pre-fetch wire URL retrieval.
const
  CERT_SRV_OCSP_RESP_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_VALUE_NAME =
    'SrvOcspRespUrlRetrievalTimeoutMilliseconds';
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_VALUE_NAME}
// 15 seconds
const
  CERT_SRV_OCSP_RESP_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_DEFAULT =
    (15 * 1000);
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_DEFAULT}

// This is the maximum number of seconds to do a server OCSP response
// pre-fetch retrieval before the OCSP response's NextUpdate. The
// server OCSP response pre-fetch thread will wait until CurrentTime >=
// NextUpdate - MaxBeforeNextUpdateSeconds before doing the next retrieval.
const
  CERT_SRV_OCSP_RESP_MAX_BEFORE_NEXT_UPDATE_SECONDS_VALUE_NAME =
    'SrvOcspRespMaxBeforeNextUpdateSeconds';
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MAX_BEFORE_NEXT_UPDATE_SECONDS_VALUE_NAME}
// 4 hours
const
  CERT_SRV_OCSP_RESP_MAX_BEFORE_NEXT_UPDATE_SECONDS_DEFAULT =
    (4 * 60 * 60);
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MAX_BEFORE_NEXT_UPDATE_SECONDS_DEFAULT}

// This is the minimum number of seconds to do a server OCSP response
// pre-fetch retrieval before the OCSP response's NextUpdate.
// If CurrentTime >= NextUpdate - MinBeforeNextUpdateSeconds, will wait until
// after NextUpdate + MinAfterNextUpdateSeconds.
const
  CERT_SRV_OCSP_RESP_MIN_BEFORE_NEXT_UPDATE_SECONDS_VALUE_NAME =
    'SrvOcspRespMinBeforeNextUpdateSeconds';
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MIN_BEFORE_NEXT_UPDATE_SECONDS_VALUE_NAME}
// 2 minutes
const
  CERT_SRV_OCSP_RESP_MIN_BEFORE_NEXT_UPDATE_SECONDS_DEFAULT =
    (2 * 60);
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MIN_BEFORE_NEXT_UPDATE_SECONDS_DEFAULT}

// This is the minimum number of seconds to do a server OCSP response
// pre-fetch retrieval after the OCSP response's NextUpdate when
// (NextUpdate - MinBeforeNextUpdateSeconds) < CurrentTime < NextUpdate.
const
  CERT_SRV_OCSP_RESP_MIN_AFTER_NEXT_UPDATE_SECONDS_VALUE_NAME =
    'SrvOcspRespMinAfterNextUpdateSeconds';
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MIN_AFTER_NEXT_UPDATE_SECONDS_VALUE_NAME}
// 1 minute
const
  CERT_SRV_OCSP_RESP_MIN_AFTER_NEXT_UPDATE_SECONDS_DEFAULT =
    (1 * 60);
  {$EXTERNALSYM CERT_SRV_OCSP_RESP_MIN_AFTER_NEXT_UPDATE_SECONDS_DEFAULT}


// The following are REG_DWORD's. These configuration parameters are used
// in the ordering of the revocation retrieval URLs.


// When the number of cached OCSP URLs associated with the same CDP extension
// equal or exceed this number, the OCSP AIA URLs aren't used.
const
  CRYPTNET_MAX_CACHED_OCSP_PER_CRL_COUNT_VALUE_NAME =
    'CryptnetMaxCachedOcspPerCrlCount';
  {$EXTERNALSYM CRYPTNET_MAX_CACHED_OCSP_PER_CRL_COUNT_VALUE_NAME}
  CRYPTNET_MAX_CACHED_OCSP_PER_CRL_COUNT_DEFAULT =
    500;
  {$EXTERNALSYM CRYPTNET_MAX_CACHED_OCSP_PER_CRL_COUNT_DEFAULT}

// The above registry value can be set to this value, to disable OCSP
// when a CDP extension is present. Note, a registry value of 0, uses the
// above default value.
const
  CRYPTNET_OCSP_AFTER_CRL_DISABLE =
    $FFFFFFFF;
  {$EXTERNALSYM CRYPTNET_OCSP_AFTER_CRL_DISABLE}

// The following are REG_DWORD's. These configuration parameters are
// used by the Cryptnet Url Cache Service (CUCS).

// The following parameter is used as the default flush exempt seconds
const
  CRYPTNET_URL_CACHE_DEFAULT_FLUSH_EXEMPT_SECONDS_VALUE_NAME =
    'CryptnetDefaultFlushExemptSeconds';
  {$EXTERNALSYM CRYPTNET_URL_CACHE_DEFAULT_FLUSH_EXEMPT_SECONDS_VALUE_NAME}

// 4 Weeks : 28 days * 24 hours * 60 minutes * 60 seconds
const
  CRYPTNET_URL_CACHE_DEFAULT_FLUSH_EXEMPT_SECONDS_DEFAULT =
    (28 * 24 * 60 * 60);
  {$EXTERNALSYM CRYPTNET_URL_CACHE_DEFAULT_FLUSH_EXEMPT_SECONDS_DEFAULT}

// Following 2 parameters are used to set the lower and upper limit
// on the max-age retrievals done before the Publish and NextUpdate times.
const
  CRYPTNET_PRE_FETCH_MIN_MAX_AGE_SECONDS_VALUE_NAME =
    'CryptnetPreFetchMinMaxAgeSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_MAX_AGE_SECONDS_VALUE_NAME}
// 1 hour
const
  CRYPTNET_PRE_FETCH_MIN_MAX_AGE_SECONDS_DEFAULT =
    (1 * 60 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_MAX_AGE_SECONDS_DEFAULT}

  CRYPTNET_PRE_FETCH_MAX_MAX_AGE_SECONDS_VALUE_NAME =
    'CryptnetPreFetchMaxMaxAgeSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MAX_MAX_AGE_SECONDS_VALUE_NAME}
// 2 Weeks : 14 days * 24 hours * 60 minutes * 60 seconds
const
  CRYPTNET_PRE_FETCH_MAX_MAX_AGE_SECONDS_DEFAULT =
    (14 * 24 * 60 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MAX_MAX_AGE_SECONDS_DEFAULT}

// Following parameter is used to set the lower limit on the
// OCSP validity period
const
  CRYPTNET_PRE_FETCH_MIN_OCSP_VALIDITY_PERIOD_SECONDS_VALUE_NAME =
    'CryptnetPreFetchMinOcspValidityPeriodSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_OCSP_VALIDITY_PERIOD_SECONDS_VALUE_NAME}
// 2 Weeks : 14 days * 24 hours * 60 minutes * 60 seconds
const
  CRYPTNET_PRE_FETCH_MIN_OCSP_VALIDITY_PERIOD_SECONDS_DEFAULT =
    (14 * 24 * 60 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_OCSP_VALIDITY_PERIOD_SECONDS_DEFAULT}

// Following 3 parameters are used to calculate the PreFetch start before
// the NextUpdate
//
// Where PreFetchStartTime = PublishTime +
//                              PublishPeriod / AfterPublishPreFetchDivisor
//       PreFetchEndTime = NextUpdate -
//                              PublishPeriod / BeforeNextUpdatePreFetchDivisor
//
//       PreFetchPeriod = PreFetchEndTime - PreFetchStartTime
//
//       if (PreFetchPeriod < MinBeforeNextUpdatePreFetchPeriodSeconds)
//          - No PreFetch is done before NextUpdate
//       else
//          - PreFetch starts are randomized over this period

// The start of the PreFetch period is delayed after the start of the
// Publish period by dividing the PublishPeriod (NextUpdate - PublishTime)
// by this integer divisor.
const
  CRYPTNET_PRE_FETCH_AFTER_PUBLISH_PRE_FETCH_DIVISOR_VALUE_NAME =
    'CryptnetPreFetchAfterPublishPreFetchDivisor';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_AFTER_PUBLISH_PRE_FETCH_DIVISOR_VALUE_NAME}
// 10, where 12 hours / 10 = 72 minutes or 1.2 hours / 10 = 7.2 minutes
const
  CRYPTNET_PRE_FETCH_AFTER_PUBLISH_PRE_FETCH_DIVISOR_DEFAULT =
    10;
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_AFTER_PUBLISH_PRE_FETCH_DIVISOR_DEFAULT}

// The finish of the PreFetch period occurs before NextUpdate
// by dividing the PublishPeriod (NextUpdate - PublishTime)
// by this integer divisor.
const
  CRYPTNET_PRE_FETCH_BEFORE_NEXT_UPDATE_PRE_FETCH_DIVISOR_VALUE_NAME =
    'CryptnetPreFetchBeforeNextUpdatePreFetchDivisor';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_BEFORE_NEXT_UPDATE_PRE_FETCH_DIVISOR_VALUE_NAME}
// 20, where 12 hours / 20 = 36 minutes or 1.2 hours / 10 = 3.6 minutes
const
  CRYPTNET_PRE_FETCH_BEFORE_NEXT_UPDATE_PRE_FETCH_DIVISOR_DEFAULT =
    20;
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_BEFORE_NEXT_UPDATE_PRE_FETCH_DIVISOR_DEFAULT}

// The PreFetch period must exceed this minimum duration in seconds
// to do a PreFetch before NextUpdate
const
  CRYPTNET_PRE_FETCH_MIN_BEFORE_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME =
    'CryptnetPreFetchMinBeforeNextUpdatePreFetchSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_BEFORE_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME}
// 1 hour
//
// For the default OCSP period of 12 hours using above defaults,
// PreFetchPeriod = 72 minutes - 7.2 minutes - 3.6 mintes = 61.2 minutes
const
  CRYPTNET_PRE_FETCH_MIN_BEFORE_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_DEFAULT =
    (1 * 60 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_BEFORE_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_DEFAULT}

// Following 4 parameters are used to calculate the PreFetch start after
// the NextUpdate
//
// ValidityPeriod = NextUpdate - ThisUpdate
//
// PreFetchPeriod = ValidityPeriod / AfterNextUpdatePreFetchDivisor
//
// Where PreFetchPeriod is decreased to MaxAfterNextUpdatePreFetchPeriodSeconds
// or increased to MinAfterNextUpdatePreFetchPeriodSeconds;
//
// PreFetchStartTime = NextUpdate
// PreFetchEndTime = PreFetchStartTime + PreFetchPeriod
//
// PreFetch starts are randomized over the above PreFetchPeriod
//
// If CurrentTime > RandomPreFetchStartTime, then, the
// AfterCurrentTimePreFetchPeriodSeconds is randomized and added to
// CurrentTime for the RandomPreFetchStartTime

// The PreFetch period after NextUpdate is initially calculated by
// dividing the ValidityPeriod (NextUpdate - ThisUpdate) by this integer
// divisor.
const
  CRYPTNET_PRE_FETCH_VALIDITY_PERIOD_AFTER_NEXT_UPDATE_PRE_FETCH_DIVISOR_VALUE_NAME =
    'CryptnetPreFetchValidityPeriodAfterNextUpdatePreFetchDivisor';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_VALIDITY_PERIOD_AFTER_NEXT_UPDATE_PRE_FETCH_DIVISOR_VALUE_NAME}
// 10, where 1 week / 10 = 16.8 hours
const
  CRYPTNET_PRE_FETCH_VALIDITY_PERIOD_AFTER_NEXT_UPDATE_PRE_FETCH_DIVISOR_DEFAULT =
    10;
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_VALIDITY_PERIOD_AFTER_NEXT_UPDATE_PRE_FETCH_DIVISOR_DEFAULT}

// If necessary, the above PreFetch period will be decreased
// to this maximum duration in seconds.
const
  CRYPTNET_PRE_FETCH_MAX_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME =
    'CryptnetPreFetchMaxAfterNextUpdatePreFetchPeriodSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MAX_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME}
// 4 hours
const
  CRYPTNET_PRE_FETCH_MAX_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_DEFAULT =
    (4 * 60 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MAX_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_DEFAULT}

// If necessary, the above PreFetch period will be increased
// to this minimum duration in seconds.
const
  CRYPTNET_PRE_FETCH_MIN_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME =
    'CryptnetPreFetchMinAfterNextUpdatePreFetchPeriodSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME}
// 30 minutes
const
  CRYPTNET_PRE_FETCH_MIN_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_DEFAULT =
    (30 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_MIN_AFTER_NEXT_UPDATE_PRE_FETCH_PERIOD_SECONDS_DEFAULT}

// If the CurrentTime is after the above randomized start time, the following
// parameter will be randomized and added to the CurrentTime.
const
  CRYPTNET_PRE_FETCH_AFTER_CURRENT_TIME_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME =
    'CryptnetPreFetchAfterCurrentTimePreFetchPeriodSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_AFTER_CURRENT_TIME_PRE_FETCH_PERIOD_SECONDS_VALUE_NAME}
// 30 minutes
const
  CRYPTNET_PRE_FETCH_AFTER_CURRENT_TIME_PRE_FETCH_PERIOD_SECONDS_DEFAULT =
    (30 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_AFTER_CURRENT_TIME_PRE_FETCH_PERIOD_SECONDS_DEFAULT}


// Following parameter specifies the minimum time period between sending
// trigger URL cache PreFetch LRPC messages to cryptsvc after doing online
// revocation enabled chain builds.
const
  CRYPTNET_PRE_FETCH_TRIGGER_PERIOD_SECONDS_VALUE_NAME =
    'CryptnetPreFetchTriggerPeriodSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_TRIGGER_PERIOD_SECONDS_VALUE_NAME}
// 10 minutes
const
  CRYPTNET_PRE_FETCH_TRIGGER_PERIOD_SECONDS_DEFAULT =
    (10 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_TRIGGER_PERIOD_SECONDS_DEFAULT}

// The above registry value can be set to this value, to disable the
// sending of trigger URL cache PreFetch LRPC messages. Note, a registry
// value of 0, uses the above default value.
const
  CRYPTNET_PRE_FETCH_TRIGGER_DISABLE =
    $FFFFFFFF;
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_TRIGGER_DISABLE}

// Following parameter specifies the delay time to wait to scan the
// URL cache directory after receiving a trigger LRPC message request.
const
  CRYPTNET_PRE_FETCH_SCAN_AFTER_TRIGGER_DELAY_SECONDS_VALUE_NAME =
    'CryptnetPreFetchScanAfterTriggerDelaySeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_SCAN_AFTER_TRIGGER_DELAY_SECONDS_VALUE_NAME}
// 30 seconds
const
  CRYPTNET_PRE_FETCH_SCAN_AFTER_TRIGGER_DELAY_SECONDS_DEFAULT =
    30;
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_SCAN_AFTER_TRIGGER_DELAY_SECONDS_DEFAULT}

// Following parameter specifies the maximum amount of time to wait for any
// PreFetch retrieval to complete
const
  CRYPTNET_PRE_FETCH_RETRIEVAL_TIMEOUT_SECONDS_VALUE_NAME =
    'CryptnetPreFetchRetrievalTimeoutSeconds';
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_RETRIEVAL_TIMEOUT_SECONDS_VALUE_NAME}
// 5 minutes
const
  CRYPTNET_PRE_FETCH_RETRIEVAL_TIMEOUT_SECONDS_DEFAULT =
    (5 * 60);
  {$EXTERNALSYM CRYPTNET_PRE_FETCH_RETRIEVAL_TIMEOUT_SECONDS_DEFAULT}

//+-------------------------------------------------------------------------
// The following configuration parameters are store in HKLM group policy
//--------------------------------------------------------------------------
const
  CERT_GROUP_POLICY_CHAIN_CONFIG_REGPATH =
    CERT_GROUP_POLICY_SYSTEM_STORE_REGPATH + '\ChainEngine\Config';
  {$EXTERNALSYM CERT_GROUP_POLICY_CHAIN_CONFIG_REGPATH}

// In Vista, the following have been moved from the above HKLM
// configuration parameters:

// The following are REG_DWORD's. These configuration parameters are used
// to override the default URL timeouts in chain building

// This is the default URL timeout in milliseconds
const
  CERT_CHAIN_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_VALUE_NAME    =
    'ChainUrlRetrievalTimeoutMilliseconds';
  {$EXTERNALSYM CERT_CHAIN_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_VALUE_NAME}
// 15 seconds
const
  CERT_CHAIN_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_DEFAULT       =
    (15 * 1000);
  {$EXTERNALSYM CERT_CHAIN_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_DEFAULT}

// This is the default revocation accumulative URL timeout in milliseconds
// The first revocation URL retrieval uses half of this timeout
const
  CERT_CHAIN_REV_ACCUMULATIVE_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_VALUE_NAME =
    'ChainRevAccumulativeUrlRetrievalTimeoutMilliseconds';
  {$EXTERNALSYM CERT_CHAIN_REV_ACCUMULATIVE_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_VALUE_NAME}
// 20 seconds
const
  CERT_CHAIN_REV_ACCUMULATIVE_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_DEFAULT =
    (20 * 1000);
  {$EXTERNALSYM CERT_CHAIN_REV_ACCUMULATIVE_URL_RETRIEVAL_TIMEOUT_MILLISECONDS_DEFAULT}

// REG_DWORD: Set this value to non-zero in order to enable Internet connections
// with Unknown Authorization
const
  CERT_RETR_BEHAVIOR_INET_AUTH_VALUE_NAME    = 'EnableInetUnknownAuth';
  {$EXTERNALSYM CERT_RETR_BEHAVIOR_INET_AUTH_VALUE_NAME}

// REG_DWORD: Set this value to non-zero in order to override Internet
// connectivity status allowing LOCAL to be treated as INTERNET.
const
  CERT_RETR_BEHAVIOR_INET_STATUS_VALUE_NAME  = 'EnableInetLocal';
  {$EXTERNALSYM CERT_RETR_BEHAVIOR_INET_STATUS_VALUE_NAME}

// REG_DWORD: Set this value to non-zero in order to allow
// file:// URL scheme.
const
  CERT_RETR_BEHAVIOR_FILE_VALUE_NAME         = 'AllowFileUrlScheme';
  {$EXTERNALSYM CERT_RETR_BEHAVIOR_FILE_VALUE_NAME}

// REG_DWORD: Set this value to non-zero in order to disable
// LDAP mutual authentication and & encryption.
const
  CERT_RETR_BEHAVIOR_LDAP_VALUE_NAME         = 'DisableLDAPSignAndEncrypt';
  {$EXTERNALSYM CERT_RETR_BEHAVIOR_LDAP_VALUE_NAME}

// Note, will allow the machine setting to be used if this value isn't
// defined.


// By default AIA OCSP URLs are before CDP CRL URLs. When the number of cached
// OCSP URLs associated with the same CDP extension equal or exceed this
// number, the CRL URLs are placed before the OCSP URLs.
const
  CRYPTNET_CACHED_OCSP_SWITCH_TO_CRL_COUNT_VALUE_NAME =
    'CryptnetCachedOcspSwitchToCrlCount';
  {$EXTERNALSYM CRYPTNET_CACHED_OCSP_SWITCH_TO_CRL_COUNT_VALUE_NAME}
  CRYPTNET_CACHED_OCSP_SWITCH_TO_CRL_COUNT_DEFAULT =
    50;
  {$EXTERNALSYM CRYPTNET_CACHED_OCSP_SWITCH_TO_CRL_COUNT_DEFAULT}

// The above registry value can be set to this value, to always place
// the CRL URLs before the OCSP URLs. Note, a registry value of 0, uses the
// above default value.
const
  CRYPTNET_CRL_BEFORE_OCSP_ENABLE =
    $FFFFFFFF;
  {$EXTERNALSYM CRYPTNET_CRL_BEFORE_OCSP_ENABLE}


// Support for the following was removed in Vista. Changed to use
// the following OPTIONS flags in HKLM Group Policy
const
  CERT_CHAIN_DISABLE_AIA_URL_RETRIEVAL_VALUE_NAME             =
    'DisableAIAUrlRetrieval';
  {$EXTERNALSYM CERT_CHAIN_DISABLE_AIA_URL_RETRIEVAL_VALUE_NAME}
// By default AIA Url Retrieval is enabled. Set this registry value to nonzero
// to disable


// This is the name of the REG_DWORD for chain engine Options
const
  CERT_CHAIN_OPTIONS_VALUE_NAME =
    'Options';
  {$EXTERNALSYM CERT_CHAIN_OPTIONS_VALUE_NAME}
// Disable AIA URL retrieval when this bit is set in the Options
const
  CERT_CHAIN_OPTION_DISABLE_AIA_URL_RETRIEVAL                = $2;
  {$EXTERNALSYM CERT_CHAIN_OPTION_DISABLE_AIA_URL_RETRIEVAL}
// Enable SIA URL retrieval when this bit is set in the Options
const
  CERT_CHAIN_OPTION_ENABLE_SIA_URL_RETRIEVAL                 = $4;
  {$EXTERNALSYM CERT_CHAIN_OPTION_ENABLE_SIA_URL_RETRIEVAL}


  CERT_CHAIN_CROSS_CERT_DOWNLOAD_INTERVAL_HOURS_VALUE_NAME =
    'CrossCertDownloadIntervalHours';
  {$EXTERNALSYM CERT_CHAIN_CROSS_CERT_DOWNLOAD_INTERVAL_HOURS_VALUE_NAME}
// 7 days
const
  CERT_CHAIN_CROSS_CERT_DOWNLOAD_INTERVAL_HOURS_DEFAULT      = (24 * 7);
  {$EXTERNALSYM CERT_CHAIN_CROSS_CERT_DOWNLOAD_INTERVAL_HOURS_DEFAULT}

// When not defined or zero, the CRL validity isn't extended
const
  CERT_CHAIN_CRL_VALIDITY_EXT_PERIOD_HOURS_VALUE_NAME =
    'CRLValidityExtensionPeriod';
  {$EXTERNALSYM CERT_CHAIN_CRL_VALIDITY_EXT_PERIOD_HOURS_VALUE_NAME}
// 12 hour
const
  CERT_CHAIN_CRL_VALIDITY_EXT_PERIOD_HOURS_DEFAULT           = 12;
  {$EXTERNALSYM CERT_CHAIN_CRL_VALIDITY_EXT_PERIOD_HOURS_DEFAULT}


//
// The chain engine defines the store namespace and cache partitioning for
// the Certificate Chaining infrastructure.  A default chain engine
// is defined for the process which uses all default system stores e.g.
// Root, CA, Trust, for chain building and caching.  If an application
// wishes to define its own store namespace or have its own partitioned
// cache then it can create its own chain engine.  It is advisable to create
// a chain engine at application startup and use it throughout the lifetime
// of the application in order to get optimal caching behavior
//

//type
//  HCERTCHAINENGINE = THandle;
//  {$EXTERNALSYM HCERTCHAINENGINE}

const
  HCCE_CURRENT_USER  = HCERTCHAINENGINE(nil);
  {$EXTERNALSYM HCCE_CURRENT_USER}
  HCCE_LOCAL_MACHINE = HCERTCHAINENGINE($1);
  {$EXTERNALSYM HCCE_LOCAL_MACHINE}

//
// Create a certificate chain engine.
//

//
// Configuration parameters for the certificate chain engine
//
//      hRestrictedRoot - restrict the root store (must be a subset of "Root")
//
//      hRestrictedTrust - restrict the store for CTLs
//
//      hRestrictedOther - restrict the store for certs and CRLs
//
//      cAdditionalStore, rghAdditionalStore - additional stores
//
//      hExclusiveRoot - the root store to be used exclusively.
//                       If not NULL, then the restricted  stores
//                       the system "Root" and "TrustedPeople" are not used
//
//      hExclusiveTrustedPeople - the trusted people store to be used exclusively.
//                       If not NULL, then the restricted  stores
//                       the system "Root" and "TrustedPeople" are not used
//
//      NOTE:
//
//        (hExclusiveRoot, hExclusiveTrustedPeople) are mutually exclusive
//        with (hRestrictedRoot, hRestrictedTrust, hRestrictedOther).
//        If either hExclusiveRoot or hExclusiveTrustedPeople are used,
//        then all restricted handles must be NULL and non of the system
//        "Root" and "TrustedPeople" are used.
//
//      The algorithm used to define the stores for the engine is as
//            follows:
//
//          If NULL!=hExclusiveRoot or NULL!=hExclusiveTrustedPeople
//              hRoot = hExclusiveRoot
//
//              hTrust = hWorld (defined later)
//
//              hOther = hWorld
//
//              hWorld = hRoot + hExclusiveTrustedPeople + "CA" + "My" + rghAdditionalStore
//
//          Else
//              hRoot = hRestrictedRoot or System Store "Root"
//
//              hTrust = hRestrictedTrust or hWorld (defined later)
//
//              hOther = hRestrictedOther or (hRestrictedTrust == NULL) ? hWorld :
//                       hRestrictedTrust + hWorld
//
//              hWorld = hRoot + "CA" + "My" + "Trust" + rghAdditionalStore
//          Endif
//
//      dwFlags  - flags
//
//          CERT_CHAIN_CACHE_END_CERT - information will be cached on
//                                      the end cert as well as the other
//                                      certs in the chain
//
//          CERT_CHAIN_THREAD_STORE_SYNC - use separate thread for store syncs
//                                         and related cache updates
//
//          CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL - don't hit the wire to get
//                                                URL based objects
//
//      dwUrlRetrievalTimeout - timeout for wire based URL object retrievals
//                              (milliseconds)
//
const
  CERT_CHAIN_CACHE_END_CERT                          = $00000001;
  {$EXTERNALSYM CERT_CHAIN_CACHE_END_CERT}
  CERT_CHAIN_THREAD_STORE_SYNC                       = $00000002;
  {$EXTERNALSYM CERT_CHAIN_THREAD_STORE_SYNC}
  CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL                = $00000004;
  {$EXTERNALSYM CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL}
  CERT_CHAIN_USE_LOCAL_MACHINE_STORE                 = $00000008;
  {$EXTERNALSYM CERT_CHAIN_USE_LOCAL_MACHINE_STORE}
  CERT_CHAIN_ENABLE_CACHE_AUTO_UPDATE                = $00000010;
  {$EXTERNALSYM CERT_CHAIN_ENABLE_CACHE_AUTO_UPDATE}
  CERT_CHAIN_ENABLE_SHARE_STORE                      = $00000020;
  {$EXTERNALSYM CERT_CHAIN_ENABLE_SHARE_STORE}

type
  PCertChainEngineConfig = ^TCertChainEngineConfig;
  _CERT_CHAIN_ENGINE_CONFIG = record

    cbSize: DWORD;
    hRestrictedRoot: HCERTSTORE;
    hRestrictedTrust: HCERTSTORE;
    hRestrictedOther: HCERTSTORE;
    cAdditionalStore: DWORD;
    rghAdditionalStore: ^HCERTSTORE;
    dwFlags: DWORD;
    dwUrlRetrievalTimeout: DWORD;      // milliseconds
    MaximumCachedCertificates: DWORD;
    CycleDetectionModulus: DWORD;

    hExclusiveRoot: HCERTSTORE;
    hExclusiveTrustedPeople: HCERTSTORE;

    dwExclusiveFlags: DWORD;

  end;
  {$EXTERNALSYM _CERT_CHAIN_ENGINE_CONFIG}
  CERT_CHAIN_ENGINE_CONFIG = _CERT_CHAIN_ENGINE_CONFIG;
  {$EXTERNALSYM CERT_CHAIN_ENGINE_CONFIG}
  TCertChainEngineConfig = _CERT_CHAIN_ENGINE_CONFIG;
  PCERT_CHAIN_ENGINE_CONFIG = PCertChainEngineConfig;
  {$EXTERNALSYM PCERT_CHAIN_ENGINE_CONFIG}

//
// dwExclusiveFlags
//

// CA certificates in hExclusiveRoot are also trusted. Chain building
// can terminate in a trusted CA certificate.
const
  CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG                = $00000001;
  {$EXTERNALSYM CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG}

function CertCreateCertificateChainEngine(
  pConfig: PCERT_CHAIN_ENGINE_CONFIG;
  out phChainEngine: HCERTCHAINENGINE): BOOL; winapi;
{$EXTERNALSYM CertCreateCertificateChainEngine}

//
// Free a certificate trust engine
//

procedure CertFreeCertificateChainEngine(
  hChainEngine: HCERTCHAINENGINE); winapi;
{$EXTERNALSYM CertFreeCertificateChainEngine}

//
// Resync the certificate chain engine.  This resync's the stores backing
// the engine and updates the engine caches.
//

function CertResyncCertificateChainEngine(
  hChainEngine: HCERTCHAINENGINE): BOOL; winapi;
{$EXTERNALSYM CertResyncCertificateChainEngine}

//
// When an application requests a certificate chain, the data structure
// returned is in the form of a CERT_CHAIN_CONTEXT.  This contains
// an array of CERT_SIMPLE_CHAIN where each simple chain goes from
// an end cert to a self signed cert and the chain context connects simple
// chains via trust lists.  Each simple chain contains the chain of
// certificates, summary trust information about the chain and trust information
// about each certificate element in the chain.
//

//
// Trust status bits
//

type
  PCertTrustStatus = ^TCertTrustStatus;
  _CERT_TRUST_STATUS = record

    dwErrorStatus: DWORD;
    dwInfoStatus: DWORD;

  end;
  {$EXTERNALSYM _CERT_TRUST_STATUS}
  CERT_TRUST_STATUS = _CERT_TRUST_STATUS;
  {$EXTERNALSYM CERT_TRUST_STATUS}
  TCertTrustStatus = _CERT_TRUST_STATUS;
  PCERT_TRUST_STATUS = PCertTrustStatus;
  {$EXTERNALSYM PCERT_TRUST_STATUS}

//
// The following are error status bits
//

// These can be applied to certificates and chains
const
  CERT_TRUST_NO_ERROR                            = $00000000;
  {$EXTERNALSYM CERT_TRUST_NO_ERROR}
  CERT_TRUST_IS_NOT_TIME_VALID                   = $00000001;
  {$EXTERNALSYM CERT_TRUST_IS_NOT_TIME_VALID}
  CERT_TRUST_IS_NOT_TIME_NESTED                  = $00000002;
  {$EXTERNALSYM CERT_TRUST_IS_NOT_TIME_NESTED}
  CERT_TRUST_IS_REVOKED                          = $00000004;
  {$EXTERNALSYM CERT_TRUST_IS_REVOKED}
  CERT_TRUST_IS_NOT_SIGNATURE_VALID              = $00000008;
  {$EXTERNALSYM CERT_TRUST_IS_NOT_SIGNATURE_VALID}
  CERT_TRUST_IS_NOT_VALID_FOR_USAGE              = $00000010;
  {$EXTERNALSYM CERT_TRUST_IS_NOT_VALID_FOR_USAGE}
  CERT_TRUST_IS_UNTRUSTED_ROOT                   = $00000020;
  {$EXTERNALSYM CERT_TRUST_IS_UNTRUSTED_ROOT}
  CERT_TRUST_REVOCATION_STATUS_UNKNOWN           = $00000040;
  {$EXTERNALSYM CERT_TRUST_REVOCATION_STATUS_UNKNOWN}
  CERT_TRUST_IS_CYCLIC                           = $00000080;
  {$EXTERNALSYM CERT_TRUST_IS_CYCLIC}

  CERT_TRUST_INVALID_EXTENSION                   = $00000100;
  {$EXTERNALSYM CERT_TRUST_INVALID_EXTENSION}
  CERT_TRUST_INVALID_POLICY_CONSTRAINTS          = $00000200;
  {$EXTERNALSYM CERT_TRUST_INVALID_POLICY_CONSTRAINTS}
  CERT_TRUST_INVALID_BASIC_CONSTRAINTS           = $00000400;
  {$EXTERNALSYM CERT_TRUST_INVALID_BASIC_CONSTRAINTS}
  CERT_TRUST_INVALID_NAME_CONSTRAINTS            = $00000800;
  {$EXTERNALSYM CERT_TRUST_INVALID_NAME_CONSTRAINTS}
  CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT   = $00001000;
  {$EXTERNALSYM CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT}

// In LH, this error will never be set.
const
  CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT     = $00002000;
  {$EXTERNALSYM CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT}

  CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT   = $00004000;
  {$EXTERNALSYM CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT}
  CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT        = $00008000;
  {$EXTERNALSYM CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT}

  CERT_TRUST_IS_OFFLINE_REVOCATION               = $01000000;
  {$EXTERNALSYM CERT_TRUST_IS_OFFLINE_REVOCATION}
  CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY            = $02000000;
  {$EXTERNALSYM CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY}
  CERT_TRUST_IS_EXPLICIT_DISTRUST                = $04000000;
  {$EXTERNALSYM CERT_TRUST_IS_EXPLICIT_DISTRUST}
  CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT      = $08000000;
  {$EXTERNALSYM CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT}
  CERT_TRUST_HAS_WEAK_SIGNATURE                  = $00100000;
  {$EXTERNALSYM CERT_TRUST_HAS_WEAK_SIGNATURE}

// These can be applied to chains only
const
  CERT_TRUST_IS_PARTIAL_CHAIN                    = $00010000;
  {$EXTERNALSYM CERT_TRUST_IS_PARTIAL_CHAIN}
  CERT_TRUST_CTL_IS_NOT_TIME_VALID               = $00020000;
  {$EXTERNALSYM CERT_TRUST_CTL_IS_NOT_TIME_VALID}
  CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID          = $00040000;
  {$EXTERNALSYM CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID}
  CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE          = $00080000;
  {$EXTERNALSYM CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE}

//
// The following are info status bits
//

// These can be applied to certificates only
const
  CERT_TRUST_HAS_EXACT_MATCH_ISSUER              = $00000001;
  {$EXTERNALSYM CERT_TRUST_HAS_EXACT_MATCH_ISSUER}
  CERT_TRUST_HAS_KEY_MATCH_ISSUER                = $00000002;
  {$EXTERNALSYM CERT_TRUST_HAS_KEY_MATCH_ISSUER}
  CERT_TRUST_HAS_NAME_MATCH_ISSUER               = $00000004;
  {$EXTERNALSYM CERT_TRUST_HAS_NAME_MATCH_ISSUER}
  CERT_TRUST_IS_SELF_SIGNED                      = $00000008;
  {$EXTERNALSYM CERT_TRUST_IS_SELF_SIGNED}
  CERT_TRUST_AUTO_UPDATE_CA_REVOCATION           = $00000010;
  {$EXTERNALSYM CERT_TRUST_AUTO_UPDATE_CA_REVOCATION}
  CERT_TRUST_AUTO_UPDATE_END_REVOCATION          = $00000020;
  {$EXTERNALSYM CERT_TRUST_AUTO_UPDATE_END_REVOCATION}
  CERT_TRUST_NO_OCSP_FAILOVER_TO_CRL             = $00000040;
  {$EXTERNALSYM CERT_TRUST_NO_OCSP_FAILOVER_TO_CRL}

// These can be applied to certificates and chains
const
  CERT_TRUST_HAS_PREFERRED_ISSUER                = $00000100;
  {$EXTERNALSYM CERT_TRUST_HAS_PREFERRED_ISSUER}
  CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY           = $00000200;
  {$EXTERNALSYM CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY}
  CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS          = $00000400;
  {$EXTERNALSYM CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS}
  CERT_TRUST_IS_PEER_TRUSTED                     = 400000800;
  {$EXTERNALSYM CERT_TRUST_IS_PEER_TRUSTED}
  CERT_TRUST_HAS_CRL_VALIDITY_EXTENDED           = $00001000;
  {$EXTERNALSYM CERT_TRUST_HAS_CRL_VALIDITY_EXTENDED}

// Indicates that the certificate was found in
// a store specified by hExclusiveRoot or hExclusiveTrustedPeople
const
  CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE       = $00002000;
  {$EXTERNALSYM CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE}

  CERT_TRUST_IS_CA_TRUSTED                       = $00004000;
  {$EXTERNALSYM CERT_TRUST_IS_CA_TRUSTED}

// These can be applied to chains only
const
  CERT_TRUST_IS_COMPLEX_CHAIN                    = $00010000;
  {$EXTERNALSYM CERT_TRUST_IS_COMPLEX_CHAIN}


//
// Each certificate context in a simple chain has a corresponding chain element
// in the simple chain context
//
// dwErrorStatus has CERT_TRUST_IS_REVOKED, pRevocationInfo set
// dwErrorStatus has CERT_TRUST_REVOCATION_STATUS_UNKNOWN, pRevocationInfo set

//
//         Note that the post processing revocation supported in the first
//         version only sets cbSize and dwRevocationResult.  Everything else
//         is NULL
//

//
// Revocation Information
//

type
  PCertRevocationInfo = ^TCertRevocationInfo;
  _CERT_REVOCATION_INFO = record

    cbSize: DWORD;
    dwRevocationResult: DWORD;
    pszRevocationOid: LPCSTR;
    pvOidSpecificInfo: LPVOID;

    // fHasFreshnessTime is only set if we are able to retrieve revocation
    // information. For a CRL its CurrentTime - ThisUpdate.
    fHasFreshnessTime: BOOL;
    dwFreshnessTime: DWORD;    // seconds

    // NonNULL for CRL base revocation checking
    pCrlInfo: PCertRevocationCRLInfo;

  end;
  {$EXTERNALSYM _CERT_REVOCATION_INFO}
  CERT_REVOCATION_INFO = _CERT_REVOCATION_INFO;
  {$EXTERNALSYM CERT_REVOCATION_INFO}
  TCertRevocationInfo =_CERT_REVOCATION_INFO;
  PCERT_REVOCATION_INFO = PCertRevocationInfo;
  {$EXTERNALSYM PCERT_REVOCATION_INFO}

//
// Trust List Information
//

type
  PCertTrustListInfo = ^TCertTrustListInfo;
  _CERT_TRUST_LIST_INFO = record

    cbSize: DWORD;
    pCtlEntry: PCTLEntry;
    pCtlContext: PCTLContext;

  end;
  {$EXTERNALSYM _CERT_TRUST_LIST_INFO}
  CERT_TRUST_LIST_INFO = _CERT_TRUST_LIST_INFO;
  {$EXTERNALSYM CERT_TRUST_LIST_INFO}
  TCertTrustListInfo = _CERT_TRUST_LIST_INFO;
  PCERT_TRUST_LIST_INFO = PCertTrustListInfo;
  {$EXTERNALSYM PCERT_TRUST_LIST_INFO}

//
// Chain Element
//

type
  PCertChainElement = ^TCertChainElement;
  _CERT_CHAIN_ELEMENT = record

    cbSize: DWORD;
    pCertContext: PCertContext;
    TrustStatus: TCertTrustStatus;
    pRevocationInfo: PCertRevocationInfo;

    pIssuanceUsage: PCertEnhKeyUsage;       // If NULL, any
    pApplicationUsage: PCertEnhKeyUsage;    // If NULL, any

    pwszExtendedErrorInfo: LPCWSTR;    // If NULL, none
  end;
  {$EXTERNALSYM _CERT_CHAIN_ELEMENT}
  CERT_CHAIN_ELEMENT = _CERT_CHAIN_ELEMENT;
  {$EXTERNALSYM CERT_CHAIN_ELEMENT}
  TCertChainElement = _CERT_CHAIN_ELEMENT;
  PCERT_CHAIN_ELEMENT = PCertChainElement;
  {$EXTERNALSYM PCERT_CHAIN_ELEMENT}
  PCCERT_CHAIN_ELEMENT = PCertChainElement;
  {$EXTERNALSYM PCCERT_CHAIN_ELEMENT}

//
// The simple chain is an array of chain elements and a summary trust status
// for the chain
//
// rgpElements[0] is the end certificate chain element
//
// rgpElements[cElement-1] is the self-signed "root" certificate chain element
//

type
  PCertSimpleChain = ^TCertSimpleChain;
  _CERT_SIMPLE_CHAIN = record

    cbSize: DWORD;
    TrustStatus: TCertTrustStatus;
    cElement: DWORD;
    rgpElement: ^PCertChainElement;
    pTrustListInfo: PCertTrustListInfo;

    // fHasRevocationFreshnessTime is only set if we are able to retrieve
    // revocation information for all elements checked for revocation.
    // For a CRL its CurrentTime - ThisUpdate.
    //
    // dwRevocationFreshnessTime is the largest time across all elements
    // checked.
    fHasRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;    // seconds

  end;
  {$EXTERNALSYM _CERT_SIMPLE_CHAIN}
  CERT_SIMPLE_CHAIN = _CERT_SIMPLE_CHAIN;
  {$EXTERNALSYM CERT_SIMPLE_CHAIN}
  TCertSimpleChain = _CERT_SIMPLE_CHAIN;
  PCERT_SIMPLE_CHAIN = PCertSimpleChain;
  {$EXTERNALSYM PCERT_SIMPLE_CHAIN}
  PCCERT_SIMPLE_CHAIN = PCertSimpleChain;
  {$EXTERNALSYM PCCERT_SIMPLE_CHAIN}

//
// And the chain context contains an array of simple chains and summary trust
// status for all the connected simple chains
//
// rgpChains[0] is the end certificate simple chain
//
// rgpChains[cChain-1] is the final (possibly trust list signer) chain which
// ends in a certificate which is contained in the root store
//

type
  PPCertChainContext = ^PCertChainContext;
  PCertChainContext = ^TCertChainContext;
  _CERT_CHAIN_CONTEXT = record
    cbSize: DWORD;
    TrustStatus: TCertTrustStatus;
    cChain: DWORD;
    rgpChain: ^PCertSimpleChain;

    // Following is returned when CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS
    // is set in dwFlags
    cLowerQualityChainContext: DWORD;
    rgpLowerQualityChainContext: ^PCertChainContext;

    // fHasRevocationFreshnessTime is only set if we are able to retrieve
    // revocation information for all elements checked for revocation.
    // For a CRL its CurrentTime - ThisUpdate.
    //
    // dwRevocationFreshnessTime is the largest time across all elements
    // checked.
    fHasRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;    // seconds

    // Flags passed when created via CertGetCertificateChain
    dwCreateFlags: DWORD;

    // Following is updated with unique Id when the chain context is logged.
    ChainId: TGUID;
  end;
  {$EXTERNALSYM _CERT_CHAIN_CONTEXT}
  CERT_CHAIN_CONTEXT = _CERT_CHAIN_CONTEXT;
  {$EXTERNALSYM CERT_CHAIN_CONTEXT}
  TCertChainContext = _CERT_CHAIN_CONTEXT;
  PCERT_CHAIN_CONTEXT = PCertChainContext;
  {$EXTERNALSYM PCERT_CHAIN_CONTEXT}
  PCCERT_CHAIN_CONTEXT = PCertChainContext;
  {$EXTERNALSYM PCCERT_CHAIN_CONTEXT}

//
// When building a chain, the there are various parameters used for finding
// issuing certificates and trust lists.  They are identified in the
// following structure
//

// Default usage match type is AND with value zero
const
  USAGE_MATCH_TYPE_AND = $00000000;
  {$EXTERNALSYM USAGE_MATCH_TYPE_AND}
  USAGE_MATCH_TYPE_OR  = $00000001;
  {$EXTERNALSYM USAGE_MATCH_TYPE_OR}

type
  PCertUsageMatch = ^TCertUsageMatch;
  _CERT_USAGE_MATCH = record

    dwType: DWORD;
    Usage: TCertEnhKeyUsage;

  end;
  {$EXTERNALSYM _CERT_USAGE_MATCH}
  CERT_USAGE_MATCH = _CERT_USAGE_MATCH;
  {$EXTERNALSYM CERT_USAGE_MATCH}
  TCertUsageMatch = _CERT_USAGE_MATCH;
  PCERT_USAGE_MATCH = PCertUsageMatch;
  {$EXTERNALSYM PCERT_USAGE_MATCH}

type
  PCTLUsageMatch = ^TCTLUsageMatch;
  _CTL_USAGE_MATCH = record

    dwType: DWORD;
    Usage: TCTLUsage;

  end;
  {$EXTERNALSYM _CTL_USAGE_MATCH}
  CTL_USAGE_MATCH = _CTL_USAGE_MATCH;
  {$EXTERNALSYM CTL_USAGE_MATCH}
  TCTLUsageMatch = _CTL_USAGE_MATCH;
  PCTL_USAGE_MATCH = PCTLUsageMatch;
  {$EXTERNALSYM PCTL_USAGE_MATCH}

type
  PCertChainPara = ^TCertChainPara;
  _CERT_CHAIN_PARA = record

    cbSize: DWORD;
    RequestedUsage: TCertUsageMatch;

//{$IFDEF CERT_CHAIN_PARA_HAS_EXTRA_FIELDS}

    // Note, if you #define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS, then, you
    // must zero all unused fields in this data structure.
    // More fields could be added in a future release.

    RequestedIssuancePolicy: TCertUsageMatch;
    dwUrlRetrievalTimeout: DWORD;     // milliseconds
    fCheckRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD; // seconds

    // If nonNULL, any cached information before this time is considered
    // time invalid and forces a wire retrieval. When set overrides
    // the registry configuration CacheResync time.
    pftCacheResync: PFileTime;

    //
    // The following is set to check for Strong Signatures
    //
    pStrongSignPara: PCertStrongSignPara;

    //
    // By default the public key in the end certificate is checked.
    // CERT_CHAIN_STRONG_SIGN_DISABLE_END_CHECK_FLAG can be
    // set in the following flags to not check if the end certificate's public
    // key length is strong.
    //
    dwStrongSignFlags: DWORD;

//{$ENDIF}

  end;
  {$EXTERNALSYM _CERT_CHAIN_PARA}
  CERT_CHAIN_PARA = _CERT_CHAIN_PARA;
  {$EXTERNALSYM CERT_CHAIN_PARA}
  TCertChainPara = _CERT_CHAIN_PARA;
  PCERT_CHAIN_PARA = PCertChainPara;
  {$EXTERNALSYM PCERT_CHAIN_PARA}

const
  CERT_CHAIN_STRONG_SIGN_DISABLE_END_CHECK_FLAG  = $00000001;
  {$EXTERNALSYM CERT_CHAIN_STRONG_SIGN_DISABLE_END_CHECK_FLAG}

//
// The following API is used for retrieving certificate chains
//
// Parameters:
//
//      hChainEngine     - the chain engine (namespace and cache) to use, NULL
//                         mean use the default chain engine
//
//      pCertContext     - the context we are retrieving the chain for, it
//                         will be the zero index element in the chain
//
//      pTime            - the point in time that we want the chain validated
//                         for.  Note that the time does not affect trust list,
//                         revocation, or root store checking.  NULL means use
//                         the current system time
//
//      hAdditionalStore - additional store to use when looking up objects
//
//      pChainPara       - parameters for chain building
//
//      dwFlags          - flags such as should revocation checking be done
//                         on the chain?
//
//      pvReserved       - reserved parameter, must be NULL
//
//      ppChainContext   - chain context returned
//

// CERT_CHAIN_CACHE_END_CERT can be used here as well
// Revocation flags are in the high nibble
const
  CERT_CHAIN_REVOCATION_CHECK_END_CERT           = $10000000;
  {$EXTERNALSYM CERT_CHAIN_REVOCATION_CHECK_END_CERT}
  CERT_CHAIN_REVOCATION_CHECK_CHAIN              = $20000000;
  {$EXTERNALSYM CERT_CHAIN_REVOCATION_CHECK_CHAIN}
  CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $40000000;
  {$EXTERNALSYM CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT}
  CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY         = $80000000;
  {$EXTERNALSYM CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY}

// By default, the dwUrlRetrievalTimeout in pChainPara is the timeout used
// for each revocation URL wire retrieval. When the following flag is set,
// dwUrlRetrievalTimeout is the accumulative timeout across all
// revocation URL wire retrievals.
const
  CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT     = $08000000;
  {$EXTERNALSYM CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT}


// Revocation checking for an independent OCSP signer certificate.
//
// The above revocation flags indicate if just the signer certificate or all
// the certificates in the chain, excluding the root should be checked
// for revocation. If the signer certificate contains the
// szOID_PKIX_OCSP_NOCHECK extension, then, revocation checking is skipped
// for the leaf signer certificate. Both OCSP and CRL checking are allowed.
// However, recursive, independent OCSP signer certs are disabled.
const
  CERT_CHAIN_REVOCATION_CHECK_OCSP_CERT          = $04000000;
  {$EXTERNALSYM CERT_CHAIN_REVOCATION_CHECK_OCSP_CERT}


// First pass determines highest quality based upon:
//  - Chain signature valid (higest quality bit of this set)
//  - Complete chain
//  - Trusted root          (lowestest quality bit of this set)
// By default, second pass only considers paths >= highest first pass quality
const
  CERT_CHAIN_DISABLE_PASS1_QUALITY_FILTERING = $00000040;
  {$EXTERNALSYM CERT_CHAIN_DISABLE_PASS1_QUALITY_FILTERING}

  CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS   = $00000080;
  {$EXTERNALSYM CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS}

  CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE   = $00000100;
  {$EXTERNALSYM CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE}


// When this flag is set, pTime will be used as the timestamp time.
// pTime will be used to determine if the end certificate was valid at this
// time. Revocation checking will be relative to pTime.
// In addition, current time will also be used
// to determine if the certificate is still time valid. All remaining
// CA and root certificates will be checked using current time and not pTime.
//
// This flag was added 4/5/01 in WXP.
const
  CERT_CHAIN_TIMESTAMP_TIME                  = $00000200;
  {$EXTERNALSYM CERT_CHAIN_TIMESTAMP_TIME}


// When this flag is set, "My" certificates having a private key or end
// entity certificates in the "TrustedPeople" store are trusted without
// doing any chain building. Neither the CERT_TRUST_IS_PARTIAL_CHAIN or
// CERT_TRUST_IS_UNTRUSTED_ROOT dwErrorStatus bits will be set for
// such certificates.
//
// This flag was added 6/9/03 in LH.
const
  CERT_CHAIN_ENABLE_PEER_TRUST               = $00000400;
  {$EXTERNALSYM CERT_CHAIN_ENABLE_PEER_TRUST}

// When this flag is set, "My" certificates aren't considered for
// PEER_TRUST.
//
// This flag was added 11/12/04 in LH.
//
// On 8-05-05 changed to never consider "My" certificates for PEER_TRUST.
const
  CERT_CHAIN_DISABLE_MY_PEER_TRUST           = $00000800;
  {$EXTERNALSYM CERT_CHAIN_DISABLE_MY_PEER_TRUST}


// The following flag should be set to explicitly disable MD2 or MD4 for
// any requested EKU. By default, MD2 or MD4 isn't disabled for none,
// code signing, driver signing or time stamping requested EKUs.
const
  CERT_CHAIN_DISABLE_MD2_MD4                 = $00001000;
  {$EXTERNALSYM CERT_CHAIN_DISABLE_MD2_MD4}

function CertGetCertificateChain(
  hChainEngine: HCERTCHAINENGINE;
  pCertContext: PCertContext;
  pTime: PFileTime;
  hAdditionalStore: HCERTSTORE;
  pChainPara: PCertChainPara;
  dwFlags: DWORD;
  pvReserved: LPVOID;
  out ppChainContext: PCertChainContext): BOOL; winapi;
{$EXTERNALSYM CertGetCertificateChain}

//
// Free a certificate chain
//

procedure CertFreeCertificateChain(
  pChainContext: PCertChainContext); winapi;
{$EXTERNALSYM CertFreeCertificateChain}

//
// Duplicate (add a reference to) a certificate chain
//

function CertDuplicateCertificateChain(
  pChainContext: PCertChainContext): PCertChainContext; winapi;
{$EXTERNALSYM CertDuplicateCertificateChain}

//+-------------------------------------------------------------------------
//  This data structure is optionally pointed to by the pChainPara field
//  in the CERT_REVOCATION_PARA and CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO
//  data structures. CertGetCertificateChain() populates when it calls
//  the CertVerifyRevocation() API.
//--------------------------------------------------------------------------
//type
//  _CERT_REVOCATION_CHAIN_PARA = record
//    cbSize: DWORD;
//    hChainEngine: HCERTCHAINENGINE;
//    hAdditionalStore: HCERTSTORE;
//    dwChainFlags: DWORD;
//    dwUrlRetrievalTimeout: DWORD;     // milliseconds
//    pftCurrentTime: PFileTime;
//    pftCacheResync: PFileTime;

    // Max size of the URL object to download, in bytes.
    // 0 value means no limit.
//    cbMaxUrlRetrievalByteCount: DWORD;
//  end;
//  {$EXTERNALSYM _CERT_REVOCATION_CHAIN_PARA}


//
// Specific Revocation Type OID and structure definitions
//

//
// CRL Revocation OID
//
const
  REVOCATION_OID_CRL_REVOCATION = LPCSTR(1);
  {$EXTERNALSYM REVOCATION_OID_CRL_REVOCATION}

//
// For the CRL revocation OID the pvRevocationPara is NULL
//

//
// CRL Revocation Info
//
type
  PCRLRevocationInfo = ^TCRLRevocationInfo;
  _CRL_REVOCATION_INFO = record

    pCrlEntry: PCRLEntry;
    pCrlContext: PCRLContext;
    pCrlIssuerChain: PCertChainContext;

  end;
  {$EXTERNALSYM _CRL_REVOCATION_INFO}
  CRL_REVOCATION_INFO = _CRL_REVOCATION_INFO;
  {$EXTERNALSYM CRL_REVOCATION_INFO}
  TCRLRevocationInfo = _CRL_REVOCATION_INFO;
  PCRL_REVOCATION_INFO = PCRLRevocationInfo;
  {$EXTERNALSYM PCRL_REVOCATION_INFO}

//+-------------------------------------------------------------------------
//  Find the first or next certificate chain context in the store.
//
//  The chain context is found according to the dwFindFlags, dwFindType and
//  its pvFindPara. See below for a list of the find types and its parameters.
//
//  If the first or next chain context isn't found, NULL is returned.
//  Otherwise, a pointer to a read only CERT_CHAIN_CONTEXT is returned.
//  CERT_CHAIN_CONTEXT must be freed by calling CertFreeCertificateChain
//  or is freed when passed as the
//  pPrevChainContext on a subsequent call. CertDuplicateCertificateChain
//  can be called to make a duplicate.
//
//  pPrevChainContext MUST BE NULL on the first
//  call to find the chain context. To find the next chain context, the
//  pPrevChainContext is set to the CERT_CHAIN_CONTEXT returned by a previous
//  call.
//
//  NOTE: a NON-NULL pPrevChainContext is always CertFreeCertificateChain'ed by
//  this function, even for an error.
//--------------------------------------------------------------------------
function CertFindChainInStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  dwFindFlags: DWORD;
  dwFindType: DWORD;
  pvFindPara: Pointer;
  pPrevChainContext: PCertChainContext): PCertChainContext; winapi;
{$EXTERNALSYM CertFindChainInStore}

const
  CERT_CHAIN_FIND_BY_ISSUER      = 1;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER}


//+-------------------------------------------------------------------------
//  CERT_CHAIN_FIND_BY_ISSUER
//
//  Find a certificate chain having a private key for the end certificate and
//  matching one of the given issuer names. A matching dwKeySpec and
//  enhanced key usage can also be specified. Additionally a callback can
//  be provided for even more caller provided filtering before building the
//  chain.
//
//  By default, only the issuers in the first simple chain are compared
//  for a name match. CERT_CHAIN_FIND_BY_ISSUER_COMPLEX_CHAIN_FLAG can
//  be set in dwFindFlags to match issuers in all the simple chains.
//
//  CERT_CHAIN_FIND_BY_ISSUER_NO_KEY_FLAG can be set in dwFindFlags to
//  not check if the end certificate has a private key.
//
//  CERT_CHAIN_FIND_BY_ISSUER_COMPARE_KEY_FLAG can be set in dwFindFlags
//  to compare the public key in the end certificate with the crypto
//  provider's public key. The dwAcquirePrivateKeyFlags can be set
//  in CERT_CHAIN_FIND_BY_ISSUER_PARA to enable caching of the private key's
//  HKEY returned by the CSP.
//
//  If dwCertEncodingType == 0, defaults to X509_ASN_ENCODING for the
//  array of encoded issuer names.
//
//  By default, the hCertStore passed to CertFindChainInStore, is passed
//  as an additional store to CertGetCertificateChain.
//  CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG can be set in dwFindFlags
//  to improve performance by only searching the cached system stores
//  (root, my, ca, trust) to find the issuer certificates. If you are doing
//  a find in the "my" system store, than, this flag should be set to
//  improve performance.
//
//  Setting CERT_CHAIN_FIND_BY_ISSUER_LOCAL_MACHINE_FLAG in dwFindFlags
//  restricts CertGetCertificateChain to search the Local Machine
//  cached system stores instead of the Current User's.
//
//  Setting CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG in dwFindFlags
//  restricts CertGetCertificateChain to only search the URL cache
//  and not hit the wire.
//--------------------------------------------------------------------------

// Returns FALSE to skip this certificate. Otherwise, returns TRUE to
// build a chain for this certificate.
type
  PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK = function(
    pCert: PCertContext;
    pvFindArg: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK}
  TFnCertChainFindByIssuerCallback = PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK;

type
  PCertChainFindIssuerPara = ^TCertChainFindIssuerPara;
  _CERT_CHAIN_FIND_BY_ISSUER_PARA = record
    cbSize: DWORD;

    // If pszUsageIdentifier == NULL, matches any usage.
    pszUsageIdentifier: LPCSTR;

    // If dwKeySpec == 0, matches any KeySpec
    dwKeySpec: DWORD;

    // When CERT_CHAIN_FIND_BY_ISSUER_COMPARE_KEY_FLAG is set in dwFindFlags,
    // CryptAcquireCertificatePrivateKey is called to do the public key
    // comparison. The following flags can be set to enable caching
    // of the acquired private key or suppress CSP UI. See the API for more
    // details on these flags.
    dwAcquirePrivateKeyFlags: DWORD;

    // Pointer to an array of X509, ASN.1 encoded issuer name blobs. If
    // cIssuer == 0, matches any issuer
    cIssuer: DWORD;
    rgIssuer: PCertNameBlob;

    // If NULL or Callback returns TRUE, builds the chain for the end
    // certificate having a private key with the specified KeySpec and
    // enhanced key usage.
    pfnFindCallback: TFnCertChainFindByIssuerCallback;
    pvFindArg: Pointer;

//{$IFDEF CERT_CHAIN_FIND_BY_ISSUER_PARA_HAS_EXTRA_FIELDS}
    // Note, if you #define CERT_CHAIN_FIND_BY_ISSUER_PARA_HAS_EXTRA_FIELDS,
    // then, you must zero all unused fields in this data structure.
    // More fields could be added in a future release.

    // If the following pointers are nonNull, returns the index of the
    // matching issuer certificate, which is at:
    // pChainContext->
    //      rgpChain[*pdwIssuerChainIndex]->rgpElement[*pdwIssuerElementIndex].
    //
    // The issuer name blob is compared against the Issuer field in the
    // certificate. The *pdwIssuerElementIndex is set to the index of this
    // subject certificate + 1. Therefore, its possible for a partial chain or
    // a self signed certificate matching the name blob, where
    // *pdwIssuerElementIndex points past the last certificate in the chain.
    //
    // Note, not updated if the above cIssuer == 0.
    pdwIssuerChainIndex: PDWORD;
    pdwIssuerElementIndex: PDWORD;
//{$ENDIF}
  end;
  {$EXTERNALSYM _CERT_CHAIN_FIND_BY_ISSUER_PARA}
  CERT_CHAIN_FIND_ISSUER_PARA = _CERT_CHAIN_FIND_BY_ISSUER_PARA;
  {$EXTERNALSYM CERT_CHAIN_FIND_ISSUER_PARA}
  TCertChainFindIssuerPara = _CERT_CHAIN_FIND_BY_ISSUER_PARA;
  PCERT_CHAIN_FIND_ISSUER_PARA = PCertChainFindIssuerPara;
  {$EXTERNALSYM PCERT_CHAIN_FIND_ISSUER_PARA}

  CERT_CHAIN_FIND_BY_ISSUER_PARA = _CERT_CHAIN_FIND_BY_ISSUER_PARA;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER_PARA}
  PCERT_CHAIN_FIND_BY_ISSUER_PARA = PCertChainFindIssuerPara;
  {$EXTERNALSYM PCERT_CHAIN_FIND_BY_ISSUER_PARA}

// The following dwFindFlags can be set for CERT_CHAIN_FIND_BY_ISSUER

// If set, compares the public key in the end certificate with the crypto
// provider's public key. This comparison is the last check made on the
// build chain.
const
  CERT_CHAIN_FIND_BY_ISSUER_COMPARE_KEY_FLAG         = $0001;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER_COMPARE_KEY_FLAG}

// If not set, only checks the first simple chain for an issuer name match.
// When set, also checks second and subsequent simple chains.
const
  CERT_CHAIN_FIND_BY_ISSUER_COMPLEX_CHAIN_FLAG       = $0002;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER_COMPLEX_CHAIN_FLAG}

// If set, CertGetCertificateChain only searches the URL cache and
// doesn't hit the wire.
const
  CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG      = $0004;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG}

// If set, CertGetCertificateChain only opens the Local Machine
// certificate stores instead of the Current User's.
const
  CERT_CHAIN_FIND_BY_ISSUER_LOCAL_MACHINE_FLAG       = $0008;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER_LOCAL_MACHINE_FLAG}

// If set, no check is made to see if the end certificate has a private
// key associated with it.
const
  CERT_CHAIN_FIND_BY_ISSUER_NO_KEY_FLAG              = $4000;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER_NO_KEY_FLAG}


// By default, the hCertStore passed to CertFindChainInStore, is passed
// as the additional store to CertGetCertificateChain. This flag can be
// set to improve performance by only searching the cached system stores
// (root, my, ca, trust) to find the issuer certificates. If not set, then,
// the hCertStore is always searched in addition to the cached system
// stores.
const
  CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG          = $8000;
  {$EXTERNALSYM CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG}


//+=========================================================================
//  Certificate Chain Policy Data Structures and APIs
//==========================================================================
type
  PCertChainPolicyPara = ^TCertChainPolicyPara;
  _CERT_CHAIN_POLICY_PARA = record
    cbSize: DWORD;
    dwFlags: DWORD;
    pvExtraPolicyPara: Pointer;     // pszPolicyOID specific
  end;
  {$EXTERNALSYM _CERT_CHAIN_POLICY_PARA}
  CERT_CHAIN_POLICY_PARA = _CERT_CHAIN_POLICY_PARA;
  {$EXTERNALSYM CERT_CHAIN_POLICY_PARA}
  TCertChainPolicyPara = _CERT_CHAIN_POLICY_PARA;
  PCERT_CHAIN_POLICY_PARA = PCertChainPolicyPara;
  {$EXTERNALSYM PCERT_CHAIN_POLICY_PARA}

// If both lChainIndex and lElementIndex are set to -1, the dwError applies
// to the whole chain context. If only lElementIndex is set to -1, the
// dwError applies to the lChainIndex'ed chain. Otherwise, the dwError applies
// to the certificate element at
// pChainContext->rgpChain[lChainIndex]->rgpElement[lElementIndex].
type
  PCertChainPolicyStatus = ^TCertChainPolicyStatus;
  _CERT_CHAIN_POLICY_STATUS = record
    cbSize: DWORD;
    dwError: DWORD;
    lChainIndex: LONG;
    lElementIndex: LONG;
    pvExtraPolicyStatus: Pointer;   // pszPolicyOID specific
  end;
  {$EXTERNALSYM _CERT_CHAIN_POLICY_STATUS}
  CERT_CHAIN_POLICY_STATUS = _CERT_CHAIN_POLICY_STATUS;
  {$EXTERNALSYM CERT_CHAIN_POLICY_STATUS}
  TCertChainPolicyStatus = _CERT_CHAIN_POLICY_STATUS;
  PCERT_CHAIN_POLICY_STATUS = PCertChainPolicyStatus;
  {$EXTERNALSYM PCERT_CHAIN_POLICY_STATUS}

// Common chain policy flags
const
  CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG               = $00000001;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG}
  CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG           = $00000002;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG}
  CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG              = $00000004;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG}
  CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG    = $00000008;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG}

  CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS = (
    CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG                or
    CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG            or
    CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG
    );
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS}


  CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG                    = $00000010;
  {$EXTERNALSYM CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG}
  CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG                  = $00000020;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG }
  CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG                 = $00000040;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG}
  CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG               = $00000080;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG}

  CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG              = $00000100;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG}
  CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG       = $00000200;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG}
  CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG               = $00000400;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG}
  CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG             = $00000800;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG}

  CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS = (
    CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG         or
    CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG  or
    CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG          or
    CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG
    );
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS}

  CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG                      = $00008000;
  {$EXTERNALSYM CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG}
  CERT_CHAIN_POLICY_TRUST_TESTROOT_FLAG                      = $00004000;
  {$EXTERNALSYM CERT_CHAIN_POLICY_TRUST_TESTROOT_FLAG}

  CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT_FLAG   = $00002000;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT_FLAG}
  CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG                   = $00001000;
  {$EXTERNALSYM CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG}


//+-------------------------------------------------------------------------
//  Verify that the certificate chain satisfies the specified policy
//  requirements. If we were able to verify the chain policy, TRUE is returned
//  and the dwError field of the pPolicyStatus is updated. A dwError of 0
//  (ERROR_SUCCESS, S_OK) indicates the chain satisfies the specified policy.
//
//  If dwError applies to the entire chain context, both lChainIndex and
//  lElementIndex are set to -1. If dwError applies to a simple chain,
//  lElementIndex is set to -1 and lChainIndex is set to the index of the
//  first offending chain having the error. If dwError applies to a
//  certificate element, lChainIndex and lElementIndex are updated to
//  index the first offending certificate having the error, where, the
//  the certificate element is at:
//      pChainContext->rgpChain[lChainIndex]->rgpElement[lElementIndex].
//
//  The dwFlags in pPolicyPara can be set to change the default policy checking
//  behaviour. In addition, policy specific parameters can be passed in
//  the pvExtraPolicyPara field of pPolicyPara.
//
//  In addition to returning dwError, in pPolicyStatus, policy OID specific
//  extra status may be returned via pvExtraPolicyStatus.
//--------------------------------------------------------------------------
function CertVerifyCertificateChainPolicy(
  pszPolicyOID: LPCSTR;
  pChainContext: PCertChainContext;
  pPolicyPara: PCertChainPolicyPara;
  pPolicyStatus: PCertChainPolicyStatus): BOOL; winapi;
{$EXTERNALSYM CertVerifyCertificateChainPolicy}

// Predefined OID Function Names
const
  CRYPT_OID_VERIFY_CERTIFICATE_CHAIN_POLICY_FUNC =
    'CertDllVerifyCertificateChainPolicy';
  {$EXTERNALSYM CRYPT_OID_VERIFY_CERTIFICATE_CHAIN_POLICY_FUNC}

// CertDllVerifyCertificateChainPolicy has same function signature as
// CertVerifyCertificateChainPolicy.

//+-------------------------------------------------------------------------
//  Predefined verify chain policies
//--------------------------------------------------------------------------
const
  CERT_CHAIN_POLICY_BASE              = LPCSTR(1);
  {$EXTERNALSYM CERT_CHAIN_POLICY_BASE}
  CERT_CHAIN_POLICY_AUTHENTICODE      = LPCSTR(2);
  {$EXTERNALSYM CERT_CHAIN_POLICY_AUTHENTICODE}
  CERT_CHAIN_POLICY_AUTHENTICODE_TS   = LPCSTR(3);
  {$EXTERNALSYM CERT_CHAIN_POLICY_AUTHENTICODE_TS}
  CERT_CHAIN_POLICY_SSL               = LPCSTR(4);
  {$EXTERNALSYM CERT_CHAIN_POLICY_SSL}
  CERT_CHAIN_POLICY_BASIC_CONSTRAINTS = LPCSTR(5);
  {$EXTERNALSYM CERT_CHAIN_POLICY_BASIC_CONSTRAINTS}
  CERT_CHAIN_POLICY_NT_AUTH           = LPCSTR(6);
  {$EXTERNALSYM CERT_CHAIN_POLICY_NT_AUTH}
  CERT_CHAIN_POLICY_MICROSOFT_ROOT    = LPCSTR(7);
  {$EXTERNALSYM CERT_CHAIN_POLICY_MICROSOFT_ROOT}
  CERT_CHAIN_POLICY_EV                = LPCSTR(8);
  {$EXTERNALSYM CERT_CHAIN_POLICY_EV}

//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_BASE
//
//  Implements the base chain policy verification checks. dwFlags can
//  be set in pPolicyPara to alter the default policy checking behaviour.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_AUTHENTICODE
//
//  Implements the Authenticode chain policy verification checks.
//
//  pvExtraPolicyPara may optionally be set to point to the following
//  AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA.
//
//  pvExtraPolicyStatus may optionally be set to point to the following
//  AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS.
//--------------------------------------------------------------------------

// dwRegPolicySettings are defined in wintrust.h
type
  PAuthenticodeExtraCertChainPolicyPara = ^TAuthenticodeExtraCertChainPolicyPara;
  _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA = record
    cbSize: DWORD;
    dwRegPolicySettings: DWORD;
    pSignerInfo: PCMsgSignerInfo;                // optional
  end;
  {$EXTERNALSYM _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA}
  AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA = _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA;
  {$EXTERNALSYM AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA}
  TAuthenticodeExtraCertChainPolicyPara = _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA;
  PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA = PAuthenticodeExtraCertChainPolicyPara;
  {$EXTERNALSYM PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA}

type
  PAuthenticodeExtraCertChainPolicyStatus = ^TAuthenticodeExtraCertChainPolicyStatus;
  _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS = record
    cbSize: DWORD;
    fCommercial: BOOL;        // obtained from signer statement
  end;
  {$EXTERNALSYM _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS}
  AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS = _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS;
  {$EXTERNALSYM AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS}
  TAuthenticodeExtraCertChainPolicyStatus = _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS;
  PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS = PAuthenticodeExtraCertChainPolicyStatus;
  {$EXTERNALSYM PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS}

//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_AUTHENTICODE_TS
//
//  Implements the Authenticode Time Stamp chain policy verification checks.
//
//  pvExtraPolicyPara may optionally be set to point to the following
//  AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA.
//
//  pvExtraPolicyStatus isn't used and must be set to NULL.
//--------------------------------------------------------------------------

// dwRegPolicySettings are defined in wintrust.h
type
  PAuthenticodeTsExtraCertChainPolicyPara = ^TAuthenticodeTsExtraCertChainPolicyPara;
  _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA = record
    cbSize: DWORD;
    dwRegPolicySettings: DWORD;
    fCommercial: BOOL;
  end;
  {$EXTERNALSYM _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA}
  AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA = _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA;
  {$EXTERNALSYM AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA}
  TAuthenticodeTsExtraCertChainPolicyPara = _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA;
  PAUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA = PAuthenticodeTsExtraCertChainPolicyPara;
  {$EXTERNALSYM PAUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA}


//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_SSL
//
//  Implements the SSL client/server chain policy verification checks.
//
//  pvExtraPolicyPara may optionally be set to point to the following
//  SSL_EXTRA_CERT_CHAIN_POLICY_PARA data structure
//--------------------------------------------------------------------------

// fdwChecks flags are defined in wininet.h
const
  AUTHTYPE_CLIENT        = 1;
  {$EXTERNALSYM AUTHTYPE_CLIENT}
  AUTHTYPE_SERVER        = 2;
  {$EXTERNALSYM AUTHTYPE_SERVER}

type
  PHTTPSPolicyCallbackData = ^THTTPSPolicyCallbackData;
  {$EXTERNALSYM PHTTPSPolicyCallbackData}
  _HTTPSPolicyCallbackData = record
    case Integer of
    0: (cbStruct: DWORD);       // sizeof(HTTPSPolicyCallbackData);
    1: (cbSize: DWORD;         // sizeof(HTTPSPolicyCallbackData);

    dwAuthType: DWORD;

    fdwChecks: DWORD;

    pwszServerName: ^WCHAR); // used to check against CN=xxxx

  end;
  {$EXTERNALSYM _HTTPSPolicyCallbackData}
  HTTPSPolicyCallbackData = _HTTPSPolicyCallbackData;
  {$EXTERNALSYM HTTPSPolicyCallbackData}
  THTTPSPolicyCallbackData = _HTTPSPolicyCallbackData;

  PSslExtraCertChainPolicyPara = PHTTPSPolicyCallbackData;
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA = _HTTPSPolicyCallbackData;
  {$EXTERNALSYM SSL_EXTRA_CERT_CHAIN_POLICY_PARA}
  TSslExtraCertChainPolicyPara = _HTTPSPolicyCallbackData;
  PSSL_EXTRA_CERT_CHAIN_POLICY_PARA = PSslExtraCertChainPolicyPara;
  {$EXTERNALSYM PSSL_EXTRA_CERT_CHAIN_POLICY_PARA}

//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_BASIC_CONSTRAINTS
//
//  Implements the basic constraints chain policy.
//
//  Iterates through all the certificates in the chain checking for either
//  a szOID_BASIC_CONSTRAINTS or a szOID_BASIC_CONSTRAINTS2 extension. If
//  neither extension is present, the certificate is assumed to have
//  valid policy. Otherwise, for the first certificate element, checks if
//  it matches the expected CA_FLAG or END_ENTITY_FLAG specified in
//  pPolicyPara->dwFlags. If neither or both flags are set, then, the first
//  element can be either a CA or END_ENTITY. All other elements must be
//  a CA. If the PathLenConstraint is present in the extension, its
//  checked.
//
//  The first elements in the remaining simple chains (ie, the certificate
//  used to sign the CTL) are checked to be an END_ENTITY.
//
//  If this verification fails, dwError will be set to
//  TRUST_E_BASIC_CONSTRAINTS.
//--------------------------------------------------------------------------
const
  BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_CA_FLAG         = $80000000;
  {$EXTERNALSYM BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_CA_FLAG}
  BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_END_ENTITY_FLAG = $40000000;
  {$EXTERNALSYM BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_END_ENTITY_FLAG}

//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_NT_AUTH
//
//  Implements the NT Authentication chain policy.
//
//  The NT Authentication chain policy consists of 3 distinct chain
//  verifications in the following order:
//      [1] CERT_CHAIN_POLICY_BASE - Implements the base chain policy
//          verification checks. The LOWORD of dwFlags can be set in
//          pPolicyPara to alter the default policy checking behaviour. See
//          CERT_CHAIN_POLICY_BASE for more details.
//
//      [2] CERT_CHAIN_POLICY_BASIC_CONSTRAINTS - Implements the basic
//          constraints chain policy. The HIWORD of dwFlags can be set
//          to specify if the first element must be either a CA or END_ENTITY.
//          See CERT_CHAIN_POLICY_BASIC_CONSTRAINTS for more details.
//
//      [3] Checks if the second element in the chain, the CA that issued
//          the end certificate, is a trusted CA for NT
//          Authentication. A CA is considered to be trusted if it exists in
//          the "NTAuth" system registry store found in the
//          CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE store location.
//          If this verification fails, whereby the CA isn't trusted,
//          dwError is set to CERT_E_UNTRUSTEDCA.
//
//          If CERT_PROT_ROOT_DISABLE_NT_AUTH_REQUIRED_FLAG is set
//          in the "Flags" value of the HKLM policy "ProtectedRoots" subkey
//          defined by CERT_PROT_ROOT_FLAGS_REGPATH, then,
//          if the above check fails, checks if the chain
//          has CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS set in dwInfoStatus. This
//          will only be set if there was a valid name constraint for all
//          name spaces including UPN. If the chain doesn't have this info
//          status set, dwError is set to CERT_E_UNTRUSTEDCA.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_MICROSOFT_ROOT
//
//  Checks if the last element of the first simple chain contains a
//  Microsoft root public key. If it doesn't contain a Microsoft root
//  public key, dwError is set to CERT_E_UNTRUSTEDROOT.
//
//  pPolicyPara is optional. However,
//  MICROSOFT_ROOT_CERT_CHAIN_POLICY_ENABLE_TEST_ROOT_FLAG can be set in
//  the dwFlags in pPolicyPara to also check for the Microsoft Test Roots.
//
//  MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG can be set
//  in the dwFlags in pPolicyPara to check for the Microsoft root for
//  application signing instead of the Microsoft product root. This flag
//  explicitly checks for the application root only and cannot be combined
//  with the test root flag.
//
//  pvExtraPolicyPara and pvExtraPolicyStatus aren't used and must be set
//  to NULL.
//--------------------------------------------------------------------------
const
  MICROSOFT_ROOT_CERT_CHAIN_POLICY_ENABLE_TEST_ROOT_FLAG       = $00010000;
  {$EXTERNALSYM MICROSOFT_ROOT_CERT_CHAIN_POLICY_ENABLE_TEST_ROOT_FLAG}
  MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG = $00020000;
  {$EXTERNALSYM MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG}

//+-------------------------------------------------------------------------
//  CERT_CHAIN_POLICY_EV
//
//  Verify the issuance policy in the end certificate of the first simple
//  chain matches with the root certificate EV policy.
//
//  pvExtraPolicyPara may optionally be set to point to the following
//  EV_EXTRA_CERT_CHAIN_POLICY_PARA. The dwRootProgramQualifierFlags member
//  can be set to one or more of the CERT_ROOT_PROGRAM_FLAG_* to define
//  which of the EV policy qualifier bits are required for validation.
//
//  pvExtraPolicyStatus may optionally be set to point to the following
//  EV_EXTRA_CERT_CHAIN_POLICY_STATUS. The fQualifiers member will contain
//  a combination of CERT_ROOT_PROGRAM_FLAG_* flags.
//--------------------------------------------------------------------------

type
  PEvExtraCertChainPolicyPara = ^TEvExtraCertChainPolicyPara;
  _EV_EXTRA_CERT_CHAIN_POLICY_PARA = record
    cbSize: DWORD;
    dwRootProgramQualifierFlags: DWORD;
  end;
  {$EXTERNALSYM _EV_EXTRA_CERT_CHAIN_POLICY_PARA}
  EV_EXTRA_CERT_CHAIN_POLICY_PARA = _EV_EXTRA_CERT_CHAIN_POLICY_PARA;
  {$EXTERNALSYM EV_EXTRA_CERT_CHAIN_POLICY_PARA}
  TEvExtraCertChainPolicyPara = _EV_EXTRA_CERT_CHAIN_POLICY_PARA;
  PEV_EXTRA_CERT_CHAIN_POLICY_PARA = PEvExtraCertChainPolicyPara;
  {$EXTERNALSYM PEV_EXTRA_CERT_CHAIN_POLICY_PARA}

type
  PEvExtraCertChainPolicyStatus = ^TEvExtraCertChainPolicyStatus;
  _EV_EXTRA_CERT_CHAIN_POLICY_STATUS = record
    cbSize: DWORD;
    dwQualifiers: DWORD;
    dwIssuanceUsageIndex: DWORD;
  end;
  {$EXTERNALSYM _EV_EXTRA_CERT_CHAIN_POLICY_STATUS}
  EV_EXTRA_CERT_CHAIN_POLICY_STATUS = _EV_EXTRA_CERT_CHAIN_POLICY_STATUS;
  {$EXTERNALSYM EV_EXTRA_CERT_CHAIN_POLICY_STATUS}
  TEvExtraCertChainPolicyStatus = _EV_EXTRA_CERT_CHAIN_POLICY_STATUS;
  PEV_EXTRA_CERT_CHAIN_POLICY_STATUS = PEvExtraCertChainPolicyStatus;
  {$EXTERNALSYM PEV_EXTRA_CERT_CHAIN_POLICY_STATUS}



//+-------------------------------------------------------------------------
// convert formatted string to binary
// If cchString is 0, then pszString is NULL terminated and
// cchString is obtained via strlen() + 1.
// dwFlags defines string format
// if pbBinary is NULL, *pcbBinary returns the size of required memory
// *pdwSkip returns the character count of skipped strings, optional
// *pdwFlags returns the actual format used in the conversion, optional
//--------------------------------------------------------------------------
function CryptStringToBinaryA(
  pszString: LPCSTR;
  cchString: DWORD;
  dwFlags: DWORD;
  pbBinary: PByte;
  var pcbBinary: DWORD;
  pdwSkip: PDWORD;
  pdwFlags: PDWORD): BOOL; winapi;
{$EXTERNALSYM CryptStringToBinaryA}

//+-------------------------------------------------------------------------
// convert formatted string to binary
// If cchString is 0, then pszString is NULL terminated and
// cchString is obtained via strlen() + 1.
// dwFlags defines string format
// if pbBinary is NULL, *pcbBinary returns the size of required memory
// *pdwSkip returns the character count of skipped strings, optional
// *pdwFlags returns the actual format used in the conversion, optional
//--------------------------------------------------------------------------
function CryptStringToBinaryW(
  pszString: LPCWSTR;
  cchString: DWORD;
  dwFlags: DWORD;
  pbBinary: PByte;
  var pcbBinary: DWORD;
  pdwSkip: PDWORD;
  pdwFlags: PDWORD): BOOL; winapi;
{$EXTERNALSYM CryptStringToBinaryW}

function CryptStringToBinary(
  pszString: LPCWSTR;
  cchString: DWORD;
  dwFlags: DWORD;
  pbBinary: PByte;
  var pcbBinary: DWORD;
  pdwSkip: PDWORD;
  pdwFlags: PDWORD): BOOL; winapi;
{$EXTERNALSYM CryptStringToBinary}

//+-------------------------------------------------------------------------
// convert binary to formatted string
// dwFlags defines string format
// if pszString is NULL, *pcchString returns size in characters
// including null-terminator
//--------------------------------------------------------------------------
function CryptBinaryToStringA(
  pbBinary: PByte;
  cbBinary: DWORD;
  dwFlags: DWORD;
  pszString: LPSTR;
  var pcchString: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptBinaryToStringA}

//+-------------------------------------------------------------------------
// convert binary to formatted string
// dwFlags defines string format
// if pszString is NULL, *pcchString returns size in characters
// including null-terminator
//--------------------------------------------------------------------------
function CryptBinaryToStringW(
  pbBinary: PByte;
  cbBinary: DWORD;
  dwFlags: DWORD;
  pszString: LPWSTR;
  var pcchString: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptBinaryToStringW}

function CryptBinaryToString(
  pbBinary: PByte;
  cbBinary: DWORD;
  dwFlags: DWORD;
  pszString: LPWSTR;
  var pcchString: DWORD): BOOL; winapi;
{$EXTERNALSYM CryptBinaryToString}

// dwFlags has the following defines
// certenrolld_begin -- CRYPT_STRING_*
const
  CRYPT_STRING_BASE64HEADER          = $00000000;
  {$EXTERNALSYM CRYPT_STRING_BASE64HEADER}
  CRYPT_STRING_BASE64                = $00000001;
  {$EXTERNALSYM CRYPT_STRING_BASE64}
  CRYPT_STRING_BINARY                = $00000002;
  {$EXTERNALSYM CRYPT_STRING_BINARY}
  CRYPT_STRING_BASE64REQUESTHEADER   = $00000003;
  {$EXTERNALSYM CRYPT_STRING_BASE64REQUESTHEADER}
  CRYPT_STRING_HEX                   = $00000004;
  {$EXTERNALSYM CRYPT_STRING_HEX}
  CRYPT_STRING_HEXASCII              = $00000005;
  {$EXTERNALSYM CRYPT_STRING_HEXASCII}
  CRYPT_STRING_BASE64_ANY            = $00000006;
  {$EXTERNALSYM CRYPT_STRING_BASE64_ANY}
  CRYPT_STRING_ANY                   = $00000007;
  {$EXTERNALSYM CRYPT_STRING_ANY}
  CRYPT_STRING_HEX_ANY               = $00000008;
  {$EXTERNALSYM CRYPT_STRING_HEX_ANY}
  CRYPT_STRING_BASE64X509CRLHEADER   = $00000009;
  {$EXTERNALSYM CRYPT_STRING_BASE64X509CRLHEADER}
  CRYPT_STRING_HEXADDR               = $0000000a;
  {$EXTERNALSYM CRYPT_STRING_HEXADDR}
  CRYPT_STRING_HEXASCIIADDR          = $0000000b;
  {$EXTERNALSYM CRYPT_STRING_HEXASCIIADDR}
  CRYPT_STRING_HEXRAW                = $0000000c;
  {$EXTERNALSYM CRYPT_STRING_HEXRAW}

  CRYPT_STRING_HASHDATA              = $10000000;
  {$EXTERNALSYM CRYPT_STRING_HASHDATA}
  CRYPT_STRING_STRICT                = $20000000;
  {$EXTERNALSYM CRYPT_STRING_STRICT}
  CRYPT_STRING_NOCRLF                = $40000000;
  {$EXTERNALSYM CRYPT_STRING_NOCRLF}
  CRYPT_STRING_NOCR                  = $80000000;
  {$EXTERNALSYM CRYPT_STRING_NOCR}
// certenrolld_end

// CryptBinaryToString uses the following flags
// CRYPT_STRING_BASE64HEADER - base64 format with certificate begin
//                             and end headers
// CRYPT_STRING_BASE64 - only base64 without headers
// CRYPT_STRING_BINARY - pure binary copy
// CRYPT_STRING_BASE64REQUESTHEADER - base64 format with request begin
//                                    and end headers
// CRYPT_STRING_BASE64X509CRLHEADER - base64 format with x509 crl begin
//                                    and end headers
// CRYPT_STRING_HEX - only hex format
// CRYPT_STRING_HEXASCII - hex format with ascii char display
// CRYPT_STRING_HEXADDR - hex format with address display
// CRYPT_STRING_HEXASCIIADDR - hex format with ascii char and address display
//
// CryptBinaryToString accepts CRYPT_STRING_NOCR or'd into one of the above.
// When set, line breaks contain only LF, instead of CR-LF pairs.

// CryptStringToBinary uses the following flags
// CRYPT_STRING_BASE64_ANY tries the following, in order:
//    CRYPT_STRING_BASE64HEADER
//    CRYPT_STRING_BASE64
// CRYPT_STRING_ANY tries the following, in order:
//    CRYPT_STRING_BASE64_ANY
//    CRYPT_STRING_BINARY -- should always succeed
// CRYPT_STRING_HEX_ANY tries the following, in order:
//    CRYPT_STRING_HEXADDR
//    CRYPT_STRING_HEXASCIIADDR
//    CRYPT_STRING_HEXASCII
//    CRYPT_STRING_HEX


//+=========================================================================
//  PFX (PKCS #12) function definitions and types
//==========================================================================

//+-------------------------------------------------------------------------
//  PKCS#12 OIDs
//--------------------------------------------------------------------------
const
  szOID_PKCS_12_PbeIds                       = '1.2.840.113549.1.12.1';
  {$EXTERNALSYM szOID_PKCS_12_PbeIds}
  szOID_PKCS_12_pbeWithSHA1And128BitRC4      = '1.2.840.113549.1.12.1.1';
  {$EXTERNALSYM szOID_PKCS_12_pbeWithSHA1And128BitRC4}
  szOID_PKCS_12_pbeWithSHA1And40BitRC4       = '1.2.840.113549.1.12.1.2';
  {$EXTERNALSYM szOID_PKCS_12_pbeWithSHA1And40BitRC4}
  szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES  = '1.2.840.113549.1.12.1.3';
  {$EXTERNALSYM szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES}
  szOID_PKCS_12_pbeWithSHA1And2KeyTripleDES  = '1.2.840.113549.1.12.1.4';
  {$EXTERNALSYM szOID_PKCS_12_pbeWithSHA1And2KeyTripleDES}
  szOID_PKCS_12_pbeWithSHA1And128BitRC2      = '1.2.840.113549.1.12.1.5';
  {$EXTERNALSYM szOID_PKCS_12_pbeWithSHA1And128BitRC2}
  szOID_PKCS_12_pbeWithSHA1And40BitRC2       = '1.2.840.113549.1.12.1.6';
  {$EXTERNALSYM szOID_PKCS_12_pbeWithSHA1And40BitRC2}


//+-------------------------------------------------------------------------
//  PBE parameters as defined in PKCS#12 as pkcs-12PbeParams.
//
//  NOTE that the salt bytes will immediately follow this structure.
//  we avoid using pointers in this structure for easy of passing
//  it into NCryptExportKey() as a NCryptBuffer (may be sent via RPC
//  to the key isolation process).
//--------------------------------------------------------------------------
type
  PCryptPKCS12PbeParams = ^TCryptPKCS12PbeParams;
  _CRYPT_PKCS12_PBE_PARAMS = record
    iIterations: Integer;      (* iteration count              *)
    cbSalt: ULONG;             (* byte size of the salt        *)
  end;
  {$EXTERNALSYM _CRYPT_PKCS12_PBE_PARAMS}
  CRYPT_PKCS12_PBE_PARAMS = _CRYPT_PKCS12_PBE_PARAMS;
  {$EXTERNALSYM CRYPT_PKCS12_PBE_PARAMS}
  TCryptPKCS12PbeParams = _CRYPT_PKCS12_PBE_PARAMS;

//+-------------------------------------------------------------------------
//      PFXImportCertStore
//
//  Import the PFX blob and return a store containing certificates
//
//  If the password parameter is incorrect or any other problems decoding
//  the PFX blob are encountered, the function will return NULL and the
//      error code can be found from GetLastError().
//
//  The dwFlags parameter may be set to the following:
//  PKCS12_IMPORT_SILENT    - only allow importing key in silent mode. If the
//                            csp or ksp requires ui then this call will fail
//                            with the error from the csp or ksp.
//  CRYPT_EXPORTABLE - specify that any imported keys should be marked as
//                     exportable (see documentation on CryptImportKey)
//  CRYPT_USER_PROTECTED - (see documentation on CryptImportKey)
//  CRYPT_MACHINE_KEYSET - used to force the private key to be stored in the
//                        the local machine and not the current user.
//  CRYPT_USER_KEYSET - used to force the private key to be stored in the
//                      the current user and not the local machine, even if
//                      the pfx blob specifies that it should go into local
//                      machine.
//  PKCS12_INCLUDE_EXTENDED_PROPERTIES - used to import all extended
//                     properties that were saved with CertExportCertStore()
//                     using the same flag.
//--------------------------------------------------------------------------
function PFXImportCertStore(
  pPFX: PCryptDataBlob;
  szPassword: LPCWSTR;
  dwFlags: DWORD): HCERTSTORE; winapi;
{$EXTERNALSYM PFXImportCertStore}

// dwFlags definitions for PFXImportCertStore
//#define CRYPT_EXPORTABLE          0x00000001  // CryptImportKey dwFlags
//#define CRYPT_USER_PROTECTED      0x00000002  // CryptImportKey dwFlags
//#define CRYPT_MACHINE_KEYSET      0x00000020  // CryptAcquireContext dwFlags
//#define PKCS12_INCLUDE_EXTENDED_PROPERTIES 0x10
const
  PKCS12_IMPORT_SILENT        = $00000040;
  {$EXTERNALSYM PKCS12_IMPORT_SILENT}
  CRYPT_USER_KEYSET           = $00001000;
  {$EXTERNALSYM CRYPT_USER_KEYSET}
  PKCS12_PREFER_CNG_KSP       = $00000100;  // prefer using CNG KSP
  {$EXTERNALSYM PKCS12_PREFER_CNG_KSP}
  PKCS12_ALWAYS_CNG_KSP       = $00000200;  // always use CNG KSP
  {$EXTERNALSYM PKCS12_ALWAYS_CNG_KSP}
  PKCS12_ALLOW_OVERWRITE_KEY  = $00004000;  // allow overwrite existing key
  {$EXTERNALSYM PKCS12_ALLOW_OVERWRITE_KEY}
  PKCS12_NO_PERSIST_KEY       = $00008000;  // key will not be persisted
  {$EXTERNALSYM PKCS12_NO_PERSIST_KEY}
  PKCS12_IMPORT_RESERVED_MASK = $ffff0000;
  {$EXTERNALSYM PKCS12_IMPORT_RESERVED_MASK}

  PKCS12_OBJECT_LOCATOR_ALL_IMPORT_FLAGS          =
              ( PKCS12_ALWAYS_CNG_KSP               or
                PKCS12_NO_PERSIST_KEY               or
                PKCS12_IMPORT_SILENT                or
                $10{PKCS12_INCLUDE_EXTENDED_PROPERTIES});
  {$EXTERNALSYM PKCS12_OBJECT_LOCATOR_ALL_IMPORT_FLAGS}

//+-------------------------------------------------------------------------
//      PFXIsPFXBlob
//
//  This function will try to decode the outer layer of the blob as a pfx
//  blob, and if that works it will return TRUE, it will return FALSE otherwise
//
//--------------------------------------------------------------------------
function PFXIsPFXBlob(
  pPFX: PCryptDataBlob): BOOL; winapi;
{$EXTERNALSYM PFXIsPFXBlob}



//+-------------------------------------------------------------------------
//      PFXVerifyPassword
//
//  This function will attempt to decode the outer layer of the blob as a pfx
//  blob and decrypt with the given password. No data from the blob will be
//  imported.
//
//  Return value is TRUE if password appears correct, FALSE otherwise.
//
//--------------------------------------------------------------------------
function PFXVerifyPassword(
  pPFX: PCryptDataBlob;
  szPassword: LPCWSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM PFXVerifyPassword}


//+-------------------------------------------------------------------------
//      PFXExportCertStoreEx
//
//  Export the certificates and private keys referenced in the passed-in store
//
//  This API encodes the blob under a stronger algorithm. The resulting
//  PKCS12 blobs are incompatible with the earlier PFXExportCertStore API.
//
//  The value passed in the password parameter will be used to encrypt and
//  verify the integrity of the PFX packet. If any problems encoding the store
//  are encountered, the function will return FALSE and the error code can
//  be found from GetLastError().
//
//  The PKCS12_PROTECT_TO_DOMAIN_SIDS flag together with an
//  NCRYPT_DESCRIPTOR_HANDLE* for pvPara means the password will be stored
//  in the pfx protected to the NCRYPT_DESCRIPTOR_HANDLE. On import, any
//  principal that is listed in NCRYPT_DESCRIPTOR_HANDLE can decrypt the
//  password within the pfx and use it to descrypt the entire pfx.
//
//  If the password parameter is NULL or L"" and the
//  PKCS12_PROTECT_TO_DOMAIN_SIDS flag is set together with an
//  NCRYPT_DESCRIPTOR_HANDLE* for pvPara then a random password of length
//  40 characters is chosen to protect the pfx. This password will be
//  protected inside the pfx.
//
//  The dwFlags parameter may be set to any combination of
//      EXPORT_PRIVATE_KEYS
//      REPORT_NO_PRIVATE_KEY
//      REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
//      PKCS12_EXPORT_SILENT
//      PKCS12_INCLUDE_EXTENDED_PROPERTIES
//      PKCS12_PROTECT_TO_DOMAIN_SIDS
//
//  The encoded PFX blob is returned in *pPFX. If pPFX->pbData is NULL upon
//  input, this is a length only calculation, whereby, pPFX->cbData is updated
//  with the number of bytes required for the encoded blob. Otherwise,
//  the memory pointed to by pPFX->pbData is updated with the encoded bytes
//  and pPFX->cbData is updated with the encoded byte length.
//--------------------------------------------------------------------------
function PFXExportCertStoreEx(
  hStore: HCERTSTORE;
  pPFX: PCryptDataBlob;
  szPassword: LPCWSTR;
  pvPara: Pointer;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM PFXExportCertStoreEx}


// dwFlags definitions for PFXExportCertStoreEx
const
  REPORT_NO_PRIVATE_KEY                  = $0001;
  {$EXTERNALSYM REPORT_NO_PRIVATE_KEY}
  REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY  = $0002;
  {$EXTERNALSYM REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY}
  EXPORT_PRIVATE_KEYS                    = $0004;
  {$EXTERNALSYM EXPORT_PRIVATE_KEYS}
  PKCS12_INCLUDE_EXTENDED_PROPERTIES     = $0010;
  {$EXTERNALSYM PKCS12_INCLUDE_EXTENDED_PROPERTIES}
  PKCS12_PROTECT_TO_DOMAIN_SIDS          = $0020;
  {$EXTERNALSYM PKCS12_PROTECT_TO_DOMAIN_SIDS}
  PKCS12_EXPORT_SILENT                   = $0040;
  {$EXTERNALSYM PKCS12_EXPORT_SILENT}
  PKCS12_EXPORT_RESERVED_MASK            = $ffff0000;
  {$EXTERNALSYM PKCS12_EXPORT_RESERVED_MASK}


//+-------------------------------------------------------------------------
//      PFXExportCertStore
//
//  Export the certificates and private keys referenced in the passed-in store
//
//  This is an old API kept for compatibility with IE4 clients. New applications
//  should call the above PfxExportCertStoreEx for enhanced security.
//--------------------------------------------------------------------------
function PFXExportCertStore(
  hStore: HCERTSTORE;
  pPFX: PCryptDataBlob;
  szPassword: LPCWSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM PFXExportCertStore}


//+=========================================================================
//  APIs to get a non-blocking, time valid OCSP response for
//  a server certificate chain.
//
//  Normally, this OCSP response will be included along with the server
//  certificate in a message returned to the client. As a result only the
//  server should need to contact the OCSP responser for its certificate.
//==========================================================================

//+-------------------------------------------------------------------------
//  Server OCSP response handle.
//--------------------------------------------------------------------------
type
  HCERT_SERVER_OCSP_RESPONSE = Pointer;
  {$EXTERNALSYM HCERT_SERVER_OCSP_RESPONSE}

//+-------------------------------------------------------------------------
//  Open a handle to an OCSP response associated with a server certificate
//  chain. If the end certificate doesn't have an OCSP AIA URL, NULL is
//  returned with LastError set to CRYPT_E_NOT_IN_REVOCATION_DATABASE. NULL
//  will also be returned if unable to allocate memory or create system
//  objects.
//
//  This API will try to retrieve an initial OCSP response before returning.
//  This API will block during the retrieval. If unable to successfully
//  retrieve the first OCSP response, a non-NULL handle will still be returned
//  if not one of the error cases mentioned above.
//
//  The CERT_SERVER_OCSP_RESPONSE_ASYNC_FLAG flag can be set to
//  return immediately without making the initial synchronous retrieval.
//
//  A background thread is created that will pre-fetch time valid
//  OCSP responses.
//
//  The input chain context will be AddRef'ed and not freed until
//  the returned handle is closed.
//
//  CertCloseServerOcspResponse() must be called to close the returned
//  handle.
//
//  pvReserved isn't currently used and must be set to NULL.
//--------------------------------------------------------------------------
function CertOpenServerOcspResponse(
  pChainContext: PCertChainContext;
  dwFlags: DWORD;
  pvReserved: LPVOID): HCERT_SERVER_OCSP_RESPONSE; winapi;
{$EXTERNALSYM CertOpenServerOcspResponse}

// Set this flag to return immediately without making the initial
// synchronous retrieval
const
  CERT_SERVER_OCSP_RESPONSE_ASYNC_FLAG       = $00000001;
  {$EXTERNALSYM CERT_SERVER_OCSP_RESPONSE_ASYNC_FLAG}

//+-------------------------------------------------------------------------
//  AddRef a HCERT_SERVER_OCSP_RESPONSE returned by
//  CertOpenServerOcspResponse(). Each Open and AddRef requires a
//  corresponding CertCloseServerOcspResponse().
//--------------------------------------------------------------------------
procedure CertAddRefServerOcspResponse(
  hServerOcspResponse: HCERT_SERVER_OCSP_RESPONSE); winapi;
{$EXTERNALSYM CertAddRefServerOcspResponse}

//+-------------------------------------------------------------------------
//  Close the handle returned by CertOpenServerOcspResponse() or AddRef'ed
//  by CertAddRefServerOcspResponse().
//
//  dwFlags isn't currently used and must be set to 0.
//--------------------------------------------------------------------------
procedure CertCloseServerOcspResponse(
  hServerOcspResponse: HCERT_SERVER_OCSP_RESPONSE;
  dwFlags: DWORD); winapi;
{$EXTERNALSYM CertCloseServerOcspResponse}


//+-------------------------------------------------------------------------
//  Server OCSP response context.
//--------------------------------------------------------------------------
type
  PCertServerOcspResponseContext = ^TCertServerOcspResponseContext;
  _CERT_SERVER_OCSP_RESPONSE_CONTEXT = record
    cbSize: DWORD;
    pbEncodedOcspResponse: PByte;
    cbEncodedOcspResponse: DWORD;
  end;
  {$EXTERNALSYM _CERT_SERVER_OCSP_RESPONSE_CONTEXT}
  CERT_SERVER_OCSP_RESPONSE_CONTEXT = _CERT_SERVER_OCSP_RESPONSE_CONTEXT;
  {$EXTERNALSYM CERT_SERVER_OCSP_RESPONSE_CONTEXT}
  TCertServerOcspResponseContext = _CERT_SERVER_OCSP_RESPONSE_CONTEXT;
  PCERT_SERVER_OCSP_RESPONSE_CONTEXT = PCertServerOcspResponseContext;
  {$EXTERNALSYM PCERT_SERVER_OCSP_RESPONSE_CONTEXT}
  PCCERT_SERVER_OCSP_RESPONSE_CONTEXT = PCertServerOcspResponseContext;
  {$EXTERNALSYM PCCERT_SERVER_OCSP_RESPONSE_CONTEXT}


//+-------------------------------------------------------------------------
//  Get a time valid OCSP response context for the handle created for
//  the server certificate chain.
//
//  This API won't block to retrieve the OCSP response. It will return
//  the current pre-fetched OCSP response. If a time valid OCSP response
//  isn't available, NULL will be returned with LAST_ERROR set to
//  CRYPT_E_REVOCATION_OFFLINE.
//
//  CertFreeServerOcspResponseContext() must be called to free the
//  returned OCSP response context.
//--------------------------------------------------------------------------
function CertGetServerOcspResponseContext(
  hServerOcspResponse: HCERT_SERVER_OCSP_RESPONSE;
  dwFlags: DWORD;
  pvReserved: LPVOID): PCertServerOcspResponseContext;
{$EXTERNALSYM CertGetServerOcspResponseContext}

//+-------------------------------------------------------------------------
//  AddRef a PCCERT_SERVER_OCSP_RESPONSE_CONTEXT returned by
//  CertGetServerOcspResponseContext(). Each Get and AddRef requires a
//  corresponding CertFreeServerOcspResponseContext().
//--------------------------------------------------------------------------
procedure CertAddRefServerOcspResponseContext(
  pServerOcspResponseContext: PCertServerOcspResponseContext); winapi;
{$EXTERNALSYM CertAddRefServerOcspResponseContext}

//+-------------------------------------------------------------------------
//  Free the OCSP response context returned by
//  CertGetServerOcspResponseContext().
//--------------------------------------------------------------------------
procedure CertFreeServerOcspResponseContext(
  pServerOcspResponseContext: PCertServerOcspResponseContext); winapi;
{$EXTERNALSYM CertFreeServerOcspResponseContext}


//+-------------------------------------------------------------------------
//  Helper function to do URL retrieval of logo or biometric information
//  specified in either the szOID_LOGOTYPE_EXT or szOID_BIOMETRIC_EXT
//  certificate extension.
//
//  Only the first hashed URL matching lpszLogoOrBiometricType is used
//  to do the URL retrieval. Only direct logotypes are supported.
//  The bytes at the first URL are retrieved via
//  CryptRetrieveObjectByUrlW and hashed. The computed hash is compared
//  against the hash in the certificate.  For success, ppbData, pcbData
//  and optionally ppwszMimeType are updated with
//  CryptMemAlloc'ed memory which must be freed by calling CryptMemFree().
//  For failure, *ppbData, *pcbData and optionally *ppwszMimeType are
//  zero'ed.
//
//  For failure, the following errors may be set in LastError:
//      E_INVALIDARG - invalid lpszLogoOrBiometricType, not one of the
//          acceptable predefined types.
//      CRYPT_E_NOT_FOUND - certificate doesn't have the
//          szOID_LOGOTYPE_EXT or szOID_BIOMETRIC_EXT extension or a matching
//          lpszLogoOrBiometricType wasn't found with a non-empty
//          hashed URL.
//      ERROR_NOT_SUPPORTED - matched the unsupported indirect logotype
//      NTE_BAD_ALGID - unknown hash algorithm OID
//      ERROR_INVALID_DATA - no bytes were retrieved at the specified URL
//          in the certificate extension
//      CRYPT_E_HASH_VALUE - the computed hash doesn't match the hash
//          in the certificate
//  CertRetrieveLogoOrBiometricInfo calls the following functions which
//  will set LastError for failure:
//      CryptDecodeObjectEx(szOID_LOGOTYPE_EXT or szOID_BIOMETRIC_EXT)
//      CryptRetrieveObjectByUrlW
//      CryptHashCertificate
//      CryptMemAlloc
//
//  lpszLogoOrBiometricType is one of the predefined logotype or biometric
//  types, an other logotype OID or a biometric OID.
//
//  dwRetrievalFlags - see CryptRetrieveObjectByUrlW
//  dwTimeout - see CryptRetrieveObjectByUrlW
//
//  dwFlags - reserved, must be set to 0
//  pvReserved - reserved, must be set to NULL
//
//  *ppwszMimeType is always NULL for the biometric types. For success,
//  the caller must always check if non-NULL before dereferencing.
//--------------------------------------------------------------------------
function CertRetrieveLogoOrBiometricInfo(
  pCertContext: PCertContext;
  lpszLogoOrBiometricType: LPCSTR;
  dwRetrievalFlags: DWORD;
  dwTimeout: DWORD;                              // milliseconds
  dwFlags: DWORD;
  pvReserved: Pointer;
  out ppbData: PByte;      // CryptMemFree()
  out pcbData: DWORD;
  ppwszMimeType: PLPWSTR         // CryptMemFree()
  ): BOOL; winapi;
{$EXTERNALSYM CertRetrieveLogoOrBiometricInfo}


// Predefined Logotypes
const
  CERT_RETRIEVE_ISSUER_LOGO                       = LPCSTR(1);
  {$EXTERNALSYM CERT_RETRIEVE_ISSUER_LOGO}
  CERT_RETRIEVE_SUBJECT_LOGO                      = LPCSTR(2);
  {$EXTERNALSYM CERT_RETRIEVE_SUBJECT_LOGO}
  CERT_RETRIEVE_COMMUNITY_LOGO                    = LPCSTR(3);
  {$EXTERNALSYM CERT_RETRIEVE_COMMUNITY_LOGO}

// Predefined Biometric types
const
  CERT_RETRIEVE_BIOMETRIC_PREDEFINED_BASE_TYPE    = LPCSTR(1000);
  {$EXTERNALSYM CERT_RETRIEVE_BIOMETRIC_PREDEFINED_BASE_TYPE}

  CERT_RETRIEVE_BIOMETRIC_PICTURE_TYPE            =
    (CERT_RETRIEVE_BIOMETRIC_PREDEFINED_BASE_TYPE + CERT_BIOMETRIC_PICTURE_TYPE);
  {$EXTERNALSYM CERT_RETRIEVE_BIOMETRIC_PICTURE_TYPE}
  CERT_RETRIEVE_BIOMETRIC_SIGNATURE_TYPE          =
    (CERT_RETRIEVE_BIOMETRIC_PREDEFINED_BASE_TYPE + CERT_BIOMETRIC_SIGNATURE_TYPE);
  {$EXTERNALSYM CERT_RETRIEVE_BIOMETRIC_SIGNATURE_TYPE}


//
// Certificate Selection API
//


type
  PCertSelectChainPara = ^TCertSelectChainPara;
  _CERT_SELECT_CHAIN_PARA = record
    hChainEngine: HCERTCHAINENGINE;
    pTime: PFileTime;
    hAdditionalStore: HCERTSTORE;
    pChainPara: PCertChainPara;
    dwFlags: DWORD;
  end;
  {$EXTERNALSYM _CERT_SELECT_CHAIN_PARA}
  CERT_SELECT_CHAIN_PARA = _CERT_SELECT_CHAIN_PARA;
  {$EXTERNALSYM CERT_SELECT_CHAIN_PARA}
  TCertSelectChainPara = _CERT_SELECT_CHAIN_PARA;
  PCERT_SELECT_CHAIN_PARA = PCertSelectChainPara;
  {$EXTERNALSYM PCERT_SELECT_CHAIN_PARA}
  PCCERT_SELECT_CHAIN_PARA = PCertSelectChainPara;
  {$EXTERNALSYM PCCERT_SELECT_CHAIN_PARA}

const
  CERT_SELECT_MAX_PARA               = 500;
  {$EXTERNALSYM CERT_SELECT_MAX_PARA}

type
  PCertSelectCriteria = ^TCertSelectCriteria;
  _CERT_SELECT_CRITERIA = record
    dwType: DWORD;
    cPara: DWORD;
    ppPara: PPointer;
  end;
  {$EXTERNALSYM _CERT_SELECT_CRITERIA}
  CERT_SELECT_CRITERIA = _CERT_SELECT_CRITERIA;
  {$EXTERNALSYM CERT_SELECT_CRITERIA}
  TCertSelectCriteria = _CERT_SELECT_CRITERIA;
  PCERT_SELECT_CRITERIA = PCertSelectCriteria;
  {$EXTERNALSYM PCERT_SELECT_CRITERIA}
  PCCERT_SELECT_CRITERIA = PCertSelectCriteria;
  {$EXTERNALSYM PCCERT_SELECT_CRITERIA}


// Selection Criteria
const
  CERT_SELECT_BY_ENHKEY_USAGE         = 1;
  {$EXTERNALSYM CERT_SELECT_BY_ENHKEY_USAGE}
  CERT_SELECT_BY_KEY_USAGE            = 2;
  {$EXTERNALSYM CERT_SELECT_BY_KEY_USAGE}
  CERT_SELECT_BY_POLICY_OID           = 3;
  {$EXTERNALSYM CERT_SELECT_BY_POLICY_OID}
  CERT_SELECT_BY_PROV_NAME            = 4;
  {$EXTERNALSYM CERT_SELECT_BY_PROV_NAME}
  CERT_SELECT_BY_EXTENSION            = 5;
  {$EXTERNALSYM CERT_SELECT_BY_EXTENSION}
  CERT_SELECT_BY_SUBJECT_HOST_NAME    = 6;
  {$EXTERNALSYM CERT_SELECT_BY_SUBJECT_HOST_NAME}
  CERT_SELECT_BY_ISSUER_ATTR          = 7;
  {$EXTERNALSYM CERT_SELECT_BY_ISSUER_ATTR}
  CERT_SELECT_BY_SUBJECT_ATTR         = 8;
  {$EXTERNALSYM CERT_SELECT_BY_SUBJECT_ATTR}
  CERT_SELECT_BY_ISSUER_NAME          = 9;
  {$EXTERNALSYM CERT_SELECT_BY_ISSUER_NAME}
  CERT_SELECT_BY_PUBLIC_KEY           = 10;
  {$EXTERNALSYM CERT_SELECT_BY_PUBLIC_KEY}
  CERT_SELECT_BY_TLS_SIGNATURES       = 11;
  {$EXTERNALSYM CERT_SELECT_BY_TLS_SIGNATURES}

  CERT_SELECT_LAST                    = CERT_SELECT_BY_TLS_SIGNATURES;
  {$EXTERNALSYM CERT_SELECT_LAST}
  CERT_SELECT_MAX                     = (CERT_SELECT_LAST * 3);
  {$EXTERNALSYM CERT_SELECT_MAX}

// Selection Flags
const
  CERT_SELECT_ALLOW_EXPIRED                  = $00000001;
  {$EXTERNALSYM CERT_SELECT_ALLOW_EXPIRED}
  CERT_SELECT_TRUSTED_ROOT                   = $00000002;
  {$EXTERNALSYM CERT_SELECT_TRUSTED_ROOT}
  CERT_SELECT_DISALLOW_SELFSIGNED            = $00000004;
  {$EXTERNALSYM CERT_SELECT_DISALLOW_SELFSIGNED}
  CERT_SELECT_HAS_PRIVATE_KEY                = $00000008;
  {$EXTERNALSYM CERT_SELECT_HAS_PRIVATE_KEY}
  CERT_SELECT_HAS_KEY_FOR_SIGNATURE          = $00000010;
  {$EXTERNALSYM CERT_SELECT_HAS_KEY_FOR_SIGNATURE}
  CERT_SELECT_HAS_KEY_FOR_KEY_EXCHANGE       = $00000020;
  {$EXTERNALSYM CERT_SELECT_HAS_KEY_FOR_KEY_EXCHANGE}
  CERT_SELECT_HARDWARE_ONLY                  = $00000040;
  {$EXTERNALSYM CERT_SELECT_HARDWARE_ONLY}
  CERT_SELECT_ALLOW_DUPLICATES               = $00000080;
  {$EXTERNALSYM CERT_SELECT_ALLOW_DUPLICATES}


//+-------------------------------------------------------------------------
//  Build certificate chains from the certificates in the store and select
//  the matching ones based on the flags and selection criteria.
//--------------------------------------------------------------------------

function CertSelectCertificateChains(
  pSelectionContext: PGUID;
  dwFlags: DWORD;
  pChainParameters: PCertSelectChainPara;
  cCriteria: DWORD;
  rgpCriteria: PCertSelectCriteria;
  hStore: HCERTSTORE;
  out pcSelection: DWORD;
  out pprgpSelection: PPCertChainContext
  ): BOOL; winapi;
{$EXTERNALSYM CertSelectCertificateChains}

//+-------------------------------------------------------------------------
//  Free the array of pointers to chain contexts.
//  CertFreeCertificateChain is NOT called for each entry.
//--------------------------------------------------------------------------

procedure CertFreeCertificateChainList(
  prgpSelection: PCertChainContext); winapi;
{$EXTERNALSYM CertFreeCertificateChainList}


//
// Time stamp API
//


//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_REQUEST
//
//--------------------------------------------------------------------------
const
  TIMESTAMP_VERSION = 1;
  {$EXTERNALSYM TIMESTAMP_VERSION}

type
  PCryptTimestampRequest = ^TCryptTimestampRequest;
  _CRYPT_TIMESTAMP_REQUEST = record
    dwVersion: DWORD;                      // v1
    HashAlgorithm: TCryptAlgorithmIdentifier;
    HashedMessage: TCryptDERBlob;
    pszTSAPolicyId: LPSTR;                 // OPTIONAL
    Nonce: TCryptIntegerBlob;              // OPTIONAL
    fCertReq: BOOL;                        // DEFAULT FALSE
    cExtension: DWORD;

    rgExtension: PCertExtension;           // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_TIMESTAMP_REQUEST}
  CRYPT_TIMESTAMP_REQUEST = _CRYPT_TIMESTAMP_REQUEST;
  {$EXTERNALSYM CRYPT_TIMESTAMP_REQUEST}
  TCryptTimestampRequest = _CRYPT_TIMESTAMP_REQUEST;
  PCRYPT_TIMESTAMP_REQUEST = PCryptTimestampRequest;
  {$EXTERNALSYM PCRYPT_TIMESTAMP_REQUEST}

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_RESPONSE
//
//--------------------------------------------------------------------------
type
  PCryptTimestampResponse = ^TCryptTimestampResponse;
  _CRYPT_TIMESTAMP_RESPONSE = record
    dwStatus: DWORD;
    cFreeText: DWORD;                      // OPTIONAL

    rgFreeText: PLPWSTR;
    FailureInfo: TCryptBitBlob;            // OPTIONAL
    ContentInfo: TCryptDERBlob;            // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_TIMESTAMP_RESPONSE}
  CRYPT_TIMESTAMP_RESPONSE = _CRYPT_TIMESTAMP_RESPONSE;
  {$EXTERNALSYM CRYPT_TIMESTAMP_RESPONSE}
  TCryptTimestampResponse = _CRYPT_TIMESTAMP_RESPONSE;
  PCRYPT_TIMESTAMP_RESPONSE = PCryptTimestampResponse;
  {$EXTERNALSYM PCRYPT_TIMESTAMP_RESPONSE}

const
  TIMESTAMP_STATUS_GRANTED                       = 0;
  {$EXTERNALSYM TIMESTAMP_STATUS_GRANTED}
  TIMESTAMP_STATUS_GRANTED_WITH_MODS             = 1;
  {$EXTERNALSYM TIMESTAMP_STATUS_GRANTED_WITH_MODS}
  TIMESTAMP_STATUS_REJECTED                      = 2;
  {$EXTERNALSYM TIMESTAMP_STATUS_REJECTED}
  TIMESTAMP_STATUS_WAITING                       = 3;
  {$EXTERNALSYM TIMESTAMP_STATUS_WAITING}
  TIMESTAMP_STATUS_REVOCATION_WARNING            = 4;
  {$EXTERNALSYM TIMESTAMP_STATUS_REVOCATION_WARNING}
  TIMESTAMP_STATUS_REVOKED                       = 5;
  {$EXTERNALSYM TIMESTAMP_STATUS_REVOKED}

  TIMESTAMP_FAILURE_BAD_ALG                      = 0;
  {$EXTERNALSYM TIMESTAMP_FAILURE_BAD_ALG}
  TIMESTAMP_FAILURE_BAD_REQUEST                  = 2;
  {$EXTERNALSYM TIMESTAMP_FAILURE_BAD_REQUEST}
  TIMESTAMP_FAILURE_BAD_FORMAT                   = 5;
  {$EXTERNALSYM TIMESTAMP_FAILURE_BAD_FORMAT}
  TIMESTAMP_FAILURE_TIME_NOT_AVAILABLE           = 14;
  {$EXTERNALSYM TIMESTAMP_FAILURE_TIME_NOT_AVAILABLE}
  TIMESTAMP_FAILURE_POLICY_NOT_SUPPORTED         = 15;
  {$EXTERNALSYM TIMESTAMP_FAILURE_POLICY_NOT_SUPPORTED}
  TIMESTAMP_FAILURE_EXTENSION_NOT_SUPPORTED      = 16;
  {$EXTERNALSYM TIMESTAMP_FAILURE_EXTENSION_NOT_SUPPORTED}
  TIMESTAMP_FAILURE_INFO_NOT_AVAILABLE           = 17;
  {$EXTERNALSYM TIMESTAMP_FAILURE_INFO_NOT_AVAILABLE}
  TIMESTAMP_FAILURE_SYSTEM_FAILURE               = 25;
  {$EXTERNALSYM TIMESTAMP_FAILURE_SYSTEM_FAILURE}

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_ACCURACY
//
//--------------------------------------------------------------------------
type
  PCryptTimestampAccuracy = ^TCryptTimestampAccuracy;
  _CRYPT_TIMESTAMP_ACCURACY = record
    dwSeconds: DWORD;                      // OPTIONAL
    dwMillis: DWORD;                       // OPTIONAL
    dwMicros: DWORD;                       // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_TIMESTAMP_ACCURACY}
  CRYPT_TIMESTAMP_ACCURACY = _CRYPT_TIMESTAMP_ACCURACY;
  {$EXTERNALSYM CRYPT_TIMESTAMP_ACCURACY}
  TCryptTimestampAccuracy  = _CRYPT_TIMESTAMP_ACCURACY;
  PCRYPT_TIMESTAMP_ACCURACY = PCryptTimestampAccuracy;
  {$EXTERNALSYM PCRYPT_TIMESTAMP_ACCURACY}

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_INFO
//
//--------------------------------------------------------------------------
type
  PCryptTimestampInfo = ^TCryptTimestampInfo;
  _CRYPT_TIMESTAMP_INFO = record
    dwVersion: DWORD;                      // v1
    pszTSAPolicyId: LPSTR;
    HashAlgorithm: TCryptAlgorithmIdentifier;
    HashedMessage: TCryptDERBlob;
    SerialNumber: TCryptIntegerBlob;
    ftTime: TFileTime;
    pvAccuracy: PCryptTimestampAccuracy;   // OPTIONAL
    fOrdering: BOOL;                       // OPTIONAL
    Nonce: TCryptDERBlob;                  // OPTIONAL
    Tsa: TCryptDERBlob;                    // OPTIONAL
    cExtension: DWORD;

    rgExtension: PCertExtension;           // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_TIMESTAMP_INFO}
  CRYPT_TIMESTAMP_INFO = _CRYPT_TIMESTAMP_INFO;
  {$EXTERNALSYM CRYPT_TIMESTAMP_INFO}
  TCryptTimestampInfo = _CRYPT_TIMESTAMP_INFO;
  PCRYPT_TIMESTAMP_INFO = PCryptTimestampInfo;
  {$EXTERNALSYM PCRYPT_TIMESTAMP_INFO}

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_CONTEXT
//
//--------------------------------------------------------------------------
type
  PCryptTimestampContext = ^TCryptTimestampContext;
  _CRYPT_TIMESTAMP_CONTEXT = record
    cbEncoded: DWORD;

    pbEncoded: PByte;
    pTimeStamp: PCryptTimestampInfo;
  end;
  {$EXTERNALSYM _CRYPT_TIMESTAMP_CONTEXT}
  CRYPT_TIMESTAMP_CONTEXT = _CRYPT_TIMESTAMP_CONTEXT;
  {$EXTERNALSYM CRYPT_TIMESTAMP_CONTEXT}
  TCryptTimestampContext = _CRYPT_TIMESTAMP_CONTEXT;
  PCRYPT_TIMESTAMP_CONTEXT = PCryptTimestampContext;
  {$EXTERNALSYM PCRYPT_TIMESTAMP_CONTEXT}

//+-------------------------------------------------------------------------
//  CRYPT_TIMESTAMP_PARA
//
//  pszTSAPolicyId
//      [optional] Specifies the TSA policy under which the time stamp token
//      should be provided.
//
//  Nonce
//      [optional] Specifies the nonce value used by the client to verify the
//      timeliness of the response when no local clock is available.
//
//  fCertReq
//      Specifies whether the TSA must include in response the certificates
//      used to sign the time stamp token.
//
//  rgExtension
//      [optional]  Specifies Extensions to be included in request.

//--------------------------------------------------------------------------
type
  PCryptTimestampPara = ^TCryptTimestampPara;
  _CRYPT_TIMESTAMP_PARA = record
    pszTSAPolicyId: LPCSTR;                // OPTIONAL
    fRequestCerts: BOOL;                   // Default is TRUE
    Nonce: TCryptIntegerBlob;              // OPTIONAL
    cExtension: DWORD;

    rgExtension: PCertExtension;           // OPTIONAL
  end;
  {$EXTERNALSYM _CRYPT_TIMESTAMP_PARA}
  CRYPT_TIMESTAMP_PARA = _CRYPT_TIMESTAMP_PARA;
  {$EXTERNALSYM CRYPT_TIMESTAMP_PARA}
  TCryptTimestampPara = _CRYPT_TIMESTAMP_PARA;
  PCRYPT_TIMESTAMP_PARA = PCryptTimestampPara;
  {$EXTERNALSYM PCRYPT_TIMESTAMP_PARA}

//+-------------------------------------------------------------------------
//  CryptRetrieveTimeStamp
//
//  wszUrl
//     [in] Specifies TSA where to send request to.
//
//  dwRetrievalFlags
//     [in]
//         TIMESTAMP_VERIFY_CONTEXT_SIGNATURE
//         TIMESTAMP_NO_AUTH_RETRIEVAL
//         TIMESTAMP_DONT_HASH_DATA
//
//  dwTimeout
//     [in] Specifies the maximum number of milliseconds to wait for retrieval.
//     If a value of zero is specified, this function does not time-out.
//
//  pszHashId
//      [in] Specifies hash algorithm OID.
//
//  pPara
//      [in, optional] Specifies additional request parameters.
//
//  pbData
//      [in] Points to array of bytes to be timestamped.
//
//  cbData
//      [in] Number of bytes in pbData.
//
//  ppTsContext
//     [out] The caller must free ppTsContext with CryptMemFree.
//
//  ppTsSigner
//     [out, optional] The address of a CERT_CONTEXT structure pointer that
//     receives the certificate of the signer.
//     When you have finished using this structure, free it by passing this
//     pointer to the CertFreeCertificateContext function.
//     This parameter can be NULL if the TSA signer's certificate is not needed.
//
// Remarks:
//
//     The TIMESTAMP_VERIFY_CONTEXT_SIGNATURE flag can be only used,
//     if fRequestCerts value is TRUE.
//
//--------------------------------------------------------------------------
function CryptRetrieveTimeStamp(
  wszUrl: LPCWSTR;
  dwRetrievalFlags: DWORD;
  dwTimeout: DWORD;
  pszHashId: LPCSTR;
  pPara: PCryptTimestampPara;
  pbData: PByte;
  cbData: DWORD;
  out ppTsContext: PCryptTimestampContext;
  ppTsSigner: PPCertContext;
  out phStore: HCERTSTORE): BOOL; winapi;
{$EXTERNALSYM CryptRetrieveTimeStamp}

// Set this flag to inhibit hash calculation on pbData
const
  TIMESTAMP_DONT_HASH_DATA               = $00000001;
  {$EXTERNALSYM TIMESTAMP_DONT_HASH_DATA}

// Set this flag to enforce signature validation on retrieved time stamp.
const
  TIMESTAMP_VERIFY_CONTEXT_SIGNATURE     = $00000020;   // CRYPT_VERIFY_CONTEXT_SIGNATURE
  {$EXTERNALSYM TIMESTAMP_VERIFY_CONTEXT_SIGNATURE}

// Set this flag to inhibit automatic authentication handling. See the
// wininet flag, INTERNET_FLAG_NO_AUTH, for more details.
const
  TIMESTAMP_NO_AUTH_RETRIEVAL            = $00020000;  //  CRYPT_NO_AUTH_RETRIEVAL
  {$EXTERNALSYM TIMESTAMP_NO_AUTH_RETRIEVAL}

//+-------------------------------------------------------------------------
// CryptVerifyTimeStampSignature
//
//  pbTSContentInfo
//      [in] Points to a buffer with timestamp content.
//      These bytes are the same as returned in response by CRYPT_TIMESTAMP_CONTEXT::pbEncoded
//
//  cbTSContentInfo
//      [in] Number of bytes in pbTSContentInfo.
//
//  pbData
//      [in] Points to array of bytes to be timestamped.
//
//  cbData
//      [in] Number of bytes in pbData.
//
// hAdditionalStore
//    [in] Handle of any additional store to search for supporting
//    TSA's signing certificates and certificate trust lists (CTLs).
//    This parameter can be NULL if no additional store is to be searched.
//
// ppTsContext
//    [out] The caller must free ppTsContext with CryptMemFree
//
// ppTsSigner
//    [out, optional] The address of a CERT_CONTEXT structure pointer that
//    receives the certificate of the signer.
//    When you have finished using this structure, free it by passing this
//    pointer to the CertFreeCertificateContext function.
//    This parameter can be NULL if the TSA signer's certificate is not needed.
//
// NOTE:
//    The caller should validate pszTSAPolicyId, if any was specified in the request,
//    and ftTime.
//    The caller should also build a chain for ppTsSigner and validate the trust.
//--------------------------------------------------------------------------
function CryptVerifyTimeStampSignature(
  pbTSContentInfo: PByte;
  cbTSContentInfo: DWORD;
  pbData: PByte;
  cbData: DWORD;
  hAdditionalStore: HCERTSTORE;
  out ppTsContext: PCryptTimestampContext;
  ppTsSigner: PPCertContext;
  out phStore: HCERTSTORE): BOOL; winapi;
{$EXTERNALSYM CryptVerifyTimeStampSignature}



//
// Object Locator Provider API
//


const
  CRYPT_OBJECT_LOCATOR_SPN_NAME_TYPE                  = 1;   //ex. "HTTP/www.contoso.com"
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_SPN_NAME_TYPE}
  CRYPT_OBJECT_LOCATOR_LAST_RESERVED_NAME_TYPE        = 32;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_LAST_RESERVED_NAME_TYPE}
  CRYPT_OBJECT_LOCATOR_FIRST_RESERVED_USER_NAME_TYPE  = 33;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_FIRST_RESERVED_USER_NAME_TYPE}
  CRYPT_OBJECT_LOCATOR_LAST_RESERVED_USER_NAME_TYPE   = $0000FFFF;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_LAST_RESERVED_USER_NAME_TYPE}

  SSL_OBJECT_LOCATOR_PFX_FUNC                     = 'SslObjectLocatorInitializePfx';
  {$EXTERNALSYM SSL_OBJECT_LOCATOR_PFX_FUNC}
  SSL_OBJECT_LOCATOR_ISSUER_LIST_FUNC             = 'SslObjectLocatorInitializeIssuerList';
  {$EXTERNALSYM SSL_OBJECT_LOCATOR_ISSUER_LIST_FUNC}
  SSL_OBJECT_LOCATOR_CERT_VALIDATION_CONFIG_FUNC  = 'SslObjectLocatorInitializeCertValidationConfig';
  {$EXTERNALSYM SSL_OBJECT_LOCATOR_CERT_VALIDATION_CONFIG_FUNC }


//--------------------------------------------------------------------------
// Releasing the locator can be done with the following reasons
// On system shutdown and process exit, the provider is not expected to
// release all memory. However, on service stop and dll unload the provider
// should clean itself up.
//--------------------------------------------------------------------------
const
  CRYPT_OBJECT_LOCATOR_RELEASE_SYSTEM_SHUTDOWN  = 1;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_RELEASE_SYSTEM_SHUTDOWN}
  CRYPT_OBJECT_LOCATOR_RELEASE_SERVICE_STOP     = 2;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_RELEASE_SERVICE_STOP}
  CRYPT_OBJECT_LOCATOR_RELEASE_PROCESS_EXIT     = 3;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_RELEASE_PROCESS_EXIT}
  CRYPT_OBJECT_LOCATOR_RELEASE_DLL_UNLOAD       = 4;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_RELEASE_DLL_UNLOAD}


//--------------------------------------------------------------------------
// The object locator provider receives this function when it is initialized.
// The object locator provider is expected to call this function when an
// object has changed. This indicates to the application that its copy of the
// object is stale and it should get an updated object.
//
// pContext
//    This is the context pararameter passed into the object locator providers
//    initialize function. The object locator provider must hold onto this context
//    and pass it back into this flush function.
//
// rgIdentifierOrNameList
//    An array of name/identifier blobs for objects that are stale. If an object
//    has an identifier then pass in the identifier name. If an object does not have
//    an identifier then pass in the name. You can pass in NULL which indicates all
//    objects are stale but this is not recommended for performance reasons.
//
// dwIdentifierOrNameListCount
//    Number of names/identifiers in the array. 0 implies that rgIdentifierOrNameList
//    is NULL which means all objects are stale.
//
//--------------------------------------------------------------------------
type
  PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FLUSH = function(
    pContext: LPVOID;
    var rgIdentifierOrNameList: PCertNameBlob;
    dwIdentifierOrNameListCount: DWORD): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FLUSH}
  TFnCryptObjectLocatorProviderFlush = PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FLUSH;


//--------------------------------------------------------------------------
// An application will call on the object provider with the GET function when
// the application needs an object. The name blob uniquely identifies the content
// to return. This function can return an identifier data blob. Subsequent calls
// to this function for the same object will pass in the identifier that was previously
// returned. The identifier does not need to uniquely identify a particular object.
//
// pPluginContext
//    This is the context that is returned by the object locator provider when
//    it is initialized.
//
// pIdentifier
//    This is the identifier that was returned on a previous GET call for this object.
//    On the first call for a particular object it is always NULL.
//
// dwNameType, pNameBlob
//    The name the application is using for the object. The name will uniquely identify
//    an object.
//
// ppContent, pcbContent
//    The returned object.
//
// ppwszPassword
//    If the returned object is a pfx then this is the password for the pfx.
//
// ppIdentifier
//    The identifier for the object.
//--------------------------------------------------------------------------
type
  PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET = function(
    pPluginContext: LPVOID;
    pIdentifier: PCryptDataBlob;
    dwNameType: DWORD;
    pNameBlob: PCertNameBlob;
    out ppbContent: PBYTE;
    out pcbContent: DWORD;
    out ppwszPassword: PCWSTR;
    out ppIdentifier: PCryptDataBlob): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET}
  TFnCryptObjectLocatorProviderGet = PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET;


//--------------------------------------------------------------------------
// The application has indicated it no longer needs to locate objects by
// calling this release function.
//
// dwReason
//   Can be one of:
//       CRYPT_OBJECT_LOCATOR_RELEASE_SYSTEM_SHUTDOWN
//       CRYPT_OBJECT_LOCATOR_RELEASE_SERVICE_STOP
//       CRYPT_OBJECT_LOCATOR_RELEASE_PROCESS_EXIT
//       CRYPT_OBJECT_LOCATOR_RELEASE_DLL_UNLOAD
//
//  pPluginContext
//    This is the context that is returned by the object locator provider when
//    it is initialized.
//--------------------------------------------------------------------------
type
  PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_RELEASE = procedure(
    dwReason: DWORD;
    pPluginContext: LPVOID); winapi;
  {$EXTERNALSYM PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_RELEASE}
  TFnCryptObjectLocatorProviderRelease = PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_RELEASE;

//--------------------------------------------------------------------------
// If the PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET function returns a password
// that is non-NULL then this function will be called to release the memory.
// Best practice is to zero the memory before releasing it.
//
//  pPluginContext
//    This is the context that is returned by the object locator provider when
//    it is initialized.
//
//  pwszPassword
//    Password obtained from PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET
//--------------------------------------------------------------------------
type
  PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_PASSWORD = procedure(
    pPluginContext: LPVOID;
    pwszPassword: PCWSTR); winapi;
  {$EXTERNALSYM PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_PASSWORD}
  TFnCryptObjectLocatorProviderFreePassword = PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_PASSWORD;

//--------------------------------------------------------------------------
// The content returned by the PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET function
// is released using this function.
//
//  pPluginContext
//    This is the context that is returned by the object locator provider when
//    it is initialized.
//
//  pbData
//    Content returned by the GET function.
//--------------------------------------------------------------------------
type
  PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE = procedure(
    pPluginContext: LPVOID;
    pbData: PBYTE); winapi;
  {$EXTERNALSYM PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE}
  TFnCryptObjectLocatorProviderFree = PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE;

//--------------------------------------------------------------------------
//
// The identifier returned by the PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET function
// is released with this function. This will be called only if the identifier is
// non-NULL.
// The identifier will be released when the application no longer needs the
// object that was returned by the GET call.
//
// pPluginContext
//    This is the context that is returned by the object locator provider when
//    it is initialized.
//
// pIdentifier
//    Identifier returned by the GET function.
//--------------------------------------------------------------------------
type
  PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_IDENTIFIER = procedure(
    pPluginContext: LPVOID;
    pIdentifier: PCryptDataBlob); winapi;
  {$EXTERNALSYM PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_IDENTIFIER}
  TFnCryptObjectLocatorProviderFreeIdentifier = PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_IDENTIFIER;


type
  PCryptObjectLocatorProviderTable = ^TCryptObjectLocatorProviderTable;
  _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE = record
    cbSize: DWORD;
    pfnGet: TFnCryptObjectLocatorProviderGet;
    pfnRelease: TFnCryptObjectLocatorProviderRelease;
    pfnFreePassword: TFnCryptObjectLocatorProviderFreePassword;
    pfnFree: TFnCryptObjectLocatorProviderFree;
    pfnFreeIdentifier: TFnCryptObjectLocatorProviderFreeIdentifier;
  end;
  {$EXTERNALSYM _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE}
  CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE = _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE;
  {$EXTERNALSYM CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE}
  TCryptObjectLocatorProviderTable = _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE;
  PCRYPT_OBJECT_LOCATOR_PROVIDER_TABLE = PCryptObjectLocatorProviderTable;
  {$EXTERNALSYM PCRYPT_OBJECT_LOCATOR_PROVIDER_TABLE}


//--------------------------------------------------------------------------
//
// This is the initialization function of the object locator provider.
//
// pfnFlush
//    This is the function which the provider must call when it detects that
//    an object has changed and the calling application should know about it
//    to prevent stale copies of the object from being used.
//
// pContext
//    This context is passed to the intialization function. The provider
//    is expected to hold onto this context and pass it back with the call
//    call to the flush function
//
// pdwExpectedObjectCount
//    The number of objects that the provider expects it will need to locate.
//    This number will determine the size of a hash table used internally.
//
// pFuncTable
//    A structure that describes a set of callback functions which can be used
//    to get objects and free objects.
//
// ppPluginContext
//    Extra information that the provider can return in its initialize call which
//    will be passed back to each of the subsequent callback functions.
//--------------------------------------------------------------------------
type
  PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_INITIALIZE = function(
    pfnFlush: TFnCryptObjectLocatorProviderFlush;
    pContext: LPVOID;
    out pdwExpectedObjectCount: DWORD;
    out ppFuncTable: PCryptObjectLocatorProviderTable;
    out ppPluginContext: Pointer): BOOL; winapi;
  {$EXTERNALSYM PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_INITIALIZE}
  TFnCryptObjectLocatorProviderInitialize = PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_INITIALIZE;

{$ENDREGION}


implementation

const
  Advapi32Dll = 'advapi32.dll';
  Crypt32Dll = 'crypt32.dll';
  CryptNetDll = 'cryptnet.dll';

{$REGION 'wincrypt.h'}
function CryptAcquireContextA; external Advapi32Dll name 'CryptAcquireContextA';
function CryptAcquireContextW; external Advapi32Dll name 'CryptAcquireContextW';
function CryptAcquireContext; external Advapi32Dll name 'CryptAcquireContextW';
function CryptReleaseContext; external Advapi32Dll name 'CryptReleaseContext';
function CryptGenKey; external Advapi32Dll name 'CryptGenKey';
function CryptDeriveKey; external Advapi32Dll name 'CryptDeriveKey';
function CryptDestroyKey; external Advapi32Dll name 'CryptDestroyKey';
function CryptSetKeyParam; external Advapi32Dll name 'CryptSetKeyParam';
function CryptGetKeyParam; external Advapi32Dll name 'CryptGetKeyParam';
function CryptSetHashParam; external Advapi32Dll name 'CryptSetHashParam';
function CryptGetHashParam; external Advapi32Dll name 'CryptGetHashParam';
function CryptSetProvParam; external Advapi32Dll name 'CryptSetProvParam';
function CryptGetProvParam; external Advapi32Dll name 'CryptGetProvParam';
function CryptGenRandom; external Advapi32Dll name 'CryptGenRandom';
function CryptGetUserKey; external Advapi32Dll name 'CryptGetUserKey';
function CryptExportKey; external Advapi32Dll name 'CryptExportKey';
function CryptImportKey; external Advapi32Dll name 'CryptImportKey';
function CryptEncrypt; external Advapi32Dll name 'CryptEncrypt';
function CryptDecrypt; external Advapi32Dll name 'CryptDecrypt';
function CryptCreateHash; external Advapi32Dll name 'CryptCreateHash';
function CryptHashData; external Advapi32Dll name 'CryptHashData';
function CryptHashSessionKey; external Advapi32Dll name 'CryptHashSessionKey';
function CryptDestroyHash; external Advapi32Dll name 'CryptDestroyHash';
function CryptSignHashA; external Advapi32Dll name 'CryptSignHashA';
function CryptSignHashW; external Advapi32Dll name 'CryptSignHashW';
function CryptSignHash; external Advapi32Dll name 'CryptSignHashW';
function CryptVerifySignatureA; external Advapi32Dll name 'CryptVerifySignatureA';
function CryptVerifySignatureW; external Advapi32Dll name 'CryptVerifySignatureW';
function CryptVerifySignature; external Advapi32Dll name 'CryptVerifySignatureW';
function CryptSetProviderA; external Advapi32Dll name 'CryptSetProviderA';
function CryptSetProviderW; external Advapi32Dll name 'CryptSetProviderW';
function CryptSetProvider; external Advapi32Dll name 'CryptSetProviderW';
function CryptSetProviderExA; external Advapi32Dll name 'CryptSetProviderExA';
function CryptSetProviderExW; external Advapi32Dll name 'CryptSetProviderExW';
function CryptSetProviderEx; external Advapi32Dll name 'CryptSetProviderExW';
function CryptGetDefaultProviderA; external Advapi32Dll name 'CryptGetDefaultProviderA';
function CryptGetDefaultProviderW; external Advapi32Dll name 'CryptGetDefaultProviderW';
function CryptGetDefaultProvider; external Advapi32Dll name 'CryptGetDefaultProviderW';
function CryptEnumProviderTypesA; external Advapi32Dll name 'CryptEnumProviderTypesA';
function CryptEnumProviderTypesW; external Advapi32Dll name 'CryptEnumProviderTypesW';
function CryptEnumProviderTypes; external Advapi32Dll name 'CryptEnumProviderTypesW';
function CryptEnumProvidersA; external Advapi32Dll name 'CryptEnumProvidersA';
function CryptEnumProvidersW; external Advapi32Dll name 'CryptEnumProvidersW';
function CryptEnumProviders; external Advapi32Dll name 'CryptEnumProvidersW';
function CryptContextAddRef; external Advapi32Dll name 'CryptContextAddRef';
function CryptDuplicateKey; external Advapi32Dll name 'CryptDuplicateKey';
function CryptDuplicateHash; external Advapi32Dll name 'CryptDuplicateHash';

function GetEncSChannel; external Advapi32Dll name '';

function CryptFormatObject; external Crypt32Dll name 'CryptFormatObject';

function CryptEncodeObjectEx; external Crypt32Dll name 'CryptEncodeObjectEx';
function CryptEncodeObject; external Crypt32Dll name 'CryptEncodeObject';

function CryptDecodeObjectEx; external Crypt32Dll name 'CryptDecodeObjectEx';
function CryptDecodeObject; external Crypt32Dll name 'CryptDecodeObject';

function CryptInstallOIDFunctionAddress; external Crypt32Dll name 'CryptInstallOIDFunctionAddress';
function CryptInitOIDFunctionSet; external Crypt32Dll name 'CryptInitOIDFunctionSet';
function CryptGetOIDFunctionAddress; external Crypt32Dll name 'CryptGetOIDFunctionAddress';
function CryptGetDefaultOIDDllList; external Crypt32Dll name 'CryptGetDefaultOIDDllList';
function CryptGetDefaultOIDFunctionAddress; external Crypt32Dll name 'CryptGetDefaultOIDFunctionAddress';
function CryptFreeOIDFunctionAddress; external Crypt32Dll name 'CryptFreeOIDFunctionAddress';
function CryptRegisterOIDFunction; external Crypt32Dll name 'CryptRegisterOIDFunction';
function CryptUnregisterOIDFunction; external Crypt32Dll name 'CryptUnregisterOIDFunction';
function CryptRegisterDefaultOIDFunction; external Crypt32Dll name 'CryptRegisterDefaultOIDFunction';
function CryptUnregisterDefaultOIDFunction; external Crypt32Dll name 'CryptUnregisterDefaultOIDFunction';
function CryptSetOIDFunctionValue; external Crypt32Dll name 'CryptSetOIDFunctionValue';
function CryptGetOIDFunctionValue; external Crypt32Dll name 'CryptGetOIDFunctionValue';
function CryptEnumOIDFunction; external Crypt32Dll name 'CryptEnumOIDFunction';
function CryptFindOIDInfo; external Crypt32Dll name 'CryptFindOIDInfo';
function CryptRegisterOIDInfo; external Crypt32Dll name 'CryptRegisterOIDInfo';
function CryptUnregisterOIDInfo; external Crypt32Dll name 'CryptUnregisterOIDInfo';
function CryptEnumOIDInfo; external Crypt32Dll name 'CryptEnumOIDInfo';
function CryptFindLocalizedName; external Crypt32Dll name 'CryptFindLocalizedName';

function CryptMsgOpenToEncode; external Crypt32Dll name 'CryptMsgOpenToEncode';
function CryptMsgCalculateEncodedLength; external Crypt32Dll name 'CryptMsgCalculateEncodedLength';
function CryptMsgOpenToDecode; external Crypt32Dll name 'CryptMsgOpenToDecode';
function CryptMsgDuplicate; external Crypt32Dll name 'CryptMsgDuplicate';
function CryptMsgClose; external Crypt32Dll name 'CryptMsgClose';
function CryptMsgUpdate; external Crypt32Dll name 'CryptMsgUpdate';
function CryptMsgGetParam; external Crypt32Dll name 'CryptMsgGetParam';
function CryptMsgControl; external Crypt32Dll name 'CryptMsgControl';
function CryptMsgVerifyCountersignatureEncoded; external Crypt32Dll name 'CryptMsgVerifyCountersignatureEncoded';
function CryptMsgVerifyCountersignatureEncodedEx; external Crypt32Dll name 'CryptMsgVerifyCountersignatureEncodedEx';
function CryptMsgCountersign; external Crypt32Dll name 'CryptMsgCountersign';
function CryptMsgCountersignEncoded; external Crypt32Dll name 'CryptMsgCountersignEncoded';

function CertOpenStore; external Crypt32Dll name 'CertOpenStore';
function CertDuplicateStore; external Crypt32Dll name 'CertDuplicateStore';
function CertSaveStore; external Crypt32Dll name 'CertSaveStore';
function CertCloseStore; external Crypt32Dll name 'CertCloseStore';
function CertGetSubjectCertificateFromStore; external Crypt32Dll name 'CertGetSubjectCertificateFromStore';
function CertEnumCertificatesInStore; external Crypt32Dll name 'CertEnumCertificatesInStore';
function CertFindCertificateInStore; external Crypt32Dll name 'CertFindCertificateInStore';
function CertGetIssuerCertificateFromStore; external Crypt32Dll name 'CertGetIssuerCertificateFromStore';
function CertVerifySubjectCertificateContext; external Crypt32Dll name 'CertVerifySubjectCertificateContext';
function CertDuplicateCertificateContext; external Crypt32Dll name 'CertDuplicateCertificateContext';
function CertCreateCertificateContext; external Crypt32Dll name 'CertCreateCertificateContext';
function CertFreeCertificateContext; external Crypt32Dll name 'CertFreeCertificateContext';
function CertSetCertificateContextProperty; external Crypt32Dll name 'CertSetCertificateContextProperty';
function CertGetCertificateContextProperty; external Crypt32Dll name 'CertGetCertificateContextProperty';
function CertEnumCertificateContextProperties; external Crypt32Dll name 'CertEnumCertificateContextProperties';
function CertCreateCTLEntryFromCertificateContextProperties; external Crypt32Dll name 'CertCreateCTLEntryFromCertificateContextProperties';
function CertSetCertificateContextPropertiesFromCTLEntry; external Crypt32Dll name 'CertSetCertificateContextPropertiesFromCTLEntry';
function CertGetCRLFromStore; external Crypt32Dll name 'CertGetCRLFromStore';
function CertEnumCRLsInStore; external Crypt32Dll name 'CertEnumCRLsInStore';
function CertFindCRLInStore; external Crypt32Dll name 'CertFindCRLInStore';
function CertDuplicateCRLContext; external Crypt32Dll name 'CertDuplicateCRLContext';
function CertCreateCRLContext; external Crypt32Dll name 'CertCreateCRLContext';
function CertFreeCRLContext; external Crypt32Dll name 'CertFreeCRLContext';
function CertSetCRLContextProperty; external Crypt32Dll name 'CertSetCRLContextProperty';
function CertGetCRLContextProperty; external Crypt32Dll name 'CertGetCRLContextProperty';
function CertEnumCRLContextProperties; external Crypt32Dll name 'CertEnumCRLContextProperties';
function CertFindCertificateInCRL; external Crypt32Dll name 'CertFindCertificateInCRL';
function CertIsValidCRLForCertificate; external Crypt32Dll name 'CertIsValidCRLForCertificate';
function CertAddEncodedCertificateToStore; external Crypt32Dll name 'CertAddEncodedCertificateToStore';
function CertAddCertificateContextToStore; external Crypt32Dll name 'CertAddCertificateContextToStore';
function CertAddSerializedElementToStore; external Crypt32Dll name 'CertAddSerializedElementToStore';
function CertDeleteCertificateFromStore; external Crypt32Dll name 'CertDeleteCertificateFromStore';
function CertAddEncodedCRLToStore; external Crypt32Dll name 'CertAddEncodedCRLToStore';
function CertAddCRLContextToStore; external Crypt32Dll name 'CertAddCRLContextToStore';
function CertDeleteCRLFromStore; external Crypt32Dll name 'CertDeleteCRLFromStore';
function CertSerializeCertificateStoreElement; external Crypt32Dll name 'CertSerializeCertificateStoreElement';
function CertSerializeCRLStoreElement; external Crypt32Dll name 'CertSerializeCRLStoreElement';

function CertDuplicateCTLContext; external Crypt32Dll name 'CertDuplicateCTLContext';
function CertCreateCTLContext; external Crypt32Dll name 'CertCreateCTLContext';
function CertFreeCTLContext; external Crypt32Dll name 'CertFreeCTLContext';
function CertSetCTLContextProperty; external Crypt32Dll name 'CertSetCTLContextProperty';
function CertGetCTLContextProperty; external Crypt32Dll name 'CertGetCTLContextProperty';
function CertEnumCTLContextProperties; external Crypt32Dll name 'CertEnumCTLContextProperties';
function CertEnumCTLsInStore; external Crypt32Dll name 'CertEnumCTLsInStore';
function CertFindSubjectInCTL; external Crypt32Dll name 'CertFindSubjectInCTL';
function CertFindCTLInStore; external Crypt32Dll name 'CertFindCTLInStore';
function CertAddEncodedCTLToStore; external Crypt32Dll name 'CertAddEncodedCTLToStore';
function CertAddCTLContextToStore; external Crypt32Dll name 'CertAddCTLContextToStore';
function CertSerializeCTLStoreElement; external Crypt32Dll name 'CertSerializeCTLStoreElement';
function CertDeleteCTLFromStore; external Crypt32Dll name 'CertDeleteCTLFromStore';
function CertAddCertificateLinkToStore; external Crypt32Dll name 'CertAddCertificateLinkToStore';
function CertAddCRLLinkToStore; external Crypt32Dll name 'CertAddCRLLinkToStore';
function CertAddCTLLinkToStore; external Crypt32Dll name 'CertAddCTLLinkToStore';
function CertAddStoreToCollection; external Crypt32Dll name 'CertAddStoreToCollection';
procedure CertRemoveStoreFromCollection; external Crypt32Dll name 'CertRemoveStoreFromCollection';
function CertControlStore; external Crypt32Dll name 'CertControlStore';

function CertSetStoreProperty; external Crypt32Dll name 'CertSetStoreProperty';
function CertGetStoreProperty; external Crypt32Dll name 'CertGetStoreProperty';
function CertCreateContext; external Crypt32Dll name 'CertCreateContext';

function CertRegisterSystemStore; external Crypt32Dll name 'CertRegisterSystemStore';
function CertRegisterPhysicalStore; external Crypt32Dll name 'CertRegisterPhysicalStore';
function CertUnregisterSystemStore; external Crypt32Dll name 'CertUnregisterSystemStore';
function CertUnregisterPhysicalStore; external Crypt32Dll name 'CertUnregisterPhysicalStore';
function CertEnumSystemStoreLocation; external Crypt32Dll name 'CertEnumSystemStoreLocation';
function CertEnumSystemStore; external Crypt32Dll name 'CertEnumSystemStore';
function CertEnumPhysicalStore; external Crypt32Dll name 'CertEnumPhysicalStore';

function CertGetEnhancedKeyUsage; external Crypt32Dll name 'CertGetEnhancedKeyUsage';
function CertSetEnhancedKeyUsage; external Crypt32Dll name 'CertSetEnhancedKeyUsage';
function CertAddEnhancedKeyUsageIdentifier; external Crypt32Dll name 'CertAddEnhancedKeyUsageIdentifier';
function CertRemoveEnhancedKeyUsageIdentifier; external Crypt32Dll name 'CertRemoveEnhancedKeyUsageIdentifier';
function CertGetValidUsages; external Crypt32Dll name 'CertGetValidUsages';

function CryptMsgGetAndVerifySigner; external Crypt32Dll name 'CryptMsgGetAndVerifySigner';
function CryptMsgSignCTL; external Crypt32Dll name 'CryptMsgSignCTL';
function CryptMsgEncodeAndSignCTL; external Crypt32Dll name 'CryptMsgEncodeAndSignCTL';
function CertFindSubjectInSortedCTL; external Crypt32Dll name 'CertFindSubjectInSortedCTL';
function CertEnumSubjectInSortedCTL; external Crypt32Dll name 'CertEnumSubjectInSortedCTL';
function CertVerifyCTLUsage; external Crypt32Dll name 'CertVerifyCTLUsage';

function CertVerifyRevocation; external Crypt32Dll name 'CertVerifyRevocation';

function CertCompareIntegerBlob; external Crypt32Dll name 'CertCompareIntegerBlob';
function CertCompareCertificate; external Crypt32Dll name 'CertCompareCertificate';
function CertCompareCertificateName; external Crypt32Dll name 'CertCompareCertificateName';
function CertIsRDNAttrsInCertificateName; external Crypt32Dll name 'CertIsRDNAttrsInCertificateName';
function CertComparePublicKeyInfo; external Crypt32Dll name 'CertComparePublicKeyInfo';
function CertGetPublicKeyLength; external Crypt32Dll name 'CertGetPublicKeyLength';
function CryptVerifyCertificateSignature; external Crypt32Dll name 'CryptVerifyCertificateSignature';
function CryptVerifyCertificateSignatureEx; external Crypt32Dll name 'CryptVerifyCertificateSignatureEx';
function CertIsStrongHashToSign; external Crypt32Dll name 'CertIsStrongHashToSign' delayed;
function CryptHashToBeSigned; external Crypt32Dll name 'CryptHashToBeSigned';
function CryptHashCertificate; external Crypt32Dll name 'CryptHashCertificate';
function CryptHashCertificate2; external Crypt32Dll name 'CryptHashCertificate2' delayed;
function CryptSignCertificate; external Crypt32Dll name 'CryptSignCertificate';
function CryptSignAndEncodeCertificate; external Crypt32Dll name 'CryptSignAndEncodeCertificate';
function CertVerifyTimeValidity; external Crypt32Dll name 'CertVerifyTimeValidity';
function CertVerifyCRLTimeValidity; external Crypt32Dll name 'CertVerifyCRLTimeValidity';
function CertVerifyValidityNesting; external Crypt32Dll name 'CertVerifyValidityNesting';
function CertVerifyCRLRevocation; external Crypt32Dll name 'CertVerifyCRLRevocation';
function CertAlgIdToOID; external Crypt32Dll name 'CertAlgIdToOID';
function CertOIDToAlgId; external Crypt32Dll name 'CertOIDToAlgId';
function CertFindExtension; external Crypt32Dll name 'CertFindExtension';
function CertFindAttribute; external Crypt32Dll name 'CertFindAttribute';
function CertFindRDNAttr; external Crypt32Dll name 'CertFindRDNAttr';
function CertGetIntendedKeyUsage; external Crypt32Dll name 'CertGetIntendedKeyUsage';
function CryptInstallDefaultContext; external Crypt32Dll name 'CryptInstallDefaultContext';
function CryptUninstallDefaultContext; external Crypt32Dll name 'CryptUninstallDefaultContext';
function CryptExportPublicKeyInfo; external Crypt32Dll name 'CryptExportPublicKeyInfo';
function CryptExportPublicKeyInfoEx; external Crypt32Dll name 'CryptExportPublicKeyInfoEx';
function CryptExportPublicKeyInfoFromBCryptKeyHandle; external Crypt32Dll name 'CryptExportPublicKeyInfoFromBCryptKeyHandle' delayed;
function CryptImportPublicKeyInfo; external Crypt32Dll name 'CryptImportPublicKeyInfo';
function CryptImportPublicKeyInfoEx; external Crypt32Dll name 'CryptImportPublicKeyInfoEx';
function CryptImportPublicKeyInfoEx2; external Crypt32Dll name 'CryptImportPublicKeyInfoEx2' delayed;
function CryptAcquireCertificatePrivateKey; external Crypt32Dll name 'CryptAcquireCertificatePrivateKey';
function CryptFindCertificateKeyProvInfo; external Crypt32Dll name 'CryptFindCertificateKeyProvInfo';
function CryptImportPKCS8; external Crypt32Dll name 'CryptImportPKCS8';
function CryptExportPKCS8; external Crypt32Dll name 'CryptExportPKCS8';
function CryptExportPKCS8Ex; external Crypt32Dll name 'CryptExportPKCS8Ex';
function CryptHashPublicKeyInfo; external Crypt32Dll name 'CryptHashPublicKeyInfo';
function CertRDNValueToStrA; external Crypt32Dll name 'CertRDNValueToStrA';
function CertRDNValueToStrW; external Crypt32Dll name 'CertRDNValueToStrW';
function CertRDNValueToStr; external Crypt32Dll name 'CertRDNValueToStrW';
function CertNameToStrA; external Crypt32Dll name 'CertNameToStrA';
function CertNameToStrW; external Crypt32Dll name 'CertNameToStrW';
function CertNameToStr; external Crypt32Dll name 'CertNameToStrW';
function CertStrToNameA; external Crypt32Dll name 'CertStrToNameA';
function CertStrToNameW; external Crypt32Dll name 'CertStrToNameW';
function CertStrToName; external Crypt32Dll name 'CertStrToNameW';
function CertGetNameStringA; external Crypt32Dll name 'CertGetNameStringA';
function CertGetNameStringW; external Crypt32Dll name 'CertGetNameStringW';
function CertGetNameString; external Crypt32Dll name 'CertGetNameStringW';

function CryptSignMessage; external Crypt32Dll name 'CryptSignMessage';
function CryptVerifyMessageSignature; external Crypt32Dll name 'CryptVerifyMessageSignature';
function CryptGetMessageSignerCount; external Crypt32Dll name 'CryptGetMessageSignerCount';
function CryptGetMessageCertificates; external Crypt32Dll name 'CryptGetMessageCertificates';
function CryptVerifyDetachedMessageSignature; external Crypt32Dll name 'CryptVerifyDetachedMessageSignature';
function CryptEncryptMessage; external Crypt32Dll name 'CryptEncryptMessage';
function CryptDecryptMessage; external Crypt32Dll name 'CryptDecryptMessage';
function CryptSignAndEncryptMessage; external Crypt32Dll name 'CryptSignAndEncryptMessage';
function CryptDecryptAndVerifyMessageSignature; external Crypt32Dll name '';
function CryptDecodeMessage; external Crypt32Dll name 'CryptDecodeMessage';
function CryptHashMessage; external Crypt32Dll name 'CryptHashMessage';
function CryptVerifyMessageHash; external Crypt32Dll name 'CryptVerifyMessageHash';
function CryptVerifyDetachedMessageHash; external Crypt32Dll name 'CryptVerifyDetachedMessageHash';
function CryptSignMessageWithKey; external Crypt32Dll name 'CryptSignMessageWithKey';
function CryptVerifyMessageSignatureWithKey; external Crypt32Dll name 'CryptVerifyMessageSignatureWithKey';

function CertOpenSystemStoreA; external Crypt32Dll name 'CertOpenSystemStoreA';
function CertOpenSystemStoreW; external Crypt32Dll name 'CertOpenSystemStoreW';
function CertOpenSystemStore; external Crypt32Dll name 'CertOpenSystemStoreW';
function CertAddEncodedCertificateToSystemStoreA; external Crypt32Dll name 'CertAddEncodedCertificateToSystemStoreA';
function CertAddEncodedCertificateToSystemStoreW; external Crypt32Dll name 'CertAddEncodedCertificateToSystemStoreW';
function CertAddEncodedCertificateToSystemStore; external Crypt32Dll name 'CertAddEncodedCertificateToSystemStoreW';
function FindCertsByIssuer; external Crypt32Dll name '';
function CryptQueryObject; external Crypt32Dll name 'CryptQueryObject';
function CryptMemAlloc; external Crypt32Dll name 'CryptMemAlloc';
function CryptMemRealloc; external Crypt32Dll name 'CryptMemRealloc';
procedure CryptMemFree; external Crypt32Dll name 'CryptMemFree';
function CryptCreateAsyncHandle; external Crypt32Dll name 'CryptCreateAsyncHandle';
function CryptSetAsyncParam; external Crypt32Dll name 'CryptSetAsyncParam';
function CryptGetAsyncParam; external Crypt32Dll name 'CryptGetAsyncParam';
function CryptCloseAsyncHandle; external Crypt32Dll name 'CryptCloseAsyncHandle';
function CryptRetrieveObjectByUrlA; external CryptNetDll name 'CryptRetrieveObjectByUrlA';
function CryptRetrieveObjectByUrlW; external CryptNetDll name 'CryptRetrieveObjectByUrlW';
function CryptRetrieveObjectByUrl; external CryptNetDll name 'CryptRetrieveObjectByUrlW';
function CryptInstallCancelRetrieval; external CryptNetDll name 'CryptInstallCancelRetrieval';
function CryptUninstallCancelRetrieval; external CryptNetDll name 'CryptUninstallCancelRetrieval';
function CryptCancelAsyncRetrieval; external CryptNetDll name 'CryptCancelAsyncRetrieval';
function CryptGetObjectUrl; external CryptNetDll name 'CryptGetObjectUrl';
function CryptGetTimeValidObject; external CryptNetDll name 'CryptGetTimeValidObject' delayed;
function CryptFlushTimeValidObject; external CryptNetDll name '';

function CertCreateSelfSignCertificate; external Crypt32Dll name 'CertCreateSelfSignCertificate';

function CryptGetKeyIdentifierProperty; external Crypt32Dll name 'CryptGetKeyIdentifierProperty';
function CryptSetKeyIdentifierProperty; external Crypt32Dll name 'CryptSetKeyIdentifierProperty';
function CryptEnumKeyIdentifierProperties; external Crypt32Dll name 'CryptEnumKeyIdentifierProperties';
function CryptCreateKeyIdentifierFromCSP; external Crypt32Dll name 'CryptCreateKeyIdentifierFromCSP';

function CertCreateCertificateChainEngine; external Crypt32Dll name 'CertCreateCertificateChainEngine';
procedure CertFreeCertificateChainEngine; external Crypt32Dll name 'CertFreeCertificateChainEngine';
function CertResyncCertificateChainEngine; external Crypt32Dll name 'CertResyncCertificateChainEngine';
function CertGetCertificateChain; external Crypt32Dll name 'CertGetCertificateChain';
procedure CertFreeCertificateChain; external Crypt32Dll name 'CertFreeCertificateChain';
function CertDuplicateCertificateChain; external Crypt32Dll name 'CertDuplicateCertificateChain';
function CertFindChainInStore; external Crypt32Dll name 'CertFindChainInStore';

function CertVerifyCertificateChainPolicy; external Crypt32Dll name 'CertVerifyCertificateChainPolicy';
function CryptStringToBinaryA; external Crypt32Dll name 'CryptStringToBinaryA';
function CryptStringToBinaryW; external Crypt32Dll name 'CryptStringToBinaryW';
function CryptStringToBinary; external Crypt32Dll name 'CryptStringToBinaryW';
function CryptBinaryToStringA; external Crypt32Dll name 'CryptBinaryToStringA';
function CryptBinaryToStringW; external Crypt32Dll name 'CryptBinaryToStringW';
function CryptBinaryToString; external Crypt32Dll name 'CryptBinaryToStringW';

function PFXImportCertStore; external Crypt32Dll name 'PFXImportCertStore';
function PFXIsPFXBlob; external Crypt32Dll name 'PFXIsPFXBlob';
function PFXVerifyPassword; external Crypt32Dll name 'PFXVerifyPassword';
function PFXExportCertStoreEx; external Crypt32Dll name 'PFXExportCertStoreEx';
function PFXExportCertStore; external Crypt32Dll name 'PFXExportCertStore';

function CertOpenServerOcspResponse; external Crypt32Dll name 'CertOpenServerOcspResponse' delayed;
procedure CertAddRefServerOcspResponse; external Crypt32Dll name 'CertAddRefServerOcspResponse' delayed;
procedure CertCloseServerOcspResponse; external Crypt32Dll name 'CertCloseServerOcspResponse' delayed;
function CertGetServerOcspResponseContext; external Crypt32Dll name 'CertGetServerOcspResponseContext' delayed;
procedure CertAddRefServerOcspResponseContext; external Crypt32Dll name 'CertAddRefServerOcspResponseContext' delayed;
procedure CertFreeServerOcspResponseContext; external Crypt32Dll name 'CertFreeServerOcspResponseContext' delayed;
function CertRetrieveLogoOrBiometricInfo; external Crypt32Dll name 'CertRetrieveLogoOrBiometricInfo' delayed;
function CertSelectCertificateChains; external Crypt32Dll name 'CertSelectCertificateChains' delayed;
procedure CertFreeCertificateChainList; external Crypt32Dll name 'CertFreeCertificateChainList' delayed;
function CryptRetrieveTimeStamp; external Crypt32Dll name 'CryptRetrieveTimeStamp' delayed;
function CryptVerifyTimeStampSignature; external Crypt32Dll name 'CryptVerifyTimeStampSignature' delayed;

function GET_ALG_CLASS(x: ALG_ID): Cardinal;
begin
  Result := (x and (7 shl 13));
end;

function GET_ALG_TYPE(x: ALG_ID): Cardinal;
begin
  Result := (x and (15 shl 9));
end;

function GET_ALG_SID(x: ALG_ID): Cardinal;
begin
  Result := x and 511;
end;

function RCRYPT_SUCCEEDED(rt: BOOL): Boolean; inline;
begin
  Result := ((rt) = CRYPT_SUCCEED);
end;

function RCRYPT_FAILED(rt: BOOL): Boolean; inline;
begin
  Result := ((rt) = CRYPT_FAILED);
end;

function IS_CERT_RDN_CHAR_STRING(X: DWORD): Boolean; inline;
begin
  Result := (((X) and CERT_RDN_TYPE_MASK) >= CERT_RDN_NUMERIC_STRING);
end;

function GET_CERT_ENCODING_TYPE(X: DWORD): DWORD; inline;
begin
  Result := (X and CERT_ENCODING_TYPE_MASK);
end;

function GET_CMSG_ENCODING_TYPE(X: DWORD): DWORD; inline;
begin
  Result := (X and CMSG_ENCODING_TYPE_MASK);
end;

function GET_CERT_UNICODE_RDN_ERR_INDEX(X: DWORD): DWORD; inline;
begin
  Result := ((X shr CERT_UNICODE_RDN_ERR_INDEX_SHIFT) and CERT_UNICODE_RDN_ERR_INDEX_MASK);
end;

function GET_CERT_UNICODE_ATTR_ERR_INDEX(X: DWORD): DWORD; inline;
begin
  Result := ((X shr CERT_UNICODE_ATTR_ERR_INDEX_SHIFT) and CERT_UNICODE_ATTR_ERR_INDEX_MASK);
end;

function GET_CERT_UNICODE_VALUE_ERR_INDEX(X: DWORD): DWORD; inline;
begin
  Result := (X and CERT_UNICODE_VALUE_ERR_INDEX_MASK);
end;

function GET_CERT_ALT_NAME_ENTRY_ERR_INDEX(X: DWORD): DWORD; inline;
begin
  Result := ((X shr CERT_ALT_NAME_ENTRY_ERR_INDEX_SHIFT) and CERT_ALT_NAME_ENTRY_ERR_INDEX_MASK);
end;

function GET_CERT_ALT_NAME_VALUE_ERR_INDEX(X: DWORD): DWORD; inline;
begin
  Result := (X and CERT_ALT_NAME_VALUE_ERR_INDEX_MASK);
end;

function GET_CRL_DIST_POINT_ERR_INDEX(X: DWORD): DWORD; inline;
begin
  Result := ((X shr CRL_DIST_POINT_ERR_INDEX_SHIFT) and CRL_DIST_POINT_ERR_INDEX_MASK);
end;

function IS_CRL_DIST_POINT_ERR_CRL_ISSUER(X: DWORD): Boolean; inline;
begin
  Result := (0 <> (X and CRL_DIST_POINT_ERR_CRL_ISSUER_BIT));
end;

function GET_CROSS_CERT_DIST_POINT_ERR_INDEX(X: DWORD): DWORD; inline;
begin
  Result := ((X shr CROSS_CERT_DIST_POINT_ERR_INDEX_SHIFT) and CROSS_CERT_DIST_POINT_ERR_INDEX_MASK);
end;

function IS_CERT_EXCLUDED_SUBTREE(X: DWORD): Boolean; inline;
begin
  Result := (0 <> (X and CERT_EXCLUDED_SUBTREE_BIT));
end;

function IS_SPECIAL_OID_INFO_ALGID(Algid: ALG_ID): Boolean; inline;
begin
  Result := (Algid >= CALG_OID_INFO_PARAMETERS);
end;

function IS_CERT_HASH_PROP_ID(X: DWORD): Boolean; inline;
begin
  Result := (CERT_SHA1_HASH_PROP_ID = X) or
            (CERT_MD5_HASH_PROP_ID = X) or
            (CERT_SIGNATURE_HASH_PROP_ID = X);
end;

function IS_PUBKEY_HASH_PROP_ID(X: DWORD): Boolean; inline;
begin
  Result := (CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = X) or
            (CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = X);
end;

function IS_CHAIN_HASH_PROP_ID(X: DWORD): Boolean; inline;
begin
  Result := (CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = X) or
            (CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = X) or
            (CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID = X) or
            (CERT_SUBJECT_NAME_MD5_HASH_PROP_ID = X);
end;

function IS_STRONG_SIGN_PROP_ID(X: DWORD): Boolean; inline;
begin
  Result := (CERT_SIGN_HASH_CNG_ALG_PROP_ID = X) or
            (CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID = X) or
            (CERT_PUB_KEY_CNG_ALG_BIT_LENGTH_PROP_ID = X);
end;

{$ENDREGION}

end.
