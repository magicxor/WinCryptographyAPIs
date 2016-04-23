unit Winapi.SslProvider;

interface

uses
  Windows, Winapi.WinCrypt, Winapi.BCrypt, Winapi.NCrypt;

{$IF not DECLARED(PVOID)}
type
  PVOID = Pointer;
  {$EXTERNALSYM PVOID}
{$IFEND}

{$REGION 'sslprovider.h'}

{$MINENUMSIZE 4}
{$WARN SYMBOL_PLATFORM OFF}

{$HPPEMIT '#include <wincrypt.h>'}


//
// Microsoft built-in providers.
//
const
  MS_SCHANNEL_PROVIDER           = 'Microsoft SSL Protocol Provider';
  {$EXTERNALSYM MS_SCHANNEL_PROVIDER}


  NCRYPT_SSL_CLIENT_FLAG = $00000001;
  {$EXTERNALSYM NCRYPT_SSL_CLIENT_FLAG}
  NCRYPT_SSL_SERVER_FLAG = $00000002;
  {$EXTERNALSYM NCRYPT_SSL_SERVER_FLAG}


//
// SSL Protocols and Cipher Suites
//

// Protocols
const
  SSL2_PROTOCOL_VERSION      = $0002;
  {$EXTERNALSYM SSL2_PROTOCOL_VERSION}
  SSL3_PROTOCOL_VERSION      = $0300;
  {$EXTERNALSYM SSL3_PROTOCOL_VERSION}
  TLS1_PROTOCOL_VERSION      = $0301;
  {$EXTERNALSYM TLS1_PROTOCOL_VERSION}

  TLS1_0_PROTOCOL_VERSION    = TLS1_PROTOCOL_VERSION;
  {$EXTERNALSYM TLS1_0_PROTOCOL_VERSION}
  TLS1_1_PROTOCOL_VERSION    = $0302;
  {$EXTERNALSYM TLS1_1_PROTOCOL_VERSION}
  TLS1_2_PROTOCOL_VERSION    = $0303;
  {$EXTERNALSYM TLS1_2_PROTOCOL_VERSION}
  DTLS1_0_PROTOCOL_VERSION   = $feff;
  {$EXTERNALSYM DTLS1_0_PROTOCOL_VERSION}

// Cipher suites
const
  TLS_RSA_WITH_NULL_MD5                      = $0001;
  {$EXTERNALSYM TLS_RSA_WITH_NULL_MD5}
  TLS_RSA_WITH_NULL_SHA                      = $0002;
  {$EXTERNALSYM TLS_RSA_WITH_NULL_SHA}
  TLS_RSA_EXPORT_WITH_RC4_40_MD5             = $0003;
  {$EXTERNALSYM TLS_RSA_EXPORT_WITH_RC4_40_MD5}
  TLS_RSA_WITH_RC4_128_MD5                   = $0004;
  {$EXTERNALSYM TLS_RSA_WITH_RC4_128_MD5}
  TLS_RSA_WITH_RC4_128_SHA                   = $0005;
  {$EXTERNALSYM TLS_RSA_WITH_RC4_128_SHA}
  TLS_RSA_WITH_DES_CBC_SHA                   = $0009;
  {$EXTERNALSYM TLS_RSA_WITH_DES_CBC_SHA}
  TLS_RSA_WITH_3DES_EDE_CBC_SHA              = $000A;
  {$EXTERNALSYM TLS_RSA_WITH_3DES_EDE_CBC_SHA}
  TLS_DHE_DSS_WITH_DES_CBC_SHA               = $0012;
  {$EXTERNALSYM TLS_DHE_DSS_WITH_DES_CBC_SHA}
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA          = $0013;
  {$EXTERNALSYM TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA}
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA          = $0016;
  {$EXTERNALSYM TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA}
  TLS_RSA_WITH_AES_128_CBC_SHA               = $002F;
  {$EXTERNALSYM TLS_RSA_WITH_AES_128_CBC_SHA}
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA           = $0032;
  {$EXTERNALSYM TLS_DHE_DSS_WITH_AES_128_CBC_SHA}
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA           = $0033;
  {$EXTERNALSYM TLS_DHE_RSA_WITH_AES_128_CBC_SHA}
  TLS_RSA_WITH_AES_256_CBC_SHA               = $0035;
  {$EXTERNALSYM TLS_RSA_WITH_AES_256_CBC_SHA}
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA           = $0038;
  {$EXTERNALSYM TLS_DHE_DSS_WITH_AES_256_CBC_SHA}
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA           = $0039;
  {$EXTERNALSYM TLS_DHE_RSA_WITH_AES_256_CBC_SHA}
  TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA        = $0062;
  {$EXTERNALSYM TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA}
  TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA    = $0063;
  {$EXTERNALSYM TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA}
  TLS_RSA_EXPORT1024_WITH_RC4_56_SHA         = $0064;
  {$EXTERNALSYM TLS_RSA_EXPORT1024_WITH_RC4_56_SHA}

// Following were added for TLS 1.2
const
  TLS_RSA_WITH_NULL_SHA256                   = $003B;
  {$EXTERNALSYM TLS_RSA_WITH_NULL_SHA256}
  TLS_RSA_WITH_AES_128_CBC_SHA256            = $003C;
  {$EXTERNALSYM TLS_RSA_WITH_AES_128_CBC_SHA256}
  TLS_RSA_WITH_AES_256_CBC_SHA256            = $003D;
  {$EXTERNALSYM TLS_RSA_WITH_AES_256_CBC_SHA256}
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256        = $0040;
  {$EXTERNALSYM TLS_DHE_DSS_WITH_AES_128_CBC_SHA256}
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256        = $006A;
  {$EXTERNALSYM TLS_DHE_DSS_WITH_AES_256_CBC_SHA256}


// PSK cipher suites
const
  TLS_PSK_WITH_3DES_EDE_CBC_SHA              = $008B;
  {$EXTERNALSYM TLS_PSK_WITH_3DES_EDE_CBC_SHA}
  TLS_PSK_WITH_AES_128_CBC_SHA               = $008C;
  {$EXTERNALSYM TLS_PSK_WITH_AES_128_CBC_SHA}
  TLS_PSK_WITH_AES_256_CBC_SHA               = $008D;
  {$EXTERNALSYM TLS_PSK_WITH_AES_256_CBC_SHA}
  TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA          = $0093;
  {$EXTERNALSYM TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA}
  TLS_RSA_PSK_WITH_AES_128_CBC_SHA           = $0094;
  {$EXTERNALSYM TLS_RSA_PSK_WITH_AES_128_CBC_SHA}
  TLS_RSA_PSK_WITH_AES_256_CBC_SHA           = $0095;
  {$EXTERNALSYM TLS_RSA_PSK_WITH_AES_256_CBC_SHA}


  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       = $c009;
  {$EXTERNALSYM TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA         = $c013;
  {$EXTERNALSYM TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       = $c00a;
  {$EXTERNALSYM TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA         = $c014;
  {$EXTERNALSYM TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}

// Following were added for TLS 1.2
const
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256    = $C023;
  {$EXTERNALSYM TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384    = $C024;
  {$EXTERNALSYM TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384}
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    = $C02B;
  {$EXTERNALSYM TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    = $C02C;
  {$EXTERNALSYM TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256      = $C027;
  {$EXTERNALSYM TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384      = $C028;
  {$EXTERNALSYM TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384}


// SSL2 cipher suites
const
  SSL_CK_RC4_128_WITH_MD5                    = $010080;
  {$EXTERNALSYM SSL_CK_RC4_128_WITH_MD5}
  SSL_CK_RC4_128_EXPORT40_WITH_MD5           = $020080;
  {$EXTERNALSYM SSL_CK_RC4_128_EXPORT40_WITH_MD5}
  SSL_CK_RC2_128_CBC_WITH_MD5                = $030080;
  {$EXTERNALSYM SSL_CK_RC2_128_CBC_WITH_MD5}
  SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5       = $040080;
  {$EXTERNALSYM SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5}
  SSL_CK_IDEA_128_CBC_WITH_MD5               = $050080;
  {$EXTERNALSYM SSL_CK_IDEA_128_CBC_WITH_MD5}
  SSL_CK_DES_64_CBC_WITH_MD5                 = $060040;
  {$EXTERNALSYM SSL_CK_DES_64_CBC_WITH_MD5}
  SSL_CK_DES_192_EDE3_CBC_WITH_MD5           = $0700C0;
  {$EXTERNALSYM SSL_CK_DES_192_EDE3_CBC_WITH_MD5}

// Key Types
// ECC curve types
const
  TLS_ECC_P256_CURVE_KEY_TYPE                = 23;
  {$EXTERNALSYM TLS_ECC_P256_CURVE_KEY_TYPE}
  TLS_ECC_P384_CURVE_KEY_TYPE                = 24;
  {$EXTERNALSYM TLS_ECC_P384_CURVE_KEY_TYPE}
  TLS_ECC_P521_CURVE_KEY_TYPE                = 25;
  {$EXTERNALSYM TLS_ECC_P521_CURVE_KEY_TYPE}

// definition for algorithms used by ssl provider
const
  SSL_ECDSA_ALGORITHM                   = 'ECDSA';
  {$EXTERNALSYM SSL_ECDSA_ALGORITHM}

// definition for szExchange field for PSK cipher suites
const
  TLS_PSK_EXCHANGE                      = 'PSK';
  {$EXTERNALSYM TLS_PSK_EXCHANGE}
  TLS_RSA_PSK_EXCHANGE                  = 'RSA_PSK';
  {$EXTERNALSYM TLS_RSA_PSK_EXCHANGE}

  NCRYPT_SSL_MAX_NAME_SIZE           = 64;
  {$EXTERNALSYM NCRYPT_SSL_MAX_NAME_SIZE}


type
  PNCryptSslCipherSuite = ^TNCryptSslCipherSuite;
  _NCRYPT_SSL_CIPHER_SUITE = record
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    dwBaseCipherSuite: DWORD;
    szCipherSuite: array [0..NCRYPT_SSL_MAX_NAME_SIZE - 1] of WCHAR;
    szCipher: array [0..NCRYPT_SSL_MAX_NAME_SIZE - 1] of WCHAR;
    dwCipherLen: DWORD;
    dwCipherBlockLen: DWORD;    // in bytes
    szHash: array [0..NCRYPT_SSL_MAX_NAME_SIZE - 1] of WCHAR;
    dwHashLen: DWORD;
    szExchange: array [0..NCRYPT_SSL_MAX_NAME_SIZE - 1] of WCHAR;
    dwMinExchangeLen: DWORD;
    dwMaxExchangeLen: DWORD;
    szCertificate: array [0..NCRYPT_SSL_MAX_NAME_SIZE - 1] of WCHAR;
    dwKeyType: DWORD;
  end;
  {$EXTERNALSYM _NCRYPT_SSL_CIPHER_SUITE}
  NCRYPT_SSL_CIPHER_SUITE = _NCRYPT_SSL_CIPHER_SUITE;
  {$EXTERNALSYM NCRYPT_SSL_CIPHER_SUITE}
  TNCryptSslCipherSuite = _NCRYPT_SSL_CIPHER_SUITE;


type
  PNCryptSslCipherLengths = ^TNCryptSslCipherLengths;
  _NCRYPT_SSL_CIPHER_LENGTHS = record
    cbLength: DWORD;
    dwHeaderLen: DWORD;
    dwFixedTrailerLen: DWORD;
    dwMaxVariableTrailerLen: DWORD;
    dwFlags: DWORD;
  end;
  {$EXTERNALSYM _NCRYPT_SSL_CIPHER_LENGTHS}
  NCRYPT_SSL_CIPHER_LENGTHS = _NCRYPT_SSL_CIPHER_LENGTHS;
  {$EXTERNALSYM NCRYPT_SSL_CIPHER_LENGTHS}
  TNCryptSslCipherLengths = _NCRYPT_SSL_CIPHER_LENGTHS;

const
  NCRYPT_SSL_CIPHER_LENGTHS_BLOCK_PADDING = $00000001;
  {$EXTERNALSYM NCRYPT_SSL_CIPHER_LENGTHS_BLOCK_PADDING}


//+-------------------------------------------------------------------------
// SslChangeNotify
//
// This function is used to register for changes to the SSL protocol
// provider configuration settings.
//--------------------------------------------------------------------------
function SslChangeNotify(
  hEvent: THandle;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslChangeNotify}


//+-------------------------------------------------------------------------
// SslComputeClientAuthHash
//
// Computes the hashes that are sent in the CertificateVerify handshake
// message.
//--------------------------------------------------------------------------
function SslComputeClientAuthHash(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hMasterKey: NCRYPT_KEY_HANDLE;
  hHandshakeHash: NCRYPT_HASH_HANDLE;
  pszAlgId: LPCWSTR;
  pbOutput: PBYTE;
  cbOutput: DWORD;
  out pcbResult: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslComputeClientAuthHash}

type
  SslComputeClientAuthHashFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hMasterKey: NCRYPT_KEY_HANDLE;
    hHandshakeHash: NCRYPT_HASH_HANDLE;
    pszAlgId: LPCWSTR;
    pbOutput: PBYTE;
    cbOutput: DWORD;
    out pcbResult: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslComputeClientAuthHashFn}
  TSslComputeClientAuthHashFn = SslComputeClientAuthHashFn;


//+-------------------------------------------------------------------------
// SslComputeEapKeyBlock
//
// Computes the key block used by EAP
//     pbRandoms must be client_random + server_random (client random
//     concatenated with the server random).
//--------------------------------------------------------------------------
function SslComputeEapKeyBlock(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hMasterKey: NCRYPT_KEY_HANDLE;
  pbRandoms: PBYTE;
  cbRandoms: DWORD;
  pbOutput: PBYTE;
  cbOutput: DWORD;
  out pcbResult: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslComputeEapKeyBlock}

type
  SslComputeEapKeyBlockFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hMasterKey: NCRYPT_KEY_HANDLE;
    pbRandoms: PBYTE;
    cbRandoms: DWORD;
    pbOutput: PBYTE;
    cbOutput: DWORD;
    out pcbResult: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslComputeEapKeyBlockFn}
  TSslComputeEapKeyBlockFn = SslComputeEapKeyBlockFn;

//
//  SslComputeEapKeyBlock flags
//
const
  NCRYPT_SSL_EAP_PRF_FIELD   = $000000ff;
  {$EXTERNALSYM NCRYPT_SSL_EAP_PRF_FIELD}
  NCRYPT_SSL_EAP_ID          = $00000000;
  {$EXTERNALSYM NCRYPT_SSL_EAP_ID}
  NCRYPT_SSL_EAP_TTLSV0_ID   = $00000001;
  {$EXTERNALSYM NCRYPT_SSL_EAP_TTLSV0_ID}
  NCRYPT_SSL_EAP_TTLSV0_CHLNG_ID = $00000002;
  {$EXTERNALSYM NCRYPT_SSL_EAP_TTLSV0_CHLNG_ID}
  NCRYPT_SSL_EAP_FAST_ID     = $00000003;
  {$EXTERNALSYM NCRYPT_SSL_EAP_FAST_ID}

//+-------------------------------------------------------------------------
// SslComputeFinishedHash
//
// Computes the hashes that are sent in the Finished handshake message.
//--------------------------------------------------------------------------
function SslComputeFinishedHash(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hMasterKey: NCRYPT_KEY_HANDLE;
  hHandshakeHash: NCRYPT_HASH_HANDLE;
  pbOutput: PBYTE;
  cbOutput: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslComputeFinishedHash}

type
  SslComputeFinishedHashFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hMasterKey: NCRYPT_KEY_HANDLE;
    hHandshakeHash: NCRYPT_HASH_HANDLE;
    pbOutput: PBYTE;
    cbOutput: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslComputeFinishedHashFn}
  TSslComputeFinishedHashFn = SslComputeFinishedHashFn;

//+-------------------------------------------------------------------------
// SslCreateEphemeralKey
//
// Creates an ephemeral key.
//--------------------------------------------------------------------------
function SslCreateEphemeralKey(
  hSslProvider: NCRYPT_PROV_HANDLE;
  out phEphemeralKey: NCRYPT_KEY_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  dwKeyType: DWORD;
  dwKeyBitLen: DWORD;
  pbParams: PBYTE;
  cbParams: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslCreateEphemeralKey}

type
  SslCreateEphemeralKeyFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    out phEphemeralKey: NCRYPT_KEY_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    dwKeyType: DWORD;
    dwKeyBitLen: DWORD;
    pbParams: PBYTE;
    cbParams: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslCreateEphemeralKeyFn}
  TSslCreateEphemeralKeyFn = SslCreateEphemeralKeyFn;


//+-------------------------------------------------------------------------
// SslCreateHandshakeHash
//
// Creates a compound hash object used to hash handshake messages.
//--------------------------------------------------------------------------
function SslCreateHandshakeHash(
  hSslProvider: NCRYPT_PROV_HANDLE;
  out phHandshakeHash: NCRYPT_HASH_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslCreateHandshakeHash}

type
  SslCreateHandshakeHashFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    out phHandshakeHash: NCRYPT_HASH_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslCreateHandshakeHashFn}
  TSslCreateHandshakeHashFn = SslCreateHandshakeHashFn;




//+-------------------------------------------------------------------------
// SslDecryptPacket
//
// Decrypts a single SSL packet.
//--------------------------------------------------------------------------
function SslDecryptPacket(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hKey: NCRYPT_KEY_HANDLE;
  pbInput: PBYTE;
  cbInput: DWORD;
  pbOutput: PBYTE;
  cbOutput: DWORD;
  out pcbResult: DWORD;
  SequenceNumber: ULONGLONG;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslDecryptPacket}

type
  SslDecryptPacketFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hKey: NCRYPT_KEY_HANDLE;
    pbInput: PBYTE;
    cbInput: DWORD;
    pbOutput: PBYTE;
    cbOutput: DWORD;
    out pcbResult: DWORD;
    SequenceNumber: ULONGLONG;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslDecryptPacketFn}
  TSslDecryptPacketFn = SslDecryptPacketFn;


//+-------------------------------------------------------------------------
// SslEncryptPacket
//
// Encrypts a single SSL packet.
//--------------------------------------------------------------------------
function SslEncryptPacket(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hKey: NCRYPT_KEY_HANDLE;
  pbInput: PBYTE;
  cbInput: DWORD;
  pbOutput: PBYTE;
  cbOutput: DWORD;
  out pcbResult: DWORD;
  SequenceNumber: ULONGLONG;
  dwContentType: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslEncryptPacket}

type
  SslEncryptPacketFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hKey: NCRYPT_KEY_HANDLE;
    pbInput: PBYTE;
    cbInput: DWORD;
    pbOutput: PBYTE;
    cbOutput: DWORD;
    out pcbResult: DWORD;
    SequenceNumber: ULONGLONG;
    dwContentType: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslEncryptPacketFn}
  TSslEncryptPacketFn = SslEncryptPacketFn;


//+-------------------------------------------------------------------------
// SslEnumCipherSuites
//
// This function is used to enumerate the list of cipher suites supported
// by an SSL protocol provider. If a private key handle is specified, then
// this function will only return cipher suites that are compatible with
// the private key.
//--------------------------------------------------------------------------
function SslEnumCipherSuites(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hPrivateKey: NCRYPT_KEY_HANDLE;
  out ppCipherSuite: PNCryptSslCipherSuite;
  var ppEnumState: PVOID;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslEnumCipherSuites}

type
  SslEnumCipherSuitesFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hPrivateKey: NCRYPT_KEY_HANDLE;
    out ppCipherSuite: PNCryptSslCipherSuite;
    var ppEnumState: PVOID;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslEnumCipherSuitesFn}
  TSslEnumCipherSuitesFn = SslEnumCipherSuitesFn;


//+-------------------------------------------------------------------------
// SslEnumProtocolProviders
//
// Returns a list of all the SSL protocol providers that are currently
// installed on the system.
//--------------------------------------------------------------------------
function SslEnumProtocolProviders(
  out pdwProviderCount: DWORD;
  out ppProviderList: PNCryptProviderName;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslEnumProtocolProviders}


//+-------------------------------------------------------------------------
// SslExportKey
//
// Exports an SSL session key into a serialized blob.
//--------------------------------------------------------------------------
function SslExportKey(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hKey: NCRYPT_KEY_HANDLE;
  pszBlobType: LPCWSTR;
  pbOutput: PBYTE;
  cbOutput: DWORD;
  out pcbResult: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslExportKey}

type
  SslExportKeyFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hKey: NCRYPT_KEY_HANDLE;
    pszBlobType: LPCWSTR;
    pbOutput: PBYTE;
    cbOutput: DWORD;
    out pcbResult: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslExportKeyFn}
  TSslExportKeyFn = SslExportKeyFn;


//+-------------------------------------------------------------------------
// SslFreeBuffer
//
// Frees a memory buffer that was allocated by one of the other SSL protocol
// provider functions.
//--------------------------------------------------------------------------
function SslFreeBuffer(
  pvInput: PVOID): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslFreeBuffer}

type
  SslFreeBufferFn = function(
    pvInput: PVOID): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslFreeBufferFn}
  TSslFreeBufferFn = SslFreeBufferFn;

//+-------------------------------------------------------------------------
// SslFreeObject
//
// Frees a key, hash, or provider object that was created using one of the
// other SSL protocol provider functions.
//--------------------------------------------------------------------------
function SslFreeObject(
  hObject: NCRYPT_HANDLE;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslFreeObject}

type
  SslFreeObjectFn = function(
    hObject: NCRYPT_HANDLE;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslFreeObjectFn}
  TSslFreeObjectFn = SslFreeObjectFn;


//+-------------------------------------------------------------------------
// SslGenerateMasterKey
//
// Perform an SSL key exchange operations. This function computes the SSL
// master secret, and returns a handle to this object to the caller. This
// master key can then be used to derive the SSL session keys and finish
// the SSL handshake.
//
// When RSA key exchange is being performed, the client-side of schannel
// calls SslGenerateMasterKey and the server-side of schannel calls
// SslImportMasterKey. When DH key exchange is being performed, schannel
// calls SslGenerateMasterKey on both the client-side and the server-side.
//--------------------------------------------------------------------------
function SslGenerateMasterKey(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hPrivateKey: NCRYPT_KEY_HANDLE;
  hPublicKey: NCRYPT_KEY_HANDLE;
  out phMasterKey: NCRYPT_KEY_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  pParameterList: PNCryptBufferDesc;
  pbOutput: PBYTE;
  cbOutput: DWORD;
  out pcbResult: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslGenerateMasterKey}

type
  SslGenerateMasterKeyFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hPrivateKey: NCRYPT_KEY_HANDLE;
    hPublicKey: NCRYPT_KEY_HANDLE;
    out phMasterKey: NCRYPT_KEY_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    pParameterList: PNCryptBufferDesc;
    pbOutput: PBYTE;
    cbOutput: DWORD;
    out pcbResult: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslGenerateMasterKeyFn}
  TSslGenerateMasterKeyFn = SslGenerateMasterKeyFn;


//+-------------------------------------------------------------------------
// SslGenerateSessionKeys
//
// Generates a set of session keys, based on a supplied master secret and
// one or more additional parameters.
//--------------------------------------------------------------------------
function SslGenerateSessionKeys(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hMasterKey: NCRYPT_KEY_HANDLE;
  out phReadKey: NCRYPT_KEY_HANDLE;
  out phWriteKey: NCRYPT_KEY_HANDLE;
  pParameterList: PNCryptBufferDesc;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslGenerateSessionKeys}

type
  SslGenerateSessionKeysFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hMasterKey: NCRYPT_KEY_HANDLE;
    out phReadKey: NCRYPT_KEY_HANDLE;
    out phWriteKey: NCRYPT_KEY_HANDLE;
    pParameterList: PNCryptBufferDesc;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslGenerateSessionKeysFn}
  TSslGenerateSessionKeysFn = SslGenerateSessionKeysFn;

// SSL provider property names.
const
  SSL_KEY_TYPE_PROPERTY               = 'KEYTYPE';
  {$EXTERNALSYM SSL_KEY_TYPE_PROPERTY}

//+-------------------------------------------------------------------------
// SslGetKeyProperty
//
// Queries information from the key.
//--------------------------------------------------------------------------
function SslGetKeyProperty(
  hKey: NCRYPT_KEY_HANDLE;
  pszProperty: LPCWSTR;
  out ppbOutput: PBYTE;
  out pcbOutput: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslGetKeyProperty}

type
  SslGetKeyPropertyFn = function(
    hKey: NCRYPT_KEY_HANDLE;
    pszProperty: LPCWSTR;
    out ppbOutput: PBYTE;
    out pcbOutput: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslGetKeyPropertyFn}
  TSslGetKeyPropertyFn = SslGetKeyPropertyFn;


//+-------------------------------------------------------------------------
// SslGetProviderProperty
//
// Queries information from the protocol provider.
//--------------------------------------------------------------------------
function SslGetProviderProperty(
  hSslProvider: NCRYPT_PROV_HANDLE;
  pszProperty: LPCWSTR;
  out ppbOutput: PBYTE;
  out pcbOutput: DWORD;
  out ppEnumState: PVOID;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslGetProviderProperty}

type
  SslGetProviderPropertyFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    pszProperty: LPCWSTR;
    out ppbOutput: PBYTE;
    out pcbOutput: DWORD;
    out ppEnumState: PVOID;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslGetProviderPropertyFn}
  TSslGetProviderPropertyFn = SslGetProviderPropertyFn;


//+-------------------------------------------------------------------------
// SslHashHandshake
//
// Adds a handshake message to the cumulative handshake hash object. This
// handshake hash is used when generating or processing Finished and
// CertificateVerify messages.
//--------------------------------------------------------------------------
function SslHashHandshake(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hHandshakeHash: NCRYPT_HASH_HANDLE;
  pbInput: PBYTE;
  cbInput: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslHashHandshake}

type
  SslHashHandshakeFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hHandshakeHash: NCRYPT_HASH_HANDLE;
    pbInput: PBYTE;
    cbInput: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslHashHandshakeFn}
  TSslHashHandshakeFn = SslHashHandshakeFn;


//+-------------------------------------------------------------------------
// SslImportKey
//
// Imports a public key into the protocol provider, as part of a key
// exchange operation. This function is also used to import session keys,
// when transferring them from one process to another.
//--------------------------------------------------------------------------
function SslImportKey(
  hSslProvider: NCRYPT_PROV_HANDLE;
  out phKey: NCRYPT_KEY_HANDLE;
  pszBlobType: LPCWSTR;
  pbKeyBlob: PBYTE;
  cbKeyBlob: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslImportKey}

type
  SslImportKeyFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    out phKey: NCRYPT_KEY_HANDLE;
    pszBlobType: LPCWSTR;
    pbKeyBlob: PBYTE;
    cbKeyBlob: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslImportKeyFn}
  TSslImportKeyFn = SslImportKeyFn;


//+-------------------------------------------------------------------------
// SslImportMasterKey
//
// This function is used when performing a server-side SSL key exchange
// operation. This function decrypts the pre-master secret, computes the
// SSL master secret, and returns a handle to this object to the caller.
// This master key can then be used to derive the SSL session keys, and
// finish the SSL handshake.
//
// Note that this function is only used when the RSA key exchange algorithm
// is being used. When DH is used, then the server-side of schannel calls
// SslGenerateMasterKey instead.
//--------------------------------------------------------------------------
function SslImportMasterKey(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hPrivateKey: NCRYPT_KEY_HANDLE;
  out phMasterKey: NCRYPT_KEY_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  pParameterList: PNCryptBufferDesc;
  pbEncryptedKey: PBYTE;
  cbEncryptedKey: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslImportMasterKey}

type
  SslImportMasterKeyFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hPrivateKey: NCRYPT_KEY_HANDLE;
    out phMasterKey: NCRYPT_KEY_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    pParameterList: PNCryptBufferDesc;
    pbEncryptedKey: PBYTE;
    cbEncryptedKey: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslImportMasterKeyFn}
  TSslImportMasterKeyFn = SslImportMasterKeyFn;

//+-------------------------------------------------------------------------
// SslLookupCipherSuiteInfo
//
// Looks up cipher suite information given the suite number and a key type.
//--------------------------------------------------------------------------
function SslLookupCipherSuiteInfo(
  hSslProvider: NCRYPT_PROV_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  dwKeyType: DWORD;
  pCipherSuite: PNCryptSslCipherSuite;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslLookupCipherSuiteInfo}

type
  SslLookupCipherSuiteInfoFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    dwKeyType: DWORD;
    pCipherSuite: PNCryptSslCipherSuite;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslLookupCipherSuiteInfoFn}
  TSslLookupCipherSuiteInfoFn = SslLookupCipherSuiteInfoFn;

//+-------------------------------------------------------------------------
// SslOpenPrivateKey
//
// This function is used to obtain a handle to the private key that
// corresponds to the passed in server certificate. This handle will be used
// by the server-side of Schannel when performing key exchange operations.
//--------------------------------------------------------------------------
function SslOpenPrivateKey(
  hSslProvider: NCRYPT_PROV_HANDLE;
  out phPrivateKey: NCRYPT_KEY_HANDLE;
  pCertContext: PCertContext;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslOpenPrivateKey}

type
  SslOpenPrivateKeyFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    out phPrivateKey: NCRYPT_KEY_HANDLE;
    pCertContext: PCertContext;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslOpenPrivateKeyFn}
  TSslOpenPrivateKeyFn = SslOpenPrivateKeyFn;

//+-------------------------------------------------------------------------
// SslOpenProvider
//
// Returns a handle to the specified protocol provider.
//--------------------------------------------------------------------------
function SslOpenProvider(
  out phSslProvider: NCRYPT_PROV_HANDLE;
  pszProviderName: LPCWSTR;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslOpenProvider}

type
  SslOpenProviderFn = function(
    out tphSslProvider: NCRYPT_PROV_HANDLE;
    pszProviderName: LPCWSTR;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslOpenProviderFn}
  TSslOpenProviderFn = SslOpenProviderFn;

//+-------------------------------------------------------------------------
// SslSignHash
//
// Signs the passed in hash with the private key specified by the passed
// in key handle.
//--------------------------------------------------------------------------
function SslSignHash(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hPrivateKey: NCRYPT_KEY_HANDLE;
  pbHashValue: PBYTE;
  cbHashValue: DWORD;
  pbSignature: PBYTE;
  cbSignature: DWORD;
  out pcbResult: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslSignHash}

type
  SslSignHashFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hPrivateKey: NCRYPT_KEY_HANDLE;
    pbHashValue: PBYTE;
    cbHashValue: DWORD;
    pbSignature: PBYTE;
    cbSignature: DWORD;
    out pcbResult: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslSignHashFn}
  TSslSignHashFn = SslSignHashFn;


//
// The following flag is set to include the hash OID in an RSASSA-PKCS1-v1_5
// signature according to the TLS 1.2 RFC. The null-terminated
// Unicode string that identifies the cryptographic algorithm to use to create
// the BCRYPT PKCS1 padding is passed at the start of the pbHashValue
// parameter. The hash bytes immediately follow the Unicode NULL terminator
// character (L'\0'). The cbHashValue includes the byte length of this
// Unicode string.
//
// This flag is only applicable to TLS 1.2 RSA signatures and MUST NOT be set
// for other protocols, such as, TLS 1.0 or other signature types like
// DSA or ECDSA.
//
const
  NCRYPT_SSL_SIGN_INCLUDE_HASHOID = $00000001;
  {$EXTERNALSYM NCRYPT_SSL_SIGN_INCLUDE_HASHOID}

//+-------------------------------------------------------------------------
// SslVerifySignature
//
// Verifies the passed in signature with the passed in hash and the
// passed in public key.
//--------------------------------------------------------------------------
function SslVerifySignature(
  hSslProvider: NCRYPT_PROV_HANDLE;
  hPublicKey: NCRYPT_KEY_HANDLE;
  pbHashValue: PBYTE;
  cbHashValue: DWORD;
  pbSignature: PBYTE;
  cbSignature: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslVerifySignature}

type
  SslVerifySignatureFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    hPublicKey: NCRYPT_KEY_HANDLE;
    pbHashValue: PBYTE;
    cbHashValue: DWORD;
    pbSignature: PBYTE;
    cbSignature: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslVerifySignatureFn}
  TSslVerifySignatureFn = SslVerifySignatureFn;

//+-------------------------------------------------------------------------
// SslCreateClientAuthHash
//
// Creates the hash object used to hash TLS 1.2 handshake messages for
// client authentication
//--------------------------------------------------------------------------
function SslLookupCipherLengths(
  hSslProvider: NCRYPT_PROV_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  dwKeyType: DWORD;
  pCipherLengths: PNCryptSslCipherLengths;
  cbCipherLengths: DWORD;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslLookupCipherLengths}

type
  SslLookupCipherLengthsFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    dwKeyType: DWORD;
    pCipherLengths: PNCryptSslCipherLengths;
    cbCipherLengths: DWORD;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslLookupCipherLengthsFn}
  TSslLookupCipherLengthsFn = SslLookupCipherLengthsFn;


function SslCreateClientAuthHash(
  hSslProvider: NCRYPT_PROV_HANDLE;
  out phHandshakeHash: NCRYPT_HASH_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  pszHashAlgId: LPCWSTR;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslCreateClientAuthHash}

type
  SslCreateClientAuthHashFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    out phHandshakeHash: NCRYPT_HASH_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    pszHashAlgId: LPCWSTR;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslCreateClientAuthHashFn}
  TSslCreateClientAuthHashFn = SslCreateClientAuthHashFn;


function SslGetCipherSuitePRFHashAlgorithm(
  hSslProvider: NCRYPT_PROV_HANDLE;
  dwProtocol: DWORD;
  dwCipherSuite: DWORD;
  dwKeyType: DWORD;
  szPRFHash: PWChar;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslGetCipherSuitePRFHashAlgorithm}

type
  SslGetCipherSuitePRFHashAlgorithmFn = function(
    hSslProvider: NCRYPT_PROV_HANDLE;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    dwKeyType: DWORD;
    szPRFHash: PWChar;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslGetCipherSuitePRFHashAlgorithmFn}
  TSslGetCipherSuitePRFHashAlgorithmFn = SslGetCipherSuitePRFHashAlgorithmFn;




//+-------------------------------------------------------------------------
// SslInitializeInterface
//
// This function is implemented by the SSL protocol provider, and provides
// the protocol router with a dispatch table of functions implemented by
// the provider.
//--------------------------------------------------------------------------
const
  NCRYPT_SSL_INTERFACE_VERSION_1: TBCryptInterfaceVersion = (MajorVersion:1; MinorVersion:0);
  {$EXTERNALSYM NCRYPT_SSL_INTERFACE_VERSION_1}
  NCRYPT_SSL_INTERFACE_VERSION: TBCryptInterfaceVersion = (MajorVersion:1; MinorVersion:0);
  {$EXTERNALSYM NCRYPT_SSL_INTERFACE_VERSION}

const
  NCRYPT_SSL_INTERFACE_VERSION_2: TBCryptInterfaceVersion = (MajorVersion:2; MinorVersion:0);
  {$EXTERNALSYM NCRYPT_SSL_INTERFACE_VERSION_2}

type
  PNCryptSslFunctionTable = ^TNCryptSslFunctionTable;
  _NCRYPT_SSL_FUNCTION_TABLE = record
    Version: TBCryptInterfaceVersion;
    ComputeClientAuthHash: TSslComputeClientAuthHashFn;
    ComputeEapKeyBlock: TSslComputeEapKeyBlockFn;
    ComputeFinishedHash: TSslComputeFinishedHashFn;
    CreateEphemeralKey: TSslCreateEphemeralKeyFn;
    CreateHandshakeHash: TSslCreateHandshakeHashFn;
    DecryptPacket: TSslDecryptPacketFn;
    EncryptPacket: TSslEncryptPacketFn;
    EnumCipherSuites: TSslEnumCipherSuitesFn;
    ExportKey: TSslExportKeyFn;
    FreeBuffer: TSslFreeBufferFn;
    FreeObject: TSslFreeObjectFn;
    GenerateMasterKey: TSslGenerateMasterKeyFn;
    GenerateSessionKeys: TSslGenerateSessionKeysFn;
    GetKeyProperty: TSslGetKeyPropertyFn;
    GetProviderProperty: TSslGetProviderPropertyFn;
    HashHandshake: TSslHashHandshakeFn;
    ImportMasterKey: TSslImportMasterKeyFn;
    ImportKey: TSslImportKeyFn;
    LookupCipherSuiteInfo: TSslLookupCipherSuiteInfoFn;
    OpenPrivateKey: TSslOpenPrivateKeyFn;
    OpenProvider: TSslOpenProviderFn;
    SignHash: TSslSignHashFn;
    VerifySignature: TSslVerifySignatureFn;
// End of entries in NCRYPT_SSL_INTERFACE_VERSION_1

    LookupCipherLengths: TSslLookupCipherLengthsFn;
    CreateClientAuthHash: TSslCreateClientAuthHashFn;
    GetCipherSuitePRFHashAlgorithm: TSslGetCipherSuitePRFHashAlgorithmFn;
// End of entries in NCRYPT_SSL_INTERFACE_VERSION_2
  end;
  {$EXTERNALSYM _NCRYPT_SSL_FUNCTION_TABLE}
  NCRYPT_SSL_FUNCTION_TABLE = _NCRYPT_SSL_FUNCTION_TABLE;
  {$EXTERNALSYM NCRYPT_SSL_FUNCTION_TABLE}
  TNCryptSslFunctionTable = _NCRYPT_SSL_FUNCTION_TABLE;


function GetSChannelInterface(
  pszProviderName: LPCWSTR;
  out ppFunctionTable: PNCryptSslFunctionTable;
  dwFlags: DWORD): NTSTATUS; winapi;
{$EXTERNALSYM GetSChannelInterface}

type
  GetSChannelInterfaceFn = function(
    pszProviderName: LPCWSTR;
    out ppFunctionTable: PNCryptSslFunctionTable;
    dwFlags: ULONG): NTSTATUS; winapi;
  {$EXTERNALSYM GetSChannelInterfaceFn}
  TGetSChannelInterfaceFn = GetSChannelInterfaceFn;


function SslInitializeInterface(
  pszProviderName: LPCWSTR;
  pFunctionTable: PNCryptSslFunctionTable;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslInitializeInterface}

type
  SslInitializeInterfaceFn = function(
    pszProviderName: LPCWSTR;
    pFunctionTable: PNCryptSslFunctionTable;
    dwFlags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslInitializeInterfaceFn}
  TSslInitializeInterfaceFn = SslInitializeInterfaceFn;



function SslIncrementProviderReferenceCount(
  hSslProvider: NCRYPT_PROV_HANDLE): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslIncrementProviderReferenceCount}


function SslDecrementProviderReferenceCount(
  hSslProvider: NCRYPT_PROV_HANDLE): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslDecrementProviderReferenceCount}
{$ENDREGION}

implementation

const
  NCryptDll = 'ncrypt.dll';

{$REGION 'sslprovider.h'}
function SslChangeNotify; external NCryptDll name 'SslChangeNotify' delayed;
function SslComputeClientAuthHash; external NCryptDll name 'SslComputeClientAuthHash' delayed;
function SslComputeEapKeyBlock; external NCryptDll name 'SslComputeEapKeyBlock' delayed;
function SslComputeFinishedHash; external NCryptDll name 'SslComputeFinishedHash' delayed;
function SslCreateEphemeralKey; external NCryptDll name 'SslCreateEphemeralKey' delayed;
function SslCreateHandshakeHash; external NCryptDll name 'SslCreateHandshakeHash' delayed;
function SslDecryptPacket; external NCryptDll name 'SslDecryptPacket' delayed;
function SslEncryptPacket; external NCryptDll name 'SslEncryptPacket' delayed;
function SslEnumCipherSuites; external NCryptDll name 'SslEnumCipherSuites' delayed;
function SslEnumProtocolProviders; external NCryptDll name 'SslEnumProtocolProviders' delayed;
function SslExportKey; external NCryptDll name 'SslExportKey' delayed;
function SslFreeBuffer; external NCryptDll name 'SslFreeBuffer' delayed;
function SslFreeObject; external NCryptDll name 'SslFreeObject' delayed;
function SslGenerateMasterKey; external NCryptDll name 'SslGenerateMasterKey' delayed;
function SslGenerateSessionKeys; external NCryptDll name 'SslGenerateSessionKeys' delayed;
function SslGetKeyProperty; external NCryptDll name 'SslGetKeyProperty' delayed;
function SslGetProviderProperty; external NCryptDll name 'SslGetProviderProperty' delayed;
function SslHashHandshake; external NCryptDll name 'SslHashHandshake' delayed;
function SslImportKey; external NCryptDll name 'SslImportKey' delayed;
function SslImportMasterKey; external NCryptDll name 'SslImportMasterKey' delayed;
function SslLookupCipherSuiteInfo; external NCryptDll name 'SslLookupCipherSuiteInfo' delayed;
function SslOpenPrivateKey; external NCryptDll name 'SslOpenPrivateKey' delayed;
function SslOpenProvider; external NCryptDll name 'SslOpenProvider' delayed;
function SslSignHash; external NCryptDll name 'SslSignHash' delayed;
function SslVerifySignature;  external NCryptDll name 'SslVerifySignature' delayed;
function SslLookupCipherLengths; external NCryptDll name 'SslLookupCipherLengths' delayed;
function SslCreateClientAuthHash; external NCryptDll name 'SslCreateClientAuthHash' delayed;
function SslGetCipherSuitePRFHashAlgorithm; external NCryptDll name 'SslGetCipherSuitePRFHashAlgorithm' delayed;
function GetSChannelInterface; external NCryptDll name '' delayed;
function SslInitializeInterface; external NCryptDll name '' delayed;
function SslIncrementProviderReferenceCount; external NCryptDll name 'SslIncrementProviderReferenceCount' delayed;
function SslDecrementProviderReferenceCount; external NCryptDll name 'SslDecrementProviderReferenceCount' delayed;
{$ENDREGION}

end.
