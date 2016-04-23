unit Winapi.Schannel;

interface

uses
  Windows, Winapi.WinCrypt;

{$IF not DECLARED(PSTR)}
type
  PSTR = PAnsiChar;
  {$EXTERNALSYM PSTR}
{$IFEND}

{$IF not DECLARED(PVOID)}
type
  PVOID = Pointer;
  {$EXTERNALSYM PVOID}
{$IFEND}

{$IF not DECLARED(LONG)}
type
  LONG = Integer;
  {$EXTERNALSYM LONG}
{$IFEND}

{$IF not DECLARED(HCRYPTPROV)}
type
  HCRYPTPROV = ULONG_PTR;
  {$EXTERNALSYM HCRYPTPROV}
{$IFEND}

{$IF not DECLARED(SECURITY_STATUS)}
type
  SECURITY_STATUS = LONG;
  {$EXTERNALSYM SECURITY_STATUS}
{$IFEND}


{$REGION 'minschannel.h'}

{$MINENUMSIZE 4}
{$WARN SYMBOL_PLATFORM OFF}

//
// Constants
//

//
// QueryContextAttributes/QueryCredentialsAttribute extensions
//
const
  SECPKG_ATTR_ISSUER_LIST          = $50;   // (OBSOLETE) returns SecPkgContext_IssuerListInfo
  {$EXTERNALSYM SECPKG_ATTR_ISSUER_LIST}
  SECPKG_ATTR_REMOTE_CRED          = $51;   // (OBSOLETE) returns SecPkgContext_RemoteCredentialInfo
  {$EXTERNALSYM SECPKG_ATTR_REMOTE_CRED}
  SECPKG_ATTR_LOCAL_CRED           = $52;   // (OBSOLETE) returns SecPkgContext_LocalCredentialInfo
  {$EXTERNALSYM SECPKG_ATTR_LOCAL_CRED}
  SECPKG_ATTR_REMOTE_CERT_CONTEXT  = $53;   // returns PCCERT_CONTEXT
  {$EXTERNALSYM SECPKG_ATTR_REMOTE_CERT_CONTEXT}
  SECPKG_ATTR_LOCAL_CERT_CONTEXT   = $54;   // returns PCCERT_CONTEXT
  {$EXTERNALSYM SECPKG_ATTR_LOCAL_CERT_CONTEXT}
  SECPKG_ATTR_ROOT_STORE           = $55;   // returns HCERTCONTEXT to the root store
  {$EXTERNALSYM SECPKG_ATTR_ROOT_STORE}
  SECPKG_ATTR_SUPPORTED_ALGS       = $56;   // returns SecPkgCred_SupportedAlgs
  {$EXTERNALSYM SECPKG_ATTR_SUPPORTED_ALGS}
  SECPKG_ATTR_CIPHER_STRENGTHS     = $57;   // returns SecPkgCred_CipherStrengths
  {$EXTERNALSYM SECPKG_ATTR_CIPHER_STRENGTHS}
  SECPKG_ATTR_SUPPORTED_PROTOCOLS  = $58;   // returns SecPkgCred_SupportedProtocols
  {$EXTERNALSYM SECPKG_ATTR_SUPPORTED_PROTOCOLS}
  SECPKG_ATTR_ISSUER_LIST_EX       = $59;   // returns SecPkgContext_IssuerListInfoEx
  {$EXTERNALSYM SECPKG_ATTR_ISSUER_LIST_EX}
  SECPKG_ATTR_CONNECTION_INFO      = $5a;   // returns SecPkgContext_ConnectionInfo
  {$EXTERNALSYM SECPKG_ATTR_CONNECTION_INFO}
  SECPKG_ATTR_EAP_KEY_BLOCK        = $5b;   // returns SecPkgContext_EapKeyBlock
  {$EXTERNALSYM SECPKG_ATTR_EAP_KEY_BLOCK}
  SECPKG_ATTR_MAPPED_CRED_ATTR     = $5c;   // returns SecPkgContext_MappedCredAttr
  {$EXTERNALSYM SECPKG_ATTR_MAPPED_CRED_ATTR}
  SECPKG_ATTR_SESSION_INFO         = $5d;   // returns SecPkgContext_SessionInfo
  {$EXTERNALSYM SECPKG_ATTR_SESSION_INFO}
  SECPKG_ATTR_APP_DATA             = $5e;   // sets/returns SecPkgContext_SessionAppData
  {$EXTERNALSYM SECPKG_ATTR_APP_DATA}
  SECPKG_ATTR_REMOTE_CERTIFICATES  = $5F;   // returns SecPkgContext_Certificates
  {$EXTERNALSYM SECPKG_ATTR_REMOTE_CERTIFICATES}
  SECPKG_ATTR_CLIENT_CERT_POLICY   = $60;   // sets    SecPkgCred_ClientCertCtlPolicy
  {$EXTERNALSYM SECPKG_ATTR_CLIENT_CERT_POLICY}
  SECPKG_ATTR_CC_POLICY_RESULT     = $61;   // returns SecPkgContext_ClientCertPolicyResult
  {$EXTERNALSYM SECPKG_ATTR_CC_POLICY_RESULT}
  SECPKG_ATTR_USE_NCRYPT           = $62;   // Sets the CRED_FLAG_USE_NCRYPT_PROVIDER FLAG on cred group
  {$EXTERNALSYM SECPKG_ATTR_USE_NCRYPT}
  SECPKG_ATTR_LOCAL_CERT_INFO      = $63;   // returns SecPkgContext_CertInfo
  {$EXTERNALSYM SECPKG_ATTR_LOCAL_CERT_INFO}
  SECPKG_ATTR_CIPHER_INFO          = $64;   // returns new CNG SecPkgContext_CipherInfo
  {$EXTERNALSYM SECPKG_ATTR_CIPHER_INFO}
  SECPKG_ATTR_EAP_PRF_INFO         = $65;   // sets    SecPkgContext_EapPrfInfo
  {$EXTERNALSYM SECPKG_ATTR_EAP_PRF_INFO}
  SECPKG_ATTR_SUPPORTED_SIGNATURES = $66;   // returns SecPkgContext_SupportedSignatures
  {$EXTERNALSYM SECPKG_ATTR_SUPPORTED_SIGNATURES}
  SECPKG_ATTR_REMOTE_CERT_CHAIN    = $67;   // returns PCCERT_CONTEXT
  {$EXTERNALSYM SECPKG_ATTR_REMOTE_CERT_CHAIN}
  SECPKG_ATTR_UI_INFO              = $68;   // sets SEcPkgContext_UiInfo
  {$EXTERNALSYM SECPKG_ATTR_UI_INFO}
  SECPKG_ATTR_EARLY_START          = $69;   // sets SecPkgContext_EarlyStart
  {$EXTERNALSYM SECPKG_ATTR_EARLY_START}

//
// typedefs
//

type
  PSecPkgCredSupportedAlgs = ^TSecPkgCredSupportedAlgs;
  _SecPkgCred_SupportedAlgs = record
    cSupportedAlgs: DWORD;
    palgSupportedAlgs: ^ALG_ID;
  end;
  {$EXTERNALSYM _SecPkgCred_SupportedAlgs}
  SecPkgCred_SupportedAlgs = _SecPkgCred_SupportedAlgs;
  {$EXTERNALSYM SecPkgCred_SupportedAlgs}
  TSecPkgCredSupportedAlgs = _SecPkgCred_SupportedAlgs;
  PSecPkgCred_SupportedAlgs = PSecPkgCredSupportedAlgs;
  {$EXTERNALSYM PSecPkgCred_SupportedAlgs}

type
  PSecPkgCredCipherStrengths = ^TSecPkgCredCipherStrengths;
  _SecPkgCred_CipherStrengths = record
    dwMinimumCipherStrength: DWORD;
    dwMaximumCipherStrength: DWORD;
  end;
  {$EXTERNALSYM _SecPkgCred_CipherStrengths}
  SecPkgCred_CipherStrengths = _SecPkgCred_CipherStrengths;
  {$EXTERNALSYM SecPkgCred_CipherStrengths}
  TSecPkgCredCipherStrengths = _SecPkgCred_CipherStrengths;
  PSecPkgCred_CipherStrengths = PSecPkgCredCipherStrengths;
  {$EXTERNALSYM PSecPkgCred_CipherStrengths}

type
  PSecPkgCredSupportedProtocols = ^TSecPkgCredSupportedProtocols;
  _SecPkgCred_SupportedProtocols = record
    grbitProtocol: DWORD;
  end;
  {$EXTERNALSYM _SecPkgCred_SupportedProtocols}
  SecPkgCred_SupportedProtocols = _SecPkgCred_SupportedProtocols;
  {$EXTERNALSYM SecPkgCred_SupportedProtocols}
  TSecPkgCredSupportedProtocols = _SecPkgCred_SupportedProtocols;
  PSecPkgCred_SupportedProtocols = PSecPkgCredSupportedProtocols;
  {$EXTERNALSYM PSecPkgCred_SupportedProtocols}

//An IDL struct _SecPkgCred_ClientCertPolicy_RPC is defined in minio/security/base/lsa/idl/sspi/sspirpc.idl for rpc calls.
//The IDL struct should also be updated if there is any change on struct _SecPkgCred_ClientCertPolicy.

type
  PSecPkgCredClientCertPolicy = ^TSecPkgCredClientCertPolicy;
  _SecPkgCred_ClientCertPolicy = record
    dwFlags: DWORD;
    guidPolicyId: TGUID;
    dwCertFlags: DWORD;
    dwUrlRetrievalTimeout: DWORD;
    fCheckRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;
    fOmitUsageCheck: BOOL;
    pwszSslCtlStoreName: LPWSTR;
    pwszSslCtlIdentifier: LPWSTR;
  end;
  {$EXTERNALSYM _SecPkgCred_ClientCertPolicy}
  SecPkgCred_ClientCertPolicy = _SecPkgCred_ClientCertPolicy;
  {$EXTERNALSYM SecPkgCred_ClientCertPolicy}
  TSecPkgCredClientCertPolicy = _SecPkgCred_ClientCertPolicy;
  PSecPkgCred_ClientCertPolicy = PSecPkgCredClientCertPolicy;
  {$EXTERNALSYM PSecPkgCred_ClientCertPolicy}


{$ENDREGION}

{$REGION 'schannel.h'}

{$MINENUMSIZE 4}
{$WARN SYMBOL_PLATFORM OFF}

{$HPPEMIT '#include <minschannel.h>'}
{$HPPEMIT '#include <wincrypt.h>'}

//
// Security package names.
//
const
  UNISP_NAME_A   = 'Microsoft Unified Security Protocol Provider';
  {$EXTERNALSYM UNISP_NAME_A}
  UNISP_NAME_W   = 'Microsoft Unified Security Protocol Provider';
  {$EXTERNALSYM UNISP_NAME_W}

  SSL2SP_NAME_A   = 'Microsoft SSL 2.0';
  {$EXTERNALSYM SSL2SP_NAME_A}
  SSL2SP_NAME_W   = 'Microsoft SSL 2.0';
  {$EXTERNALSYM SSL2SP_NAME_W}

  SSL3SP_NAME_A   = 'Microsoft SSL 3.0';
  {$EXTERNALSYM SSL3SP_NAME_A}
  SSL3SP_NAME_W   = 'Microsoft SSL 3.0';
  {$EXTERNALSYM SSL3SP_NAME_W}

  TLS1SP_NAME_A   = 'Microsoft TLS 1.0';
  {$EXTERNALSYM TLS1SP_NAME_A}
  TLS1SP_NAME_W   = 'Microsoft TLS 1.0';
  {$EXTERNALSYM TLS1SP_NAME_W}

  PCT1SP_NAME_A   = 'Microsoft PCT 1.0';
  {$EXTERNALSYM PCT1SP_NAME_A}
  PCT1SP_NAME_W   = 'Microsoft PCT 1.0';
  {$EXTERNALSYM PCT1SP_NAME_W}

  SCHANNEL_NAME_A = 'Schannel';
  {$EXTERNALSYM SCHANNEL_NAME_A}
  SCHANNEL_NAME_W = 'Schannel';
  {$EXTERNALSYM SCHANNEL_NAME_W}


  UNISP_NAME = UNISP_NAME_W;
  {$EXTERNALSYM UNISP_NAME}
  PCT1SP_NAME = PCT1SP_NAME_W;
  {$EXTERNALSYM PCT1SP_NAME}
  SSL2SP_NAME = SSL2SP_NAME_W;
  {$EXTERNALSYM SSL2SP_NAME}
  SSL3SP_NAME = SSL3SP_NAME_W;
  {$EXTERNALSYM SSL3SP_NAME}
  TLS1SP_NAME = TLS1SP_NAME_W;
  {$EXTERNALSYM TLS1SP_NAME}
  SCHANNEL_NAME = SCHANNEL_NAME_W;
  {$EXTERNALSYM SCHANNEL_NAME}

type
  eTlsSignatureAlgorithm = (
    TlsSignatureAlgorithm_Anonymous         = 0,
    TlsSignatureAlgorithm_Rsa               = 1,
    TlsSignatureAlgorithm_Dsa               = 2,
    TlsSignatureAlgorithm_Ecdsa             = 3
  );
  {$EXTERNALSYM eTlsSignatureAlgorithm}

type
  eTlsHashAlgorithm = (
    TlsHashAlgorithm_None                   = 0,
    TlsHashAlgorithm_Md5                    = 1,
    TlsHashAlgorithm_Sha1                   = 2,
    TlsHashAlgorithm_Sha224                 = 3,
    TlsHashAlgorithm_Sha256                 = 4,
    TlsHashAlgorithm_Sha384                 = 5,
    TlsHashAlgorithm_Sha512                 = 6
  );
  {$EXTERNALSYM eTlsHashAlgorithm}


//
// RPC constants.
//

const
  UNISP_RPC_ID   = 14;
  {$EXTERNALSYM UNISP_RPC_ID}


// OBSOLETE - included here for backward compatibility only
type
  PSecPkgContextRemoteCredentialInfo = ^TSecPkgContextRemoteCredentialInfo;
  _SecPkgContext_RemoteCredentialInfo = record
    cbCertificateChain: DWORD;
    pbCertificateChain: PBYTE;
    cCertificates: DWORD;
    fFlags: DWORD;
    dwBits: DWORD;
  end;
  {$EXTERNALSYM _SecPkgContext_RemoteCredentialInfo}
  SecPkgContext_RemoteCredentialInfo = _SecPkgContext_RemoteCredentialInfo;
  {$EXTERNALSYM SecPkgContext_RemoteCredentialInfo}
  TSecPkgContextRemoteCredentialInfo = _SecPkgContext_RemoteCredentialInfo;
  PSecPkgContext_RemoteCredentialInfo = PSecPkgContextRemoteCredentialInfo;
  {$EXTERNALSYM PSecPkgContext_RemoteCredentialInfo}


const
  RCRED_STATUS_NOCRED         = $00000000;
  {$EXTERNALSYM RCRED_STATUS_NOCRED}
  RCRED_CRED_EXISTS           = $00000001;
  {$EXTERNALSYM RCRED_CRED_EXISTS}
  RCRED_STATUS_UNKNOWN_ISSUER = $00000002;
  {$EXTERNALSYM RCRED_STATUS_UNKNOWN_ISSUER}


// OBSOLETE - included here for backward compatibility only
type
  PSecPkgContextLocalCredentialInfo = ^TSecPkgContextLocalCredentialInfo;
  _SecPkgContext_LocalCredentialInfo = record
    cbCertificateChain: DWORD;
    pbCertificateChain: PBYTE;
    cCertificates: DWORD;
    fFlags: DWORD;
    dwBits: DWORD;
  end;
  {$EXTERNALSYM _SecPkgContext_LocalCredentialInfo}
  SecPkgContext_LocalCredentialInfo = _SecPkgContext_LocalCredentialInfo;
  {$EXTERNALSYM SecPkgContext_LocalCredentialInfo}
  TSecPkgContextLocalCredentialInfo = _SecPkgContext_LocalCredentialInfo;
  PSecPkgContext_LocalCredentialInfo = PSecPkgContextLocalCredentialInfo;
  {$EXTERNALSYM PSecPkgContext_LocalCredentialInfo}


const
  LCRED_STATUS_NOCRED         = $00000000;
  {$EXTERNALSYM LCRED_STATUS_NOCRED}
  LCRED_CRED_EXISTS           = $00000001;
  {$EXTERNALSYM LCRED_CRED_EXISTS}
  LCRED_STATUS_UNKNOWN_ISSUER = $00000002;
  {$EXTERNALSYM LCRED_STATUS_UNKNOWN_ISSUER}


type
  PSecPkgContextClientCertPolicyResult = ^TSecPkgContextClientCertPolicyResult;
  _SecPkgContext_ClientCertPolicyResult = record
    dwPolicyResult: HRESULT;
    guidPolicyId: TGUID;
  end;
  {$EXTERNALSYM _SecPkgContext_ClientCertPolicyResult}
  SecPkgContext_ClientCertPolicyResult = _SecPkgContext_ClientCertPolicyResult;
  {$EXTERNALSYM SecPkgContext_ClientCertPolicyResult}
  TSecPkgContextClientCertPolicyResult = _SecPkgContext_ClientCertPolicyResult;
  PSecPkgContext_ClientCertPolicyResult = PSecPkgContextClientCertPolicyResult;
  {$EXTERNALSYM PSecPkgContext_ClientCertPolicyResult}


type
  PSecPkgContextIssuerListInfoEx = ^TSecPkgContextIssuerListInfoEx;
  _SecPkgContext_IssuerListInfoEx = record
    aIssuers: PCertNameBlob;
    cIssuers: DWORD;
  end;
  {$EXTERNALSYM _SecPkgContext_IssuerListInfoEx}
  SecPkgContext_IssuerListInfoEx = _SecPkgContext_IssuerListInfoEx;
  {$EXTERNALSYM SecPkgContext_IssuerListInfoEx}
  TSecPkgContextIssuerListInfoEx = _SecPkgContext_IssuerListInfoEx;
  PSecPkgContext_IssuerListInfoEx = PSecPkgContextIssuerListInfoEx;
  {$EXTERNALSYM PSecPkgContext_IssuerListInfoEx}

type
  PSecPkgContextConnectionInfo = ^TSecPkgContextConnectionInfo;
  _SecPkgContext_ConnectionInfo = record
    dwProtocol: DWORD;
    aiCipher: ALG_ID;
    dwCipherStrength: DWORD;
    aiHash: ALG_ID;
    dwHashStrength: DWORD;
    aiExch: ALG_ID;
    dwExchStrength: DWORD
  end;
  {$EXTERNALSYM _SecPkgContext_ConnectionInfo}
  SecPkgContext_ConnectionInfo = _SecPkgContext_ConnectionInfo;
  {$EXTERNALSYM SecPkgContext_ConnectionInfo}
  TSecPkgContextConnectionInfo = _SecPkgContext_ConnectionInfo;
  PSecPkgContext_ConnectionInfo = PSecPkgContextConnectionInfo;
  {$EXTERNALSYM PSecPkgContext_ConnectionInfo}

const
  SZ_ALG_MAX_SIZE = 64;
  {$EXTERNALSYM SZ_ALG_MAX_SIZE}
  SECPKGCONTEXT_CIPHERINFO_V1 = 1;
  {$EXTERNALSYM SECPKGCONTEXT_CIPHERINFO_V1}

type
  PSecPkgContextCipherInfo = ^TSecPkgContextCipherInfo;
  _SecPkgContext_CipherInfo = record

    dwVersion: DWORD;
    dwProtocol: DWORD;
    dwCipherSuite: DWORD;
    dwBaseCipherSuite: DWORD;
    szCipherSuite: array [0..SZ_ALG_MAX_SIZE] of WCHAR;
    szCipher: array [0..SZ_ALG_MAX_SIZE - 1] of WCHAR;
    dwCipherLen: DWORD;
    dwCipherBlockLen: DWORD;    // in bytes
    szHash: array [0..SZ_ALG_MAX_SIZE - 1] of WCHAR;
    dwHashLen: DWORD;
    szExchange: array [0..SZ_ALG_MAX_SIZE - 1] of WCHAR;
    dwMinExchangeLen: DWORD;
    dwMaxExchangeLen: DWORD;
    szCertificate: array [0..SZ_ALG_MAX_SIZE - 1] of WCHAR;
    dwKeyType: DWORD;
  end;
  {$EXTERNALSYM _SecPkgContext_CipherInfo}
  SecPkgContext_CipherInfo = _SecPkgContext_CipherInfo;
  {$EXTERNALSYM SecPkgContext_CipherInfo}
  TSecPkgContextCipherInfo = _SecPkgContext_CipherInfo;
  PSecPkgContext_CipherInfo = PSecPkgContextCipherInfo;
  {$EXTERNALSYM PSecPkgContext_CipherInfo}



type
  PSecPkgContextEapKeyBlock = ^TSecPkgContextEapKeyBlock;
  _SecPkgContext_EapKeyBlock = record
    rgbKeys: array [0..128 - 1] of BYTE;
    rgbIVs: array [0..64 - 1] of BYTE;
  end;
  {$EXTERNALSYM _SecPkgContext_EapKeyBlock}
  SecPkgContext_EapKeyBlock = _SecPkgContext_EapKeyBlock;
  {$EXTERNALSYM SecPkgContext_EapKeyBlock}
  TSecPkgContextEapKeyBlock = _SecPkgContext_EapKeyBlock;
  PSecPkgContext_EapKeyBlock = PSecPkgContextEapKeyBlock;
  {$EXTERNALSYM PSecPkgContext_EapKeyBlock}


type
  PSecPkgContextMappedCredAttr = ^TSecPkgContextMappedCredAttr;
  _SecPkgContext_MappedCredAttr = record
    dwAttribute: DWORD;
    pvBuffer: PVOID;
  end;
  {$EXTERNALSYM _SecPkgContext_MappedCredAttr}
  SecPkgContext_MappedCredAttr = _SecPkgContext_MappedCredAttr;
  {$EXTERNALSYM SecPkgContext_MappedCredAttr}
  TSecPkgContextMappedCredAttr = _SecPkgContext_MappedCredAttr;
  PSecPkgContext_MappedCredAttr = PSecPkgContextMappedCredAttr;
  {$EXTERNALSYM PSecPkgContext_MappedCredAttr}


// Flag values for SecPkgContext_SessionInfo
const
  SSL_SESSION_RECONNECT  = 1;
  {$EXTERNALSYM SSL_SESSION_RECONNECT}

type
  PSecPkgContextSessionInfo = ^TSecPkgContextSessionInfo;
  _SecPkgContext_SessionInfo = record
    dwFlags: DWORD;
    cbSessionId: DWORD;
    rgbSessionId: array [0..32 - 1] of BYTE;
  end;
  {$EXTERNALSYM _SecPkgContext_SessionInfo}
  SecPkgContext_SessionInfo = _SecPkgContext_SessionInfo;
  {$EXTERNALSYM SecPkgContext_SessionInfo}
  TSecPkgContextSessionInfo = _SecPkgContext_SessionInfo;
  PSecPkgContext_SessionInfo = PSecPkgContextSessionInfo;
  {$EXTERNALSYM PSecPkgContext_SessionInfo}

type
  PSecPkgContextSessionAppData = ^TSecPkgContextSessionAppData;
  _SecPkgContext_SessionAppData = record
    dwFlags: DWORD;
    cbAppData: DWORD;
    pbAppData: PBYTE;
  end;
  {$EXTERNALSYM _SecPkgContext_SessionAppData}
  SecPkgContext_SessionAppData = _SecPkgContext_SessionAppData;
  {$EXTERNALSYM SecPkgContext_SessionAppData}
  TSecPkgContextSessionAppData = _SecPkgContext_SessionAppData;
  PSecPkgContext_SessionAppData = PSecPkgContextSessionAppData;
  {$EXTERNALSYM PSecPkgContext_SessionAppData}

type
  PSecPkgContextEapPrfInfo = ^TSecPkgContextEapPrfInfo;
  _SecPkgContext_EapPrfInfo = record
    dwVersion: DWORD;
    cbPrfData: DWORD;
    pbPrfData: PBYTE;
  end;
  {$EXTERNALSYM _SecPkgContext_EapPrfInfo}
  SecPkgContext_EapPrfInfo = _SecPkgContext_EapPrfInfo;
  {$EXTERNALSYM SecPkgContext_EapPrfInfo}
  TSecPkgContextEapPrfInfo = _SecPkgContext_EapPrfInfo;
  PSecPkgContext_EapPrfInfo = PSecPkgContextEapPrfInfo;
  {$EXTERNALSYM PSecPkgContext_EapPrfInfo}


type
  PSecPkgContextSupportedSignatures = ^TSecPkgContextSupportedSignatures;
  _SecPkgContext_SupportedSignatures = record
    cSignatureAndHashAlgorithms: WORD;

    //
    // Upper byte (from TLS 1.2, RFC 4346):
    //     enum {
    //         anonymous(0), rsa(1), dsa(2), ecdsa(3), (255)
    //     } SignatureAlgorithm;
    //
    // enum eTlsSignatureAlgorithm

    //
    // Lower byte (from TLS 1.2, RFC 4346):
    //     enum {
    //         none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
    //         sha512(6), (255)
    //     } HashAlgorithm;
    //
    //
    // enum eTlsHashAlgorithm

    pSignatureAndHashAlgorithms: PWORD;
  end;
  {$EXTERNALSYM _SecPkgContext_SupportedSignatures}
  SecPkgContext_SupportedSignatures = _SecPkgContext_SupportedSignatures;
  {$EXTERNALSYM SecPkgContext_SupportedSignatures}
  TSecPkgContextSupportedSignatures = _SecPkgContext_SupportedSignatures;
  PSecPkgContext_SupportedSignatures = PSecPkgContextSupportedSignatures;
  {$EXTERNALSYM PSecPkgContext_SupportedSignatures}


//
// This property returns the raw binary certificates that were received
// from the remote party. The format of the buffer that's returned is as
// follows.
//
//     <4 bytes> length of certificate #1
//     <n bytes> certificate #1
//     <4 bytes> length of certificate #2
//     <n bytes> certificate #2
//     ...
//
// After this data is processed, the caller of QueryContextAttributes
// must free the pbCertificateChain buffer using FreeContextBuffer.
//
type
  PSecPkgContextCertificates = ^TSecPkgContextCertificates;
  _SecPkgContext_Certificates = record
    cCertificates: DWORD;
    cbCertificateChain: DWORD;
    pbCertificateChain: PBYTE;
  end;
  {$EXTERNALSYM _SecPkgContext_Certificates}
  SecPkgContext_Certificates = _SecPkgContext_Certificates;
  {$EXTERNALSYM SecPkgContext_Certificates}
  TSecPkgContextCertificates = _SecPkgContext_Certificates;
  PSecPkgContext_Certificates = PSecPkgContextCertificates;
  {$EXTERNALSYM PSecPkgContext_Certificates}


//
// This property returns information about a certificate. In particular
// it is useful (and only available) in the kernel where CAPI2 is not
// available.
//
type
  PSecPkgContextCertInfo = ^TSecPkgContextCertInfo;
  _SecPkgContext_CertInfo = record
    dwVersion: DWORD;
    cbSubjectName: DWORD;
    pwszSubjectName: LPWSTR;
    cbIssuerName: DWORD;
    pwszIssuerName: LPWSTR;
    dwKeySize: DWORD;
  end;
  {$EXTERNALSYM _SecPkgContext_CertInfo}
  SecPkgContext_CertInfo = _SecPkgContext_CertInfo;
  {$EXTERNALSYM SecPkgContext_CertInfo}
  TSecPkgContextCertInfo = _SecPkgContext_CertInfo;
  PSecPkgContext_CertInfo = PSecPkgContextCertInfo;
  {$EXTERNALSYM PSecPkgContext_CertInfo}

const
  KERN_CONTEXT_CERT_INFO_V1 = $00000000;
  {$EXTERNALSYM KERN_CONTEXT_CERT_INFO_V1}

type
  PSecPkgContextUiInfo = ^TSecPkgContextUiInfo;
  _SecPkgContext_UiInfo  = record
    hParentWindow: HWND;
  end;
  {$EXTERNALSYM _SecPkgContext_UiInfo}
  SecPkgContext_UiInfo = _SecPkgContext_UiInfo;
  {$EXTERNALSYM SecPkgContext_UiInfo}
  TSecPkgContextUiInfo = _SecPkgContext_UiInfo;
  PSecPkgContext_UiInfo = PSecPkgContextUiInfo;
  {$EXTERNALSYM PSecPkgContext_UiInfo}

type
  PSecPkgContextEarlyStart = ^TSecPkgContextEarlyStart;
  _SecPkgContext_EarlyStart = record
    dwEarlyStartFlags: DWORD;
  end;
  {$EXTERNALSYM _SecPkgContext_EarlyStart}
  SecPkgContext_EarlyStart = _SecPkgContext_EarlyStart;
  {$EXTERNALSYM SecPkgContext_EarlyStart}
  TSecPkgContextEarlyStart = _SecPkgContext_EarlyStart;
  PSecPkgContext_EarlyStart = PSecPkgContextEarlyStart;
  {$EXTERNALSYM PSecPkgContext_EarlyStart}

// Flag values for SecPkgContext_EarlyStart
const
  ENABLE_TLS_CLIENT_EARLY_START          = $00000001;
  {$EXTERNALSYM ENABLE_TLS_CLIENT_EARLY_START}

//
// Schannel credentials data structure.
//
const
  SCH_CRED_V1             = $00000001;
  {$EXTERNALSYM SCH_CRED_V1}
  SCH_CRED_V2             = $00000002;  // for legacy code
  {$EXTERNALSYM SCH_CRED_V2}
  SCH_CRED_VERSION        = $00000002;  // for legacy code
  {$EXTERNALSYM SCH_CRED_VERSION}
  SCH_CRED_V3             = $00000003;  // for legacy code
  {$EXTERNALSYM SCH_CRED_V3}
  SCHANNEL_CRED_VERSION   = $00000004;
  {$EXTERNALSYM SCHANNEL_CRED_VERSION}


//struct _HMAPPER;

type
  PSchannelCred = ^TSchannelCred;
  _SCHANNEL_CRED = record
    dwVersion: DWORD;      // always SCHANNEL_CRED_VERSION
    cCreds: DWORD;
    paCred: PPCertContext;
    hRootStore: HCERTSTORE;

    cMappers: DWORD;
    aphMappers: PPointer; //struct _HMAPPER **

    cSupportedAlgs: DWORD;
    palgSupportedAlgs: ^ALG_ID;

    grbitEnabledProtocols: DWORD;
    dwMinimumCipherStrength: DWORD;
    dwMaximumCipherStrength: DWORD;
    dwSessionLifespan: DWORD;
    dwFlags: DWORD;
    dwCredFormat: DWORD;
  end;
  {$EXTERNALSYM _SCHANNEL_CRED}
  SCHANNEL_CRED = _SCHANNEL_CRED;
  {$EXTERNALSYM SCHANNEL_CRED}
  TSchannelCred = _SCHANNEL_CRED;
  PSCHANNEL_CRED = PSchannelCred;
  {$EXTERNALSYM PSCHANNEL_CRED}


// Values for SCHANNEL_CRED dwCredFormat field.
const
  SCH_CRED_FORMAT_CERT_CONTEXT    = $00000000;
  {$EXTERNALSYM SCH_CRED_FORMAT_CERT_CONTEXT}
  SCH_CRED_FORMAT_CERT_HASH       = $00000001;
  {$EXTERNALSYM SCH_CRED_FORMAT_CERT_HASH}
  SCH_CRED_FORMAT_CERT_HASH_STORE = $00000002;
  {$EXTERNALSYM SCH_CRED_FORMAT_CERT_HASH_STORE}

  SCH_CRED_MAX_STORE_NAME_SIZE    = 128;
  {$EXTERNALSYM SCH_CRED_MAX_STORE_NAME_SIZE}
  SCH_CRED_MAX_SUPPORTED_ALGS     = 256;
  {$EXTERNALSYM SCH_CRED_MAX_SUPPORTED_ALGS}
  SCH_CRED_MAX_SUPPORTED_CERTS    = 100;
  {$EXTERNALSYM SCH_CRED_MAX_SUPPORTED_CERTS}

type
  PSchannelCertHash = ^TSchannelCertHash;
  _SCHANNEL_CERT_HASH = record
    dwLength: DWORD;
    dwFlags: DWORD;
    hProv: HCRYPTPROV;
    ShaHash: array [0..20 - 1] of BYTE;
  end;
  {$EXTERNALSYM _SCHANNEL_CERT_HASH}
  SCHANNEL_CERT_HASH = _SCHANNEL_CERT_HASH;
  {$EXTERNALSYM SCHANNEL_CERT_HASH}
  TSchannelCertHash = _SCHANNEL_CERT_HASH;
  PSCHANNEL_CERT_HASH = PSchannelCertHash;
  {$EXTERNALSYM PSCHANNEL_CERT_HASH}

type
  PSchannelCertHashStore = ^TSchannelCertHashStore;
  _SCHANNEL_CERT_HASH_STORE = record
    dwLength: DWORD;
    dwFlags: DWORD;
    hProv: HCRYPTPROV;
    ShaHash: array[0..20 - 1] of BYTE;
    pwszStoreName: array [0..SCH_CRED_MAX_STORE_NAME_SIZE - 1] of WCHAR;
  end;
  {$EXTERNALSYM _SCHANNEL_CERT_HASH_STORE}
  SCHANNEL_CERT_HASH_STORE = _SCHANNEL_CERT_HASH_STORE;
  {$EXTERNALSYM SCHANNEL_CERT_HASH_STORE}
  TSchannelCertHashStore = _SCHANNEL_CERT_HASH_STORE;
  PSCHANNEL_CERT_HASH_STORE = PSchannelCertHashStore;
  {$EXTERNALSYM PSCHANNEL_CERT_HASH_STORE}

// Values for SCHANNEL_CERT_HASH dwFlags field.
const
  SCH_MACHINE_CERT_HASH          = $00000001;
  {$EXTERNALSYM SCH_MACHINE_CERT_HASH}


//+-------------------------------------------------------------------------
// Flags for use with SCHANNEL_CRED
//
// SCH_CRED_NO_SYSTEM_MAPPER
//      This flag is intended for use by server applications only. If this
//      flag is set, then schannel does *not* attempt to map received client
//      certificate chains to an NT user account using the built-in system
//      certificate mapper.This flag is ignored by non-NT5 versions of
//      schannel.
//
// SCH_CRED_NO_SERVERNAME_CHECK
//      This flag is intended for use by client applications only. If this
//      flag is set, then when schannel validates the received server
//      certificate chain, is does *not* compare the passed in target name
//      with the subject name embedded in the certificate. This flag is
//      ignored by non-NT5 versions of schannel. This flag is also ignored
//      if the SCH_CRED_MANUAL_CRED_VALIDATION flag is set.
//
// SCH_CRED_MANUAL_CRED_VALIDATION
//      This flag is intended for use by client applications only. If this
//      flag is set, then schannel will *not* automatically attempt to
//      validate the received server certificate chain. This flag is
//      ignored by non-NT5 versions of schannel, but all client applications
//      that wish to validate the certificate chain themselves should
//      specify this flag, so that there's at least a chance they'll run
//      correctly on NT5.
//
// SCH_CRED_NO_DEFAULT_CREDS
//      This flag is intended for use by client applications only. If this
//      flag is set, and the server requests client authentication, then
//      schannel will *not* attempt to automatically acquire a suitable
//      default client certificate chain. This flag is ignored by non-NT5
//      versions of schannel, but all client applications that wish to
//      manually specify their certicate chains should specify this flag,
//      so that there's at least a chance they'll run correctly on NT5.
//
// SCH_CRED_AUTO_CRED_VALIDATION
//      This flag is the opposite of SCH_CRED_MANUAL_CRED_VALIDATION.
//      Conservatively written client applications will always specify one
//      flag or the other.
//
// SCH_CRED_USE_DEFAULT_CREDS
//      This flag is the opposite of SCH_CRED_NO_DEFAULT_CREDS.
//      Conservatively written client applications will always specify one
//      flag or the other.
//
// SCH_CRED_DISABLE_RECONNECTS
//      This flag is intended for use by server applications only. If this
//      flag is set, then full handshakes performed with this credential
//      will not be marked suitable for reconnects. A cache entry will still
//      be created, however, so the session can be made resumable later
//      via a call to ApplyControlToken.
//
//
// SCH_CRED_REVOCATION_CHECK_END_CERT
// SCH_CRED_REVOCATION_CHECK_CHAIN
// SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
//      These flags specify that when schannel automatically validates a
//      received certificate chain, some or all of the certificates are to
//      be checked for revocation. Only one of these flags may be specified.
//      See the CertGetCertificateChain function. These flags are ignored by
//      non-NT5 versions of schannel.
//
// SCH_CRED_IGNORE_NO_REVOCATION_CHECK
// SCH_CRED_IGNORE_REVOCATION_OFFLINE
//      These flags instruct schannel to ignore the
//      CRYPT_E_NO_REVOCATION_CHECK and CRYPT_E_REVOCATION_OFFLINE errors
//      respectively if they are encountered when attempting to check the
//      revocation status of a received certificate chain. These flags are
//      ignored if none of the above flags are set.
//
// SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE
//      This flag instructs schannel to pass CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
//      flags to CertGetCertificateChain when validating the specified
//      credentials during a call to AcquireCredentialsHandle. The default for
//      vista is to not specify CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL. Use
//      SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE to override this behavior.
//      NOTE: Prior to Vista, this flag(CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL) was
//      specified by default.
//
//  SCH_SEND_ROOT_CERT
//      This flag instructs schannel to send the root cert as part of the
//      certificate message.
//
//  SCH_SEND_AUX_RECORD
//      This flag instructs schannel to split application records.
//+-------------------------------------------------------------------------
const
  SCH_CRED_NO_SYSTEM_MAPPER                    = $00000002;
  {$EXTERNALSYM SCH_CRED_NO_SYSTEM_MAPPER}
  SCH_CRED_NO_SERVERNAME_CHECK                 = $00000004;
  {$EXTERNALSYM SCH_CRED_NO_SERVERNAME_CHECK}
  SCH_CRED_MANUAL_CRED_VALIDATION              = $00000008;
  {$EXTERNALSYM SCH_CRED_MANUAL_CRED_VALIDATION}
  SCH_CRED_NO_DEFAULT_CREDS                    = $00000010;
  {$EXTERNALSYM SCH_CRED_NO_DEFAULT_CREDS}
  SCH_CRED_AUTO_CRED_VALIDATION                = $00000020;
  {$EXTERNALSYM SCH_CRED_AUTO_CRED_VALIDATION}
  SCH_CRED_USE_DEFAULT_CREDS                   = $00000040;
  {$EXTERNALSYM SCH_CRED_USE_DEFAULT_CREDS}
  SCH_CRED_DISABLE_RECONNECTS                  = $00000080;
  {$EXTERNALSYM SCH_CRED_DISABLE_RECONNECTS}

  SCH_CRED_REVOCATION_CHECK_END_CERT           = $00000100;
  {$EXTERNALSYM SCH_CRED_REVOCATION_CHECK_END_CERT}
  SCH_CRED_REVOCATION_CHECK_CHAIN              = $00000200;
  {$EXTERNALSYM SCH_CRED_REVOCATION_CHECK_CHAIN}
  SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $00000400;
  {$EXTERNALSYM SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT}
  SCH_CRED_IGNORE_NO_REVOCATION_CHECK          = $00000800;
  {$EXTERNALSYM SCH_CRED_IGNORE_NO_REVOCATION_CHECK}
  SCH_CRED_IGNORE_REVOCATION_OFFLINE           = $00001000;
  {$EXTERNALSYM SCH_CRED_IGNORE_REVOCATION_OFFLINE}

  SCH_CRED_RESTRICTED_ROOTS                    = $00002000;
  {$EXTERNALSYM SCH_CRED_RESTRICTED_ROOTS}
  SCH_CRED_REVOCATION_CHECK_CACHE_ONLY         = $00004000;
  {$EXTERNALSYM SCH_CRED_REVOCATION_CHECK_CACHE_ONLY}
  SCH_CRED_CACHE_ONLY_URL_RETRIEVAL            = $00008000;
  {$EXTERNALSYM SCH_CRED_CACHE_ONLY_URL_RETRIEVAL}

  SCH_CRED_MEMORY_STORE_CERT                   = $00010000;
  {$EXTERNALSYM SCH_CRED_MEMORY_STORE_CERT}

  SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE  = $00020000;
  {$EXTERNALSYM SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE}

  SCH_SEND_ROOT_CERT                           = $00040000;
  {$EXTERNALSYM SCH_SEND_ROOT_CERT}
  SCH_CRED_SNI_CREDENTIAL                      = $00080000;
  {$EXTERNALSYM SCH_CRED_SNI_CREDENTIAL}
  SCH_CRED_SNI_ENABLE_OCSP                     = $00100000;
  {$EXTERNALSYM SCH_CRED_SNI_ENABLE_OCSP}
  SCH_SEND_AUX_RECORD                          = $00200000;
  {$EXTERNALSYM SCH_SEND_AUX_RECORD}

//
//
// ApplyControlToken PkgParams types
//
// These identifiers are the DWORD types
// to be passed into ApplyControlToken
// through a PkgParams buffer.
const
  SCHANNEL_RENEGOTIATE   = 0;   // renegotiate a connection
  {$EXTERNALSYM SCHANNEL_RENEGOTIATE}
  SCHANNEL_SHUTDOWN      = 1;   // gracefully close down a connection
  {$EXTERNALSYM SCHANNEL_SHUTDOWN}
  SCHANNEL_ALERT         = 2;   // build an error message
  {$EXTERNALSYM SCHANNEL_ALERT}
  SCHANNEL_SESSION       = 3;   // session control
  {$EXTERNALSYM SCHANNEL_SESSION}


// Alert token structure.
type
  PSchannelAlertToken = ^TSchannelAlertToken;
  _SCHANNEL_ALERT_TOKEN = record
    dwTokenType: DWORD;            // SCHANNEL_ALERT
    dwAlertType: DWORD;
    dwAlertNumber: DWORD;
  end;
  {$EXTERNALSYM _SCHANNEL_ALERT_TOKEN}
  SCHANNEL_ALERT_TOKEN = _SCHANNEL_ALERT_TOKEN;
  {$EXTERNALSYM SCHANNEL_ALERT_TOKEN}
  TSchannelAlertToken = _SCHANNEL_ALERT_TOKEN;

// Alert types.
const
  TLS1_ALERT_WARNING             = 1;
  {$EXTERNALSYM TLS1_ALERT_WARNING}
  TLS1_ALERT_FATAL               = 2;
  {$EXTERNALSYM TLS1_ALERT_FATAL}

// Alert messages.
const
  TLS1_ALERT_CLOSE_NOTIFY        =  0;       // warning
  {$EXTERNALSYM TLS1_ALERT_CLOSE_NOTIFY}
  TLS1_ALERT_UNEXPECTED_MESSAGE  =  10;      // error
  {$EXTERNALSYM TLS1_ALERT_UNEXPECTED_MESSAGE}
  TLS1_ALERT_BAD_RECORD_MAC      =  20;      // error
  {$EXTERNALSYM TLS1_ALERT_BAD_RECORD_MAC}
  TLS1_ALERT_DECRYPTION_FAILED   =  21;      // reserved
  {$EXTERNALSYM TLS1_ALERT_DECRYPTION_FAILED}
  TLS1_ALERT_RECORD_OVERFLOW     =  22;      // error
  {$EXTERNALSYM TLS1_ALERT_RECORD_OVERFLOW}
  TLS1_ALERT_DECOMPRESSION_FAIL  =  30;      // error
  {$EXTERNALSYM TLS1_ALERT_DECOMPRESSION_FAIL}
  TLS1_ALERT_HANDSHAKE_FAILURE   =  40;      // error
  {$EXTERNALSYM TLS1_ALERT_HANDSHAKE_FAILURE}
  TLS1_ALERT_BAD_CERTIFICATE     =  42;      // warning or error
  {$EXTERNALSYM TLS1_ALERT_BAD_CERTIFICATE}
  TLS1_ALERT_UNSUPPORTED_CERT    =  43;      // warning or error
  {$EXTERNALSYM TLS1_ALERT_UNSUPPORTED_CERT}
  TLS1_ALERT_CERTIFICATE_REVOKED =  44;      // warning or error
  {$EXTERNALSYM TLS1_ALERT_CERTIFICATE_REVOKED}
  TLS1_ALERT_CERTIFICATE_EXPIRED =  45;      // warning or error
  {$EXTERNALSYM TLS1_ALERT_CERTIFICATE_EXPIRED}
  TLS1_ALERT_CERTIFICATE_UNKNOWN =  46;      // warning or error
  {$EXTERNALSYM TLS1_ALERT_CERTIFICATE_UNKNOWN}
  TLS1_ALERT_ILLEGAL_PARAMETER   =  47;      // error
  {$EXTERNALSYM TLS1_ALERT_ILLEGAL_PARAMETER}
  TLS1_ALERT_UNKNOWN_CA          =  48;      // error
  {$EXTERNALSYM TLS1_ALERT_UNKNOWN_CA}
  TLS1_ALERT_ACCESS_DENIED       =  49;      // error
  {$EXTERNALSYM TLS1_ALERT_ACCESS_DENIED}
  TLS1_ALERT_DECODE_ERROR        =  50;      // error
  {$EXTERNALSYM TLS1_ALERT_DECODE_ERROR}
  TLS1_ALERT_DECRYPT_ERROR       =  51;      // error
  {$EXTERNALSYM TLS1_ALERT_DECRYPT_ERROR}
  TLS1_ALERT_EXPORT_RESTRICTION  =  60;      // reserved
  {$EXTERNALSYM TLS1_ALERT_EXPORT_RESTRICTION}
  TLS1_ALERT_PROTOCOL_VERSION    =  70;      // error
  {$EXTERNALSYM TLS1_ALERT_PROTOCOL_VERSION}
  TLS1_ALERT_INSUFFIENT_SECURITY =  71;      // error
  {$EXTERNALSYM TLS1_ALERT_INSUFFIENT_SECURITY}
  TLS1_ALERT_INTERNAL_ERROR      =  80;      // error
  {$EXTERNALSYM TLS1_ALERT_INTERNAL_ERROR}
  TLS1_ALERT_USER_CANCELED       =  90;      // warning or error
  {$EXTERNALSYM TLS1_ALERT_USER_CANCELED}
  TLS1_ALERT_NO_RENEGOTIATION    = 100;      // warning
  {$EXTERNALSYM TLS1_ALERT_NO_RENEGOTIATION}
  TLS1_ALERT_UNSUPPORTED_EXT     = 110;      // error
  {$EXTERNALSYM TLS1_ALERT_UNSUPPORTED_EXT}


// Session control flags
const
  SSL_SESSION_ENABLE_RECONNECTS  = 1;
  {$EXTERNALSYM SSL_SESSION_ENABLE_RECONNECTS}
  SSL_SESSION_DISABLE_RECONNECTS = 2;
  {$EXTERNALSYM SSL_SESSION_DISABLE_RECONNECTS}

// Session control token structure.
type
  PSchannelSessionToken = ^TSchannelSessionToken;
  _SCHANNEL_SESSION_TOKEN = record
    dwTokenType: DWORD;        // SCHANNEL_SESSION
    dwFlags: DWORD;
  end;
  {$EXTERNALSYM _SCHANNEL_SESSION_TOKEN}
  SCHANNEL_SESSION_TOKEN = _SCHANNEL_SESSION_TOKEN;
  {$EXTERNALSYM SCHANNEL_SESSION_TOKEN}
  TSchannelSessionToken = _SCHANNEL_SESSION_TOKEN;


type
  PSchannelClientSignature = ^TSchannelClientSignature;
  _SCHANNEL_CLIENT_SIGNATURE = record
    cbLength: DWORD;
    aiHash: ALG_ID;
    cbHash: DWORD;
    HashValue: array [0..36 - 1] of BYTE;
    CertThumbprint: array [0..20 - 1] of BYTE;
  end;
  {$EXTERNALSYM _SCHANNEL_CLIENT_SIGNATURE}
  SCHANNEL_CLIENT_SIGNATURE = _SCHANNEL_CLIENT_SIGNATURE;
  {$EXTERNALSYM SCHANNEL_CLIENT_SIGNATURE}
  TSchannelClientSignature = _SCHANNEL_CLIENT_SIGNATURE;
  PSCHANNEL_CLIENT_SIGNATURE = PSchannelClientSignature;
  {$EXTERNALSYM PSCHANNEL_CLIENT_SIGNATURE}


//
// Flags for identifying the various different protocols.
//

(* flag/identifiers for protocols we support *)
const
  SP_PROT_PCT1_SERVER            = $00000001;
  {$EXTERNALSYM SP_PROT_PCT1_SERVER}
  SP_PROT_PCT1_CLIENT            = $00000002;
  {$EXTERNALSYM SP_PROT_PCT1_CLIENT}
  SP_PROT_PCT1                   = (SP_PROT_PCT1_SERVER or SP_PROT_PCT1_CLIENT);
  {$EXTERNALSYM SP_PROT_PCT1}

  SP_PROT_SSL2_SERVER            = $00000004;
  {$EXTERNALSYM SP_PROT_SSL2_SERVER}
  SP_PROT_SSL2_CLIENT            = $00000008;
  {$EXTERNALSYM SP_PROT_SSL2_CLIENT}
  SP_PROT_SSL2                   = (SP_PROT_SSL2_SERVER or SP_PROT_SSL2_CLIENT);
  {$EXTERNALSYM SP_PROT_SSL2}

  SP_PROT_SSL3_SERVER            = $00000010;
  {$EXTERNALSYM SP_PROT_SSL3_SERVER}
  SP_PROT_SSL3_CLIENT            = $00000020;
  {$EXTERNALSYM SP_PROT_SSL3_CLIENT}
  SP_PROT_SSL3                   = (SP_PROT_SSL3_SERVER or SP_PROT_SSL3_CLIENT);
  {$EXTERNALSYM SP_PROT_SSL3}

  SP_PROT_TLS1_SERVER            = $00000040;
  {$EXTERNALSYM SP_PROT_TLS1_SERVER}
  SP_PROT_TLS1_CLIENT            = $00000080;
  {$EXTERNALSYM SP_PROT_TLS1_CLIENT}
  SP_PROT_TLS1                   = (SP_PROT_TLS1_SERVER or SP_PROT_TLS1_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1}

  SP_PROT_SSL3TLS1_CLIENTS       = (SP_PROT_TLS1_CLIENT or SP_PROT_SSL3_CLIENT);
  {$EXTERNALSYM SP_PROT_SSL3TLS1_CLIENTS}
  SP_PROT_SSL3TLS1_SERVERS       = (SP_PROT_TLS1_SERVER or SP_PROT_SSL3_SERVER);
  {$EXTERNALSYM SP_PROT_SSL3TLS1_SERVERS}
  SP_PROT_SSL3TLS1               = (SP_PROT_SSL3 or SP_PROT_TLS1);
  {$EXTERNALSYM SP_PROT_SSL3TLS1}

  SP_PROT_UNI_SERVER             = $40000000;
  {$EXTERNALSYM SP_PROT_UNI_SERVER}
  SP_PROT_UNI_CLIENT             = $80000000;
  {$EXTERNALSYM SP_PROT_UNI_CLIENT}
  SP_PROT_UNI                    = (SP_PROT_UNI_SERVER or SP_PROT_UNI_CLIENT);
  {$EXTERNALSYM SP_PROT_UNI}

  SP_PROT_ALL                    = $ffffffff;
  {$EXTERNALSYM SP_PROT_ALL}
  SP_PROT_NONE                   = 0;
  {$EXTERNALSYM SP_PROT_NONE}
  SP_PROT_CLIENTS                = (SP_PROT_PCT1_CLIENT or SP_PROT_SSL2_CLIENT or SP_PROT_SSL3_CLIENT or SP_PROT_UNI_CLIENT or SP_PROT_TLS1_CLIENT);
  {$EXTERNALSYM SP_PROT_CLIENTS}
  SP_PROT_SERVERS                = (SP_PROT_PCT1_SERVER or SP_PROT_SSL2_SERVER or SP_PROT_SSL3_SERVER or SP_PROT_UNI_SERVER or SP_PROT_TLS1_SERVER);
  {$EXTERNALSYM SP_PROT_SERVERS}


  SP_PROT_TLS1_0_SERVER          = SP_PROT_TLS1_SERVER;
  {$EXTERNALSYM SP_PROT_TLS1_0_SERVER}
  SP_PROT_TLS1_0_CLIENT          = SP_PROT_TLS1_CLIENT;
  {$EXTERNALSYM SP_PROT_TLS1_0_CLIENT}
  SP_PROT_TLS1_0                 = (SP_PROT_TLS1_0_SERVER or
                                    SP_PROT_TLS1_0_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1_0}

  SP_PROT_TLS1_1_SERVER          = $00000100;
  {$EXTERNALSYM SP_PROT_TLS1_1_SERVER}
  SP_PROT_TLS1_1_CLIENT          = $00000200;
  {$EXTERNALSYM SP_PROT_TLS1_1_CLIENT}
  SP_PROT_TLS1_1                 = (SP_PROT_TLS1_1_SERVER or
                                    SP_PROT_TLS1_1_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1_1}

  SP_PROT_TLS1_2_SERVER          = $00000400;
  {$EXTERNALSYM SP_PROT_TLS1_2_SERVER}
  SP_PROT_TLS1_2_CLIENT          = $00000800;
  {$EXTERNALSYM SP_PROT_TLS1_2_CLIENT}
  SP_PROT_TLS1_2                 = (SP_PROT_TLS1_2_SERVER or
                                    SP_PROT_TLS1_2_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1_2}

  SP_PROT_DTLS_SERVER            = $00010000;
  {$EXTERNALSYM SP_PROT_DTLS_SERVER}
  SP_PROT_DTLS_CLIENT            = $00020000;
  {$EXTERNALSYM SP_PROT_DTLS_CLIENT}
  SP_PROT_DTLS                   = (SP_PROT_DTLS_SERVER or
                                    SP_PROT_DTLS_CLIENT);
  {$EXTERNALSYM SP_PROT_DTLS}

  SP_PROT_DTLS1_0_SERVER         = SP_PROT_DTLS_SERVER;
  {$EXTERNALSYM SP_PROT_DTLS1_0_SERVER}
  SP_PROT_DTLS1_0_CLIENT         = SP_PROT_DTLS_CLIENT;
  {$EXTERNALSYM SP_PROT_DTLS1_0_CLIENT}
  SP_PROT_DTLS1_0                = (SP_PROT_DTLS1_0_SERVER or SP_PROT_DTLS1_0_CLIENT);
  {$EXTERNALSYM SP_PROT_DTLS1_0}

  SP_PROT_DTLS1_X_SERVER         = SP_PROT_DTLS1_0_SERVER;
  {$EXTERNALSYM SP_PROT_DTLS1_X_SERVER}

  SP_PROT_DTLS1_X_CLIENT         = SP_PROT_DTLS1_0_CLIENT;
  {$EXTERNALSYM SP_PROT_DTLS1_X_CLIENT}

  SP_PROT_DTLS1_X                = (SP_PROT_DTLS1_X_SERVER or
                                    SP_PROT_DTLS1_X_CLIENT);
  {$EXTERNALSYM SP_PROT_DTLS1_X}

  SP_PROT_TLS1_1PLUS_SERVER      = (SP_PROT_TLS1_1_SERVER or
                                    SP_PROT_TLS1_2_SERVER);
  {$EXTERNALSYM SP_PROT_TLS1_1PLUS_SERVER}
  SP_PROT_TLS1_1PLUS_CLIENT      = (SP_PROT_TLS1_1_CLIENT or
                                    SP_PROT_TLS1_2_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1_1PLUS_CLIENT}

  SP_PROT_TLS1_1PLUS             = (SP_PROT_TLS1_1PLUS_SERVER or
                                    SP_PROT_TLS1_1PLUS_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1_1PLUS}

  SP_PROT_TLS1_X_SERVER          = (SP_PROT_TLS1_0_SERVER or
                                    SP_PROT_TLS1_1_SERVER or
                                    SP_PROT_TLS1_2_SERVER);
  {$EXTERNALSYM SP_PROT_TLS1_X_SERVER}
  SP_PROT_TLS1_X_CLIENT          = (SP_PROT_TLS1_0_CLIENT or
                                    SP_PROT_TLS1_1_CLIENT or
                                    SP_PROT_TLS1_2_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1_X_CLIENT}
  SP_PROT_TLS1_X                 = (SP_PROT_TLS1_X_SERVER or
                                    SP_PROT_TLS1_X_CLIENT);
  {$EXTERNALSYM SP_PROT_TLS1_X}

  SP_PROT_SSL3TLS1_X_CLIENTS     = (SP_PROT_TLS1_X_CLIENT or
                                    SP_PROT_SSL3_CLIENT);
  {$EXTERNALSYM SP_PROT_SSL3TLS1_X_CLIENTS}
  SP_PROT_SSL3TLS1_X_SERVERS     = (SP_PROT_TLS1_X_SERVER or
                                    SP_PROT_SSL3_SERVER);
  {$EXTERNALSYM SP_PROT_SSL3TLS1_X_SERVERS}
  SP_PROT_SSL3TLS1_X             = (SP_PROT_SSL3 or SP_PROT_TLS1_X);
  {$EXTERNALSYM SP_PROT_SSL3TLS1_X}

  SP_PROT_X_CLIENTS              = (SP_PROT_CLIENTS or
                                    SP_PROT_TLS1_X_CLIENT or
                                    SP_PROT_DTLS1_X_CLIENT);
  {$EXTERNALSYM SP_PROT_X_CLIENTS}
  SP_PROT_X_SERVERS              = (SP_PROT_SERVERS or
                                    SP_PROT_TLS1_X_SERVER or
                                    SP_PROT_DTLS1_X_SERVER );
  {$EXTERNALSYM SP_PROT_X_SERVERS}

//
// Helper function used to flush the SSL session cache.
//

type
  SSL_EMPTY_CACHE_FN_A = function(
    pszTargetName: LPSTR;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM SSL_EMPTY_CACHE_FN_A}
  TSslEmptyCacheFnA = SSL_EMPTY_CACHE_FN_A;

function SslEmptyCacheA(
  pszTargetName: LPSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM SslEmptyCacheA}

type
  SSL_EMPTY_CACHE_FN_W = function(
    pszTargetName: LPWSTR;
    dwFlags: DWORD): BOOL; winapi;
  {$EXTERNALSYM SSL_EMPTY_CACHE_FN_W}
  TSslEmptyCacheFnW = SSL_EMPTY_CACHE_FN_W;

function SslEmptyCacheW(
  pszTargetName: LPWSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM SslEmptyCacheW}

type
  SSL_EMPTY_CACHE_FN = SSL_EMPTY_CACHE_FN_W;
  {$EXTERNALSYM SSL_EMPTY_CACHE_FN}
  TSslEmptyCacheFn = SSL_EMPTY_CACHE_FN_W;

function SslEmptyCache(
  pszTargetName: LPWSTR;
  dwFlags: DWORD): BOOL; winapi;
{$EXTERNALSYM SslEmptyCache}


// Structures for compatability with the
// NT 4.0 SP2 / IE 3.0 schannel interface, do
// not use.

type
  PSslCredentialCertificate = ^TSslCredentialCertificate;
  _SSL_CREDENTIAL_CERTIFICATE = record
    cbPrivateKey: DWORD;
    pPrivateKey: PBYTE;
    cbCertificate: DWORD;
    pCertificate: PBYTE;
    pszPassword: PSTR;
  end;
  {$EXTERNALSYM _SSL_CREDENTIAL_CERTIFICATE}
  SSL_CREDENTIAL_CERTIFICATE = _SSL_CREDENTIAL_CERTIFICATE;
  {$EXTERNALSYM SSL_CREDENTIAL_CERTIFICATE}
  TSslCredentialCertificate = _SSL_CREDENTIAL_CERTIFICATE;
  PSSL_CREDENTIAL_CERTIFICATE = PSslCredentialCertificate;
  {$EXTERNALSYM PSSL_CREDENTIAL_CERTIFICATE}




// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
const
  SCHANNEL_SECRET_TYPE_CAPI  = $00000001;
  {$EXTERNALSYM SCHANNEL_SECRET_TYPE_CAPI}
  SCHANNEL_SECRET_PRIVKEY    = $00000002;
  {$EXTERNALSYM SCHANNEL_SECRET_PRIVKEY}
  SCH_CRED_X509_CERTCHAIN    = $00000001;
  {$EXTERNALSYM SCH_CRED_X509_CERTCHAIN}
  SCH_CRED_X509_CAPI         = $00000002;
  {$EXTERNALSYM SCH_CRED_X509_CAPI}
  SCH_CRED_CERT_CONTEXT      = $00000003;
  {$EXTERNALSYM SCH_CRED_CERT_CONTEXT}

//struct _HMAPPER;
type
  PSchCred = ^TSchCred;
  _SCH_CRED = record
    dwVersion: DWORD;                // always SCH_CRED_VERSION.
    cCreds: DWORD;                   // Number of credentials.
    paSecret: ^PVOID;                // Array of SCH_CRED_SECRET_* pointers
    paPublic: ^PVOID;                // Array of SCH_CRED_PUBLIC_* pointers
    cMappers: DWORD;                 // Number of credential mappers.
    aphMappers: PPointer{struct _HMAPPER   **};  // pointer to an array of pointers to credential mappers
  end;
  {$EXTERNALSYM _SCH_CRED}
  SCH_CRED = _SCH_CRED;
  {$EXTERNALSYM SCH_CRED}
  TSchCred = _SCH_CRED;
  PSCH_CRED = PSchCred;
  {$EXTERNALSYM PSCH_CRED}

// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
type
  PSchCredSecretCapi = ^TSchCredSecretCapi;
  _SCH_CRED_SECRET_CAPI = record
    dwType: DWORD;        // SCHANNEL_SECRET_TYPE_CAPI
    hProv: HCRYPTPROV;    // credential secret information.

  end;
  {$EXTERNALSYM _SCH_CRED_SECRET_CAPI}
  SCH_CRED_SECRET_CAPI = _SCH_CRED_SECRET_CAPI;
  {$EXTERNALSYM SCH_CRED_SECRET_CAPI}
  TSchCredSecretCapi = _SCH_CRED_SECRET_CAPI;
  PSCH_CRED_SECRET_CAPI = PSchCredSecretCapi;
  {$EXTERNALSYM PSCH_CRED_SECRET_CAPI}


// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
type
  PSchCredSecretPrivKey = ^TSchCredSecretPrivKey;
  _SCH_CRED_SECRET_PRIVKEY = record
    dwType: DWORD;        // SCHANNEL_SECRET_PRIVKEY
    pPrivateKey: PBYTE;   // Der encoded private key
    cbPrivateKey: DWORD;
    pszPassword: PSTR;    // Password to crack the private key.

  end;
  {$EXTERNALSYM _SCH_CRED_SECRET_PRIVKEY}
  SCH_CRED_SECRET_PRIVKEY = _SCH_CRED_SECRET_PRIVKEY;
  {$EXTERNALSYM SCH_CRED_SECRET_PRIVKEY}
  TSchCredSecretPrivKey = _SCH_CRED_SECRET_PRIVKEY;
  PSCH_CRED_SECRET_PRIVKEY = PSchCredSecretPrivKey;
  {$EXTERNALSYM PSCH_CRED_SECRET_PRIVKEY}


// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
type
  PSchCredPublicCertChain = ^TSchCredPublicCertChain;
  _SCH_CRED_PUBLIC_CERTCHAIN = record
    dwType: DWORD;
    cbCertChain: DWORD;
    pCertChain: PBYTE;
  end;
  {$EXTERNALSYM _SCH_CRED_PUBLIC_CERTCHAIN}
  SCH_CRED_PUBLIC_CERTCHAIN = _SCH_CRED_PUBLIC_CERTCHAIN;
  {$EXTERNALSYM SCH_CRED_PUBLIC_CERTCHAIN}
  TSchCredPublicCertChain = _SCH_CRED_PUBLIC_CERTCHAIN;
  PSCH_CRED_PUBLIC_CERTCHAIN = PSchCredPublicCertChain;
  {$EXTERNALSYM PSCH_CRED_PUBLIC_CERTCHAIN}


// Structures needed for Pre NT4.0 SP2 calls.
type
  PPctPublicKey = ^TPctPublicKey;
  _PctPublicKey = record
    &Type: DWORD;
    cbKey: DWORD;
    pKey: array [0..1 - 1] of UCHAR;
  end;
  {$EXTERNALSYM _PctPublicKey}
  PctPublicKey = _PctPublicKey;
  {$EXTERNALSYM PctPublicKey}
  TPctPublicKey = _PctPublicKey;

type
  PX509Certificate = ^TX509Certificate;
  {$EXTERNALSYM PX509Certificate}
  _X509Certificate = record
    Version: DWORD;
    SerialNumber: array [0..4 - 1] of DWORD;
    SignatureAlgorithm: ALG_ID;
    ValidFrom: TFileTime;
    ValidUntil: TFileTime;
    pszIssuer: PSTR;
    pszSubject: PSTR;
    pPublicKey: PPctPublicKey;
  end;
  {$EXTERNALSYM _X509Certificate}
  X509Certificate = _X509Certificate;
  {$EXTERNALSYM X509Certificate}
  TX509Certificate = _X509Certificate;


// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
function SslGenerateKeyPair(
  pCerts: PSslCredentialCertificate;
  pszDN: PSTR;
  pszPassword: PSTR;
  Bits: DWORD): BOOL; winapi;
{$EXTERNALSYM SslGenerateKeyPair}

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
procedure SslGenerateRandomBits(
  pRandomData: PUCHAR;
  cRandomData: LONG
  ); winapi;
{$EXTERNALSYM SslGenerateRandomBits}

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
function SslCrackCertificate(
  pbCertificate: PUCHAR;
  cbCertificate: DWORD;
  dwFlags:  DWORD;
  out ppCertificate: PX509Certificate
  ): BOOL; winapi;
{$EXTERNALSYM SslCrackCertificate}

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
procedure SslFreeCertificate(
  pCertificate:   PX509Certificate
  ); winapi;
{$EXTERNALSYM SslFreeCertificate}

function SslGetMaximumKeySize(
  Reserved: DWORD): DWORD; winapi;
{$EXTERNALSYM SslGetMaximumKeySize}

function SslGetDefaultIssuers(
  pbIssuers: PBYTE;
  out pcbIssuers: DWORD): BOOL; winapi;
{$EXTERNALSYM SslGetDefaultIssuers}

const
  SSL_CRACK_CERTIFICATE_NAME = 'SslCrackCertificate';
  {$EXTERNALSYM SSL_CRACK_CERTIFICATE_NAME}
  SSL_FREE_CERTIFICATE_NAME  = 'SslFreeCertificate';
  {$EXTERNALSYM SSL_FREE_CERTIFICATE_NAME}

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
type
  SSL_CRACK_CERTIFICATE_FN = function(
    pbCertificate: PUCHAR;
    cbCertificate: DWORD;
    VerifySignature: BOOL;
    out ppCertificate: PX509Certificate): BOOL; winapi;
  {$EXTERNALSYM SSL_CRACK_CERTIFICATE_FN}
  TSslCrackCertificateFn = SSL_CRACK_CERTIFICATE_FN;


// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
type
  SSL_FREE_CERTIFICATE_FN = procedure(
    pCertificate: PX509Certificate); winapi;
  {$EXTERNALSYM SSL_FREE_CERTIFICATE_FN}
  TSslFreeCertificateFn = SSL_FREE_CERTIFICATE_FN;


type
  SslGetServerIdentityFn = function(
    ClientHello: PBYTE;
    ClientHelloSize: DWORD;
    out ServerIdentity: PBYTE;
    out ServerIdentitySize: DWORD;
    Flags: DWORD): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SslGetServerIdentityFn}

function SslGetServerIdentity(
  ClientHello: PBYTE;
  ClientHelloSize: DWORD;
  out ServerIdentity: PBYTE;
  out ServerIdentitySize: DWORD;
  Flags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM SslGetServerIdentity}

{$ENDREGION}

implementation

const
  SchannelDll = 'schannel.dll';

{$REGION 'schannel.h'}
function SslEmptyCacheA; external SchannelDll name 'SslEmptyCacheA';
function SslEmptyCacheW; external SchannelDll name 'SslEmptyCacheW';
function SslEmptyCache; external SchannelDll name 'SslEmptyCache';
function SslGenerateKeyPair; external SchannelDll name '';
procedure SslGenerateRandomBits; external SchannelDll name 'SslGenerateRandomBits';
function SslCrackCertificate; external SchannelDll name 'SslCrackCertificate';
procedure SslFreeCertificate; external SchannelDll name 'SslFreeCertificate';
function SslGetMaximumKeySize; external SchannelDll name 'SslGetMaximumKeySize';
function SslGetDefaultIssuers; external SchannelDll name '';
function SslGetServerIdentity; external SchannelDll name 'SslGetServerIdentity' delayed;
{$ENDREGION}

end.
