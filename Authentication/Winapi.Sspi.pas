unit Winapi.Sspi;

interface

uses
  Windows;

{$IF not DECLARED(LONG)}
type
  LONG = Integer;
  {$EXTERNALSYM LONG}
{$IFEND}

{$IF not DECLARED(PVOID)}
type
  PVOID = Pointer;
  {$EXTERNALSYM PVOID}
{$IFEND}

{$IF not DECLARED(PCWSTR)}
type
  PCWSTR = PWideChar;
  {$EXTERNALSYM PCWSTR}
{$IFEND}

{$IF not DECLARED(PCSTR)}
type
  PCSTR = PAnsiChar;
  {$EXTERNALSYM PCSTR}
{$IFEND}

{$IF not DECLARED(PWSTR)}
type
  PWSTR = PWideChar;
  {$EXTERNALSYM PWSTR}
{$IFEND}

{$REGION 'sspi.h'}

{$MINENUMSIZE 4}
{$WARN SYMBOL_PLATFORM OFF}


//
// Determine environment:
//

const
  ISSP_LEVEL = 32;
  {$EXTERNALSYM ISSP_LEVEL}
  ISSP_MODE  = 0;
  {$EXTERNALSYM ISSP_MODE}

//
// Now, define platform specific mappings:
//

type
  PSecWChar = PWChar;
  SEC_WCHAR = WCHAR;
  {$EXTERNALSYM SEC_WCHAR}
  TSecWChar = WCHAR;
  PSecChar = PAnsiChar;
  SEC_CHAR = AnsiChar;
  {$EXTERNALSYM SEC_CHAR}
  TSecChar = AnsiChar;

{$IF not DECLARED(SECURITY_STATUS)}
type
  SECURITY_STATUS = LONG;
  {$EXTERNALSYM SECURITY_STATUS}
{$IFEND}

//
// Decide what a string - 32 bits only since for 16 bits it is clear.
//


type
  SECURITY_PSTR = PSecWChar;
  {$EXTERNALSYM SECURITY_PSTR}
  SECURITY_PCSTR = PSecWChar;
  {$EXTERNALSYM SECURITY_PCSTR}


//
// Equivalent string for rpcrt:
//



//
// Okay, security specific types:
//

{$IF not DECLARED(SecHandle)}
type
  PSecHandle = ^TSecHandle;
  {$EXTERNALSYM PSecHandle}
  _SecHandle = record
    dwLower: ULONG_PTR;
    dwUpper: ULONG_PTR;
  end;
  {$EXTERNALSYM _SecHandle}
  SecHandle = _SecHandle;
  {$EXTERNALSYM SecHandle}
  TSecHandle = _SecHandle;
{$IFEND}

procedure SecInvalidateHandle(var x: TSecHandle); inline;
{$EXTERNALSYM SecInvalidateHandle}

function SecIsValidHandle(var x: TSecHandle): Boolean; inline;
{$EXTERNALSYM SecIsValidHandle}

//
// pseudo handle value: the handle has already been deleted
//
const
  SEC_DELETED_HANDLE  = ULONG_PTR(-2);
  {$EXTERNALSYM SEC_DELETED_HANDLE}

type
  PCredHandle = PSecHandle;
  {$EXTERNALSYM PCredHandle}
  CredHandle = SecHandle;
  {$EXTERNALSYM CredHandle}
  TCredHandle = SecHandle;

  PCtxtHandle = PSecHandle;
  {$EXTERNALSYM PCtxtHandle}
  CtxtHandle = SecHandle;
  {$EXTERNALSYM CtxtHandle}
  TCtxtHandle = SecHandle;

type
  _SECURITY_INTEGER = TLargeInteger;
  {$EXTERNALSYM _SECURITY_INTEGER}
  SECURITY_INTEGER = TLargeInteger;
  {$EXTERNALSYM SECURITY_INTEGER}
  PSECURITY_INTEGER = PLargeInteger;
  {$EXTERNALSYM PSECURITY_INTEGER}

type
  PTimeStamp = PSECURITY_INTEGER;
  {$EXTERNALSYM PTimeStamp}
  TimeStamp = SECURITY_INTEGER;
  {$EXTERNALSYM TimeStamp}
  TTimeStamp = SECURITY_INTEGER;

//
// If we are in 32 bit mode, define the SECURITY_STRING structure,
// as a clone of the base UNICODE_STRING structure.  This is used
// internally in security components, an as the string interface
// for kernel components (e.g. FSPs)
//



//
// SecPkgInfo structure
//
//  Provides general information about a security provider
//

type
  PSecPkgInfoW = ^TSecPkgInfoW;
  {$EXTERNALSYM PSecPkgInfoW}
  _SecPkgInfoW = record

    fCapabilities: Cardinal;        // Capability bitmask
    wVersion: Word;                 // Version of driver
    wRPCID: Word;                   // ID for RPC Runtime
    cbMaxToken: Cardinal;           // Size of authentication token (max)
    Name: PSecWChar;                // Text name

    Comment: PSecWChar;             // Comment
  end;
  {$EXTERNALSYM _SecPkgInfoW}
  SecPkgInfoW = _SecPkgInfoW;
  {$EXTERNALSYM SecPkgInfoW}
  TSecPkgInfoW = _SecPkgInfoW;

type
  PSecPkgInfoA = ^TSecPkgInfoA;
  {$EXTERNALSYM PSecPkgInfoA}
  _SecPkgInfoA = record

    fCapabilities: Cardinal;        // Capability bitmask
    wVersion: Word;                 // Version of driver
    wRPCID: Word;                   // ID for RPC Runtime
    cbMaxToken: Cardinal;           // Size of authentication token (max)
    Name: PSecChar;                 // Text name

    Comment: PSecChar;              // Comment
  end;
  {$EXTERNALSYM _SecPkgInfoA}
  SecPkgInfoA = _SecPkgInfoA;
  {$EXTERNALSYM SecPkgInfoA}
  TSecPkgInfoA = _SecPkgInfoA;

type
  PSecPkgInfo = PSecPkgInfoW;
  {$EXTERNALSYM PSecPkgInfo}
  SecPkgInfo = SecPkgInfoW;
  {$EXTERNALSYM SecPkgInfo}
  TSecPkgInfo = SecPkgInfoW;

//
//  Security Package Capabilities
//
const
  SECPKG_FLAG_INTEGRITY                  = $00000001;  // Supports integrity on messages
  {$EXTERNALSYM SECPKG_FLAG_INTEGRITY}
  SECPKG_FLAG_PRIVACY                    = $00000002;  // Supports privacy (confidentiality)
  {$EXTERNALSYM SECPKG_FLAG_PRIVACY}
  SECPKG_FLAG_TOKEN_ONLY                 = $00000004;  // Only security token needed
  {$EXTERNALSYM SECPKG_FLAG_TOKEN_ONLY}
  SECPKG_FLAG_DATAGRAM                   = $00000008;  // Datagram RPC support
  {$EXTERNALSYM SECPKG_FLAG_DATAGRAM}
  SECPKG_FLAG_CONNECTION                 = $00000010;  // Connection oriented RPC support
  {$EXTERNALSYM SECPKG_FLAG_CONNECTION}
  SECPKG_FLAG_MULTI_REQUIRED             = $00000020;  // Full 3-leg required for re-auth.
  {$EXTERNALSYM SECPKG_FLAG_MULTI_REQUIRED}
  SECPKG_FLAG_CLIENT_ONLY                = $00000040;  // Server side functionality not available
  {$EXTERNALSYM SECPKG_FLAG_CLIENT_ONLY}
  SECPKG_FLAG_EXTENDED_ERROR             = $00000080;  // Supports extended error msgs
  {$EXTERNALSYM SECPKG_FLAG_EXTENDED_ERROR}
  SECPKG_FLAG_IMPERSONATION              = $00000100;  // Supports impersonation
  {$EXTERNALSYM SECPKG_FLAG_IMPERSONATION}
  SECPKG_FLAG_ACCEPT_WIN32_NAME          = $00000200;  // Accepts Win32 names
  {$EXTERNALSYM SECPKG_FLAG_ACCEPT_WIN32_NAME}
  SECPKG_FLAG_STREAM                     = $00000400;  // Supports stream semantics
  {$EXTERNALSYM SECPKG_FLAG_STREAM}
  SECPKG_FLAG_NEGOTIABLE                 = $00000800;  // Can be used by the negotiate package
  {$EXTERNALSYM SECPKG_FLAG_NEGOTIABLE}
  SECPKG_FLAG_GSS_COMPATIBLE             = $00001000;  // GSS Compatibility Available
  {$EXTERNALSYM SECPKG_FLAG_GSS_COMPATIBLE}
  SECPKG_FLAG_LOGON                      = $00002000;  // Supports common LsaLogonUser
  {$EXTERNALSYM SECPKG_FLAG_LOGON}
  SECPKG_FLAG_ASCII_BUFFERS              = $00004000;  // Token Buffers are in ASCII
  {$EXTERNALSYM SECPKG_FLAG_ASCII_BUFFERS}
  SECPKG_FLAG_FRAGMENT                   = $00008000;  // Package can fragment to fit
  {$EXTERNALSYM SECPKG_FLAG_FRAGMENT}
  SECPKG_FLAG_MUTUAL_AUTH                = $00010000;  // Package can perform mutual authentication
  {$EXTERNALSYM SECPKG_FLAG_MUTUAL_AUTH}
  SECPKG_FLAG_DELEGATION                 = $00020000;  // Package can delegate
  {$EXTERNALSYM SECPKG_FLAG_DELEGATION}
  SECPKG_FLAG_READONLY_WITH_CHECKSUM     = $00040000;  // Package can delegate
  {$EXTERNALSYM SECPKG_FLAG_READONLY_WITH_CHECKSUM}
  SECPKG_FLAG_RESTRICTED_TOKENS          = $00080000;  // Package supports restricted callers
  {$EXTERNALSYM SECPKG_FLAG_RESTRICTED_TOKENS}
  SECPKG_FLAG_NEGO_EXTENDER              = $00100000;  // this package extends SPNEGO, there is at most one
  {$EXTERNALSYM SECPKG_FLAG_NEGO_EXTENDER}
  SECPKG_FLAG_NEGOTIABLE2                = $00200000;  // this package is negotiated under the NegoExtender
  {$EXTERNALSYM SECPKG_FLAG_NEGOTIABLE2}
  SECPKG_FLAG_APPCONTAINER_PASSTHROUGH   = $00400000;  // this package receives all calls from appcontainer apps
  {$EXTERNALSYM SECPKG_FLAG_APPCONTAINER_PASSTHROUGH}
  SECPKG_FLAG_APPCONTAINER_CHECKS        = $00800000;  // this package receives calls from appcontainer apps
  {$EXTERNALSYM SECPKG_FLAG_APPCONTAINER_CHECKS}
                                                      // if the following checks succeed
                                                      // 1. Caller has domain auth capability or
                                                      // 2. Target is a proxy server or
                                                      // 3. The caller has supplied creds

  SECPKG_ID_NONE     = $FFFF;
  {$EXTERNALSYM SECPKG_ID_NONE}

//
// Extended Call Flags that currently contains
// Appcontainer related information about the caller.
// Packages can query for these
// via an LsaFunction GetExtendedCallFlags
//
const
  SECPKG_CALLFLAGS_APPCONTAINER                  = $00000001;
  {$EXTERNALSYM SECPKG_CALLFLAGS_APPCONTAINER}
  SECPKG_CALLFLAGS_APPCONTAINER_AUTHCAPABLE      = $00000002;
  {$EXTERNALSYM SECPKG_CALLFLAGS_APPCONTAINER_AUTHCAPABLE}
  SECPKG_CALLFLAGS_FORCE_SUPPLIED                = $00000004;
  {$EXTERNALSYM SECPKG_CALLFLAGS_FORCE_SUPPLIED}


//
// SecBuffer
//
//  Generic memory descriptors for buffers passed in to the security
//  API
//

type
  PSecBuffer = ^TSecBuffer;
  {$EXTERNALSYM PSecBuffer}
  _SecBuffer = record
    cbBuffer: Cardinal;             // Size of the buffer, in bytes
    BufferType: Cardinal;           // Type of the buffer (below)
    pvBuffer: Pointer;              // Pointer to the buffer
  end;
  {$EXTERNALSYM _SecBuffer}
  SecBuffer = _SecBuffer;
  {$EXTERNALSYM SecBuffer}
  TSecBuffer = _SecBuffer;

type
  PSecBufferDesc = ^TSecBufferDesc;
  {$EXTERNALSYM PSecBufferDesc}
  _SecBufferDesc = record
    ulVersion: Cardinal;            // Version number
    cBuffers: Cardinal;             // Number of buffers
    pBuffers: PSecBuffer;           // Pointer to array of buffers
  end;
  {$EXTERNALSYM _SecBufferDesc}
  SecBufferDesc = _SecBufferDesc;
  {$EXTERNALSYM SecBufferDesc}
  TSecBufferDesc = _SecBufferDesc;

const
  SECBUFFER_VERSION          = 0;
  {$EXTERNALSYM SECBUFFER_VERSION}

  SECBUFFER_EMPTY            = 0;   // Undefined, replaced by provider
  {$EXTERNALSYM SECBUFFER_EMPTY}
  SECBUFFER_DATA             = 1;   // Packet data
  {$EXTERNALSYM SECBUFFER_DATA}
  SECBUFFER_TOKEN            = 2;   // Security token
  {$EXTERNALSYM SECBUFFER_TOKEN}
  SECBUFFER_PKG_PARAMS       = 3;   // Package specific parameters
  {$EXTERNALSYM SECBUFFER_PKG_PARAMS}
  SECBUFFER_MISSING          = 4;   // Missing Data indicator
  {$EXTERNALSYM SECBUFFER_MISSING}
  SECBUFFER_EXTRA            = 5;   // Extra data
  {$EXTERNALSYM SECBUFFER_EXTRA}
  SECBUFFER_STREAM_TRAILER   = 6;   // Security Trailer
  {$EXTERNALSYM SECBUFFER_STREAM_TRAILER}
  SECBUFFER_STREAM_HEADER    = 7;   // Security Header
  {$EXTERNALSYM SECBUFFER_STREAM_HEADER}
  SECBUFFER_NEGOTIATION_INFO = 8;   // Hints from the negotiation pkg
  {$EXTERNALSYM SECBUFFER_NEGOTIATION_INFO}
  SECBUFFER_PADDING          = 9;   // non-data padding
  {$EXTERNALSYM SECBUFFER_PADDING}
  SECBUFFER_STREAM           = 10;  // whole encrypted message
  {$EXTERNALSYM SECBUFFER_STREAM}
  SECBUFFER_MECHLIST         = 11;
  {$EXTERNALSYM SECBUFFER_MECHLIST}
  SECBUFFER_MECHLIST_SIGNATURE = 12;
  {$EXTERNALSYM SECBUFFER_MECHLIST_SIGNATURE}
  SECBUFFER_TARGET           = 13;  // obsolete
  {$EXTERNALSYM SECBUFFER_TARGET}
  SECBUFFER_CHANNEL_BINDINGS = 14;
  {$EXTERNALSYM SECBUFFER_CHANNEL_BINDINGS}
  SECBUFFER_CHANGE_PASS_RESPONSE = 15;
  {$EXTERNALSYM SECBUFFER_CHANGE_PASS_RESPONSE}
  SECBUFFER_TARGET_HOST      = 16;
  {$EXTERNALSYM SECBUFFER_TARGET_HOST}
  SECBUFFER_ALERT            = 17;
  {$EXTERNALSYM SECBUFFER_ALERT}

  SECBUFFER_ATTRMASK                     = $F0000000;
  {$EXTERNALSYM SECBUFFER_ATTRMASK}
  SECBUFFER_READONLY                     = $80000000;  // Buffer is read-only, no checksum
  {$EXTERNALSYM SECBUFFER_READONLY}
  SECBUFFER_READONLY_WITH_CHECKSUM       = $10000000;  // Buffer is read-only, and checksummed
  {$EXTERNALSYM SECBUFFER_READONLY_WITH_CHECKSUM}
  SECBUFFER_RESERVED                     = $60000000;  // Flags reserved to security system
  {$EXTERNALSYM SECBUFFER_RESERVED}


type
  PSecNegotiationInfo = ^TSecNegotiationInfo;
  _SEC_NEGOTIATION_INFO = record
    Size: Cardinal;           // Size of this structure
    NameLength: Cardinal;     // Length of name hint
    Name: PSecWChar;          // Name hint
    Reserved: Pointer;        // Reserved
  end;
  {$EXTERNALSYM _SEC_NEGOTIATION_INFO}
  SEC_NEGOTIATION_INFO = _SEC_NEGOTIATION_INFO;
  {$EXTERNALSYM SEC_NEGOTIATION_INFO}
  TSecNegotiationInfo = _SEC_NEGOTIATION_INFO;
  PSEC_NEGOTIATION_INFO = PSecNegotiationInfo;
  {$EXTERNALSYM PSEC_NEGOTIATION_INFO}

type
  PSecChannelBindings = ^TSecChannelBindings;
  _SEC_CHANNEL_BINDINGS = record
    dwInitiatorAddrType: Cardinal;
    cbInitiatorLength: Cardinal;
    dwInitiatorOffset: Cardinal;
    dwAcceptorAddrType: Cardinal;
    cbAcceptorLength: Cardinal;
    dwAcceptorOffset: Cardinal;
    cbApplicationDataLength: Cardinal;
    dwApplicationDataOffset: Cardinal;
  end;
  {$EXTERNALSYM _SEC_CHANNEL_BINDINGS}
  SEC_CHANNEL_BINDINGS = _SEC_CHANNEL_BINDINGS;
  {$EXTERNALSYM SEC_CHANNEL_BINDINGS}
  TSecChannelBindings = _SEC_CHANNEL_BINDINGS;
  PSEC_CHANNEL_BINDINGS = PSecChannelBindings;
  {$EXTERNALSYM PSEC_CHANNEL_BINDINGS}


//
//  Data Representation Constant:
//
const
  SECURITY_NATIVE_DREP       = $00000010;
  {$EXTERNALSYM SECURITY_NATIVE_DREP}
  SECURITY_NETWORK_DREP      = $00000000;
  {$EXTERNALSYM SECURITY_NETWORK_DREP}

//
//  Credential Use Flags
//
const
  SECPKG_CRED_INBOUND        = $00000001;
  {$EXTERNALSYM SECPKG_CRED_INBOUND}
  SECPKG_CRED_OUTBOUND       = $00000002;
  {$EXTERNALSYM SECPKG_CRED_OUTBOUND}
  SECPKG_CRED_BOTH           = $00000003;
  {$EXTERNALSYM SECPKG_CRED_BOTH}
  SECPKG_CRED_DEFAULT        = $00000004;
  {$EXTERNALSYM SECPKG_CRED_DEFAULT}
  SECPKG_CRED_RESERVED       = $F0000000;
  {$EXTERNALSYM SECPKG_CRED_RESERVED}

//
//  SSP SHOULD prompt the user for credentials/consent, independent
//  of whether credentials to be used are the 'logged on' credentials
//  or retrieved from credman.
//
//  An SSP may choose not to prompt, however, in circumstances determined
//  by the SSP.
//
const
  SECPKG_CRED_AUTOLOGON_RESTRICTED   = $00000010;
  {$EXTERNALSYM SECPKG_CRED_AUTOLOGON_RESTRICTED}

//
// auth will always fail, ISC() is called to process policy data only
//
const
  SECPKG_CRED_PROCESS_POLICY_ONLY    = $00000020;
  {$EXTERNALSYM SECPKG_CRED_PROCESS_POLICY_ONLY}


//
//  InitializeSecurityContext Requirement and return flags:
//
const
  ISC_REQ_DELEGATE               = $00000001;
  {$EXTERNALSYM ISC_REQ_DELEGATE}
  ISC_REQ_MUTUAL_AUTH            = $00000002;
  {$EXTERNALSYM ISC_REQ_MUTUAL_AUTH}
  ISC_REQ_REPLAY_DETECT          = $00000004;
  {$EXTERNALSYM ISC_REQ_REPLAY_DETECT}
  ISC_REQ_SEQUENCE_DETECT        = $00000008;
  {$EXTERNALSYM ISC_REQ_SEQUENCE_DETECT}
  ISC_REQ_CONFIDENTIALITY        = $00000010;
  {$EXTERNALSYM ISC_REQ_CONFIDENTIALITY}
  ISC_REQ_USE_SESSION_KEY        = $00000020;
  {$EXTERNALSYM ISC_REQ_USE_SESSION_KEY}
  ISC_REQ_PROMPT_FOR_CREDS       = $00000040;
  {$EXTERNALSYM ISC_REQ_PROMPT_FOR_CREDS}
  ISC_REQ_USE_SUPPLIED_CREDS     = $00000080;
  {$EXTERNALSYM ISC_REQ_USE_SUPPLIED_CREDS}
  ISC_REQ_ALLOCATE_MEMORY        = $00000100;
  {$EXTERNALSYM ISC_REQ_ALLOCATE_MEMORY}
  ISC_REQ_USE_DCE_STYLE          = $00000200;
  {$EXTERNALSYM ISC_REQ_USE_DCE_STYLE}
  ISC_REQ_DATAGRAM               = $00000400;
  {$EXTERNALSYM ISC_REQ_DATAGRAM}
  ISC_REQ_CONNECTION             = $00000800;
  {$EXTERNALSYM ISC_REQ_CONNECTION}
  ISC_REQ_CALL_LEVEL             = $00001000;
  {$EXTERNALSYM ISC_REQ_CALL_LEVEL}
  ISC_REQ_FRAGMENT_SUPPLIED      = $00002000;
  {$EXTERNALSYM ISC_REQ_FRAGMENT_SUPPLIED}
  ISC_REQ_EXTENDED_ERROR         = $00004000;
  {$EXTERNALSYM ISC_REQ_EXTENDED_ERROR}
  ISC_REQ_STREAM                 = $00008000;
  {$EXTERNALSYM ISC_REQ_STREAM}
  ISC_REQ_INTEGRITY              = $00010000;
  {$EXTERNALSYM ISC_REQ_INTEGRITY}
  ISC_REQ_IDENTIFY               = $00020000;
  {$EXTERNALSYM ISC_REQ_IDENTIFY}
  ISC_REQ_NULL_SESSION           = $00040000;
  {$EXTERNALSYM ISC_REQ_NULL_SESSION}
  ISC_REQ_MANUAL_CRED_VALIDATION = $00080000;
  {$EXTERNALSYM ISC_REQ_MANUAL_CRED_VALIDATION}
  ISC_REQ_RESERVED1              = $00100000;
  {$EXTERNALSYM ISC_REQ_RESERVED1}
  ISC_REQ_FRAGMENT_TO_FIT        = $00200000;
  {$EXTERNALSYM ISC_REQ_FRAGMENT_TO_FIT}
// This exists only in Windows Vista and greater
const
  ISC_REQ_FORWARD_CREDENTIALS    = $00400000;
  {$EXTERNALSYM ISC_REQ_FORWARD_CREDENTIALS}
  ISC_REQ_NO_INTEGRITY           = $00800000; // honored only by SPNEGO
  {$EXTERNALSYM ISC_REQ_NO_INTEGRITY}
  ISC_REQ_USE_HTTP_STYLE         = $01000000;
  {$EXTERNALSYM ISC_REQ_USE_HTTP_STYLE}
  ISC_REQ_UNVERIFIED_TARGET_NAME = $20000000;
  {$EXTERNALSYM ISC_REQ_UNVERIFIED_TARGET_NAME}
  ISC_REQ_CONFIDENTIALITY_ONLY   = $40000000; // honored by SPNEGO/Kerberos
  {$EXTERNALSYM ISC_REQ_CONFIDENTIALITY_ONLY}

  ISC_RET_DELEGATE               = $00000001;
  {$EXTERNALSYM ISC_RET_DELEGATE}
  ISC_RET_MUTUAL_AUTH            = $00000002;
  {$EXTERNALSYM ISC_RET_MUTUAL_AUTH}
  ISC_RET_REPLAY_DETECT          = $00000004;
  {$EXTERNALSYM ISC_RET_REPLAY_DETECT}
  ISC_RET_SEQUENCE_DETECT        = $00000008;
  {$EXTERNALSYM ISC_RET_SEQUENCE_DETECT}
  ISC_RET_CONFIDENTIALITY        = $00000010;
  {$EXTERNALSYM ISC_RET_CONFIDENTIALITY}
  ISC_RET_USE_SESSION_KEY        = $00000020;
  {$EXTERNALSYM ISC_RET_USE_SESSION_KEY}
  ISC_RET_USED_COLLECTED_CREDS   = $00000040;
  {$EXTERNALSYM ISC_RET_USED_COLLECTED_CREDS}
  ISC_RET_USED_SUPPLIED_CREDS    = $00000080;
  {$EXTERNALSYM ISC_RET_USED_SUPPLIED_CREDS}
  ISC_RET_ALLOCATED_MEMORY       = $00000100;
  {$EXTERNALSYM ISC_RET_ALLOCATED_MEMORY}
  ISC_RET_USED_DCE_STYLE         = $00000200;
  {$EXTERNALSYM ISC_RET_USED_DCE_STYLE}
  ISC_RET_DATAGRAM               = $00000400;
  {$EXTERNALSYM ISC_RET_DATAGRAM}
  ISC_RET_CONNECTION             = $00000800;
  {$EXTERNALSYM ISC_RET_CONNECTION}
  ISC_RET_INTERMEDIATE_RETURN    = $00001000;
  {$EXTERNALSYM ISC_RET_INTERMEDIATE_RETURN}
  ISC_RET_CALL_LEVEL             = $00002000;
  {$EXTERNALSYM ISC_RET_CALL_LEVEL}
  ISC_RET_EXTENDED_ERROR         = $00004000;
  {$EXTERNALSYM ISC_RET_EXTENDED_ERROR}
  ISC_RET_STREAM                 = $00008000;
  {$EXTERNALSYM ISC_RET_STREAM}
  ISC_RET_INTEGRITY              = $00010000;
  {$EXTERNALSYM ISC_RET_INTEGRITY}
  ISC_RET_IDENTIFY               = $00020000;
  {$EXTERNALSYM ISC_RET_IDENTIFY}
  ISC_RET_NULL_SESSION           = $00040000;
  {$EXTERNALSYM ISC_RET_NULL_SESSION}
  ISC_RET_MANUAL_CRED_VALIDATION = $00080000;
  {$EXTERNALSYM ISC_RET_MANUAL_CRED_VALIDATION}
  ISC_RET_RESERVED1              = $00100000;
  {$EXTERNALSYM ISC_RET_RESERVED1}
  ISC_RET_FRAGMENT_ONLY          = $00200000;
  {$EXTERNALSYM ISC_RET_FRAGMENT_ONLY}
// This exists only in Windows Vista and greater
const
  ISC_RET_FORWARD_CREDENTIALS    = $00400000;
  {$EXTERNALSYM ISC_RET_FORWARD_CREDENTIALS}

  ISC_RET_USED_HTTP_STYLE        = $01000000;
  {$EXTERNALSYM ISC_RET_USED_HTTP_STYLE}
  ISC_RET_NO_ADDITIONAL_TOKEN    = $02000000; // *INTERNAL*
  {$EXTERNALSYM ISC_RET_NO_ADDITIONAL_TOKEN}
  ISC_RET_REAUTHENTICATION       = $08000000; // *INTERNAL*
  {$EXTERNALSYM ISC_RET_REAUTHENTICATION}
  ISC_RET_CONFIDENTIALITY_ONLY   = $40000000; // honored by SPNEGO/Kerberos
  {$EXTERNALSYM ISC_RET_CONFIDENTIALITY_ONLY}

  ASC_REQ_DELEGATE               = $00000001;
  {$EXTERNALSYM ASC_REQ_DELEGATE}
  ASC_REQ_MUTUAL_AUTH            = $00000002;
  {$EXTERNALSYM ASC_REQ_MUTUAL_AUTH}
  ASC_REQ_REPLAY_DETECT          = $00000004;
  {$EXTERNALSYM ASC_REQ_REPLAY_DETECT}
  ASC_REQ_SEQUENCE_DETECT        = $00000008;
  {$EXTERNALSYM ASC_REQ_SEQUENCE_DETECT}
  ASC_REQ_CONFIDENTIALITY        = $00000010;
  {$EXTERNALSYM ASC_REQ_CONFIDENTIALITY}
  ASC_REQ_USE_SESSION_KEY        = $00000020;
  {$EXTERNALSYM ASC_REQ_USE_SESSION_KEY}
  ASC_REQ_ALLOCATE_MEMORY        = $00000100;
  {$EXTERNALSYM ASC_REQ_ALLOCATE_MEMORY}
  ASC_REQ_USE_DCE_STYLE          = $00000200;
  {$EXTERNALSYM ASC_REQ_USE_DCE_STYLE}
  ASC_REQ_DATAGRAM               = $00000400;
  {$EXTERNALSYM ASC_REQ_DATAGRAM}
  ASC_REQ_CONNECTION             = $00000800;
  {$EXTERNALSYM ASC_REQ_CONNECTION}
  ASC_REQ_CALL_LEVEL             = $00001000;
  {$EXTERNALSYM ASC_REQ_CALL_LEVEL}
  ASC_REQ_EXTENDED_ERROR         = $00008000;
  {$EXTERNALSYM ASC_REQ_EXTENDED_ERROR}
  ASC_REQ_STREAM                 = $00010000;
  {$EXTERNALSYM ASC_REQ_STREAM}
  ASC_REQ_INTEGRITY              = $00020000;
  {$EXTERNALSYM ASC_REQ_INTEGRITY}
  ASC_REQ_LICENSING              = $00040000;
  {$EXTERNALSYM ASC_REQ_LICENSING}
  ASC_REQ_IDENTIFY               = $00080000;
  {$EXTERNALSYM ASC_REQ_IDENTIFY}
  ASC_REQ_ALLOW_NULL_SESSION     = $00100000;
  {$EXTERNALSYM ASC_REQ_ALLOW_NULL_SESSION}
  ASC_REQ_ALLOW_NON_USER_LOGONS  = $00200000;
  {$EXTERNALSYM ASC_REQ_ALLOW_NON_USER_LOGONS}
  ASC_REQ_ALLOW_CONTEXT_REPLAY   = $00400000;
  {$EXTERNALSYM ASC_REQ_ALLOW_CONTEXT_REPLAY}
  ASC_REQ_FRAGMENT_TO_FIT        = $00800000;
  {$EXTERNALSYM ASC_REQ_FRAGMENT_TO_FIT}
  ASC_REQ_FRAGMENT_SUPPLIED      = $00002000;
  {$EXTERNALSYM ASC_REQ_FRAGMENT_SUPPLIED}
  ASC_REQ_NO_TOKEN               = $01000000;
  {$EXTERNALSYM ASC_REQ_NO_TOKEN}
  ASC_REQ_PROXY_BINDINGS         = $04000000;
  {$EXTERNALSYM ASC_REQ_PROXY_BINDINGS}
//      SSP_RET_REAUTHENTICATION        0x08000000  // *INTERNAL*
  ASC_REQ_ALLOW_MISSING_BINDINGS = $10000000;
  {$EXTERNALSYM ASC_REQ_ALLOW_MISSING_BINDINGS}

  ASC_RET_DELEGATE               = $00000001;
  {$EXTERNALSYM ASC_RET_DELEGATE}
  ASC_RET_MUTUAL_AUTH            = $00000002;
  {$EXTERNALSYM ASC_RET_MUTUAL_AUTH}
  ASC_RET_REPLAY_DETECT          = $00000004;
  {$EXTERNALSYM ASC_RET_REPLAY_DETECT}
  ASC_RET_SEQUENCE_DETECT        = $00000008;
  {$EXTERNALSYM ASC_RET_SEQUENCE_DETECT}
  ASC_RET_CONFIDENTIALITY        = $00000010;
  {$EXTERNALSYM ASC_RET_CONFIDENTIALITY}
  ASC_RET_USE_SESSION_KEY        = $00000020;
  {$EXTERNALSYM ASC_RET_USE_SESSION_KEY}
  ASC_RET_ALLOCATED_MEMORY       = $00000100;
  {$EXTERNALSYM ASC_RET_ALLOCATED_MEMORY}
  ASC_RET_USED_DCE_STYLE         = $00000200;
  {$EXTERNALSYM ASC_RET_USED_DCE_STYLE}
  ASC_RET_DATAGRAM               = $00000400;
  {$EXTERNALSYM ASC_RET_DATAGRAM}
  ASC_RET_CONNECTION             = $00000800;
  {$EXTERNALSYM ASC_RET_CONNECTION}
  ASC_RET_CALL_LEVEL             = $00002000; // skipped 1000 to be like ISC_
  {$EXTERNALSYM ASC_RET_CALL_LEVEL}
  ASC_RET_THIRD_LEG_FAILED       = $00004000;
  {$EXTERNALSYM ASC_RET_THIRD_LEG_FAILED}
  ASC_RET_EXTENDED_ERROR         = $00008000;
  {$EXTERNALSYM ASC_RET_EXTENDED_ERROR}
  ASC_RET_STREAM                 = $00010000;
  {$EXTERNALSYM ASC_RET_STREAM}
  ASC_RET_INTEGRITY              = $00020000;
  {$EXTERNALSYM ASC_RET_INTEGRITY}
  ASC_RET_LICENSING              = $00040000;
  {$EXTERNALSYM ASC_RET_LICENSING}
  ASC_RET_IDENTIFY               = $00080000;
  {$EXTERNALSYM ASC_RET_IDENTIFY}
  ASC_RET_NULL_SESSION           = $00100000;
  {$EXTERNALSYM ASC_RET_NULL_SESSION}
  ASC_RET_ALLOW_NON_USER_LOGONS  = $00200000;
  {$EXTERNALSYM ASC_RET_ALLOW_NON_USER_LOGONS}
  ASC_RET_ALLOW_CONTEXT_REPLAY   = $00400000;  // deprecated - don't use this flag!!!
  {$EXTERNALSYM ASC_RET_ALLOW_CONTEXT_REPLAY}
  ASC_RET_FRAGMENT_ONLY          = $00800000;
  {$EXTERNALSYM ASC_RET_FRAGMENT_ONLY}
  ASC_RET_NO_TOKEN               = $01000000;
  {$EXTERNALSYM ASC_RET_NO_TOKEN}
  ASC_RET_NO_ADDITIONAL_TOKEN    = $02000000;  // *INTERNAL*
  {$EXTERNALSYM ASC_RET_NO_ADDITIONAL_TOKEN}
//      SSP_RET_REAUTHENTICATION        0x08000000  // *INTERNAL*

//
//  Security Credentials Attributes:
//
const
  SECPKG_CRED_ATTR_NAMES        = 1;
  {$EXTERNALSYM SECPKG_CRED_ATTR_NAMES}
  SECPKG_CRED_ATTR_SSI_PROVIDER = 2;
  {$EXTERNALSYM SECPKG_CRED_ATTR_SSI_PROVIDER}
  SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS = 3;
  {$EXTERNALSYM SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS}
  SECPKG_CRED_ATTR_CERT         = 4;
  {$EXTERNALSYM SECPKG_CRED_ATTR_CERT}

type
  PSecPkgCredentialsNamesW = ^TSecPkgCredentialsNamesW;
  _SecPkgCredentials_NamesW = record
    sUserName: PSecWChar;

  end;
  {$EXTERNALSYM _SecPkgCredentials_NamesW}
  SecPkgCredentials_NamesW = _SecPkgCredentials_NamesW;
  {$EXTERNALSYM SecPkgCredentials_NamesW}
  TSecPkgCredentialsNamesW = _SecPkgCredentials_NamesW;
  PSecPkgCredentials_NamesW = PSecPkgCredentialsNamesW;
  {$EXTERNALSYM PSecPkgCredentials_NamesW}

type
  PSecPkgCredentialsNamesA = ^TSecPkgCredentialsNamesA;
  _SecPkgCredentials_NamesA = record
    sUserName: PSecChar;

  end;
  {$EXTERNALSYM _SecPkgCredentials_NamesA}
  SecPkgCredentials_NamesA = _SecPkgCredentials_NamesA;
  {$EXTERNALSYM SecPkgCredentials_NamesA}
  TSecPkgCredentialsNamesA = _SecPkgCredentials_NamesA;
  PSecPkgCredentials_NamesA = PSecPkgCredentialsNamesA;
  {$EXTERNALSYM PSecPkgCredentials_NamesA}

type
   PSecPkgCredentialsNames = PSecPkgCredentials_NamesW;
   SecPkgCredentials_Names = SecPkgCredentials_NamesW;
   {$EXTERNALSYM SecPkgCredentials_Names}
   TSecPkgCredentialsNames = SecPkgCredentials_NamesW;
   PSecPkgCredentials_Names = PSecPkgCredentialsNames;
   {$EXTERNALSYM PSecPkgCredentials_Names}


type
  PSecPkgCredentialsSSIProviderW = ^TSecPkgCredentialsSSIProviderW;
  _SecPkgCredentials_SSIProviderW = record
    sProviderName: PSecWChar;
    ProviderInfoLength: Cardinal;
    ProviderInfo: PAnsiChar;
  end;
  {$EXTERNALSYM _SecPkgCredentials_SSIProviderW}
  SecPkgCredentials_SSIProviderW = _SecPkgCredentials_SSIProviderW;
  {$EXTERNALSYM SecPkgCredentials_SSIProviderW}
  TSecPkgCredentialsSSIProviderW = _SecPkgCredentials_SSIProviderW;
  PSecPkgCredentials_SSIProviderW = PSecPkgCredentialsSSIProviderW;
  {$EXTERNALSYM PSecPkgCredentials_SSIProviderW}

type
  PSecPkgCredentialsSSIProviderA = ^TSecPkgCredentialsSSIProviderA;
  _SecPkgCredentials_SSIProviderA = record
    sProviderName: PSecChar;
    ProviderInfoLength: Cardinal;
    ProviderInfo: PAnsiChar;
  end;
  {$EXTERNALSYM _SecPkgCredentials_SSIProviderA}
  SecPkgCredentials_SSIProviderA = _SecPkgCredentials_SSIProviderA;
  {$EXTERNALSYM SecPkgCredentials_SSIProviderA}
  TSecPkgCredentialsSSIProviderA = _SecPkgCredentials_SSIProviderA;
  PSecPkgCredentials_SSIProviderA = PSecPkgCredentialsSSIProviderA;
  {$EXTERNALSYM PSecPkgCredentials_SSIProviderA}

type
  PSecPkgCredentialsSSIProvider = PSecPkgCredentials_SSIProviderW;
  SecPkgCredentials_SSIProvider = SecPkgCredentials_SSIProviderW;
  {$EXTERNALSYM SecPkgCredentials_SSIProvider}
  TSecPkgCredentialsSSIProvider = SecPkgCredentials_SSIProviderW;
  PSecPkgCredentials_SSIProvider = PSecPkgCredentialsSSIProvider;
  {$EXTERNALSYM PSecPkgCredentials_SSIProvider}

const
  KDC_PROXY_SETTINGS_V1               =  1;
  {$EXTERNALSYM KDC_PROXY_SETTINGS_V1}
  KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY = $1;
  {$EXTERNALSYM KDC_PROXY_SETTINGS_FLAGS_FORCEPROXY}

type
  PSecPkgCredentialsKdcProxySettingsW = ^TSecPkgCredentialsKdcProxySettingsW;
  _SecPkgCredentials_KdcProxySettingsW = record
    Version: ULONG;              // KDC_PROXY_SETTINGS_V1
    Flags: ULONG ;               // KDC_PROXY_SETTINGS_FLAGS_*
    ProxyServerOffset: USHORT;   // ProxyServer, optional
    ProxyServerLength: USHORT;
    ClientTlsCredOffset: USHORT; // ClientTlsCred, optional
    ClientTlsCredLength: USHORT;
  end;
  {$EXTERNALSYM _SecPkgCredentials_KdcProxySettingsW}
  SecPkgCredentials_KdcProxySettingsW = _SecPkgCredentials_KdcProxySettingsW;
  {$EXTERNALSYM SecPkgCredentials_KdcProxySettingsW}
  TSecPkgCredentialsKdcProxySettingsW = _SecPkgCredentials_KdcProxySettingsW;
  PSecPkgCredentials_KdcProxySettingsW = PSecPkgCredentialsKdcProxySettingsW;
  {$EXTERNALSYM PSecPkgCredentials_KdcProxySettingsW}

type
  PSecPkgCredentialsCert = ^TSecPkgCredentialsCert;
  _SecPkgCredentials_Cert = record
    EncodedCertSize: Cardinal;
    EncodedCert: PByte;
  end;
  {$EXTERNALSYM _SecPkgCredentials_Cert}
  SecPkgCredentials_Cert = _SecPkgCredentials_Cert;
  {$EXTERNALSYM SecPkgCredentials_Cert}
  TSecPkgCredentialsCert = _SecPkgCredentials_Cert;
  PSecPkgCredentials_Cert = PSecPkgCredentialsCert;
  {$EXTERNALSYM PSecPkgCredentials_Cert}

//
//  Security Context Attributes:
//
const
  SECPKG_ATTR_SIZES           = 0;
  {$EXTERNALSYM SECPKG_ATTR_SIZES}
  SECPKG_ATTR_NAMES           = 1;
  {$EXTERNALSYM SECPKG_ATTR_NAMES}
  SECPKG_ATTR_LIFESPAN        = 2;
  {$EXTERNALSYM SECPKG_ATTR_LIFESPAN}
  SECPKG_ATTR_DCE_INFO        = 3;
  {$EXTERNALSYM SECPKG_ATTR_DCE_INFO}
  SECPKG_ATTR_STREAM_SIZES    = 4;
  {$EXTERNALSYM SECPKG_ATTR_STREAM_SIZES}
  SECPKG_ATTR_KEY_INFO        = 5;
  {$EXTERNALSYM SECPKG_ATTR_KEY_INFO}
  SECPKG_ATTR_AUTHORITY       = 6;
  {$EXTERNALSYM SECPKG_ATTR_AUTHORITY}
  SECPKG_ATTR_PROTO_INFO      = 7;
  {$EXTERNALSYM SECPKG_ATTR_PROTO_INFO}
  SECPKG_ATTR_PASSWORD_EXPIRY = 8;
  {$EXTERNALSYM SECPKG_ATTR_PASSWORD_EXPIRY}
  SECPKG_ATTR_SESSION_KEY     = 9;
  {$EXTERNALSYM SECPKG_ATTR_SESSION_KEY}
  SECPKG_ATTR_PACKAGE_INFO    = 10;
  {$EXTERNALSYM SECPKG_ATTR_PACKAGE_INFO}
  SECPKG_ATTR_USER_FLAGS      = 11;
  {$EXTERNALSYM SECPKG_ATTR_USER_FLAGS}
  SECPKG_ATTR_NEGOTIATION_INFO = 12;
  {$EXTERNALSYM SECPKG_ATTR_NEGOTIATION_INFO}
  SECPKG_ATTR_NATIVE_NAMES    = 13;
  {$EXTERNALSYM SECPKG_ATTR_NATIVE_NAMES}
  SECPKG_ATTR_FLAGS           = 14;
  {$EXTERNALSYM SECPKG_ATTR_FLAGS}
// These attributes exist only in Win XP and greater
const
  SECPKG_ATTR_USE_VALIDATED   = 15;
  {$EXTERNALSYM SECPKG_ATTR_USE_VALIDATED}
  SECPKG_ATTR_CREDENTIAL_NAME = 16;
  {$EXTERNALSYM SECPKG_ATTR_CREDENTIAL_NAME}
  SECPKG_ATTR_TARGET_INFORMATION = 17;
  {$EXTERNALSYM SECPKG_ATTR_TARGET_INFORMATION}
  SECPKG_ATTR_ACCESS_TOKEN    = 18;
  {$EXTERNALSYM SECPKG_ATTR_ACCESS_TOKEN}
// These attributes exist only in Win2K3 and greater
const
  SECPKG_ATTR_TARGET          = 19;
  {$EXTERNALSYM SECPKG_ATTR_TARGET}
  SECPKG_ATTR_AUTHENTICATION_ID = 20;
  {$EXTERNALSYM SECPKG_ATTR_AUTHENTICATION_ID}
// These attributes exist only in Win2K3SP1 and greater
const
  SECPKG_ATTR_LOGOFF_TIME     = 21;
  {$EXTERNALSYM SECPKG_ATTR_LOGOFF_TIME}
//
// win7 or greater
//
const
  SECPKG_ATTR_NEGO_KEYS         = 22;
  {$EXTERNALSYM SECPKG_ATTR_NEGO_KEYS}
  SECPKG_ATTR_PROMPTING_NEEDED  = 24;
  {$EXTERNALSYM SECPKG_ATTR_PROMPTING_NEEDED}
  SECPKG_ATTR_UNIQUE_BINDINGS   = 25;
  {$EXTERNALSYM SECPKG_ATTR_UNIQUE_BINDINGS}
  SECPKG_ATTR_ENDPOINT_BINDINGS = 26;
  {$EXTERNALSYM SECPKG_ATTR_ENDPOINT_BINDINGS}
  SECPKG_ATTR_CLIENT_SPECIFIED_TARGET = 27;
  {$EXTERNALSYM SECPKG_ATTR_CLIENT_SPECIFIED_TARGET}

  SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS = 30;
  {$EXTERNALSYM SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS}
  SECPKG_ATTR_NEGO_PKG_INFO        = 31; // contains nego info of packages
  {$EXTERNALSYM SECPKG_ATTR_NEGO_PKG_INFO}
  SECPKG_ATTR_NEGO_STATUS          = 32; // contains the last error
  {$EXTERNALSYM SECPKG_ATTR_NEGO_STATUS}
  SECPKG_ATTR_CONTEXT_DELETED      = 33; // a context has been deleted
  {$EXTERNALSYM SECPKG_ATTR_CONTEXT_DELETED}

//
// win8 or greater
//
const
  SECPKG_ATTR_DTLS_MTU        = 34;
  {$EXTERNALSYM SECPKG_ATTR_DTLS_MTU}
  SECPKG_ATTR_DATAGRAM_SIZES  = SECPKG_ATTR_STREAM_SIZES;
  {$EXTERNALSYM SECPKG_ATTR_DATAGRAM_SIZES}

  SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES = 128;
  {$EXTERNALSYM SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES}

type
  PSecPkgContextSubjectAttributes = ^TSecPkgContextSubjectAttributes;
  _SecPkgContext_SubjectAttributes = record
    AttributeInfo: Pointer; // contains a PAUTHZ_SECURITY_ATTRIBUTES_INFORMATION structure
  end;
  {$EXTERNALSYM _SecPkgContext_SubjectAttributes}
  SecPkgContext_SubjectAttributes = _SecPkgContext_SubjectAttributes;
  {$EXTERNALSYM SecPkgContext_SubjectAttributes}
  TSecPkgContextSubjectAttributes = _SecPkgContext_SubjectAttributes;
  PSecPkgContext_SubjectAttributes = PSecPkgContextSubjectAttributes;
  {$EXTERNALSYM PSecPkgContext_SubjectAttributes}

const
  SECPKG_ATTR_NEGO_INFO_FLAG_NO_KERBEROS = $1;
  {$EXTERNALSYM SECPKG_ATTR_NEGO_INFO_FLAG_NO_KERBEROS}
  SECPKG_ATTR_NEGO_INFO_FLAG_NO_NTLM     = $2;
  {$EXTERNALSYM SECPKG_ATTR_NEGO_INFO_FLAG_NO_NTLM}

//
// types of credentials, used by SECPKG_ATTR_PROMPTING_NEEDED
//

type
  PSecPkgCredClass = ^TSecPkgCredClass;
  _SECPKG_CRED_CLASS = (
    SecPkgCredClass_None = 0,               // no creds
    SecPkgCredClass_Ephemeral = 10,         // logon creds
    SecPkgCredClass_PersistedGeneric = 20,  // saved creds, not target specific
    SecPkgCredClass_PersistedSpecific = 30, // saved creds, target specific
    SecPkgCredClass_Explicit = 40           // explicitly supplied creds
  );
  {$EXTERNALSYM _SECPKG_CRED_CLASS}
  SECPKG_CRED_CLASS = _SECPKG_CRED_CLASS;
  {$EXTERNALSYM SECPKG_CRED_CLASS}
  TSecPkgCredClass = _SECPKG_CRED_CLASS;
  PSECPKG_CRED_CLASS = PSecPkgCredClass;
  {$EXTERNALSYM PSECPKG_CRED_CLASS}

type
  PSecPkgContextCredInfo = ^TSecPkgContextCredInfo;
  _SecPkgContext_CredInfo = record
    CredClass: TSecPkgCredClass;
    IsPromptingNeeded: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_CredInfo}
  SecPkgContext_CredInfo = _SecPkgContext_CredInfo;
  {$EXTERNALSYM SecPkgContext_CredInfo}
  TSecPkgContextCredInfo = _SecPkgContext_CredInfo;
  PSecPkgContext_CredInfo = PSecPkgContextCredInfo;
  {$EXTERNALSYM PSecPkgContext_CredInfo}

type
  PSecPkgContextNegoPackageInfo = ^TSecPkgContextNegoPackageInfo;
  _SecPkgContext_NegoPackageInfo = record
    PackageMask: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_NegoPackageInfo}
  SecPkgContext_NegoPackageInfo = _SecPkgContext_NegoPackageInfo;
  {$EXTERNALSYM SecPkgContext_NegoPackageInfo}
  TSecPkgContextNegoPackageInfo = _SecPkgContext_NegoPackageInfo;
  PSecPkgContext_NegoPackageInfo = PSecPkgContextNegoPackageInfo;
  {$EXTERNALSYM PSecPkgContext_NegoPackageInfo}

type
  PSecPkgContextNegoStatus = ^TSecPkgContextNegoStatus;
  _SecPkgContext_NegoStatus = record
    LastStatus: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_NegoStatus}
  SecPkgContext_NegoStatus = _SecPkgContext_NegoStatus;
  {$EXTERNALSYM SecPkgContext_NegoStatus}
  TSecPkgContextNegoStatus = _SecPkgContext_NegoStatus;
  PSecPkgContext_NegoStatus = PSecPkgContextNegoStatus;
  {$EXTERNALSYM PSecPkgContext_NegoStatus}

type
  PSecPkgContextSizes = ^TSecPkgContextSizes;
  _SecPkgContext_Sizes = record
    cbMaxToken: Cardinal;
    cbMaxSignature: Cardinal;
    cbBlockSize: Cardinal;
    cbSecurityTrailer: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_Sizes}
  SecPkgContext_Sizes = _SecPkgContext_Sizes;
  {$EXTERNALSYM SecPkgContext_Sizes}
  TSecPkgContextSizes = _SecPkgContext_Sizes;
  PSecPkgContext_Sizes = PSecPkgContextSizes;
  {$EXTERNALSYM PSecPkgContext_Sizes}

type
  PSecPkgContextStreamSizes = ^TSecPkgContextStreamSizes;
  _SecPkgContext_StreamSizes = record
    cbHeader: Cardinal;
    cbTrailer: Cardinal;
    cbMaximumMessage: Cardinal;
    cBuffers: Cardinal;
    cbBlockSize: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_StreamSizes}
  SecPkgContext_StreamSizes = _SecPkgContext_StreamSizes;
  {$EXTERNALSYM SecPkgContext_StreamSizes}
  TSecPkgContextStreamSizes = _SecPkgContext_StreamSizes;
  PSecPkgContext_StreamSizes = PSecPkgContextStreamSizes;
  {$EXTERNALSYM PSecPkgContext_StreamSizes}

type
  PSecPkgContextDatagramSizes = PSecPkgContext_StreamSizes;
  SecPkgContext_DatagramSizes = SecPkgContext_StreamSizes;
  {$EXTERNALSYM SecPkgContext_DatagramSizes}
  TSecPkgContextDatagramSizes = SecPkgContext_StreamSizes;
  PSecPkgContext_DatagramSizes = PSecPkgContextDatagramSizes;
  {$EXTERNALSYM PSecPkgContext_DatagramSizes}

type
  PSecPkgContextNamesW = ^TSecPkgContextNamesW;
  _SecPkgContext_NamesW = record
    sUserName: PSecWChar;
  end;
  {$EXTERNALSYM _SecPkgContext_NamesW}
  SecPkgContext_NamesW = _SecPkgContext_NamesW;
  {$EXTERNALSYM SecPkgContext_NamesW}
  TSecPkgContextNamesW = _SecPkgContext_NamesW;
  PSecPkgContext_NamesW = PSecPkgContextNamesW;
  {$EXTERNALSYM PSecPkgContext_NamesW}


type
  PSecPkgAttrLctStatus = ^TSecPkgAttrLctStatus;
  _SECPKG_ATTR_LCT_STATUS = (
    SecPkgAttrLastClientTokenYes,
    SecPkgAttrLastClientTokenNo,
    SecPkgAttrLastClientTokenMaybe
  );
  {$EXTERNALSYM _SECPKG_ATTR_LCT_STATUS}
  SECPKG_ATTR_LCT_STATUS = _SECPKG_ATTR_LCT_STATUS;
  {$EXTERNALSYM SECPKG_ATTR_LCT_STATUS}
  TSecPkgAttrLctStatus = _SECPKG_ATTR_LCT_STATUS;
  PSECPKG_ATTR_LCT_STATUS = PSecPkgAttrLctStatus;
  {$EXTERNALSYM PSECPKG_ATTR_LCT_STATUS}


type
  PSecPkgContextLastClientTokenStatus = ^TSecPkgContextLastClientTokenStatus;
  _SecPkgContext_LastClientTokenStatus = record
    LastClientTokenStatus:  TSecPkgAttrLctStatus;
  end;
  {$EXTERNALSYM _SecPkgContext_LastClientTokenStatus}
  SecPkgContext_LastClientTokenStatus = _SecPkgContext_LastClientTokenStatus;
  {$EXTERNALSYM SecPkgContext_LastClientTokenStatus}
  TSecPkgContextLastClientTokenStatus = _SecPkgContext_LastClientTokenStatus;
  PSecPkgContext_LastClientTokenStatus = PSecPkgContextLastClientTokenStatus;
  {$EXTERNALSYM PSecPkgContext_LastClientTokenStatus}

type
  PSecPkgContextNamesA = ^TSecPkgContextNamesA;
  _SecPkgContext_NamesA = record
    sUserName: PSecChar;
  end;
  {$EXTERNALSYM _SecPkgContext_NamesA}
  SecPkgContext_NamesA = _SecPkgContext_NamesA;
  {$EXTERNALSYM SecPkgContext_NamesA}
  TSecPkgContextNamesA = _SecPkgContext_NamesA;
  PSecPkgContext_NamesA = PSecPkgContextNamesA;
  {$EXTERNALSYM PSecPkgContext_NamesA}

type
  PSecPkgContextNames = PSecPkgContext_NamesW;
  SecPkgContext_Names = SecPkgContext_NamesW;
  {$EXTERNALSYM SecPkgContext_Names}
  TSecPkgContextNames = SecPkgContext_NamesW;
  PSecPkgContext_Names = PSecPkgContextNames;
  {$EXTERNALSYM PSecPkgContext_Names}

type
  PSecPkgContextLifespan = ^TSecPkgContextLifespan;
  _SecPkgContext_Lifespan = record
    tsStart: TTimeStamp;
    tsExpiry: TTimeStamp
  end;
  {$EXTERNALSYM _SecPkgContext_Lifespan}
  SecPkgContext_Lifespan = _SecPkgContext_Lifespan;
  {$EXTERNALSYM SecPkgContext_Lifespan}
  TSecPkgContextLifespan = _SecPkgContext_Lifespan;
  PSecPkgContext_Lifespan = PSecPkgContextLifespan;
  {$EXTERNALSYM PSecPkgContext_Lifespan}

type
  PSecPkgContextDceInfo = ^TSecPkgContextDceInfo;
  _SecPkgContext_DceInfo = record
    AuthzSvc: Cardinal;
    pPac: Pointer;
  end;
  {$EXTERNALSYM _SecPkgContext_DceInfo}
  SecPkgContext_DceInfo = _SecPkgContext_DceInfo;
  {$EXTERNALSYM SecPkgContext_DceInfo}
  TSecPkgContextDceInfo = _SecPkgContext_DceInfo;
  PSecPkgContext_DceInfo = PSecPkgContextDceInfo;
  {$EXTERNALSYM PSecPkgContext_DceInfo}

type
  PSecPkgContextKeyInfoA = ^TSecPkgContextKeyInfoA;
  _SecPkgContext_KeyInfoA = record
    sSignatureAlgorithmName: PSecChar;
    sEncryptAlgorithmName: PSecChar;
    KeySize: Cardinal;
    SignatureAlgorithm: Cardinal;
    EncryptAlgorithm: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_KeyInfoA}
  SecPkgContext_KeyInfoA = _SecPkgContext_KeyInfoA;
  {$EXTERNALSYM SecPkgContext_KeyInfoA}
  TSecPkgContextKeyInfoA = _SecPkgContext_KeyInfoA;
  PSecPkgContext_KeyInfoA = PSecPkgContextKeyInfoA;
  {$EXTERNALSYM PSecPkgContext_KeyInfoA}

type
  PSecPkgContextKeyInfoW = ^TSecPkgContextKeyInfoW;
  _SecPkgContext_KeyInfoW = record
    sSignatureAlgorithmName: PSecWChar;
    sEncryptAlgorithmName: PSecWChar;
    KeySize: Cardinal;
    SignatureAlgorithm: Cardinal;
    EncryptAlgorithm: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_KeyInfoW}
  SecPkgContext_KeyInfoW = _SecPkgContext_KeyInfoW;
  {$EXTERNALSYM SecPkgContext_KeyInfoW}
  TSecPkgContextKeyInfoW = _SecPkgContext_KeyInfoW;
  PSecPkgContext_KeyInfoW = PSecPkgContextKeyInfoW;
  {$EXTERNALSYM PSecPkgContext_KeyInfoW}

type
  PSecPkgContextKeyInfo = PSecPkgContext_KeyInfoW;
  SecPkgContext_KeyInfo = SecPkgContext_KeyInfoW;
  {$EXTERNALSYM SecPkgContext_KeyInfo}
  TSecPkgContextKeyInfo = SecPkgContext_KeyInfoW;
  PSecPkgContext_KeyInfo = PSecPkgContextKeyInfo;
  {$EXTERNALSYM PSecPkgContext_KeyInfo}

type
  PSecPkgContextAuthorityA = ^TSecPkgContextAuthorityA;
  _SecPkgContext_AuthorityA = record
    sAuthorityName: PSecChar;
  end;
  {$EXTERNALSYM _SecPkgContext_AuthorityA}
  SecPkgContext_AuthorityA = _SecPkgContext_AuthorityA;
  {$EXTERNALSYM SecPkgContext_AuthorityA}
  TSecPkgContextAuthorityA = _SecPkgContext_AuthorityA;
  PSecPkgContext_AuthorityA = PSecPkgContextAuthorityA;
  {$EXTERNALSYM PSecPkgContext_AuthorityA}

type
  PSecPkgContextAuthorityW = ^TSecPkgContextAuthorityW;
  _SecPkgContext_AuthorityW = record
    sAuthorityName: PSecWChar;
  end;
  {$EXTERNALSYM _SecPkgContext_AuthorityW}
  SecPkgContext_AuthorityW = _SecPkgContext_AuthorityW;
  {$EXTERNALSYM SecPkgContext_AuthorityW}
  TSecPkgContextAuthorityW = _SecPkgContext_AuthorityW;
  PSecPkgContext_AuthorityW = PSecPkgContextAuthorityW;
  {$EXTERNALSYM PSecPkgContext_AuthorityW}

type
  PSecPkgContextAuthority = PSecPkgContext_AuthorityW;
  SecPkgContext_Authority = SecPkgContext_AuthorityW;
  {$EXTERNALSYM SecPkgContext_Authority}
  TSecPkgContextAuthority = SecPkgContext_AuthorityW;
  PSecPkgContext_Authority = PSecPkgContextAuthority;
  {$EXTERNALSYM PSecPkgContext_Authority}

type
  PSecPkgContextProtoInfoA = ^TSecPkgContextProtoInfoA;
  _SecPkgContext_ProtoInfoA = record
    sProtocolName: PSecChar;
    majorVersion: Cardinal;
    minorVersion: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_ProtoInfoA}
  SecPkgContext_ProtoInfoA = _SecPkgContext_ProtoInfoA;
  {$EXTERNALSYM SecPkgContext_ProtoInfoA}
  TSecPkgContextProtoInfoA = _SecPkgContext_ProtoInfoA;
  PSecPkgContext_ProtoInfoA = PSecPkgContextProtoInfoA;
  {$EXTERNALSYM PSecPkgContext_ProtoInfoA}

type
  PSecPkgContextProtoInfoW = ^TSecPkgContextProtoInfoW;
  _SecPkgContext_ProtoInfoW = record
    sProtocolName: PSecWChar;
    majorVersion: Cardinal;
    minorVersion: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_ProtoInfoW}
  SecPkgContext_ProtoInfoW = _SecPkgContext_ProtoInfoW;
  {$EXTERNALSYM SecPkgContext_ProtoInfoW}
  TSecPkgContextProtoInfoW = _SecPkgContext_ProtoInfoW;
  PSecPkgContext_ProtoInfoW = PSecPkgContextProtoInfoW;
  {$EXTERNALSYM PSecPkgContext_ProtoInfoW}

type
  PSecPkgContextProtoInfo = PSecPkgContext_ProtoInfoW;
  SecPkgContext_ProtoInfo  = SecPkgContext_ProtoInfoW;
  {$EXTERNALSYM SecPkgContext_ProtoInfo}
  TSecPkgContextProtoInfo = SecPkgContext_ProtoInfoW;
  PSecPkgContext_ProtoInfo = PSecPkgContextProtoInfo;
  {$EXTERNALSYM PSecPkgContext_ProtoInfo}

type
  PSecPkgContextPasswordExpiry = ^TSecPkgContextPasswordExpiry;
  _SecPkgContext_PasswordExpiry = record
    tsPasswordExpires: TTimeStamp;
  end;
  {$EXTERNALSYM _SecPkgContext_PasswordExpiry}
  SecPkgContext_PasswordExpiry = _SecPkgContext_PasswordExpiry;
  {$EXTERNALSYM SecPkgContext_PasswordExpiry}
  TSecPkgContextPasswordExpiry = _SecPkgContext_PasswordExpiry;
  PSecPkgContext_PasswordExpiry = PSecPkgContextPasswordExpiry;
  {$EXTERNALSYM PSecPkgContext_PasswordExpiry}

type
  PSecPkgContextLogoffTime = ^TSecPkgContextLogoffTime;
  _SecPkgContext_LogoffTime = record
    tsLogoffTime: TTimeStamp;
  end;
  {$EXTERNALSYM _SecPkgContext_LogoffTime}
  SecPkgContext_LogoffTime = _SecPkgContext_LogoffTime;
  {$EXTERNALSYM SecPkgContext_LogoffTime}
  TSecPkgContextLogoffTime =  _SecPkgContext_LogoffTime;
  PSecPkgContext_LogoffTime = PSecPkgContextLogoffTime;
  {$EXTERNALSYM PSecPkgContext_LogoffTime}

type
  PSecPkgContextSessionKey = ^TSecPkgContextSessionKey;
  _SecPkgContext_SessionKey = record
    SessionKeyLength: Cardinal;
    SessionKey: PByte;
  end;
  {$EXTERNALSYM _SecPkgContext_SessionKey}
  SecPkgContext_SessionKey = _SecPkgContext_SessionKey;
  {$EXTERNALSYM SecPkgContext_SessionKey}
  TSecPkgContextSessionKey = _SecPkgContext_SessionKey;
  PSecPkgContext_SessionKey = PSecPkgContextSessionKey;
  {$EXTERNALSYM PSecPkgContext_SessionKey}

// used by nego2
type
  PSecPkgContextNegoKeys = ^TSecPkgContextNegoKeys;
  _SecPkgContext_NegoKeys = record
    KeyType: Cardinal;
    KeyLength: Word;
    KeyValue: PByte;
    VerifyKeyType: Cardinal;
    VerifyKeyLength: Word;
    VerifyKeyValue: PByte;
  end;
  {$EXTERNALSYM _SecPkgContext_NegoKeys}
  SecPkgContext_NegoKeys = _SecPkgContext_NegoKeys;
  {$EXTERNALSYM SecPkgContext_NegoKeys}
  TSecPkgContextNegoKeys = _SecPkgContext_NegoKeys;
  PSecPkgContext_NegoKeys = PSecPkgContextNegoKeys;
  {$EXTERNALSYM PSecPkgContext_NegoKeys}

type
  PSecPkgContextPackageInfoW = ^TSecPkgContextPackageInfoW;
  _SecPkgContext_PackageInfoW = record
    PackageInfo: PSecPkgInfoW;
  end;
  {$EXTERNALSYM _SecPkgContext_PackageInfoW}
  SecPkgContext_PackageInfoW = _SecPkgContext_PackageInfoW;
  {$EXTERNALSYM SecPkgContext_PackageInfoW}
  TSecPkgContextPackageInfoW = _SecPkgContext_PackageInfoW;
  PSecPkgContext_PackageInfoW = PSecPkgContextPackageInfoW;
  {$EXTERNALSYM PSecPkgContext_PackageInfoW}

type
  PSecPkgContextPackageInfoA = ^TSecPkgContextPackageInfoA;
  _SecPkgContext_PackageInfoA = record
    PackageInfo: PSecPkgInfoA;
  end;
  {$EXTERNALSYM _SecPkgContext_PackageInfoA}
  SecPkgContext_PackageInfoA = _SecPkgContext_PackageInfoA;
  {$EXTERNALSYM SecPkgContext_PackageInfoA}
  TSecPkgContextPackageInfoA = _SecPkgContext_PackageInfoA;
  PSecPkgContext_PackageInfoA = PSecPkgContextPackageInfoA;
  {$EXTERNALSYM PSecPkgContext_PackageInfoA}

type
  PSecPkgContextUserFlags = ^TSecPkgContextUserFlags;
  _SecPkgContext_UserFlags = record
    UserFlags: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_UserFlags}
  SecPkgContext_UserFlags = _SecPkgContext_UserFlags;
  {$EXTERNALSYM SecPkgContext_UserFlags}
  TSecPkgContextUserFlags = _SecPkgContext_UserFlags;
  PSecPkgContext_UserFlags = PSecPkgContextUserFlags;
  {$EXTERNALSYM PSecPkgContext_UserFlags}

type
  PSecPkgContextFlags = ^TSecPkgContextFlags;
  _SecPkgContext_Flags = record
    Flags: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_Flags}
  SecPkgContext_Flags = _SecPkgContext_Flags;
  {$EXTERNALSYM SecPkgContext_Flags}
  TSecPkgContextFlags = _SecPkgContext_Flags;
  PSecPkgContext_Flags = PSecPkgContextFlags;
  {$EXTERNALSYM PSecPkgContext_Flags}

type
  PSecPkgContextPackageInfo = PSecPkgContext_PackageInfoW;
  SecPkgContext_PackageInfo = SecPkgContext_PackageInfoW;
  {$EXTERNALSYM SecPkgContext_PackageInfo}
  TSecPkgContextPackageInfo = SecPkgContext_PackageInfoW;
  PSecPkgContext_PackageInfo = PSecPkgContextPackageInfo;
  {$EXTERNALSYM PSecPkgContext_PackageInfo}

type
  PSecPkgContextNegotiationInfoA = ^TSecPkgContextNegotiationInfoA;
  _SecPkgContext_NegotiationInfoA = record
    PackageInfo: PSecPkgInfoA;
    NegotiationState: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_NegotiationInfoA}
  SecPkgContext_NegotiationInfoA = _SecPkgContext_NegotiationInfoA;
  {$EXTERNALSYM SecPkgContext_NegotiationInfoA}
  TSecPkgContextNegotiationInfoA = _SecPkgContext_NegotiationInfoA;
  PSecPkgContext_NegotiationInfoA = PSecPkgContextNegotiationInfoA;
  {$EXTERNALSYM PSecPkgContext_NegotiationInfoA}

type
  PSecPkgContextNegotiationInfoW = ^TSecPkgContextNegotiationInfoW;
  _SecPkgContext_NegotiationInfoW = record
    PackageInfo: PSecPkgInfoW;
    NegotiationState: Cardinal;
  end;
  {$EXTERNALSYM _SecPkgContext_NegotiationInfoW}
  SecPkgContext_NegotiationInfoW = _SecPkgContext_NegotiationInfoW;
  {$EXTERNALSYM SecPkgContext_NegotiationInfoW}
  TSecPkgContextNegotiationInfoW = _SecPkgContext_NegotiationInfoW;
  PSecPkgContext_NegotiationInfoW = PSecPkgContextNegotiationInfoW;
  {$EXTERNALSYM PSecPkgContext_NegotiationInfoW}

type
  PSecPkgContextNegotiationInfo = PSecPkgContext_NegotiationInfoW;
  SecPkgContext_NegotiationInfo = SecPkgContext_NegotiationInfoW;
  {$EXTERNALSYM SecPkgContext_NegotiationInfo}
  TSecPkgContextNegotiationInfo = SecPkgContext_NegotiationInfoW;
  PSecPkgContext_NegotiationInfo = PSecPkgContextNegotiationInfo;
  {$EXTERNALSYM PSecPkgContext_NegotiationInfo}

const
  SECPKG_NEGOTIATION_COMPLETE            = 0;
  {$EXTERNALSYM SECPKG_NEGOTIATION_COMPLETE}
  SECPKG_NEGOTIATION_OPTIMISTIC          = 1;
  {$EXTERNALSYM SECPKG_NEGOTIATION_OPTIMISTIC}
  SECPKG_NEGOTIATION_IN_PROGRESS         = 2;
  {$EXTERNALSYM SECPKG_NEGOTIATION_IN_PROGRESS}
  SECPKG_NEGOTIATION_DIRECT              = 3;
  {$EXTERNALSYM SECPKG_NEGOTIATION_DIRECT}
  SECPKG_NEGOTIATION_TRY_MULTICRED       = 4;
  {$EXTERNALSYM SECPKG_NEGOTIATION_TRY_MULTICRED}


type
  PSecPkgContextNativeNamesW = ^TSecPkgContextNativeNamesW;
  _SecPkgContext_NativeNamesW = record
    sClientName: PSecWChar;
    sServerName: PSecWChar;
  end;
  {$EXTERNALSYM _SecPkgContext_NativeNamesW}
  SecPkgContext_NativeNamesW = _SecPkgContext_NativeNamesW;
  {$EXTERNALSYM SecPkgContext_NativeNamesW}
  TSecPkgContextNativeNamesW = _SecPkgContext_NativeNamesW;
  PSecPkgContext_NativeNamesW = PSecPkgContextNativeNamesW;
  {$EXTERNALSYM PSecPkgContext_NativeNamesW}

type
  PSecPkgContextNativeNamesA = ^TSecPkgContextNativeNamesA;
  _SecPkgContext_NativeNamesA = record
    sClientName: PSecChar;
    sServerName: PSecChar;
  end;
  {$EXTERNALSYM _SecPkgContext_NativeNamesA}
  SecPkgContext_NativeNamesA = _SecPkgContext_NativeNamesA;
  {$EXTERNALSYM SecPkgContext_NativeNamesA}
  TSecPkgContextNativeNamesA = _SecPkgContext_NativeNamesA;
  PSecPkgContext_NativeNamesA = PSecPkgContextNativeNamesA;
  {$EXTERNALSYM PSecPkgContext_NativeNamesA}

type
  PSecPkgContextNativeNames = PSecPkgContext_NativeNamesW;
  SecPkgContext_NativeNames = SecPkgContext_NativeNamesW;
  {$EXTERNALSYM SecPkgContext_NativeNames}
  TSecPkgContextNativeNames = SecPkgContext_NativeNamesW;
  PSecPkgContext_NativeNames = PSecPkgContextNativeNames;
  {$EXTERNALSYM PSecPkgContext_NativeNames}


type
  PSecPkgContextCredentailNameW = ^TSecPkgContextCredentailNameW;
  _SecPkgContext_CredentialNameW = record
    CredentialType: Cardinal;
    sCredentialName: PSecWChar;
  end;
  {$EXTERNALSYM _SecPkgContext_CredentialNameW}
  SecPkgContext_CredentialNameW = _SecPkgContext_CredentialNameW;
  {$EXTERNALSYM SecPkgContext_CredentialNameW}
  TSecPkgContextCredentailNameW = _SecPkgContext_CredentialNameW;
  PSecPkgContext_CredentialNameW = PSecPkgContextCredentailNameW;
  {$EXTERNALSYM PSecPkgContext_CredentialNameW}


type
  PSecPkgContextCredentialNameA = ^TSecPkgContextCredentialNameA;
  _SecPkgContext_CredentialNameA = record
    CredentialType: Cardinal;
    sCredentialName: PSecChar;
  end;
  {$EXTERNALSYM _SecPkgContext_CredentialNameA}
  SecPkgContext_CredentialNameA = _SecPkgContext_CredentialNameA;
  {$EXTERNALSYM SecPkgContext_CredentialNameA}
  TSecPkgContextCredentialNameA = _SecPkgContext_CredentialNameA;
  PSecPkgContext_CredentialNameA = PSecPkgContextCredentialNameA;
  {$EXTERNALSYM PSecPkgContext_CredentialNameA}

type
  PSecPkgContextCredentialName = PSecPkgContext_CredentialNameW;
  SecPkgContext_CredentialName = SecPkgContext_CredentialNameW;
  {$EXTERNALSYM SecPkgContext_CredentialName}
  TSecPkgContextCredentialName = SecPkgContext_CredentialNameW;
  PSecPkgContext_CredentialName = PSecPkgContextCredentialName;
  {$EXTERNALSYM PSecPkgContext_CredentialName}

type
  PSecPkgContextAccessToken = ^TSecPkgContextAccessToken;
  _SecPkgContext_AccessToken = record
    AccessToken: Pointer;
  end;
  {$EXTERNALSYM _SecPkgContext_AccessToken}
  SecPkgContext_AccessToken = _SecPkgContext_AccessToken;
  {$EXTERNALSYM SecPkgContext_AccessToken}
  TSecPkgContextAccessToken = _SecPkgContext_AccessToken;
  PSecPkgContext_AccessToken = PSecPkgContextAccessToken;
  {$EXTERNALSYM PSecPkgContext_AccessToken}

type
  PSecPkgContextTargetInformation = ^TSecPkgContextTargetInformation;
  _SecPkgContext_TargetInformation = record
    MarshalledTargetInfoLength: Cardinal;
    MarshalledTargetInfo: PByte;
  end;
  {$EXTERNALSYM _SecPkgContext_TargetInformation}
  SecPkgContext_TargetInformation = _SecPkgContext_TargetInformation;
  {$EXTERNALSYM SecPkgContext_TargetInformation}
  TSecPkgContextTargetInformation = _SecPkgContext_TargetInformation;
  PSecPkgContext_TargetInformation = PSecPkgContextTargetInformation;
  {$EXTERNALSYM PSecPkgContext_TargetInformation}

type
  PSecPkgContextAuthzID = ^TSecPkgContextAuthzID;
  _SecPkgContext_AuthzID = record
    AuthzIDLength: Cardinal;
    AuthzID: PAnsiChar;
  end;
  {$EXTERNALSYM _SecPkgContext_AuthzID}
  SecPkgContext_AuthzID = _SecPkgContext_AuthzID;
  {$EXTERNALSYM SecPkgContext_AuthzID}
  TSecPkgContextAuthzID = _SecPkgContext_AuthzID;
  PSecPkgContext_AuthzID = PSecPkgContextAuthzID;
  {$EXTERNALSYM PSecPkgContext_AuthzID}

type
  PSecPkgContextTarget = ^TSecPkgContextTarget;
  _SecPkgContext_Target = record
    TargetLength: Cardinal;
    Target: PAnsiChar;
  end;
  {$EXTERNALSYM _SecPkgContext_Target}
  SecPkgContext_Target = _SecPkgContext_Target;
  {$EXTERNALSYM SecPkgContext_Target}
  TSecPkgContextTarget = _SecPkgContext_Target;
  PSecPkgContext_Target = PSecPkgContextTarget;
  {$EXTERNALSYM PSecPkgContext_Target}


type
  PSecPkgContextClientSpecifiedTarget = ^TSecPkgContextClientSpecifiedTarget;
  _SecPkgContext_ClientSpecifiedTarget = record
    sTargetName: PSecWChar;
  end;
  {$EXTERNALSYM _SecPkgContext_ClientSpecifiedTarget}
  SecPkgContext_ClientSpecifiedTarget = _SecPkgContext_ClientSpecifiedTarget;
  {$EXTERNALSYM SecPkgContext_ClientSpecifiedTarget}
  TSecPkgContextClientSpecifiedTarget = _SecPkgContext_ClientSpecifiedTarget;
  PSecPkgContext_ClientSpecifiedTarget = PSecPkgContextClientSpecifiedTarget;
  {$EXTERNALSYM PSecPkgContext_ClientSpecifiedTarget}

type
  PSecPkgContextBindings = ^TSecPkgContextBindings;
  _SecPkgContext_Bindings = record
    BindingsLength: Cardinal;
   Bindings: PSecChannelBindings;
  end;
  {$EXTERNALSYM _SecPkgContext_Bindings}
  SecPkgContext_Bindings = _SecPkgContext_Bindings;
  {$EXTERNALSYM SecPkgContext_Bindings}
  TSecPkgContextBindings = _SecPkgContext_Bindings;
  PSecPkgContext_Bindings = PSecPkgContextBindings;
  {$EXTERNALSYM PSecPkgContext_Bindings}


type
  SEC_GET_KEY_FN = procedure(
    Arg: Pointer;                 // Argument passed in
    Principal: Pointer;           // Principal ID
    KeyVer: Cardinal;             // Key Version
    out Key: Pointer;             // Returned ptr to key
    out Status: SECURITY_STATUS   // returned status
    ); winapi;
  {$EXTERNALSYM SEC_GET_KEY_FN}
  TSecGetKeyFn = SEC_GET_KEY_FN;

//
// Flags for ExportSecurityContext
//
const
  SECPKG_CONTEXT_EXPORT_RESET_NEW        = $00000001;      // New context is reset to initial state
  {$EXTERNALSYM SECPKG_CONTEXT_EXPORT_RESET_NEW}
  SECPKG_CONTEXT_EXPORT_DELETE_OLD       = $00000002;      // Old context is deleted during export
  {$EXTERNALSYM SECPKG_CONTEXT_EXPORT_DELETE_OLD}
// This is only valid in W2K3SP1 and greater
const
  SECPKG_CONTEXT_EXPORT_TO_KERNEL        = $00000004;      // Context is to be transferred to the kernel
  {$EXTERNALSYM SECPKG_CONTEXT_EXPORT_TO_KERNEL}


function AcquireCredentialsHandleW(
  pszPrincipal: LPWSTR;                 // Name of principal
  pszPackage: LPWSTR;                   // Name of package
  fCredentialUse: Cardinal;             // Flags indicating use
  pvLogonId: Pointer;                   // Pointer to logon ID
  pAuthData: Pointer;                   // Package specific data
  pGetKeyFn: TSecGetKeyFn;              // Pointer to GetKey() func
  pvGetKeyArgument: Pointer;            // Value to pass to GetKey()
  out phCredential: TCredHandle;        // (out) Cred Handle
  ptsExpiry: PTimeStamp                 // (out) Lifetime (optional)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AcquireCredentialsHandleW}

type
  ACQUIRE_CREDENTIALS_HANDLE_FN_W = function(
    pszPrincipal: PSecWChar;
    pszPackage: PSecWChar;
    fCredentialUse: Cardinal;
    pvLogonId: Pointer;
    pAuthData: Pointer;
    pGetKeyFn: TSecGetKeyFn;
    pvGetKeyArgument: Pointer;
    out phCredential: TCredHandle;
    ptsExpiry: PTimeStamp): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ACQUIRE_CREDENTIALS_HANDLE_FN_W}
  TAcquireCredentialsHandleFnW = ACQUIRE_CREDENTIALS_HANDLE_FN_W;

function AcquireCredentialsHandleA(
  pszPrincipal: LPSTR;                  // Name of principal
  pszPackage: LPSTR;                    // Name of package
  fCredentialUse: Cardinal;             // Flags indicating use
  pvLogonId: Pointer;                   // Pointer to logon ID
  pAuthData: Pointer;                   // Package specific data
  pGetKeyFn: TSecGetKeyFn;              // Pointer to GetKey() func
  pvGetKeyArgument: Pointer;            // Value to pass to GetKey()
  out phCredential: TCredHandle;        // (out) Cred Handle
  ptsExpiry: PTimeStamp                 // (out) Lifetime (optional)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AcquireCredentialsHandleA}

type
  ACQUIRE_CREDENTIALS_HANDLE_FN_A = function(
    pszPrincipal: PSecChar;
    pszPackage: PSecChar;
    fCredentialUse: Cardinal;
    pvLogonId: Pointer;
    pAuthData: Pointer;
    pGetKeyFn: TSecGetKeyFn;
    pvGetKeyArgument: Pointer;
    out phCredential: TCredHandle;
    ptsExpiry: PTimeStamp): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ACQUIRE_CREDENTIALS_HANDLE_FN_A}
   TAcquireCredentialsHandleFnA = ACQUIRE_CREDENTIALS_HANDLE_FN_A;

function AcquireCredentialsHandle(
  pszPrincipal: LPWSTR;                 // Name of principal
  pszPackage: LPWSTR;                   // Name of package
  fCredentialUse: Cardinal;             // Flags indicating use
  pvLogonId: Pointer;                   // Pointer to logon ID
  pAuthData: Pointer;                   // Package specific data
  pGetKeyFn: TSecGetKeyFn;              // Pointer to GetKey() func
  pvGetKeyArgument: Pointer;            // Value to pass to GetKey()
  out phCredential: TCredHandle;        // (out) Cred Handle
  ptsExpiry: PTimeStamp                 // (out) Lifetime (optional)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AcquireCredentialsHandle}

type
  ACQUIRE_CREDENTIALS_HANDLE_FN = ACQUIRE_CREDENTIALS_HANDLE_FN_W;
  {$EXTERNALSYM ACQUIRE_CREDENTIALS_HANDLE_FN}
  TAcquireCredentialsHandleFn = ACQUIRE_CREDENTIALS_HANDLE_FN_W;

function FreeCredentialsHandle(
  phCredential: PCredHandle             // Handle to free
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM FreeCredentialsHandle}

type
  FREE_CREDENTIALS_HANDLE_FN = function(
    phCredential: PCredHandle): SECURITY_STATUS; winapi;
  {$EXTERNALSYM FREE_CREDENTIALS_HANDLE_FN}
  TFreeCredentialsHandleFn = FREE_CREDENTIALS_HANDLE_FN;

function AddCredentialsW(
  hCredentials: PCredHandle;
  pszPrincipal: LPWSTR;                 // Name of principal
  pszPackage: LPWSTR;                   // Name of package
  fCredentialUse: Cardinal;             // Flags indicating use
  pAuthData: Pointer;                   // Package specific data
  pGetKeyFn: TSecGetKeyFn;              // Pointer to GetKey() func
  pvGetKeyArgument: Pointer;            // Value to pass to GetKey()
  ptsExpiry: PTimeStamp                 // (out) Lifetime (optional)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AddCredentialsW}

type
  ADD_CREDENTIALS_FN_W = function(
    hCredentials: PCredHandle;
    pszPrincipal: PSecWChar;
    pszPackage: PSecWChar;
    fCredentialUse: Cardinal;
    pAuthData: Pointer;
    pGetKeyFn: TSecGetKeyFn;
    pvGetKeyArgument: Pointer;
    ptsExpiry: PTimeStamp): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ADD_CREDENTIALS_FN_W}
  TAddCredentialsFnW = ADD_CREDENTIALS_FN_W;

function AddCredentialsA(
  hCredentials: PCredHandle;
  pszPrincipal: LPSTR;                  // Name of principal
  pszPackage: LPSTR;                    // Name of package
  fCredentialUse: Cardinal;             // Flags indicating use
  pAuthData: Pointer;                   // Package specific data
  pGetKeyFn: TSecGetKeyFn;              // Pointer to GetKey() func
  pvGetKeyArgument: Pointer;            // Value to pass to GetKey()
  ptsExpiry: PTimeStamp                 // (out) Lifetime (optional)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AddCredentialsA}

type
  ADD_CREDENTIALS_FN_A = function(
    hCredentials: PCredHandle;
    pszPrincipal: PSecChar;
    pszPackage: PSecChar;
    fCredentialUse: Cardinal;
    pAuthData: Pointer;
    pGetKeyFn: TSecGetKeyFn;
    pvGetKeyArgument: Pointer;
    ptsExpiry: PTimeStamp): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ADD_CREDENTIALS_FN_A}
  TAddCredentialsFnA = ADD_CREDENTIALS_FN_A;

function AddCredentials(
  hCredentials: PCredHandle;
  pszPrincipal: LPWSTR;                 // Name of principal
  pszPackage: LPWSTR;                   // Name of package
  fCredentialUse: Cardinal;             // Flags indicating use
  pAuthData: Pointer;                   // Package specific data
  pGetKeyFn: TSecGetKeyFn;              // Pointer to GetKey() func
  pvGetKeyArgument: Pointer;            // Value to pass to GetKey()
  ptsExpiry: PTimeStamp                 // (out) Lifetime (optional)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AddCredentials}

type
  ADD_CREDENTIALS_FN = ADD_CREDENTIALS_FN_W;
  {$EXTERNALSYM ADD_CREDENTIALS_FN}
  TAddCredentialsFn = ADD_CREDENTIALS_FN_W;


////////////////////////////////////////////////////////////////////////
///
/// Password Change Functions
///
////////////////////////////////////////////////////////////////////////


function ChangeAccountPasswordW(
  pszPackageName: PSecWChar;
  pszDomainName: PSecWChar;
  pszAccountName: PSecWChar;
  pszOldPassword: PSecWChar;
  pszNewPassword: PSecWChar;
  bImpersonating: ByteBool;
  dwReserved: Cardinal;
  pOutput: PSecBufferDesc): SECURITY_STATUS; winapi;
{$EXTERNALSYM ChangeAccountPasswordW}

type
  CHANGE_PASSWORD_FN_W = function(
    pszPackageName: PSecWChar;
    pszDomainName: PSecWChar;
    pszAccountName: PSecWChar;
    pszOldPassword: PSecWChar;
    pszNewPassword: PSecWChar;
    bImpersonating: ByteBool;
    dwReserved: Cardinal;
    pOutput: PSecBufferDesc): SECURITY_STATUS; winapi;
  {$EXTERNALSYM CHANGE_PASSWORD_FN_W}
  TChangePasswordFnW = CHANGE_PASSWORD_FN_W;

function ChangeAccountPasswordA(
  pszPackageName: PSecChar;
  pszDomainName: PSecChar;
  pszAccountName: PSecChar;
  pszOldPassword: PSecChar;
  pszNewPassword: PSecChar;
  bImpersonating: ByteBool;
  dwReserved: Cardinal;
  pOutput: PSecBufferDesc): SECURITY_STATUS; winapi;
{$EXTERNALSYM ChangeAccountPasswordA}

type
  CHANGE_PASSWORD_FN_A = function(
    pszPackageName: PSecChar;
    pszDomainName: PSecChar;
    pszAccountName: PSecChar;
    pszOldPassword: PSecChar;
    pszNewPassword: PSecChar;
    bImpersonating: ByteBool;
    dwReserved: Cardinal;
    pOutput:  PSecBufferDesc): SECURITY_STATUS; winapi;
  {$EXTERNALSYM CHANGE_PASSWORD_FN_A}
  TChangePasswordFnA = CHANGE_PASSWORD_FN_A;

function ChangeAccountPassword(
  pszPackageName: PSecWChar;
  pszDomainName: PSecWChar;
  pszAccountName: PSecWChar;
  pszOldPassword: PSecWChar;
  pszNewPassword: PSecWChar;
  bImpersonating: ByteBool;
  dwReserved: Cardinal;
  pOutput: PSecBufferDesc): SECURITY_STATUS; winapi;
{$EXTERNALSYM ChangeAccountPassword}

type
  CHANGE_PASSWORD_FN = CHANGE_PASSWORD_FN_W;
  {$EXTERNALSYM CHANGE_PASSWORD_FN}
  TChangePasswordFn = CHANGE_PASSWORD_FN_W;


////////////////////////////////////////////////////////////////////////
///
/// Context Management Functions
///
////////////////////////////////////////////////////////////////////////

function InitializeSecurityContextW(
  phCredential: PCredHandle;                // Cred to base context
  phContext: PCtxtHandle;                   // Existing context (OPT)
  pszTargetName: PSecWChar;                 // Name of target
  fContextReq: Cardinal;                    // Context Requirements
  Reserved1: Cardinal;                      // Reserved, MBZ
  TargetDataRep: Cardinal;                  // Data rep of target
  pInput: PSecBufferDesc;                   // Input Buffers
  Reserved2: Cardinal;                      // Reserved, MBZ
  phNewContext: PCtxtHandle;                // (out) New Context handle
  pOutput: PSecBufferDesc;                  // (inout) Output Buffers
  out pfContextAttr: Cardinal;              // (out) Context attrs
  ptsExpiry: PTimeStamp                     // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM InitializeSecurityContextW}

type
  INITIALIZE_SECURITY_CONTEXT_FN_W = function(
    phCredential: PCredHandle;
    phContext: PCtxtHandle;
    pszTargetName: PSecWChar;
    fContextReq: Cardinal;
    Reserved1: Cardinal;
    TargetDataRep: Cardinal;
    pInput: PSecBufferDesc;
    Reserved2: Cardinal;
    phNewContext: PCtxtHandle;
    pOutput: PSecBufferDesc;
    out pfContextAttr: Cardinal;
    ptsExpiry: PTimeStamp): SECURITY_STATUS; winapi;
  {$EXTERNALSYM INITIALIZE_SECURITY_CONTEXT_FN_W}
  TInitializeSecurityContextFnW = INITIALIZE_SECURITY_CONTEXT_FN_W;


function InitializeSecurityContextA(
  phCredential: PCredHandle;                // Cred to base context
  phContext: PCtxtHandle;                   // Existing context (OPT)
  pszTargetName: PSecChar;                  // Name of target
  fContextReq: Cardinal;                    // Context Requirements
  Reserved1: Cardinal;                      // Reserved, MBZ
  TargetDataRep: Cardinal;                  // Data rep of target
  pInput: PSecBufferDesc;                   // Input Buffers
  Reserved2: Cardinal;                      // Reserved, MBZ
  phNewContext: PCtxtHandle;                // (out) New Context handle
  pOutput: PSecBufferDesc;                  // (inout) Output Buffers
  out pfContextAttr: Cardinal;              // (out) Context attrs
  ptsExpiry: PTimeStamp                     // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
  {$EXTERNALSYM InitializeSecurityContextA}

type
  INITIALIZE_SECURITY_CONTEXT_FN_A = function(
    phCredential: PCredHandle;
    phContext: PCtxtHandle;
    pszTargetName: PSecChar;
    fContextReq: Cardinal;
    Reserved1: Cardinal;
    TargetDataRep: Cardinal;
    pInput: PSecBufferDesc;
    Reserved2: Cardinal;
    phNewContext: PCtxtHandle;
    pOutput: PSecBufferDesc;
    out pfContextAttr: Cardinal;
    ptsExpiry: PTimeStamp): SECURITY_STATUS; winapi;
  {$EXTERNALSYM INITIALIZE_SECURITY_CONTEXT_FN_A}
  TInitializeSecurityContextFnA = INITIALIZE_SECURITY_CONTEXT_FN_A;

function InitializeSecurityContext(
  phCredential: PCredHandle;                // Cred to base context
  phContext: PCtxtHandle;                   // Existing context (OPT)
  pszTargetName: PSecWChar;                 // Name of target
  fContextReq: Cardinal;                    // Context Requirements
  Reserved1: Cardinal;                      // Reserved, MBZ
  TargetDataRep: Cardinal;                  // Data rep of target
  pInput: PSecBufferDesc;                   // Input Buffers
  Reserved2: Cardinal;                      // Reserved, MBZ
  phNewContext: PCtxtHandle;                // (out) New Context handle
  pOutput: PSecBufferDesc;                  // (inout) Output Buffers
  out pfContextAttr: Cardinal;              // (out) Context attrs
  ptsExpiry: PTimeStamp                     // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM InitializeSecurityContext}

type
  INITIALIZE_SECURITY_CONTEXT_FN = INITIALIZE_SECURITY_CONTEXT_FN_W;
  {$EXTERNALSYM INITIALIZE_SECURITY_CONTEXT_FN}
  TInitializeSecurityContextFn = INITIALIZE_SECURITY_CONTEXT_FN_W;

function AcceptSecurityContext(
  phCredential: PCredHandle;                // Cred to base context
  phContext: PCtxtHandle;                   // Existing context (OPT)
  pInput: PSecBufferDesc;                   // Input buffer
  fContextReq: Cardinal;                    // Context Requirements
  TargetDataRep: Cardinal;                  // Target Data Rep
  phNewContext: PCtxtHandle;                // (out) New context handle
  pOutput: PSecBufferDesc;                  // (inout) Output buffers
  out pfContextAttr: Cardinal;              // (out) Context attributes
  ptsExpiry: PTimeStamp                     // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AcceptSecurityContext}

type
  ACCEPT_SECURITY_CONTEXT_FN = function(
    phCredential: PCredHandle;
    phContext: PCtxtHandle;
    pInput: PSecBufferDesc;
    fContextReq: Cardinal;
    TargetDataRep: Cardinal;
    phNewContext: PCtxtHandle;
    pOutput: PSecBufferDesc;
    out pfContextAttr: Cardinal;
    ptsExpiry: PTimeStamp): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ACCEPT_SECURITY_CONTEXT_FN}
  TAcceptSecurityContextFn = ACCEPT_SECURITY_CONTEXT_FN;


function CompleteAuthToken(
  phContext: PCtxtHandle;                // Context to complete
  pToken: PSecBufferDesc                 // Token to complete
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM CompleteAuthToken}

type
  COMPLETE_AUTH_TOKEN_FN = function(
    phContext: PCtxtHandle;
    pToken: PSecBufferDesc): SECURITY_STATUS; winapi;
  {$EXTERNALSYM COMPLETE_AUTH_TOKEN_FN}
  TCompleteAuthTokenFn = COMPLETE_AUTH_TOKEN_FN;

function ImpersonateSecurityContext(
  phContext: PCtxtHandle                 // Context to impersonate
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM ImpersonateSecurityContext}

type
  IMPERSONATE_SECURITY_CONTEXT_FN = function(
    phContext: PCtxtHandle): SECURITY_STATUS; winapi;
  {$EXTERNALSYM IMPERSONATE_SECURITY_CONTEXT_FN}
  TImpersonateSecurityContextFn = IMPERSONATE_SECURITY_CONTEXT_FN;

function RevertSecurityContext(
  phContext: PCtxtHandle                 // Context from which to re
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM RevertSecurityContext}

type
  REVERT_SECURITY_CONTEXT_FN = function(
    phContext: PCtxtHandle): SECURITY_STATUS; winapi;
  {$EXTERNALSYM REVERT_SECURITY_CONTEXT_FN}
  TRevertSecurityContextFn = REVERT_SECURITY_CONTEXT_FN;

function QuerySecurityContextToken(
  phContext: PCtxtHandle;
  out Token: Pointer): SECURITY_STATUS; winapi;
{$EXTERNALSYM QuerySecurityContextToken}

type
  QUERY_SECURITY_CONTEXT_TOKEN_FN = function(
    phContext: PCtxtHandle;
    out Token: Pointer): SECURITY_STATUS; winapi;
  {$EXTERNALSYM QUERY_SECURITY_CONTEXT_TOKEN_FN}
  TQuerySecurityContextTokenFn = QUERY_SECURITY_CONTEXT_TOKEN_FN;


function DeleteSecurityContext(
  phContext: PCtxtHandle                 // Context to delete
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM DeleteSecurityContext}

type
  DELETE_SECURITY_CONTEXT_FN = function(
    phContext: PCtxtHandle): SECURITY_STATUS; winapi;
  {$EXTERNALSYM DELETE_SECURITY_CONTEXT_FN}
  TDeleteSecurityContextFn = DELETE_SECURITY_CONTEXT_FN;

function ApplyControlToken(
  phContext: PCtxtHandle;               // Context to modify
  pInput: PSecBufferDesc                // Input token to apply
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM ApplyControlToken}

type
  APPLY_CONTROL_TOKEN_FN = function(
    phContext: PCtxtHandle;
    pInput: PSecBufferDesc): PSecBufferDesc; winapi;
  {$EXTERNALSYM APPLY_CONTROL_TOKEN_FN}
  TApplyControlTokenFn = APPLY_CONTROL_TOKEN_FN;

function QueryContextAttributesW(
  phContext: PCtxtHandle;               // Context to query
  ulAttribute: Cardinal;                // Attribute to query
  pBuffer: Pointer                      // Buffer for attributes
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QueryContextAttributesW}

type
  QUERY_CONTEXT_ATTRIBUTES_FN_W = function(
    phContext: PCtxtHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer): SECURITY_STATUS; winapi;
  {$EXTERNALSYM QUERY_CONTEXT_ATTRIBUTES_FN_W}
  TQueryContextAttributesFnW = QUERY_CONTEXT_ATTRIBUTES_FN_W;

function QueryContextAttributesA(
  phContext: PCtxtHandle;               // Context to query
  ulAttribute: Cardinal;                // Attribute to query
  pBuffer: Pointer                      // Buffer for attributes
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QueryContextAttributesA}

type
  QUERY_CONTEXT_ATTRIBUTES_FN_A = function(
    phContext: PCtxtHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer): SECURITY_STATUS; winapi;
  {$EXTERNALSYM QUERY_CONTEXT_ATTRIBUTES_FN_A}
  TQueryContextAttributesFnA = QUERY_CONTEXT_ATTRIBUTES_FN_A;

function QueryContextAttributes(
  phContext: PCtxtHandle;               // Context to query
  ulAttribute: Cardinal;                // Attribute to query
  pBuffer: Pointer                      // Buffer for attributes
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QueryContextAttributes}

type
  QUERY_CONTEXT_ATTRIBUTES_FN = QUERY_CONTEXT_ATTRIBUTES_FN_W;
  {$EXTERNALSYM QUERY_CONTEXT_ATTRIBUTES_FN}
  TQueryContextAttributesFn = QUERY_CONTEXT_ATTRIBUTES_FN_W;



function SetContextAttributesW(
  phContext: PCtxtHandle;                    // Context to Set
  ulAttribute: Cardinal;                     // Attribute to Set
  pBuffer: Pointer;                          // Buffer for attributes
  cbBuffer: Cardinal                         // Size (in bytes) of Buffer
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SetContextAttributesW}

type
  SET_CONTEXT_ATTRIBUTES_FN_W = function(
    phContext: PCtxtHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer;
    cbBuffer: Cardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SET_CONTEXT_ATTRIBUTES_FN_W}
  TSetContextAttributesFnW = SET_CONTEXT_ATTRIBUTES_FN_W;


function SetContextAttributesA(
  phContext: PCtxtHandle;                   // Context to Set
  ulAttribute: Cardinal;                    // Attribute to Set
  pBuffer: Pointer;                         // Buffer for attributes
  cbBuffer: Cardinal                        // Size (in bytes) of Buffer
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SetContextAttributesA}

type
  SET_CONTEXT_ATTRIBUTES_FN_A = function(
    phContext: PCtxtHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer;
    cbBuffer: Cardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SET_CONTEXT_ATTRIBUTES_FN_A}
  TSetContextAttributesFnA = SET_CONTEXT_ATTRIBUTES_FN_A;

function SetContextAttributes(
  phContext: PCtxtHandle;                    // Context to Set
  ulAttribute: Cardinal;                     // Attribute to Set
  pBuffer: Pointer;                          // Buffer for attributes
  cbBuffer: Cardinal                         // Size (in bytes) of Buffer
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SetContextAttributes}

type
  SET_CONTEXT_ATTRIBUTES_FN = SET_CONTEXT_ATTRIBUTES_FN_W;
  {$EXTERNALSYM SET_CONTEXT_ATTRIBUTES_FN}
  TSetContextAttributesFn = SET_CONTEXT_ATTRIBUTES_FN_W;

function QueryCredentialsAttributesW(
  phCredential: PCredHandle;            // Credential to query
  ulAttribute: Cardinal;                // Attribute to query
  pBuffer: Pointer                      // Buffer for attributes
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QueryCredentialsAttributesW}

type
  QUERY_CREDENTIALS_ATTRIBUTES_FN_W = function(
    phCredential: PCredHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer): SECURITY_STATUS; winapi;
  {$EXTERNALSYM QUERY_CREDENTIALS_ATTRIBUTES_FN_W}
  TQueryCredentialsAttributesFnW = QUERY_CREDENTIALS_ATTRIBUTES_FN_W;

function QueryCredentialsAttributesA(
  phCredential: PCredHandle;            // Credential to query
  ulAttribute: Cardinal;                // Attribute to query
  pBuffer: Pointer                      // Buffer for attributes
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QueryCredentialsAttributesA}

type
  QUERY_CREDENTIALS_ATTRIBUTES_FN_A = function(
    phCredential: PCredHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer): SECURITY_STATUS; winapi;
  {$EXTERNALSYM QUERY_CREDENTIALS_ATTRIBUTES_FN_A}
  TQueryCredentialsAttributesFnA = QUERY_CREDENTIALS_ATTRIBUTES_FN_A;

function QueryCredentialsAttributes(
  phCredential: PCredHandle;            // Credential to query
  ulAttribute: Cardinal;                // Attribute to query
  pBuffer: Pointer                      // Buffer for attributes
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QueryCredentialsAttributes}

type
  QUERY_CREDENTIALS_ATTRIBUTES_FN = QUERY_CREDENTIALS_ATTRIBUTES_FN_W;
  {$EXTERNALSYM QUERY_CREDENTIALS_ATTRIBUTES_FN}
  TQueryCredentialsAttributesFn = QUERY_CREDENTIALS_ATTRIBUTES_FN_W;


function SetCredentialsAttributesW(
  phCredential: PCredHandle;                 // Credential to Set
  ulAttribute: Cardinal;                     // Attribute to Set
  pBuffer: Pointer;                          // Buffer for attributes
  cbBuffer: Cardinal                         // Size (in bytes) of Buffer
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SetCredentialsAttributesW}

type
  SET_CREDENTIALS_ATTRIBUTES_FN_W = function(
    phCredential: PCredHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer;
    cbBuffer: Cardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SET_CREDENTIALS_ATTRIBUTES_FN_W}
  TSetCredentialsAttributesFnW = SET_CREDENTIALS_ATTRIBUTES_FN_W;


function SetCredentialsAttributesA(
  phCredential: PCredHandle;                 // Credential to Set
  ulAttribute: Cardinal;                     // Attribute to Set
  pBuffer: Pointer;                          // Buffer for attributes
  cbBuffer: Cardinal                         // Size (in bytes) of Buffer
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SetCredentialsAttributesA}

type
  SET_CREDENTIALS_ATTRIBUTES_FN_A = function(
    phCredential: PCredHandle;
    ulAttribute: Cardinal;
    pBuffer: Pointer;
    cbBuffer: Cardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM SET_CREDENTIALS_ATTRIBUTES_FN_A}
  TSetCredentialsAttributesFnA = SET_CREDENTIALS_ATTRIBUTES_FN_A;

function SetCredentialsAttributes(
  phCredential: PCredHandle;                 // Credential to Set
  ulAttribute: Cardinal;                     // Attribute to Set
  pBuffer: Pointer;                          // Buffer for attributes
  cbBuffer: Cardinal                         // Size (in bytes) of Buffer
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SetCredentialsAttributes}

type
  SET_CREDENTIALS_ATTRIBUTES_FN = SET_CREDENTIALS_ATTRIBUTES_FN_W;
  {$EXTERNALSYM SET_CREDENTIALS_ATTRIBUTES_FN}
  TSetCredentialsAttributesFn = SET_CREDENTIALS_ATTRIBUTES_FN_W;

function FreeContextBuffer(
  pvContextBuffer: PVOID        // buffer to free
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM FreeContextBuffer}

type
  FREE_CONTEXT_BUFFER_FN = function(
    pvContextBuffer: PVOID): SECURITY_STATUS; winapi;
  {$EXTERNALSYM FREE_CONTEXT_BUFFER_FN}
  TFreeContextBufferFn = FREE_CONTEXT_BUFFER_FN;

///////////////////////////////////////////////////////////////////
////
////    Message Support API
////
//////////////////////////////////////////////////////////////////

function MakeSignature(
  phContext: PCtxtHandle;               // Context to use
  fQOP: Cardinal;                       // Quality of Protection
  pMessage: PSecBufferDesc;             // Message to sign
  MessageSeqNo: Cardinal                // Message Sequence Num.
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM MakeSignature}

type
  MAKE_SIGNATURE_FN = function(
    phContext: PCtxtHandle;
    fQOP: Cardinal;
    pMessage: PSecBufferDesc;
    MessageSeqNo: Cardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM MAKE_SIGNATURE_FN}
  TMakeSignatureFn = MAKE_SIGNATURE_FN;


function VerifySignature(
  phContext: PCtxtHandle;              // Context to use
  pMessage: PSecBufferDesc;            // Message to verify
  MessageSeqNo: Cardinal;              // Sequence Num.
  out pfQOP: Cardinal                  // QOP used
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM VerifySignature}

type
  VERIFY_SIGNATURE_FN = function(
    phContext: PCtxtHandle;
    pMessage: PSecBufferDesc;
    MessageSeqNo: Cardinal;
    out pfQOP: Cardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM VERIFY_SIGNATURE_FN}
  TVerfiySignatureFn = VERIFY_SIGNATURE_FN;

// This only exists win Win2k3 and Greater
const
  SECQOP_WRAP_NO_ENCRYPT     = $80000001;
  {$EXTERNALSYM SECQOP_WRAP_NO_ENCRYPT}
  SECQOP_WRAP_OOB_DATA       = $40000000;
  {$EXTERNALSYM SECQOP_WRAP_OOB_DATA}

function EncryptMessage(
  phContext: PCtxtHandle;
  fQOP: Cardinal;
  pMessage: PSecBufferDesc;
  MessageSeqNo: Cardinal): SECURITY_STATUS; winapi;
{$EXTERNALSYM EncryptMessage}

type
  ENCRYPT_MESSAGE_FN = function(
    phContext: PCtxtHandle;
    fQOP: Cardinal;
    pMessage: PSecBufferDesc;
    MessageSeqNo: Cardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ENCRYPT_MESSAGE_FN}
  TEncryptMessageFn = ENCRYPT_MESSAGE_FN;

function DecryptMessage(
  phContext: PCtxtHandle;
  pMessage: PSecBufferDesc;
  MessageSeqNo: Cardinal;
  pfQOP: PCardinal): SECURITY_STATUS; winapi;
{$EXTERNALSYM DecryptMessage}


type
  DECRYPT_MESSAGE_FN = function(
    phContext: PCtxtHandle;
    pMessage: PSecBufferDesc;
    MessageSeqNo: Cardinal;
    pfQOP: PCardinal): SECURITY_STATUS; winapi;
  {$EXTERNALSYM DECRYPT_MESSAGE_FN}
  TDecryptMessageFn = DECRYPT_MESSAGE_FN;


///////////////////////////////////////////////////////////////////////////
////
////    Misc.
////
///////////////////////////////////////////////////////////////////////////

function EnumerateSecurityPackagesW(
  out pcPackages: Cardinal;            // Receives num. packages
  out ppPackageInfo: PSecPkgInfoW      // Receives array of info
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM EnumerateSecurityPackagesW}

type
  ENUMERATE_SECURITY_PACKAGES_FN_W = function(
    out pcPackages: Cardinal;
    out ppPackageInfo: PSecPkgInfoW): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ENUMERATE_SECURITY_PACKAGES_FN_W}
  TEnumerateSecurityPackagesFnW = ENUMERATE_SECURITY_PACKAGES_FN_W;


function EnumerateSecurityPackagesA(
  out pcPackages: Cardinal;            // Receives num. packages
  out ppPackageInfo: PSecPkgInfoA      // Receives array of info
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM EnumerateSecurityPackagesA}

type
  ENUMERATE_SECURITY_PACKAGES_FN_A = function(
    out pcPackages: Cardinal;
    out ppPackageInfo: PSecPkgInfoA): SECURITY_STATUS; winapi;
  {$EXTERNALSYM ENUMERATE_SECURITY_PACKAGES_FN_A}
  TEnumerateSecurityPackagesFnA = ENUMERATE_SECURITY_PACKAGES_FN_A;

function EnumerateSecurityPackages(
  out pcPackages: Cardinal;            // Receives num. packages
  out ppPackageInfo: PSecPkgInfoW      // Receives array of info
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM EnumerateSecurityPackages}

type
  ENUMERATE_SECURITY_PACKAGES_FN = ENUMERATE_SECURITY_PACKAGES_FN_W;
  {$EXTERNALSYM ENUMERATE_SECURITY_PACKAGES_FN}
  TEnumerateSecurityPackagesFn = ENUMERATE_SECURITY_PACKAGES_FN_W;

function QuerySecurityPackageInfoW(
  pszPackageName: LPWSTR;              // Name of package
  out ppPackageInfo: PSecPkgInfoW      // Receives package info
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QuerySecurityPackageInfoW}

type
  QUERY_SECURITY_PACKAGE_INFO_FN_W = function(
    pszPackageName: PSecWChar;
    out ppPackageInfo: PSecPkgInfoW): SECURITY_STATUS; winapi;
  {$EXTERNALSYM QUERY_SECURITY_PACKAGE_INFO_FN_W}
  TQuerySecurityPackageInfoFnW = QUERY_SECURITY_PACKAGE_INFO_FN_W;

function QuerySecurityPackageInfoA(
  pszPackageName: LPSTR;               // Name of package
  out ppPackageInfo: PSecPkgInfoA      // Receives package info
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QuerySecurityPackageInfoA}

type
  QUERY_SECURITY_PACKAGE_INFO_FN_A = function(
    pszPackageName: PSecChar;
    out ppPackageInfo: PSecPkgInfoA): SECURITY_STATUS; winapi;
  {$EXTERNALSYM QUERY_SECURITY_PACKAGE_INFO_FN_A}
  TQuerySecurityPackageInfoFnA = QUERY_SECURITY_PACKAGE_INFO_FN_A;

function QuerySecurityPackageInfo(
  pszPackageName: LPWSTR;              // Name of package
  out ppPackageInfo: PSecPkgInfoW      // Receives package info
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM QuerySecurityPackageInfo}

type
  QUERY_SECURITY_PACKAGE_INFO_FN = QUERY_SECURITY_PACKAGE_INFO_FN_W;
  {$EXTERNALSYM QUERY_SECURITY_PACKAGE_INFO_FN}
  TQuerySecurityPackageInfoFn = QUERY_SECURITY_PACKAGE_INFO_FN_W;

type
  PSecDelegationType = ^TSecDelegationType;
  {$EXTERNALSYM PSecDelegationType}
  _SecDelegationType = (
    SecFull,
    SecService,
    SecTree,
    SecDirectory,
    SecObject
  );
  {$EXTERNALSYM _SecDelegationType}
  SecDelegationType = _SecDelegationType;
  {$EXTERNALSYM SecDelegationType}
  TSecDelegationType = _SecDelegationType;

function DelegateSecurityContext(
  phContext: PCtxtHandle;                   // IN Active context to delegate
  pszTarget: LPSTR;
  TDelegationType: SecDelegationType;       // IN Type of delegation
  pExpiry: PTimeStamp;                      // IN OPTIONAL time limit
  pPackageParameters: PSecBuffer;           // IN OPTIONAL package specific
  pOutput: PSecBufferDesc                   // OUT Token for applycontroltoken.
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM DelegateSecurityContext}

///////////////////////////////////////////////////////////////////////////
////
////    Proxies
////
///////////////////////////////////////////////////////////////////////////


//
// Proxies are only available on NT platforms
//


///////////////////////////////////////////////////////////////////////////
////
////    Context export/import
////
///////////////////////////////////////////////////////////////////////////


function ExportSecurityContext(
  phContext: PCtxtHandle;                       // (in) context to export
  fFlags: ULONG;                                // (in) option flags
  pPackedContext: PSecBuffer;                   // (out) marshalled context
  out pToken: PPointer                          // (out, optional) token handle for impersonation
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM ExportSecurityContext}

type
  EXPORT_SECURITY_CONTEXT_FN = function(
    phContext: PCtxtHandle;
    fFlags: ULONG;
    pPackedContext: PSecBuffer;
    out pToken: PPointer
    ): SECURITY_STATUS; winapi;
  {$EXTERNALSYM EXPORT_SECURITY_CONTEXT_FN}
  TExportSecurityContextFn = EXPORT_SECURITY_CONTEXT_FN;

function ImportSecurityContextW(
  pszPackage: LPWSTR;
  pPackedContext: PSecBuffer;                        // (in) marshalled context
  Token: Pointer;                                    // (in, optional) handle to token for context
  out phContext: PCtxtHandle                         // (out) new context handle
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM ImportSecurityContextW}

type
  IMPORT_SECURITY_CONTEXT_FN_W = function(
    pszPackage: PSecWChar;
    pPackedContext: PSecBuffer;
    Token: Pointer;
    out phContext: PCtxtHandle
    ): SECURITY_STATUS; winapi;
  {$EXTERNALSYM IMPORT_SECURITY_CONTEXT_FN_W}
  TImportSecurityContextFnW = IMPORT_SECURITY_CONTEXT_FN_W;

function ImportSecurityContextA(
  pszPackage: LPSTR;
  pPackedContext: PSecBuffer;                        // (in) marshalled context
  Token: Pointer;                                    // (in, optional) handle to token for context
  out phContext: PCtxtHandle                         // (out) new context handle
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM ImportSecurityContextA}

type
  IMPORT_SECURITY_CONTEXT_FN_A = function(
    pszPackage: PSecChar;
    pPackedContext: PSecBuffer;
    Token: Pointer;
    out phContext: PCtxtHandle
    ): SECURITY_STATUS; winapi;
  {$EXTERNALSYM IMPORT_SECURITY_CONTEXT_FN_A}
  TImportSecurityContextFnA = IMPORT_SECURITY_CONTEXT_FN_A;

function ImportSecurityContext(
  pszPackage: LPWSTR;
  pPackedContext: PSecBuffer;                        // (in) marshalled context
  Token: Pointer;                                    // (in, optional) handle to token for context
  out phContext: PCtxtHandle                         // (out) new context handle
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM ImportSecurityContext}

type
  IMPORT_SECURITY_CONTEXT_FN = IMPORT_SECURITY_CONTEXT_FN_W;
  {$EXTERNALSYM IMPORT_SECURITY_CONTEXT_FN}
  TImportSecurityContextFn = IMPORT_SECURITY_CONTEXT_FN_W;


///////////////////////////////////////////////////////////////////////////////
////
////  Fast access for RPC:
////
///////////////////////////////////////////////////////////////////////////////
const
  SECURITY_ENTRYPOINT_ANSIW = 'InitSecurityInterfaceW';
  {$EXTERNALSYM SECURITY_ENTRYPOINT_ANSIW}
  SECURITY_ENTRYPOINT_ANSIA = 'InitSecurityInterfaceA';
  {$EXTERNALSYM SECURITY_ENTRYPOINT_ANSIA}
  SECURITY_ENTRYPOINTW = 'InitSecurityInterfaceW';
  {$EXTERNALSYM SECURITY_ENTRYPOINTW}
  SECURITY_ENTRYPOINTA = 'InitSecurityInterfaceA';
  {$EXTERNALSYM SECURITY_ENTRYPOINTA}
  SECURITY_ENTRYPOINT16 = 'INITSECURITYINTERFACEA';
  {$EXTERNALSYM SECURITY_ENTRYPOINT16}

const
  SECURITY_ENTRYPOINT = SECURITY_ENTRYPOINTW;
  {$EXTERNALSYM SECURITY_ENTRYPOINT}
  SECURITY_ENTRYPOINT_ANSI = SECURITY_ENTRYPOINT_ANSIW;
  {$EXTERNALSYM SECURITY_ENTRYPOINT_ANSI}

function FreeCredentialHandle(
  phCredential: PCredHandle             // Handle to free
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM FreeCredentialHandle}

type
  PSecurityFunctionTableW = ^TSecurityFunctionTableW;
  {$EXTERNALSYM PSecurityFunctionTableW}
  _SECURITY_FUNCTION_TABLE_W = record
    dwVersion: Cardinal;
    EnumerateSecurityPackagesW: TEnumerateSecurityPackagesFnW;
    QueryCredentialsAttributesW: TQueryCredentialsAttributesFnW;
    AcquireCredentialsHandleW: TAcquireCredentialsHandleFnW;
    FreeCredentialsHandle: TFreeCredentialsHandleFn;
    Reserved2: Pointer;
    InitializeSecurityContextW: TInitializeSecurityContextFnW;
    AcceptSecurityContext: TAcceptSecurityContextFn;
    CompleteAuthToken: TCompleteAuthTokenFn;
    DeleteSecurityContext: TDeleteSecurityContextFn;
    ApplyControlToken: TApplyControlTokenFn;
    QueryContextAttributesW: TQueryContextAttributesFnW;
    ImpersonateSecurityContext: TImpersonateSecurityContextFn;
    RevertSecurityContext: TRevertSecurityContextFn;
    MakeSignature: TMakeSignatureFn;
    VerifySignature: TVerfiySignatureFn;
    FreeContextBuffer: TFreeContextBufferFn;
    QuerySecurityPackageInfoW: TQuerySecurityPackageInfoFnW;
    Reserved3: Pointer;
    Reserved4: Pointer;
    ExportSecurityContext: TExportSecurityContextFn;
    ImportSecurityContextW: TImportSecurityContextFnW;
    AddCredentialsW: TAddCredentialsFnW;
    Reserved8: Pointer;
    QuerySecurityContextToken: TQuerySecurityContextTokenFn;
    EncryptMessage: TEncryptMessageFn;
    DecryptMessage: TDecryptMessageFn;
    // Fields below this are available in OSes after w2k
    SetContextAttributesW: TSetContextAttributesFnW;

    // Fields below this are available in OSes after W2k3SP1
    SetCredentialsAttributesW: TSetCredentialsAttributesFnW;
{$IF ISSP_MODE <> 0}
    ChangeAccountPasswordW:  CHANGE_PASSWORD_FN_W
{$ELSE}
    Reserved9: Pointer;
{$IFEND}
  end;
  {$EXTERNALSYM _SECURITY_FUNCTION_TABLE_W}
  SecurityFunctionTableW = _SECURITY_FUNCTION_TABLE_W;
  {$EXTERNALSYM SecurityFunctionTableW}
  TSecurityFunctionTableW = _SECURITY_FUNCTION_TABLE_W;

type
  PSecurityFunctionTableA = ^TSecurityFunctionTableA;
  {$EXTERNALSYM PSecurityFunctionTableA}
  _SECURITY_FUNCTION_TABLE_A = record
    dwVersion: Cardinal;
    EnumerateSecurityPackagesA: TEnumerateSecurityPackagesFnA;
    QueryCredentialsAttributesA: TQueryCredentialsAttributesFnA;
    AcquireCredentialsHandleA: TAcquireCredentialsHandleFnA;
    FreeCredentialHandle: TFreeCredentialsHandleFn;
    Reserved2: Pointer;
    InitializeSecurityContextA: TInitializeSecurityContextFnA;
    AcceptSecurityContext: TAcceptSecurityContextFn;
    CompleteAuthToken: TCompleteAuthTokenFn;
    DeleteSecurityContext: TDeleteSecurityContextFn;
    ApplyControlToken: TApplyControlTokenFn;
    QueryContextAttributesA: TQueryContextAttributesFnA;
    ImpersonateSecurityContext: TImpersonateSecurityContextFn;
    RevertSecurityContext: TRevertSecurityContextFn;
    MakeSignature: TMakeSignatureFn;
    VerifySignature: TVerfiySignatureFn;
    FreeContextBuffer: TFreeContextBufferFn;
    QuerySecurityPackageInfoA: TQuerySecurityPackageInfoFnA;
    Reserved3: Pointer;
    Reserved4: Pointer;
    ExportSecurityContext: TExportSecurityContextFn;
    ImportSecurityContextA: TImportSecurityContextFnA;
    AddCredentialsA: TAddCredentialsFnA;
    Reserved8: Pointer;
    QuerySecurityContextToken: TQuerySecurityContextTokenFn;
    EncryptMessage: TEncryptMessageFn;
    DecryptMessage: TDecryptMessageFn;
    SetContextAttributesA: TSetContextAttributesFnA;
    SetCredentialsAttributesA: TSetCredentialsAttributesFnA;
{$IF ISSP_MODE <> 0}
    ChangeAccountPasswordA: TChangePasswordFnA;
{$ELSE}
    Reserved9: Pointer;
{$IFend}
  end;
  {$EXTERNALSYM _SECURITY_FUNCTION_TABLE_A}
  SecurityFunctionTableA = _SECURITY_FUNCTION_TABLE_A;
  {$EXTERNALSYM SecurityFunctionTableA}
  TSecurityFunctionTableA = _SECURITY_FUNCTION_TABLE_A;

type
  PSecurityFunctionTable = PSecurityFunctionTableW;
  {$EXTERNALSYM PSecurityFunctionTable}
  SecurityFunctionTable = SecurityFunctionTableW;
  {$EXTERNALSYM SecurityFunctionTable}
  TSecurityFunctionTable = SecurityFunctionTableW;

//#define SECURITY_

// Function table has all routines through DecryptMessage
const
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION    = 1;
  {$EXTERNALSYM SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION}

// Function table has all routines through SetContextAttributes
const
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_2  = 2;
  {$EXTERNALSYM SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_2}

// Function table has all routines through SetCredentialsAttributes
const
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_3  = 3;
  {$EXTERNALSYM SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_3}

// Function table has all routines through ChangeAccountPassword
const
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_4  = 4;
  {$EXTERNALSYM SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_4}

function InitSecurityInterfaceA: PSecurityFunctionTableA; winapi;
{$EXTERNALSYM InitSecurityInterfaceA}

type
  INIT_SECURITY_INTERFACE_A = function: PSecurityFunctionTableA; winapi;
  {$EXTERNALSYM INIT_SECURITY_INTERFACE_A}
  TInitSecurityInterfaceA = INIT_SECURITY_INTERFACE_A;

function InitSecurityInterfaceW: PSecurityFunctionTableW; winapi;
{$EXTERNALSYM InitSecurityInterfaceW}

type
  INIT_SECURITY_INTERFACE_W = function: PSecurityFunctionTableW; winapi;
  {$EXTERNALSYM INIT_SECURITY_INTERFACE_W}
  TInitSecurityInterfaceW = INIT_SECURITY_INTERFACE_W;

function InitSecurityInterface: PSecurityFunctionTableW; winapi;
{$EXTERNALSYM InitSecurityInterface}

type
  INIT_SECURITY_INTERFACE = INIT_SECURITY_INTERFACE_W;
  {$EXTERNALSYM INIT_SECURITY_INTERFACE}
  TInitSecurityInterface = INIT_SECURITY_INTERFACE_W;


//
// SASL Profile Support
//


function SaslEnumerateProfilesA(
  out ProfileList: LPSTR;
  out ProfileCount: ULONG
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslEnumerateProfilesA}

function SaslEnumerateProfilesW(
  out ProfileList: LPWSTR;
  out ProfileCount: ULONG
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslEnumerateProfilesW}

function SaslEnumerateProfiles(
  out ProfileList: LPWSTR;
  out ProfileCount: ULONG
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslEnumerateProfiles}


function SaslGetProfilePackageA(
  ProfileName: LPSTR;
  out PackageInfo: PSecPkgInfoA
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslGetProfilePackageA}

function SaslGetProfilePackageW(
  ProfileName: LPWSTR;
  out PackageInfo: PSecPkgInfoW
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslGetProfilePackageW}

function SaslGetProfilePackage(
  ProfileName: LPWSTR;
  out PackageInfo: PSecPkgInfoW
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslGetProfilePackage}


function SaslIdentifyPackageA(
  pInput: PSecBufferDesc;
  out PackageInfo: PSecPkgInfoA
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslIdentifyPackageA}

function SaslIdentifyPackageW(
  pInput: PSecBufferDesc;
  out PackageInfo: PSecPkgInfoW
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslIdentifyPackageW}

function SaslIdentifyPackage(
  pInput: PSecBufferDesc;
  out PackageInfo: PSecPkgInfoW
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslIdentifyPackage}


function SaslInitializeSecurityContextW(
  phCredential: PCredHandle;                        // Cred to base context
  phContext: PCtxtHandle;                           // Existing context (OPT)
  pszTargetName: LPWSTR;                            // Name of target
  fContextReq: Cardinal;                            // Context Requirements
  Reserved1: Cardinal;                              // Reserved, MBZ
  TargetDataRep: Cardinal;                          // Data rep of target
  pInput: PSecBufferDesc;                           // Input Buffers
  Reserved2: Cardinal;                              // Reserved, MBZ
  phNewContext: PCtxtHandle;                        // (out) New Context handle
  pOutput: PSecBufferDesc;                          // (inout) Output Buffers
  out pfContextAttr: Cardinal;                      // (out) Context attrs
  ptsExpiry: PTimeStamp                             // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslInitializeSecurityContextW}

function SaslInitializeSecurityContextA(
  phCredential: PCredHandle;                        // Cred to base context
  phContext: PCtxtHandle;                           // Existing context (OPT)
  pszTargetName: LPSTR;                             // Name of target
  fContextReq: Cardinal;                            // Context Requirements
  Reserved1: Cardinal;                              // Reserved, MBZ
  TargetDataRep: Cardinal;                          // Data rep of target
  pInput: PSecBufferDesc;                           // Input Buffers
  Reserved2: Cardinal;                              // Reserved, MBZ
  phNewContext: PCtxtHandle;                        // (out) New Context handle
  pOutput: PSecBufferDesc;                          // (inout) Output Buffers
  out pfContextAttr: Cardinal;                      // (out) Context attrs
  ptsExpiry: PTimeStamp                             // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslInitializeSecurityContextA}

function SaslInitializeSecurityContext(
  phCredential: PCredHandle;                        // Cred to base context
  phContext: PCtxtHandle;                           // Existing context (OPT)
  pszTargetName: LPWSTR;                            // Name of target
  fContextReq: Cardinal;                            // Context Requirements
  Reserved1: Cardinal;                              // Reserved, MBZ
  TargetDataRep: Cardinal;                          // Data rep of target
  pInput: PSecBufferDesc;                           // Input Buffers
  Reserved2: Cardinal;                              // Reserved, MBZ
  phNewContext: PCtxtHandle;                        // (out) New Context handle
  pOutput: PSecBufferDesc;                          // (inout) Output Buffers
  out pfContextAttr: Cardinal;                      // (out) Context attrs
  ptsExpiry: PTimeStamp                             // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslInitializeSecurityContext}


function SaslAcceptSecurityContext(
  phCredential: PCredHandle;                        // Cred to base context
  phContext: PCtxtHandle;                           // Existing context (OPT)
  pInput: PSecBufferDesc;                           // Input buffer
  fContextReq: Cardinal;                            // Context Requirements
  TargetDataRep: Cardinal;                          // Target Data Rep
  phNewContext: PCtxtHandle;                        // (out) New context handle
  pOutput: PSecBufferDesc;                          // (inout) Output buffers
  out pfContextAttr: Cardinal;                      // (out) Context attributes
  ptsExpiry: PTimeStamp                             // (out) Life span (OPT)
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslAcceptSecurityContext}

const
  SASL_OPTION_SEND_SIZE      = 1;       // Maximum size to send to peer
  {$EXTERNALSYM SASL_OPTION_SEND_SIZE}
  SASL_OPTION_RECV_SIZE      = 2;       // Maximum size willing to receive
  {$EXTERNALSYM SASL_OPTION_RECV_SIZE}
  SASL_OPTION_AUTHZ_STRING   = 3;       // Authorization string
  {$EXTERNALSYM SASL_OPTION_AUTHZ_STRING}
  SASL_OPTION_AUTHZ_PROCESSING   = 4;       // Authorization string processing
  {$EXTERNALSYM SASL_OPTION_AUTHZ_PROCESSING}

type
  PSaslAuthzIDState = ^TSaslAuthzIDState;
  _SASL_AUTHZID_STATE = (
    Sasl_AuthZIDForbidden,            // allow no AuthZID strings to be specified - error out (default)
    Sasl_AuthZIDProcessed             // AuthZID Strings processed by Application or SSP
  );
  {$EXTERNALSYM _SASL_AUTHZID_STATE}
  SASL_AUTHZID_STATE = _SASL_AUTHZID_STATE;
  {$EXTERNALSYM SASL_AUTHZID_STATE}
  TSaslAuthzIDState = _SASL_AUTHZID_STATE;


function SaslSetContextOption(
  ContextHandle: PCtxtHandle;
  Option: ULONG;
  Value: PVOID;
  Size: ULONG
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslSetContextOption}


function SaslGetContextOption(
  ContextHandle: PCtxtHandle;
  Option: ULONG;
  Value: PVOID;
  Size: ULONG;
  Needed: PULONG
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SaslGetContextOption}


//
// This is the legacy credentials structure.
// The EX version below is preferred.

{$IF not DECLARED(SEC_WINNT_AUTH_IDENTITY_EX2)}

const
  SEC_WINNT_AUTH_IDENTITY_VERSION_2 = $201;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_VERSION_2}

type
  PSecWinNTAuthIdentityEx2 = ^TSecWinNTAuthIdentityEx2;
  _SEC_WINNT_AUTH_IDENTITY_EX2 = record
    Version: Cardinal;                   // contains SEC_WINNT_AUTH_IDENTITY_VERSION_2
    cbHeaderLength: Word;
    cbStructureLength: Cardinal;
    UserOffset: Cardinal;                // Non-NULL terminated string, unicode only
    UserLength: Word;                    // # of bytes (NOT WCHARs), not including NULL.
    DomainOffset: Cardinal;              // Non-NULL terminated string, unicode only
    DomainLength: Word;                  // # of bytes (NOT WCHARs), not including NULL.
    PackedCredentialsOffset: Cardinal;   // Non-NULL terminated string, unicode only
    PackedCredentialsLength: Word;       // # of bytes (NOT WCHARs), not including NULL.
    Flags: Cardinal;
    PackageListOffset: Cardinal;         // Non-NULL terminated string, unicode only
    PackageListLength: Word;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_IDENTITY_EX2}
  SEC_WINNT_AUTH_IDENTITY_EX2 = _SEC_WINNT_AUTH_IDENTITY_EX2;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_EX2}
  TSecWinNTAuthIdentityEx2 = _SEC_WINNT_AUTH_IDENTITY_EX2;
  PSEC_WINNT_AUTH_IDENTITY_EX2 = PSecWinNTAuthIdentityEx2;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_EX2}

{$IFEND}

{$IF not DECLARED(SEC_WINNT_AUTH_IDENTITY)}

//
// This was not defined in NTIFS.h for windows 2000 however
// this struct has always been there and are safe to use
// in windows 2000 and above.
//
const
  SEC_WINNT_AUTH_IDENTITY_ANSI    = $1;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_ANSI}
  SEC_WINNT_AUTH_IDENTITY_UNICODE = $2;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_UNICODE}

type
  PSecWinNTAuthIdentityW = ^TSecWinNTAuthIdentityW;
  _SEC_WINNT_AUTH_IDENTITY_W = record
    User: PWideChar;          //  Non-NULL terminated string.
    UserLength: Cardinal;     //  # of characters (NOT bytes), not including NULL.
    Domain: PWideChar;        //  Non-NULL terminated string.
    DomainLength: Cardinal;   //  # of characters (NOT bytes), not including NULL.
    Password: PWideChar;      //  Non-NULL terminated string.
    PasswordLength: Cardinal; //  # of characters (NOT bytes), not including NULL.
    Flags: Cardinal;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_IDENTITY_W}
  SEC_WINNT_AUTH_IDENTITY_W = _SEC_WINNT_AUTH_IDENTITY_W;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_W}
  TSecWinNTAuthIdentityW = _SEC_WINNT_AUTH_IDENTITY_W;
  PSEC_WINNT_AUTH_IDENTITY_W = PSecWinNTAuthIdentityW;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_W}



type
  PSecWinNTAuthIdentityA = ^TSecWinNTAuthIdentityA;
  _SEC_WINNT_AUTH_IDENTITY_A = record
    User: PAnsiChar;          //  Non-NULL terminated string.
    UserLength: Cardinal;     //  # of characters (NOT bytes), not including NULL.
    Domain: PAnsiChar;        //  Non-NULL terminated string.
    DomainLength: Cardinal;   //  # of characters (NOT bytes), not including NULL.
    Password: PAnsiChar;      //  Non-NULL terminated string.
    PasswordLength: Cardinal; //  # of characters (NOT bytes), not including NULL.
    Flags: Cardinal;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_IDENTITY_A}
  SEC_WINNT_AUTH_IDENTITY_A = _SEC_WINNT_AUTH_IDENTITY_A;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_A}
  TSecWinNTAuthIdentityA = _SEC_WINNT_AUTH_IDENTITY_A;
  PSEC_WINNT_AUTH_IDENTITY_A = PSecWinNTAuthIdentityA;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_A}

type
  PSecWinNTAuthIdentity = PSEC_WINNT_AUTH_IDENTITY_W;
  SEC_WINNT_AUTH_IDENTITY = SEC_WINNT_AUTH_IDENTITY_W;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY}
  TSecWinNTAuthIdentity = SEC_WINNT_AUTH_IDENTITY_W;
  PSEC_WINNT_AUTH_IDENTITY = PSecWinNTAuthIdentity;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY}
  _SEC_WINNT_AUTH_IDENTITY = _SEC_WINNT_AUTH_IDENTITY_W;
  {$EXTERNALSYM _SEC_WINNT_AUTH_IDENTITY}

{$IFEND}

//
// This is the combined authentication identity structure that may be
// used with the negotiate package, NTLM, Kerberos, or SCHANNEL
//

{$IF not DECLARED(SEC_WINNT_AUTH_IDENTITY_VERSION)}
const
  SEC_WINNT_AUTH_IDENTITY_VERSION = $200;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_VERSION}

type
  PSecWinNTAuthIdentityExW = ^TSecWinNTAuthIdentityExW;
  _SEC_WINNT_AUTH_IDENTITY_EXW = record
    Version: Cardinal;
    Length: Cardinal;
    User: PWideChar;            //  Non-NULL terminated string.
    UserLength: Cardinal;       //  # of characters (NOT bytes), not including NULL.
    Domain: PWideChar;          //  Non-NULL terminated string.
    DomainLength: Cardinal;     //  # of characters (NOT bytes), not including NULL.
    Password: PWideChar;        //  Non-NULL terminated string.
    PasswordLength: Cardinal;   //  # of characters (NOT bytes), not including NULL.
    Flags: Cardinal;
    PackageList: PWideChar;
    PackageListLength: Cardinal;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_IDENTITY_EXW}
  SEC_WINNT_AUTH_IDENTITY_EXW = _SEC_WINNT_AUTH_IDENTITY_EXW;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_EXW}
  TSecWinNTAuthIdentityExW = _SEC_WINNT_AUTH_IDENTITY_EXW;
  PSEC_WINNT_AUTH_IDENTITY_EXW = PSecWinNTAuthIdentityExW;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_EXW}


type
  PSecWinNTAuthIdentityExA = ^TSecWinNTAuthIdentityExA;
  _SEC_WINNT_AUTH_IDENTITY_EXA  = record
    Version: Cardinal;
    Length: Cardinal;
    User: PAnsiChar;            //  Non-NULL terminated string.
    UserLength: Cardinal;       //  # of characters (NOT bytes), not including NULL.
    Domain: PAnsiChar;          //  Non-NULL terminated string.
    DomainLength: Cardinal;     //  # of characters (NOT bytes), not including NULL.
    Password: PAnsiChar;        //  Non-NULL terminated string.
    PasswordLength: Cardinal;   //  # of characters (NOT bytes), not including NULL.
    Flags: Cardinal;
    PackageList: PAnsiChar;
    PackageListLength: Cardinal;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_IDENTITY_EXA}
  SEC_WINNT_AUTH_IDENTITY_EXA = _SEC_WINNT_AUTH_IDENTITY_EXA;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_EXA}
  TSecWinNTAuthIdentityExA = _SEC_WINNT_AUTH_IDENTITY_EXA;
  PSEC_WINNT_AUTH_IDENTITY_EXA = PSecWinNTAuthIdentityExA;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_EXA}

type
  PSecWinNTAuthIdentityEx = PSEC_WINNT_AUTH_IDENTITY_EXW;
  SEC_WINNT_AUTH_IDENTITY_EX = SEC_WINNT_AUTH_IDENTITY_EXW;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_EX}
  TSecWinNTAuthIdentityEx = SEC_WINNT_AUTH_IDENTITY_EXW;
  PSEC_WINNT_AUTH_IDENTITY_EX = PSecWinNTAuthIdentityEx;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_EX}

{$IFEND}

{$IF not DECLARED(SEC_WINNT_AUTH_IDENTITY_INFO)}

//
// the procedure for how to parse a SEC_WINNT_AUTH_IDENTITY_INFO structure:
//
// 1) First check the first DWORD of SEC_WINNT_AUTH_IDENTITY_INFO, if the first
//   DWORD is 0x200, it is either an AuthIdExw or AuthIdExA, otherwise if the first
//   DWORD is 0x201, the structure is an AuthIdEx2 structure. Otherwise the structure
//   is either an AuthId_a or an AuthId_w.
//
// 2) Secondly check the flags for SEC_WINNT_AUTH_IDENTITY_ANSI or
//   SEC_WINNT_AUTH_IDENTITY_UNICODE, the presence of the former means the structure
//   is an ANSI structure. Otherwise, the structure is the wide version.  Note that
//   AuthIdEx2 does not have an ANSI version so this check does not apply to it.
//

type
  PSecWinNTAuthIdentityInfo = ^TSecWinNTAuthIdentityInfo;
  _SEC_WINNT_AUTH_IDENTITY_INFO = record
    case Integer of
    0: (AuthIdExw: TSecWinNTAuthIdentityExW);
    1: (AuthIdExa: TSecWinNTAuthIdentityExA);
    2: (AuthId_a: TSecWinNTAuthIdentityA);
    3: (AuthId_w: TSecWinNTAuthIdentityW);
    4: (AuthIdEx2: TSecWinNTAuthIdentityEx2);
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_IDENTITY_INFO}
  SEC_WINNT_AUTH_IDENTITY_INFO = _SEC_WINNT_AUTH_IDENTITY_INFO;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_INFO}
  TSecWinNTAuthIdentityInfo = _SEC_WINNT_AUTH_IDENTITY_INFO;
  PSEC_WINNT_AUTH_IDENTITY_INFO = PSecWinNTAuthIdentityInfo;
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_INFO}

// the credential structure is encrypted via
// RtlEncryptMemory(OptionFlags = 0)
const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED = $10;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED}

// the credential structure is protected by local system via
// RtlEncryptMemory(OptionFlags=IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON)
const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED  = $20;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED}

// the credential structure is encrypted by a non-system context
// RtlEncryptMemory(OptionFlags=IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON)
const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED    = $40;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED}

  SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED      = $10000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED}
  SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER     = $20000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER}
  SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN   = $40000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN}
  SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER   = $80000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER}


//
//  These bits are for communication between SspiPromptForCredentials()
//  and the credential providers. Do not use these bits for any other
//  purpose.
//
const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_USE_MASK = $FF000000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_USE_MASK}

//
//  Instructs the credential provider to not save credentials itself
//  when caller selects the "Remember my credential" checkbox.
//

const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_SAVE = $80000000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_SAVE}

//
// Support the old name for this flag for callers that were built for earlier
// versions of the SDK.
//

const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_SAVE_CRED_BY_CALLER  = SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_SAVE;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_SAVE_CRED_BY_CALLER}

//
//  State of the "Remember my credentials" checkbox.
//  When set, indicates checked; when cleared, indicates unchecked.
//

const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_SAVE_CRED_CHECKED    = $40000000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_SAVE_CRED_CHECKED}

//
// The "Save" checkbox is not displayed on the credential provider tiles
//

const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_NO_CHECKBOX          = $20000000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_NO_CHECKBOX}

//
// Credential providers will not attempt to prepopulate the CredUI dialog
// box with credentials retrieved from Cred Man.
//

const
  SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_LOAD = $10000000;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_LOAD}


  SEC_WINNT_AUTH_IDENTITY_FLAGS_VALID_SSPIPFC_FLAGS   =
                (SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_SAVE or
                 SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_SAVE_CRED_CHECKED or
                 SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_NO_CHECKBOX or
                 SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_LOAD);
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_FLAGS_VALID_SSPIPFC_FLAGS}


{$IFEND}



type
  PSEC_WINNT_AUTH_IDENTITY_OPAQUE = PVOID; // the credential structure is opaque
  {$EXTERNALSYM PSEC_WINNT_AUTH_IDENTITY_OPAQUE}
  PSecWinNTAuthIdentityOpaque = PVOID;

//
//  dwFlags parameter of SspiPromptForCredentials():
//

//
//  Indicates that the credentials should not be saved if
//  the user selects the 'save' (or 'remember my password')
//  checkbox in the credential dialog box. The location pointed
//  to by the pfSave parameter indicates whether or not the user
//  selected the checkbox.
//
//  Note that some credential providers won't honour this flag and
//  may save the credentials in a persistent manner anyway if the
//  user selects the 'save' checbox.
//
const
  SSPIPFC_CREDPROV_DO_NOT_SAVE   = $00000001;
  {$EXTERNALSYM SSPIPFC_CREDPROV_DO_NOT_SAVE}

//
// Support the old name for this flag for callers that were built for earlier
// versions of the SDK.
//

const
  SSPIPFC_SAVE_CRED_BY_CALLER    = SSPIPFC_CREDPROV_DO_NOT_SAVE;
  {$EXTERNALSYM SSPIPFC_SAVE_CRED_BY_CALLER}

//
// The password and smart card credential providers will not display the
// "Remember my credentials" check box in the provider tiles.
//
const
  SSPIPFC_NO_CHECKBOX            = $00000002;
  {$EXTERNALSYM SSPIPFC_NO_CHECKBOX}

//
// Credential providers will not attempt to prepopulate the CredUI dialog
// box with credentials retrieved from Cred Man.
//
const
  SSPIPFC_CREDPROV_DO_NOT_LOAD   = $00000004;
  {$EXTERNALSYM SSPIPFC_CREDPROV_DO_NOT_LOAD}

//
// Credential providers along with UI Dialog will be hosted in a separate
// broker process.
//
const
  SSPIPFC_USE_CREDUIBROKER = $00000008;
  {$EXTERNALSYM SSPIPFC_USE_CREDUIBROKER}

  SSPIPFC_VALID_FLAGS = (SSPIPFC_CREDPROV_DO_NOT_SAVE or SSPIPFC_NO_CHECKBOX or SSPIPFC_CREDPROV_DO_NOT_LOAD or SSPIPFC_USE_CREDUIBROKER);
  {$EXTERNALSYM SSPIPFC_VALID_FLAGS}


// Use SspiFreeAuthIdentity() to free the buffer returned
// in ppAuthIdentity.

function SspiPromptForCredentialsW(
  pszTargetName: PCWSTR;
{$IF DECLARED(CREDUI_INFO)}
  pUiInfo: PCredUIInfoW;
{$ELSE}
  pUiInfo: PVOID;
{$IFEND}
  dwAuthError: Cardinal;
  pszPackage: PCWSTR;
  pInputAuthIdentity: PSecWinNTAuthIdentityOpaque;
  out ppAuthIdentity: PSecWinNTAuthIdentityOpaque;
  var pfSave: Integer;
  dwFlags: Cardinal
  ): Cardinal; winapi;
{$EXTERNALSYM SspiPromptForCredentialsW}

// Use SspiFreeAuthIdentity() to free the buffer returned
// in ppAuthIdentity.

function SspiPromptForCredentialsA(
  pszTargetName: PCSTR;
{$IF DECLARED(CREDUI_INFO)}
  pUiInfo: PCredUIInfoA;
{$ELSE}
  pUiInfo: PVOID;
{$IFEND}
  dwAuthError: Cardinal;
  pszPackage: PCSTR;
  pInputAuthIdentity: PSecWinNTAuthIdentityOpaque;
  out ppAuthIdentity: PSecWinNTAuthIdentityOpaque;
  var pfSave: Integer;
  dwFlags: Cardinal
  ): Cardinal; winapi;
{$EXTERNALSYM SspiPromptForCredentialsA}

function SspiPromptForCredentials(
  pszTargetName: PCWSTR;
{$IF DECLARED(CREDUI_INFO)}
  pUiInfo: PCredUIInfoW;
{$ELSE}
  pUiInfo: PVOID;
{$IFEND}
  dwAuthError: Cardinal;
  pszPackage: PCWSTR;
  pInputAuthIdentity: PSecWinNTAuthIdentityOpaque;
  out ppAuthIdentity: PSecWinNTAuthIdentityOpaque;
  var pfSave: Integer;
  dwFlags: Cardinal
  ): Cardinal; winapi;
{$EXTERNALSYM SspiPromptForCredentials}
//#ifdef _SEC_WINNT_AUTH_TYPES

type
  PSecWinNTAuthByteVector = ^TSecWinNTAuthByteVector;
  _SEC_WINNT_AUTH_BYTE_VECTOR = record
    ByteArrayOffset: Cardinal; // each element is a byte
    ByteArrayLength: Word; //
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_BYTE_VECTOR}
  SEC_WINNT_AUTH_BYTE_VECTOR = _SEC_WINNT_AUTH_BYTE_VECTOR;
  {$EXTERNALSYM SEC_WINNT_AUTH_BYTE_VECTOR}
  TSecWinNTAuthByteVector = _SEC_WINNT_AUTH_BYTE_VECTOR;
  PSEC_WINNT_AUTH_BYTE_VECTOR = PSecWinNTAuthByteVector;
  {$EXTERNALSYM PSEC_WINNT_AUTH_BYTE_VECTOR}

type
  PSecWinNTAuthData = ^TSecWinNTAuthData;
  _SEC_WINNT_AUTH_DATA = record
    CredType: TGUID;
    CredData: TSecWinNTAuthByteVector;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_DATA}
  SEC_WINNT_AUTH_DATA = _SEC_WINNT_AUTH_DATA;
  {$EXTERNALSYM SEC_WINNT_AUTH_DATA}
  TSecWinNTAuthData = _SEC_WINNT_AUTH_DATA;
  PSEC_WINNT_AUTH_DATA = PSecWinNTAuthData;
  {$EXTERNALSYM PSEC_WINNT_AUTH_DATA}

type
  PSecWinNTAuthPackedCredentials = ^TSecWinNTAuthPackedCredentials;
  _SEC_WINNT_AUTH_PACKED_CREDENTIALS = record
    cbHeaderLength: Word;    // the length of the header
    cbStructureLength: Word; // pay load length including the header
    AuthData: TSecWinNTAuthData;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_PACKED_CREDENTIALS}
  SEC_WINNT_AUTH_PACKED_CREDENTIALS = _SEC_WINNT_AUTH_PACKED_CREDENTIALS;
  {$EXTERNALSYM SEC_WINNT_AUTH_PACKED_CREDENTIALS}
  TSecWinNTAuthPackedCredentials = _SEC_WINNT_AUTH_PACKED_CREDENTIALS;
  PSEC_WINNT_AUTH_PACKED_CREDENTIALS = PSecWinNTAuthPackedCredentials;
  {$EXTERNALSYM PSEC_WINNT_AUTH_PACKED_CREDENTIALS}

// {28BFC32F-10F6-4738-98D1-1AC061DF716A}
const
  SEC_WINNT_AUTH_DATA_TYPE_PASSWORD: TGUID =
    (D1:$28bfc32f; D2:$10f6; D3:$4738; D4:( $98, $d1, $1a, $c0, $61, $df, $71, $6a ));
  {$EXTERNALSYM SEC_WINNT_AUTH_DATA_TYPE_PASSWORD}

// {235F69AD-73FB-4dbc-8203-0629E739339B}
const
  SEC_WINNT_AUTH_DATA_TYPE_CERT: TGUID =
    (D1:$235f69ad; D2:$73fb; D3:$4dbc; D4:( $82, $3, $6, $29, $e7, $39, $33, $9b ));
  {$EXTERNALSYM SEC_WINNT_AUTH_DATA_TYPE_CERT}

type
  PSecWinNTAuthDataPassword = ^TSecWinNTAuthDataPassword;
  _SEC_WINNT_AUTH_DATA_PASSWORD = record
    UnicodePassword: TSecWinNTAuthByteVector;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_DATA_PASSWORD}
  SEC_WINNT_AUTH_DATA_PASSWORD = _SEC_WINNT_AUTH_DATA_PASSWORD;
  {$EXTERNALSYM SEC_WINNT_AUTH_DATA_PASSWORD}
  TSecWinNTAuthDataPassword = _SEC_WINNT_AUTH_DATA_PASSWORD;
  PSEC_WINNT_AUTH_DATA_PASSWORD = PSecWinNTAuthDataPassword;
  {$EXTERNALSYM PSEC_WINNT_AUTH_DATA_PASSWORD}

//
// smartcard cred data
//
// {68FD9879-079C-4dfe-8281-578AADC1C100}

const
  SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA: TGUID =
    (D1:$68fd9879; D2:$79c; D3:$4dfe; D4:( $82, $81, $57, $8a, $ad, $c1, $c1, $0 ));
  {$EXTERNALSYM SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA}

type
  PSecWinNTAuthCertificateData = ^TSecWinNTAuthCertificateData;
  _SEC_WINNT_AUTH_CERTIFICATE_DATA = record
     cbHeaderLength: Word;
     cbStructureLength: Word;
     Certificate: TSecWinNTAuthByteVector;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_CERTIFICATE_DATA}
  SEC_WINNT_AUTH_CERTIFICATE_DATA = _SEC_WINNT_AUTH_CERTIFICATE_DATA;
  {$EXTERNALSYM SEC_WINNT_AUTH_CERTIFICATE_DATA}
  TSecWinNTAuthCertificateData = _SEC_WINNT_AUTH_CERTIFICATE_DATA;
  PSEC_WINNT_AUTH_CERTIFICATE_DATA = PSecWinNTAuthCertificateData;
  {$EXTERNALSYM PSEC_WINNT_AUTH_CERTIFICATE_DATA}

type
  PSecWinNTCredUIContextVector = ^TSecWinNTCredUIContextVector;
  _SEC_WINNT_CREDUI_CONTEXT_VECTOR = record
    CredUIContextArrayOffset: ULONG; // offset starts at the beginning of
    // this structure, and each element is a SEC_WINNT_AUTH_BYTE_VECTOR that
    // describes the flat CredUI context returned by SpGetCredUIContext()
    CredUIContextCount: USHORT;
  end;
  {$EXTERNALSYM _SEC_WINNT_CREDUI_CONTEXT_VECTOR}
  SEC_WINNT_CREDUI_CONTEXT_VECTOR = _SEC_WINNT_CREDUI_CONTEXT_VECTOR;
  {$EXTERNALSYM SEC_WINNT_CREDUI_CONTEXT_VECTOR}
  TSecWinNTCredUIContextVector = _SEC_WINNT_CREDUI_CONTEXT_VECTOR;
  PSEC_WINNT_CREDUI_CONTEXT_VECTOR = PSecWinNTCredUIContextVector;
  {$EXTERNALSYM PSEC_WINNT_CREDUI_CONTEXT_VECTOR}

type
  PSecWinNTAuthShortVector = ^TSecWinNTAuthShortVector;
  _SEC_WINNT_AUTH_SHORT_VECTOR = record
    ShortArrayOffset: ULONG; // each element is a short
    ShortArrayCount: USHORT; // number of characters
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_SHORT_VECTOR}
  SEC_WINNT_AUTH_SHORT_VECTOR = _SEC_WINNT_AUTH_SHORT_VECTOR;
  {$EXTERNALSYM SEC_WINNT_AUTH_SHORT_VECTOR}
  TSecWinNTAuthShortVector = _SEC_WINNT_AUTH_SHORT_VECTOR;
  PSEC_WINNT_AUTH_SHORT_VECTOR = PSecWinNTAuthShortVector;
  {$EXTERNALSYM PSEC_WINNT_AUTH_SHORT_VECTOR}

// free the returned memory using SspiLocalFree

function SspiGetCredUIContext(
  ContextHandle: THandle;
  const CredType: TGUID;
  LogonId: PLUID;  // use this LogonId, the caller must be localsystem to supply a logon id
  out CredUIContexts: PSecWinNTCredUIContextVector;
  TokenHandle: PHandle
  ): SECURITY_STATUS; winapi;

function SspiUpdateCredentials(
  ContextHandle: THandle;
  const CredType: TGUID;
  FlatCredUIContextLength: ULONG;
  FlatCredUIContext: PUCHAR
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiUpdateCredentials}

type
  PCredUIWinMarshaledContext = ^TCredUIWinMarshaledContext;
  _CREDUIWIN_MARSHALED_CONTEXT = record
    StructureType: TGUID;
    cbHeaderLength: USHORT;
    LogonId: TLUID; // user's logon id
    MarshaledDataType: TGUID;
    MarshaledDataOffset: ULONG;
    MarshaledDataLength: USHORT;
  end;
  {$EXTERNALSYM _CREDUIWIN_MARSHALED_CONTEXT}
  CREDUIWIN_MARSHALED_CONTEXT = _CREDUIWIN_MARSHALED_CONTEXT;
  {$EXTERNALSYM CREDUIWIN_MARSHALED_CONTEXT}
  TCredUIWinMarshaledContext = _CREDUIWIN_MARSHALED_CONTEXT;
  PCREDUIWIN_MARSHALED_CONTEXT = PCredUIWinMarshaledContext;
  {$EXTERNALSYM PCREDUIWIN_MARSHALED_CONTEXT}

type
  PSecWinNTCredUIContext = ^TSecWinNTCredUIContext;
  _SEC_WINNT_CREDUI_CONTEXT = record
    cbHeaderLength: USHORT;
    CredUIContextHandle: THandle; // the handle to call SspiGetCredUIContext()
{$IF DECLARED(CREDUI_INFO)}
    UIInfo: PCredUIInfoW; // input from SspiPromptForCredentials()
{$ELSE}
    UIInfo: PVOID;
{$IFEND}
    dwAuthError: ULONG; // the authentication error
    pInputAuthIdentity: PSecWinNTAuthIdentityOpaque;
    TargetName: Pointer; //!!!!  PUNICODE_STRING;
  end;
  {$EXTERNALSYM _SEC_WINNT_CREDUI_CONTEXT}
  SEC_WINNT_CREDUI_CONTEXT = _SEC_WINNT_CREDUI_CONTEXT;
  {$EXTERNALSYM SEC_WINNT_CREDUI_CONTEXT}
  TSecWinNTCredUIContext = _SEC_WINNT_CREDUI_CONTEXT;
  PSEC_WINNT_CREDUI_CONTEXT = PSecWinNTCredUIContext;
  {$EXTERNALSYM PSEC_WINNT_CREDUI_CONTEXT}

// {3C3E93D9-D96B-49b5-94A7-458592088337}
const
  CREDUIWIN_STRUCTURE_TYPE_SSPIPFC: TGUID =
    (D1:$3c3e93d9; D2:$d96b; D3:$49b5; D4:( $94, $a7, $45, $85, $92, $8, $83, $37 ));
  {$EXTERNALSYM CREDUIWIN_STRUCTURE_TYPE_SSPIPFC}

// {C2FFFE6F-503D-4c3d-A95E-BCE821213D44}
const
  SSPIPFC_STRUCTURE_TYPE_CREDUI_CONTEXT: TGUID =
    (D1:$c2fffe6f; D2:$503d; D3:$4c3d; D4:( $a9, $5e, $bc, $e8, $21, $21, $3d, $44 ));
  {$EXTERNALSYM SSPIPFC_STRUCTURE_TYPE_CREDUI_CONTEXT}

type
  PSecWinNTAuthPackedCredentialsEx = ^TSecWinNTAuthPackedCredentialsEx;
  _SEC_WINNT_AUTH_PACKED_CREDENTIALS_EX = record
    cbHeaderLength: Word;
    Flags: Cardinal;    // contains the Flags field in
                        // SEC_WINNT_AUTH_IDENTITY_EX
    PackedCredentials: TSecWinNTAuthByteVector;
    PackageList: TSecWinNTAuthShortVector;
  end;
  {$EXTERNALSYM _SEC_WINNT_AUTH_PACKED_CREDENTIALS_EX}
  SEC_WINNT_AUTH_PACKED_CREDENTIALS_EX = _SEC_WINNT_AUTH_PACKED_CREDENTIALS_EX;
  {$EXTERNALSYM SEC_WINNT_AUTH_PACKED_CREDENTIALS_EX}
  TSecWinNTAuthPackedCredentialsEx = _SEC_WINNT_AUTH_PACKED_CREDENTIALS_EX;
  PSEC_WINNT_AUTH_PACKED_CREDENTIALS_EX = PSecWinNTAuthPackedCredentialsEx;
  {$EXTERNALSYM PSEC_WINNT_AUTH_PACKED_CREDENTIALS_EX}

//
// free the returned memory using SspiLocalFree
//

function SspiUnmarshalCredUIContext(
  MarshaledCredUIContext: PUCHAR;
  MarshaledCredUIContextLength: ULONG;
  out CredUIContext: PSecWinNTCredUIContext
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiUnmarshalCredUIContext}

//#endif // _SEC_WINNT_AUTH_TYPES

function SspiPrepareForCredRead(
  AuthIdentity: PSecWinNTAuthIdentityOpaque;
  pszTargetName: PCWSTR;
  out pCredmanCredentialType: ULONG;
  out ppszCredmanTargetName: PCWSTR
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiPrepareForCredRead}

function SspiPrepareForCredWrite(
  AuthIdentity: PSecWinNTAuthIdentityOpaque;
  pszTargetName: PCWSTR; // supply NULL for username-target credentials
  out pCredmanCredentialType: ULONG;
  out ppszCredmanTargetName: PCWSTR;
  out ppszCredmanUserName: PCWSTR;
  out ppCredentialBlob: PUCHAR;
  out pCredentialBlobSize: ULONG
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiPrepareForCredWrite}

//
// Input flags for SspiEncryptAuthIdentityEx and
// SspiDecryptAuthIdentityEx functions
//
const
  SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_LOGON       = $1;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_LOGON}
  SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_PROCESS     = $2;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_ENCRYPT_SAME_PROCESS}


function SspiEncryptAuthIdentity(
  AuthData: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiEncryptAuthIdentity}

function SspiEncryptAuthIdentityEx(
  Options: ULONG;
  AuthData: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiEncryptAuthIdentityEx}

function SspiDecryptAuthIdentity(
  EncryptedAuthData: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiDecryptAuthIdentity}

function SspiDecryptAuthIdentityEx(
  Options: ULONG;
  EncryptedAuthData: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS;
{$EXTERNALSYM SspiDecryptAuthIdentityEx}

function SspiIsAuthIdentityEncrypted(
  EncryptedAuthData: PSecWinNTAuthIdentityOpaque
  ): ByteBool; winapi;
{$EXTERNALSYM SspiIsAuthIdentityEncrypted}


//
//  Convert the _OPAQUE structure passed in to the
//  3 tuple <username, domainname, 'password'>.
//
//  Note: The 'strings' returned need not necessarily be
//  in user recognisable form. The purpose of this API
//  is to 'flatten' the _OPAQUE structure into the 3 tuple.
//  User recognisable <username, domainname> can always be
//  obtained by passing NULL to the pszPackedCredentialsString
//  parameter.
//
// zero out the pszPackedCredentialsString then
// free the returned memory using SspiLocalFree()
//

function SspiEncodeAuthIdentityAsStrings(
  pAuthIdentity: PSecWinNTAuthIdentityOpaque;
  out ppszUserName: PCWSTR;
  out ppszDomainName: PCWSTR;
  out ppszPackedCredentialsString: PCWSTR
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiEncodeAuthIdentityAsStrings}

function SspiValidateAuthIdentity(
  AuthData: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiValidateAuthIdentity}

//
// free the returned memory using SspiFreeAuthIdentity()
//


function SspiCopyAuthIdentity(
  AuthData: PSecWinNTAuthIdentityOpaque;
  out AuthDataCopy: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiCopyAuthIdentity}

//
// use only for the memory returned by SspiCopyAuthIdentity().
// Internally calls SspiZeroAuthIdentity().
//

procedure SspiFreeAuthIdentity(
  AuthData: PSecWinNTAuthIdentityOpaque
  ); winapi;
{$EXTERNALSYM SspiFreeAuthIdentity}

procedure SspiZeroAuthIdentity(
  AuthData: PSecWinNTAuthIdentityOpaque
  ); winapi;
{$EXTERNALSYM SspiZeroAuthIdentity}

procedure SspiLocalFree(
  DataBuffer: PVOID
  ); winapi;
{$EXTERNALSYM SspiLocalFree}

//
// call SspiFreeAuthIdentity to free the returned AuthIdentity
// which zeroes out the credentials blob before freeing it
//

function SspiEncodeStringsAsAuthIdentity(
  pszUserName: PCWSTR;
  pszDomainName: PCWSTR;
  pszPackedCredentialsString: PCWSTR;
  out ppAuthIdentity: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiEncodeStringsAsAuthIdentity}

function SspiCompareAuthIdentities(
  AuthIdentity1: PSecWinNTAuthIdentityOpaque;
  AuthIdentity2: PSecWinNTAuthIdentityOpaque;
  SameSuppliedUser: PBOOLEAN;
  SameSuppliedIdentity: PBOOLEAN
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiCompareAuthIdentities}

//
// zero out the returned AuthIdentityByteArray then
// free the returned memory using SspiLocalFree()
//

function SspiMarshalAuthIdentity(
  AuthIdentity: PSecWinNTAuthIdentityOpaque;
  out AuthIdentityLength: Cardinal;
  out AuthIdentityByteArray: PByte
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiMarshalAuthIdentity}

//
// free the returned auth identity using SspiFreeAuthIdentity()
//

function SspiUnmarshalAuthIdentity(
  AuthIdentityLength: Cardinal;
  AuthIdentityByteArray: PByte;
  out ppAuthIdentity: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiUnmarshalAuthIdentity}

function SspiIsPromptingNeeded(
  ErrorOrNtStatus: Cardinal
  ): ByteBool; winapi;
{$EXTERNALSYM SspiIsPromptingNeeded}

function SspiGetTargetHostName(
  pszTargetName: PCWSTR;
  out pszHostName: PWSTR
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiGetTargetHostName}

function SspiExcludePackage(
  AuthIdentity: PSecWinNTAuthIdentityOpaque;
  pszPackageName: PCWSTR;
  out ppNewAuthIdentity: PSecWinNTAuthIdentityOpaque
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM SspiExcludePackage}


//
// Common types used by negotiable security packages
//
// These are defined after W2K
//
const
  SEC_WINNT_AUTH_IDENTITY_MARSHALLED     = $4;     // all data is in one buffer
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_MARSHALLED}
  SEC_WINNT_AUTH_IDENTITY_ONLY           = $8;     // these credentials are for identity only - no PAC needed
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_ONLY}


//
// Routines for manipulating packages
//

type
  PSecurityPackageOptions = ^TSecurityPackageOptions;
  _SECURITY_PACKAGE_OPTIONS = record
    Size: Cardinal;
    &Type: Cardinal;
    Flags: Cardinal;
    SignatureSize: Cardinal;
    Signature: Pointer;
  end;
  {$EXTERNALSYM _SECURITY_PACKAGE_OPTIONS}
  SECURITY_PACKAGE_OPTIONS = _SECURITY_PACKAGE_OPTIONS;
  {$EXTERNALSYM SECURITY_PACKAGE_OPTIONS}
  TSecurityPackageOptions = _SECURITY_PACKAGE_OPTIONS;
  PSECURITY_PACKAGE_OPTIONS = PSecurityPackageOptions;
  {$EXTERNALSYM PSECURITY_PACKAGE_OPTIONS}

const
  SECPKG_OPTIONS_TYPE_UNKNOWN = 0;
  {$EXTERNALSYM SECPKG_OPTIONS_TYPE_UNKNOWN}
  SECPKG_OPTIONS_TYPE_LSA     = 1;
  {$EXTERNALSYM SECPKG_OPTIONS_TYPE_LSA}
  SECPKG_OPTIONS_TYPE_SSPI    = 2;
  {$EXTERNALSYM SECPKG_OPTIONS_TYPE_SSPI}

  SECPKG_OPTIONS_PERMANENT    = $00000001;
  {$EXTERNALSYM SECPKG_OPTIONS_PERMANENT}


function AddSecurityPackageA(
  pszPackageName: LPSTR;
  pOptions: PSecurityPackageOptions
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AddSecurityPackageA}

function AddSecurityPackageW(
  pszPackageName: LPWSTR;
  pOptions: PSecurityPackageOptions
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AddSecurityPackageW}

function AddSecurityPackage(
  pszPackageName: LPWSTR;
  pOptions: PSecurityPackageOptions
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM AddSecurityPackage}


function DeleteSecurityPackageA(
  pszPackageName: LPSTR
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM DeleteSecurityPackageA}

function DeleteSecurityPackageW(
  pszPackageName: LPWSTR
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM DeleteSecurityPackageW}

function DeleteSecurityPackage(
  pszPackageName: LPWSTR
  ): SECURITY_STATUS; winapi;
{$EXTERNALSYM DeleteSecurityPackage}

{$ENDREGION}

implementation

const
  Secur32Dll = 'secur32.dll';
  CreduiDll = 'credui.dll';
  SspiCliDll = 'sspicli.dll';

{$REGION 'sspi.h'}
function AcquireCredentialsHandleW; external Secur32Dll name 'AcquireCredentialsHandleW';
function AcquireCredentialsHandleA; external Secur32Dll name 'AcquireCredentialsHandleA';
function AcquireCredentialsHandle; external Secur32Dll name 'AcquireCredentialsHandleW';
function FreeCredentialsHandle; external Secur32Dll name 'FreeCredentialsHandle';
function AddCredentialsW; external Secur32Dll name 'AddCredentialsW';
function AddCredentialsA; external Secur32Dll name 'AddCredentialsA';
function AddCredentials; external Secur32Dll name 'AddCredentialsW';

function ChangeAccountPasswordW; external Secur32Dll name 'ChangeAccountPasswordW' delayed;
function ChangeAccountPasswordA; external Secur32Dll name 'ChangeAccountPasswordA' delayed;
function ChangeAccountPassword; external Secur32Dll name 'ChangeAccountPasswordW' delayed;

function InitializeSecurityContextW; external Secur32Dll name 'InitializeSecurityContextW';
function InitializeSecurityContextA; external Secur32Dll name 'InitializeSecurityContextA';
function InitializeSecurityContext; external Secur32Dll name 'InitializeSecurityContextW';
function AcceptSecurityContext; external Secur32Dll name 'AcceptSecurityContext';
function CompleteAuthToken; external Secur32Dll name 'CompleteAuthToken';
function ImpersonateSecurityContext; external Secur32Dll name 'ImpersonateSecurityContext';
function RevertSecurityContext; external Secur32Dll name 'RevertSecurityContext';
function QuerySecurityContextToken; external Secur32Dll name 'QuerySecurityContextToken';
function DeleteSecurityContext; external Secur32Dll name 'DeleteSecurityContext';
function ApplyControlToken; external Secur32Dll name 'ApplyControlToken';
function QueryContextAttributesW; external Secur32Dll name 'QueryContextAttributesW';
function QueryContextAttributesA; external Secur32Dll name 'QueryContextAttributesA';
function QueryContextAttributes; external Secur32Dll name 'QueryContextAttributesW';
function SetContextAttributesW; external Secur32Dll name 'SetContextAttributesW';
function SetContextAttributesA; external Secur32Dll name 'SetContextAttributesA';
function SetContextAttributes; external Secur32Dll name 'SetContextAttributesW';
function QueryCredentialsAttributesW; external Secur32Dll name 'QueryCredentialsAttributesW';
function QueryCredentialsAttributesA; external Secur32Dll name 'QueryCredentialsAttributesA';
function QueryCredentialsAttributes; external Secur32Dll name 'QueryCredentialsAttributesW';
function SetCredentialsAttributesW; external Secur32Dll name 'SetCredentialsAttributesW';
function SetCredentialsAttributesA; external Secur32Dll name 'SetCredentialsAttributesA';
function SetCredentialsAttributes; external Secur32Dll name 'SetCredentialsAttributesW';
function FreeContextBuffer; external Secur32Dll name 'FreeContextBuffer';

function MakeSignature; external Secur32Dll name 'MakeSignature';
function VerifySignature; external Secur32Dll name 'VerifySignature';
function EncryptMessage; external Secur32Dll name 'EncryptMessage';
function DecryptMessage; external Secur32Dll name 'DecryptMessage';

function EnumerateSecurityPackagesW; external Secur32Dll name 'EnumerateSecurityPackagesW';
function EnumerateSecurityPackagesA; external Secur32Dll name 'EnumerateSecurityPackagesA';
function EnumerateSecurityPackages; external Secur32Dll name 'EnumerateSecurityPackagesW';
function QuerySecurityPackageInfoW; external Secur32Dll name 'QuerySecurityPackageInfoW';
function QuerySecurityPackageInfoA; external Secur32Dll name 'QuerySecurityPackageInfoA';
function QuerySecurityPackageInfo; external Secur32Dll name 'QuerySecurityPackageInfoW';
function DelegateSecurityContext; external Secur32Dll name 'DelegateSecurityContext';

function ExportSecurityContext; external Secur32Dll name 'ExportSecurityContext';
function ImportSecurityContextW; external Secur32Dll name 'ImportSecurityContextW';
function ImportSecurityContextA; external Secur32Dll name 'ImportSecurityContextA';
function ImportSecurityContext; external Secur32Dll name 'ImportSecurityContextW';

function FreeCredentialHandle; external Secur32Dll name 'FreeCredentialsHandle';
function InitSecurityInterfaceA; external Secur32Dll name 'InitSecurityInterfaceA';
function InitSecurityInterfaceW; external Secur32Dll name 'InitSecurityInterfaceW';
function InitSecurityInterface; external Secur32Dll name 'InitSecurityInterfaceW';

function SaslEnumerateProfilesA; external Secur32Dll name 'SaslEnumerateProfilesA' delayed;
function SaslEnumerateProfilesW; external Secur32Dll name 'SaslEnumerateProfilesW' delayed;
function SaslEnumerateProfiles; external Secur32Dll name 'SaslEnumerateProfilesW' delayed;
function SaslGetProfilePackageA; external Secur32Dll name 'SaslGetProfilePackageA' delayed;
function SaslGetProfilePackageW; external Secur32Dll name 'SaslGetProfilePackageW' delayed;
function SaslGetProfilePackage; external Secur32Dll name 'SaslGetProfilePackageW' delayed;
function SaslIdentifyPackageA; external Secur32Dll name 'SaslIdentifyPackageA' delayed;
function SaslIdentifyPackageW; external Secur32Dll name 'SaslIdentifyPackageW' delayed;
function SaslIdentifyPackage; external Secur32Dll name 'SaslIdentifyPackageW' delayed;
function SaslInitializeSecurityContextW; external Secur32Dll name 'SaslInitializeSecurityContextW' delayed;
function SaslInitializeSecurityContextA; external Secur32Dll name 'SaslInitializeSecurityContextA' delayed;
function SaslInitializeSecurityContext; external Secur32Dll name 'SaslInitializeSecurityContextW' delayed;
function SaslAcceptSecurityContext; external Secur32Dll name 'SaslAcceptSecurityContext' delayed;
function SaslSetContextOption; external Secur32Dll name 'SaslSetContextOption' delayed;
function SaslGetContextOption; external Secur32Dll name 'SaslGetContextOption' delayed;

function SspiPromptForCredentialsW; external CreduiDll name 'SspiPromptForCredentialsW' delayed;
function SspiPromptForCredentialsA; external CreduiDll name 'SspiPromptForCredentialsA' delayed;
function SspiPromptForCredentials;  external CreduiDll name 'SspiPromptForCredentialsW' delayed;
function SspiGetCredUIContext; external CreduiDll name 'SspiGetCredUIContext' delayed;
function SspiUpdateCredentials; external CreduiDll name 'SspiUpdateCredentials' delayed;
function SspiUnmarshalCredUIContext; external CreduiDll name 'SspiUnmarshalCredUIContext' delayed;
function SspiPrepareForCredRead; external SspiCliDll name 'SspiPrepareForCredRead' delayed;
function SspiPrepareForCredWrite; external SspiCliDll name 'SspiPrepareForCredWrite' delayed;
function SspiEncryptAuthIdentity; external SspiCliDll name 'SspiEncryptAuthIdentity' delayed;
function SspiEncryptAuthIdentityEx; external SspiCliDll name 'SspiEncryptAuthIdentityEx' delayed;
function SspiDecryptAuthIdentity; external SspiCliDll name 'SspiDecryptAuthIdentity' delayed;
function SspiDecryptAuthIdentityEx; external SspiCliDll name 'SspiDecryptAuthIdentityEx' delayed;
function SspiIsAuthIdentityEncrypted; external SspiCliDll name 'SspiIsAuthIdentityEncrypted' delayed;
function SspiEncodeAuthIdentityAsStrings; external SspiCliDll name 'SspiEncodeAuthIdentityAsStrings' delayed;
function SspiValidateAuthIdentity; external SspiCliDll name 'SspiValidateAuthIdentity' delayed;
function SspiCopyAuthIdentity; external SspiCliDll name 'SspiCopyAuthIdentity' delayed;
procedure SspiFreeAuthIdentity; external SspiCliDll name 'SspiFreeAuthIdentity' delayed;
procedure SspiZeroAuthIdentity; external SspiCliDll name 'SspiZeroAuthIdentity' delayed;
procedure SspiLocalFree; external SspiCliDll name 'SspiLocalFree' delayed;
function SspiEncodeStringsAsAuthIdentity; external SspiCliDll name 'SspiEncodeStringsAsAuthIdentity' delayed;
function SspiCompareAuthIdentities; external SspiCliDll name 'SspiCompareAuthIdentities' delayed;
function SspiMarshalAuthIdentity; external SspiCliDll name 'SspiMarshalAuthIdentity' delayed;
function SspiUnmarshalAuthIdentity; external SspiCliDll name 'SspiUnmarshalAuthIdentity' delayed;
function SspiIsPromptingNeeded; external CreduiDll name 'SspiIsPromptingNeeded' delayed;
function SspiGetTargetHostName; external SspiCliDll name 'SspiGetTargetHostName' delayed;
function SspiExcludePackage; external Secur32Dll name 'SspiExcludePackage' delayed;

function AddSecurityPackageA; external Secur32Dll name 'AddSecurityPackageA' delayed;
function AddSecurityPackageW; external Secur32Dll name 'AddSecurityPackageW' delayed;
function AddSecurityPackage; external Secur32Dll name 'AddSecurityPackageW' delayed;
function DeleteSecurityPackageA; external Secur32Dll name 'DeleteSecurityPackageA' delayed;
function DeleteSecurityPackageW; external Secur32Dll name 'DeleteSecurityPackageW' delayed;
function DeleteSecurityPackage; external Secur32Dll name 'DeleteSecurityPackageW' delayed;


procedure SecInvalidateHandle(var x: TSecHandle); inline;
begin
  x.dwLower := ULONG_PTR(INT_PTR(-1));
  x.dwUpper := ULONG_PTR(INT_PTR(-1));
end;

function SecIsValidHandle(var x: TSecHandle): Boolean; inline;
begin
  Result := (x.dwLower <> ULONG_PTR(INT_PTR(-1))) and
            (x.dwUpper <> ULONG_PTR(INT_PTR(-1)));
end;
{$ENDREGION}

end.
