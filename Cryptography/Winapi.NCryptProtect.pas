unit Winapi.NCryptProtect;

interface

uses
  Windows, Winapi.NCrypt;

{$IF not DECLARED(SIZE_T)}
type
  SIZE_T = ULONG_PTR;
  {$EXTERNALSYM SIZE_T}
{$IFEND}

{$REGION 'ncryptprotect.h'}

{$WARN SYMBOL_PLATFORM OFF}

const
  NCRYPT_DESCR_DELIMITER_OR   = 'OR';
  {$EXTERNALSYM NCRYPT_DESCR_DELIMITER_OR}
  NCRYPT_DESCR_DELIMITER_AND  = 'AND';
  {$EXTERNALSYM NCRYPT_DESCR_DELIMITER_AND}
  NCRYPT_DESCR_EQUAL          = '=';
  {$EXTERNALSYM NCRYPT_DESCR_EQUAL}

(****************************************************************************
    Examples of Protection Descriptor:


    "SID=S-1-5-21-4392301 AND SID=S-1-5-21-3101812"
    "SDDL=O:S-1-5-5-0-290724G:SYD:(A;;CCDC;;;S-1-5-5-0-290724)(A;;DC;;;WD)"
    "LOCAL=user"
    "LOCAL=machine"

    "WEBCREDENTIALS=MyPasswordName"
    "WEBCREDENTIALS=MyPasswordName,myweb.com"

****************************************************************************)


(****************************************************************************
  Microsoft Key Protection Provider

    NCRYPT_KEY_PROTECTION_ALGORITHM_SID
    NCRYPT_KEY_PROTECTION_ALGORITHM_SDDL
    NCRYPT_KEY_PROTECTION_ALGORITHM_LOCAL
****************************************************************************)
const
  MS_KEY_PROTECTION_PROVIDER     = 'Microsoft Key Protection Provider';
  {$EXTERNALSYM MS_KEY_PROTECTION_PROVIDER}

//
// Microsoft Key Protection Provider supports the following formats:
//

const
  NCRYPT_KEY_PROTECTION_ALGORITHM_SID            = 'SID';
  {$EXTERNALSYM NCRYPT_KEY_PROTECTION_ALGORITHM_SID}
//
// SID=%SidString%
//
// %SidString% is a SID string that identifies the object's group or principal identity
//
const
  NCRYPT_KEY_PROTECTION_ALGORITHM_LOCAL    = 'LOCAL';
  {$EXTERNALSYM NCRYPT_KEY_PROTECTION_ALGORITHM_LOCAL}

  NCRYPT_KEY_PROTECTION_LOCAL_LOGON        = 'logon';
  {$EXTERNALSYM NCRYPT_KEY_PROTECTION_LOCAL_LOGON}
  NCRYPT_KEY_PROTECTION_LOCAL_USER         = 'user';
  {$EXTERNALSYM NCRYPT_KEY_PROTECTION_LOCAL_USER}
  NCRYPT_KEY_PROTECTION_LOCAL_MACHINE      = 'machine';
  {$EXTERNALSYM NCRYPT_KEY_PROTECTION_LOCAL_MACHINE}
//
// Cases for LOCAL protector
//
// Local=logon        : protects to the current logon session,
//                    - user will not be able to unprotect after logoff or reboot;
// Local=user         : protects to the user on local machine,
//                    - only this caller on the local machine will be able to unprotect;
// Local=machine      : protects to Local Machine,
//                    - all users on the local machine will be able to unprotect;
//

const
  NCRYPT_KEY_PROTECTION_ALGORITHM_SDDL           = 'SDDL';
  {$EXTERNALSYM NCRYPT_KEY_PROTECTION_ALGORITHM_SDDL}
//
// SDDL=%SecurityDescriptor%
//
// %SecurityDescriptor% is a SDDL string that identifies the Security Descriptor
//


(****************************************************************************
//
// Windows Client Key Protection Provider
//
//  Available only on Windows Client SKU
//
****************************************************************************)
const
  WINDOWS_CLIENT_KEY_PROTECTION_PROVIDER     = 'Windows Client Key Protection Provider';
  {$EXTERNALSYM WINDOWS_CLIENT_KEY_PROTECTION_PROVIDER}


  NCRYPT_KEY_PROTECTION_ALGORITHM_WEBCREDENTIALS = 'WEBCREDENTIALS';
  {$EXTERNALSYM NCRYPT_KEY_PROTECTION_ALGORITHM_WEBCREDENTIALS}
//
// WEBCREDENTIALS=%Identity%[,%Source%]
//
// Credential Vault stores web passwords by Source:Identity name
// If %Source% is not specified, then the default value will be used
//

//
// NCRYPT_DESCRIPTOR_HANDLE
//
type
  NCRYPT_DESCRIPTOR_HANDLE = Pointer;
  {$EXTERNALSYM NCRYPT_DESCRIPTOR_HANDLE}


(****************************************************************************
 NCryptRegisterProtectionDescriptorName

    Creates a persistent association between the specified descriptor name
    and the descriptor string value.
    The descriptor name can then be used in calls to NCryptProtectSecret
    with NCRYPT_NAMED_DESCRIPTOR_FLAG flag.

    Named Descriptors are recommended for applications and systems,
    where an administrator or Group Policy should be able to configure
    the protection descriptor.

 pwszName
    [in] Specifies a Unicode string of named descriptor to be registered.

 pwszDescriptorString
    [in, optional] Specifies a Unicode string of Protection Descriptor.
    When this parameter is NULL or an empty string, the name
    will be unregistered.

 dwFlags
    The following flags are supported.
        NCRYPT_MACHINE_KEY_FLAG

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE


****************************************************************************)
function NCryptRegisterProtectionDescriptorName(
  pwszName: LPCWSTR;
  pwszDescriptorString: LPCWSTR;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptRegisterProtectionDescriptorName}

(****************************************************************************
 NCryptQueryProtectionDescriptorName

 pwszName
    [in] Specifies a Unicode string of named descriptor to be registered.

 pwszDescriptorString
    [out] Specifies a buffer that receive a Unicode string of Protection Descriptor.

 pcDescriptorString
    [in, out] Specifies size, in characters, of buffer that receive a
    Unicode string of Protection Descriptor, including terminating '\0'.

 dwFlags
    The following flags are supported.
        NCRYPT_MACHINE_KEY_FLAG

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE


****************************************************************************)
function NCryptQueryProtectionDescriptorName(
  pwszName: LPCWSTR;
  pwszDescriptorString: LPWSTR;
  var pcDescriptorString: SIZE_T;
  dwFlags: DWORD): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptQueryProtectionDescriptorName}

(****************************************************************************
 NCryptCreateProtectionDescriptor

 dwFlags
    The following flags are supported.

        NCRYPT_NAMED_DESCRIPTOR_FLAG
        NCRYPT_MACHINE_KEY_FLAG

 pwszDescriptorString
    [in] Specifies a Unicode string of Protection Descriptor.

 phDescriptor
    [out] Pointer to Handle of Protection Descriptor.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE

****************************************************************************)
function NCryptCreateProtectionDescriptor(
  pwszDescriptorString: LPCWSTR;
  dwFlags: DWORD;
  out phDescriptor: NCRYPT_DESCRIPTOR_HANDLE): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptCreateProtectionDescriptor}

//
// The NCRYPT_NAMED_DESCRIPTOR_FLAG flag indicates that pwszDescriptorString
// value is a name registered by NCryptRegisterProtectionDescriptorName()
//
const
  NCRYPT_NAMED_DESCRIPTOR_FLAG                   = $00000001;
  {$EXTERNALSYM NCRYPT_NAMED_DESCRIPTOR_FLAG}

(****************************************************************************
 NCryptCloseProtectionDescriptor

 hDescriptor
    [in] Handle of Protection Descriptor created by
    NCryptCreateProtectionDescriptor function

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_HANDLE

****************************************************************************)
function NCryptCloseProtectionDescriptor(
  hDescriptor: NCRYPT_DESCRIPTOR_HANDLE): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptCloseProtectionDescriptor}

(****************************************************************************
 NCryptGetProtectionDescriptorInfo

    Retrieves Protection Descriptor information from the descriptor handle.

 hDescriptor
    [in] Handle of Protection Descriptor created by
    NCryptCreateProtectionDescriptor or NCryptUnprotectSecret functions.
    See Remarks section for more information.

 pMemPara
    [in, optional] Pointer to NCRYPT_ALLOC_PARA that specifies memory management
    functions. If this parameter is NULL, then LocalAlloc() function is used
    to allocate memory, and the caller must use LocalFree() free to release
    memory pointed by *ppvInfo.

 dwInfoType
    [in] Indicates the parameter types of data to be retrieved.
    The type of data to be retrieved determines the type of structure to use for *ppvInfo.

 ppvInfo
    [out] A pointer to a buffer that receives the data retrieved.
    The form of this data will vary depending on the value of the dwInfoType parameter.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE

  Remarks:
    Applications can retrieve information about Protection Descriptor used
    to protect data from a protected blob by calling NCryptUnprotectSecret
    function with NCRYPT_UNPROTECT_NO_DECRYPT.
    When this flag is set, then only blob header will be decoded and
    no actual decryption will occur.

****************************************************************************)

//
//  wInfoType                                      Value       *ppvInfo
//  ---------------------------------------------  ----------- ----------------------------------
//
const
  NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING  = $00000001;  // LPWSTR
  {$EXTERNALSYM NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING}

function NCryptGetProtectionDescriptorInfo(
  hDescriptor: NCRYPT_DESCRIPTOR_HANDLE;
  pMemPara: PNCryptAllocPara;
  dwInfoType: DWORD;
  out ppvInfo: Pointer): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptGetProtectionDescriptorInfo}

(****************************************************************************
 NCryptProtectSecret

  Performs cryptographic protection on the secret or key material.
  For large data protection, applications should use NCryptProtectMessage function.

 hDescriptor
    [in] Handle of Protection Descriptor.

 dwFlags
    The following flags are supported.
    NCRYPT_SILENT_FLAG

 pbData
    [in] A pointer to an array of bytes to be protected.

 cbData
    [in] Specifies count of bytes in pbData.

 pMemPara
    [in, optional] Pointer to NCRYPT_ALLOC_PARA that specifies memory management
    functions. If this parameter is NULL, then LocalAlloc() function is used
    to allocate memory, and the caller must use LocalFree() free to release
    memory pointed by *ppbProtectedBlob.

 hWnd
    [in, optional] A window handle (HWND) to be used as the parent of any user
    interface that is displayed.

 ppbProtectedBlob
    [out, deref] Receives a pointer to an allocated Protected Blob.
    The caller must free the memory using NCRYPT_ALLOC_PARA.

 pcbProtectedBlob
    [out] Receives a count of bytes in ppbProtectedBlob.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE

****************************************************************************)
function NCryptProtectSecret(
  hDescriptor: NCRYPT_DESCRIPTOR_HANDLE;
  dwFlags: DWORD;
  pbData: PByte;
  cbData: ULONG;
  pMemPara: PNCryptAllocPara;
  hWnd: HWND;
  out ppbProtectedBlob: PByte;
  out pcbProtectedBlob: ULONG): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptProtectSecret}

(****************************************************************************
 NCryptUnprotectSecret

 phDescriptor
    [out, optional] Pointer to Handle of Protection Descriptor.

 pbProtectedBlob
    [in] A pointer to an array of bytes that holds the encrypted data

 cbProtectedBlob
    [in] Specifies count of bytes in pbProtectedBlob.

 dwFlags
    The following flags are supported.

    NCRYPT_UNPROTECT_NO_DECRYPT
    NCRYPT_SILENT_FLAG

    See Remarks section for more info.

 pMemPara
    [in, optional] Pointer to NCRYPT_ALLOC_PARA that specifies memory management
    functions. If this parameter is NULL, then LocalAlloc() function is used
    to allocate memory, and the caller must use LocalFree() free to release
    memory pointed by *ppbData.

 hWnd
    [in, optional] A window handle (HWND) to be used as the parent of any user
    interface that is displayed.

 ppbData
    [out, deref] Receives a pointer to an allocated buffer with decrypted data.
    The caller must free the memory using NCRYPT_ALLOC_PARA.

 pcbData
    [out] Receives a count of bytes in ppbData.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE
    NTE_DECRYPTION_FAILURE

  Remarks:
    Applications can retrieve information about Protection Descriptor used
    to protect data from a protected blob by calling NCryptUnprotectSecret
    function with NCRYPT_UNPROTECT_NO_DECRYPT.
    When this flag is set, then only blob header will be decoded and
    no actual decryption will occur.

****************************************************************************)
function NCryptUnprotectSecret(
  out phDescriptor: NCRYPT_DESCRIPTOR_HANDLE;
  dwFlags: DWORD;
  pbProtectedBlob: PByte;
  cbProtectedBlob: ULONG;
  pMemPara: PNCryptAllocPara;
  hWnd: HWND;
  out ppbData: PByte;
  out pcbData: ULONG): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptUnprotectSecret}

const
  NCRYPT_UNPROTECT_NO_DECRYPT                    = $00000001;
  {$EXTERNALSYM NCRYPT_UNPROTECT_NO_DECRYPT}

(*--------------------------------------------------------------------------
//
//                               STREAM API
//
---------------------------------------------------------------------------*)
type
  NCRYPT_STREAM_HANDLE = Pointer;
  {$EXTERNALSYM NCRYPT_STREAM_HANDLE}


(****************************************************************************
  PFNCryptStreamOutputCallback

    pvCallbackCtxt
        The arguments specified by NCRYPT_PROTECT_STREAM_INFO.

    pbData
        A pointer to a block of processed data that is available to the application.

    cbData
        The size, in bytes, of the block of processed data at pbData.

    fFinal
        Specifies that the last block of data is being processed and that this
        is the last time the callback will be executed.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE

****************************************************************************)
type
  PFNCryptStreamOutputCallback = function(
    pvCallbackCtxt: Pointer;
    pbData: PByte;
    cbData: SIZE_T;
    fFinal: BOOL): SECURITY_STATUS; winapi;
  {$EXTERNALSYM PFNCryptStreamOutputCallback}
  TFnCryptStreamOutputCallback = PFNCryptStreamOutputCallback;

(****************************************************************************
 NCRYPT_PROTECT_STREAM_INFO

    The NCRYPT_PROTECT_STREAM_INFO structure is used to enable stream processing
    of data rather than single block processing.
    This structure is passed to the NCryptStreamOpenToProtect and
    NCryptStreamOpenToUnprotect functions.

    pfnStreamOutput
        [in] The address of a callback function used to read from and write
        data to a disk when processing large messages.

    pvCallbackCtxt
        [in] A pointer to the argument to pass to the callback function.

****************************************************************************)
type
  PNCryptProtectStreamInfo = ^TNCryptProtectStreamInfo;
  NCRYPT_PROTECT_STREAM_INFO = record
    pfnStreamOutput: TFnCryptStreamOutputCallback;
    pvCallbackCtxt: Pointer;
  end;
  {$EXTERNALSYM NCRYPT_PROTECT_STREAM_INFO}
  TNCryptProtectStreamInfo = NCRYPT_PROTECT_STREAM_INFO;

(****************************************************************************
 NCryptStreamOpenToProtect

    Performs cryptographic protection on large data in stream mode.

 hDescriptor
    [in] Handle of Protection Descriptor.

 dwFlags
    The following flags are supported.
    NCRYPT_SILENT_FLAG

 hWnd
    [in, optional] A window handle (HWND) to be used as the parent of any user
    interface that is displayed.

 pStreamInfo
    [in] A pointer to NCRYPT_PROTECT_STREAM_INFO.

 phStream
    [out] Receives a pointer to a stream handle.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE

****************************************************************************)
function NCryptStreamOpenToProtect(
  hDescriptor: NCRYPT_DESCRIPTOR_HANDLE;
  dwFlags: DWORD;
  hWnd: HWND;
  const pStreamInfo: TNCryptProtectStreamInfo;
  out phStream: NCRYPT_STREAM_HANDLE): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptStreamOpenToProtect}

(****************************************************************************
 NCryptStreamOpenToUnprotect

 pStreamInfo
    [in] A pointer to NCRYPT_PROTECT_STREAM_INFO.

 dwFlags
    The following flags are supported.
    NCRYPT_SILENT_FLAG

 hWnd
    [in, optional] A window handle (HWND) to be used as the parent of any user
    interface that is displayed.

 phStream
    [out] Receives a pointer to a stream handle.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE
    NTE_DECRYPTION_FAILURE

****************************************************************************)
function NCryptStreamOpenToUnprotect(
  const pStreamInfo: TNCryptProtectStreamInfo;
  dwFlags: DWORD;
  hWnd: HWND;
  out phStream: NCRYPT_STREAM_HANDLE): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptStreamOpenToUnprotect}

(****************************************************************************
 NCryptStreamUpdate

 The NCryptStreamUpdate encrypts or decrypts a chunk of data.

 hStream
    [in] Handle returned by NCryptStreamOpenToProtect or
    NCryptStreamOpenToUnprotect function.

 pbData
    [in] A pointer to an array of bytes to be protected.

 cbData
    [in] Specifies count of bytes in pbData.

 fFinal
    [in] Indicates that the last block of data for protecting or unprotecting
    is being processed.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_BAD_FLAGS
    NTE_BAD_DATA
    NTE_NO_MEMORY
    NTE_NOT_FOUND
    NTE_NOT_SUPPORTED
    NTE_INVALID_HANDLE
    NTE_BAD_KEY
    NTE_BAD_PROVIDER
    NTE_BAD_TYPE
    NTE_DECRYPTION_FAILURE

****************************************************************************)
function NCryptStreamUpdate(
  hStream: NCRYPT_STREAM_HANDLE;
  pbData: PByte;
  cbData: SIZE_T;
  fFinal: BOOL): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptStreamUpdate}

(****************************************************************************
 NCryptStreamClose

 hStream
    [in] Handle returned by NCryptStreamOpenToProtect or
    NCryptStreamOpenToUnprotect function.

 Return Value
    Returns a status code that indicates the success or failure of the function.
    Possible return codes include, but are not limited to, the following.

    ERROR_SUCCESS
    NTE_INVALID_PARAMETER
    NTE_INVALID_HANDLE

****************************************************************************)
function NCryptStreamClose(
  hStream: NCRYPT_STREAM_HANDLE): SECURITY_STATUS; winapi;
{$EXTERNALSYM NCryptStreamClose}

{$ENDREGION}

implementation

const
  NCryptDll = 'ncrypt.dll';

{$REGION 'ncryptprotect.h'}
function NCryptRegisterProtectionDescriptorName; external NCryptDll name 'NCryptRegisterProtectionDescriptorName' delayed;
function NCryptQueryProtectionDescriptorName; external NCryptDll name 'NCryptQueryProtectionDescriptorName' delayed;
function NCryptCreateProtectionDescriptor; external NCryptDll name 'NCryptCreateProtectionDescriptor' delayed;
function NCryptCloseProtectionDescriptor; external NCryptDll name 'NCryptCloseProtectionDescriptor' delayed;
function NCryptGetProtectionDescriptorInfo; external NCryptDll name 'NCryptGetProtectionDescriptorInfo' delayed;
function NCryptProtectSecret; external NCryptDll name 'NCryptProtectSecret' delayed;
function NCryptUnprotectSecret; external NCryptDll name 'NCryptUnprotectSecret' delayed;
function NCryptStreamOpenToProtect; external NCryptDll name 'NCryptStreamOpenToProtect' delayed;
function NCryptStreamOpenToUnprotect; external NCryptDll name 'NCryptStreamOpenToUnprotect' delayed;
function NCryptStreamUpdate; external NCryptDll name 'NCryptStreamUpdate' delayed;
function NCryptStreamClose; external NCryptDll name 'NCryptStreamClose' delayed;
{$ENDREGION}

end.

