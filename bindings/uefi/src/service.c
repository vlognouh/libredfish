/** @file

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
//----------------------------------------------------------------------------
// Copyright Notice:
// Copyright 2017 Distributed Management Task Force, Inc. All rights reserved.
// License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libredfish/LICENSE.md
//----------------------------------------------------------------------------
#include <redfishService.h>
#include <redfishPayload.h>
#include "../../../include/redpath.h"

static int initRest(redfishService* service, void * restProtocol);
static redfishService* createServiceEnumeratorNoAuth(const char* host, const char* rootUri, bool enumerate, unsigned int flags, void * restProtocol);
static redfishService* createServiceEnumeratorBasicAuth(const char* host, const char* rootUri, const char* username, const char* password, unsigned int flags, void * restProtocol);
static redfishService* createServiceEnumeratorSessionAuth(const char* host, const char* rootUri, const char* username, const char* password, unsigned int flags, void * restProtocol);
static char* makeUrlForService(redfishService* service, const char* uri);
static json_t* getVersions(redfishService* service, const char* rootUri);
static void addStringToJsonObject(json_t* object, const char* key, const char* value);

CHAR16*
C8ToC16 (CHAR8 *AsciiStr)
{
  CHAR16   *Str;
  UINTN   BufLen;

  BufLen = (AsciiStrLen (AsciiStr) + 1) * 2;
  Str = AllocatePool (BufLen);
  ASSERT (Str != NULL);

  AsciiStrToUnicodeStrS (AsciiStr, Str, AsciiStrLen (AsciiStr) + 1);

  return Str;
}

VOID
RestConfigFreeHttpRequestData (
  IN EFI_HTTP_REQUEST_DATA        *RequestData
  )
{
  if (RequestData == NULL) {
    return ;
  }

  if (RequestData->Url != NULL) {
    FreePool (RequestData->Url);
  }

  FreePool (RequestData);
}

VOID
RestConfigFreeHttpMessage (
  IN EFI_HTTP_MESSAGE             *Message,
  IN BOOLEAN                      IsRequest
  )
{
  if (Message == NULL) {
    return ;
  }

  if (IsRequest) {
    RestConfigFreeHttpRequestData (Message->Data.Request);
    Message->Data.Request = NULL;
  } else {
    if (Message->Data.Response != NULL) {
      FreePool (Message->Data.Response);
      Message->Data.Response = NULL;
    }
  }

  if (Message->Headers != NULL) {
    FreePool (Message->Headers);
    Message->Headers = NULL;
  }
  if (Message->Body != NULL) {
    FreePool (Message->Body);
    Message->Body = NULL;
  }
}

/**
  Configure a REST EX protocol according to the Redfish network host interface record.

  @param[in]       RestEx                A pointer to the REST EX protocol.
  @param[in]       RedfishData           Redfish network host interface record.
  @param[in]       ReceiveTimeout        HTTP response time out in uints of millisecond.

  @retval EFI_SUCCESS           The REST EX was successfully configured.
  @retval Others                Failed to configure the REST EX protocol.

**/
EFI_STATUS
RedfishConfigRestEx (
  IN EFI_REST_EX_PROTOCOL            *RestEx,
  IN REDFISH_OVER_IP_PROTOCOL_DATA   *RedfishData,
  IN UINT32                          ReceiveTimeout
  )
{
  EFI_STATUS                        Status;
  EFI_REST_EX_HTTP_CONFIG_DATA      *RestExHttpConfigData;

  if (RestEx == NULL || RedfishData == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  RestExHttpConfigData = AllocateZeroPool (sizeof (EFI_REST_EX_HTTP_CONFIG_DATA));
  if (RestExHttpConfigData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  RestExHttpConfigData->SendReceiveTimeout = ReceiveTimeout;

  RestExHttpConfigData->HttpConfigData.HttpVersion = HttpVersion11;
  RestExHttpConfigData->HttpConfigData.LocalAddressIsIPv6 = (RedfishData->HostIpAddressFormat == REDFISH_HOST_INTERFACE_HOST_IP_ADDRESS_FORMAT_IP6) ? TRUE: FALSE;

  if (RestExHttpConfigData->HttpConfigData.LocalAddressIsIPv6) {
    RestExHttpConfigData->HttpConfigData.AccessPoint.IPv6Node = AllocateZeroPool (sizeof (EFI_HTTPv6_ACCESS_POINT));
    if (RestExHttpConfigData->HttpConfigData.AccessPoint.IPv6Node == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto ON_EXIT;
    }

    IP6_COPY_ADDRESS (&RestExHttpConfigData->HttpConfigData.AccessPoint.IPv6Node->LocalAddress, RedfishData->HostIpAddress);
  } else {
    RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node = AllocateZeroPool (sizeof (EFI_HTTPv4_ACCESS_POINT));
    if (RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto ON_EXIT;
    }
    if (RedfishData->HostIpAssignmentType == 1) {
      RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node->UseDefaultAddress = FALSE;
      IP4_COPY_ADDRESS (&RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node->LocalAddress, RedfishData->HostIpAddress);
      IP4_COPY_ADDRESS (&RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node->LocalSubnet, RedfishData->HostIpMask);
    } else if (RedfishData->HostIpAssignmentType == 3) {
      RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node->UseDefaultAddress = TRUE;
    } else {
      Status = EFI_UNSUPPORTED;
      goto ON_EXIT;
    }
  }

  Status = RestEx->Configure (
                     RestEx,
                     (EFI_REST_EX_CONFIG_DATA)(UINT8 *)RestExHttpConfigData
                     );
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

ON_EXIT:

  if (RestExHttpConfigData != NULL) {
    if (RestExHttpConfigData->HttpConfigData.LocalAddressIsIPv6 && RestExHttpConfigData->HttpConfigData.AccessPoint.IPv6Node != NULL) {
      FreePool (RestExHttpConfigData->HttpConfigData.AccessPoint.IPv6Node);
    }

    if (!RestExHttpConfigData->HttpConfigData.LocalAddressIsIPv6 && RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node != NULL) {
      FreePool (RestExHttpConfigData->HttpConfigData.AccessPoint.IPv4Node);
    }

    FreePool (RestExHttpConfigData);
  }

  return Status;
}

/**
  Destroy a child of the REST EX service.

  @param[in]   Image                 The image handle used to open service.
  @param[in]   Controller            The controller which has the service installed.
  @param[in]   ChildHandle           The child to destroy.
  @param[in]   RestEx                The REST EX protocol on the child.

  @retval EFI_SUCCESS           The child was destroyed.
  @retval Others                Failed to destroy the child.

**/
EFI_STATUS
RedfishDestroyRestExChild (
  IN EFI_HANDLE              Image,
  IN EFI_HANDLE              Controller,
  IN EFI_HANDLE              ChildHandle,
  IN EFI_REST_EX_PROTOCOL    *RestEx
  )
{
  EFI_STATUS                        Status;

  Status = EFI_SUCCESS;

  if (RestEx != NULL) {
    gBS->CloseProtocol (
           ChildHandle,
           &gEfiRestExProtocolGuid,
           Image,
           Controller
           );
  }

  if (ChildHandle != NULL) {
    NetLibDestroyServiceChild (
      Controller,
      Image,
      &gEfiRestExServiceBindingProtocolGuid,
      ChildHandle
      );
  }

  return Status;
}

/**
  Create a child of the REST EX service.

  This is a helper function to implement driver binding and service binding protocols.
  This function will also check if the REST EX protocol instance is a preferred one.

  If ChildHandle is NULL, then ASSERT().
  If RestEx is NULL, then ASSERT().

  @param[in]       Image                 The image handle used to open service.
  @param[in]       Controller            The controller which has the REST EX service installed.
  @param[in, out]  ChildHandle           The handle to receive the created child.
  @param[out]      RestEx                The REST EX protocol on the new created child.


  @retval EFI_SUCCESS           The child was successfully created.
  @retval Others                Failed to create the child.

**/
EFI_STATUS
RedfishCreateRestExChild (
  IN      EFI_HANDLE              Image,
  IN      EFI_HANDLE              Controller,
  IN OUT  EFI_HANDLE              *ChildHandle,
  OUT     EFI_REST_EX_PROTOCOL    **RestEx
  )
{
  EFI_STATUS                        Status;
  EFI_REST_EX_PROTOCOL              *RestExProtocol;

  ASSERT (ChildHandle != NULL);
  ASSERT (RestEx != NULL);

  RestExProtocol    = NULL;

  //
  // Create a underlayer child instance.
  //
  Status = NetLibCreateServiceChild (
             Controller,
             Image,
             &gEfiRestExServiceBindingProtocolGuid,
             ChildHandle
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Open ChildHandle via BY_DRIVER.
  // This is to establish the relationship between ControllerHandle and ChildHandle.
  // Therefore, when DisconnectController(), RestConfigurationDriverBindingStop() will be called.
  //
  Status = gBS->OpenProtocol (
                  *ChildHandle,
                  &gEfiRestExProtocolGuid,
                  &RestExProtocol,
                  Image,
                  Controller,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  *RestEx = RestExProtocol;

  return EFI_SUCCESS;

ON_ERROR:

  RedfishDestroyRestExChild (
    Image,
    Controller,
    *ChildHandle,
    RestExProtocol
    );

  return Status;
}

/**
  Converts the Unicode string to ASCII string to a new allocated buffer.

  @param[in]       String       Unicode string to be converted.

  @return     Buffer points to ASCII string, or NULL if error happens.

**/

CHAR8 *
UnicodeStrDupToAsciiStr (
  CONST CHAR16 *String
  )
{
  CHAR8      *AsciiStr;
  UINTN      BufLen;
  EFI_STATUS Status;

  BufLen = StrLen (String) + 1;
  AsciiStr = AllocatePool (BufLen);
  if (AsciiStr == NULL) {
    return NULL;
  }

  Status = UnicodeStrToAsciiStrS (String, AsciiStr, BufLen);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return AsciiStr;
}

/**
  Create a HTTP URL string for specific Redfish resource.

  This function build a URL string from the Redfish Host interface record and caller specified
  relative path of the resource.

  Callers are responsible for freeing the returned string storage pointed by HttpUrl.

  @param[in]   RedfishData         Redfish network host interface record.
  @param[in]   RelativePath        Relative path of a resource.
  @param[out]  HttpUrl             The pointer to store the returned URL string.

  @retval EFI_SUCCESS              Build the URL string successfully.
  @retval EFI_INVALID_PARAMETER    RedfishData or HttpUrl is NULL.
  @retval EFI_OUT_OF_RESOURCES     There are not enough memory resources.

**/
EFI_STATUS
RedfishBuildUrl (
  IN  REDFISH_OVER_IP_PROTOCOL_DATA *RedfishData,
  IN  CHAR16                        *RelativePath,   OPTIONAL
  OUT CHAR16                        **HttpUrl
  )
{
  CHAR16                            *Url;
  CHAR16                            *UrlHead;
  UINTN                             UrlLength;
  UINTN                             PathLen;
  UINT8                             Buffer[8];
  UINT8                             *Tmp;
  CHAR16                            ServiceIpStr[sizeof"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  if ((RedfishData == NULL) || (HttpUrl == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // RFC2616: http_URL = "http(s):" "//" host [ ":" port ] [ abs_path [ "?" query ]]
  //
  if (RelativePath == NULL) {
    PathLen = 0;
  } else {
    PathLen = StrLen (RelativePath);
  }
  UrlLength = StrLen (HTTPS_FLAG) + StrLen (REDFISH_FIRST_URL) + 1 + sizeof(ServiceIpStr)/sizeof(CHAR16) + PathLen;
  if (RedfishData->RedfishServiceIpPort != 0) {
    UrlLength = UrlLength + 1 + 6;
  }

  Url = AllocateZeroPool (UrlLength * sizeof (CHAR16));
  if (Url == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  UrlHead = Url;

  //
  // Copy "http://" or "https://" according RedfishServiceIpPort.
  //
  if (RedfishData->RedfishServiceIpPort != 443) {
    StrCpyS (Url, StrLen (HTTPS_FLAG) + 1, HTTP_FLAG);
    Url = Url + StrLen (HTTP_FLAG);
  } else {
    StrCpyS (Url, StrLen (HTTPS_FLAG) + 1, HTTPS_FLAG);
    Url = Url + StrLen (HTTPS_FLAG);
  }

  //
  // Copy RedfishServiceIpAddress
  //
  if (RedfishData->RedfishServiceIpAddressFormat == 0x01) {
    UnicodeSPrint (
      ServiceIpStr,
      sizeof (ServiceIpStr),
      L"%d.%d.%d.%d",
      ((EFI_IPv4_ADDRESS *) (RedfishData->RedfishServiceIpAddress))->Addr[0],
      ((EFI_IPv4_ADDRESS *) (RedfishData->RedfishServiceIpAddress))->Addr[1],
      ((EFI_IPv4_ADDRESS *) (RedfishData->RedfishServiceIpAddress))->Addr[2],
      ((EFI_IPv4_ADDRESS *) (RedfishData->RedfishServiceIpAddress))->Addr[3]
      );
  } else {
    NetLibIp6ToStr (
      (EFI_IPv6_ADDRESS *) (RedfishData->RedfishServiceIpAddress),
      ServiceIpStr,
      sizeof (ServiceIpStr)
      );
  }

  StrCpyS (Url, sizeof(ServiceIpStr)/sizeof(CHAR16), ServiceIpStr);

  Url = Url + StrLen (ServiceIpStr);

  //
  // Copy [":" port]
  //
  if (RedfishData->RedfishServiceIpPort != 0) {
    *Url = L':';
    Url++;

    ZeroMem (Buffer, sizeof (Buffer));
    NetLibUintnToAscDecWithFormat (
      RedfishData->RedfishServiceIpPort,
      Buffer,
      6
      );

    //
    // Skip '0' in port.
    //
    Tmp = Buffer;
    while (*Tmp == '0') {
      Tmp++;
    }

    AsciiStrToUnicodeStrS (Tmp, Url, UrlLength);

    while (*Url != '\0') {
      Url++;
    }
  }

  //
  // Copy abs_path
  //
  if (RelativePath != NULL && PathLen != 0 ) {
    StrnCpyS (Url, UrlLength, RelativePath, PathLen);
  }
  *HttpUrl = UrlHead;
  return EFI_SUCCESS;
}

redfishService* createServiceEnumerator(EFI_HANDLE Image, EFI_HANDLE Controller, REDFISH_OVER_IP_PROTOCOL_DATA *RedfishData, const char* rootUri, enumeratorAuthentication* auth, unsigned int flags)
{
  EFI_STATUS           Status;
  CHAR16               *HttpUrl;
  CHAR8                *AsciiHost;
  EFI_HANDLE           ChildHandle;
  EFI_REST_EX_PROTOCOL *RestEx;
  redfishService       *ret;

  HttpUrl = NULL;
  AsciiHost = NULL;
  ChildHandle = NULL;
  RestEx = NULL;
  ret = NULL;

  Status = RedfishBuildUrl (RedfishData, NULL, &HttpUrl);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  ASSERT (HttpUrl != NULL);

  AsciiHost = UnicodeStrDupToAsciiStr (HttpUrl);
  if (AsciiHost == NULL) {
    goto ON_EXIT;
  }

  Status = RedfishCreateRestExChild (Image, Controller, &ChildHandle, &RestEx);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  //
  // Configure the EFI_REST_EX_PROTOCOL.
  //
  Status = RedfishConfigRestEx (RestEx, RedfishData, REDFISH_HTTP_RESPONSE_TIMEOUT);
  if (EFI_ERROR (Status)) {
    RedfishDestroyRestExChild (Image, Controller, ChildHandle, RestEx);
    goto ON_EXIT;
  }

  if(auth == NULL)
  {
    ret = createServiceEnumeratorNoAuth(AsciiHost, rootUri, true, flags, RestEx);
  }
  else if(auth->authType == REDFISH_AUTH_BASIC)
  {
    ret = createServiceEnumeratorBasicAuth(AsciiHost, rootUri, auth->authCodes.userPass.username, auth->authCodes.userPass.password, flags, RestEx);
  }
  else if(auth->authType == REDFISH_AUTH_SESSION)
  {
    ret = createServiceEnumeratorSessionAuth(AsciiHost, rootUri, auth->authCodes.userPass.username, auth->authCodes.userPass.password, flags, RestEx);
  }
  else
  {
    RedfishDestroyRestExChild (Image, Controller, ChildHandle, RestEx);
    goto ON_EXIT;
  }

  ret->Image = Image;
  ret->Controller = Controller;
  ret->ChildHandle = ChildHandle;

ON_EXIT:
  if (HttpUrl != NULL) {
    FreePool (HttpUrl);
  }

  if (AsciiHost != NULL) {
    FreePool (AsciiHost);
  }

  return ret;
}

json_t* getUriFromService(redfishService* service, const char* uri, EFI_HTTP_STATUS_CODE** StatusCode)
{
  char* url;
  json_t* ret;
  HTTP_IO_HEADER                    *HttpIoHeader = NULL;
  EFI_STATUS                        Status;
  EFI_HTTP_REQUEST_DATA             *RequestData = NULL;
  EFI_HTTP_MESSAGE                  *RequestMsg = NULL;
  EFI_HTTP_MESSAGE                  ResponseMsg;

  if(service == NULL || uri == NULL || StatusCode == NULL)
  {
      return NULL;
  }

  *StatusCode = NULL;

  url = makeUrlForService(service, uri);
  if(!url)
  {
      return NULL;
  }

  DEBUG((EFI_D_INFO, "libredfish: getUriFromService(): %a\n", url));

  //
  // Step 1: Create HTTP request message with 4 headers:
  //
  HttpIoHeader = HttpIoCreateHeader ((service->sessionToken || service->basicAuthStr) ? 5 : 4);
  if (HttpIoHeader == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  if(service->sessionToken)
  {
    Status = HttpIoSetHeader (HttpIoHeader, "X-Auth-Token", service->sessionToken);
    ASSERT_EFI_ERROR (Status);
  } else if (service->basicAuthStr) {
    Status = HttpIoSetHeader (HttpIoHeader, "Authorization", service->basicAuthStr);
    ASSERT_EFI_ERROR (Status);
  }

  Status = HttpIoSetHeader (HttpIoHeader, "Host", service->HostHeaderValue);
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "OData-Version", "4.0");
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "Accept", "application/json");
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "User-Agent", "libredfish");
  ASSERT_EFI_ERROR (Status);

  //
  // Step 2: build the rest of HTTP request info.
  //
  RequestData = AllocateZeroPool (sizeof (EFI_HTTP_REQUEST_DATA));
  if (RequestData == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  RequestData->Method = HttpMethodGet;
  RequestData->Url = C8ToC16 (url);

  //
  // Step 3: fill in EFI_HTTP_MESSAGE
  //
  RequestMsg = AllocateZeroPool (sizeof (EFI_HTTP_MESSAGE));
  if (RequestMsg == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  RequestMsg->Data.Request = RequestData;
  RequestMsg->HeaderCount  = HttpIoHeader->HeaderCount;
  RequestMsg->Headers      = HttpIoHeader->Headers;

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  //
  // Step 4: call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    ret = NULL;
    goto ON_EXIT;
  }

  //
  // Step 5: Return the HTTP StatusCode and Body message.
  //
  if (ResponseMsg.Data.Response != NULL) {
    *StatusCode = AllocateZeroPool (sizeof (EFI_HTTP_STATUS_CODE));
    if (*StatusCode == NULL) {
      ret = NULL;
      goto ON_EXIT;
    }

    //
    // The caller shall take the responsibility to free the buffer.
    //
    **StatusCode = ResponseMsg.Data.Response->StatusCode;
  }

  if (ResponseMsg.BodyLength != 0 && ResponseMsg.Body != NULL) {
    ret = json_loadb (ResponseMsg.Body, ResponseMsg.BodyLength, 0, NULL);
  } else {
    //
    // There is no message body returned from server.
    //
    ret = NULL;
  }

ON_EXIT:
  if (url != NULL) {
    free (url);
  }

  if (HttpIoHeader != NULL) {
    HttpIoFreeHeader (HttpIoHeader);
  }

  if (RequestData != NULL) {
    RestConfigFreeHttpRequestData (RequestData);
  }

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t* patchUriFromService(redfishService* service, const char* uri, const char* content, EFI_HTTP_STATUS_CODE** StatusCode)
{
  char*               url;
  json_t*             ret;
  HTTP_IO_HEADER                    *HttpIoHeader = NULL;
  EFI_STATUS                        Status;
  EFI_HTTP_REQUEST_DATA             *RequestData = NULL;
  EFI_HTTP_MESSAGE                  *RequestMsg = NULL;
  EFI_HTTP_MESSAGE                  ResponseMsg;
  CHAR8                             ContentLengthStr[80];

  if(service == NULL || uri == NULL || content == NULL || StatusCode == NULL)
  {
      return NULL;
  }

  *StatusCode = NULL;

  url = makeUrlForService(service, uri);
  if(!url)
  {
      return NULL;
  }

  DEBUG((EFI_D_INFO, "libredfish: patchUriFromService(): %a\n", url));

  //
  // Step 1: Create HTTP request message with 4 headers:
  //
  HttpIoHeader = HttpIoCreateHeader ((service->sessionToken || service->basicAuthStr) ? 7 : 6);
  if (HttpIoHeader == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  if(service->sessionToken)
  {
    Status = HttpIoSetHeader (HttpIoHeader, "X-Auth-Token", service->sessionToken);
    ASSERT_EFI_ERROR (Status);
  } else if (service->basicAuthStr) {
    Status = HttpIoSetHeader (HttpIoHeader, "Authorization", service->basicAuthStr);
    ASSERT_EFI_ERROR (Status);
  }

  Status = HttpIoSetHeader (HttpIoHeader, "Host", service->HostHeaderValue);
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "Content-Type", "application/json");
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "Accept", "application/json");
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "User-Agent", "libredfish");
  ASSERT_EFI_ERROR (Status);
  AsciiSPrint(
    ContentLengthStr,
    sizeof (ContentLengthStr),
    "%lu",
    (UINT64) strlen(content)
    );
  Status = HttpIoSetHeader (HttpIoHeader, "Content-Length", ContentLengthStr);
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "OData-Version", "4.0");
  ASSERT_EFI_ERROR (Status);

  //
  // Step 2: build the rest of HTTP request info.
  //
  RequestData = AllocateZeroPool (sizeof (EFI_HTTP_REQUEST_DATA));
  if (RequestData == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  RequestData->Method = HttpMethodPatch;
  RequestData->Url = C8ToC16 (url);

  //
  // Step 3: fill in EFI_HTTP_MESSAGE
  //
  RequestMsg = AllocateZeroPool (sizeof (EFI_HTTP_MESSAGE));
  if (RequestMsg == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  RequestMsg->Data.Request = RequestData;
  RequestMsg->HeaderCount  = HttpIoHeader->HeaderCount;
  RequestMsg->Headers      = HttpIoHeader->Headers;
  RequestMsg->BodyLength   = strlen(content);
  RequestMsg->Body         = (VOID*) content;

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  //
  // Step 4: call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    ret = NULL;
    goto ON_EXIT;
  }

  //
  // Step 5: Return the HTTP StatusCode and Body message.
  //
  if (ResponseMsg.Data.Response != NULL) {
    *StatusCode = AllocateZeroPool (sizeof (EFI_HTTP_STATUS_CODE));
    if (*StatusCode == NULL) {
      ret = NULL;
      goto ON_EXIT;
    }

    //
    // The caller shall take the responsibility to free the buffer.
    //
    **StatusCode = ResponseMsg.Data.Response->StatusCode;
  }


  if (ResponseMsg.BodyLength != 0 && ResponseMsg.Body != NULL) {
    ret = json_loadb (ResponseMsg.Body, ResponseMsg.BodyLength, 0, NULL);
  } else {
    //
    // There is no message body returned from server.
    //
    ret = NULL;
  }

ON_EXIT:
  if (url != NULL) {
    free (url);
  }

  if (HttpIoHeader != NULL) {
    HttpIoFreeHeader (HttpIoHeader);
  }

  if (RequestData != NULL) {
    RestConfigFreeHttpRequestData (RequestData);
  }

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t* postUriFromService(redfishService* service, const char* uri, const char* content, size_t contentLength, const char* contentType, EFI_HTTP_STATUS_CODE** StatusCode)
{
  char*               url = NULL;
  json_t*             ret;
  HTTP_IO_HEADER                    *HttpIoHeader = NULL;
  EFI_STATUS                        Status;
  EFI_HTTP_REQUEST_DATA             *RequestData = NULL;
  EFI_HTTP_MESSAGE                  *RequestMsg = NULL;
  EFI_HTTP_MESSAGE                  ResponseMsg;
  CHAR8                             ContentLengthStr[80];
  EFI_HTTP_HEADER                   *HttpHeader = NULL;

  ret = NULL;

  if(service == NULL || uri == NULL || content == NULL || StatusCode == NULL)
  {
      return NULL;
  }

  *StatusCode = NULL;

  url = makeUrlForService(service, uri);
  if(!url)
  {
      return NULL;
  }

  DEBUG((EFI_D_INFO, "libredfish: postUriFromService(): %a\n", url));

  if(contentLength == 0)
  {
      contentLength = strlen(content);
  }

  //
  // Step 1: Create HTTP request message with 4 headers:
  //
  HttpIoHeader = HttpIoCreateHeader ((service->sessionToken || service->basicAuthStr) ? 7 : 6);
  if (HttpIoHeader == NULL) {
    goto ON_EXIT;
  }

  if(service->sessionToken)
  {
    Status = HttpIoSetHeader (HttpIoHeader, "X-Auth-Token", service->sessionToken);
    ASSERT_EFI_ERROR (Status);
  } else if (service->basicAuthStr) {
    Status = HttpIoSetHeader (HttpIoHeader, "Authorization", service->basicAuthStr);
    ASSERT_EFI_ERROR (Status);
  }

  if(contentType == NULL) {
    Status = HttpIoSetHeader (HttpIoHeader, "Content-Type", "application/json");
    ASSERT_EFI_ERROR (Status);
  } else {
    Status = HttpIoSetHeader (HttpIoHeader, "Content-Type", (CHAR8 *) contentType);
    ASSERT_EFI_ERROR (Status);
  }
  Status = HttpIoSetHeader (HttpIoHeader, "Host", service->HostHeaderValue);
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "Accept", "application/json");
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "User-Agent", "libredfish");
  ASSERT_EFI_ERROR (Status);
  AsciiSPrint(
    ContentLengthStr,
    sizeof (ContentLengthStr),
    "%lu",
    (UINT64) contentLength
    );
  Status = HttpIoSetHeader (HttpIoHeader, "Content-Length", ContentLengthStr);
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "OData-Version", "4.0");
  ASSERT_EFI_ERROR (Status);

  //
  // Step 2: build the rest of HTTP request info.
  //
  RequestData = AllocateZeroPool (sizeof (EFI_HTTP_REQUEST_DATA));
  if (RequestData == NULL) {
    goto ON_EXIT;
  }

  RequestData->Method = HttpMethodPost;
  RequestData->Url = C8ToC16 (url);

  //
  // Step 3: fill in EFI_HTTP_MESSAGE
  //
  RequestMsg = AllocateZeroPool (sizeof (EFI_HTTP_MESSAGE));
  if (RequestMsg == NULL) {
    goto ON_EXIT;
  }

  RequestMsg->Data.Request = RequestData;
  RequestMsg->HeaderCount  = HttpIoHeader->HeaderCount;
  RequestMsg->Headers      = HttpIoHeader->Headers;
  RequestMsg->BodyLength   = contentLength;
  RequestMsg->Body         = (VOID*) content;

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  //
  // Step 4: call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  //
  // Step 5: Return the HTTP StatusCode and Body message.
  //
  if (ResponseMsg.Data.Response != NULL) {
    *StatusCode = AllocateZeroPool (sizeof (EFI_HTTP_STATUS_CODE));
    if (*StatusCode == NULL) {
      goto ON_EXIT;
    }

    //
    // The caller shall take the responsibility to free the buffer.
    //
    **StatusCode = ResponseMsg.Data.Response->StatusCode;
  }

  if (ResponseMsg.BodyLength != 0 && ResponseMsg.Body != NULL) {
    ret = json_loadb (ResponseMsg.Body, ResponseMsg.BodyLength, 0, NULL);
  }

  //
  // Step 6: Parsing the HttpHeader to retrive the X-Auth-Token if the HTTP StatusCode is correct.
  //
  if (ResponseMsg.Data.Response->StatusCode == HTTP_STATUS_200_OK ||
      ResponseMsg.Data.Response->StatusCode == HTTP_STATUS_204_NO_CONTENT) {
    HttpHeader = HttpFindHeader (ResponseMsg.HeaderCount, ResponseMsg.Headers, "X-Auth-Token");
    if (HttpHeader != NULL) {
      if(service->sessionToken)
      {
          free(service->sessionToken);
      }
      service->sessionToken = AllocateCopyPool (AsciiStrSize (HttpHeader->FieldValue), HttpHeader->FieldValue);
    }

    /*
    //
    // Below opeation seems to be unnecessary.
    // Besides, the FieldValue for the Location is the full HTTP URI (Http://0.0.0.0:5000/XXX), so we can't use it as the
    // parameter of getUriFromService () directly.
    //
    HttpHeader = HttpFindHeader (ResponseMsg.HeaderCount, ResponseMsg.Headers, "Location");
    if (HttpHeader != NULL) {
      ret = getUriFromService(service, HttpHeader->FieldValue);
      goto ON_EXIT;
    }
    */
  }

ON_EXIT:
  if (url != NULL) {
    free (url);
  }

  if (HttpIoHeader != NULL) {
    HttpIoFreeHeader (HttpIoHeader);
  }

  if (RequestData != NULL) {
    RestConfigFreeHttpRequestData (RequestData);
  }

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

json_t* deleteUriFromService(redfishService* service, const char* uri, EFI_HTTP_STATUS_CODE** StatusCode)
{
  char*               url;
  json_t*             ret;
  HTTP_IO_HEADER                    *HttpIoHeader = NULL;
  EFI_STATUS                        Status;
  EFI_HTTP_REQUEST_DATA             *RequestData = NULL;
  EFI_HTTP_MESSAGE                  *RequestMsg = NULL;
  EFI_HTTP_MESSAGE                  ResponseMsg;

  ret = NULL;

  if(service == NULL || uri == NULL || StatusCode == NULL)
  {
      return NULL;
  }

  *StatusCode = NULL;

  url = makeUrlForService(service, uri);
  if(!url)
  {
      return NULL;
  }

  DEBUG((EFI_D_INFO, "libredfish: deleteUriFromService(): %a\n", url));

  //
  // Step 1: Create HTTP request message with 4 headers:
  //
  HttpIoHeader = HttpIoCreateHeader ((service->sessionToken || service->basicAuthStr) ? 4 : 3);
  if (HttpIoHeader == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  if(service->sessionToken)
  {
    Status = HttpIoSetHeader (HttpIoHeader, "X-Auth-Token", service->sessionToken);
    ASSERT_EFI_ERROR (Status);
  } else if (service->basicAuthStr) {
    Status = HttpIoSetHeader (HttpIoHeader, "Authorization", service->basicAuthStr);
    ASSERT_EFI_ERROR (Status);
  }
  Status = HttpIoSetHeader (HttpIoHeader, "Host", service->HostHeaderValue);
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "User-Agent", "libredfish");
  ASSERT_EFI_ERROR (Status);
  Status = HttpIoSetHeader (HttpIoHeader, "OData-Version", "4.0");
  ASSERT_EFI_ERROR (Status);

  //
  // Step 2: build the rest of HTTP request info.
  //
  RequestData = AllocateZeroPool (sizeof (EFI_HTTP_REQUEST_DATA));
  if (RequestData == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  RequestData->Method = HttpMethodDelete;
  RequestData->Url = C8ToC16 (url);

  //
  // Step 3: fill in EFI_HTTP_MESSAGE
  //
  RequestMsg = AllocateZeroPool (sizeof (EFI_HTTP_MESSAGE));
  if (RequestMsg == NULL) {
    ret = NULL;
    goto ON_EXIT;
  }

  RequestMsg->Data.Request = RequestData;
  RequestMsg->HeaderCount  = HttpIoHeader->HeaderCount;
  RequestMsg->Headers      = HttpIoHeader->Headers;

  ZeroMem (&ResponseMsg, sizeof (ResponseMsg));

  //
  // Step 4: call RESTEx to get response from REST service.
  //
  Status = service->RestEx->SendReceive (service->RestEx, RequestMsg, &ResponseMsg);
  if (EFI_ERROR (Status)) {
    ret = NULL;
    goto ON_EXIT;
  }

  //
  // Step 5: Return the HTTP StatusCode and Body message.
  //
  if (ResponseMsg.Data.Response != NULL) {
    *StatusCode = AllocateZeroPool (sizeof (EFI_HTTP_STATUS_CODE));
    if (*StatusCode == NULL) {
      ret = NULL;
      goto ON_EXIT;
    }

    //
    // The caller shall take the responsibility to free the buffer.
    //
    **StatusCode = ResponseMsg.Data.Response->StatusCode;
  }

  if (ResponseMsg.BodyLength != 0 && ResponseMsg.Body != NULL) {
    ret = json_loadb (ResponseMsg.Body, ResponseMsg.BodyLength, 0, NULL);
  }

ON_EXIT:
  if (url != NULL) {
    free (url);
  }

  if (HttpIoHeader != NULL) {
    HttpIoFreeHeader (HttpIoHeader);
  }

  if (RequestData != NULL) {
    RestConfigFreeHttpRequestData (RequestData);
  }

  if (RequestMsg != NULL) {
    FreePool (RequestMsg);
  }

  RestConfigFreeHttpMessage (&ResponseMsg, FALSE);

  return ret;
}

redfishPayload* getRedfishServiceRoot(redfishService* service, const char* version, EFI_HTTP_STATUS_CODE** StatusCode)
{
    json_t* value;
    json_t* versionNode;
    const char* verUrl;

    if(version == NULL)
    {
        versionNode = json_object_get(service->versions, "v1");
    }
    else
    {
        versionNode = json_object_get(service->versions, version);
    }
    if(versionNode == NULL)
    {
        return NULL;
    }
    verUrl = json_string_value(versionNode);
    if(verUrl == NULL)
    {
        return NULL;
    }
    value = getUriFromService(service, verUrl, StatusCode);
    if(value == NULL)
    {
        if((service->flags & REDFISH_FLAG_SERVICE_NO_VERSION_DOC) == 0)
        {
            json_decref(versionNode);
        }
        return NULL;
    }
    return createRedfishPayload(value, service);
}

redfishPayload* getPayloadByPath(redfishService* service, const char* path, EFI_HTTP_STATUS_CODE** StatusCode)
{
    redPathNode* redpath;
    redfishPayload* root;
    redfishPayload* ret;

    if(!service || !path || StatusCode == NULL)
    {
        return NULL;
    }

    *StatusCode = NULL;

    redpath = parseRedPath(path);
    if(!redpath)
    {
        return NULL;
    }
    if(!redpath->isRoot)
    {
        cleanupRedPath(redpath);
        return NULL;
    }
    root = getRedfishServiceRoot(service, redpath->version, StatusCode);
    if (*StatusCode == NULL || **StatusCode < HTTP_STATUS_200_OK || **StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT) {
      cleanupRedPath(redpath);
      return root;
    }

    if(redpath->next == NULL)
    {
        cleanupRedPath(redpath);
        return root;
    }

    FreePool (*StatusCode);
    *StatusCode = NULL;

    ret = getPayloadForPath(root, redpath->next, StatusCode);
    if (*StatusCode == NULL && ret != NULL) {
      //
      // In such a case, the Redfish resource is parsed from the input payload (root) directly.
      // So, we still return HTTP_STATUS_200_OK.
      //
      *StatusCode = AllocateZeroPool (sizeof (EFI_HTTP_STATUS_CODE));
      if (*StatusCode == NULL) {
        ret = NULL;
      } else {
        **StatusCode = HTTP_STATUS_200_OK;
      }
    }
    cleanupPayload(root);
    cleanupRedPath(redpath);
    return ret;
}

void cleanupServiceEnumerator(redfishService* service)
{
  if(!service)
  {
      return;
  }
  free(service->host);
  json_decref(service->versions);
  if(service->sessionToken != NULL)
  {
      ZeroMem (service->sessionToken, (UINTN)strlen(service->sessionToken));
      FreePool(service->sessionToken);
  }
  if (service->basicAuthStr != NULL) {
      ZeroMem (service->basicAuthStr, (UINTN)strlen(service->basicAuthStr));
      FreePool (service->basicAuthStr);
  }

  if (service->RestEx != NULL && service->ChildHandle != NULL) {
    RedfishDestroyRestExChild (
      service->Image,
      service->Controller,
      service->ChildHandle,
      service->RestEx
      );
  }

  free(service);
}

static int initRest(redfishService* service, void * restProtocol)
{
  service->RestEx = restProtocol;
  return 0;
}

static redfishService* createServiceEnumeratorNoAuth(const char* host, const char* rootUri, bool enumerate, unsigned int flags, void * restProtocol)
{
    redfishService* ret;
    char  *HostStart;

    ret = (redfishService*)calloc(1, sizeof(redfishService));
    ZeroMem (ret, sizeof(redfishService));
    if(initRest(ret, restProtocol) != 0)
    {
        free(ret);
        return NULL;
    }
    ret->host = AllocateCopyPool(AsciiStrSize(host), host);
    ret->flags = flags;
    if(enumerate)
    {
        ret->versions = getVersions(ret, rootUri);
    }
    HostStart = strstr (ret->host, "//");
    if (HostStart != NULL && (*(HostStart + 2) != '\0')) {
      ret->HostHeaderValue = HostStart + 2;
    }

    return ret;
}

EFI_STATUS
createBasicAuthStr (
  IN  redfishService*                         service,
  IN  CONST CHAR8                             *UserId,
  IN  CONST CHAR8                             *Password
  )
{
  EFI_STATUS                        Status;
  CHAR8                             *RawAuthValue;
  UINTN                             RawAuthBufSize;
  CHAR8                             *EnAuthValue;
  UINTN                             EnAuthValueSize;
  CHAR8                             *BasicWithEnAuthValue;
  UINTN                             BasicBufSize;

  EnAuthValue     = NULL;
  EnAuthValueSize = 0;

  RawAuthBufSize = AsciiStrLen (UserId) + AsciiStrLen (Password) + 2;
  RawAuthValue = AllocatePool (RawAuthBufSize);
  if (RawAuthValue == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Build raw AuthValue (UserId:Password).
  //
  AsciiSPrint (
    RawAuthValue,
    RawAuthBufSize,
    "%a:%a",
    UserId,
    Password
    );

  //
  // Encoding RawAuthValue into Base64 format.
  //
  Status = HttpBase64Encode (
             (CONST VOID *) RawAuthValue,
             AsciiStrLen (RawAuthValue),
             (UINT8 *) EnAuthValue,
             &EnAuthValueSize
             );
  if (Status == EFI_BUFFER_TOO_SMALL) {
    EnAuthValue = (CHAR8 *) AllocateZeroPool (EnAuthValueSize);
    if (EnAuthValue == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      return Status;
    }

    Status = HttpBase64Encode (
               (CONST VOID *) RawAuthValue,
               AsciiStrLen (RawAuthValue),
               (UINT8 *) EnAuthValue,
               &EnAuthValueSize
               );
  }

  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  BasicBufSize = AsciiStrLen ("Basic ") + AsciiStrLen(EnAuthValue) + 2;
  BasicWithEnAuthValue = AllocatePool (BasicBufSize);
  if (BasicWithEnAuthValue == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  //
  // Build encoded EnAuthValue with Basic (Basic EnAuthValue).
  //
  AsciiSPrint (
    BasicWithEnAuthValue,
    BasicBufSize,
    "%a %a",
    "Basic",
    EnAuthValue
    );

  service->basicAuthStr = BasicWithEnAuthValue;

Exit:
  if (RawAuthValue != NULL) {
    ZeroMem (RawAuthValue, RawAuthBufSize);
    FreePool (RawAuthValue);
  }

  if (EnAuthValue != NULL) {
    ZeroMem (EnAuthValue, EnAuthValueSize);
    FreePool (EnAuthValue);
  }

  return Status;
}

static redfishService* createServiceEnumeratorBasicAuth(const char* host, const char* rootUri, const char* username, const char* password, unsigned int flags, void * restProtocol)
{
    redfishService* ret;
    EFI_STATUS   Status;

    ret = createServiceEnumeratorNoAuth(host, rootUri, false, flags, restProtocol);

    // add basic auth str
    Status = createBasicAuthStr (ret, username, password);
    if (EFI_ERROR(Status)) {
      cleanupServiceEnumerator (ret);
      return NULL;
    }

    ret->versions = getVersions(ret, rootUri);
    return ret;
}

static redfishService* createServiceEnumeratorSessionAuth(const char* host, const char* rootUri, const char* username, const char* password, unsigned int flags, void * restProtocol)
{
    redfishService* ret;
    redfishPayload* payload;
    redfishPayload* links;
    json_t* sessionPayload;
    json_t* session;
    json_t* odataId;
    const char* uri;
    json_t* post;
    char* content;
    EFI_HTTP_STATUS_CODE *StatusCode;

    content = NULL;
    StatusCode = NULL;

    ret = createServiceEnumeratorNoAuth(host, rootUri, true, flags, restProtocol);
    if(ret == NULL)
    {
        return NULL;
    }
    payload = getRedfishServiceRoot(ret, NULL, &StatusCode);
    if(StatusCode == NULL || *StatusCode < HTTP_STATUS_200_OK || *StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT)
    {
        if (StatusCode != NULL) {
          FreePool (StatusCode);
        }

        if (payload != NULL) {
          cleanupPayload(payload);
        }
        cleanupServiceEnumerator(ret);
        return NULL;
    }

    if (StatusCode != NULL) {
      FreePool (StatusCode);
      StatusCode = NULL;
    }

    links = getPayloadByNodeName(payload, "Links", &StatusCode);
    cleanupPayload(payload);
    if(links == NULL)
    {
        cleanupServiceEnumerator(ret);
        return NULL;
    }
    session = json_object_get(links->json, "Sessions");
    if(session == NULL)
    {
        cleanupPayload(links);
        cleanupServiceEnumerator(ret);
        return NULL;
    }
    odataId = json_object_get(session, "@odata.id");
    if(odataId == NULL)
    {
        cleanupPayload(links);
        cleanupServiceEnumerator(ret);
        return NULL;
    }
    uri = json_string_value(odataId);
    post = json_object();
    addStringToJsonObject(post, "UserName", username);
    addStringToJsonObject(post, "Password", password);
    content = json_dumps(post, 0);
    json_decref(post);
    sessionPayload = postUriFromService(ret, uri, content, 0, NULL, &StatusCode);

    if (content != NULL) {
      ZeroMem (content, (UINTN)strlen(content));
      free(content);
    }

    if(sessionPayload == NULL || StatusCode == NULL || *StatusCode < HTTP_STATUS_200_OK || *StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT)
    {
        //Failed to create session!

        cleanupPayload(links);
        cleanupServiceEnumerator(ret);

        if (StatusCode != NULL) {
          FreePool (StatusCode);
        }

        if (sessionPayload != NULL) {
          json_decref(sessionPayload);
        }

        return NULL;
    }
    json_decref(sessionPayload);
    cleanupPayload(links);
    FreePool (StatusCode);
    return ret;
}

static char* makeUrlForService(redfishService* service, const char* uri)
{
    char* url;
    if(service->host == NULL)
    {
        return NULL;
    }
    url = (char*)malloc(strlen(service->host)+strlen(uri)+1);
    strcpy(url, service->host);
    strcat(url, uri);
    return url;
}

static json_t* getVersions(redfishService* service, const char* rootUri)
{
    json_t*         ret = NULL;
    EFI_HTTP_STATUS_CODE* StatusCode = NULL;

    if(service->flags & REDFISH_FLAG_SERVICE_NO_VERSION_DOC)
    {
        service->versions = json_object();
        if(service->versions == NULL)
        {
            return NULL;
        }
        addStringToJsonObject(service->versions, "v1", "/redfish/v1");
        return service->versions;
    }
    if(rootUri != NULL)
    {
        ret = getUriFromService(service, rootUri, &StatusCode);
    }
    else
    {
        ret = getUriFromService(service, "/redfish", &StatusCode);
    }

    if (ret == NULL || StatusCode == NULL || *StatusCode < HTTP_STATUS_200_OK || *StatusCode > HTTP_STATUS_206_PARTIAL_CONTENT) {
      if (ret != NULL) {
        json_decref(ret);
      }
      ret = NULL;
    }

    if (StatusCode != NULL) {
      FreePool (StatusCode);
    }

    return ret;
}

static void addStringToJsonObject(json_t* object, const char* key, const char* value)
{
    json_t* jValue = json_string(value);

    json_object_set(object, key, jValue);

    json_decref(jValue);
}
