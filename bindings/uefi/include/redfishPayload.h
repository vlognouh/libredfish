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
#ifndef _REDFISH_PAYLOAD_H_
#define _REDFISH_PAYLOAD_H_

#include "redfishService.h"

#include "../../../include/redpath.h"

redfishPayload* createRedfishPayload(json_t* value, redfishService* service);
redfishPayload* getPayloadByNodeName(redfishPayload* payload, const char* nodeName, EFI_HTTP_STATUS_CODE** StatusCode);
redfishPayload* getPayloadByIndex(redfishPayload* payload, size_t index, EFI_HTTP_STATUS_CODE** StatusCode);
redfishPayload* getPayloadForPath(redfishPayload* payload, redPathNode* redpath, EFI_HTTP_STATUS_CODE** StatusCode);
redfishPayload* getPayloadForPathString(redfishPayload* payload, const char* string, EFI_HTTP_STATUS_CODE** StatusCode);
redfishPayload* patchPayload(redfishPayload* target, redfishPayload* payload, EFI_HTTP_STATUS_CODE** StatusCode);
redfishPayload* postContentToPayload(redfishPayload* target, const char* data, size_t dataSize, const char* contentType, EFI_HTTP_STATUS_CODE** StatusCode);
redfishPayload* postPayload(redfishPayload* target, redfishPayload* payload, EFI_HTTP_STATUS_CODE** StatusCode);
void            cleanupPayload(redfishPayload* payload);

#endif
