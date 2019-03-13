// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include "openssl/rc4.h"
#include "openssl/hmac.h"
#include "openssl\ossl_typ.h"
#include "openssl\err.h"

#include <algorithm>
#include <vector>
#include <string>
#include <memory>


// TODO: reference additional headers your program requires here
