/*
 *  Client interface for local Tuya device access
 *
 *  Copyright 2022-2024 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#include "tuyaAPI.hpp"
#include "tuyaAPI31.hpp"
#include "tuyaAPI33.hpp"
#include "tuyaAPI34.hpp"

tuyaAPI* tuyaAPI::create(const std::string &version)
{
	if (version == "3.1")
		return new tuyaAPI31();
	if (version == "3.3")
		return new tuyaAPI33();
	if (version == "3.4")
		return new tuyaAPI34();
	return nullptr;
}
