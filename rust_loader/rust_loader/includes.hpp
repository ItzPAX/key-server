#pragma once
#include <string>
#include <vector>

#define CRASH(p) ((void(*)())p)();

namespace user_data
{
	inline char key[256];
	inline bool is_authenticated = false;

	inline uint32_t expiry_date = 0;
	inline uint32_t time_remaining = 0;
	inline std::string expiry_date_str;

	inline std::string session;

	inline std::string hwid;
}

namespace loader_data
{
	inline bool processing_request = false;
	inline bool session_thread_launched = false;
	inline std::string auth_errors;
	inline std::vector<std::string> log;
	inline int old_log_size = 0;
}

#include "image_data.h"
#include "server/server.hpp"
#include "utils.hpp"
#include "ui.h"
#include "auth.hpp"