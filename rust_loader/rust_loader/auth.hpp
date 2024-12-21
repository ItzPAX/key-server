#pragma once
#include "includes.hpp"
#include "utils.hpp"

namespace auth
{
	inline void manage_user_session()
	{
		loader_data::session_thread_launched = true;

		user_data::session = server::create_session(user_data::key, user_data::hwid);
		loader_data::log.push_back($("Started user session, welcome back!"));

		while (true)
		{
			if (!server::session_valid(user_data::key, user_data::session, user_data::hwid))
				CRASH(rand());

			server::refresh_session(user_data::key, user_data::session, user_data::hwid);
			Sleep(300000); // 5 min
		}
	}

	// returns true if login is successfull
	inline bool login()
	{
		// key is empty
		if (user_data::key[0] == '\0')
		{
			loader_data::auth_errors = $("Key connot be empty!");
			loader_data::processing_request = false;
			return false;
		}

		if (!server::verify_key(user_data::key, user_data::hwid, loader_data::auth_errors))
		{
			memset(user_data::key, 0, 256);
			loader_data::processing_request = false;
			return false;
		}

		if (server::get_key_time_remaining(user_data::key, user_data::hwid) <= 0)
		{
			memset(user_data::key, 0, 256);
			loader_data::auth_errors = $("Key expired!");
			loader_data::processing_request = false;
			return false;
		}

		loader_data::log.push_back($("Successfully logged in!"));

		// get user data
		user_data::expiry_date = server::get_key_duration(user_data::key, user_data::hwid);
		if (user_data::expiry_date == 0) // shouldn't ever happen but just in case
		{
			CRASH(rand());
		}

		user_data::expiry_date_str = utils::unix_timestamp_to_date(user_data::expiry_date);

		std::string s = $("Sub valid until ") + user_data::expiry_date_str;
		loader_data::log.push_back(s);

		user_data::is_authenticated = true;
		loader_data::processing_request = false;

		return true;
	}

	inline bool load_cheat()
	{
		loader_data::enc_file_b64 = server::download(user_data::key, user_data::session, user_data::hwid);
		std::string encrypted_pe = server::encryption::Base64_Decode(loader_data::enc_file_b64);
		std::string decrypted_pe = server::encryption::AES_Decrypt(encrypted_pe);
		loader_data::processing_request = false;

		HANDLE host_handle = launcher::LaunchHostProcess($("C:\\Windows\\System32\\svchost.exe"));
		if (host_handle == (HANDLE)0)
		{
			return false;
		}

		launcher::ManualMapExe(host_handle, (BYTE*)decrypted_pe.data(), decrypted_pe.size(), false);

		return true;
	}
}