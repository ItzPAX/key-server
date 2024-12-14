#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <random> 
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>

#include "httplib.h"
#include "json.hpp"
#include "xorstr.hpp"

#define $ xorstr_

namespace server
{
    inline httplib::Client cli("localhost:8000");
    inline std::mt19937 mt(time(0));

    namespace encryption
    {
        using namespace CryptoPP;

        // Utility: SHA-256 hashing
        inline std::string SHA256_HASH(const std::string& input) {
            SHA256 hash;
            std::string digest;
            StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
            return digest;
        }

        // Utility: SHA-256 hashing (binary output)
        std::string SHA256_HASH_BINARY(const std::string& input) {
            SHA256 hash;
            std::string digest;
            StringSource(input, true, new HashFilter(hash, new StringSink(digest)));
            return digest; // 32 bytes (256 bits)
        }

        // Constants
        inline const std::string HASH_SECRET = $("zgC4S43KF33dLhjGDhUn5sBMKLkZTNRy");
        inline const std::string ENC_SECRET = $("4KKFCT6DtGEWhd9jqvrbKUAyHP3Mtfwk");
        inline const std::string AES_KEY = SHA256_HASH_BINARY(ENC_SECRET);
        inline const byte AES_IV[AES::BLOCKSIZE] = { 0x7f, 0xe6, 0x55, 0xf1, 0xfd, 0x1a, 0x48, 0xc3, 0x68, 0x6f, 0xd4, 0x9e, 0x57, 0x96, 0x6d, 0x49 };

        // AES Encryption
        inline std::string AES_Encrypt(const std::string& plaintext) {
            std::string ciphertext;

            try {
                CBC_Mode<AES>::Encryption encryptor((byte*) AES_KEY.data(), AES_KEY.size(), AES_IV);
                StringSource(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            }
            catch (const Exception& e) {
                throw;
            }

            return ciphertext;
        }

        // AES Decryption
        inline std::string AES_Decrypt(const std::string& ciphertext) {
            std::string decrypted;

            try {
                CBC_Mode<AES>::Decryption decryptor((byte*) AES_KEY.data(), AES_KEY.size(), AES_IV);
                StringSource(ciphertext, true, new StreamTransformationFilter(decryptor, new StringSink(decrypted)));
            }
            catch (const Exception& e) {
                throw;
            }

            return decrypted;
        }

        // Base64 Encoding
        inline std::string Base64_Encode(const std::string& input) {
            std::string encoded;
            StringSource(input, true, new Base64Encoder(new StringSink(encoded)));
            return encoded;
        }

        // Base64 Decoding
        inline std::string Base64_Decode(const std::string& input) {
            std::string decoded;
            StringSource(input, true, new Base64Decoder(new StringSink(decoded)));
            return decoded;
        }

        inline nlohmann::json Data_Decrypt(httplib::Result& server_resp)
        {
            nlohmann::json data_json = nlohmann::json::parse(server_resp->body);

            if (!data_json.contains($("data")))
                return nlohmann::json();

            std::string data = data_json[$("data")];

            std::string data_decoded = server::encryption::Base64_Decode(data);
            std::string data_decrypted = server::encryption::AES_Decrypt(data_decoded);
            std::replace(data_decrypted.begin(), data_decrypted.end(), '\'', '\"');

            nlohmann::json decrypted_data_json = nlohmann::json::parse(data_decrypted);

            return decrypted_data_json;
        }

        inline nlohmann::json Data_Encrypt(nlohmann::json& server_req)
        {
            std::string req_text = server_req.dump();
            std::string encrypted = server::encryption::AES_Encrypt(req_text);
            std::string encoded = server::encryption::Base64_Encode(encrypted);
            
            if (!encoded.empty() && encoded.back() == '\n') {
                encoded.pop_back();
            }

            nlohmann::json request_body = {
                { $("data"), encoded }
            };

            return request_body;
        }
    }

    // returns the agreed upon challenge to solve
    // the challenge will only be valid for one request
    std::string agree_on_ch()
    {
        std::string ch = encryption::SHA256_HASH(std::to_string(mt()));
        std::string rh = encryption::SHA256_HASH(ch);

        while (true)
        {
            nlohmann::json request_body = {
                {$("ch"), ch.c_str()},
                {$("rh"), rh.c_str()},
                {$("body"), encryption::SHA256_HASH(std::to_string(mt()))}
            };

            nlohmann::json encryted_req = encryption::Data_Encrypt(request_body);

            httplib::Result res = cli.Post($("/is_ch_valid/"), encryted_req.dump(), $("application/json"));

            if (!encryption::Data_Decrypt(res).contains($("error")))
                break;

            ch = encryption::SHA256_HASH(std::to_string(mt())); 
            rh = encryption::SHA256_HASH(ch);
        }

        // return variation of the agreed challenge
        return encryption::SHA256_HASH(rh);
    }

    // returns the response hash the server can use to validate the request
    std::string generate_respone_hash(std::string ch, std::string data)
    {
        std::string server_combined = ch + data + server::encryption::HASH_SECRET;
        return server::encryption::SHA256_HASH(server_combined);
    }

    // returns if a key is valid
    bool verify_key(std::string key, std::string hwid)
    {
        std::string random_data = encryption::SHA256_HASH(std::to_string(mt()));
        std::string ch = agree_on_ch();
        std::string rh = generate_respone_hash(ch, key + hwid + random_data);

        nlohmann::json request_body = {
            {$("ch"), ch.c_str()},
            {$("rh"), rh.c_str()},
            {$("key"), key},
            {$("hwid"), hwid},
            {$("rng"), random_data}
        };

        nlohmann::json encryted_req = encryption::Data_Encrypt(request_body);

        httplib::Result res = cli.Post($("/verify_key/"), encryted_req.dump(), $("application/json"));
        nlohmann::json dec_res = encryption::Data_Decrypt(res);
        std::cout << dec_res.dump() << std::endl;
        return !dec_res.contains($("error"));
    }

    // returns a unix timestamp of the key expiration date (NOT the remaining time)
    std::uint32_t get_key_duration(std::string key, std::string hwid)
    {
        std::string random_data = encryption::SHA256_HASH(std::to_string(mt()));
        std::string ch = agree_on_ch();
        std::string rh = generate_respone_hash(ch, key + hwid + random_data);

        nlohmann::json request_body = {
            {$("ch"), ch.c_str()},
            {$("rh"), rh.c_str()},
            {$("key"), key},
            {$("hwid"), hwid},
            {$("rng"), random_data}
        };

        nlohmann::json encryted_req = encryption::Data_Encrypt(request_body);

        httplib::Result res = cli.Post($("/get_duration/"), encryted_req.dump(), $("application/json"));
        nlohmann::json dec_res = encryption::Data_Decrypt(res);
        std::cout << dec_res.dump() << std::endl;
        if (dec_res.contains($("duration")))
            return dec_res[$("duration")];
        return 0;
    }

    // creates a session on the backend (sessions time out after 15 minutes if they are not refreshed)
    // returns the session id
    std::string create_session(std::string key, std::string hwid)
    {
        std::string random_data = encryption::SHA256_HASH(std::to_string(mt()));
        std::string ch = agree_on_ch();
        std::string rh = generate_respone_hash(ch, key + hwid + random_data);

        nlohmann::json request_body = {
            {$("ch"), ch.c_str()},
            {$("rh"), rh.c_str()},
            {$("key"), key},
            {$("hwid"), hwid },
            {$("rng"), random_data}
        };

        nlohmann::json encryted_req = encryption::Data_Encrypt(request_body);

        httplib::Result res = cli.Post($("/create_session/"), encryted_req.dump(), $("application/json"));
        nlohmann::json dec_res = encryption::Data_Decrypt(res);
        std::cout << dec_res.dump() << std::endl;
        if (dec_res.contains($("session")))
            return dec_res[$("session")];
        return std::string();
    }

    // refreshes a session for another 15 minutes
    bool refresh_session(std::string key, std::string session, std::string hwid)
    {
        std::string random_data = encryption::SHA256_HASH(std::to_string(mt()));
        std::string ch = agree_on_ch();
        std::string rh = generate_respone_hash(ch, key + session + hwid + random_data);

        nlohmann::json request_body = {
            {$("ch"), ch.c_str()},
            {$("rh"), rh.c_str()},
            {$("session"), session},
            {$("key"), key},
            {$("hwid"), hwid },
            {$("rng"), random_data}
        };

        nlohmann::json encryted_req = encryption::Data_Encrypt(request_body);

        httplib::Result res = cli.Post($("/refresh_session/"), encryted_req.dump(), $("application/json"));
        nlohmann::json dec_res = encryption::Data_Decrypt(res);
        std::cout << dec_res.dump() << std::endl;
        return !dec_res.contains($("error"));
    }

    // returns if a session is valid
    bool session_valid(std::string key, std::string session, std::string hwid)
    {
        std::string random_data = encryption::SHA256_HASH(std::to_string(mt()));
        std::string ch = agree_on_ch();
        std::string rh = generate_respone_hash(ch, key + session + hwid + random_data);

        nlohmann::json request_body = {
            {$("ch"), ch.c_str()},
            {$("rh"), rh.c_str()},
            {$("session"), session},
            {$("key"), key},
            {$("hwid"), hwid },
            {$("rng"), random_data}
        };

        nlohmann::json encryted_req = encryption::Data_Encrypt(request_body);

        httplib::Result res = cli.Post($("/session_valid/"), encryted_req.dump(), $("application/json"));
        nlohmann::json dec_res = encryption::Data_Decrypt(res);
        std::cout << dec_res.dump() << std::endl;
        return !dec_res.contains($("error"));
    }
}