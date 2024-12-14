#include "server.hpp"

int main()
{
    //system("pause");
    //
    std::cout << server::session_valid("Test", "TestSession", "Test") << "\n";
    std::cout << server::refresh_session("Test", "TestSession", "Test") << "\n";
    std::cout << server::verify_key("KEY", "Test") << "\n";
    std::cout << server::get_key_duration("KEY", "Test") << "\n";
    std::string session = server::create_session("Test", "Test");
    std::cout << session << "\n";
    std::cout << server::session_valid("Test", session, "Test") << "\n";
    std::cout << server::refresh_session("Test", session, "Test") << "\n";
    return 0;

    //nlohmann::json request_body = {
    //    {$("ch"), "krasse challenge"},
    //    {$("rh"), "krasse response"},
    //    {$("body"), "krasse daten"}
    //};
    //
    //server::encryption::Data_Encrypt(request_body);

    // Example plaintext
    std::string plaintext = R"({"key": "KEY-1", "duration": 1736194472})";

    std::string server_encoded = "eCqL0WH70e+XhJGGTM52hw8uTH7aj0iZGNmv9oJ0gF8="; // {'error': 'invalid hash'}

    std::cout << "Server Encrypted Response (Base64): " << server_encoded << std::endl;

    // Decode and decrypt
    std::string server_decoded = server::encryption::Base64_Decode(server_encoded);
    std::string server_decrypted = server::encryption::AES_Decrypt(server_decoded);

    std::cout << "Server Decrypted Response: " << server_decrypted << std::endl;

    // Hashing a challenge + response
    std::string server_challenge = "example_challenge";
    std::string server_key = "EMPTYBASE";
    std::string server_combined = server_challenge + server_key + server::encryption::HASH_SECRET;

    std::cout << "Server Combined: " << server_combined << std::endl;

    std::string server_hash = server::encryption::SHA256_HASH(server_combined);

    std::cout << "Server Expected Hash: " << server_hash << std::endl << std::endl;

    // Encrypt and encode
    std::string encrypted = server::encryption::AES_Encrypt(plaintext);
    std::string encoded = server::encryption::Base64_Encode(encrypted);


    std::cout << "Encrypted (Base64): " << encoded << std::endl;

    // Decode and decrypt
    std::string decoded = server::encryption::Base64_Decode(encoded);
    std::string decrypted = server::encryption::AES_Decrypt(decoded);

    std::cout << "Decrypted: " << decrypted << std::endl;

    // Hashing a challenge + response
    std::string challenge = "example_challenge";
    std::string key = "KEY-1";
    std::string combined = challenge + key + server::encryption::HASH_SECRET;
    std::string hash = server::encryption::SHA256_HASH(combined);

    std::cout << "Hash: " << hash << std::endl;

	return 0;
}