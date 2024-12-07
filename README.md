# key-server
 
# Features
- Unique hashing challenge for every request
- Full AES encryption
- Asynchronous calls

# Usage example
```cpp
#include "server.hpp"

int main()
{
    std::cout << server::session_valid("TestSession") << "\n";
    std::cout << server::refresh_session("TestSession") << "\n";
    std::cout << server::verify_key("KEY-1") << "\n";
    std::cout << server::get_key_duration("KEY-1") << "\n";
    std::string session = server::create_session();
    std::cout << session << "\n";
    std::cout << server::session_valid(session) << "\n";
    std::cout << server::refresh_session(session) << "\n";
    return 0;
}
```
