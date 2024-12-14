#pragma once
#include <iostream>
#include <string>
#include <ctime>

namespace utils
{
    inline std::string unix_timestamp_to_date(time_t timestamp)
    {
        struct tm newtime;
        errno_t err = _gmtime64_s(&newtime, &timestamp);
        if (err) {
            return $("");
        }

        char buffer[20];
        if (std::strftime(buffer, sizeof(buffer), $("%Y-%m-%d %H:%M:%S"), &newtime)) {
            return std::string(buffer);
        }
        else {
            return $("");
        }
    }
}