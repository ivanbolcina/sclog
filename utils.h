#ifndef AUDIT_CORE_UTILS_H
#define AUDIT_CORE_UTILS_H

#include <functional>
#include <cctype>
#include <locale>
#include <iostream>
#include <sstream>
#include <string>

#include <iostream>
#include <vector>
#include <algorithm>
#include <thread>

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            std::not1(std::ptr_fun<int, int>(std::isspace))));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

// trim from start (copying)
static inline std::string ltrim_copy(std::string s) {
    ltrim(s);
    return s;
}

// trim from end (copying)
static inline std::string rtrim_copy(std::string s) {
    rtrim(s);
    return s;
}
// trim from both ends (copying)
static inline std::string trim_copy(std::string s) {
    trim(s);
    return s;
}

static inline std::string first(std::string s) {
    std::stringstream ss {s};
    std::string w;
    ss >> w;
    return w;
    //auto x=s;
    //x.erase(x.begin(), std::find_if(x.begin(), x.end(),
    //        (std::ptr_fun<int, int>(std::isspace))));
    //return s.substr(0,s.size()-x.size());
}

inline void sleepForMilliseconds(int x)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(x));
}


#endif