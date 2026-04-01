#include "verademo_vulns.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <array>
#include <memory>
#include <cstring>
#include <cstdio>
#include <cstdlib>

// Simple MD5 stub
namespace SimpleMD5 {
    std::string md5(const std::string& input) {
        unsigned int hash = 5381;
        for (char c : input) {
            hash = ((hash << 5) + hash) + c;
        }
        std::stringstream ss;
        ss << std::hex << hash;
        return ss.str();
    }
}

// CWE-89: SQL Injection in login
bool UserController::login_vulnerable(const std::string& username, const std::string& password) {
    std::cout << "[UserController::login_vulnerable] Processing login\n";
    std::string password_hash = CryptoUtils::md5_hash_vulnerable(password);
    std::string sql_query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password_hash + "';";
    std::cout << "[DEBUG] SQL: " << sql_query << "\n";
    std::string result = execute_sql_query(sql_query);
    return !result.empty();
}

// CWE-89: SQL Injection in password hint
std::string UserController::get_password_hint_vulnerable(const std::string& username) {
    std::cout << "[UserController::get_password_hint_vulnerable]\n";
    std::string sql = "SELECT password_hint FROM users WHERE username = '" + username + "'";
    std::cout << "[DEBUG] SQL: " << sql << "\n";
    return execute_sql_query(sql);
}

// CWE-89: SQL Injection in registration
bool UserController::register_user_vulnerable(const std::string& username, const std::string& password,
                                               const std::string& real_name, const std::string& blab_name) {
    std::cout << "[UserController::register_user_vulnerable]\n";
    std::string password_hash = CryptoUtils::md5_hash_vulnerable(password);
    std::string sql = "INSERT INTO users VALUES('" + username + "','" + password_hash + "','" + real_name + "','" + blab_name + "')";
    std::cout << "[DEBUG] SQL: " << sql << "\n";
    execute_sql_query(sql);
    return true;
}

// CWE-89: SQL Injection in user history
std::vector<std::string> UserController::get_user_history_vulnerable(const std::string& username) {
    std::cout << "[UserController::get_user_history_vulnerable]\n";
    std::string sql = "SELECT event FROM users_history WHERE blabber=\"" + username + "\"";
    std::cout << "[DEBUG] SQL: " << sql << "\n";
    std::vector<std::string> events;
    events.push_back(execute_sql_query(sql));
    return events;
}

// CWE-89 + CWE-564: SQL Injection in ORDER BY
std::vector<User> BlabController::get_blabbers_vulnerable(const std::string& username, const std::string& sort_column) {
    std::cout << "[BlabController::get_blabbers_vulnerable]\n";
    std::string sql = "SELECT * FROM users WHERE username!='" + username + "' ORDER BY " + sort_column;
    std::cout << "[DEBUG] SQL: " << sql << "\n";
    execute_sql_query(sql);
    return std::vector<User>();
}

// CWE-78: Command Injection in ping
std::string ToolsController::ping_vulnerable(const std::string& host) {
    std::cout << "[ToolsController::ping_vulnerable] host=" << host << "\n";
    std::string command = "ping -c1 " + host;
    std::cout << "[DEBUG] CMD: " << command << "\n";
    return execute_command(command);
}

// CWE-78: Command Injection in fortune
std::string ToolsController::fortune_vulnerable(const std::string& fortune_file) {
    std::cout << "[ToolsController::fortune_vulnerable]\n";
    std::string cmd = "/usr/games/fortune " + fortune_file;
    std::cout << "[DEBUG] CMD: " << cmd << "\n";
    return execute_command(cmd);
}

// CWE-327: Weak MD5 hashing
std::string CryptoUtils::md5_hash_vulnerable(const std::string& input) {
    return SimpleMD5::md5(input);
}

// CWE-73: Path Traversal
std::string FileController::download_profile_image_vulnerable(const std::string& image_name) {
    std::cout << "[FileController::download_profile_image_vulnerable]\n";
    std::string path = "/var/www/resources/images/" + image_name;
    std::cout << "[DEBUG] PATH: " << path << "\n";
    std::ifstream file(path);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
    return "[ERROR] File not found";
}

// CWE-611: XXE
std::string XMLParser::parse_xml_vulnerable(const std::string& xml_content) {
    std::cout << "[XMLParser::parse_xml_vulnerable]\n";
    std::cout << "[DEBUG] XML: " << xml_content.substr(0, 100) << "\n";
    return "[XML parsed - XXE vulnerable]";
}

// ============================================================================
// CWE-119/120/121/122: Buffer Overflow Vulnerabilities
// ============================================================================

// CWE-120: Buffer Copy without Checking Size of Input (strcpy)
void BufferOverflowVulns::unsafe_string_copy(const char* user_input) {
    std::cout << "[BufferOverflowVulns::unsafe_string_copy]\n";
    
    /* START VULNERABILITY - CWE-120: strcpy Buffer Overflow */
    char buffer[32];
    strcpy(buffer, user_input);  // VULNERABLE: No bounds checking
    /* END VULNERABILITY */
    
    std::cout << "[DEBUG] Copied to buffer: " << buffer << "\n";
}

// CWE-134: Uncontrolled Format String
void BufferOverflowVulns::format_string_vulnerability(const char* user_input) {
    std::cout << "[BufferOverflowVulns::format_string_vulnerability]\n";
    
    /* START VULNERABILITY - CWE-134: Format String Vulnerability */
    char output[256];
    sprintf(output, user_input);  // VULNERABLE: User controls format string
    printf(user_input);           // VULNERABLE: Direct printf of user input
    /* END VULNERABILITY */
    
    std::cout << "[DEBUG] Formatted output\n";
}

// CWE-121: Stack-based Buffer Overflow
void BufferOverflowVulns::stack_buffer_overflow(const char* user_data) {
    std::cout << "[BufferOverflowVulns::stack_buffer_overflow]\n";
    
    /* START VULNERABILITY - CWE-121: Stack Buffer Overflow */
    char local_buffer[64];
    strncpy(local_buffer, user_data, 200);  // VULNERABLE: Copies more than buffer size
    local_buffer[63] = '\0';
    
    // Another vulnerability with sprintf
    char formatted[50];
    sprintf(formatted, "User input: %s", user_data);  // VULNERABLE: No bounds check
    /* END VULNERABILITY */
    
    std::cout << "[DEBUG] Buffer contents: " << local_buffer << "\n";
}

// CWE-122: Heap-based Buffer Overflow
char* BufferOverflowVulns::heap_buffer_overflow(const char* input) {
    std::cout << "[BufferOverflowVulns::heap_buffer_overflow]\n";
    
    /* START VULNERABILITY - CWE-122: Heap Buffer Overflow */
    char* heap_buffer = (char*)malloc(32);
    strcpy(heap_buffer, input);  // VULNERABLE: No size check on heap buffer
    /* END VULNERABILITY */
    
    std::cout << "[DEBUG] Heap buffer allocated and filled\n";
    return heap_buffer;
}

// CWE-126: Buffer Over-read
void BufferOverflowVulns::buffer_overread(const char* data, int length) {
    std::cout << "[BufferOverflowVulns::buffer_overread]\n";
    
    /* START VULNERABILITY - CWE-126: Buffer Over-read */
    char internal_buffer[50];
    // Copy without checking if length exceeds data size
    memcpy(internal_buffer, data, length);  // VULNERABLE: length not validated
    internal_buffer[49] = '\0';
    
    // Reading beyond buffer bounds
    for (int i = 0; i < length + 10; i++) {  // VULNERABLE: Reads past buffer
        char c = data[i];
        (void)c;  // Suppress unused warning
    }
    /* END VULNERABILITY */
    
    std::cout << "[DEBUG] Buffer read complete\n";
}

// CWE-676: Use of Potentially Dangerous Function
void BufferOverflowVulns::dangerous_function_usage() {
    std::cout << "[BufferOverflowVulns::dangerous_function_usage]\n";
    
    /* START VULNERABILITY - CWE-676: Dangerous Functions */
    char input_buffer[100];
    char output_buffer[50];
    
    // gets() is banned - extremely dangerous
    std::cout << "Enter some text: ";
    // gets(input_buffer);  // VULNERABLE: No bounds checking (commented to avoid crash)
    
    // Using scanf without width limit
    scanf("%s", input_buffer);  // VULNERABLE: No width specifier
    
    // Using strcpy, strcat without bounds checking
    strcpy(output_buffer, input_buffer);   // VULNERABLE
    strcat(output_buffer, " - processed");  // VULNERABLE
    
    // sprintf without size checking
    char final_buffer[30];
    sprintf(final_buffer, "Result: %s", output_buffer);  // VULNERABLE
    /* END VULNERABILITY */
    
    std::cout << "[DEBUG] Input processed\n";
}

// CWE-805: Buffer Access with Incorrect Length Value
void BufferOverflowVulns::incorrect_buffer_length(const char* src, int wrong_length) {
    std::cout << "[BufferOverflowVulns::incorrect_buffer_length]\n";
    
    /* START VULNERABILITY - CWE-805: Incorrect Buffer Length */
    char dest[32];
    
    // Using wrong length value
    memcpy(dest, src, wrong_length);  // VULNERABLE: wrong_length not validated
    
    // Another example with strncat using incorrect length
    char buffer[40] = "Prefix: ";
    strncat(buffer, src, wrong_length);  // VULNERABLE: length not checked against dest size
    /* END VULNERABILITY */
    
    std::cout << "[DEBUG] Buffer operation complete\n";
}

// Helper functions
std::string execute_sql_query(const std::string& query) {
    std::cout << "[SQL EXECUTION]\n";
    return (query.find("SELECT") != std::string::npos) ? "result_data" : "";
}

std::string execute_command(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) return "[ERROR] Command failed\n";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}
