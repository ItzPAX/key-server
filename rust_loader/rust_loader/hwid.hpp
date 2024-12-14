#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <bcrypt.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "bcrypt.lib")

namespace hwid
{
    // Function to initialize COM and set up WMI
    inline HRESULT InitializeWMI(IWbemLocator** pLocator, IWbemServices** pServices) {
        HRESULT hres;

        // Initialize COM
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            return hres;
        }

        // Set general COM security levels
        hres = CoInitializeSecurity(
            NULL,
            -1,                          // COM negotiates authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities 
            NULL                         // Reserved
        );

        if (FAILED(hres)) {
            CoUninitialize();
            return hres;
        }

        // Obtain the initial locator to WMI 
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*) pLocator);

        if (FAILED(hres)) {
            return hres;
        }

        // Connect to WMI namespace
        hres = (*pLocator)->ConnectServer(
            _bstr_t($(L"ROOT\\CIMV2")), // WMI namespace
            NULL,                    // User name
            NULL,                    // User password
            0,                       // Locale
            NULL,                    // Security flags
            0,                       // Authority
            0,                       // Context object
            pServices                // IWbemServices proxy
        );

        if (FAILED(hres)) {
            (*pLocator)->Release();
            CoUninitialize();
            return hres;
        }

        // Set security levels on the proxy
        hres = CoSetProxyBlanket(
            *pServices,                        // the proxy to set
            RPC_C_AUTHN_WINNT,                 // authentication service
            RPC_C_AUTHZ_NONE,                  // authorization service
            NULL,                               // Server principal name 
            RPC_C_AUTHN_LEVEL_CALL,            // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE,       // impersonation level
            NULL,                               // client identity
            EOAC_NONE                           // proxy capabilities     
        );

        if (FAILED(hres)) {
            (*pServices)->Release();
            (*pLocator)->Release();
            CoUninitialize();
            return hres;
        }

        return S_OK;
    }

    // Function to execute a WMI query and retrieve a property
    inline std::string GetWMIProperty(IWbemServices* pServices, const std::wstring& className, const std::wstring& propertyName) {
        HRESULT hres;
        IEnumWbemClassObject* pEnumerator = NULL;
        std::string result = $("");

        // Build the WMI query
        std::wstring query = $(L"SELECT ") + propertyName + $(L" FROM ") + className;
        hres = pServices->ExecQuery(
            bstr_t($("WQL")),
            bstr_t(query.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator);

        if (FAILED(hres)) {
            return result;
        }

        IWbemClassObject* pClassObject = NULL;
        ULONG returnVal = 0;

        // Get the data from the query
        if (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &returnVal);
            if (returnVal) {
                VARIANT vtProp;
                hr = pClassObject->Get(propertyName.c_str(), 0, &vtProp, 0, 0);
                if (SUCCEEDED(hr) && (vtProp.vt == VT_BSTR)) {
                    _bstr_t bstrValue(vtProp.bstrVal);
                    result = (const char*) bstrValue;
                }
                VariantClear(&vtProp);
                pClassObject->Release();
            }
            pEnumerator->Release();
        }

        return result;
    }

    // Function to retrieve all necessary hardware identifiers
    inline std::vector<std::string> GetHardwareIdentifiers(IWbemServices* pServices) {
        std::vector<std::string> identifiers;

        // CPU ID
        std::string cpuID = GetWMIProperty(pServices, $(L"Win32_Processor"), $(L"ProcessorId"));
        if (!cpuID.empty()) identifiers.push_back(cpuID);

        // Motherboard Serial Number
        std::string motherboardSN = GetWMIProperty(pServices, $(L"Win32_BaseBoard"), $(L"SerialNumber"));
        if (!motherboardSN.empty()) identifiers.push_back(motherboardSN);

        // BIOS Serial Number
        std::string biosSN = GetWMIProperty(pServices, $(L"Win32_BIOS"), $(L"SerialNumber"));
        if (!biosSN.empty()) identifiers.push_back(biosSN);

        // Primary Hard Disk Serial Number
        std::string diskSN = GetWMIProperty(pServices, $(L"Win32_DiskDrive"), $(L"SerialNumber"));
        if (!diskSN.empty()) identifiers.push_back(diskSN);

        // MAC Address
        std::string macAddr = GetWMIProperty(pServices, $(L"Win32_NetworkAdapterConfiguration"), $(L"MACAddress"));
        if (!macAddr.empty()) identifiers.push_back(macAddr);

        return identifiers;
    }

    // Function to compute SHA-256 hash
    inline std::string ComputeSHA256(const std::string& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        DWORD cbHash = 0, cbData = 0;
        PBYTE pbHash = NULL;
        std::string hashString = "";

        // Open an algorithm handle
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
            return hashString;
        }

        // Calculate the size of the hash object
        if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE) &cbHash, sizeof(DWORD), &cbData, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return hashString;
        }

        pbHash = new BYTE[cbHash];
        if (!pbHash) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return hashString;
        }

        // Create a hash
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
            delete[] pbHash;
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return hashString;
        }

        // Hash the data
        if (BCryptHashData(hHash, (PBYTE) data.c_str(), data.length(), 0) != 0) {
            BCryptDestroyHash(hHash);
            delete[] pbHash;
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return hashString;
        }

        // Get the hash value
        if (BCryptFinishHash(hHash, pbHash, cbHash, 0) != 0) {
            BCryptDestroyHash(hHash);
            delete[] pbHash;
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return hashString;
        }

        // Convert hash to hexadecimal string
        std::ostringstream oss;
        for (DWORD i = 0; i < cbHash; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int) pbHash[i];
        }
        hashString = oss.str();

        // Clean up
        BCryptDestroyHash(hHash);
        delete[] pbHash;
        BCryptCloseAlgorithmProvider(hAlg, 0);

        return hashString;
    }

    inline std::string calc_hwid()
    {
        IWbemLocator* pLocator = NULL;
        IWbemServices* pServices = NULL;
        HRESULT hres = InitializeWMI(&pLocator, &pServices);
        if (FAILED(hres)) {
            CRASH(rand());
        }

        std::vector<std::string> hwIdentifiers = GetHardwareIdentifiers(pServices);

        pServices->Release();
        pLocator->Release();
        CoUninitialize();

        if (hwIdentifiers.empty()) {
            CRASH(rand());
        }

        std::string combinedData;
        for (const auto& id : hwIdentifiers) {
            combinedData += id + "|";
        }

        std::string hwid = ComputeSHA256(combinedData);
        if (hwid.empty()) {
            CRASH(rand());
        }

        return hwid;
    }
}