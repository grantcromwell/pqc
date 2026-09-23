#include "qprotect/hardware.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string_view>
#include <vector>

namespace qprotect::cpp {
namespace {

struct Capability {
    std::string domain;
    std::string name;
    std::string state;
    std::string source;
    std::string evidence;
};

std::string quote_json(std::string_view value) {
    std::string result{"\""};
    static constexpr char digits[] = "0123456789abcdef";
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (ch < 0x20) {
                    result += "\\u00";
                    result.push_back(digits[ch >> 4]);
                    result.push_back(digits[ch & 0x0f]);
                } else {
                    result.push_back(static_cast<char>(ch));
                }
        }
    }
    result.push_back('"');
    return result;
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) return {};
    std::string value;
    std::getline(input, value);
    return value;
}

std::string link_target(const std::filesystem::path& path) {
    std::error_code error;
    const auto target = std::filesystem::canonical(path, error);
    return error ? std::string{} : target.string();
}

#if defined(__linux__)

void discover_boot(std::vector<Capability>& output) {
    const std::filesystem::path efi_root{"/sys/firmware/efi"};
    std::error_code error;
    if (!std::filesystem::is_directory(efi_root, error)) {
        output.push_back({"boot", "uefi", "unavailable", efi_root.string(),
                          "UEFI sysfs interface is not present"});
        output.push_back({"boot", "secure_boot", "unknown", efi_root.string(),
                          "Secure Boot state cannot be read without UEFI variables"});
        return;
    }
    output.push_back({"boot", "uefi", "available", efi_root.string(),
                      "UEFI sysfs interface is present"});

    const std::filesystem::path variables = efi_root / "efivars";
    std::string secure_boot;
    std::string setup_mode;
    for (std::filesystem::directory_iterator item(variables, error), end;
         !error && item != end; item.increment(error)) {
        const std::string name = item->path().filename().string();
        const auto read_variable = [&item]() -> std::string {
            std::ifstream input(item->path(), std::ios::binary);
            if (!input) return {};
            std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(input)), {});
            if (bytes.size() < 5) return {};
            return bytes[4] == 0 ? "0" : "1";
        };
        if (name.starts_with("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")) {
            secure_boot = read_variable();
        } else if (name.starts_with("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c")) {
            setup_mode = read_variable();
        }
    }
    if (!secure_boot.empty() && !setup_mode.empty()) {
        const std::string state = secure_boot == "1" && setup_mode == "0" ? "enabled" : "disabled";
        const std::string reason = setup_mode == "1" ? "firmware is in Setup Mode" :
            (secure_boot == "1" ? "EFI SecureBoot variable is enabled" : "EFI SecureBoot variable is disabled");
        output.push_back({"boot", "secure_boot", state, variables.string(), reason});
    } else {
        output.push_back({"boot", "secure_boot", "unknown", variables.string(),
                          error ? "UEFI variable access failed" : "required EFI variables are unavailable"});
    }
}

void discover_devices(std::vector<Capability>& output) {
    const std::filesystem::path pci_root{"/sys/bus/pci/devices"};
    std::error_code error;
    std::size_t pci_count = 0;
    std::size_t network_count = 0;
    std::vector<std::string> pci_entries;
    for (std::filesystem::directory_iterator item(pci_root, error), end;
         !error && item != end; item.increment(error)) {
        const std::string id = item->path().filename().string();
        const std::string class_code = read_text(item->path() / "class");
        const std::string vendor = read_text(item->path() / "vendor");
        const std::string device = read_text(item->path() / "device");
        const std::string driver = link_target(item->path() / "driver");
        ++pci_count;
        std::ostringstream entry;
        entry << id << "{class=" << (class_code.empty() ? "unknown" : class_code)
            << ",vendor=" << (vendor.empty() ? "unknown" : vendor)
            << ",device=" << (device.empty() ? "unknown" : device)
            << ",driver=" << (driver.empty() ? "unbound" : std::filesystem::path(driver).filename().string()) << '}';
        pci_entries.push_back(entry.str());
        if (class_code.starts_with("0x02")) ++network_count;
    }
    std::sort(pci_entries.begin(), pci_entries.end());
    std::ostringstream pci;
    for (std::size_t index = 0; index < pci_entries.size(); ++index) {
        if (index != 0) pci << ';';
        pci << pci_entries[index];
    }
    output.push_back({"bus", "pci_devices", error ? "unknown" : "available", pci_root.string(),
                      error ? "PCI inventory is unavailable" : std::to_string(pci_count) + " devices: " + pci.str()});
    output.push_back({"network", "pci_controllers", error ? "unknown" : "available", pci_root.string(),
                      error ? "PCI network inventory is unavailable" : std::to_string(network_count) + " class-02 controllers"});

    const std::filesystem::path net_root{"/sys/class/net"};
    error.clear();
    std::vector<std::string> interface_entries;
    std::size_t interface_count = 0;
    for (std::filesystem::directory_iterator item(net_root, error), end;
         !error && item != end; item.increment(error)) {
        ++interface_count;
        const std::string name = item->path().filename().string();
        const std::string device_path = link_target(item->path() / "device");
        interface_entries.push_back(name + "{device=" +
            (device_path.empty() ? "virtual-or-unavailable" : device_path) + "}");
    }
    std::sort(interface_entries.begin(), interface_entries.end());
    std::ostringstream interfaces;
    for (std::size_t index = 0; index < interface_entries.size(); ++index) {
        if (index != 0) interfaces << ';';
        interfaces << interface_entries[index];
    }
    output.push_back({"network", "interfaces", error ? "unknown" : "available", net_root.string(),
                      error ? "network interface inventory is unavailable" : std::to_string(interface_count) + " interfaces: " + interfaces.str()});

    const std::filesystem::path tpm_root{"/dev"};
    error.clear();
    std::vector<std::string> tpm_entries;
    std::size_t tpm_count = 0;
    for (std::filesystem::directory_iterator item(tpm_root, error), end;
         !error && item != end; item.increment(error)) {
        const std::string name = item->path().filename().string();
        const bool numbered_tpm = name.starts_with("tpm") &&
            (name.size() > 3 && std::all_of(name.begin() + 3, name.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; }));
        const bool resource_manager = name.starts_with("tpmrm") &&
            (name.size() > 5 && std::all_of(name.begin() + 5, name.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; }));
        if (!numbered_tpm && !resource_manager) continue;
        ++tpm_count;
        tpm_entries.push_back(name);
    }
    std::sort(tpm_entries.begin(), tpm_entries.end());
    std::ostringstream tpms;
    for (std::size_t index = 0; index < tpm_entries.size(); ++index) {
        if (index != 0) tpms << ';';
        tpms << tpm_entries[index];
    }
    output.push_back({"trust", "tpm_device_nodes", error ? "unknown" : (tpm_count ? "available" : "unavailable"),
                      tpm_root.string(), error ? "device inventory access failed" :
                      (tpm_count ? "nodes found: " + tpms.str() + "; TPM capabilities not attested" : "no TPM character device node found")});

    const std::filesystem::path rng_root{"/sys/class/misc/hw_random"};
    const std::string available_rngs = read_text(rng_root / "rng_available");
    const std::string current_rng = read_text(rng_root / "rng_current");
    output.push_back({"entropy", "hardware_rng", available_rngs.empty() ? "unavailable" : "available", rng_root.string(),
                      available_rngs.empty() ? "no hardware RNG list exposed; OpenSSL still uses its configured DRBG" :
                      "available=" + available_rngs + "; current=" + (current_rng.empty() ? "unknown" : current_rng) + "; output quality not tested"});

    const std::filesystem::path block_root{"/sys/class/block"};
    error.clear();
    std::vector<std::string> block_entries;
    std::size_t block_count = 0;
    for (std::filesystem::directory_iterator item(block_root, error), end;
         !error && item != end; item.increment(error)) {
        const std::string name = item->path().filename().string();
        ++block_count;
        std::ostringstream entry;
        entry << name << "{dev=" << read_text(item->path() / "dev")
              << ",ro=" << read_text(item->path() / "ro")
              << ",sectors=" << read_text(item->path() / "size") << '}';
        block_entries.push_back(entry.str());
    }
    std::sort(block_entries.begin(), block_entries.end());
    std::ostringstream blocks;
    for (std::size_t index = 0; index < block_entries.size(); ++index) {
        if (index != 0) blocks << ';';
        blocks << block_entries[index];
    }
    output.push_back({"storage", "block_devices", error ? "unknown" : "available", block_root.string(),
                      error ? "block device inventory is unavailable" : std::to_string(block_count) + " devices: " + blocks.str()});
}

#endif

} // namespace

std::string hardware_report_json() {
    std::vector<Capability> capabilities;
#if defined(__linux__)
    discover_boot(capabilities);
    discover_devices(capabilities);
    capabilities.push_back({"physical_security", "side_channel_controls", "not_assessed", "platform-specific validation",
                            "software inventory cannot establish physical resistance"});
    capabilities.push_back({"registers", "safe_register_inventory", "unsupported", "no platform register provider",
                            "requires a platform driver and an explicit read-only register allowlist"});
#else
    capabilities.push_back({"platform", "hardware_inventory", "unsupported", "no adapter for this operating system",
                            "capability provider interface is platform neutral; an OS adapter is required"});
#endif

    std::ostringstream json;
#if defined(__linux__)
    constexpr const char* platform = "linux";
#elif defined(_WIN32)
    constexpr const char* platform = "windows";
#elif defined(__APPLE__)
    constexpr const char* platform = "macos";
#else
    constexpr const char* platform = "unknown";
#endif
    json << "{\"schema_version\":1,\"platform\":" << quote_json(platform)
         << ",\"read_only\":true,\"capabilities\":[";
    for (std::size_t index = 0; index < capabilities.size(); ++index) {
        if (index != 0) json << ',';
        const Capability& item = capabilities[index];
        json << "{\"domain\":" << quote_json(item.domain)
             << ",\"name\":" << quote_json(item.name)
             << ",\"state\":" << quote_json(item.state)
             << ",\"source\":" << quote_json(item.source)
             << ",\"evidence\":" << quote_json(item.evidence) << '}';
    }
    json << "]}\n";
    return json.str();
}

} // namespace qprotect::cpp
