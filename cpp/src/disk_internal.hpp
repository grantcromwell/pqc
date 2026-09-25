#pragma once

#include <string>

namespace qprotect::cpp::detail {

/// Validate a captured lsblk JSON report before any destructive operation.
void validate_lsblk_safety_json(const std::string& report,
                                const std::string& expected_device,
                                unsigned int expected_major,
                                unsigned int expected_minor);

} // namespace qprotect::cpp::detail
