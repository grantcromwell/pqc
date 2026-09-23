#pragma once

#include <string>

namespace qprotect::cpp::detail {

/// Validate a captured lsblk JSON report before any destructive operation.
void validate_lsblk_safety_json(const std::string& report);

} // namespace qprotect::cpp::detail
