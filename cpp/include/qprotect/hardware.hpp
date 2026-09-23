#pragma once

#include <string>

namespace qprotect::cpp {

/// Return a platform-neutral, read-only inventory of hardware-visible
/// capabilities. Values describe observed OS interfaces, not trust claims.
std::string hardware_report_json();

} // namespace qprotect::cpp
