#pragma once

#include "json_minimal.hpp"

namespace qprotect::cpp::detail {

/// Validate and normalize a JSON identity record to the qprotect field schema.
json::Value normalize_identity(const json::Value& input);

} // namespace qprotect::cpp::detail
