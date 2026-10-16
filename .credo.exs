# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Credo's defaults, with the scripts added to the files it checks.
%{
  configs: [
    %{
      name: "default",
      files: %{included: ["lib/", "test/", "scripts/"]}
    }
  ]
}
