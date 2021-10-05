#!/bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

echo "Checking output from Test Harness..."
if ! grep -Fxq "[ Info    ] Failed: 0" test_harness_output.log
then
    echo "Validation Failed"
    exit 1
fi
echo "Validation PASSED"
