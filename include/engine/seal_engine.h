
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hebench/api_bridge/cpp/hebench.hpp"
#include "seal/seal.h"
#include "seal_types.h"
#include <memory>
#include <string>
#include <vector>

class SEALEngine : public hebench::cpp::BaseEngine
{
public:
    HEBERROR_DECLARE_CLASS_NAME(SEALEngine)
    static SEALEngine *create();
    static void destroy(SEALEngine *p);

    ~SEALEngine() override;

protected:
    SEALEngine();

    void init() override;
};
