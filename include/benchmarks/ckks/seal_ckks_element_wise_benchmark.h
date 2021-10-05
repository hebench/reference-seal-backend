
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hebench/api_bridge/cpp/hebench.hpp"
#include "seal/seal.h"

#include "engine/seal_context.h"

class SEALEngine;

namespace sbe {
namespace ckks {

enum ElementWiseOP
{
    ADD,
    MULTIPLY
};

class ElementWiseBenchmarkDescription : public hebench::cpp::BenchmarkDescription
{
public:
    HEBERROR_DECLARE_CLASS_NAME(ElementWiseBenchmarkDescription)
    static constexpr std::uint64_t NumWorkloadParams  = 1;
    static constexpr const char *AlgorithmName        = "Vector";
    static constexpr const char *AlgorithmDescription = "One vector per ciphertext";

    static constexpr std::size_t DefaultPolyModulusDegree   = 8192;
    static constexpr std::size_t DefaultMultiplicativeDepth = 2;
    static constexpr int DefaultScaleBits                   = 40;

public:
    ElementWiseBenchmarkDescription() {}
    ElementWiseBenchmarkDescription(hebench::APIBridge::Category category, ElementWiseOP op);
    ~ElementWiseBenchmarkDescription() override;

    hebench::cpp::BaseBenchmark *createBenchmark(hebench::cpp::BaseEngine &engine,
                                                 const hebench::APIBridge::WorkloadParams *p_params) override;
    void destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench) override;
    std::string getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const override;
};

class ElementWiseBenchmark : public hebench::cpp::BaseBenchmark
{
public:
    HEBERROR_DECLARE_CLASS_NAME(ElementWiseBenchmark)

public:
    static constexpr std::int64_t tag = 0x1;

    ElementWiseBenchmark(hebench::cpp::BaseEngine &engine,
                         const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                         const hebench::APIBridge::WorkloadParams &bench_params);
    ~ElementWiseBenchmark() override;

    hebench::APIBridge::Handle encode(const hebench::APIBridge::PackedData *p_parameters) override;
    void decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::PackedData *p_native) override;
    hebench::APIBridge::Handle encrypt(hebench::APIBridge::Handle encoded_data) override;
    hebench::APIBridge::Handle decrypt(hebench::APIBridge::Handle encrypted_data) override;

    hebench::APIBridge::Handle load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;
    void store(hebench::APIBridge::Handle remote_data,
               hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;

    hebench::APIBridge::Handle operate(hebench::APIBridge::Handle h_remote_packed,
                                       const hebench::APIBridge::ParameterIndexer *p_param_indexers) override;

    std::int64_t classTag() const override { return BaseBenchmark::classTag() | ElementWiseBenchmark::tag; }

private:
    //SEALEngine *m_seal_engine;
    SEALContextWrapper::Ptr m_p_ctx_wrapper;
    ElementWiseOP m_operation;
    unsigned int m_vector_size;
};

} // namespace ckks
} // namespace sbe
