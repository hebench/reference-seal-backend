
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hebench/api_bridge/cpp/hebench.hpp"
#include "seal/seal.h"

#include "engine/seal_context.h"

namespace sbe {
namespace bfv {

class DotProductBenchmarkDescription : public hebench::cpp::BenchmarkDescription
{
public:
    HEBERROR_DECLARE_CLASS_NAME(DotProductBenchmarkDescription)
    static constexpr std::uint64_t NumWorkloadParams  = 1;
    static constexpr const char *AlgorithmName        = "Vector";
    static constexpr const char *AlgorithmDescription = "One vector per ciphertext";

    static constexpr std::size_t DefaultPolyModulusDegree   = 8192;
    static constexpr std::size_t DefaultMultiplicativeDepth = 2;
    static constexpr std::size_t DefaultCoeffModBits        = 45;
    static constexpr int DefaultPlainModulusBits            = 20;

public:
    DotProductBenchmarkDescription() {}
    DotProductBenchmarkDescription(hebench::APIBridge::Category category);
    ~DotProductBenchmarkDescription() override;

    hebench::cpp::BaseBenchmark *createBenchmark(hebench::cpp::BaseEngine &engine,
                                                 const hebench::APIBridge::WorkloadParams *p_params) override;
    void destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench) override;
    std::string getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const override;
};

class DotProductBenchmark : public hebench::cpp::BaseBenchmark
{
public:
    HEBERROR_DECLARE_CLASS_NAME(SEALDotProductBenchmark)

public:
    static constexpr std::int64_t tag = 0x1;

    DotProductBenchmark(hebench::cpp::BaseEngine &engine,
                        const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                        const hebench::APIBridge::WorkloadParams &bench_params);
    ~DotProductBenchmark() override;

    hebench::APIBridge::Handle encode(const hebench::APIBridge::PackedData *p_parameters) override;
    void decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::PackedData *p_native) override;
    hebench::APIBridge::Handle encrypt(hebench::APIBridge::Handle encoded_data) override;
    hebench::APIBridge::Handle decrypt(hebench::APIBridge::Handle encrypted_data) override;

    hebench::APIBridge::Handle load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;
    void store(hebench::APIBridge::Handle remote_data,
               hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;

    hebench::APIBridge::Handle operate(hebench::APIBridge::Handle h_remote_packed,
                                       const hebench::APIBridge::ParameterIndexer *p_param_indexers) override;

    std::int64_t classTag() const override { return BaseBenchmark::classTag() | DotProductBenchmark::tag; }

private:
    SEALContextWrapper::Ptr m_p_ctx_wrapper;
    unsigned int m_vector_size;
};
} // namespace bfv
} // namespace sbe
