
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hebench/api_bridge/cpp/hebench.hpp"
#include "seal/seal.h"

#include "engine/seal_context.h"

namespace sbe {
namespace ckks {

class DotProductBenchmarkDescription : public hebench::cpp::BenchmarkDescription
{
public:
    HEBERROR_DECLARE_CLASS_NAME(ckks::DotProductBenchmarkDescription)
    static constexpr const char *AlgorithmName        = "Vector";
    static constexpr const char *AlgorithmDescription = "One vector per ciphertext";
    static constexpr std::size_t NumOpParams          = 2;

    static constexpr std::size_t DefaultPolyModulusDegree   = 8192;
    static constexpr std::size_t DefaultMultiplicativeDepth = 2;
    static constexpr std::size_t DefaultCoeffModulusBits    = 40;
    static constexpr std::size_t DefaultScaleBits           = DefaultCoeffModulusBits;

    // other workload parameters
    static constexpr std::size_t DefaultNumThreads = 0; // 0 - use all available threads

    enum : std::uint64_t
    {
        Index_WParamsStart = 0,
        Index_n            = Index_WParamsStart,
        Index_ExtraWParamsStart,
        Index_PolyModulusDegree = Index_ExtraWParamsStart,
        Index_NumCoefficientModuli,
        Index_CoefficientModulusBits,
        Index_ScaleExponentBits,
        Index_NumThreads,
        NumWorkloadParams // This workload requires 1 parameters, and we add 5 encryption params
    };

public:
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
    HEBERROR_DECLARE_CLASS_NAME(ckks::DotProductBenchmark)

public:
    static constexpr std::int64_t tag = 0x1;

    DotProductBenchmark(hebench::cpp::BaseEngine &engine,
                        const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                        const hebench::APIBridge::WorkloadParams &bench_params);
    ~DotProductBenchmark() override;

    hebench::APIBridge::Handle encode(const hebench::APIBridge::DataPackCollection *p_parameters) override;
    void decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::DataPackCollection *p_native) override;
    hebench::APIBridge::Handle encrypt(hebench::APIBridge::Handle encoded_data) override;
    hebench::APIBridge::Handle decrypt(hebench::APIBridge::Handle encrypted_data) override;

    hebench::APIBridge::Handle load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;
    void store(hebench::APIBridge::Handle remote_data,
               hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;

    hebench::APIBridge::Handle operate(hebench::APIBridge::Handle h_remote_packed,
                                       const hebench::APIBridge::ParameterIndexer *p_param_indexers,
                                       std::uint64_t indexers_count) override;

    std::int64_t classTag() const override { return BaseBenchmark::classTag() | DotProductBenchmark::tag; }

private:
    SEALContextWrapper::Ptr m_p_ctx_wrapper;
    hebench::cpp::WorkloadParams::DotProduct m_w_params;
    int m_num_threads;
};
} // namespace ckks
} // namespace sbe
