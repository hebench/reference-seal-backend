
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include <hebench/api_bridge/cpp/hebench.hpp>
#include <seal/seal.h>

#include "engine/seal_context.h"

namespace sbe {
namespace ckks {

class LogRegHornerBenchmarkDescription : public hebench::cpp::BenchmarkDescription
{
public:
    HEBERROR_DECLARE_CLASS_NAME(ckks::LogRegHornerBenchmarkDescription)
    static constexpr std::uint64_t DefaultBatchSize   = 100;
    static constexpr std::int64_t LogRegOtherID       = 0x01;
    static constexpr const char *AlgorithmName        = "HornerPolyEval";
    static constexpr const char *AlgorithmDescription = "Horner method for polynomial evaluation, single input vector per ciphertext";

    // other workload parameters
    static constexpr std::size_t DefaultNumThreads = 0; // 0 - use all available threads

    // Operation parameter indices
    enum : std::uint64_t
    {
        Index_OpParamsStart = 0,
        Index_W             = Index_OpParamsStart,
        Index_b,
        Index_X,
        NumOpParams
    };

    // Workload parameter indices
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
        NumWorkloadParams // This workload requires 1 parameters, and we add 4 encryption params
    };

    // encryption params
    static constexpr size_t DefaultPolyModulusDegree = 16384;
    //static constexpr const int coeff_modulus[] = { 60, 45, 45, 45, 45, 45, 60 };
    static constexpr std::size_t DefaultCoeffModulusBits    = 45;
    static constexpr std::size_t DefaultMultiplicativeDepth = 6;
    static constexpr std::size_t DefaultScaleBits           = DefaultCoeffModulusBits; // 2^45

public:
    LogRegHornerBenchmarkDescription(hebench::APIBridge::Category category, std::size_t batch_size = 0);
    ~LogRegHornerBenchmarkDescription() override;

    hebench::cpp::BaseBenchmark *createBenchmark(hebench::cpp::BaseEngine &engine,
                                                 const hebench::APIBridge::WorkloadParams *p_params) override;
    void destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench) override;
    std::string getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const override;
};

/**
 * @brief Benchmarks logistic regression inference.
 * @details Sigmoid activation using 3rd degree polynomial according to
 * workload type hebench::APIBridge::Workload::LogisticRegression_PolyD3.
 *
 * Polynomial evaluation performed using horner method.
 */
class LogRegHornerBenchmark : public hebench::cpp::BaseBenchmark
{
public:
    HEBERROR_DECLARE_CLASS_NAME(ckks::LogRegHornerBenchmark)

public:
    static constexpr std::int64_t tag = 0x1;

    LogRegHornerBenchmark(hebench::cpp::BaseEngine &engine,
                          const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                          const hebench::APIBridge::WorkloadParams &bench_params);
    ~LogRegHornerBenchmark() override;

    hebench::APIBridge::Handle encode(const hebench::APIBridge::DataPackCollection *p_parameters) override;
    void decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::DataPackCollection *p_native) override;
    hebench::APIBridge::Handle encrypt(hebench::APIBridge::Handle encoded_data) override;
    hebench::APIBridge::Handle decrypt(hebench::APIBridge::Handle encrypted_data) override;

    hebench::APIBridge::Handle load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;
    void store(hebench::APIBridge::Handle remote_data,
               hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;

    hebench::APIBridge::Handle operate(hebench::APIBridge::Handle h_remote_packed,
                                       const hebench::APIBridge::ParameterIndexer *p_param_indexers) override;

    std::int64_t classTag() const override { return BaseBenchmark::classTag() | LogRegHornerBenchmark::tag; }

private:
    typedef std::tuple<seal::Plaintext, seal::Plaintext, std::vector<seal::Plaintext>> EncodedOpParams;
    typedef std::tuple<seal::Ciphertext, seal::Ciphertext, std::vector<seal::Ciphertext>> EncryptedOpParams;

    static constexpr std::int64_t EncodedOpParamsTag   = 0x10;
    static constexpr std::int64_t EncryptedOpParamsTag = 0x20;
    static constexpr std::int64_t EncryptedResultTag   = 0x40;
    static constexpr std::int64_t EncodedResultTag     = 0x80;
    // coefficients for sigmoid polynomial approx
    static constexpr const double SigmoidPolyCoeff[] = { 0.5, 0.15012, 0.0, -0.0015930078125 };

    seal::Plaintext encodeW(const hebench::APIBridge::DataPack &data_pack);
    seal::Plaintext encodeBias(const hebench::APIBridge::DataPack &data_pack);
    std::vector<seal::Plaintext> encodeInputs(const hebench::APIBridge::DataPack &data_pack);

    SEALContextWrapper::Ptr m_p_ctx_wrapper;
    hebench::cpp::WorkloadParams::LogisticRegression m_w_params;
    std::vector<seal::Plaintext> m_plain_coeff; // encoded coefficients for sigmoid polynomial approx
    int m_num_threads;
};
} // namespace ckks
} // namespace sbe
