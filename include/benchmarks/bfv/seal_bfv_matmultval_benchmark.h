
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <memory>
#include <utility>
#include <vector>

#include "engine/seal_context.h"
#include "hebench/api_bridge/cpp/hebench.hpp"

namespace sbe {
namespace bfv {

class MatMultValBenchmarkDescription : public hebench::cpp::BenchmarkDescription
{
public:
    HEBERROR_DECLARE_CLASS_NAME(bfv::MatMultValBenchmarkDescription)
public:
    static constexpr std::int64_t MatMultValOtherID   = 0;
    static constexpr std::uint64_t NumOpParams        = 2; // number of operation parameters
    static constexpr const char *AlgorithmName        = "MatMultVal";
    static constexpr const char *AlgorithmDescription = "One matrix row per ciphertext, Encode transposes second matrix";

    // HE specific parameters
    static constexpr std::size_t DefaultPolyModulusDegree   = 8192;
    static constexpr std::size_t DefaultMultiplicativeDepth = 2;
    static constexpr std::size_t DefaultCoeffModulusBits    = 40;
    static constexpr std::size_t DefaultPlainModulusBits    = 20;

    enum : std::uint64_t
    {
        Index_WParamsStart = 0,
        Index_rows_M0      = Index_WParamsStart,
        Index_cols_M0,
        Index_cols_M1,
        Index_ExtraWParamsStart,
        Index_PolyModulusDegree = Index_ExtraWParamsStart,
        Index_NumCoefficientModuli,
        Index_CoefficientModulusBits,
        Index_PlainModulusBits,
        NumWorkloadParams // This workload requires 3 parameters, and we add 4 encryption params
    };

    MatMultValBenchmarkDescription();
    ~MatMultValBenchmarkDescription() override;

    std::string getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const override;

    hebench::cpp::BaseBenchmark *createBenchmark(hebench::cpp::BaseEngine &engine,
                                                 const hebench::APIBridge::WorkloadParams *p_params) override;
    void destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench) override;
};

class MatMultValBenchmark : public hebench::cpp::BaseBenchmark
{
public:
    HEBERROR_DECLARE_CLASS_NAME(bfv::MatMultValBenchmark)

public:
    static constexpr std::int64_t tag = 0x20 + MatMultValBenchmarkDescription::MatMultValOtherID;

    MatMultValBenchmark(hebench::cpp::BaseEngine &engine,
                        const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                        const hebench::APIBridge::WorkloadParams &bench_params);
    ~MatMultValBenchmark() override;

    hebench::APIBridge::Handle encode(const hebench::APIBridge::PackedData *p_parameters) override;
    void decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::PackedData *p_native) override;
    hebench::APIBridge::Handle encrypt(hebench::APIBridge::Handle encoded_data) override;
    hebench::APIBridge::Handle decrypt(hebench::APIBridge::Handle encrypted_data) override;

    hebench::APIBridge::Handle load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;
    void store(hebench::APIBridge::Handle remote_data,
               hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;

    hebench::APIBridge::Handle operate(hebench::APIBridge::Handle h_remote_packed,
                                       const hebench::APIBridge::ParameterIndexer *p_param_indexers) override;

    std::int64_t classTag() const override { return BaseBenchmark::classTag() | MatMultValBenchmark::tag; }

private:
    static constexpr std::uint64_t ParametersCount       = 2; // number of parameters for this operation
    static constexpr std::uint64_t ResultComponentsCount = 1; // number of components of result for this operation

    static constexpr std::int64_t tagEncodedResult   = 0x20;
    static constexpr std::int64_t tagEncryptedResult = 0x10;

    template <class T>
    struct InternalMatrix
    {
    public:
        InternalMatrix(std::uint64_t param_position = 0) :
            m_param_position(param_position)
        {
            m_p_rows = std::make_shared<std::vector<T>>();
        }
        const std::vector<T> &rows() const { return *m_p_rows; }
        std::vector<T> &rows() { return *m_p_rows; }
        std::uint64_t paramPosition() const { return m_param_position; }

    private:
        std::shared_ptr<std::vector<T>> m_p_rows;
        std::uint64_t m_param_position;
    };

    typedef InternalMatrix<seal::Plaintext> InternalMatrixPlain;
    typedef InternalMatrix<seal::Ciphertext> InternalMatrixCipher;

    static std::vector<std::vector<std::int64_t>> prepareMatrix(const hebench::APIBridge::NativeDataBuffer &buffer,
                                                                std::uint64_t rows, std::uint64_t cols);
    std::vector<seal::Plaintext> encodeMatrix(const std::vector<std::vector<std::int64_t>> &data);
    std::vector<seal::Plaintext> encodeM0(const std::vector<std::vector<std::int64_t>> &data);
    std::vector<seal::Plaintext> encodeM1(const std::vector<std::vector<std::int64_t>> &data);
    std::vector<seal::Ciphertext> encryptMatrix(const std::vector<seal::Plaintext> &plain);
    std::vector<std::vector<seal::Ciphertext>>
    doMatMultVal(const std::vector<seal::Ciphertext> &M0,
                 const std::vector<seal::Ciphertext> &M1_T);

    SEALContextWrapper::Ptr m_p_ctx_wrapper;
    hebench::cpp::WorkloadParams::MatrixMultiply m_w_params;
};

} // namespace bfv
} // namespace sbe
