
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <memory>
#include <utility>
#include <vector>

#include "engine/seal_context.h"
#include <hebench/api_bridge/cpp/hebench.hpp>

namespace sbe {
namespace bfv {

class MatMultRowBenchmarkDescription : public hebench::cpp::BenchmarkDescription
{
public:
    HEBERROR_DECLARE_CLASS_NAME(bfv::MatMultRowBenchmarkDescription)
public:
    static constexpr std::int64_t MatMultRowOtherID   = 0x02;
    static constexpr std::uint64_t NumOpParams        = 2; // number of operation parameters
    static constexpr const char *AlgorithmName        = "MatMulRow";
    static constexpr const char *AlgorithmDescription = "";

    // encryption params
    static constexpr std::size_t DefaultPolyModulusDegree   = 8192;
    static constexpr std::size_t DefaultMultiplicativeDepth = 3;
    static constexpr std::size_t DefaultCoeffModulusBits    = 40;
    static constexpr std::size_t DefaultPlainModulusBits    = 20;

    // other workload parameters
    static constexpr std::size_t DefaultNumThreads = 0; // 0 - use all available threads

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
        Index_NumThreads,
        NumWorkloadParams // This workload requires 3 parameters, and we add 4 encryption params
    };

public:
    MatMultRowBenchmarkDescription();
    ~MatMultRowBenchmarkDescription() override;

    hebench::cpp::BaseBenchmark *createBenchmark(hebench::cpp::BaseEngine &engine,
                                                 const hebench::APIBridge::WorkloadParams *p_params) override;
    void destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench) override;
    std::string getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const override;
};

class MatMultRowLatencyBenchmark final : public hebench::cpp::BaseBenchmark
{
public:
    HEBERROR_DECLARE_CLASS_NAME(bfv::MatMultRowBenchmark)

public:
    static constexpr std::int64_t tag = 0x1;

    MatMultRowLatencyBenchmark(hebench::cpp::BaseEngine &engine,
                               const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                               const hebench::APIBridge::WorkloadParams &bench_params);
    ~MatMultRowLatencyBenchmark() override;

    hebench::APIBridge::Handle encode(const hebench::APIBridge::PackedData *p_parameters) override;
    void decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::PackedData *p_native) override;
    hebench::APIBridge::Handle encrypt(hebench::APIBridge::Handle encoded_data) override;
    hebench::APIBridge::Handle decrypt(hebench::APIBridge::Handle encrypted_data) override;

    hebench::APIBridge::Handle load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;
    void store(hebench::APIBridge::Handle remote_data,
               hebench::APIBridge::Handle *p_local_data, std::uint64_t count) override;

    hebench::APIBridge::Handle operate(hebench::APIBridge::Handle h_remote_packed,
                                       const hebench::APIBridge::ParameterIndexer *p_param_indexers) override;

    std::int64_t classTag() const override { return BaseBenchmark::classTag() | MatMultRowLatencyBenchmark::tag; }

private:
    struct MatrixDims
    {
        std::uint64_t rows;
        std::uint64_t cols;
    };

    template <class T>
    struct OpParamSampleM0
    {
    public:
        OpParamSampleM0()
        {
            dims.rows = 0;
            dims.cols = 0;
        }
        OpParamSampleM0(std::uint64_t rows, std::uint64_t cols, std::size_t count)
        {
            dims.rows = rows;
            dims.cols = cols;
            data      = std::make_shared<std::vector<T>>(count);
        }
        MatrixDims dims;
        std::shared_ptr<std::vector<T>> data;
    };
    typedef OpParamSampleM0<seal::Plaintext> OpParamSampleM0Plain;
    typedef OpParamSampleM0<seal::Ciphertext> OpParamSampleM0Cipher;
    typedef OpParamSampleM0<seal::Plaintext> OpResultSamplePlain;
    typedef OpParamSampleM0<seal::Ciphertext> OpResultSampleCipher;

    template <class T>
    struct OpParamSampleM1
    {
    public:
        OpParamSampleM1()
        {
            dims.rows = 0;
            dims.cols = 0;
            data      = std::make_shared<T>();
        }
        OpParamSampleM1(std::uint64_t rows, std::uint64_t cols)
        {
            dims.rows = rows;
            dims.cols = cols;
            data      = std::make_shared<T>();
        }

        MatrixDims dims;
        std::shared_ptr<T> data;
    };
    typedef OpParamSampleM1<seal::Plaintext> OpParamSampleM1Plain;
    typedef OpParamSampleM1<seal::Ciphertext> OpParamSampleM1Cipher;

    OpParamSampleM0Plain encodeM0(const std::vector<gsl::span<const std::int64_t>> &mat,
                                  std::size_t dim1, std::size_t dim2, std::size_t dim3);
    OpParamSampleM1Plain encodeM1(const std::vector<gsl::span<const std::int64_t>> &mat,
                                  std::size_t dim2, std::size_t dim3);
    std::vector<seal::Ciphertext> matmultrow(const std::vector<seal::Ciphertext> &A,
                                             const seal::Ciphertext &B,
                                             std::size_t dim2);
    std::vector<std::vector<std::int64_t>> decodeResult(std::vector<seal::Plaintext> vec_pt_res,
                                                        std::size_t dim1, std::size_t dim3);

    SEALContextWrapper::Ptr m_p_ctx_wrapper;
    hebench::cpp::WorkloadParams::MatrixMultiply m_w_params;
    int m_num_threads;
};

} // namespace bfv
} // namespace sbe
