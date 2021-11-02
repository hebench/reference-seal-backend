
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <omp.h>

#include "benchmarks/bfv/seal_bfv_matmult_row_benchmark.h"
#include "engine/seal_engine.h"
#include "engine/seal_types.h"

namespace sbe {
namespace bfv {

//--------------------------------------------------
// class MatMultRowBenchmarkDescription
//--------------------------------------------------

MatMultRowBenchmarkDescription::MatMultRowBenchmarkDescription()
{
    std::memset(&m_descriptor, 0, sizeof(hebench::APIBridge::BenchmarkDescriptor));
    m_descriptor.workload                                   = hebench::APIBridge::Workload::MatrixMultiply;
    m_descriptor.data_type                                  = hebench::APIBridge::DataType::Int64;
    m_descriptor.category                                   = hebench::APIBridge::Category::Latency;
    m_descriptor.cat_params.latency.warmup_iterations_count = 1;
    m_descriptor.cat_params.latency.min_test_time_ms        = 0;
    m_descriptor.cipher_param_mask                          = HEBENCH_HE_PARAM_FLAGS_ALL_CIPHER;
    m_descriptor.scheme                                     = HEBENCH_HE_SCHEME_BFV;
    m_descriptor.security                                   = HEBENCH_HE_SECURITY_128;
    m_descriptor.other                                      = MatMultRowOtherID;

    // specify default arguments for this workload flexible parameters:
    hebench::cpp::WorkloadParams::MatrixMultiply default_workload_params;
    default_workload_params.rows_M0 = 10;
    default_workload_params.cols_M0 = 9;
    default_workload_params.cols_M1 = 8;
    default_workload_params.add<std::uint64_t>(MatMultRowBenchmarkDescription::DefaultPolyModulusDegree, "PolyModulusDegree");
    default_workload_params.add<std::uint64_t>(MatMultRowBenchmarkDescription::DefaultMultiplicativeDepth, "MultiplicativeDepth");
    default_workload_params.add<std::uint64_t>(MatMultRowBenchmarkDescription::DefaultCoeffModulusBits, "CoefficientModulusBits");
    default_workload_params.add<std::uint64_t>(MatMultRowBenchmarkDescription::DefaultPlainModulusBits, "PlainModulusBits");
    this->addDefaultParameters(default_workload_params);
}

MatMultRowBenchmarkDescription::~MatMultRowBenchmarkDescription()
{
    //
}

hebench::cpp::BaseBenchmark *MatMultRowBenchmarkDescription::createBenchmark(hebench::cpp::BaseEngine &engine,
                                                                             const hebench::APIBridge::WorkloadParams *p_params)
{
    if (!p_params)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid empty workload parameters. Matrix Multiplication requires parameters."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    SEALEngine &seal_engine = dynamic_cast<SEALEngine &>(engine);
    return new MatMultRowLatencyBenchmark(seal_engine, m_descriptor, *p_params);
}

void MatMultRowBenchmarkDescription::destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench)
{
    if (p_bench)
        delete p_bench;
}

std::string MatMultRowBenchmarkDescription::getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const
{
    std::stringstream ss;
    std::string s_tmp = BenchmarkDescription::getBenchmarkDescription(p_w_params);

    if (!p_w_params)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid null workload parameters `p_w_params`"),
                                         HEBENCH_ECODE_INVALID_ARGS);

    assert(p_w_params->count >= MatMultRowBenchmarkDescription::NumWorkloadParams);

    std::uint64_t poly_modulus_degree  = p_w_params->params[MatMultRowBenchmarkDescription::Index_PolyModulusDegree].u_param;
    std::uint64_t multiplicative_depth = p_w_params->params[MatMultRowBenchmarkDescription::Index_NumCoefficientModuli].u_param;
    std::uint64_t coeff_mudulus_bits   = p_w_params->params[MatMultRowBenchmarkDescription::Index_CoefficientModulusBits].u_param;
    std::uint64_t plain_modulus_bits   = p_w_params->params[MatMultRowBenchmarkDescription::Index_PlainModulusBits].u_param;
    if (!s_tmp.empty())
        ss << s_tmp << std::endl;
    ss << ", Encryption Parameters" << std::endl
       << ", , Poly modulus degree, " << poly_modulus_degree << std::endl
       << ", , Coefficient Modulus, 60";
    for (std::size_t i = 1; i < multiplicative_depth; ++i)
        ss << ", " << coeff_mudulus_bits;
    ss << ", 60" << std::endl
       << ", , Plain Modulus, " << plain_modulus_bits << std::endl
       << ", Algorithm, " << AlgorithmName << ", " << AlgorithmDescription << std::endl;
    return ss.str();

    return ss.str();
}

//---------------------------------------
// class MatMultRowBenchmark
//---------------------------------------

MatMultRowLatencyBenchmark::MatMultRowLatencyBenchmark(hebench::cpp::BaseEngine &engine,
                                                       const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                                                       const hebench::APIBridge::WorkloadParams &bench_params) :
    hebench::cpp::BaseBenchmark(engine, bench_desc, bench_params),
    m_w_params(bench_params)
{
    if (bench_desc.workload != hebench::APIBridge::Workload::MatrixMultiply
        || bench_desc.data_type != hebench::APIBridge::DataType::Int64
        || bench_desc.category != hebench::APIBridge::Category::Latency
        || ((bench_desc.cipher_param_mask & 0x03) != 0x03)
        || bench_desc.scheme != HEBENCH_HE_SCHEME_BFV
        || bench_desc.security != HEBENCH_HE_SECURITY_128
        || bench_desc.other != MatMultRowBenchmarkDescription::MatMultRowOtherID)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Benchmark descriptor received is not supported."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::uint64_t poly_modulus_degree  = m_w_params.get<std::uint64_t>(MatMultRowBenchmarkDescription::Index_PolyModulusDegree);
    std::uint64_t multiplicative_depth = m_w_params.get<std::uint64_t>(MatMultRowBenchmarkDescription::Index_NumCoefficientModuli);
    std::uint64_t coeff_mudulus_bits   = m_w_params.get<std::uint64_t>(MatMultRowBenchmarkDescription::Index_CoefficientModulusBits);
    std::uint64_t plain_modulus_bits   = m_w_params.get<std::uint64_t>(MatMultRowBenchmarkDescription::Index_PlainModulusBits);

    if (m_w_params.rows_M0 <= 0 || m_w_params.cols_M0 <= 0 || m_w_params.cols_M1 <= 0)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Matrix dimensions must be greater than 0."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    if (coeff_mudulus_bits < 1)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Multiplicative depth must be greater than 0."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    m_p_ctx_wrapper = SEALContextWrapper::createBFVContext(poly_modulus_degree,
                                                           multiplicative_depth,
                                                           static_cast<int>(coeff_mudulus_bits),
                                                           static_cast<int>(plain_modulus_bits),
                                                           seal::sec_level_type::tc128);
}

MatMultRowLatencyBenchmark::~MatMultRowLatencyBenchmark()
{
}

hebench::APIBridge::Handle MatMultRowLatencyBenchmark::encode(const hebench::APIBridge::PackedData *p_parameters)
{
    // since this benchmark is cipher-cipher, encode receives 2 parameter packs from test harness

    if (p_parameters->pack_count != MatMultRowBenchmarkDescription::NumOpParams)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Expected 2 parameter packs, but " + std::to_string(p_parameters->pack_count) + " received."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // convert raw matrix data into mat[row][col] format

    std::array<std::vector<gsl::span<const std::int64_t>>, MatMultRowBenchmarkDescription::NumOpParams> mats;
    for (std::uint64_t op_param_i = 0; op_param_i < MatMultRowBenchmarkDescription::NumOpParams; ++op_param_i)
    {
        std::uint64_t mat_rows, mat_cols;
        switch (op_param_i)
        {
        case 1:
            mat_rows = m_w_params.cols_M0;
            mat_cols = m_w_params.cols_M1;
            break;

        default:
            mat_rows = m_w_params.rows_M0;
            mat_cols = m_w_params.cols_M0;
            break;
        } // end switch

        std::vector<gsl::span<const std::int64_t>> &mat = mats[op_param_i];
        mat.resize(mat_rows);

        const hebench::APIBridge::DataPack &data_pack_mat = findDataPack(*p_parameters, op_param_i);
        if (data_pack_mat.buffer_count < 1)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Latency test requires, at least, 1 sample per operation parameter. None found for operation parameter 0."),
                                             HEBENCH_ECODE_INVALID_ARGS);
        // - for latency operation, we have a single sample per data pack
        if (!data_pack_mat.p_buffers || !data_pack_mat.p_buffers[0].p)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty buffer in data pack."),
                                             HEBENCH_ECODE_CRITICAL_ERROR);

        gsl::span<std::int64_t> raw_mat =
            gsl::span<std::int64_t>(reinterpret_cast<std::int64_t *>(data_pack_mat.p_buffers[0].p),
                                    data_pack_mat.p_buffers[0].size / sizeof(std::int64_t));
        if (raw_mat.size() < mat_rows * mat_cols)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Insufficient data for parameter 0 sample."),
                                             HEBENCH_ECODE_CRITICAL_ERROR);

        for (std::uint64_t row_i = 0; row_i < mat.size(); row_i++)
            mat[row_i] = gsl::span<std::int64_t>(&raw_mat[row_i * mat_cols], mat_cols);
    } // end for

    // do the actual encode
    std::pair<OpParamSampleM0Plain, OpParamSampleM1Plain> retval =
        std::make_pair(encodeM0(mats[0], m_w_params.rows_M0, m_w_params.cols_M0, m_w_params.cols_M1),
                       encodeM1(mats[1], m_w_params.cols_M0, m_w_params.cols_M1));

    // return encoded data as handle
    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

MatMultRowLatencyBenchmark::OpParamSampleM0Plain MatMultRowLatencyBenchmark::encodeM0(const std::vector<gsl::span<const std::int64_t>> &mat,
                                                                                      std::size_t dim1, std::size_t dim2, std::size_t dim3)
{
    assert(mat.size() >= dim1 && mat.front().size() >= dim2);

    std::size_t encoder_row_size = m_p_ctx_wrapper->BFVEncoder()->slot_count() / 2;

    // cleartext vector for holding rows of Matrix-A at a time
    std::vector<std::int64_t> cleartext_vec_a(m_p_ctx_wrapper->BFVEncoder()->slot_count(), 0);

    // Spaces normally == slots / dim 2. But now row_size since using batching encoder
    size_t spacers = encoder_row_size / dim2;

    // a container for each of Matrix-A's rows in their own plaintext
    std::vector<std::vector<int64_t>> vec_container_a;
    for (std::size_t i = 0; i < dim1; i += 2)
    {
        for (std::size_t j = 0; j < dim2; j++)
        {
            for (std::size_t k = 0; k < dim3; k++)
            {
                cleartext_vec_a[spacers * j + k] = mat[i][j];
                if (i + 1 < dim1)
                    cleartext_vec_a[encoder_row_size + (spacers * j + k)] = mat[i + 1][j];
            }
        }
        vec_container_a.push_back(cleartext_vec_a);
    }

    // Encoding vectors of input into plaintext vectors
    // (For Matrix A, one for every two rows)
    std::vector<seal::Plaintext> vec_pt_a(vec_container_a.size());
    for (size_t i = 0; i < vec_container_a.size(); i++)
        m_p_ctx_wrapper->BFVEncoder()->encode(vec_container_a[i], vec_pt_a[i]);

    // return vec_pt_a;
    OpParamSampleM0Plain retval;
    retval.dims.rows = dim1;
    retval.dims.cols = dim2;
    retval.data      = std::make_shared<decltype(vec_pt_a)>(std::move(vec_pt_a));

    return retval;
}

MatMultRowLatencyBenchmark::OpParamSampleM1Plain MatMultRowLatencyBenchmark::encodeM1(const std::vector<gsl::span<const std::int64_t>> &mat,
                                                                                      std::size_t dim2, std::size_t dim3)
{
    assert(mat.size() >= dim2 && mat.front().size() >= dim3);

    std::size_t encoder_row_size = m_p_ctx_wrapper->BFVEncoder()->slot_count() / 2;

    // cleartext vector for holding rows of Matrix-B at a time
    std::vector<std::int64_t> cleartext_vec_b(m_p_ctx_wrapper->BFVEncoder()->slot_count(), 0);

    // Spaces normally == slots / dim 2. But now row_size since using batching encoder
    size_t spacers = encoder_row_size / dim2;

    for (std::size_t j = 0; j < dim2; j++)
    {
        for (std::size_t k = 0; k < dim3; k++)
        {
            cleartext_vec_b[spacers * j + k]                      = mat[j][k];
            cleartext_vec_b[encoder_row_size + (spacers * j + k)] = mat[j][k];
        }
    }

    seal::Plaintext pt_b;
    m_p_ctx_wrapper->BFVEncoder()->encode(cleartext_vec_b, pt_b);

    //return pt_b;
    OpParamSampleM1Plain retval;
    retval.dims.rows = dim2;
    retval.dims.cols = dim3;
    retval.data      = std::make_shared<decltype(pt_b)>(std::move(pt_b));

    return retval;
}

void MatMultRowLatencyBenchmark::decode(hebench::APIBridge::Handle h_encoded_data, hebench::APIBridge::PackedData *p_native)
{
    // supports decoding of OpResultSamplePlain only

    if (p_native->pack_count > 0)
    {
        if (!p_native->p_data_packs)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty 'p_native->p_data_packs'."),
                                             HEBENCH_ECODE_CRITICAL_ERROR);

        hebench::APIBridge::DataPack &result_component = findDataPack(*p_native, 0);
        if (result_component.buffer_count > 0 && result_component.p_buffers[0].p)
        {
            OpResultSamplePlain &encoded =
                this->getEngine().retrieveFromHandle<OpResultSamplePlain>(h_encoded_data);
            if (!encoded.data)
                throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty handle 'h_encoded_data'."),
                                                 HEBENCH_ECODE_CRITICAL_ERROR);

            std::vector<std::vector<std::int64_t>> clear_result =
                decodeResult(*encoded.data, encoded.dims.rows, encoded.dims.cols);

            gsl::span<std::int64_t> result_raw =
                gsl::span<std::int64_t>(reinterpret_cast<std::int64_t *>(result_component.p_buffers[0].p),
                                        result_component.p_buffers[0].size / sizeof(int64_t));

            // size of data pointed may be more or less than required to hold the result, so,
            // copy as much as we can
            gsl::span<std::int64_t> result_raw_row = result_raw;
            for (auto row_it = clear_result.begin(); !result_raw_row.empty() && row_it != clear_result.end(); ++row_it)
            {
                std::size_t min_size = std::min(row_it->size(), result_raw_row.size());
                std::copy_n(row_it->begin(), min_size, result_raw_row.begin());
                // point span to next row
                result_raw_row = result_raw_row.last(result_raw_row.size() - min_size);
            }
        } // end if
    } // end if
}

std::vector<std::vector<std::int64_t>> MatMultRowLatencyBenchmark::decodeResult(std::vector<seal::Plaintext> vec_pt_res,
                                                                                std::size_t dim1, std::size_t dim3)
{
    std::size_t encoder_row_size = m_p_ctx_wrapper->BFVEncoder()->slot_count() / 2;

    std::vector<std::vector<std::int64_t>> ret_mat(dim1, std::vector<std::int64_t>(dim3));
    std::vector<std::vector<std::int64_t>> vec_container_res;
    std::vector<std::int64_t> vec_result(m_p_ctx_wrapper->BFVEncoder()->slot_count(), 0);

    for (size_t i = 0; i < vec_pt_res.size(); i += 2)
    {
        m_p_ctx_wrapper->BFVEncoder()->decode(vec_pt_res[i], vec_result);
        vec_container_res.push_back(vec_result);
        if (i + 1 < vec_pt_res.size())
        {
            m_p_ctx_wrapper->BFVEncoder()->decode(vec_pt_res[i + 1], vec_result);
            vec_container_res.push_back(vec_result);
        }
    }

    for (std::size_t i = 0; i < dim1; i += 2)
    {
        for (std::size_t j = 0; j < dim3; j++)
        {
            ret_mat[i][j] = vec_container_res[i / 2][j];
            if (i + 1 < dim1)
                ret_mat[i + 1][j] = vec_container_res[i / 2][j + encoder_row_size];
        }
    }
    return ret_mat;
}

hebench::APIBridge::Handle MatMultRowLatencyBenchmark::encrypt(hebench::APIBridge::Handle h_encoded_data)
{
    // supports encryption of std::pair<OpParamSampleM0Plain, OpParamSampleM1Plain> only

    const std::pair<OpParamSampleM0Plain, OpParamSampleM1Plain> &encoded =
        this->getEngine().retrieveFromHandle<std::pair<OpParamSampleM0Plain, OpParamSampleM1Plain>>(h_encoded_data);
    const OpParamSampleM0Plain &m0_plain = encoded.first;
    const OpParamSampleM1Plain &m1_plain = encoded.second;

    std::pair<OpParamSampleM0Cipher, OpParamSampleM1Cipher> retval =
        std::make_pair(OpParamSampleM0Cipher(m0_plain.dims.rows, m0_plain.dims.cols, m0_plain.data->size()),
                       OpParamSampleM1Cipher(m1_plain.dims.rows, m1_plain.dims.cols));
    OpParamSampleM0Cipher &m0_cipher = retval.first;
    OpParamSampleM1Cipher &m1_cipher = retval.second;

    // m0
    for (std::size_t i = 0; i < m0_plain.data->size(); ++i)
        m_p_ctx_wrapper->encryptor()->encrypt(m0_plain.data->at(i), m0_cipher.data->at(i));
    // m1
    m_p_ctx_wrapper->encryptor()->encrypt(*m1_plain.data, *m1_cipher.data);

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

hebench::APIBridge::Handle MatMultRowLatencyBenchmark::decrypt(hebench::APIBridge::Handle h_encrypted_data)
{
    // supports decryption of OpResultSampleCipher only

    const OpResultSampleCipher &encrypted =
        this->getEngine().retrieveFromHandle<OpResultSampleCipher>(h_encrypted_data);

    OpResultSamplePlain retval(encrypted.dims.rows, encrypted.dims.cols, encrypted.data->size());
    for (std::size_t i = 0; i < encrypted.data->size(); ++i)
    {
        m_p_ctx_wrapper->decrypt(encrypted.data->at(i), retval.data->at(i));
    } // end for

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

hebench::APIBridge::Handle MatMultRowLatencyBenchmark::load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count)
{
    // supports only loading pair<OpParamSampleM0Cipher, OpParamSampleM1Cipher>

    if (count != 1)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Expected only 1 local handle to load."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // remote host is same as local host, so, just copy the data
    // (shared_ptr ensures data is shallow copied and properly destroyed when needed)

    std::pair<OpParamSampleM0Cipher, OpParamSampleM1Cipher> retval =
        this->getEngine().retrieveFromHandle<std::pair<OpParamSampleM0Cipher, OpParamSampleM1Cipher>>(p_local_data[0]);

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

void MatMultRowLatencyBenchmark::store(hebench::APIBridge::Handle h_remote_data,
                                       hebench::APIBridge::Handle *p_h_local_data,
                                       std::uint64_t count)
{
    // Supports only storing OpResultSampleCipher

    if (count > 0)
    {
        // remote host is same as local host, so, just copy the data
        // (shared_ptr ensures data is shallow copied and properly destroyed when needed)
        p_h_local_data[0] = this->getEngine().duplicateHandle(h_remote_data);
    } // end if
}

hebench::APIBridge::Handle MatMultRowLatencyBenchmark::operate(hebench::APIBridge::Handle h_remote_packed,
                                                               const hebench::APIBridge::ParameterIndexer *p_param_indexers)
{
    // this method does not support indexing portions of the batch
    for (std::size_t i = 0; i < MatMultRowBenchmarkDescription::NumOpParams; ++i)
    {
        if (p_param_indexers[i].value_index > 0)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected index in parameter indexer."),
                                             HEBENCH_ECODE_INVALID_ARGS);
        if (p_param_indexers[i].batch_size != 1)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Batch size must be 1 for latency test."),
                                             HEBENCH_ECODE_INVALID_ARGS);
    } // end for

    const std::pair<OpParamSampleM0Cipher, OpParamSampleM1Cipher> &inputs =
        this->getEngine().retrieveFromHandle<std::pair<OpParamSampleM0Cipher, OpParamSampleM1Cipher>>(h_remote_packed);

    assert(inputs.first.dims.cols == inputs.second.dims.rows);

    OpResultSampleCipher retval;
    retval.dims.rows = inputs.first.dims.rows;
    retval.dims.cols = inputs.second.dims.cols;
    retval.data      = std::make_shared<std::vector<seal::Ciphertext>>(
        matmultrow(*inputs.first.data, *inputs.second.data, inputs.first.dims.cols));

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

std::vector<seal::Ciphertext> MatMultRowLatencyBenchmark::matmultrow(const std::vector<seal::Ciphertext> &A,
                                                                     const seal::Ciphertext &B,
                                                                     std::size_t dim2)
{
    std::size_t encoder_row_size = m_p_ctx_wrapper->BFVEncoder()->slot_count() / 2;

    std::vector<seal::Ciphertext> result(A.size());
    //std::vector<seal::Ciphertext> base_ct_res = result;
    std::vector<seal::Ciphertext> base_ct_res(A.size()); // avoids the copy of empty ciphertexts
    // Spaces normally == slots / dim 2. But now row_size since using batching encoder
    int spacers = static_cast<int>(encoder_row_size) / dim2;

    int num_threads = omp_get_max_threads();
    int threads_at_level[2];
    threads_at_level[0] = static_cast<int>(A.size());
    if (threads_at_level[0] > num_threads)
        threads_at_level[0] = num_threads;
    threads_at_level[1] = num_threads / threads_at_level[0];
    if (threads_at_level[1] < 1)
        threads_at_level[1] = 1;

    const int old_max_active_levels = omp_get_max_active_levels();
    const int old_nested_value      = omp_get_nested();
    omp_set_nested(true);
    omp_set_max_active_levels(2);

#pragma omp parallel for num_threads(threads_at_level[0])
    for (std::size_t i = 0; i < A.size(); i++)
    {
        m_p_ctx_wrapper->evaluator()->multiply(A[i], B, base_ct_res[i], seal::MemoryPoolHandle::ThreadLocal());
        m_p_ctx_wrapper->evaluator()->relinearize_inplace(base_ct_res[i], m_p_ctx_wrapper->relinKeys(), seal::MemoryPoolHandle::ThreadLocal());

        // Rotating by step * spacer
        result[i] = base_ct_res[i];
        std::mutex mtx;
#pragma omp parallel for num_threads(threads_at_level[1])
        for (std::size_t j = 1; j < dim2; j++)
        {
            seal::Ciphertext rotated;
            m_p_ctx_wrapper->evaluator()->rotate_rows(base_ct_res[i],
                                                      j * spacers,
                                                      m_p_ctx_wrapper->galoisKeys(),
                                                      rotated,
                                                      seal::MemoryPoolHandle::ThreadLocal());
            std::scoped_lock<std::mutex> lock(mtx);
            m_p_ctx_wrapper->evaluator()->add_inplace(result[i], rotated);
        }
    }

    omp_set_max_active_levels(old_max_active_levels);
    omp_set_nested(old_nested_value);

    return result;
}

} // namespace bfv
} // namespace sbe
