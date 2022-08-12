
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>
#include <mutex>
#include <omp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "benchmarks/bfv/seal_bfv_matmult_cipherbatchaxis_benchmark.h"
#include "engine/seal_engine.h"
#include "engine/seal_types.h"

namespace sbe {
namespace bfv {

//--------------------------------------------------
// class MatMultCipherBatchAxisBenchmarkDescription
//--------------------------------------------------

MatMultCipherBatchAxisBenchmarkDescription::MatMultCipherBatchAxisBenchmarkDescription()
{
    std::memset(&m_descriptor, 0, sizeof(hebench::APIBridge::BenchmarkDescriptor));
    m_descriptor.workload                                   = hebench::APIBridge::Workload::MatrixMultiply;
    m_descriptor.data_type                                  = hebench::APIBridge::DataType::Int64;
    m_descriptor.category                                   = hebench::APIBridge::Category::Latency;
    m_descriptor.cat_params.latency.warmup_iterations_count = 1;
    m_descriptor.cat_params.min_test_time_ms                = 0;
    m_descriptor.cipher_param_mask                          = HEBENCH_HE_PARAM_FLAGS_ALL_CIPHER;
    m_descriptor.scheme                                     = HEBENCH_HE_SCHEME_BFV;
    m_descriptor.security                                   = HEBENCH_HE_SECURITY_128;
    m_descriptor.other                                      = MatMultOtherID;

    // specify default arguments for this workload flexible parameters:
    hebench::cpp::WorkloadParams::MatrixMultiply default_workload_params;
    default_workload_params.rows_M0() = 10;
    default_workload_params.cols_M0() = 9;
    default_workload_params.cols_M1() = 8;
    default_workload_params.add<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::DefaultPolyModulusDegree, "PolyModulusDegree");
    default_workload_params.add<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::DefaultMultiplicativeDepth, "MultiplicativeDepth");
    default_workload_params.add<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::DefaultCoeffModulusBits, "CoefficientModulusBits");
    default_workload_params.add<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::DefaultPlainModulusBits, "PlainModulusBits");
    default_workload_params.add<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::DefaultNumThreads, "NumThreads");
    this->addDefaultParameters(default_workload_params);
}

MatMultCipherBatchAxisBenchmarkDescription::~MatMultCipherBatchAxisBenchmarkDescription()
{
    //
}

hebench::cpp::BaseBenchmark *MatMultCipherBatchAxisBenchmarkDescription::createBenchmark(hebench::cpp::BaseEngine &engine,
                                                                                         const hebench::APIBridge::WorkloadParams *p_params)
{
    if (!p_params)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid empty workload parameters. Matrix Multiplication requires parameters."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    if ((m_descriptor.cipher_param_mask & 0x03) == 0x03) // all cipher
    {
        SEALEngine &seal_engine = dynamic_cast<SEALEngine &>(engine);
        return new MatMultCipherBatchAxisBenchmark(seal_engine,
                                                   m_descriptor,
                                                   *p_params);
    }
    else
    {
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Cipher/plain combination of operation parameters requested is not supported."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    } // end else
}

void MatMultCipherBatchAxisBenchmarkDescription::destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench)
{
    if (p_bench)
        delete p_bench;
}

std::string MatMultCipherBatchAxisBenchmarkDescription::getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const
{
    std::stringstream ss;
    std::string s_tmp = BenchmarkDescription::getBenchmarkDescription(p_w_params);

    if (!p_w_params)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid null workload parameters `p_w_params`"),
                                         HEBENCH_ECODE_INVALID_ARGS);

    assert(p_w_params->count >= MatMultCipherBatchAxisBenchmarkDescription::NumWorkloadParams);

    std::uint64_t poly_modulus_degree  = p_w_params->params[MatMultCipherBatchAxisBenchmarkDescription::Index_PolyModulusDegree].u_param;
    std::uint64_t multiplicative_depth = p_w_params->params[MatMultCipherBatchAxisBenchmarkDescription::Index_NumCoefficientModuli].u_param;
    std::uint64_t coeff_mudulus_bits   = p_w_params->params[MatMultCipherBatchAxisBenchmarkDescription::Index_CoefficientModulusBits].u_param;
    std::uint64_t plain_modulus_bits   = p_w_params->params[MatMultCipherBatchAxisBenchmarkDescription::Index_PlainModulusBits].u_param;
    std::uint64_t num_threads          = p_w_params->params[MatMultCipherBatchAxisBenchmarkDescription::Index_NumThreads].u_param;
    if (num_threads <= 0)
        num_threads = omp_get_max_threads();
    if (!s_tmp.empty())
        ss << s_tmp << std::endl;
    ss << ", Encryption Parameters" << std::endl
       << ", , Poly modulus degree, " << poly_modulus_degree << std::endl
       << ", , Coefficient Modulus, 60";
    for (std::size_t i = 1; i < multiplicative_depth; ++i)
        ss << ", " << coeff_mudulus_bits;
    ss << ", 60" << std::endl
       << ", , Plain Modulus, " << plain_modulus_bits << std::endl
       << ", Algorithm, " << AlgorithmName << ", " << AlgorithmDescription << std::endl
       << ", Number of threads, " << num_threads;

    return ss.str();
}

//---------------------------------------
// class MatMultCipherBatchAxisBenchmark
//---------------------------------------

MatMultCipherBatchAxisBenchmark::MatMultCipherBatchAxisBenchmark(hebench::cpp::BaseEngine &engine,
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
        || bench_desc.other != MatMultCipherBatchAxisBenchmarkDescription::MatMultOtherID)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Benchmark descriptor received is not supported."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::uint64_t poly_modulus_degree  = m_w_params.get<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::Index_PolyModulusDegree);
    std::uint64_t multiplicative_depth = m_w_params.get<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::Index_NumCoefficientModuli);
    std::uint64_t coeff_mudulus_bits   = m_w_params.get<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::Index_CoefficientModulusBits);
    std::uint64_t plain_modulus_bits   = m_w_params.get<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::Index_PlainModulusBits);
    m_num_threads                      = static_cast<int>(m_w_params.get<std::uint64_t>(MatMultCipherBatchAxisBenchmarkDescription::Index_NumThreads));
    if (m_num_threads <= 0)
        m_num_threads = omp_get_max_threads();

    if (m_w_params.rows_M0() <= 0 || m_w_params.cols_M0() <= 0 || m_w_params.cols_M1() <= 0)
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

MatMultCipherBatchAxisBenchmark::~MatMultCipherBatchAxisBenchmark()
{
}

hebench::APIBridge::Handle MatMultCipherBatchAxisBenchmark::encode(const hebench::APIBridge::DataPackCollection *p_parameters)
{
    // since this benchmark is cipher-cipher, encode receives 2 parameter packs from test harness

    if (p_parameters->pack_count != MatMultCipherBatchAxisBenchmarkDescription::NumOpParams)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Expected 2 parameter packs, but " + std::to_string(p_parameters->pack_count) + " received."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::vector<OpParamSamplePlain> retval;
    // - for latency operation, we have a single sample per data pack
    retval.emplace_back(m_w_params.rows_M0(), m_w_params.cols_M0()); // op param 0
    retval.emplace_back(m_w_params.cols_M0(), m_w_params.cols_M1()); // op param 1

    for (std::uint64_t op_param_i = 0; op_param_i < MatMultCipherBatchAxisBenchmarkDescription::NumOpParams; ++op_param_i)
    {
        // find data pack corresponding to this op parameter
        hebench::APIBridge::DataPack *p_data_pack = nullptr;
        for (std::uint64_t data_pack_i = 0; !p_data_pack && data_pack_i < p_parameters->pack_count; ++data_pack_i)
            if (p_parameters->p_data_packs[op_param_i].param_position == op_param_i)
                p_data_pack = &p_parameters->p_data_packs[op_param_i];
        if (!p_data_pack)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Operation parameter " + std::to_string(op_param_i) + " not found in 'p_parameters'."),
                                             HEBENCH_ECODE_INVALID_ARGS);
        if (p_data_pack->buffer_count < 1)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Latency test requires, at least, 1 sample per operation parameter. None found for operation parameter " + std::to_string(op_param_i) + "."),
                                             HEBENCH_ECODE_INVALID_ARGS);
        if (!p_data_pack->p_buffers)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty buffer in data pack."),
                                             HEBENCH_ECODE_CRITICAL_ERROR);

        gsl::span<std::int64_t> data_buffer =
            gsl::span<std::int64_t>(reinterpret_cast<std::int64_t *>(p_data_pack->p_buffers[0].p),
                                    p_data_pack->p_buffers[0].size / sizeof(std::int64_t));
        for (std::uint64_t col_i = 0; col_i < retval[op_param_i].cols(); ++col_i)
        {
            for (std::uint64_t row_i = 0; row_i < retval[op_param_i].rows(); ++row_i)
            {
                // encode this op param in column major format (incoming raw is row major)
                gsl::span<std::int64_t> clear_value = gsl::span<std::int64_t>(&data_buffer[row_i * retval[op_param_i].cols() + col_i], 1);
                seal::Plaintext &plain_encoded      = retval[op_param_i].at(row_i, col_i);
                m_p_ctx_wrapper->BFVEncoder()->encode(clear_value, plain_encoded);
            } // end for
        } // end for
    } // end for

    // return encoded data as handle
    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

void MatMultCipherBatchAxisBenchmark::decode(hebench::APIBridge::Handle h_encoded_data, hebench::APIBridge::DataPackCollection *p_native)
{
    if (p_native->pack_count > 0)
    {
        if (!p_native->p_data_packs)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty 'p_native->p_data_packs'."),
                                             HEBENCH_ECODE_CRITICAL_ERROR);

        std::vector<OpParamSamplePlain> &encoded =
            this->getEngine().retrieveFromHandle<std::vector<OpParamSamplePlain>>(h_encoded_data);

        for (std::size_t op_param_i = 0; op_param_i < encoded.size(); ++op_param_i)
        {
            // find data pack corresponding to this op parameter
            hebench::APIBridge::DataPack *p_data_pack = nullptr;
            for (std::uint64_t data_pack_i = 0; !p_data_pack && data_pack_i < p_native->pack_count; ++data_pack_i)
                if (p_native->p_data_packs[op_param_i].param_position == op_param_i)
                    p_data_pack = &p_native->p_data_packs[op_param_i];
            if (p_data_pack && p_data_pack->buffer_count > 0)
            {
                if (!p_data_pack->p_buffers)
                    throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty buffer in data pack."),
                                                     HEBENCH_ECODE_CRITICAL_ERROR);

                if (p_data_pack->p_buffers[0].size > 0)
                {
                    if (!p_data_pack->p_buffers[0].p)
                        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty buffer in data pack."),
                                                         HEBENCH_ECODE_CRITICAL_ERROR);
                    gsl::span<std::int64_t> result_clear =
                        gsl::span<std::int64_t>(reinterpret_cast<std::int64_t *>(p_data_pack->p_buffers[0].p),
                                                p_data_pack->p_buffers[0].size / sizeof(std::int64_t));
                    // decode as much as we can (coverting from column major to row major)
                    auto it = result_clear.begin();
                    for (std::uint64_t row_i = 0; it != result_clear.end() && row_i < encoded[op_param_i].rows(); ++row_i)
                    {
                        for (std::uint64_t col_i = 0; it != result_clear.end() && col_i < encoded[op_param_i].cols(); ++col_i)
                        {
                            std::vector<std::int64_t> clear_decoded;
                            m_p_ctx_wrapper->BFVEncoder()->decode(encoded[op_param_i].at(row_i, col_i), clear_decoded);

                            *it = clear_decoded.empty() ? 0 : clear_decoded.front();
                            ++it;
                        } // end for
                    } // end for
                } // end if
            } // end if
        } // end if
    } // end if
}

hebench::APIBridge::Handle MatMultCipherBatchAxisBenchmark::encrypt(hebench::APIBridge::Handle h_encoded_data)
{
    std::vector<OpParamSamplePlain> &encoded =
        this->getEngine().retrieveFromHandle<std::vector<OpParamSamplePlain>>(h_encoded_data);

    std::vector<OpParamSampleCipher> retval;
    for (auto plain_it = encoded.begin(); plain_it != encoded.end(); ++plain_it)
    {
        retval.emplace_back(plain_it->rows(), plain_it->cols());
        for (std::uint64_t col_i = 0; col_i < plain_it->cols(); ++col_i)
        {
            for (std::uint64_t row_i = 0; row_i < plain_it->rows(); ++row_i)
            {
                m_p_ctx_wrapper->encryptor()->encrypt(plain_it->at(row_i, col_i), retval.back().at(row_i, col_i));
            } // end for
        } // end for
    } // end for

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

hebench::APIBridge::Handle MatMultCipherBatchAxisBenchmark::decrypt(hebench::APIBridge::Handle h_encrypted_data)
{
    std::vector<OpParamSampleCipher> &encrypted =
        this->getEngine().retrieveFromHandle<std::vector<OpParamSampleCipher>>(h_encrypted_data);

    std::vector<OpParamSamplePlain> retval;
    for (auto cipher_it = encrypted.begin(); cipher_it != encrypted.end(); ++cipher_it)
    {
        retval.emplace_back(cipher_it->rows(), cipher_it->cols());
        for (std::uint64_t col_i = 0; col_i < cipher_it->cols(); ++col_i)
        {
            for (std::uint64_t row_i = 0; row_i < cipher_it->rows(); ++row_i)
            {
                m_p_ctx_wrapper->decrypt(cipher_it->at(row_i, col_i), retval.back().at(row_i, col_i));
            } // end for
        } // end for
    } // end for

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

hebench::APIBridge::Handle MatMultCipherBatchAxisBenchmark::load(const hebench::APIBridge::Handle *p_local_data, std::uint64_t count)
{
    // remote host is same as local host, so, just copy the data
    // (shared_ptr ensures data is shallow copied and properly destroyed when needed)

    std::vector<OpParamSampleCipher> retval;
    for (std::uint64_t i = 0; i < count; ++i)
    {
        std::vector<OpParamSampleCipher> &encrypted =
            this->getEngine().retrieveFromHandle<std::vector<OpParamSampleCipher>>(p_local_data[i]);
        retval.insert(retval.end(), encrypted.begin(), encrypted.end());
    } // end for

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

void MatMultCipherBatchAxisBenchmark::store(hebench::APIBridge::Handle h_remote_data,
                                            hebench::APIBridge::Handle *p_h_local_data,
                                            std::uint64_t count)
{
    // remote host is same as local host, so, just copy the data
    assert(count == 0 || p_h_local_data);
    if (count > 0)
    {
        // pad with zeros any excess local handles as per specifications
        std::memset(p_h_local_data, 0, sizeof(hebench::APIBridge::Handle) * count);

        // since remote and host are the same, we just need to return a copy
        // of the remote as local data.
        p_h_local_data[0] = this->getEngine().duplicateHandle(h_remote_data);
    } // end if
}

hebench::APIBridge::Handle MatMultCipherBatchAxisBenchmark::operate(hebench::APIBridge::Handle h_remote_packed,
                                                                    const hebench::APIBridge::ParameterIndexer *p_param_indexers)
{
    for (std::size_t i = 0; i < MatMultCipherBatchAxisBenchmarkDescription::NumOpParams; ++i)
    {
        if (p_param_indexers[i].value_index > 0)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected index in parameter indexer."),
                                             HEBENCH_ECODE_INVALID_ARGS);
        if (p_param_indexers[i].batch_size > 1)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Batch size must be 1 for latency test."),
                                             HEBENCH_ECODE_INVALID_ARGS);
    } // end for

    std::vector<OpParamSampleCipher> &remote =
        this->getEngine().retrieveFromHandle<std::vector<OpParamSampleCipher>>(h_remote_packed);

    if (remote.size() < 2)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Insufficient number of arguments for operation parameters."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    const OpParamSampleCipher &m0 = remote[0];
    const OpParamSampleCipher &m1 = remote[1];
    std::vector<OpParamSampleCipher> retval;
    retval.emplace_back(m0.rows(), m1.cols());
    OpParamSampleCipher &m = retval.back();

    std::mutex mtx;
    std::exception_ptr p_ex;
#pragma omp parallel for collapse(2) num_threads(m_num_threads)
    for (size_t out_ind0 = 0; out_ind0 < m0.rows(); ++out_ind0)
    {
        for (size_t out_ind1 = 0; out_ind1 < m1.cols(); ++out_ind1)
        {
            try
            {
                if (!p_ex)
                {
                    seal::Ciphertext &out = m.at(out_ind0, out_ind1);
                    for (size_t inner_dim = 0; inner_dim < m0.cols(); inner_dim++)
                    {
                        const seal::Ciphertext &arg1 = m0.at(out_ind0, inner_dim);
                        const seal::Ciphertext &arg2 = m1.at(inner_dim, out_ind1);

                        if (inner_dim == 0)
                        {
                            m_p_ctx_wrapper->evaluator()->multiply(arg1, arg2, out);
                            m_p_ctx_wrapper->evaluator()->relinearize_inplace(out, m_p_ctx_wrapper->relinKeys());
                        }
                        else
                        {
                            seal::Ciphertext tmp;
                            m_p_ctx_wrapper->evaluator()->multiply(arg1, arg2, tmp);
                            m_p_ctx_wrapper->evaluator()->relinearize_inplace(tmp, m_p_ctx_wrapper->relinKeys());
                            m_p_ctx_wrapper->evaluator()->add_inplace(out, tmp);
                        }
                    }
                } // end if
            }
            catch (...)
            {
                std::scoped_lock<std::mutex> lock(mtx);
                if (!p_ex)
                    p_ex = std::current_exception();
            }
        }
    }
    if (p_ex)
        std::rethrow_exception(p_ex);

    return this->getEngine().createHandle<decltype(retval)>(sizeof(retval),
                                                            0,
                                                            std::move(retval));
}

} // namespace bfv
} // namespace sbe
