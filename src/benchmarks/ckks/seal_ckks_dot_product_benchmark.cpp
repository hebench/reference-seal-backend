
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <vector>

#include <omp.h>

#include "benchmarks/ckks/seal_ckks_dot_product_benchmark.h"
#include "engine/seal_types.h"

using namespace sbe::ckks;

//-----------------------------------
// class DotProductBenchmarkDescription
//-----------------------------------

DotProductBenchmarkDescription::DotProductBenchmarkDescription(hebench::APIBridge::Category category)
{
    // initialize the descriptor for this benchmark
    std::memset(&m_descriptor, 0, sizeof(hebench::APIBridge::BenchmarkDescriptor));
    m_descriptor.data_type = hebench::APIBridge::DataType::Float64;
    m_descriptor.category  = category;
    switch (category)
    {
    case hebench::APIBridge::Category::Latency:
        m_descriptor.cat_params.latency.min_test_time_ms        = 0; // 2s
        m_descriptor.cat_params.latency.warmup_iterations_count = 1;
        break;

    case hebench::APIBridge::Category::Offline:
        m_descriptor.cat_params.offline.data_count[0] = 0;
        m_descriptor.cat_params.offline.data_count[1] = 0;
        break;

    default:
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid category received."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    }
    m_descriptor.cipher_param_mask = HEBENCH_HE_PARAM_FLAGS_ALL_CIPHER;
    //
    m_descriptor.scheme   = HEBENCH_HE_SCHEME_CKKS;
    m_descriptor.security = HEBENCH_HE_SECURITY_128;
    m_descriptor.other    = 0; // no extra parameters
    m_descriptor.workload = hebench::APIBridge::Workload::DotProduct;

    hebench::cpp::WorkloadParams::DotProduct default_workload_params;
    default_workload_params.n = 100;
    default_workload_params.add<std::uint64_t>(DotProductBenchmarkDescription::DefaultPolyModulusDegree, "PolyModulusDegree");
    default_workload_params.add<std::uint64_t>(DotProductBenchmarkDescription::DefaultMultiplicativeDepth, "MultiplicativeDepth");
    default_workload_params.add<std::uint64_t>(DotProductBenchmarkDescription::DefaultCoeffModulusBits, "CoefficientModulusBits");
    default_workload_params.add<std::uint64_t>(DotProductBenchmarkDescription::DefaultScaleBits, "ScaleBits");
    default_workload_params.add<std::uint64_t>(DotProductBenchmarkDescription::DefaultNumThreads, "NumThreads");
    this->addDefaultParameters(default_workload_params);
}

DotProductBenchmarkDescription::~DotProductBenchmarkDescription()
{
    // nothing needed in this example
}

hebench::cpp::BaseBenchmark *DotProductBenchmarkDescription::createBenchmark(hebench::cpp::BaseEngine &engine, const hebench::APIBridge::WorkloadParams *p_params)
{
    return new DotProductBenchmark(engine, m_descriptor, *p_params);
}

void DotProductBenchmarkDescription::destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench)
{
    if (p_bench)
        delete p_bench;
}

std::string DotProductBenchmarkDescription::getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const
{
    std::stringstream ss;
    std::string s_tmp = BenchmarkDescription::getBenchmarkDescription(p_w_params);

    if (!p_w_params)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid null workload parameters `p_w_params`"),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::uint64_t poly_modulus_degree  = p_w_params->params[DotProductBenchmarkDescription::Index_PolyModulusDegree].u_param;
    std::uint64_t multiplicative_depth = p_w_params->params[DotProductBenchmarkDescription::Index_NumCoefficientModuli].u_param;
    std::uint64_t coeff_mudulus_bits   = p_w_params->params[DotProductBenchmarkDescription::Index_CoefficientModulusBits].u_param;
    std::uint64_t scale_bits           = p_w_params->params[DotProductBenchmarkDescription::Index_ScaleExponentBits].u_param;
    std::uint64_t num_threads          = p_w_params->params[DotProductBenchmarkDescription::Index_NumThreads].u_param;
    if (m_descriptor.category == hebench::APIBridge::Category::Latency)
        num_threads = 1;
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
       << ", , Scale, 2^" << scale_bits << std::endl
       << ", Algorithm, " << AlgorithmName << ", " << AlgorithmDescription << std::endl
       << ", Number of threads, " << num_threads;

    return ss.str();
}

//------------------------
// class DotProductBenchmark
//------------------------

DotProductBenchmark::DotProductBenchmark(hebench::cpp::BaseEngine &engine,
                                         const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                                         const hebench::APIBridge::WorkloadParams &bench_params) :
    hebench::cpp::BaseBenchmark(engine, bench_desc, bench_params),
    m_w_params(bench_params)
{
    assert(bench_params.count >= DotProductBenchmarkDescription::NumWorkloadParams);

    if (m_w_params.n <= 0)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Vector size must be greater than 0."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::uint64_t poly_modulus_degree  = m_w_params.get<std::uint64_t>(DotProductBenchmarkDescription::Index_PolyModulusDegree);
    std::uint64_t multiplicative_depth = m_w_params.get<std::uint64_t>(DotProductBenchmarkDescription::Index_NumCoefficientModuli);
    std::uint64_t coeff_mudulus_bits   = m_w_params.get<std::uint64_t>(DotProductBenchmarkDescription::Index_CoefficientModulusBits);
    std::uint64_t scale_bits           = m_w_params.get<std::uint64_t>(DotProductBenchmarkDescription::Index_ScaleExponentBits);
    m_num_threads                      = static_cast<int>(m_w_params.get<std::uint64_t>(DotProductBenchmarkDescription::Index_NumThreads));
    if (this->getDescriptor().category == hebench::APIBridge::Category::Latency)
        m_num_threads = 1; // override threads to 1 for latency, since threading is on batch size
    if (m_num_threads <= 0)
        m_num_threads = omp_get_max_threads();

    if (coeff_mudulus_bits < 1)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Multiplicative depth must be greater than 0."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    m_p_ctx_wrapper        = SEALContextWrapper::createCKKSContext(poly_modulus_degree,
                                                            multiplicative_depth,
                                                            static_cast<int>(coeff_mudulus_bits),
                                                            static_cast<int>(scale_bits),
                                                            seal::sec_level_type::tc128);
    std::size_t slot_count = m_p_ctx_wrapper->CKKSEncoder()->slot_count();
    if (m_w_params.n > slot_count)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Vector size cannot be greater than " + std::to_string(slot_count) + "."),
                                         HEBENCH_ECODE_INVALID_ARGS);
}

DotProductBenchmark::~DotProductBenchmark()
{
    // nothing needed in this example
}

hebench::APIBridge::Handle DotProductBenchmark::encode(const hebench::APIBridge::PackedData *p_parameters)
{
    if (p_parameters->pack_count != DotProductBenchmarkDescription::NumOpParams)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid number of parameters detected in parameter pack. Expected 2."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // allocate our internal version of the encoded data

    // We are using shared_ptr because we want to be able to copy the pointer object later
    // and use the reference counter to avoid leaving dangling. If our internal object
    // does not need to be copied, shared_ptr is not really needed.

    std::vector<std::vector<seal::Plaintext>> params;

    params.resize(p_parameters->pack_count);
    const unsigned int params_size = params.size();
    for (unsigned int x = 0; x < params_size; ++x)
    {
        params[x].resize(p_parameters->p_data_packs[x].buffer_count);
    }

    std::vector<double> values;
    values.resize(m_w_params.n);
    for (unsigned int x = 0; x < params.size(); ++x)
    {
        for (unsigned int y = 0; y < params[x].size(); ++y)
        {
            const hebench::APIBridge::DataPack &parameter = p_parameters->p_data_packs[x];
            // take first sample from parameter (because latency test has a single sample per parameter)
            const hebench::APIBridge::NativeDataBuffer &sample = parameter.p_buffers[y];
            // convert the native data to pointer to double as per specification of workload
            const double *p_row = reinterpret_cast<const double *>(sample.p);
            for (unsigned int x = 0; x < m_w_params.n; ++x)
            {
                values[x] = p_row[x];
            }
            params[x][y] = m_p_ctx_wrapper->encodeVector(values);
        }
    }
    return this->getEngine().createHandle<decltype(params)>(sizeof(params),
                                                            0,
                                                            std::move(params));
}

void DotProductBenchmark::decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::PackedData *p_native)
{
    // retrieve our internal format object from the handle
    const std::vector<seal::Plaintext> &params =
        this->getEngine().retrieveFromHandle<std::vector<seal::Plaintext>>(encoded_data);

    const size_t params_size = params.size();
    for (size_t result_i = 0; result_i < params_size; ++result_i)
    {
        double *output_location = reinterpret_cast<double *>(p_native->p_data_packs[0].p_buffers[result_i].p);
        std::vector<double> result_vec;
        m_p_ctx_wrapper->CKKSEncoder()->decode(params[result_i], result_vec);
        if (std::abs(result_vec.front()) < 0.00005)
            output_location[0] = 0;
        else
            output_location[0] = result_vec.front();
    }
}

hebench::APIBridge::Handle DotProductBenchmark::encrypt(hebench::APIBridge::Handle encoded_data)
{
    // retrieve our internal format object from the handle
    const std::vector<std::vector<seal::Plaintext>> &encoded_data_ref =
        this->getEngine().retrieveFromHandle<std::vector<std::vector<seal::Plaintext>>>(encoded_data);

    std::vector<std::vector<seal::Ciphertext>> encrypted_data;

    encrypted_data.resize(encoded_data_ref.size());
    for (unsigned int param_i = 0; param_i < encoded_data_ref.size(); param_i++)
    {
        encrypted_data[param_i].resize(encoded_data_ref[param_i].size());
        for (unsigned int parameter_sample = 0; parameter_sample < encoded_data_ref[param_i].size(); parameter_sample++)
        {
            m_p_ctx_wrapper->encryptor()->encrypt(encoded_data_ref[param_i][parameter_sample], encrypted_data[param_i][parameter_sample]);
        }
    }

    return this->getEngine().createHandle<decltype(encrypted_data)>(sizeof(encrypted_data),
                                                                    0,
                                                                    std::move(encrypted_data));
}

hebench::APIBridge::Handle DotProductBenchmark::decrypt(hebench::APIBridge::Handle encrypted_data)
{
    if ((encrypted_data.tag & hebench::cpp::EngineObject::tag) == 0)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid tag detected. Expected EngineObject::tag."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // retrieve our internal format object from the handle
    std::vector<seal::Ciphertext> &encrypted_data_ref =
        this->getEngine().retrieveFromHandle<std::vector<seal::Ciphertext>>(encrypted_data);

    std::vector<seal::Plaintext> plaintext_data;
    plaintext_data.resize(encrypted_data_ref.size());

    for (unsigned int res_count = 0; res_count < encrypted_data_ref.size(); ++res_count)
    {
        plaintext_data[res_count] = m_p_ctx_wrapper->decrypt(encrypted_data_ref[res_count]);
    }

    return this->getEngine().createHandle<decltype(plaintext_data)>(sizeof(plaintext_data),
                                                                    0,
                                                                    std::move(plaintext_data));
}

hebench::APIBridge::Handle DotProductBenchmark::load(const hebench::APIBridge::Handle *p_local_data, uint64_t count)
{
    assert(count == 0 || p_local_data);
    if (count != 1)
        // we do all ops in plain text, so, we should get only one pack of data
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid number of handles. Expected 1."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    return this->getEngine().duplicateHandle(p_local_data[0]);
}

void DotProductBenchmark::store(hebench::APIBridge::Handle remote_data,
                                hebench::APIBridge::Handle *p_local_data, std::uint64_t count)
{
    assert(count == 0 || p_local_data);
    if (count > 0)
    {
        // pad with zeros any excess local handles as per specifications
        std::memset(p_local_data, 0, sizeof(hebench::APIBridge::Handle) * count);

        // since remote and host are the same, we just need to return a copy
        // of the remote as local data.
        p_local_data[0] = this->getEngine().duplicateHandle(remote_data);
    } // end if
}

hebench::APIBridge::Handle DotProductBenchmark::operate(hebench::APIBridge::Handle h_remote_packed,
                                                        const hebench::APIBridge::ParameterIndexer *p_param_indexers)
{
    // retrieve our internal format object from the handle
    const std::vector<std::vector<seal::Ciphertext>> &params =
        this->getEngine().retrieveFromHandle<std::vector<std::vector<seal::Ciphertext>>>(h_remote_packed);

    // create a new internal object for result
    std::vector<seal::Ciphertext> result;

    // perform the actual operation
    result.resize(p_param_indexers[0].batch_size * p_param_indexers[1].batch_size);
    std::mutex mtx;
    std::exception_ptr p_ex;
#pragma omp parallel for collapse(2) num_threads(m_num_threads)
    for (uint64_t result_i = 0; result_i < p_param_indexers[0].batch_size; result_i++)
    {
        for (uint64_t result_x = 0; result_x < p_param_indexers[1].batch_size; result_x++)
        {
            try
            {
                if (!p_ex)
                {
                    auto &result_cipher = result[result_i * p_param_indexers[1].batch_size + result_x];
                    m_p_ctx_wrapper->evaluator()->multiply(params[0][p_param_indexers[0].value_index + result_i],
                                                           params[1][p_param_indexers[1].value_index + result_x],
                                                           result_cipher,
                                                           seal::MemoryPoolHandle::ThreadLocal());
                    m_p_ctx_wrapper->evaluator()->relinearize_inplace(result_cipher, m_p_ctx_wrapper->relinKeys(), seal::MemoryPoolHandle::ThreadLocal());
                    result_cipher = m_p_ctx_wrapper->accumulateCKKS(result_cipher, m_w_params.n);
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

    return this->getEngine().createHandle<decltype(result)>(sizeof(result),
                                                            0,
                                                            std::move(result));
}
