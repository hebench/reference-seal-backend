
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

#include "benchmarks/bfv/seal_bfv_element_wise_benchmark.h"
#include "engine/seal_engine.h"

using namespace sbe::bfv;

//------------------------
// class ElementWiseBenchmarkDescription
//------------------------

ElementWiseBenchmarkDescription::ElementWiseBenchmarkDescription(hebench::APIBridge::Category category, hebench::APIBridge::Workload op)
{
    if (op != hebench::APIBridge::Workload::EltwiseAdd
        && op != hebench::APIBridge::Workload::EltwiseMultiply)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Workload operation not supported."),
                                         HEBENCH_ECODE_CRITICAL_ERROR);

    // initialize the descriptor for this benchmark
    std::memset(&m_descriptor, 0, sizeof(hebench::APIBridge::BenchmarkDescriptor));
    m_descriptor.workload  = op;
    m_descriptor.data_type = hebench::APIBridge::DataType::Int64;
    m_descriptor.category  = category;
    switch (category)
    {
    case hebench::APIBridge::Category::Latency:
        m_descriptor.cat_params.latency.min_test_time_ms        = 0; // any
        m_descriptor.cat_params.latency.warmup_iterations_count = 1;
        break;

    case hebench::APIBridge::Category::Offline:
        m_descriptor.cat_params.offline.data_count[0] = 0; // flexible
        m_descriptor.cat_params.offline.data_count[1] = 0;
        break;

    default:
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid category received."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    }
    m_descriptor.cipher_param_mask = HEBENCH_HE_PARAM_FLAGS_ALL_CIPHER;
    //
    m_descriptor.scheme   = HEBENCH_HE_SCHEME_BFV;
    m_descriptor.security = HEBENCH_HE_SECURITY_128;
    m_descriptor.other    = 0; // no extra parameters

    hebench::cpp::WorkloadParams::VectorSize default_workload_params;
    default_workload_params.n = 1000;
    default_workload_params.add<std::uint64_t>(ElementWiseBenchmarkDescription::DefaultPolyModulusDegree, "PolyModulusDegree");
    default_workload_params.add<std::uint64_t>(ElementWiseBenchmarkDescription::DefaultMultiplicativeDepth, "MultiplicativeDepth");
    default_workload_params.add<std::uint64_t>(ElementWiseBenchmarkDescription::DefaultCoeffModulusBits, "CoefficientModulusBits");
    default_workload_params.add<std::uint64_t>(ElementWiseBenchmarkDescription::DefaultPlainModulusBits, "PlainModulusBits");
    this->addDefaultParameters(default_workload_params);
}

ElementWiseBenchmarkDescription::~ElementWiseBenchmarkDescription()
{
    // nothing needed in this example
}

hebench::cpp::BaseBenchmark *ElementWiseBenchmarkDescription::createBenchmark(hebench::cpp::BaseEngine &engine, const hebench::APIBridge::WorkloadParams *p_params)
{
    SEALEngine &ex_engine = dynamic_cast<SEALEngine &>(engine);
    return new ElementWiseBenchmark(ex_engine, m_descriptor, *p_params);
}

void ElementWiseBenchmarkDescription::destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench)
{
    if (p_bench)
        delete p_bench;
}

std::string ElementWiseBenchmarkDescription::getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const
{
    std::stringstream ss;
    std::string s_tmp = BenchmarkDescription::getBenchmarkDescription(p_w_params);

    if (!p_w_params)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid null workload parameters `p_w_params`"),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::uint64_t poly_modulus_degree  = p_w_params->params[ElementWiseBenchmarkDescription::Index_PolyModulusDegree].u_param;
    std::uint64_t multiplicative_depth = p_w_params->params[ElementWiseBenchmarkDescription::Index_NumCoefficientModuli].u_param;
    std::uint64_t coeff_mudulus_bits   = p_w_params->params[ElementWiseBenchmarkDescription::Index_CoefficientModulusBits].u_param;
    std::uint64_t plain_modulus_bits   = p_w_params->params[ElementWiseBenchmarkDescription::Index_PlainModulusBits].u_param;
    if (!s_tmp.empty())
        ss << s_tmp << std::endl;
    ss << ", Encryption Parameters" << std::endl
       << ", , Poly modulus degree, " << poly_modulus_degree << std::endl
       << ", , Coefficient Modulus, 60";
    for (std::size_t i = 1; i < multiplicative_depth; ++i)
        ss << ", " << coeff_mudulus_bits;
    ss << ", 60" << std::endl
       << ", , Plain Text Modulus Bits, " << plain_modulus_bits << std::endl
       << ", Algorithm, " << AlgorithmName << ", " << AlgorithmDescription;

    return ss.str();
}

//------------------------
// class ElementWiseBenchmark
//------------------------

ElementWiseBenchmark::ElementWiseBenchmark(hebench::cpp::BaseEngine &engine,
                                           const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                                           const hebench::APIBridge::WorkloadParams &bench_params) :
    hebench::cpp::BaseBenchmark(engine, bench_desc, bench_params),
    m_w_params(bench_params)
{
    assert(bench_params.count >= ElementWiseBenchmarkDescription::NumWorkloadParams);

    if (m_w_params.n <= 0)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Vector size must be greater than 0."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::uint64_t poly_modulus_degree  = m_w_params.get<std::uint64_t>(ElementWiseBenchmarkDescription::Index_PolyModulusDegree);
    std::uint64_t multiplicative_depth = m_w_params.get<std::uint64_t>(ElementWiseBenchmarkDescription::Index_NumCoefficientModuli);
    std::uint64_t coeff_mudulus_bits   = m_w_params.get<std::uint64_t>(ElementWiseBenchmarkDescription::Index_CoefficientModulusBits);
    std::uint64_t plain_modulus_bits   = m_w_params.get<std::uint64_t>(ElementWiseBenchmarkDescription::Index_PlainModulusBits);

    if (coeff_mudulus_bits < 1)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Multiplicative depth must be greater than 0."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    m_p_ctx_wrapper        = SEALContextWrapper::createBFVContext(poly_modulus_degree,
                                                           multiplicative_depth,
                                                           static_cast<int>(coeff_mudulus_bits),
                                                           static_cast<int>(plain_modulus_bits),
                                                           seal::sec_level_type::tc128);
    std::size_t slot_count = m_p_ctx_wrapper->BFVEncoder()->slot_count();
    if (m_w_params.n > slot_count)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Vector size cannot be greater than " + std::to_string(slot_count) + "."),
                                         HEBENCH_ECODE_INVALID_ARGS);
}

ElementWiseBenchmark::~ElementWiseBenchmark()
{
    // nothing needed in this example
}

hebench::APIBridge::Handle ElementWiseBenchmark::encode(const hebench::APIBridge::PackedData *p_parameters)
{
    if (p_parameters->pack_count != ElementWiseBenchmarkDescription::NumOpParams)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid number of parameters detected in parameter pack. Expected 2."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    std::vector<std::vector<seal::Plaintext>> params;

    params.resize(p_parameters->pack_count);
    const unsigned int params_size = params.size();
    for (unsigned int x = 0; x < params_size; ++x)
    {
        params[x].resize(p_parameters->p_data_packs[x].buffer_count);
    }

    std::vector<int64_t> values;
    values.resize(m_w_params.n);
    for (unsigned int x = 0; x < params.size(); ++x)
    {
        for (unsigned int y = 0; y < params[x].size(); ++y)
        {
            const hebench::APIBridge::DataPack &parameter = p_parameters->p_data_packs[x];
            // take first sample from parameter (because latency test has a single sample per parameter)
            const hebench::APIBridge::NativeDataBuffer &sample = parameter.p_buffers[y];
            // convert the native data to pointer to int64_t as per specification of workload
            const int64_t *p_row = reinterpret_cast<const int64_t *>(sample.p);
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

void ElementWiseBenchmark::decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::PackedData *p_native)
{
    // retrieve our internal format object from the handle
    const std::vector<seal::Plaintext> &params =
        this->getEngine().retrieveFromHandle<std::vector<seal::Plaintext>>(encoded_data);

    for (size_t result_i = 0; result_i < params.size(); ++result_i)
    {
        int64_t *output_location = reinterpret_cast<int64_t *>(p_native->p_data_packs[0].p_buffers[result_i].p);
        std::vector<int64_t> result_vec;
        m_p_ctx_wrapper->BFVEncoder()->decode(params[result_i], result_vec);
        for (size_t x = 0; x < m_w_params.n; ++x)
        {
            output_location[x] = result_vec[x];
        }
    }
}

hebench::APIBridge::Handle ElementWiseBenchmark::encrypt(hebench::APIBridge::Handle encoded_data)
{
    const std::vector<std::vector<seal::Plaintext>> &encoded_data_ref =
        this->getEngine().retrieveFromHandle<std::vector<std::vector<seal::Plaintext>>>(encoded_data);

    std::vector<std::vector<seal::Ciphertext>> encrypted_data;
    encrypted_data.resize(encoded_data_ref.size());
    for (unsigned int param_i = 0; param_i < encoded_data_ref.size(); param_i++)
    {
        encrypted_data[param_i].resize(encoded_data_ref[param_i].size());
        for (unsigned int parameter_sample = 0; parameter_sample < encoded_data_ref[param_i].size(); parameter_sample++)
        {
            m_p_ctx_wrapper->encryptor()->encrypt(encoded_data_ref[param_i][parameter_sample],
                                                  encrypted_data[param_i][parameter_sample]);
        }
    }

    return this->getEngine().createHandle<decltype(encrypted_data)>(sizeof(encrypted_data),
                                                                    0,
                                                                    std::move(encrypted_data));
}

hebench::APIBridge::Handle ElementWiseBenchmark::decrypt(hebench::APIBridge::Handle encrypted_data)
{
    const std::vector<seal::Ciphertext> &encrypted_data_ref =
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

hebench::APIBridge::Handle ElementWiseBenchmark::load(const hebench::APIBridge::Handle *p_local_data, uint64_t count)
{
    if (count != 1)
        // we do all ops in ciphertext, so, we should get only one pack of data
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid number of handles. Expected 1."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    assert(p_local_data);

    // since remote and host are the same for this example, we just need to return a copy
    // of the local data as remote.

    return this->getEngine().duplicateHandle(p_local_data[0]);
}

void ElementWiseBenchmark::store(hebench::APIBridge::Handle remote_data,
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

hebench::APIBridge::Handle ElementWiseBenchmark::operate(hebench::APIBridge::Handle h_remote_packed,
                                                         const hebench::APIBridge::ParameterIndexer *p_param_indexers)
{
    const std::vector<std::vector<seal::Ciphertext>> &params =
        this->getEngine().retrieveFromHandle<std::vector<std::vector<seal::Ciphertext>>>(h_remote_packed);

    std::vector<seal::Ciphertext> result;
    result.resize(p_param_indexers[0].batch_size * p_param_indexers[1].batch_size);
    std::mutex mtx;
    std::exception_ptr p_ex;
#pragma omp parallel for collapse(2)
    for (uint64_t result_i = 0; result_i < p_param_indexers[0].batch_size; result_i++)
    {
        for (uint64_t result_x = 0; result_x < p_param_indexers[1].batch_size; result_x++)
        {
            try
            {
                if (!p_ex)
                {
                    const seal::Ciphertext &p0 = params[0][p_param_indexers[0].value_index + result_i];
                    const seal::Ciphertext &p1 = params[1][p_param_indexers[1].value_index + result_x];
                    seal::Ciphertext &r        = result[result_i * p_param_indexers[1].batch_size + result_x];
                    switch (this->getDescriptor().workload)
                    {
                    case hebench::APIBridge::EltwiseAdd:
                        m_p_ctx_wrapper->evaluator()->add(p0, p1, r);
                        break;
                    case hebench::APIBridge::EltwiseMultiply:
                        m_p_ctx_wrapper->evaluator()->multiply(p0, p1, r, seal::MemoryPoolHandle::ThreadLocal());
                        break;

                    default:
                        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Operation not implimented."),
                                                         HEBENCH_ECODE_INVALID_ARGS);
                    } // end switch
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
