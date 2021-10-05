
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

#include "benchmarks/bfv/seal_bfv_dot_product_benchmark.h"
#include "engine/seal_types.h"

using namespace sbe::bfv;
//-----------------------------------
// class DotProductBenchmarkDescription
//-----------------------------------

DotProductBenchmarkDescription::DotProductBenchmarkDescription(hebench::APIBridge::Category category)
{
    // initialize the descriptor for this benchmark
    std::memset(&m_descriptor, 0, sizeof(hebench::APIBridge::BenchmarkDescriptor));
    m_descriptor.data_type = hebench::APIBridge::DataType::Int64;
    m_descriptor.category  = category;
    switch (category)
    {
    case hebench::APIBridge::Category::Latency:
        m_descriptor.cat_params.latency.min_test_time_ms        = 0;
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
    m_descriptor.scheme   = HEBENCH_HE_SCHEME_BFV;
    m_descriptor.security = HEBENCH_HE_SECURITY_128;
    m_descriptor.other    = 0; // no extra parameters
    m_descriptor.workload = hebench::APIBridge::Workload::DotProduct;

    hebench::cpp::WorkloadParams::DotProduct default_workload_params;
    default_workload_params.n = 100;
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
    if (!s_tmp.empty())
        ss << s_tmp << std::endl;
    ss << ", Encryption Parameters" << std::endl
       << ", , Poly modulus degree, " << DefaultPolyModulusDegree << std::endl
       << ", , Coefficient Modulus, 60";
    for (std::size_t i = 1; i < DefaultMultiplicativeDepth; ++i)
    {
        ss << ", " << DefaultCoeffModBits;
    }
    ss << ", 60" << std::endl
       << ", , Plain Text Modulus Bits, " << DefaultPlainModulusBits << std::endl
       << ", Algorithm, " << AlgorithmName << ", " << AlgorithmDescription;
    return ss.str();
}

//------------------------
// DotProductBenchmark
//------------------------

DotProductBenchmark::DotProductBenchmark(hebench::cpp::BaseEngine &engine,
                                         const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                                         const hebench::APIBridge::WorkloadParams &bench_params) :
    hebench::cpp::BaseBenchmark(engine, bench_desc, bench_params)
{
    m_vector_size = bench_params.params[0].u_param;

    m_p_ctx_wrapper = SEALContextWrapper::createBFVContext(DotProductBenchmarkDescription::DefaultPolyModulusDegree,
                                                           DotProductBenchmarkDescription::DefaultMultiplicativeDepth,
                                                           DotProductBenchmarkDescription::DefaultCoeffModBits,
                                                           DotProductBenchmarkDescription::DefaultPlainModulusBits,
                                                           seal::sec_level_type::tc128);
}

DotProductBenchmark::~DotProductBenchmark()
{
    // nothing needed in this example
}

hebench::APIBridge::Handle DotProductBenchmark::encode(const hebench::APIBridge::PackedData *p_parameters)
{
    if (p_parameters->pack_count != 2)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid number of parameters detected in parameter pack. Expected 2."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // allocate our internal version of the encoded data

    // We are using shared_ptr because we want to be able to copy the pointer object later
    // and use the reference counter to avoid leaving dangling. If our internal object
    // does not need to be copied, shared_ptr is not really needed.

    std::shared_ptr<std::vector<std::vector<seal::Plaintext>>> p_params = std::make_shared<std::vector<std::vector<seal::Plaintext>>>();
    if (!p_params)
    {
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid memory allocation."), HEBENCH_ECODE_CRITICAL_ERROR);
    }
    std::vector<std::vector<seal::Plaintext>> &params = *p_params;

    params.resize(p_parameters->pack_count);
    const unsigned int params_size = params.size();
    for (unsigned int x = 0; x < params_size; ++x)
    {
        params[x].resize(p_parameters->p_data_packs[x].buffer_count);
    }

    std::vector<int64_t> values;
    values.resize(m_vector_size);
    for (unsigned int x = 0; x < params.size(); ++x)
    {
        for (unsigned int y = 0; y < params[x].size(); ++y)
        {
            const hebench::APIBridge::DataPack &parameter = p_parameters->p_data_packs[x];
            // take first sample from parameter (because latency test has a single sample per parameter)
            const hebench::APIBridge::NativeDataBuffer &sample = parameter.p_buffers[y];
            // convert the native data to pointer to int64_t as per specification of workload
            const int64_t *p_row = reinterpret_cast<const int64_t *>(sample.p);
            for (unsigned int x = 0; x < m_vector_size; ++x)
            {
                values[x] = p_row[x];
            }
            params[x][y] = m_p_ctx_wrapper->encodeVector(values);
        }
    }

    // Use EngineObject to encapsulate our internal object to cross the boundary of the API Bridge.
    // EngineObject encapsulation ensures proper destruction from the C++ wrapper.
    hebench::cpp::EngineObject *p_retval =
        this->getEngine().template createEngineObj<std::shared_ptr<std::vector<std::vector<seal::Plaintext>>>>(p_params);

    hebench::APIBridge::Handle retval;
    retval.p    = p_retval;
    retval.size = sizeof(hebench::cpp::EngineObject); // size is arbitrary and implementation dependent
    retval.tag  = p_retval->classTag(); // make sure that the bit mask for EngineObject is part of the tag

    return retval;
}

void DotProductBenchmark::decode(hebench::APIBridge::Handle encoded_data, hebench::APIBridge::PackedData *p_native)
{
    // retrieve our internal format object from the handle
    hebench::cpp::EngineObject *p_obj =
        reinterpret_cast<hebench::cpp::EngineObject *>(encoded_data.p);
    std::vector<seal::Plaintext> &params =
        *p_obj->get<std::shared_ptr<std::vector<seal::Plaintext>>>();

    const size_t params_size = params.size();
    for (size_t result_i = 0; result_i < params_size; ++result_i)
    {
        int64_t *output_location = reinterpret_cast<int64_t *>(p_native->p_data_packs[0].p_buffers[result_i].p);
        std::vector<int64_t> result_vec;
        m_p_ctx_wrapper->BFVEncoder()->decode(params[result_i], result_vec);
        output_location[0] = result_vec.front();
    }
}

hebench::APIBridge::Handle DotProductBenchmark::encrypt(hebench::APIBridge::Handle encoded_data)
{
    if ((encoded_data.tag & hebench::cpp::EngineObject::tag) == 0)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid tag detected. Expected EngineObject::tag."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // we only do plain text in this example, so, just return a copy

    // retrieve our internal format object from the handle
    hebench::cpp::EngineObject *p_obj = reinterpret_cast<hebench::cpp::EngineObject *>(encoded_data.p);
    std::shared_ptr<std::vector<std::vector<seal::Plaintext>>> p_encoded_data =
        p_obj->get<std::shared_ptr<std::vector<std::vector<seal::Plaintext>>>>();

    std::vector<std::vector<seal::Plaintext>> &encoded_data_ref = *p_encoded_data;

    std::vector<std::vector<seal::Ciphertext>> encrypted_data;

    encrypted_data.resize(p_encoded_data->size());
    for (unsigned int param_i = 0; param_i < p_encoded_data->size(); param_i++)
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

    // we only do plain text in this example, so, just return a copy

    // retrieve our internal format object from the handle
    std::vector<seal::Ciphertext> &encrypted_data_ref = this->getEngine().retrieveFromHandle<std::vector<seal::Ciphertext>>(encrypted_data);

    std::shared_ptr<std::vector<seal::Plaintext>> p_plaintext_data = std::make_shared<std::vector<seal::Plaintext>>();
    if (!p_plaintext_data)
    {
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid memory allocation."), HEBENCH_ECODE_CRITICAL_ERROR);
    }
    std::vector<seal::Plaintext> &plaintext_data = *p_plaintext_data;
    plaintext_data.resize(encrypted_data_ref.size());

    for (unsigned int res_count = 0; res_count < encrypted_data_ref.size(); ++res_count)
    {
        plaintext_data[res_count] = m_p_ctx_wrapper->decrypt(encrypted_data_ref[res_count]);
    }

    // copy the object and convert to external format
    // (use EngineObject to send across the boundary of the API Bridge)
    hebench::cpp::EngineObject *p_retval =
        this->getEngine().template createEngineObj<std::shared_ptr<std::vector<seal::Plaintext>>>(p_plaintext_data);

    hebench::APIBridge::Handle retval;
    retval.p    = p_retval;
    retval.size = sizeof(hebench::cpp::EngineObject); // size is arbitrary and implementation dependent
    retval.tag  = p_retval->classTag(); // make sure that the bit mask for EngineObject is part of the tag

    return retval;
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
    // This method should perform as fast as possible since it is the
    // method benchmarked by Test Harness.

    if ((h_remote_packed.tag & hebench::cpp::EngineObject::tag) == 0)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid tag detected. Expected EngineObject::tag."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // retrieve our internal format object from the handle
    std::vector<std::vector<seal::Ciphertext>> &params =
        this->getEngine().retrieveFromHandle<std::vector<std::vector<seal::Ciphertext>>>(h_remote_packed);

    // create a new internal object for result
    std::vector<seal::Ciphertext> result;
    // perform the actual operation
    result.resize(p_param_indexers[0].batch_size * p_param_indexers[1].batch_size);
    for (uint64_t result_i = 0; result_i < p_param_indexers[0].batch_size; result_i++)
    {
        for (uint64_t result_x = 0; result_x < p_param_indexers[1].batch_size; result_x++)
        {
            auto &result_cipher = result[result_i * p_param_indexers[1].batch_size + result_x];
            m_p_ctx_wrapper->evaluator()->multiply(params[0][p_param_indexers[0].value_index + result_i],
                                                   params[1][p_param_indexers[1].value_index + result_x],
                                                   result_cipher);
            m_p_ctx_wrapper->evaluator()->relinearize_inplace(result_cipher, m_p_ctx_wrapper->relinKeys());
            result_cipher = m_p_ctx_wrapper->accumulateBFV(result_cipher, m_vector_size);
        }
    }

    return this->getEngine().createHandle<decltype(result)>(sizeof(result),
                                                            0,
                                                            std::move(result));
}
