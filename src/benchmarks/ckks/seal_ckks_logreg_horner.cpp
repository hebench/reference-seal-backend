
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

#include "benchmarks/ckks/seal_ckks_logreg_horner.h"
#include "engine/seal_engine.h"

namespace sbe {
namespace ckks {

//----------------------------------------
// class LogRegHornerBenchmarkDescription
//----------------------------------------

LogRegHornerBenchmarkDescription::LogRegHornerBenchmarkDescription(hebench::APIBridge::Category category, std::size_t batch_size)
{
    // initialize the descriptor for this benchmark
    std::memset(&m_descriptor, 0, sizeof(hebench::APIBridge::BenchmarkDescriptor));
    m_descriptor.data_type = hebench::APIBridge::DataType::Float64;
    m_descriptor.category  = category;
    switch (category)
    {
    case hebench::APIBridge::Category::Latency:
        m_descriptor.cat_params.latency.min_test_time_ms        = 0;
        m_descriptor.cat_params.latency.warmup_iterations_count = 1;
        break;

    case hebench::APIBridge::Category::Offline:
        if (batch_size > DefaultPolyModulusDegree / 2)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Batch size must be under " + std::to_string(DefaultPolyModulusDegree / 2) + "."),
                                             HEBENCH_ECODE_INVALID_ARGS);
        m_descriptor.cat_params.offline.data_count[0] = 1;
        m_descriptor.cat_params.offline.data_count[1] = 1;
        m_descriptor.cat_params.offline.data_count[2] = batch_size;
        break;

    default:
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid category received."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    }
    m_descriptor.cipher_param_mask = HEBENCH_HE_PARAM_FLAGS_ALL_CIPHER;
    //
    m_descriptor.scheme   = HEBENCH_HE_SCHEME_CKKS;
    m_descriptor.security = HEBENCH_HE_SECURITY_128;
    m_descriptor.other    = LogRegOtherID;
    m_descriptor.workload = hebench::APIBridge::Workload::LogisticRegression_PolyD3;

    hebench::cpp::WorkloadParams::LogisticRegression default_workload_params;
    default_workload_params.n = 16;
    this->addDefaultParameters(default_workload_params);
}

LogRegHornerBenchmarkDescription::~LogRegHornerBenchmarkDescription()
{
    // nothing needed in this example
}

hebench::cpp::BaseBenchmark *LogRegHornerBenchmarkDescription::createBenchmark(hebench::cpp::BaseEngine &engine, const hebench::APIBridge::WorkloadParams *p_params)
{
    SEALEngine &seal_engine = dynamic_cast<SEALEngine &>(engine);
    return new LogRegHornerBenchmark(seal_engine, m_descriptor, *p_params);
}

void LogRegHornerBenchmarkDescription::destroyBenchmark(hebench::cpp::BaseBenchmark *p_bench)
{
    if (p_bench)
        delete p_bench;
}

std::string LogRegHornerBenchmarkDescription::getBenchmarkDescription(const hebench::APIBridge::WorkloadParams *p_w_params) const
{
    std::stringstream ss;
    std::string s_tmp = BenchmarkDescription::getBenchmarkDescription(p_w_params);
    if (!s_tmp.empty())
        ss << s_tmp << std::endl;
    ss << ", Encryption Parameters" << std::endl
       << ", , Poly modulus degree, " << DefaultPolyModulusDegree << std::endl
       << ", , Coefficient Modulus, 60";
    for (std::size_t i = 1; i < DefaultMultiplicativeDepth; ++i)
        ss << ", " << DefaultCoeffMudulusBits;
    ss << ", 60" << std::endl
       << ", , Scale, 2^" << DefaultScaleBits << std::endl
       << ", Algorithm, " << AlgorithmName << ", " << AlgorithmDescription;

    return ss.str();
}

//-----------------------------
// class LogRegHornerBenchmark
//-----------------------------

LogRegHornerBenchmark::LogRegHornerBenchmark(hebench::cpp::BaseEngine &engine,
                                             const hebench::APIBridge::BenchmarkDescriptor &bench_desc,
                                             const hebench::APIBridge::WorkloadParams &bench_params) :
    hebench::cpp::BaseBenchmark(engine, bench_desc, bench_params),
    m_w_params(bench_params)
{
    const hebench::APIBridge::BenchmarkDescriptor &local_bench_desc = getDescriptor();

    if (local_bench_desc.workload != hebench::APIBridge::Workload::LogisticRegression_PolyD3
        || local_bench_desc.data_type != hebench::APIBridge::DataType::Float64
        || (local_bench_desc.category != hebench::APIBridge::Category::Latency
            && local_bench_desc.category != hebench::APIBridge::Category::Offline)
        || ((local_bench_desc.cipher_param_mask & 0x03) != 0x03)
        || local_bench_desc.scheme != HEBENCH_HE_SCHEME_CKKS
        || local_bench_desc.security != HEBENCH_HE_SECURITY_128
        || local_bench_desc.other != LogRegHornerBenchmarkDescription::LogRegOtherID)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Benchmark descriptor received is not supported."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    if (local_bench_desc.category == hebench::APIBridge::Category::Offline
        && (local_bench_desc.cat_params.offline.data_count[0] > 1
            || local_bench_desc.cat_params.offline.data_count[1] > 1))
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Benchmark descriptor received is not supported."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    m_p_ctx_wrapper = SEALContextWrapper::createCKKSContext(LogRegHornerBenchmarkDescription::DefaultPolyModulusDegree,
                                                            LogRegHornerBenchmarkDescription::DefaultMultiplicativeDepth,
                                                            LogRegHornerBenchmarkDescription::DefaultCoeffMudulusBits,
                                                            LogRegHornerBenchmarkDescription::DefaultScaleBits,
                                                            seal::sec_level_type::tc128);
    if (m_w_params.n > m_p_ctx_wrapper->CKKSEncoder()->slot_count())
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid workload parameter 'n'. Number of features must be under " + std::to_string(m_p_ctx_wrapper->CKKSEncoder()->slot_count()) + "."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // encode polynomial coefficients
    m_plain_coeff.resize(sizeof(SigmoidPolyCoeff) / sizeof(SigmoidPolyCoeff[0]));
    for (std::size_t coeff_i = 0; coeff_i < m_plain_coeff.size(); ++coeff_i)
        m_p_ctx_wrapper->CKKSEncoder()->encode(SigmoidPolyCoeff[coeff_i], m_p_ctx_wrapper->scale(), m_plain_coeff[coeff_i]);
}

LogRegHornerBenchmark::~LogRegHornerBenchmark()
{
    //
}

hebench::APIBridge::Handle LogRegHornerBenchmark::encode(const hebench::APIBridge::PackedData *p_parameters)
{
    if (p_parameters->pack_count != LogRegHornerBenchmarkDescription::NumOpParams)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid number of operation parameters detected in parameter pack. Expected " + std::to_string(LogRegHornerBenchmarkDescription::NumOpParams) + "."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    // validate all op parameters are in this pack
    for (std::uint64_t param_i = 0; param_i < LogRegHornerBenchmarkDescription::NumOpParams; ++param_i)
    {
        if (findDataPackIndex(*p_parameters, param_i) >= p_parameters->pack_count)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("DataPack for Logistic Regression inference operation parameter " + std::to_string(param_i) + " expected, but not found in 'p_parameters'."),
                                             HEBENCH_ECODE_INVALID_ARGS);
    } // end for

    const hebench::APIBridge::DataPack &pack_W = findDataPack(*p_parameters, LogRegHornerBenchmarkDescription::Index_W);
    const hebench::APIBridge::DataPack &pack_b = findDataPack(*p_parameters, LogRegHornerBenchmarkDescription::Index_b);
    const hebench::APIBridge::DataPack &pack_X = findDataPack(*p_parameters, LogRegHornerBenchmarkDescription::Index_X);

    return this->getEngine().createHandle<EncodedOpParams>(sizeof(EncodedOpParams),
                                                           EncodedOpParamsTag,
                                                           std::make_tuple(encodeW(pack_W), encodeBias(pack_b), encodeInputs(pack_X)));
}

seal::Plaintext LogRegHornerBenchmark::encodeW(const hebench::APIBridge::DataPack &data_pack)
{
    assert(data_pack.param_position == LogRegHornerBenchmarkDescription::Index_W);
    if (data_pack.buffer_count < 1 || !data_pack.p_buffers || !data_pack.p_buffers[0].p)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty DataPack for 'W'."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    // convert Test Harness format to our internal clear text format
    gsl::span<const double> buffer =
        gsl::span<const double>(reinterpret_cast<const double *>(data_pack.p_buffers[0].p),
                                data_pack.p_buffers[0].size / sizeof(double));
    if (buffer.size() < m_w_params.n)
    {
        std::stringstream ss;
        ss << "Insufficient features for 'W'. Expected " << m_w_params.n << ", but " << buffer.size() << " received.";
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS(ss.str()),
                                         HEBENCH_ECODE_INVALID_ARGS);
    } // end if

    // encode
    seal::Plaintext retval;
    m_p_ctx_wrapper->CKKSEncoder()->encode(buffer, m_p_ctx_wrapper->scale(), retval);
    return retval;
}

seal::Plaintext LogRegHornerBenchmark::encodeBias(const hebench::APIBridge::DataPack &data_pack)
{
    assert(data_pack.param_position == LogRegHornerBenchmarkDescription::Index_b);
    if (data_pack.buffer_count < 1
        || !data_pack.p_buffers
        || !data_pack.p_buffers[0].p
        || data_pack.p_buffers[0].size < sizeof(double))
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty DataPack for 'b'."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    // convert Test Harness format to our internal clear text format
    double bias = *reinterpret_cast<const double *>(data_pack.p_buffers[0].p);

    // encode
    seal::Plaintext retval;
    m_p_ctx_wrapper->CKKSEncoder()->encode(bias, m_p_ctx_wrapper->scale(), retval);
    return retval;
}

std::vector<seal::Plaintext> LogRegHornerBenchmark::encodeInputs(const hebench::APIBridge::DataPack &data_pack)
{
    assert(data_pack.param_position == LogRegHornerBenchmarkDescription::Index_X);

    // prepare our internal representation

    std::vector<seal::Plaintext> retval;
    std::uint64_t batch_size =
        this->getDescriptor().category == hebench::APIBridge::Category::Offline ?
            getDescriptor().cat_params.offline.data_count[LogRegHornerBenchmarkDescription::Index_X] :
            1;

    if (!data_pack.p_buffers)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty DataPack for 'W'."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    if (data_pack.buffer_count < batch_size)
    {
        std::stringstream ss;
        ss << "Unexpected batch size for inputs. Expected, at least, " << batch_size
           << ", but " << data_pack.buffer_count << " received.";
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS(ss.str()),
                                         HEBENCH_ECODE_INVALID_ARGS);
    } // end if

    retval.reserve(data_pack.buffer_count);
    for (std::uint64_t input_sample_i = 0; input_sample_i < data_pack.buffer_count; ++input_sample_i)
    {
        if (!data_pack.p_buffers[input_sample_i].p)
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Unexpected empty input sample " + std::to_string(input_sample_i) + "."),
                                             HEBENCH_ECODE_INVALID_ARGS);
        // convert Test Harness format to our internal clear text format
        gsl::span<const double> buffer =
            gsl::span<const double>(reinterpret_cast<const double *>(data_pack.p_buffers[input_sample_i].p),
                                    data_pack.p_buffers[input_sample_i].size / sizeof(double));
        if (buffer.size() < m_w_params.n)
        {
            std::stringstream ss;
            ss << "Invalid input sample size in sample " << input_sample_i
               << ". Expected " << m_w_params.n << ", but " << buffer.size() << " received.";
            throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS(ss.str()),
                                             HEBENCH_ECODE_INVALID_ARGS);
        } // end if

        // encode
        retval.emplace_back();
        m_p_ctx_wrapper->CKKSEncoder()->encode(buffer, m_p_ctx_wrapper->scale(), retval.back());
    } // end for

    return retval;
}

void LogRegHornerBenchmark::decode(hebench::APIBridge::Handle h_encoded_data, hebench::APIBridge::PackedData *p_native)
{
    // only supports decoding results from decrypt

    // get result component target
    hebench::APIBridge::DataPack &result = this->findDataPack(*p_native, 0);
    // find minimum batch size to decode
    std::uint64_t batch_size = 1; // for latency
    if (this->getDescriptor().category == hebench::APIBridge::Category::Offline)
        batch_size = this->getDescriptor().cat_params.offline.data_count[LogRegHornerBenchmarkDescription::Index_X] > 0 ?
                         this->getDescriptor().cat_params.offline.data_count[LogRegHornerBenchmarkDescription::Index_X] :
                         result.buffer_count;
    std::uint64_t min_count = std::min(result.buffer_count, batch_size);
    if (min_count > 0)
    {
        // decode into local format
        const seal::Plaintext &encoded =
            this->getEngine().retrieveFromHandle<seal::Plaintext>(h_encoded_data, EncodedResultTag);
        std::vector<double> decoded;
        m_p_ctx_wrapper->CKKSEncoder()->decode(encoded, decoded);
        decoded.resize(min_count);
        // convert local format to Test Harness format
        for (std::uint64_t result_sample_i = 0; result_sample_i < min_count; ++result_sample_i)
        {
            if (result.p_buffers[result_sample_i].p && result.p_buffers[result_sample_i].size >= sizeof(double))
            {
                double *p_result_sample = reinterpret_cast<double *>(result.p_buffers[result_sample_i].p);
                *p_result_sample        = decoded[result_sample_i];
            } // end if
        } // end for
    } // end if
}

hebench::APIBridge::Handle LogRegHornerBenchmark::encrypt(hebench::APIBridge::Handle h_encoded_data)
{
    // supports encryption of EncodedOpParams only

    const EncodedOpParams &encoded_params =
        this->getEngine().retrieveFromHandle<EncodedOpParams>(h_encoded_data, EncodedOpParamsTag);
    // use smart ptr to be able to copy during load phase
    //    std::shared_ptr<EncryptedOpParams> p_retval = std::make_shared<EncryptedOpParams>(
    //        std::make_tuple(m_p_ctx_wrapper->encryptPlaintext(std::get<LogRegHornerBenchmarkDescription::Index_W>(encoded_params)),
    //                        m_p_ctx_wrapper->encryptPlaintext(std::get<LogRegHornerBenchmarkDescription::Index_b>(encoded_params)),
    //                        m_p_ctx_wrapper->encryptPlaintext(std::get<LogRegHornerBenchmarkDescription::Index_X>(encoded_params))));

    EncryptedOpParams retval; // = std::make_tuple<seal::Ciphertext, seal::Ciphertext, seal::Ciphertext>();
    m_p_ctx_wrapper->encryptor()->encrypt(std::get<LogRegHornerBenchmarkDescription::Index_W>(encoded_params), std::get<LogRegHornerBenchmarkDescription::Index_W>(retval));
    m_p_ctx_wrapper->encryptor()->encrypt(std::get<LogRegHornerBenchmarkDescription::Index_b>(encoded_params), std::get<LogRegHornerBenchmarkDescription::Index_b>(retval));
    std::get<LogRegHornerBenchmarkDescription::Index_X>(retval) = m_p_ctx_wrapper->encrypt(std::get<LogRegHornerBenchmarkDescription::Index_X>(encoded_params));

    return this->getEngine().createHandle<decltype(retval)>(sizeof(EncryptedOpParams),
                                                            EncryptedOpParamsTag,
                                                            std::move(retval));
}

hebench::APIBridge::Handle LogRegHornerBenchmark::decrypt(hebench::APIBridge::Handle h_encrypted_data)
{
    // only supports decrypting results from operate

    seal::Ciphertext cipher =
        this->getEngine().retrieveFromHandle<seal::Ciphertext>(h_encrypted_data, EncryptedResultTag);
    seal::Plaintext retval = m_p_ctx_wrapper->decrypt(cipher);
    // just return a copy
    return this->getEngine().createHandle<decltype(retval)>(m_w_params.n,
                                                            EncodedResultTag,
                                                            std::move(retval));
}

hebench::APIBridge::Handle LogRegHornerBenchmark::load(const hebench::APIBridge::Handle *p_h_local_data, uint64_t count)
{
    // supports only loading EncryptedOpParams

    if (count != 1)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Expected only 1 local handle to load."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    return this->getEngine().duplicateHandle(p_h_local_data[0], EncryptedOpParamsTag);
}

void LogRegHornerBenchmark::store(hebench::APIBridge::Handle h_remote_data,
                                  hebench::APIBridge::Handle *p_h_local_data, std::uint64_t count)
{
    // only supports storing results from operate

    if (count > 0)
    {
        p_h_local_data[0] = this->getEngine().duplicateHandle(h_remote_data, EncryptedResultTag);
    } // end if
}

hebench::APIBridge::Handle LogRegHornerBenchmark::operate(hebench::APIBridge::Handle h_remote_packed,
                                                          const hebench::APIBridge::ParameterIndexer *p_param_indexers)
{
    // input to operation is always EncryptedOpParams

    EncryptedOpParams remote =
        this->getEngine().retrieveFromHandle<EncryptedOpParams>(h_remote_packed, EncryptedOpParamsTag);

    // extract our internal representation from handle
    const seal::Ciphertext &cipher_W                   = std::get<LogRegHornerBenchmarkDescription::Index_W>(remote);
    const std::vector<seal::Ciphertext> &cipher_inputs = std::get<LogRegHornerBenchmarkDescription::Index_X>(remote);
    // make a copy of the bias to be able to operate without modifying the original
    seal::Ciphertext cipher_b = std::get<LogRegHornerBenchmarkDescription::Index_b>(remote);

    // validate the indexers

    // this method does not support indexing portions of the batch
    if (p_param_indexers[LogRegHornerBenchmarkDescription::Index_X].value_index != 0
        || (this->getDescriptor().category == hebench::APIBridge::Category::Offline
            && p_param_indexers[LogRegHornerBenchmarkDescription::Index_X].batch_size != cipher_inputs.size())
        || (this->getDescriptor().category == hebench::APIBridge::Category::Latency
            && p_param_indexers[LogRegHornerBenchmarkDescription::Index_X].batch_size != 1))
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Invalid indexer range for parameter " + std::to_string(LogRegHornerBenchmarkDescription::Index_X) + " detected."),
                                         HEBENCH_ECODE_INVALID_ARGS);

    // linear regression
    std::vector<seal::Ciphertext> cipher_dots(cipher_inputs.size());
    std::mutex mtx;
    std::exception_ptr p_ex;
#pragma omp parallel for
    for (std::size_t input_i = 0; input_i < cipher_inputs.size(); ++input_i)
    {
        try
        {
            if (!p_ex)
            {
                m_p_ctx_wrapper->evaluator()->multiply(cipher_W, cipher_inputs[input_i], cipher_dots[input_i], seal::MemoryPoolHandle::ThreadLocal());
                m_p_ctx_wrapper->evaluator()->relinearize_inplace(cipher_dots[input_i], m_p_ctx_wrapper->relinKeys(), seal::MemoryPoolHandle::ThreadLocal());
                cipher_dots[input_i] = m_p_ctx_wrapper->accumulateCKKS(cipher_dots[input_i], m_w_params.n);
                m_p_ctx_wrapper->evaluator()->rescale_to_next_inplace(cipher_dots[input_i], seal::MemoryPoolHandle::ThreadLocal());
            } // end if
        }
        catch (...)
        {
            std::scoped_lock<std::mutex> lock(mtx);
            if (!p_ex)
                p_ex = std::current_exception();
        }
    } // end for

    if (p_ex)
        std::rethrow_exception(p_ex);

    // TODO: check if collapsing before adding bias is better:
    // - adds bias once to collapsed results
    // - computes sigmoid only once on all collapsed results
    // vs: no collapse
    // - add bias to every result
    // - compute sigmoid on every result

    seal::Ciphertext cipher_lr = m_p_ctx_wrapper->collapseCKKS(cipher_dots, true);
    cipher_dots.clear();

    // add bias

    m_p_ctx_wrapper->matchLevel(cipher_b, cipher_lr);
    // match scales (results will be wrong if scales are not close enough)
    cipher_b.scale()  = m_p_ctx_wrapper->scale();
    cipher_lr.scale() = m_p_ctx_wrapper->scale();
    m_p_ctx_wrapper->evaluator()->add_inplace(cipher_lr, cipher_b);

    // cipher_lr contains all the linear regressions

    // compute sigmoid approximation

    // make a copy of the coefficients since evaluatePolynomial will modify the plaintexts
    // during the operation
    // Is there a more efficient way to do this?
    // (think: latency will do this copy many times; offline, only once)
    std::vector<seal::Plaintext> plain_coeff_copy = m_plain_coeff;
    seal::Ciphertext retval                       = m_p_ctx_wrapper->evaluatePolynomial(cipher_lr, plain_coeff_copy);

    // use smart ptr to be able to copy during store phase
    return this->getEngine().createHandle<decltype(retval)>(sizeof(seal::Ciphertext),
                                                            EncryptedResultTag,
                                                            std::move(retval));
}

} // namespace ckks
} // namespace sbe
