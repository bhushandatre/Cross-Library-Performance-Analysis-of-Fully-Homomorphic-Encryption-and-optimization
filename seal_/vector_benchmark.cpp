#include <seal/seal.h>
#include <sys/resource.h>
#include <chrono>
#include <vector>
#include <iostream>
#include <fstream>

using namespace std;
using namespace seal;

// Function to get peak memory usage in KB (Linux)
long getPeakMemoryUsageKB() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss; // in KB
}

// Log function with enc/dec as columns
void log_result(ofstream &log_file, const string &operation,
                long mem_kb, size_t poly_degree, size_t vector_size,
                double enc_time_ms, double op_time_ms, double dec_time_ms) {
    log_file << operation << "," << mem_kb << "," << poly_degree << "," << vector_size
             << "," << enc_time_ms << "," << op_time_ms << "," << dec_time_ms << "\n";
}

int main() {
    vector<size_t> poly_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
    vector<size_t> vector_sizes = {1000, 10000, 100000, 1000000};

    ofstream log_file("SEAL_vector_log.csv", ios::app);
    log_file << "Operation,Memory(KB),PolyModulusDegree,VectorSize,EncryptionTime(ms),OperationTime(ms),DecryptionTime(ms)\n";

    for (size_t poly_deg : poly_degrees) {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(poly_deg);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_deg));
        parms.set_plain_modulus(PlainModulus::Batching(poly_deg, 20));

        SEALContext context(parms);
        KeyGenerator keygen(context);

        PublicKey public_key;
        keygen.create_public_key(public_key);
        SecretKey secret_key = keygen.secret_key();

        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);
        BatchEncoder encoder(context);

        for (size_t vec_size : vector_sizes) {
            size_t slot_count = encoder.slot_count();
            if (vec_size > slot_count) continue;

            vector<uint64_t> vec1(vec_size, 3);
            vector<uint64_t> vec2(vec_size, 5);
            Plaintext plain1, plain2;
            encoder.encode(vec1, plain1);
            encoder.encode(vec2, plain2);

            Ciphertext enc1, enc2;
            Plaintext decrypted;

            // Encryption timing
            auto start = chrono::high_resolution_clock::now();
            encryptor.encrypt(plain1, enc1);
            encryptor.encrypt(plain2, enc2);
            auto end = chrono::high_resolution_clock::now();
            double enc_time = chrono::duration<double, milli>(end - start).count();

            // ---- Cipher + Cipher ----
            start = chrono::high_resolution_clock::now();
            Ciphertext result_add;
            evaluator.add(enc1, enc2, result_add);
            end = chrono::high_resolution_clock::now();
            double op_time = chrono::duration<double, milli>(end - start).count();

            start = chrono::high_resolution_clock::now();
            decryptor.decrypt(result_add, decrypted);
            end = chrono::high_resolution_clock::now();
            double dec_time = chrono::duration<double, milli>(end - start).count();

            log_result(log_file, "Cipher+Cipher", getPeakMemoryUsageKB(),
                       poly_deg, vec_size, enc_time, op_time, dec_time);

            // ---- Cipher * Cipher ----
            start = chrono::high_resolution_clock::now();
            Ciphertext result_mul;
            evaluator.multiply(enc1, enc2, result_mul);
            end = chrono::high_resolution_clock::now();
            op_time = chrono::duration<double, milli>(end - start).count();

            start = chrono::high_resolution_clock::now();
            decryptor.decrypt(result_mul, decrypted);
            end = chrono::high_resolution_clock::now();
            dec_time = chrono::duration<double, milli>(end - start).count();

            log_result(log_file, "Cipher*Cipher", getPeakMemoryUsageKB(),
                       poly_deg, vec_size, enc_time, op_time, dec_time);

            // ---- Cipher + Plain ----
            start = chrono::high_resolution_clock::now();
            Ciphertext result_cp_add;
            evaluator.add_plain(enc1, plain2, result_cp_add);
            end = chrono::high_resolution_clock::now();
            op_time = chrono::duration<double, milli>(end - start).count();

            start = chrono::high_resolution_clock::now();
            decryptor.decrypt(result_cp_add, decrypted);
            end = chrono::high_resolution_clock::now();
            dec_time = chrono::duration<double, milli>(end - start).count();

            log_result(log_file, "Cipher+Plain", getPeakMemoryUsageKB(),
                       poly_deg, vec_size, enc_time, op_time, dec_time);

            // ---- Plain + Cipher (same but logged separately) ----
            start = chrono::high_resolution_clock::now();
            Ciphertext result_pc_add;
            evaluator.add_plain(enc2, plain1, result_pc_add);
            end = chrono::high_resolution_clock::now();
            op_time = chrono::duration<double, milli>(end - start).count();

            start = chrono::high_resolution_clock::now();
            decryptor.decrypt(result_pc_add, decrypted);
            end = chrono::high_resolution_clock::now();
            dec_time = chrono::duration<double, milli>(end - start).count();

            log_result(log_file, "Plain+Cipher", getPeakMemoryUsageKB(),
                       poly_deg, vec_size, enc_time, op_time, dec_time);

            // ---- Cipher * Plain ----
            start = chrono::high_resolution_clock::now();
            Ciphertext result_cp_mul;
            evaluator.multiply_plain(enc1, plain2, result_cp_mul);
            end = chrono::high_resolution_clock::now();
            op_time = chrono::duration<double, milli>(end - start).count();

            start = chrono::high_resolution_clock::now();
            decryptor.decrypt(result_cp_mul, decrypted);
            end = chrono::high_resolution_clock::now();
            dec_time = chrono::duration<double, milli>(end - start).count();

            log_result(log_file, "Cipher*Plain", getPeakMemoryUsageKB(),
                       poly_deg, vec_size, enc_time, op_time, dec_time);

            // ---- Plain * Cipher (same but logged separately) ----
            start = chrono::high_resolution_clock::now();
            Ciphertext result_pc_mul;
            evaluator.multiply_plain(enc2, plain1, result_pc_mul);
            end = chrono::high_resolution_clock::now();
            op_time = chrono::duration<double, milli>(end - start).count();

            start = chrono::high_resolution_clock::now();
            decryptor.decrypt(result_pc_mul, decrypted);
            end = chrono::high_resolution_clock::now();
            dec_time = chrono::duration<double, milli>(end - start).count();

            log_result(log_file, "Plain*Cipher", getPeakMemoryUsageKB(),
                       poly_deg, vec_size, enc_time, op_time, dec_time);
        }
    }

    log_file.close();
    return 0;
}

