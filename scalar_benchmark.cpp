#include <seal/seal.h>
#include <sys/resource.h>
#include <chrono>
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
using namespace seal;

// Function to get peak memory usage in KB
long getPeakMemoryUsageKB() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss; // in KB
}

// Function to log results with enc/dec/op time
void log_result(ofstream &log_file, const string &operation,
                size_t poly_degree, uint64_t scalar1, uint64_t scalar2,
                double enc_time_ms, double op_time_ms, double dec_time_ms) {
    long mem_kb = getPeakMemoryUsageKB();
    log_file << operation << "," << mem_kb << "," << poly_degree << ","
             << scalar1 << "," << scalar2 << ","
             << enc_time_ms << "," << op_time_ms << "," << dec_time_ms << "\n";
}

int main() {
    vector<size_t> poly_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
    vector<uint64_t> scalars = {1, 7, 42, 12345, 65536}; // scalar values

    ofstream log_file("SEAL_scalar_log.csv", ios::app);
    log_file << "Operation,Memory(KB),PolyModulusDegree,Scalar1,Scalar2,"
                "EncryptionTime(ms),OperationTime(ms),DecryptionTime(ms)\n";

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

        for (size_t i = 0; i < scalars.size(); i++) {
            for (size_t j = 0; j < scalars.size(); j++) {
                uint64_t val1 = scalars[i];
                uint64_t val2 = scalars[j];

                Plaintext plain1, plain2;
                encoder.encode(vector<uint64_t>{val1}, plain1);
                encoder.encode(vector<uint64_t>{val2}, plain2);

                Ciphertext enc1, enc2;

                // Encryption timing
                auto enc_start = chrono::high_resolution_clock::now();
                encryptor.encrypt(plain1, enc1);
                encryptor.encrypt(plain2, enc2);
                auto enc_end = chrono::high_resolution_clock::now();
                double enc_time_ms = chrono::duration<double, std::milli>(enc_end - enc_start).count();

                // --- Cipher + Cipher ---
                auto op_start = chrono::high_resolution_clock::now();
                Ciphertext result_add;
                evaluator.add(enc1, enc2, result_add);
                auto op_end = chrono::high_resolution_clock::now();
                double op_time_ms = chrono::duration<double, std::milli>(op_end - op_start).count();

                // Decryption timing
                Plaintext decrypted;
                auto dec_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(result_add, decrypted);
                auto dec_end = chrono::high_resolution_clock::now();
                double dec_time_ms = chrono::duration<double, std::milli>(dec_end - dec_start).count();

                log_result(log_file, "Cipher+Cipher", poly_deg, val1, val2,
                           enc_time_ms, op_time_ms, dec_time_ms);

                // Multiply
                op_start = chrono::high_resolution_clock::now();
                Ciphertext result_mul;
                evaluator.multiply(enc1, enc2, result_mul);
                op_end = chrono::high_resolution_clock::now();
                op_time_ms = chrono::duration<double, std::milli>(op_end - op_start).count();

                dec_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(result_mul, decrypted);
                dec_end = chrono::high_resolution_clock::now();
                dec_time_ms = chrono::duration<double, std::milli>(dec_end - dec_start).count();

                log_result(log_file, "Cipher*Cipher", poly_deg, val1, val2,
                           enc_time_ms, op_time_ms, dec_time_ms);

                // Cipher + Plain Add
                op_start = chrono::high_resolution_clock::now();
                Ciphertext result_cp_add;
                evaluator.add_plain(enc1, plain2, result_cp_add);
                op_end = chrono::high_resolution_clock::now();
                op_time_ms = chrono::duration<double, std::milli>(op_end - op_start).count();

                dec_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(result_cp_add, decrypted);
                dec_end = chrono::high_resolution_clock::now();
                dec_time_ms = chrono::duration<double, std::milli>(dec_end - dec_start).count();

                log_result(log_file, "Cipher+Plain", poly_deg, val1, val2,
                           enc_time_ms, op_time_ms, dec_time_ms);

                // Cipher + Plain Mul
                op_start = chrono::high_resolution_clock::now();
                Ciphertext result_cp_mul;
                evaluator.multiply_plain(enc1, plain2, result_cp_mul);
                op_end = chrono::high_resolution_clock::now();
                op_time_ms = chrono::duration<double, std::milli>(op_end - op_start).count();

                dec_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(result_cp_mul, decrypted);
                dec_end = chrono::high_resolution_clock::now();
                dec_time_ms = chrono::duration<double, std::milli>(dec_end - dec_start).count();

                log_result(log_file, "Cipher*Plain", poly_deg, val1, val2,
                           enc_time_ms, op_time_ms, dec_time_ms);

                // Plain + Cipher Add
                op_start = chrono::high_resolution_clock::now();
                Ciphertext result_pc_add;
                evaluator.add_plain(enc2, plain1, result_pc_add);
                op_end = chrono::high_resolution_clock::now();
                op_time_ms = chrono::duration<double, std::milli>(op_end - op_start).count();

                dec_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(result_pc_add, decrypted);
                dec_end = chrono::high_resolution_clock::now();
                dec_time_ms = chrono::duration<double, std::milli>(dec_end - dec_start).count();

                log_result(log_file, "Plain+Cipher", poly_deg, val1, val2,
                           enc_time_ms, op_time_ms, dec_time_ms);

                // Plain + Cipher Mul
                op_start = chrono::high_resolution_clock::now();
                Ciphertext result_pc_mul;
                evaluator.multiply_plain(enc2, plain1, result_pc_mul);
                op_end = chrono::high_resolution_clock::now();
                op_time_ms = chrono::duration<double, std::milli>(op_end - op_start).count();

                dec_start = chrono::high_resolution_clock::now();
                decryptor.decrypt(result_pc_mul, decrypted);
                dec_end = chrono::high_resolution_clock::now();
                dec_time_ms = chrono::duration<double, std::milli>(dec_end - dec_start).count();

                log_result(log_file, "Plain*Cipher", poly_deg, val1, val2,
                           enc_time_ms, op_time_ms, dec_time_ms);
            }
        }
        cout << "Completed Poly Degree = " << poly_deg << endl;
    }

    log_file.close();
    cout << "Benchmarking complete. Check SEAL_scalar_log.csv\n";
    return 0;
}

