#include <seal/seal.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <chrono>
#include <cmath>

using namespace std;
using namespace seal;

class SEALRotationExperiment {
private:
    shared_ptr<SEALContext> context;
    KeyGenerator *keygen;
    SecretKey secret_key;
    PublicKey public_key;
    Encryptor *encryptor;
    Evaluator *evaluator;
    Decryptor *decryptor;
    BatchEncoder *batch_encoder;
    GaloisKeys galois_keys;
    
    ofstream log_file;

public:
    SEALRotationExperiment() : keygen(nullptr), encryptor(nullptr), evaluator(nullptr), 
                               decryptor(nullptr), batch_encoder(nullptr) {
        log_file.open("seal_rotation_experiment.csv");
        log_file << "poly_modulus_degree,vector_size,rotation_type,rotation_time_ms\n";
    }

    ~SEALRotationExperiment() {
        cleanup();
        if (log_file.is_open()) {
            log_file.close();
        }
    }

    void cleanup() {
        if (batch_encoder) delete batch_encoder;
        if (decryptor) delete decryptor;
        if (evaluator) delete evaluator;
        if (encryptor) delete encryptor;
        if (keygen) delete keygen;
    }

    bool try_parameters(size_t poly_modulus_degree, const vector<int>& bit_sizes, uint64_t plain_mod) {
        try {
            EncryptionParameters params(scheme_type::bfv);
            params.set_poly_modulus_degree(poly_modulus_degree);
            params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
            params.set_plain_modulus(plain_mod);
            
            context = make_shared<SEALContext>(params);
            
            if (!context->parameters_set()) {
                return false;
            }
            
            // Test if we can create all the necessary objects
            keygen = new KeyGenerator(*context);
            secret_key = keygen->secret_key();
            keygen->create_public_key(public_key);
            keygen->create_galois_keys(galois_keys);
            encryptor = new Encryptor(*context, public_key);
            evaluator = new Evaluator(*context);
            decryptor = new Decryptor(*context, secret_key);
            batch_encoder = new BatchEncoder(*context);
            
            return true;
        } catch (const exception& e) {
            cleanup();
            return false;
        }
    }

    bool setup_context(size_t poly_modulus_degree) {
        cleanup();

        cout << "Setting up context for poly_modulus_degree: " << poly_modulus_degree << endl;

        // Try different parameter combinations for problematic degrees
        if (poly_modulus_degree == 1024 || poly_modulus_degree == 2048) {
            vector<vector<int>> coeff_modulus_options;
            vector<uint64_t> plain_modulus_options = {65537, 12289, 40961};
            
            if (poly_modulus_degree == 1024) {
                coeff_modulus_options = {
                    {27, 27},      // 2 moduli
                    {30, 30},      // 2 moduli  
                    {27, 27, 27},  // 3 moduli
                    {20, 20}       // Smaller moduli
                };
            } else if (poly_modulus_degree == 2048) {
                coeff_modulus_options = {
                    {36, 36, 37},  // 3 moduli
                    {30, 30, 30},  // 3 smaller moduli
                    {36, 36},      // 2 moduli
                    {27, 27, 27}   // 3 smaller moduli
                };
            }

            // Try all combinations
            for (const auto& coeff_modulus : coeff_modulus_options) {
                for (auto plain_mod : plain_modulus_options) {
                    cout << "  Trying coeff_modulus: [";
                    for (size_t i = 0; i < coeff_modulus.size(); i++) {
                        cout << coeff_modulus[i];
                        if (i < coeff_modulus.size() - 1) cout << ", ";
                    }
                    cout << "], plain_modulus: " << plain_mod << " ... ";
                    
                    if (try_parameters(poly_modulus_degree, coeff_modulus, plain_mod)) {
                        cout << "SUCCESS!" << endl;
                        cout << "  Context setup completed successfully" << endl;
                        cout << "  Slot count: " << batch_encoder->slot_count() << endl;
                        return true;
                    } else {
                        cout << "FAILED" << endl;
                        cleanup();
                    }
                }
            }

            cout << "  ERROR: No working parameters found for poly_modulus_degree: " << poly_modulus_degree << endl;
            return false;
        }
        else {
            // For larger degrees, use SEAL defaults
            EncryptionParameters params(scheme_type::bfv);
            params.set_poly_modulus_degree(poly_modulus_degree);
            
            try {
                params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
                params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

                context = make_shared<SEALContext>(params);

                if (!context->parameters_set()) {
                    cout << "  ERROR: Parameters are not valid" << endl;
                    return false;
                }

                keygen = new KeyGenerator(*context);
                secret_key = keygen->secret_key();
                keygen->create_public_key(public_key);
                keygen->create_galois_keys(galois_keys);
                encryptor = new Encryptor(*context, public_key);
                evaluator = new Evaluator(*context);
                decryptor = new Decryptor(*context, secret_key);
                batch_encoder = new BatchEncoder(*context);

                cout << "  Context setup completed successfully" << endl;
                cout << "  Slot count: " << batch_encoder->slot_count() << endl;
                return true;

            } catch (const exception& e) {
                cout << "  ERROR in setup: " << e.what() << endl;
                return false;
            }
        }
    }

    void log_rotation(size_t poly_modulus_degree, size_t vector_size, const string& rotation_type, double rotation_time) {
        log_file << poly_modulus_degree << "," << vector_size << "," << rotation_type << "," << rotation_time << endl;
        
        cout << "PolyModulus: " << poly_modulus_degree 
             << ", VectorSize: " << vector_size
             << ", Rotation: " << rotation_type
             << ", Time: " << rotation_time << " ms" << endl;
    }

    void test_rotation(size_t poly_modulus_degree, size_t vector_size) {
        size_t slot_count = batch_encoder->slot_count();
        
        // Prepare data - sequential integers in all slots
        vector<uint64_t> plain_vector(slot_count);
        for (size_t i = 0; i < slot_count; i++) {
            plain_vector[i] = i;
        }
        
        Plaintext plain;
        batch_encoder->encode(plain_vector, plain);

        // Encrypt the data
        Ciphertext cipher;
        encryptor->encrypt(plain, cipher);

        // Test only the required rotation types
        vector<pair<string, int>> rotations = {
            {"ROTATE_LEFT_1", 1},
            {"ROTATE_RIGHT_1", -1}
        };

        for (const auto& rotation : rotations) {
            string rotation_type = rotation.first;
            int steps = rotation.second;
            
            cout << "  Testing rotation: " << rotation_type << endl;

            // Rotation time
            auto start_rotation = chrono::high_resolution_clock::now();
            
            Ciphertext rotated;
            if (steps > 0) {
                // Left rotation
                evaluator->rotate_rows(cipher, steps, galois_keys, rotated);
            } else {
                // Right rotation
                evaluator->rotate_rows(cipher, -steps, galois_keys, rotated);
            }
            
            auto end_rotation = chrono::high_resolution_clock::now();
            double rotation_time = chrono::duration<double, milli>(end_rotation - start_rotation).count();

            log_rotation(poly_modulus_degree, vector_size, rotation_type, rotation_time);
        }

        // Test column rotation (rotate columns)
        cout << "  Testing rotation: ROTATE_COLUMNS" << endl;
        auto start_col_rotation = chrono::high_resolution_clock::now();
        
        Ciphertext col_rotated;
        evaluator->rotate_columns(cipher, galois_keys, col_rotated);
        
        auto end_col_rotation = chrono::high_resolution_clock::now();
        double col_rotation_time = chrono::duration<double, milli>(end_col_rotation - start_col_rotation).count();

        log_rotation(poly_modulus_degree, vector_size, "ROTATE_COLUMNS", col_rotation_time);
    }

    void run_experiment(size_t poly_modulus_degree, size_t vector_size) {
        cout << "\n=== Starting Rotation Experiment: PolyModulus=" << poly_modulus_degree 
             << ", VectorSize=" << vector_size << " ===" << endl;
        
        if (!setup_context(poly_modulus_degree)) {
            cout << "SKIPPING - Failed to setup context for poly_modulus_degree: " << poly_modulus_degree << endl;
            return;
        }
        
        size_t slot_count = batch_encoder->slot_count();
        
        cout << "Testing - PolyModulus: " << poly_modulus_degree 
             << ", VectorSize: " << vector_size 
             << ", SlotCount: " << slot_count << endl;

        test_rotation(poly_modulus_degree, vector_size);
        
        cout << "=== Completed Rotation Experiment: PolyModulus=" << poly_modulus_degree 
             << ", VectorSize=" << vector_size << " ===" << endl;
    }

    void run_all_experiments() {
        vector<size_t> poly_modulus_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
        vector<size_t> vector_sizes;
        
        // Generate vector sizes from 2^4 to 2^10
        for (int i = 4; i <= 10; i++) {
            vector_sizes.push_back(1 << i);
        }

        cout << "Testing ALL poly modulus degrees including 1024 and 2048" << endl;
        cout << "Vector sizes: 16 to 1024" << endl;
        cout << "Rotation types: ROTATE_LEFT_1, ROTATE_RIGHT_1, ROTATE_COLUMNS" << endl;

        for (auto poly_degree : poly_modulus_degrees) {
            for (auto vec_size : vector_sizes) {
                run_experiment(poly_degree, vec_size);
            }
        }
    }
};

int main() {
    SEALRotationExperiment experiment;
    cout << "Starting Rotation Experiments..." << endl;
    cout << "Testing polynomial modulus degrees: 1024, 2048, 4096, 8192, 16384, 32768" << endl;
    cout << "Testing vector sizes: 16, 32, 64, 128, 256, 512, 1024" << endl;
    cout << "Testing rotation types: Single step left, single step right, column rotation" << endl;
    experiment.run_all_experiments();
    cout << "Rotation Experiments Completed!" << endl;
    return 0;
}
